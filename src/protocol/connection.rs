//! Compression-aware packet framing.
//!
//! Minecraft has two wire formats. Before Set Compression is negotiated:
//!
//! ```text
//! [VarInt packet_length] [VarInt packet_id] [payload...]
//! ```
//!
//! After Set Compression, every frame gains a `data_length` field:
//!
//! ```text
//! [VarInt packet_length] [VarInt data_length] [ zlib(packet_id + payload) ]
//! ```
//!
//! where `data_length == 0` means the body was left uncompressed because it was
//! below the threshold. Both directions of a connection negotiate this
//! independently, so the reader and writer each carry their own threshold.

use std::io::{Read, Write};
use std::time::Duration;

use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::packet::{RawPacket, MAX_PACKET_SIZE};
use super::varint::{read_varint, write_varint};

/// A VarInt encodes a 32-bit value in at most five bytes.
const MAX_VARINT_BYTES: usize = 5;

/// Reads a VarInt one byte at a time straight off the socket. We cannot read
/// ahead here: the length prefix is the only thing telling us where the frame
/// ends, so over-reading would steal bytes from the next packet.
async fn read_varint_async<R: AsyncRead + Unpin>(reader: &mut R) -> anyhow::Result<i32> {
    let mut result: i32 = 0;
    let mut shift: u32 = 0;
    let mut bytes_read = 0usize;

    loop {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte).await?;
        let b = byte[0];

        // The length check has to happen *before* the shift. A VarInt is at
        // most five bytes, and on a sixth byte `shift` would be 35, which
        // overflows a 32-bit shift and panics. Any peer can send six bytes with
        // the continuation bit set, so this is reachable from the network.
        bytes_read += 1;
        if bytes_read > MAX_VARINT_BYTES {
            anyhow::bail!("VarInt longer than {} bytes", MAX_VARINT_BYTES);
        }

        result |= ((b & 0x7F) as i32) << shift;
        shift += 7;

        if b & 0x80 == 0 {
            return Ok(result);
        }
    }
}

/// The read half of a Minecraft connection.
pub struct FrameReader<R> {
    inner: R,
    /// `None` until Set Compression has been negotiated.
    threshold: Option<i32>,
    /// Fails the read if no complete frame arrives in time. A connection that
    /// opens and then says nothing otherwise holds a task and a socket forever.
    read_timeout: Option<Duration>,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            threshold: None,
            read_timeout: None,
        }
    }

    /// Sets the idle timeout for a single frame. `None` waits forever.
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        self.read_timeout = timeout;
    }

    /// Enables compression on this half. A negative threshold disables it again,
    /// which is what a server means when it sends Set Compression with -1.
    pub fn set_threshold(&mut self, threshold: i32) {
        self.threshold = if threshold < 0 { None } else { Some(threshold) };
    }

    pub fn compression_enabled(&self) -> bool {
        self.threshold.is_some()
    }

    /// Reads one frame and returns its decompressed body (packet id + payload).
    ///
    /// On timeout the connection is finished: a partly-consumed length prefix
    /// cannot be resumed, so callers must drop the reader rather than retry.
    pub async fn read_frame(&mut self) -> anyhow::Result<Vec<u8>> {
        match self.read_timeout {
            Some(timeout) => tokio::time::timeout(timeout, self.read_frame_inner())
                .await
                .map_err(|_| anyhow::anyhow!("no data for {:?}", timeout))?,
            None => self.read_frame_inner().await,
        }
    }

    async fn read_frame_inner(&mut self) -> anyhow::Result<Vec<u8>> {
        let packet_length = read_varint_async(&mut self.inner).await?;
        if packet_length < 0 || packet_length as usize > MAX_PACKET_SIZE {
            anyhow::bail!("invalid packet length {}", packet_length);
        }
        let mut frame = vec![0u8; packet_length as usize];
        self.inner.read_exact(&mut frame).await?;

        if self.threshold.is_none() {
            return Ok(frame);
        }

        // Compressed format: split off data_length, then inflate if non-zero.
        let (data_length, consumed) = read_varint(&frame)?;
        let body = &frame[consumed..];

        if data_length == 0 {
            return Ok(body.to_vec());
        }
        if data_length < 0 || data_length as usize > MAX_PACKET_SIZE {
            anyhow::bail!("invalid uncompressed size {}", data_length);
        }

        // Bound the inflate by the declared size. Without this a small frame of
        // highly compressible bytes expands unchecked -- roughly 1000:1 -- and
        // one 2 MB frame could allocate gigabytes before the size check below
        // ever ran. Reading one byte past the declared length still lets an
        // over-long stream be detected rather than silently truncated.
        let mut decoder = ZlibDecoder::new(body).take(data_length as u64 + 1);
        let mut out = Vec::with_capacity(data_length as usize);
        decoder.read_to_end(&mut out)?;

        if out.len() != data_length as usize {
            anyhow::bail!(
                "decompressed size mismatch: header said {}, got {}",
                data_length,
                out.len()
            );
        }
        Ok(out)
    }

    /// Reads one frame and splits it into packet id + payload.
    pub async fn read_packet(&mut self) -> anyhow::Result<RawPacket> {
        let body = self.read_frame().await?;
        let (id, id_size) = read_varint(&body)?;
        Ok(RawPacket::new(id, body[id_size..].to_vec()))
    }
}

/// The write half of a Minecraft connection.
pub struct FrameWriter<W> {
    inner: W,
    threshold: Option<i32>,
}

impl<W: AsyncWrite + Unpin> FrameWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            threshold: None,
        }
    }

    pub fn set_threshold(&mut self, threshold: i32) {
        self.threshold = if threshold < 0 { None } else { Some(threshold) };
    }

    /// Writes a frame whose body is already `packet_id + payload`.
    pub async fn write_frame(&mut self, body: &[u8]) -> anyhow::Result<()> {
        let mut out = Vec::with_capacity(body.len() + 8);

        match self.threshold {
            None => {
                write_varint(&mut out, body.len() as i32);
                out.extend_from_slice(body);
            }
            Some(threshold) => {
                let mut inner = Vec::with_capacity(body.len() + 5);
                if body.len() >= threshold as usize && threshold > 0 {
                    write_varint(&mut inner, body.len() as i32);
                    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
                    encoder.write_all(body)?;
                    inner.extend_from_slice(&encoder.finish()?);
                } else {
                    // Below threshold: data_length 0 marks it as stored verbatim.
                    write_varint(&mut inner, 0);
                    inner.extend_from_slice(body);
                }
                write_varint(&mut out, inner.len() as i32);
                out.extend_from_slice(&inner);
            }
        }

        self.inner.write_all(&out).await?;
        self.inner.flush().await?;
        Ok(())
    }

    pub async fn write_packet(&mut self, packet: &RawPacket) -> anyhow::Result<()> {
        let mut body = Vec::with_capacity(packet.data.len() + 5);
        write_varint(&mut body, packet.id);
        body.extend_from_slice(&packet.data);
        self.write_frame(&body).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn roundtrip(threshold: i32, payload: Vec<u8>) {
        let packet = RawPacket::new(0x1A, payload);

        let mut buf = Vec::new();
        let mut writer = FrameWriter::new(&mut buf);
        writer.set_threshold(threshold);
        writer.write_packet(&packet).await.unwrap();

        let mut reader = FrameReader::new(&buf[..]);
        reader.set_threshold(threshold);
        let got = reader.read_packet().await.unwrap();

        assert_eq!(got.id, packet.id);
        assert_eq!(got.data, packet.data);
    }

    #[tokio::test]
    async fn uncompressed_roundtrip() {
        roundtrip(-1, vec![1, 2, 3]).await;
    }

    #[tokio::test]
    async fn below_threshold_stays_verbatim() {
        roundtrip(256, vec![7; 10]).await;
    }

    #[tokio::test]
    async fn above_threshold_is_deflated() {
        roundtrip(256, vec![9; 4096]).await;
    }

    #[tokio::test]
    async fn an_overlong_varint_length_is_rejected_not_a_panic() {
        // Six bytes with the continuation bit set. Before the length check was
        // moved ahead of the shift, this panicked with a shift overflow.
        let data = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F];
        let mut reader = FrameReader::new(&data[..]);
        assert!(reader.read_frame().await.is_err());
    }

    #[tokio::test]
    async fn back_to_back_frames_do_not_bleed() {
        // The reader must consume exactly one frame, leaving the next intact.
        let mut buf = Vec::new();
        let mut writer = FrameWriter::new(&mut buf);
        writer.set_threshold(256);
        writer
            .write_packet(&RawPacket::new(1, vec![0xAA; 5]))
            .await
            .unwrap();
        writer
            .write_packet(&RawPacket::new(2, vec![0xBB; 1024]))
            .await
            .unwrap();

        let mut reader = FrameReader::new(&buf[..]);
        reader.set_threshold(256);
        let a = reader.read_packet().await.unwrap();
        let b = reader.read_packet().await.unwrap();
        assert_eq!(a.id, 1);
        assert_eq!(a.data.len(), 5);
        assert_eq!(b.id, 2);
        assert_eq!(b.data.len(), 1024);
    }
}

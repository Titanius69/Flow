use super::varint::{read_varint, varint_size, write_varint};

/// Maximum packet size we'll accept (2 MB). Minecraft uses 2 MB as the default
/// for the `network-compression-threshold` and packet size limits.
pub const MAX_PACKET_SIZE: usize = 2_097_152;

/// A decoded Minecraft packet: packet ID (VarInt) + payload.
///
/// Reading and writing go through `connection::FrameReader` / `FrameWriter`,
/// which own the length prefix and the compression state. Deliberately no
/// async helpers live here: a direct socket read that skipped the compression
/// layer was how the stream used to desynchronise after Set Compression.
#[derive(Debug, Clone)]
pub struct RawPacket {
    pub id: i32,
    pub data: Vec<u8>,
}

impl RawPacket {
    /// Creates a new RawPacket from a packet ID and payload bytes.
    pub fn new(id: i32, data: Vec<u8>) -> Self {
        Self { id, data }
    }

    /// Encodes this packet into a byte buffer ready to be sent over the wire.
    /// Format: [VarInt total_length] [VarInt packet_id] [payload...]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let id_size = varint_size(self.id);
        let total_payload_size = id_size + self.data.len();

        write_varint(&mut buf, total_payload_size as i32);
        write_varint(&mut buf, self.id);
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Decodes a single packet from a byte buffer that starts with a length-prefixed
    /// Minecraft packet. Returns the decoded packet and the number of bytes consumed.
    pub fn decode(data: &[u8]) -> Result<(Self, usize), anyhow::Error> {
        let (packet_length, mut consumed) = read_varint(data)?;
        if packet_length < 0 {
            anyhow::bail!("negative packet length {}", packet_length);
        }
        let packet_length = packet_length as usize;

        if packet_length > MAX_PACKET_SIZE {
            anyhow::bail!(
                "packet length {} exceeds maximum {}",
                packet_length,
                MAX_PACKET_SIZE
            );
        }

        let frame_end = consumed
            .checked_add(packet_length)
            .ok_or_else(|| anyhow::anyhow!("packet length {} overflows", packet_length))?;
        if data.len() < frame_end {
            anyhow::bail!(
                "not enough data: need {} bytes, have {}",
                frame_end,
                data.len()
            );
        }

        // Read the id from inside the frame only. Reading from the whole buffer
        // would let a VarInt run past the declared length, making `id_size`
        // larger than the frame and underflowing the payload size below.
        let (id, id_size) = read_varint(&data[consumed..frame_end])?;
        consumed += id_size;

        let payload_len = packet_length
            .checked_sub(id_size)
            .ok_or_else(|| anyhow::anyhow!("packet id is longer than the declared frame"))?;
        let payload = data[consumed..consumed + payload_len].to_vec();
        consumed += payload_len;

        Ok((RawPacket::new(id, payload), consumed))
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_roundtrip() {
        let packet = RawPacket::new(0x00, vec![0x01, 0x02, 0x03]);
        let encoded = packet.encode();
        let (decoded, consumed) = RawPacket::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.id, packet.id);
        assert_eq!(decoded.data, packet.data);
    }

    #[test]
    fn test_empty_payload() {
        let packet = RawPacket::new(0x02, vec![]);
        let encoded = packet.encode();
        let (decoded, consumed) = RawPacket::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.id, 0x02);
        assert!(decoded.data.is_empty());
    }
}

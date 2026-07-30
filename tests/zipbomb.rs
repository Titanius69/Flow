//! A compressed frame must not be allowed to inflate beyond the size it
//! declares. Zlib reaches roughly 1000:1 on repetitive input, so an unbounded
//! inflate turns a small frame into an out-of-memory kill.

use flate2::write::ZlibEncoder;
use flate2::Compression;
use flow_proxy::protocol::connection::{FrameReader, FrameWriter};
use flow_proxy::protocol::varint::write_varint;
use std::io::Write;

fn bomb(declared: i32, actual_size: usize) -> Vec<u8> {
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::best());
    enc.write_all(&vec![0u8; actual_size]).unwrap();
    let compressed = enc.finish().unwrap();

    let mut inner = Vec::new();
    write_varint(&mut inner, declared);
    inner.extend_from_slice(&compressed);

    let mut frame = Vec::new();
    write_varint(&mut frame, inner.len() as i32);
    frame.extend_from_slice(&inner);
    frame
}

#[tokio::test]
async fn declared_size_bounds_decompression() {
    let frame = bomb(10, 50 * 1024 * 1024);

    let mut reader = FrameReader::new(&frame[..]);
    reader.set_threshold(256);
    let err = reader.read_frame().await.unwrap_err().to_string();

    assert!(
        !err.contains("52428800"),
        "the whole 50 MB was inflated before the declared size was checked: {}",
        err
    );
    assert!(
        err.contains("mismatch"),
        "the frame should be rejected as malformed, got: {}",
        err
    );
}

#[tokio::test]
async fn honest_compressed_frames_still_round_trip() {
    // The bound must not break legitimate large packets, e.g. chunk data.
    let payload = vec![0x7Eu8; 200_000];

    let mut buf = Vec::new();
    let mut writer = FrameWriter::new(&mut buf);
    writer.set_threshold(256);
    writer
        .write_packet(&flow_proxy::protocol::packet::RawPacket::new(
            0x21,
            payload.clone(),
        ))
        .await
        .unwrap();

    let mut reader = FrameReader::new(&buf[..]);
    reader.set_threshold(256);
    let got = reader.read_packet().await.unwrap();
    assert_eq!(got.id, 0x21);
    assert_eq!(got.data, payload);
}

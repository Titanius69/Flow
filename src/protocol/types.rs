use super::varint::{varint_size, write_varint};

/// Minecraft protocol data type helpers.
/// These operate on `Vec<u8>` for encoding (push-based) and byte slices for decoding.

/// Reads a UTF-8 string prefixed by a VarInt length.
pub fn read_string(data: &[u8]) -> Result<(String, usize), anyhow::Error> {
    let (len, consumed) = super::varint::read_varint(data)?;
    let len = len as usize;
    let start = consumed;
    let end = start + len;
    if end > data.len() {
        anyhow::bail!("string length {} exceeds remaining data {}", len, data.len() - start);
    }
    let s = String::from_utf8(data[start..end].to_vec())?;
    Ok((s, end))
}

/// Writes a UTF-8 string prefixed by a VarInt length into a `Vec<u8>`.
pub fn write_string(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    write_varint(buf, bytes.len() as i32);
    buf.extend_from_slice(bytes);
}

/// Returns the total encoded size of a string (VarInt length prefix + UTF-8 bytes).
pub fn string_size(s: &str) -> usize {
    varint_size(s.len() as i32) + s.len()
}

/// Reads a 16-byte UUID (big-endian) from a byte slice.
pub fn read_uuid(data: &[u8]) -> Result<(uuid::Uuid, usize), anyhow::Error> {
    if data.len() < 16 {
        anyhow::bail!("not enough data for UUID: need 16 bytes, got {}", data.len());
    }
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&data[..16]);
    let u = uuid::Uuid::from_bytes(bytes);
    Ok((u, 16))
}

/// Writes a 16-byte UUID (big-endian) into a `Vec<u8>`.
pub fn write_uuid(buf: &mut Vec<u8>, u: &uuid::Uuid) {
    buf.extend_from_slice(u.as_bytes());
}

/// Reads an unsigned short (2 bytes, big-endian).
pub fn read_ushort(data: &[u8]) -> Result<(u16, usize), anyhow::Error> {
    if data.len() < 2 {
        anyhow::bail!("not enough data for ushort");
    }
    Ok((u16::from_be_bytes([data[0], data[1]]), 2))
}

/// Writes an unsigned short (2 bytes, big-endian) into a `Vec<u8>`.
pub fn write_ushort(buf: &mut Vec<u8>, val: u16) {
    buf.extend_from_slice(&val.to_be_bytes());
}

/// Reads a long (8 bytes, big-endian).
pub fn read_long(data: &[u8]) -> Result<(i64, usize), anyhow::Error> {
    if data.len() < 8 {
        anyhow::bail!("not enough data for long");
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&data[..8]);
    Ok((i64::from_be_bytes(bytes), 8))
}

/// Writes a long (8 bytes, big-endian) into a `Vec<u8>`.
pub fn write_long(buf: &mut Vec<u8>, val: i64) {
    buf.extend_from_slice(&val.to_be_bytes());
}

/// Reads a VarInt-prefixed byte array.
pub fn read_byte_array(data: &[u8]) -> Result<(Vec<u8>, usize), anyhow::Error> {
    let (len, consumed) = super::varint::read_varint(data)?;
    let len = len as usize;
    let start = consumed;
    let end = start + len;
    if end > data.len() {
        anyhow::bail!("byte array length {} exceeds remaining data {}", len, data.len() - start);
    }
    Ok((data[start..end].to_vec(), end))
}

/// Writes a VarInt-prefixed byte array into a `Vec<u8>`.
pub fn write_byte_array(buf: &mut Vec<u8>, bytes: &[u8]) {
    write_varint(buf, bytes.len() as i32);
    buf.extend_from_slice(bytes);
}

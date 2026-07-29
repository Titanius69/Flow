/// Maximum number of bytes a VarInt can occupy (5 bytes for 32-bit).
const MAX_VARINT_SIZE: usize = 5;

/// Error type for VarInt/VarLong decoding.
#[derive(Debug, thiserror::Error)]
pub enum VarIntError {
    #[error("unexpected end of data while reading VarInt")]
    UnexpectedEnd,
    #[error("VarInt is too large (exceeds 5 bytes)")]
    TooLarge,
}

/// Reads a VarInt from a byte slice, returning the value and the number of bytes consumed.
pub fn read_varint(data: &[u8]) -> Result<(i32, usize), VarIntError> {
    let mut result: i32 = 0;
    let mut shift: u32 = 0;
    let mut consumed: usize = 0;

    for &byte in data {
        consumed += 1;
        if consumed > MAX_VARINT_SIZE {
            return Err(VarIntError::TooLarge);
        }
        result |= ((byte & 0x7F) as i32) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Ok((result, consumed));
        }
    }

    Err(VarIntError::UnexpectedEnd)
}

/// Writes a VarInt into a `Vec<u8>`, returning the number of bytes written.
pub fn write_varint(buf: &mut Vec<u8>, value: i32) -> usize {
    let mut val = value as u32;
    let mut written = 0;

    loop {
        if (val & !0x7F) == 0 {
            buf.push(val as u8);
            written += 1;
            return written;
        }
        buf.push((val as u8 & 0x7F) | 0x80);
        written += 1;
        val >>= 7;
    }
}

/// Returns the exact number of bytes this VarInt would occupy when encoded.
pub fn varint_size(value: i32) -> usize {
    let mut val = value as u32;
    let mut size = 0;
    loop {
        size += 1;
        if (val & !0x7F) == 0 {
            return size;
        }
        val >>= 7;
    }
}

/// Writes a VarInt into a fixed-size `&mut [u8]` buffer, returning bytes written.
/// The buffer must be at least 5 bytes long.
pub fn write_varint_slice(buf: &mut [u8], value: i32) -> usize {
    let mut val = value as u32;
    let mut written = 0;

    loop {
        if (val & !0x7F) == 0 {
            buf[written] = val as u8;
            written += 1;
            return written;
        }
        buf[written] = (val as u8 & 0x7F) | 0x80;
        written += 1;
        val >>= 7;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_roundtrip() {
        let values = [0, 1, 127, 128, 255, 2147483647, -1, -2147483648];
        for &v in &values {
            let mut buf = Vec::new();
            let n = write_varint(&mut buf, v);
            let (decoded, consumed) = read_varint(&buf[..n]).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(consumed, n);
        }
    }

    #[test]
    fn test_varint_slice_roundtrip() {
        let values = [0, 1, 127, 128, 255, 2147483647, -1, -2147483648];
        for &v in &values {
            let mut buf = [0u8; 5];
            let n = write_varint_slice(&mut buf, v);
            let (decoded, consumed) = read_varint(&buf[..n]).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(consumed, n);
        }
    }
}

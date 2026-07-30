//! Java `DataInputStream` / `DataOutputStream` primitives.
//!
//! Plugin messages on the BungeeCord channel are written by Java plugins with
//! `DataOutputStream`, not with Minecraft's own packet types. Strings there are
//! *modified UTF-8* with a `u16` byte-length prefix, which is not the same as
//! the protocol's VarInt-prefixed UTF-8: NUL is encoded as two bytes, and
//! characters outside the Basic Multilingual Plane are written as a CESU-8
//! surrogate pair rather than a 4-byte sequence.

/// Reads a Java modified-UTF-8 string. Returns the string and bytes consumed.
pub fn read_utf(data: &[u8]) -> anyhow::Result<(String, usize)> {
    if data.len() < 2 {
        anyhow::bail!("truncated Java UTF length prefix");
    }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let end = 2usize
        .checked_add(len)
        .ok_or_else(|| anyhow::anyhow!("Java UTF length overflows"))?;
    if end > data.len() {
        anyhow::bail!(
            "Java UTF length {} exceeds remaining data {}",
            len,
            data.len() - 2
        );
    }
    Ok((decode_modified_utf8(&data[2..end])?, end))
}

/// Writes a Java modified-UTF-8 string.
pub fn write_utf(buf: &mut Vec<u8>, s: &str) {
    let encoded = encode_modified_utf8(s);
    let len = encoded.len().min(u16::MAX as usize);
    buf.extend_from_slice(&(len as u16).to_be_bytes());
    buf.extend_from_slice(&encoded[..len]);
}

/// Reads a big-endian `i32`.
pub fn read_int(data: &[u8]) -> anyhow::Result<(i32, usize)> {
    if data.len() < 4 {
        anyhow::bail!("truncated Java int");
    }
    Ok((
        i32::from_be_bytes([data[0], data[1], data[2], data[3]]),
        4,
    ))
}

/// Writes a big-endian `i32`.
pub fn write_int(buf: &mut Vec<u8>, value: i32) {
    buf.extend_from_slice(&value.to_be_bytes());
}

fn encode_modified_utf8(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    for ch in text.chars() {
        let cp = ch as u32;
        if cp == 0 {
            out.extend_from_slice(&[0xC0, 0x80]);
        } else if cp < 0x80 {
            out.push(cp as u8);
        } else if cp < 0x800 {
            out.push(0xC0 | (cp >> 6) as u8);
            out.push(0x80 | (cp & 0x3F) as u8);
        } else if cp < 0x10000 {
            out.push(0xE0 | (cp >> 12) as u8);
            out.push(0x80 | ((cp >> 6) & 0x3F) as u8);
            out.push(0x80 | (cp & 0x3F) as u8);
        } else {
            // CESU-8: encode as a surrogate pair, each half in three bytes.
            let v = cp - 0x10000;
            let high = 0xD800 + (v >> 10);
            let low = 0xDC00 + (v & 0x3FF);
            for half in [high, low] {
                out.push(0xE0 | (half >> 12) as u8);
                out.push(0x80 | ((half >> 6) & 0x3F) as u8);
                out.push(0x80 | (half & 0x3F) as u8);
            }
        }
    }
    out
}

fn decode_modified_utf8(bytes: &[u8]) -> anyhow::Result<String> {
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        let b = bytes[i];
        if b & 0x80 == 0 {
            units.push(b as u16);
            i += 1;
        } else if b & 0xE0 == 0xC0 {
            if i + 1 >= bytes.len() {
                anyhow::bail!("truncated two-byte sequence in Java UTF");
            }
            let v = (((b & 0x1F) as u16) << 6) | ((bytes[i + 1] & 0x3F) as u16);
            units.push(v);
            i += 2;
        } else if b & 0xF0 == 0xE0 {
            if i + 2 >= bytes.len() {
                anyhow::bail!("truncated three-byte sequence in Java UTF");
            }
            let v = (((b & 0x0F) as u16) << 12)
                | (((bytes[i + 1] & 0x3F) as u16) << 6)
                | ((bytes[i + 2] & 0x3F) as u16);
            units.push(v);
            i += 3;
        } else {
            anyhow::bail!("invalid leading byte 0x{:02X} in Java UTF", b);
        }
    }

    // The units are UTF-16, so surrogate pairs recombine here.
    String::from_utf16(&units).map_err(|_| anyhow::anyhow!("invalid UTF-16 in Java UTF string"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_round_trip() {
        let mut buf = Vec::new();
        write_utf(&mut buf, "lobby");
        assert_eq!(&buf[..2], &[0x00, 0x05]);
        let (s, n) = read_utf(&buf).unwrap();
        assert_eq!(s, "lobby");
        assert_eq!(n, buf.len());
    }

    #[test]
    fn nul_uses_the_two_byte_form() {
        let mut buf = Vec::new();
        write_utf(&mut buf, "a\0b");
        // Four bytes on the wire even though the string is three characters.
        assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), 4);
        assert_eq!(read_utf(&buf).unwrap().0, "a\0b");
    }

    #[test]
    fn astral_characters_use_a_surrogate_pair() {
        let mut buf = Vec::new();
        write_utf(&mut buf, "\u{1F600}");
        // CESU-8 spends six bytes, not the four that plain UTF-8 would.
        assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), 6);
        assert_eq!(read_utf(&buf).unwrap().0, "\u{1F600}");
    }

    #[test]
    fn accented_characters_round_trip() {
        let mut buf = Vec::new();
        write_utf(&mut buf, "árvíztűrő");
        assert_eq!(read_utf(&buf).unwrap().0, "árvíztűrő");
    }

    #[test]
    fn truncated_input_is_an_error() {
        let mut buf = Vec::new();
        write_utf(&mut buf, "lobby");
        for cut in 0..buf.len() {
            assert!(read_utf(&buf[..cut]).is_err(), "cut at {}", cut);
        }
    }

    #[test]
    fn int_round_trip() {
        let mut buf = Vec::new();
        write_int(&mut buf, -12345);
        assert_eq!(read_int(&buf).unwrap().0, -12345);
        assert!(read_int(&buf[..3]).is_err());
    }
}

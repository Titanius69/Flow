//! Just enough NBT to write text components.
//!
//! Since 1.20.3 chat components on the wire are NBT rather than JSON strings,
//! and since 1.20.2 the root tag is nameless. A bare `TAG_String` is a valid
//! component: the client reads it as literal text, which is all the proxy needs
//! for its own messages.

/// TAG_String.
const TAG_STRING: u8 = 0x08;

/// Writes `text` as a nameless NBT string, i.e. a literal text component.
pub fn write_text_component(buf: &mut Vec<u8>, text: &str) {
    buf.push(TAG_STRING);

    // NBT strings use Java's modified UTF-8 with a u16 byte length. For the
    // Basic Multilingual Plane that is identical to UTF-8; astral characters
    // (emoji) would need surrogate-pair encoding, which we do not emit, so they
    // are replaced rather than written incorrectly.
    let encoded = encode_modified_utf8(text);
    let len = encoded.len().min(u16::MAX as usize);
    buf.extend_from_slice(&(len as u16).to_be_bytes());
    buf.extend_from_slice(&encoded[..len]);
}

/// Returns `text` as a text component ready to be appended to a packet.
pub fn text_component(text: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    write_text_component(&mut buf, text);
    buf
}

/// Encodes to modified UTF-8, substituting characters we cannot represent.
fn encode_modified_utf8(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            // Modified UTF-8 encodes NUL as two bytes so it cannot terminate.
            '\0' => out.extend_from_slice(&[0xC0, 0x80]),
            // Outside the BMP, correct encoding needs a CESU-8 surrogate pair.
            // Emitting plain UTF-8 here would desynchronise the client's
            // reader, so substitute instead.
            c if c as u32 > 0xFFFF => out.push(b'?'),
            c => {
                let mut tmp = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut tmp).as_bytes());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_a_nameless_string_tag() {
        let out = text_component("hi");
        assert_eq!(out, vec![0x08, 0x00, 0x02, b'h', b'i']);
    }

    #[test]
    fn nul_uses_the_two_byte_form() {
        let out = text_component("\0");
        assert_eq!(out, vec![0x08, 0x00, 0x02, 0xC0, 0x80]);
    }

    #[test]
    fn astral_characters_are_substituted_not_mis_encoded() {
        // A 4-byte UTF-8 character must not reach the client as plain UTF-8.
        let out = text_component("a\u{1F600}b");
        assert_eq!(out, vec![0x08, 0x00, 0x03, b'a', b'?', b'b']);
    }

    #[test]
    fn multibyte_bmp_length_is_in_bytes_not_chars() {
        let out = text_component("á");
        assert_eq!(out[1..3], [0x00, 0x02]);
    }
}

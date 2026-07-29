//! Login state packets for protocol 769 (Minecraft 1.21.4).
//!
//! These structs encode *payloads* only. Length prefixing and compression are
//! the framing layer's job (see `connection.rs`), so nothing here writes a
//! length prefix -- doing that in two places was one of the original bugs.

use super::types::{read_string, read_uuid, write_string, write_uuid};
use super::varint::{read_varint, write_varint};

// Clientbound (server -> client) Login packet IDs.
pub const CB_DISCONNECT: i32 = 0x00;
pub const CB_ENCRYPTION_REQUEST: i32 = 0x01;
pub const CB_LOGIN_SUCCESS: i32 = 0x02;
pub const CB_SET_COMPRESSION: i32 = 0x03;
pub const CB_LOGIN_PLUGIN_REQUEST: i32 = 0x04;
pub const CB_COOKIE_REQUEST: i32 = 0x05;

// Serverbound (client -> server) Login packet IDs.
pub const SB_LOGIN_START: i32 = 0x00;
pub const SB_LOGIN_PLUGIN_RESPONSE: i32 = 0x02;
pub const SB_LOGIN_ACKNOWLEDGED: i32 = 0x03;
pub const SB_COOKIE_RESPONSE: i32 = 0x04;

/// Computes the offline-mode UUID for a username, matching vanilla's
/// `UUID.nameUUIDFromBytes(("OfflinePlayer:" + name).getBytes(UTF_8))`.
///
/// This is a raw MD5 digest with the version-3 and RFC-4122 variant bits
/// forced in -- not a namespaced v3 UUID. Getting this wrong gives every
/// player a different UUID than the backend expects, which silently breaks
/// permissions, playerdata and bans.
pub fn offline_uuid(username: &str) -> uuid::Uuid {
    use md5::{Digest, Md5};

    let mut hasher = Md5::new();
    hasher.update(format!("OfflinePlayer:{}", username).as_bytes());
    let mut bytes: [u8; 16] = hasher.finalize().into();

    bytes[6] = (bytes[6] & 0x0F) | 0x30; // version 3
    bytes[8] = (bytes[8] & 0x3F) | 0x80; // RFC 4122 variant

    uuid::Uuid::from_bytes(bytes)
}

/// Serverbound Login Start (0x00).
///
/// Since 1.20.2 the UUID field is mandatory and *not* prefixed by a boolean.
#[derive(Debug, Clone)]
pub struct LoginStart {
    pub username: String,
    pub uuid: uuid::Uuid,
}

impl LoginStart {
    pub fn decode(data: &[u8]) -> anyhow::Result<Self> {
        let (username, offset) = read_string(data)?;

        // Tolerate the older optional-boolean form and pre-1.20.2 clients that
        // omit the field, so a stray old client gets a clean login instead of a
        // parse error.
        let uuid = if data.len() == offset + 17 {
            let (uuid, _) = read_uuid(&data[offset + 1..])?;
            uuid
        } else if data.len() >= offset + 16 {
            let (uuid, _) = read_uuid(&data[offset..])?;
            uuid
        } else {
            offline_uuid(&username)
        };

        Ok(LoginStart { username, uuid })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        write_string(&mut buf, &self.username);
        write_uuid(&mut buf, &self.uuid);
        buf
    }
}

/// A game profile property (skin textures and their signature).
#[derive(Debug, Clone)]
pub struct ProfileProperty {
    pub name: String,
    pub value: String,
    pub signature: Option<String>,
}

/// Clientbound Login Success (0x02).
///
/// For protocol 769 the payload is uuid + username + properties. The
/// `strict_error_handling` boolean that existed in 1.20.5-1.21.1 was removed
/// in 1.21.2, so it must not be written here.
#[derive(Debug, Clone)]
pub struct LoginSuccess {
    pub uuid: uuid::Uuid,
    pub username: String,
    pub properties: Vec<ProfileProperty>,
}

impl LoginSuccess {
    pub fn decode(data: &[u8]) -> anyhow::Result<Self> {
        let mut offset = 0;

        let (uuid, n) = read_uuid(&data[offset..])?;
        offset += n;
        let (username, n) = read_string(&data[offset..])?;
        offset += n;
        let (count, n) = read_varint(&data[offset..])?;
        offset += n;

        let mut properties = Vec::new();
        for _ in 0..count.max(0) {
            let (name, n) = read_string(&data[offset..])?;
            offset += n;
            let (value, n) = read_string(&data[offset..])?;
            offset += n;
            if offset >= data.len() {
                anyhow::bail!("truncated property in Login Success");
            }
            let has_sig = data[offset] != 0;
            offset += 1;
            let signature = if has_sig {
                let (sig, n) = read_string(&data[offset..])?;
                offset += n;
                Some(sig)
            } else {
                None
            };
            properties.push(ProfileProperty { name, value, signature });
        }

        Ok(LoginSuccess { uuid, username, properties })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        write_uuid(&mut buf, &self.uuid);
        write_string(&mut buf, &self.username);
        write_varint(&mut buf, self.properties.len() as i32);
        for prop in &self.properties {
            write_string(&mut buf, &prop.name);
            write_string(&mut buf, &prop.value);
            match &prop.signature {
                Some(sig) => {
                    buf.push(0x01);
                    write_string(&mut buf, sig);
                }
                None => buf.push(0x00),
            }
        }
        buf
    }
}

/// Clientbound Login Plugin Request (0x04).
#[derive(Debug, Clone)]
pub struct LoginPluginRequest {
    pub message_id: i32,
    pub channel: String,
    pub data: Vec<u8>,
}

impl LoginPluginRequest {
    pub fn decode(data: &[u8]) -> anyhow::Result<Self> {
        let mut offset = 0;
        let (message_id, n) = read_varint(&data[offset..])?;
        offset += n;
        let (channel, n) = read_string(&data[offset..])?;
        offset += n;
        Ok(LoginPluginRequest {
            message_id,
            channel,
            data: data[offset..].to_vec(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        write_varint(&mut buf, self.message_id);
        write_string(&mut buf, &self.channel);
        buf.extend_from_slice(&self.data);
        buf
    }
}

/// Serverbound Login Plugin Response (0x02).
#[derive(Debug, Clone)]
pub struct LoginPluginResponse {
    pub message_id: i32,
    pub successful: bool,
    pub data: Vec<u8>,
}

impl LoginPluginResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        write_varint(&mut buf, self.message_id);
        buf.push(if self.successful { 0x01 } else { 0x00 });
        if self.successful {
            buf.extend_from_slice(&self.data);
        }
        buf
    }
}

/// Clientbound Set Compression (0x03).
pub struct SetCompression {
    pub threshold: i32,
}

impl SetCompression {
    pub fn decode(data: &[u8]) -> anyhow::Result<Self> {
        let (threshold, _) = read_varint(data)?;
        Ok(SetCompression { threshold })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        write_varint(&mut buf, self.threshold);
        buf
    }
}

/// Clientbound Login Disconnect (0x00). In Login state the reason is a plain
/// JSON string, not an NBT component like in Play state.
pub struct LoginDisconnect;

impl LoginDisconnect {
    pub fn decode_reason(data: &[u8]) -> anyhow::Result<String> {
        let (reason_json, _) = read_string(data)?;
        Ok(reason_json)
    }

    pub fn encode_text(message: &str) -> Vec<u8> {
        let json = serde_json::json!({ "text": message }).to_string();
        let mut buf = Vec::new();
        write_string(&mut buf, &json);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_uuid_matches_vanilla() {
        // Verified against UUID.nameUUIDFromBytes("OfflinePlayer:<name>").
        assert_eq!(
            offline_uuid("Notch").to_string(),
            "b50ad385-829d-3141-a216-7e7d7539ba7f"
        );
        assert_eq!(
            offline_uuid("jeb_").to_string(),
            "a762f560-4fce-3236-812a-b80efff0b62b"
        );
        assert_eq!(
            offline_uuid("Steve").to_string(),
            "5627dd98-e6be-3c21-b8a8-e92344183641"
        );
    }

    #[test]
    fn login_start_roundtrip() {
        let start = LoginStart {
            username: "Steve".into(),
            uuid: offline_uuid("Steve"),
        };
        let decoded = LoginStart::decode(&start.encode()).unwrap();
        assert_eq!(decoded.username, "Steve");
        assert_eq!(decoded.uuid, start.uuid);
    }

    #[test]
    fn login_success_roundtrip() {
        let success = LoginSuccess {
            uuid: offline_uuid("Alex"),
            username: "Alex".into(),
            properties: vec![ProfileProperty {
                name: "textures".into(),
                value: "abc".into(),
                signature: Some("sig".into()),
            }],
        };
        let decoded = LoginSuccess::decode(&success.encode()).unwrap();
        assert_eq!(decoded.username, "Alex");
        assert_eq!(decoded.uuid, success.uuid);
        assert_eq!(decoded.properties.len(), 1);
        assert_eq!(decoded.properties[0].signature.as_deref(), Some("sig"));
    }
}

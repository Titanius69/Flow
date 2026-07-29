//! Velocity "modern" player info forwarding.
//!
//! The backend sends a Login Plugin Request on `velocity:player_info` whose
//! single data byte is the highest forwarding version it supports. We reply
//! with an HMAC-signed payload describing the player.
//!
//! Critically, the payload layout depends on the version we answer with. The
//! key-bearing versions (2 and 3) require a real Mojang-signed player public
//! key. A proxy that does not run Mojang authentication has no such key, so
//! answering 2 with empty key bytes makes Paper's RSA key decode throw and the
//! login fails. When we have no key we must answer version 1.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;

use super::types::{read_string, read_uuid, write_string, write_uuid};
use super::varint::{read_varint, write_varint};

type HmacSha256 = Hmac<Sha256>;

/// The channel name used for Velocity modern forwarding.
pub const VELOCITY_CHANNEL: &str = "velocity:player_info";

/// No player key: only the plain profile is forwarded.
pub const MODERN_DEFAULT: i32 = 1;
/// Carries a Mojang-signed player public key (1.19+).
pub const MODERN_FORWARDING_WITH_KEY: i32 = 2;
/// As above, plus the signer UUID (1.19.1+).
pub const MODERN_FORWARDING_WITH_KEY_V2: i32 = 3;
/// Key material is resolved lazily by the backend (1.19.3+).
pub const MODERN_LAZY_SESSION: i32 = 4;

/// A property from the game profile (skin textures and their signature).
#[derive(Debug, Clone)]
pub struct Property {
    pub name: String,
    pub value: String,
    pub signature: Option<String>,
}

/// A Mojang-signed player public key, when one is available.
#[derive(Debug, Clone)]
pub struct PlayerKey {
    pub expiry: i64,
    pub key: Vec<u8>,
    pub signature: Vec<u8>,
    /// The account the key belongs to, required from version 3 onwards.
    pub signer: Option<Uuid>,
}

/// Everything the backend needs to reconstruct the player's identity.
#[derive(Debug, Clone)]
pub struct ForwardingData {
    pub client_address: String,
    pub player_uuid: Uuid,
    pub username: String,
    pub properties: Vec<Property>,
    /// `None` for an offline-mode proxy, which forces version 1.
    pub player_key: Option<PlayerKey>,
}

/// Picks the forwarding version to answer with, given what the backend asked
/// for and whether we actually hold a player key.
pub fn negotiate_version(requested: i32, has_key: bool) -> i32 {
    let capped = requested.min(MODERN_LAZY_SESSION);
    if capped <= MODERN_DEFAULT || !has_key {
        // Without key material only version 1 is safe to emit.
        MODERN_DEFAULT
    } else {
        capped
    }
}

/// Builds the Login Plugin Response payload.
///
/// Layout: `HMAC-SHA256(body)` (32 bytes) followed by the body, where the body
/// is version, address, uuid, username, properties, and -- only for versions 2
/// and 3 -- the player key.
pub fn build_forwarding_payload(secret: &[u8], version: i32, data: &ForwardingData) -> Vec<u8> {
    let mut body = Vec::new();

    write_varint(&mut body, version);
    write_string(&mut body, &data.client_address);
    write_uuid(&mut body, &data.player_uuid);
    write_string(&mut body, &data.username);

    write_varint(&mut body, data.properties.len() as i32);
    for prop in &data.properties {
        write_string(&mut body, &prop.name);
        write_string(&mut body, &prop.value);
        match &prop.signature {
            Some(sig) => {
                body.push(0x01);
                write_string(&mut body, sig);
            }
            None => body.push(0x00),
        }
    }

    // The key block exists only in versions 2 and 3. Version 4 deliberately
    // omits it, and version 1 never had it.
    if version >= MODERN_FORWARDING_WITH_KEY && version < MODERN_LAZY_SESSION {
        if let Some(key) = &data.player_key {
            body.extend_from_slice(&key.expiry.to_be_bytes());
            write_varint(&mut body, key.key.len() as i32);
            body.extend_from_slice(&key.key);
            write_varint(&mut body, key.signature.len() as i32);
            body.extend_from_slice(&key.signature);

            if version >= MODERN_FORWARDING_WITH_KEY_V2 {
                match &key.signer {
                    Some(signer) => {
                        body.push(0x01);
                        write_uuid(&mut body, signer);
                    }
                    None => body.push(0x00),
                }
            }
        }
    }

    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&body);
    let signature = mac.finalize().into_bytes();

    let mut payload = Vec::with_capacity(32 + body.len());
    payload.extend_from_slice(&signature);
    payload.extend_from_slice(&body);
    payload
}

/// Verifies a forwarding payload and extracts the profile. Mirrors what Paper
/// does on receipt, which makes it useful for tests and for a future mode where
/// this proxy sits behind another one.
pub fn verify_forwarding_payload(secret: &[u8], payload: &[u8]) -> anyhow::Result<ForwardingData> {
    if payload.len() < 32 {
        anyhow::bail!("forwarding payload too short: need at least 32 bytes of signature");
    }

    let (received_sig, body) = payload.split_at(32);

    let mut mac = HmacSha256::new_from_slice(secret)?;
    mac.update(body);
    mac.verify_slice(received_sig)
        .map_err(|_| anyhow::anyhow!("HMAC mismatch: the forwarding secret does not match the backend"))?;

    let mut offset = 0;

    let (version, n) = read_varint(&body[offset..])?;
    offset += n;
    let (client_address, n) = read_string(&body[offset..])?;
    offset += n;
    let (player_uuid, n) = read_uuid(&body[offset..])?;
    offset += n;
    let (username, n) = read_string(&body[offset..])?;
    offset += n;
    let (prop_count, n) = read_varint(&body[offset..])?;
    offset += n;

    let mut properties = Vec::new();
    for _ in 0..prop_count.max(0) {
        let (name, n) = read_string(&body[offset..])?;
        offset += n;
        let (value, n) = read_string(&body[offset..])?;
        offset += n;
        if offset >= body.len() {
            anyhow::bail!("truncated property in forwarding payload");
        }
        let has_sig = body[offset] != 0;
        offset += 1;
        let signature = if has_sig {
            let (sig, n) = read_string(&body[offset..])?;
            offset += n;
            Some(sig)
        } else {
            None
        };
        properties.push(Property { name, value, signature });
    }

    let player_key = if version >= MODERN_FORWARDING_WITH_KEY && version < MODERN_LAZY_SESSION {
        let (expiry, n) = super::types::read_long(&body[offset..])?;
        offset += n;
        let (key, n) = super::types::read_byte_array(&body[offset..])?;
        offset += n;
        let (signature, n) = super::types::read_byte_array(&body[offset..])?;
        offset += n;

        let signer = if version >= MODERN_FORWARDING_WITH_KEY_V2 && offset < body.len() {
            let present = body[offset] != 0;
            offset += 1;
            if present {
                let (signer, _) = read_uuid(&body[offset..])?;
                Some(signer)
            } else {
                None
            }
        } else {
            None
        };

        Some(PlayerKey { expiry, key, signature, signer })
    } else {
        None
    };

    Ok(ForwardingData {
        client_address,
        player_uuid,
        username,
        properties,
        player_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ForwardingData {
        ForwardingData {
            client_address: "203.0.113.7".to_string(),
            player_uuid: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            username: "TestPlayer".to_string(),
            properties: vec![Property {
                name: "textures".to_string(),
                value: "base64".to_string(),
                signature: Some("sig".to_string()),
            }],
            player_key: None,
        }
    }

    #[test]
    fn roundtrip_v1() {
        let secret = b"secret";
        let payload = build_forwarding_payload(secret, MODERN_DEFAULT, &sample());
        let got = verify_forwarding_payload(secret, &payload).unwrap();
        assert_eq!(got.username, "TestPlayer");
        assert_eq!(got.client_address, "203.0.113.7");
        assert_eq!(got.properties.len(), 1);
        assert!(got.player_key.is_none());
    }

    #[test]
    fn roundtrip_v3_with_key() {
        let secret = b"secret";
        let mut data = sample();
        data.player_key = Some(PlayerKey {
            expiry: 1234567890,
            key: vec![1, 2, 3],
            signature: vec![4, 5, 6],
            signer: Some(Uuid::nil()),
        });

        let payload = build_forwarding_payload(secret, MODERN_FORWARDING_WITH_KEY_V2, &data);
        let got = verify_forwarding_payload(secret, &payload).unwrap();
        let key = got.player_key.expect("key should round-trip");
        assert_eq!(key.expiry, 1234567890);
        assert_eq!(key.key, vec![1, 2, 3]);
        assert_eq!(key.signature, vec![4, 5, 6]);
        assert_eq!(key.signer, Some(Uuid::nil()));
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let payload = build_forwarding_payload(b"right", MODERN_DEFAULT, &sample());
        assert!(verify_forwarding_payload(b"wrong", &payload).is_err());
    }

    #[test]
    fn version_falls_back_to_one_without_a_key() {
        // Paper asks for 4; with no key material we must not answer 2 or 3.
        assert_eq!(negotiate_version(4, false), MODERN_DEFAULT);
        assert_eq!(negotiate_version(2, false), MODERN_DEFAULT);
        assert_eq!(negotiate_version(1, false), MODERN_DEFAULT);
    }

    #[test]
    fn version_is_capped_to_what_we_support() {
        assert_eq!(negotiate_version(99, true), MODERN_LAZY_SESSION);
        assert_eq!(negotiate_version(3, true), MODERN_FORWARDING_WITH_KEY_V2);
    }
}

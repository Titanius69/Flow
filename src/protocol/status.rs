//! Status (server list ping) packets. Payload-only, like the login packets.

use super::types::{read_long, write_string};

pub const CB_STATUS_RESPONSE: i32 = 0x00;
pub const CB_PONG: i32 = 0x01;
pub const SB_STATUS_REQUEST: i32 = 0x00;
pub const SB_PING_REQUEST: i32 = 0x01;

/// Serverbound Ping Request (0x01): a 64-bit token to echo back verbatim.
pub struct PingRequest {
    pub payload: i64,
}

impl PingRequest {
    pub fn decode(data: &[u8]) -> anyhow::Result<Self> {
        let (payload, _) = read_long(data)?;
        Ok(PingRequest { payload })
    }
}

/// Clientbound Status Response (0x00).
pub struct StatusResponse {
    pub json_response: serde_json::Value,
}

impl StatusResponse {
    pub fn encode(&self) -> Vec<u8> {
        let json = serde_json::to_string(&self.json_response).expect("status JSON is serializable");
        let mut buf = Vec::new();
        write_string(&mut buf, &json);
        buf
    }
}

/// Clientbound Pong Response (0x01).
pub struct PingResponse {
    pub payload: i64,
}

impl PingResponse {
    pub fn encode(&self) -> Vec<u8> {
        self.payload.to_be_bytes().to_vec()
    }
}

/// Serverbound Handshake next-state values.
pub const NEXT_STATE_STATUS: i32 = 1;
pub const NEXT_STATE_LOGIN: i32 = 2;
/// 1.20.5+ transfer packet, which arrives as a third next-state value.
pub const NEXT_STATE_TRANSFER: i32 = 3;

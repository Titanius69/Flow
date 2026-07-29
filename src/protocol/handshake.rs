use super::types::{read_string, read_ushort, write_string, write_ushort};
use super::varint::{read_varint, write_varint};

/// Serverbound Handshake packet (Packet ID 0x00).
/// This is the first packet sent by the client.
#[derive(Debug, Clone)]
pub struct HandshakePacket {
    /// Protocol version (e.g. 769 for 1.21.4)
    pub protocol_version: i32,
    /// Server address the client connected to (e.g. "localhost")
    pub server_address: String,
    /// Port the client connected to
    pub server_port: u16,
    /// Next intended state: 1 = Status, 2 = Login
    pub next_state: i32,
}

impl HandshakePacket {
    /// Decodes a Handshake packet from the raw payload (after the packet ID).
    pub fn decode(data: &[u8]) -> Result<(Self, usize), anyhow::Error> {
        let mut offset = 0;

        let (protocol_version, n) = read_varint(&data[offset..])?;
        offset += n;

        let (server_address, n) = read_string(&data[offset..])?;
        offset += n;

        let (server_port, n) = read_ushort(&data[offset..])?;
        offset += n;

        let (next_state, n) = read_varint(&data[offset..])?;
        offset += n;

        Ok((
            HandshakePacket {
                protocol_version,
                server_address,
                server_port,
                next_state,
            },
            offset,
        ))
    }

    /// Encodes this Handshake packet into a payload (without the packet ID).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        write_varint(&mut buf, self.protocol_version);
        write_string(&mut buf, &self.server_address);
        write_ushort(&mut buf, self.server_port);
        write_varint(&mut buf, self.next_state);
        buf
    }
}

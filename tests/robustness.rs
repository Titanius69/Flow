//! Robustness harness for the packet decoders.
//!
//! Every decoder here runs on bytes that arrive from the network before the
//! sender has been authenticated, so a panic on malformed input is reachable by
//! anyone who can open a socket. A panic only kills the connection's task
//! rather than the process, but it is still a bug and an easy denial-of-service
//! lever if it can be triggered cheaply.
//!
//! These are deterministic pseudo-random sweeps rather than a real fuzzing
//! campaign: they run on every `cargo test` and catch the obvious classes
//! (negative lengths, truncation, offset overflow). For coverage-guided
//! fuzzing, see `fuzz/` and run `cargo +nightly fuzz run <target>`.

use flow_proxy::protocol::connection::FrameReader;
use flow_proxy::protocol::forwarding::verify_forwarding_payload;
use flow_proxy::protocol::handshake::HandshakePacket;
use flow_proxy::protocol::login::{
    LoginDisconnect, LoginPluginRequest, LoginStart, LoginSuccess, SetCompression,
};
use flow_proxy::protocol::packet::RawPacket;
use flow_proxy::protocol::plugin_message::BungeeMessage;
use flow_proxy::protocol::status::PingRequest;
use flow_proxy::protocol::types::{
    read_byte_array, read_long, read_string, read_ushort, read_uuid,
};
use flow_proxy::protocol::varint::read_varint;

/// xorshift64*, so failures are reproducible from the seed alone.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn byte(&mut self) -> u8 {
        (self.next() >> 33) as u8
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() >> 33) as usize % n.max(1)
    }

    /// Biased towards bytes that matter: VarInt continuation bits, 0xFF runs
    /// (negative lengths) and zeroes. Uniform noise mostly fails the very first
    /// bounds check and never reaches the interesting code.
    fn spicy_byte(&mut self) -> u8 {
        match self.below(6) {
            0 => 0xFF,
            1 => 0x80,
            2 => 0x00,
            3 => 0x7F,
            _ => self.byte(),
        }
    }

    fn blob(&mut self, max: usize) -> Vec<u8> {
        let len = self.below(max);
        (0..len).map(|_| self.spicy_byte()).collect()
    }
}

/// Runs every decoder over one input. Any panic fails the test.
fn hammer(data: &[u8]) {
    let _ = read_varint(data);
    let _ = read_string(data);
    let _ = read_uuid(data);
    let _ = read_ushort(data);
    let _ = read_long(data);
    let _ = read_byte_array(data);
    let _ = RawPacket::decode(data);
    let _ = HandshakePacket::decode(data);
    let _ = LoginStart::decode(data);
    let _ = LoginSuccess::decode(data);
    let _ = LoginPluginRequest::decode(data);
    let _ = SetCompression::decode(data);
    let _ = LoginDisconnect::decode_reason(data);
    let _ = PingRequest::decode(data);
    let _ = verify_forwarding_payload(b"secret", data);
    let _ = BungeeMessage::decode(data);
}

#[test]
fn decoders_survive_random_input() {
    let mut rng = Rng(0x5EED_1234_ABCD_9876);
    for _ in 0..60_000 {
        let data = rng.blob(64);
        hammer(&data);
    }
}

#[test]
fn decoders_survive_long_random_input() {
    let mut rng = Rng(0xDEAD_BEEF_0000_1111);
    for _ in 0..3_000 {
        let data = rng.blob(2048);
        hammer(&data);
    }
}

#[test]
fn decoders_survive_truncation_of_valid_packets() {
    // Truncation is the most common real-world malformation: a peer that dies
    // mid-write, or an attacker probing for off-by-one reads.
    let mut valid: Vec<Vec<u8>> = Vec::new();

    valid.push(
        HandshakePacket {
            protocol_version: 769,
            server_address: "mc.example.com".into(),
            server_port: 25565,
            next_state: 2,
        }
        .encode(),
    );
    valid.push(
        LoginStart {
            username: "Notch".into(),
            uuid: flow_proxy::protocol::login::offline_uuid("Notch"),
        }
        .encode(),
    );
    valid.push(
        LoginSuccess {
            uuid: flow_proxy::protocol::login::offline_uuid("Notch"),
            username: "Notch".into(),
            properties: vec![flow_proxy::protocol::login::ProfileProperty {
                name: "textures".into(),
                value: "x".into(),
                signature: Some("s".into()),
            }],
        }
        .encode(),
    );
    valid.push(
        LoginPluginRequest {
            message_id: 7,
            channel: "velocity:player_info".into(),
            data: vec![1, 2, 3],
        }
        .encode(),
    );
    valid.push(BungeeMessage::connect_request("lobby"));

    for packet in &valid {
        for cut in 0..=packet.len() {
            hammer(&packet[..cut]);
        }
    }
}

#[test]
fn decoders_survive_bit_flips_in_valid_packets() {
    let base = HandshakePacket {
        protocol_version: 769,
        server_address: "mc.example.com".into(),
        server_port: 25565,
        next_state: 2,
    }
    .encode();

    let mut rng = Rng(0x1234_5678_9ABC_DEF0);
    for _ in 0..20_000 {
        let mut data = base.clone();
        let flips = 1 + rng.below(4);
        for _ in 0..flips {
            let idx = rng.below(data.len());
            data[idx] = rng.spicy_byte();
        }
        hammer(&data);
    }
}

#[tokio::test]
async fn frame_reader_survives_random_streams() {
    let mut rng = Rng(0xA5A5_5A5A_1234_9999);
    for _ in 0..4_000 {
        let data = rng.blob(512);

        let mut reader = FrameReader::new(&data[..]);
        let _ = reader.read_frame().await;

        // Again with compression enabled, which adds the data_length field and
        // the inflate path.
        let mut reader = FrameReader::new(&data[..]);
        reader.set_threshold(256);
        let _ = reader.read_frame().await;
    }
}

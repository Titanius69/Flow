//! End-to-end login test: a mock 1.21.4 client connects through the proxy to a
//! mock Paper backend that uses compression and Velocity modern forwarding.
//!
//! This is the scenario that used to fail: the client never got past login.

use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};

use flow_proxy::config::{BackendConfig, Config};
use flow_proxy::protocol::connection::{FrameReader, FrameWriter};
use flow_proxy::protocol::forwarding::{verify_forwarding_payload, VELOCITY_CHANNEL};
use flow_proxy::protocol::handshake::HandshakePacket;
use flow_proxy::protocol::login::{
    self as login, offline_uuid, LoginStart, LoginSuccess, ProfileProperty,
};
use flow_proxy::protocol::packet::RawPacket;
use flow_proxy::protocol::types::{read_string, write_string};
use flow_proxy::protocol::varint::{read_varint, write_varint};
use flow_proxy::session::ClientSession;

const SECRET: &str = "super-secret-velocity-key";
const BACKEND_THRESHOLD: i32 = 256;
const CLIENT_THRESHOLD: i32 = 128;
const PROTOCOL: i32 = 769;

/// Every test is wrapped in this. A regression that stalls the handshake -- the
/// original symptom -- must fail the suite quickly instead of hanging it.
async fn within<F: std::future::Future>(fut: F) -> F::Output {
    match tokio::time::timeout(std::time::Duration::from_secs(10), fut).await {
        Ok(v) => v,
        Err(_) => panic!("timed out: the login sequence stalled"),
    }
}

/// What the mock backend observed, so the test can assert on it.
struct BackendObservation {
    handshake_protocol: i32,
    handshake_vhost: String,
    login_start_username: String,
    forwarded_version: i32,
    forwarded_username: String,
    forwarded_uuid: uuid::Uuid,
    forwarded_address: String,
    got_login_acknowledged: bool,
    config_echo: Vec<u8>,
}

/// A stand-in for Paper with `network-compression-threshold=256` and Velocity
/// modern forwarding enabled.
async fn mock_backend(listener: TcpListener) -> anyhow::Result<BackendObservation> {
    let (stream, _) = listener.accept().await?;
    let (rh, wh) = stream.into_split();
    let mut reader = FrameReader::new(rh);
    let mut writer = FrameWriter::new(wh);

    // Handshake
    let packet = reader.read_packet().await?;
    assert_eq!(packet.id, 0x00, "expected handshake");
    let (handshake, _) = HandshakePacket::decode(&packet.data)?;

    // Login Start
    let packet = reader.read_packet().await?;
    assert_eq!(packet.id, login::SB_LOGIN_START);
    let login_start = LoginStart::decode(&packet.data)?;

    // Set Compression, then switch our own framing.
    writer
        .write_packet(&RawPacket::new(
            login::CB_SET_COMPRESSION,
            login::SetCompression {
                threshold: BACKEND_THRESHOLD,
            }
            .encode(),
        ))
        .await?;
    writer.set_threshold(BACKEND_THRESHOLD);
    reader.set_threshold(BACKEND_THRESHOLD);

    // Ask for forwarding data, advertising version 4 like a modern Paper does.
    let request = login::LoginPluginRequest {
        message_id: 99,
        channel: VELOCITY_CHANNEL.to_string(),
        data: vec![4],
    };
    writer
        .write_packet(&RawPacket::new(
            login::CB_LOGIN_PLUGIN_REQUEST,
            request.encode(),
        ))
        .await?;

    // Login Plugin Response
    let packet = reader.read_packet().await?;
    assert_eq!(packet.id, login::SB_LOGIN_PLUGIN_RESPONSE);
    let (message_id, mut offset) = read_varint(&packet.data)?;
    assert_eq!(message_id, 99, "message id must be echoed back");
    let successful = packet.data[offset] != 0;
    offset += 1;
    assert!(successful, "proxy must answer the velocity channel");

    // Verify exactly as Paper would: HMAC first, then the profile.
    let forwarded = verify_forwarding_payload(SECRET.as_bytes(), &packet.data[offset..])
        .expect("HMAC must validate against the shared secret");
    let (forwarded_version, _) = read_varint(&packet.data[offset + 32..])?;

    // Login Success, using the forwarded identity, plus a skin property so we
    // can prove properties survive the hop.
    let success = LoginSuccess {
        uuid: forwarded.player_uuid,
        username: forwarded.username.clone(),
        properties: vec![ProfileProperty {
            name: "textures".into(),
            value: "backend-supplied".into(),
            signature: None,
        }],
    };
    writer
        .write_packet(&RawPacket::new(login::CB_LOGIN_SUCCESS, success.encode()))
        .await?;

    // Login Acknowledged: the backend cannot enter Configuration without it.
    let packet = reader.read_packet().await?;
    let got_login_acknowledged = packet.id == login::SB_LOGIN_ACKNOWLEDGED;

    // A Configuration-state exchange. Deliberately larger than the client's
    // threshold but handled under ours, to exercise recompression both ways.
    let big = vec![0x5A; 1000];
    let mut payload = Vec::new();
    write_string(&mut payload, "flow:test");
    payload.extend_from_slice(&big);
    writer
        .write_packet(&RawPacket::new(0x01, payload))
        .await?;

    let echoed = reader.read_packet().await?;

    Ok(BackendObservation {
        handshake_protocol: handshake.protocol_version,
        handshake_vhost: handshake.server_address,
        login_start_username: login_start.username,
        forwarded_version,
        forwarded_username: forwarded.username,
        forwarded_uuid: forwarded.player_uuid,
        forwarded_address: forwarded.client_address,
        got_login_acknowledged,
        config_echo: echoed.data,
    })
}

#[tokio::test]
async fn client_reaches_play_through_the_proxy() {
    within(async {
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend_listener.local_addr().unwrap();
    let backend = tokio::spawn(mock_backend(backend_listener));

    let config = Arc::new(Config {
        bind: "127.0.0.1:0".into(),
        motd: "test".into(),
        max_players: 20,
        protocol_version: PROTOCOL,
        version_name: "1.21.4".into(),
        backend: BackendConfig {
            address: backend_addr.to_string(),
        },
        forwarding_secret: SECRET.into(),
        compression_threshold: CLIENT_THRESHOLD,
    });

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, addr) = proxy_listener.accept().await.unwrap();
        ClientSession::new(stream, addr, config).run().await;
    });

    // ---- mock client ----
    let stream = TcpStream::connect(proxy_addr).await.unwrap();
    let (rh, wh) = stream.into_split();
    let mut reader = FrameReader::new(rh);
    let mut writer = FrameWriter::new(wh);

    let handshake = HandshakePacket {
        protocol_version: PROTOCOL,
        server_address: "mc.example.com".into(),
        server_port: 25565,
        next_state: 2,
    };
    writer
        .write_packet(&RawPacket::new(0x00, handshake.encode()))
        .await
        .unwrap();

    let start = LoginStart {
        username: "Notch".into(),
        uuid: offline_uuid("Notch"),
    };
    writer
        .write_packet(&RawPacket::new(login::SB_LOGIN_START, start.encode()))
        .await
        .unwrap();

    // Set Compression must arrive before Login Success.
    let packet = reader.read_packet().await.unwrap();
    assert_eq!(
        packet.id,
        login::CB_SET_COMPRESSION,
        "proxy should offer compression first"
    );
    let threshold = login::SetCompression::decode(&packet.data).unwrap().threshold;
    assert_eq!(threshold, CLIENT_THRESHOLD);
    reader.set_threshold(threshold);
    writer.set_threshold(threshold);

    // Login Success must be 0x02, not 0x03.
    let packet = reader.read_packet().await.unwrap();
    assert_eq!(
        packet.id,
        login::CB_LOGIN_SUCCESS,
        "Login Success must use packet id 0x02"
    );
    let success = LoginSuccess::decode(&packet.data).unwrap();
    assert_eq!(success.username, "Notch");
    assert_eq!(success.uuid, offline_uuid("Notch"));
    assert_eq!(
        success.properties.len(),
        1,
        "profile properties from the backend should reach the client"
    );
    assert_eq!(success.properties[0].value, "backend-supplied");

    writer
        .write_packet(&RawPacket::new(login::SB_LOGIN_ACKNOWLEDGED, Vec::new()))
        .await
        .unwrap();

    // Configuration state: receive the backend's large frame, echo it back.
    let packet = reader.read_packet().await.unwrap();
    assert_eq!(packet.id, 0x01);
    let (channel, offset) = read_string(&packet.data).unwrap();
    assert_eq!(channel, "flow:test");
    assert_eq!(
        &packet.data[offset..],
        &vec![0x5A; 1000][..],
        "payload must survive decompress/recompress across the proxy"
    );

    let mut echo = Vec::new();
    write_varint(&mut echo, 4321);
    echo.extend_from_slice(&vec![0x77; 900]);
    writer
        .write_packet(&RawPacket::new(0x02, echo))
        .await
        .unwrap();

    // ---- assertions on what the backend saw ----
    let observed = backend.await.unwrap().unwrap();

    assert_eq!(
        observed.handshake_protocol, PROTOCOL,
        "the client's protocol version must be mirrored to the backend"
    );
    assert_eq!(
        observed.handshake_vhost, "mc.example.com",
        "the original vhost should be forwarded"
    );
    assert_eq!(observed.login_start_username, "Notch");
    assert_eq!(
        observed.forwarded_version, 1,
        "without player key material the proxy must fall back to forwarding v1"
    );
    assert_eq!(observed.forwarded_username, "Notch");
    assert_eq!(observed.forwarded_uuid, offline_uuid("Notch"));
    assert_eq!(observed.forwarded_address, "127.0.0.1");
    assert!(
        observed.got_login_acknowledged,
        "the proxy must send Login Acknowledged or the backend never leaves Login state"
    );

    let (echo_id, off) = read_varint(&observed.config_echo).unwrap();
    assert_eq!(echo_id, 4321);
    assert_eq!(&observed.config_echo[off..], &vec![0x77; 900][..]);
    })
    .await;
}

/// A wrong secret must surface as a clean, explained disconnect rather than a
/// dead socket.
#[tokio::test]
async fn mismatched_secret_disconnects_with_a_reason() {
    within(async {
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend_listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (stream, _) = backend_listener.accept().await.unwrap();
        let (rh, wh) = stream.into_split();
        let mut reader = FrameReader::new(rh);
        let mut writer = FrameWriter::new(wh);

        let _ = reader.read_packet().await.unwrap(); // handshake
        let _ = reader.read_packet().await.unwrap(); // login start

        let request = login::LoginPluginRequest {
            message_id: 1,
            channel: VELOCITY_CHANNEL.to_string(),
            data: vec![4],
        };
        writer
            .write_packet(&RawPacket::new(
                login::CB_LOGIN_PLUGIN_REQUEST,
                request.encode(),
            ))
            .await
            .unwrap();

        let response = reader.read_packet().await.unwrap();
        let (_, mut offset) = read_varint(&response.data).unwrap();
        offset += 1;
        // Paper checks the HMAC and kicks when it fails.
        assert!(verify_forwarding_payload(b"the-real-secret", &response.data[offset..]).is_err());

        writer
            .write_packet(&RawPacket::new(
                login::CB_DISCONNECT,
                login::LoginDisconnect::encode_text("Invalid proxy response!"),
            ))
            .await
            .unwrap();
    });

    let config = Arc::new(Config {
        bind: "127.0.0.1:0".into(),
        motd: "test".into(),
        max_players: 20,
        protocol_version: PROTOCOL,
        version_name: "1.21.4".into(),
        backend: BackendConfig {
            address: backend_addr.to_string(),
        },
        forwarding_secret: "wrong-secret".into(),
        compression_threshold: -1,
    });

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, addr) = proxy_listener.accept().await.unwrap();
        ClientSession::new(stream, addr, config).run().await;
    });

    let stream = TcpStream::connect(proxy_addr).await.unwrap();
    let (rh, wh) = stream.into_split();
    let mut reader = FrameReader::new(rh);
    let mut writer = FrameWriter::new(wh);

    let handshake = HandshakePacket {
        protocol_version: PROTOCOL,
        server_address: "localhost".into(),
        server_port: 25565,
        next_state: 2,
    };
    writer
        .write_packet(&RawPacket::new(0x00, handshake.encode()))
        .await
        .unwrap();
    writer
        .write_packet(&RawPacket::new(
            login::SB_LOGIN_START,
            LoginStart {
                username: "Notch".into(),
                uuid: offline_uuid("Notch"),
            }
            .encode(),
        ))
        .await
        .unwrap();

    let packet = reader.read_packet().await.unwrap();
    assert_eq!(
        packet.id,
        login::CB_DISCONNECT,
        "the client should receive a Login Disconnect"
    );
    let reason = read_string(&packet.data).unwrap().0;
    assert!(
        reason.contains("Invalid proxy response"),
        "the backend's reason should be surfaced, got: {}",
        reason
    );
    })
    .await;
}

/// The server list ping must still work.
#[tokio::test]
async fn status_ping_works() {
    within(async {
    let config = Arc::new(Config {
        bind: "127.0.0.1:0".into(),
        motd: "Flow test MOTD".into(),
        max_players: 42,
        protocol_version: PROTOCOL,
        version_name: "1.21.4".into(),
        backend: BackendConfig {
            address: "127.0.0.1:1".into(),
        },
        forwarding_secret: SECRET.into(),
        compression_threshold: 256,
    });

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, addr) = proxy_listener.accept().await.unwrap();
        ClientSession::new(stream, addr, config).run().await;
    });

    let stream = TcpStream::connect(proxy_addr).await.unwrap();
    let (rh, wh) = stream.into_split();
    let mut reader = FrameReader::new(rh);
    let mut writer = FrameWriter::new(wh);

    let handshake = HandshakePacket {
        protocol_version: PROTOCOL,
        server_address: "localhost".into(),
        server_port: 25565,
        next_state: 1,
    };
    writer
        .write_packet(&RawPacket::new(0x00, handshake.encode()))
        .await
        .unwrap();
    writer
        .write_packet(&RawPacket::new(0x00, Vec::new()))
        .await
        .unwrap();

    let packet = reader.read_packet().await.unwrap();
    assert_eq!(packet.id, 0x00);
    let json = read_string(&packet.data).unwrap().0;
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["version"]["protocol"], PROTOCOL);
    assert_eq!(value["version"]["name"], "1.21.4");
    assert_eq!(value["players"]["max"], 42);
    assert_eq!(value["description"]["text"], "Flow test MOTD");

    // Ping / Pong
    let mut ping = Vec::new();
    ping.extend_from_slice(&1234567890i64.to_be_bytes());
    writer
        .write_packet(&RawPacket::new(0x01, ping))
        .await
        .unwrap();
    let packet = reader.read_packet().await.unwrap();
    assert_eq!(packet.id, 0x01);
    assert_eq!(
        i64::from_be_bytes(packet.data[..8].try_into().unwrap()),
        1234567890
    );
    })
    .await;
}

//! End-to-end tests driving the proxy with a mock 1.21.4 client and mock Paper
//! backends: login, forced-host routing, failover, runtime server switching and
//! the HAProxy PROXY protocol.
//!
//! The Configuration and Play packet IDs used here come from the same
//! version-pinned table the proxy uses, so these tests verify sequencing and
//! state tracking. They cannot verify that the IDs themselves are right for
//! 1.21.4 — only a real client can.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use flow_proxy::config::{Advanced, Config, ServersSection};
use flow_proxy::haproxy;
use flow_proxy::protocol::connection::{FrameReader, FrameWriter};
use flow_proxy::protocol::forwarding::{verify_forwarding_payload, ForwardingData, VELOCITY_CHANNEL};
use flow_proxy::protocol::handshake::HandshakePacket;
use flow_proxy::protocol::login::{self as login, offline_uuid, LoginStart, LoginSuccess};
use flow_proxy::protocol::packet::RawPacket;
use flow_proxy::protocol::packets::{config_serverbound, play_clientbound, play_serverbound};
use flow_proxy::protocol::plugin_message::{self as bungee, BungeeMessage};
use flow_proxy::protocol::types::read_string;
use flow_proxy::protocol::varint::read_varint;
use flow_proxy::registry::Registry;
use flow_proxy::session::{ClientSession, ProxyContext};

const SECRET: &str = "super-secret-velocity-key";
const PROTOCOL: i32 = 769;
/// Clientbound Finish Configuration in the Configuration state.
const CB_FINISH_CONFIGURATION: i32 = 0x03;

/// Wraps a test body so a stall fails the suite quickly instead of hanging it.
async fn within<F: std::future::Future>(fut: F) -> F::Output {
    match tokio::time::timeout(Duration::from_secs(15), fut).await {
        Ok(v) => v,
        Err(_) => panic!("timed out: the proxy stopped making progress"),
    }
}

// ---------------------------------------------------------------- config setup

fn config(
    servers: &[(&str, &str)],
    try_order: &[&str],
    forced: &[(&str, &[&str])],
    compression: i32,
) -> Arc<Config> {
    let mut c = Config::default();
    c.bind = "127.0.0.1:0".into();
    c.motd = "Flow test MOTD".into();
    c.show_max_players = 42;
    c.protocol_version = PROTOCOL;
    c.version_name = "1.21.4".into();
    c.servers = ServersSection {
        try_order: try_order.iter().map(|s| s.to_string()).collect(),
        servers: servers
            .iter()
            .map(|(n, a)| (n.to_string(), a.to_string()))
            .collect(),
    };
    c.forced_hosts = forced
        .iter()
        .map(|(h, names)| {
            (
                h.to_string(),
                names.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            )
        })
        .collect();
    c.advanced = Advanced {
        compression_threshold: compression,
        // Every test connects from 127.0.0.1, so the per-address limits would
        // throttle the suite against itself. They get their own tests.
        login_ratelimit: 0,
        connections_per_ip: 0,
        ..Advanced::default()
    };
    Arc::new(c.with_secret(SECRET))
}

/// Starts the proxy on an ephemeral port, serving `connections` clients.
async fn start_proxy(config: Arc<Config>, connections: usize) -> SocketAddr {
    start_proxy_ctx(config, connections).await.0
}

/// As above, but also hands back the shared context so a test can inspect the
/// registry.
async fn start_proxy_ctx(
    config: Arc<Config>,
    connections: usize,
) -> (SocketAddr, Arc<ProxyContext>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let enabled = config.advanced.haproxy_protocol;
    let ctx = ProxyContext::new(config);
    let accept_ctx = Arc::clone(&ctx);

    tokio::spawn(async move {
        for _ in 0..connections {
            let (stream, peer) = listener.accept().await.unwrap();
            let ctx = Arc::clone(&accept_ctx);
            let guard = ctx.limiter.accept(peer.ip()).ok();
            tokio::spawn(async move {
                if let Ok(Some((stream, addr))) =
                    haproxy::resolve_client_address(stream, peer, enabled).await
                {
                    ClientSession::with_guard(stream, addr, ctx, guard)
                        .run()
                        .await;
                }
            });
        }
    });

    (addr, ctx)
}

/// Waits for a condition on the shared state, so tests do not race the session
/// tasks that update it.
async fn eventually(mut check: impl FnMut() -> bool) -> bool {
    for _ in 0..200 {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

// --------------------------------------------------------------- mock backend

struct BackendSide {
    reader: FrameReader<OwnedReadHalf>,
    writer: FrameWriter<OwnedWriteHalf>,
    forwarded: ForwardingData,
    handshake_protocol: i32,
    handshake_vhost: String,
}

/// Plays the part of Paper through the login sequence, then hands back the
/// connection so each test can script what happens next.
async fn backend_login(listener: &TcpListener, compression: Option<i32>) -> BackendSide {
    let (stream, _) = listener.accept().await.unwrap();
    let (rh, wh) = stream.into_split();
    let mut reader = FrameReader::new(rh);
    let mut writer = FrameWriter::new(wh);

    let packet = reader.read_packet().await.unwrap();
    assert_eq!(packet.id, 0x00, "expected handshake");
    let (handshake, _) = HandshakePacket::decode(&packet.data).unwrap();

    let packet = reader.read_packet().await.unwrap();
    assert_eq!(packet.id, login::SB_LOGIN_START);
    let _login_start = LoginStart::decode(&packet.data).unwrap();

    if let Some(threshold) = compression {
        writer
            .write_packet(&RawPacket::new(
                login::CB_SET_COMPRESSION,
                login::SetCompression { threshold }.encode(),
            ))
            .await
            .unwrap();
        writer.set_threshold(threshold);
        reader.set_threshold(threshold);
    }

    // Ask for forwarding data, advertising version 4 like a modern Paper does.
    writer
        .write_packet(&RawPacket::new(
            login::CB_LOGIN_PLUGIN_REQUEST,
            login::LoginPluginRequest {
                message_id: 99,
                channel: VELOCITY_CHANNEL.to_string(),
                data: vec![4],
            }
            .encode(),
        ))
        .await
        .unwrap();

    let packet = reader.read_packet().await.unwrap();
    assert_eq!(packet.id, login::SB_LOGIN_PLUGIN_RESPONSE);
    let (message_id, mut offset) = read_varint(&packet.data).unwrap();
    assert_eq!(message_id, 99, "message id must be echoed back");
    let successful = packet.data[offset] != 0;
    offset += 1;
    assert!(successful, "proxy must answer the velocity channel");

    let forwarded = verify_forwarding_payload(SECRET.as_bytes(), &packet.data[offset..])
        .expect("HMAC must validate against the shared secret");

    writer
        .write_packet(&RawPacket::new(
            login::CB_LOGIN_SUCCESS,
            LoginSuccess {
                uuid: forwarded.player_uuid,
                username: forwarded.username.clone(),
                properties: Vec::new(),
            }
            .encode(),
        ))
        .await
        .unwrap();

    let packet = reader.read_packet().await.unwrap();
    assert_eq!(
        packet.id,
        login::SB_LOGIN_ACKNOWLEDGED,
        "the proxy must acknowledge or the backend never leaves Login state"
    );

    BackendSide {
        reader,
        writer,
        forwarded,
        handshake_protocol: handshake.protocol_version,
        handshake_vhost: handshake.server_address,
    }
}

/// Refuses the login at the first opportunity, like a full or restarting server.
async fn backend_refuse(listener: &TcpListener, reason: &str) {
    let (stream, _) = listener.accept().await.unwrap();
    let (rh, wh) = stream.into_split();
    let mut reader = FrameReader::new(rh);
    let mut writer = FrameWriter::new(wh);

    reader.read_packet().await.unwrap(); // handshake
    reader.read_packet().await.unwrap(); // login start

    writer
        .write_packet(&RawPacket::new(
            login::CB_DISCONNECT,
            login::LoginDisconnect::encode_text(reason),
        ))
        .await
        .unwrap();
}

// ---------------------------------------------------------------- mock client

struct ClientSide {
    reader: FrameReader<OwnedReadHalf>,
    writer: FrameWriter<OwnedWriteHalf>,
    success: LoginSuccess,
    /// Frames read while looking for a different packet id. Kept rather than
    /// discarded, so a later `read_until` can still find them regardless of the
    /// order the backend happened to send them in.
    pending: Vec<RawPacket>,
}

impl ClientSide {
    /// Reads frames until one with `id` arrives, returning its payload.
    async fn read_until(&mut self, id: i32) -> Vec<u8> {
        if let Some(pos) = self.pending.iter().position(|p| p.id == id) {
            return self.pending.remove(pos).data;
        }
        for _ in 0..64 {
            let packet = self.reader.read_packet().await.unwrap();
            if packet.id == id {
                return packet.data;
            }
            self.pending.push(packet);
        }
        panic!("packet 0x{:02X} never arrived", id);
    }

    /// Answers the server's Finish Configuration, entering Play state.
    async fn finish_configuration(&mut self) {
        self.read_until(CB_FINISH_CONFIGURATION).await;
        self.writer
            .write_packet(&RawPacket::new(
                config_serverbound::FINISH_CONFIGURATION,
                Vec::new(),
            ))
            .await
            .unwrap();
    }

    async fn send_command(&mut self, command: &str) {
        let mut payload = Vec::new();
        flow_proxy::protocol::types::write_string(&mut payload, command);
        self.writer
            .write_packet(&RawPacket::new(play_serverbound::CHAT_COMMAND, payload))
            .await
            .unwrap();
    }

    /// Plays the client half of a server switch.
    async fn accept_configuration_switch(&mut self) {
        self.read_until(play_clientbound::START_CONFIGURATION).await;
        self.writer
            .write_packet(&RawPacket::new(
                play_serverbound::CONFIGURATION_ACKNOWLEDGED,
                Vec::new(),
            ))
            .await
            .unwrap();
    }
}

async fn client_login(proxy: SocketAddr, username: &str, vhost: &str, prefix: &[u8]) -> ClientSide {
    let mut stream = TcpStream::connect(proxy).await.unwrap();

    if !prefix.is_empty() {
        use tokio::io::AsyncWriteExt;
        // A PROXY protocol header goes ahead of the handshake, unframed, so it
        // is written straight to the socket before any packet framing starts.
        stream.write_all(prefix).await.unwrap();
    }

    let (rh, wh) = stream.into_split();
    let mut reader = FrameReader::new(rh);
    let mut writer = FrameWriter::new(wh);

    writer
        .write_packet(&RawPacket::new(
            0x00,
            HandshakePacket {
                protocol_version: PROTOCOL,
                server_address: vhost.into(),
                server_port: 25565,
                next_state: 2,
            }
            .encode(),
        ))
        .await
        .unwrap();

    writer
        .write_packet(&RawPacket::new(
            login::SB_LOGIN_START,
            LoginStart {
                username: username.into(),
                uuid: offline_uuid(username),
            }
            .encode(),
        ))
        .await
        .unwrap();

    // Set Compression, if the proxy offers it, then Login Success.
    let mut packet = reader.read_packet().await.unwrap();
    if packet.id == login::CB_SET_COMPRESSION {
        let threshold = login::SetCompression::decode(&packet.data).unwrap().threshold;
        reader.set_threshold(threshold);
        writer.set_threshold(threshold);
        packet = reader.read_packet().await.unwrap();
    }

    assert_eq!(
        packet.id,
        login::CB_LOGIN_SUCCESS,
        "Login Success must use packet id 0x02"
    );
    let success = LoginSuccess::decode(&packet.data).unwrap();

    writer
        .write_packet(&RawPacket::new(login::SB_LOGIN_ACKNOWLEDGED, Vec::new()))
        .await
        .unwrap();

    ClientSide {
        reader,
        writer,
        success,
        pending: Vec::new(),
    }
}

// --------------------------------------------------------------------- tests

#[tokio::test]
async fn login_reaches_the_backend_through_the_proxy() {
    within(async {
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let task = tokio::spawn(async move { backend_login(&backend, Some(256)).await });

        let cfg = config(
            &[("lobby", &backend_addr.to_string())],
            &["lobby"],
            &[],
            128,
        );
        let proxy = start_proxy(cfg, 1).await;

        let client = client_login(proxy, "Notch", "mc.example.com", &[]).await;
        assert_eq!(client.success.username, "Notch");
        assert_eq!(client.success.uuid, offline_uuid("Notch"));

        let observed = task.await.unwrap();
        assert_eq!(observed.handshake_protocol, PROTOCOL);
        assert_eq!(observed.handshake_vhost, "mc.example.com");
        assert_eq!(observed.forwarded.username, "Notch");
        assert_eq!(observed.forwarded.player_uuid, offline_uuid("Notch"));
        assert_eq!(observed.forwarded.client_address, "127.0.0.1");
    })
    .await;
}

#[tokio::test]
async fn forced_host_overrides_the_try_order() {
    within(async {
        let lobby = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let survival = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let lobby_addr = lobby.local_addr().unwrap().to_string();
        let survival_addr = survival.local_addr().unwrap().to_string();

        // Only the survival backend is scripted. If routing picks lobby the
        // test times out rather than quietly passing.
        let task = tokio::spawn(async move { backend_login(&survival, None).await });

        let cfg = config(
            &[("lobby", &lobby_addr), ("survival", &survival_addr)],
            &["lobby"],
            &[("survival.example.com", &["survival"])],
            -1,
        );
        let proxy = start_proxy(cfg, 1).await;

        client_login(proxy, "Notch", "survival.example.com", &[]).await;

        let observed = task.await.unwrap();
        assert_eq!(observed.forwarded.username, "Notch");
        drop(lobby);
    })
    .await;
}

#[tokio::test]
async fn failover_moves_on_when_the_first_backend_refuses() {
    within(async {
        let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let first_addr = first.local_addr().unwrap().to_string();
        let second_addr = second.local_addr().unwrap().to_string();

        let refuse = tokio::spawn(async move { backend_refuse(&first, "Server is full!").await });
        let accept = tokio::spawn(async move { backend_login(&second, None).await });

        let cfg = config(
            &[("full", &first_addr), ("backup", &second_addr)],
            &["full", "backup"],
            &[],
            -1,
        );
        let proxy = start_proxy(cfg, 1).await;

        let client = client_login(proxy, "Notch", "mc.example.com", &[]).await;
        assert_eq!(client.success.username, "Notch");

        refuse.await.unwrap();
        let observed = accept.await.unwrap();
        assert_eq!(observed.forwarded.username, "Notch");
    })
    .await;
}

#[tokio::test]
async fn all_backends_refusing_kicks_with_a_reason() {
    within(async {
        let only = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let only_addr = only.local_addr().unwrap().to_string();
        tokio::spawn(async move { backend_refuse(&only, "Invalid proxy response!").await });

        let cfg = config(&[("lobby", &only_addr)], &["lobby"], &[], -1);
        let proxy = start_proxy(cfg, 1).await;

        let stream = TcpStream::connect(proxy).await.unwrap();
        let (rh, wh) = stream.into_split();
        let mut reader = FrameReader::new(rh);
        let mut writer = FrameWriter::new(wh);

        writer
            .write_packet(&RawPacket::new(
                0x00,
                HandshakePacket {
                    protocol_version: PROTOCOL,
                    server_address: "mc.example.com".into(),
                    server_port: 25565,
                    next_state: 2,
                }
                .encode(),
            ))
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
        assert_eq!(packet.id, login::CB_DISCONNECT);
        let reason = read_string(&packet.data).unwrap().0;
        assert!(
            reason.contains("Invalid proxy response"),
            "the backend's reason should be surfaced, got: {}",
            reason
        );
    })
    .await;
}

#[tokio::test]
async fn server_command_switches_the_backend() {
    within(async {
        let lobby = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let survival = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let lobby_addr = lobby.local_addr().unwrap().to_string();
        let survival_addr = survival.local_addr().unwrap().to_string();

        let lobby_task = tokio::spawn(async move {
            let mut side = backend_login(&lobby, Some(256)).await;
            // Move the player into Play so /server can be used.
            side.writer
                .write_packet(&RawPacket::new(CB_FINISH_CONFIGURATION, Vec::new()))
                .await
                .unwrap();
            // Keep reading until the proxy drops us during the switch.
            let mut frames = 0;
            while side.reader.read_frame().await.is_ok() {
                frames += 1;
            }
            frames
        });

        let survival_task = tokio::spawn(async move {
            let mut side = backend_login(&survival, Some(64)).await;
            side.writer
                .write_packet(&RawPacket::new(CB_FINISH_CONFIGURATION, Vec::new()))
                .await
                .unwrap();
            // A distinctive Play packet proving the client is now talking to us.
            side.writer
                .write_packet(&RawPacket::new(0x42, b"HELLO-FROM-SURVIVAL".to_vec()))
                .await
                .unwrap();
            side
        });

        let cfg = config(
            &[("lobby", &lobby_addr), ("survival", &survival_addr)],
            &["lobby"],
            &[],
            128,
        );
        let proxy = start_proxy(cfg, 1).await;

        let mut client = client_login(proxy, "Notch", "mc.example.com", &[]).await;

        // Configuration -> Play on the lobby.
        client.finish_configuration().await;

        client.send_command("server survival").await;

        // The proxy should now ask us to reconfigure.
        client.accept_configuration_switch().await;

        // The survival backend's configuration sequence now flows through.
        client.finish_configuration().await;

        let payload = client.read_until(0x42).await;
        assert_eq!(
            payload, b"HELLO-FROM-SURVIVAL",
            "the client should be receiving the new backend's packets"
        );

        // The old backend must have been dropped.
        let lobby_frames = lobby_task.await.unwrap();
        assert!(
            lobby_frames < 1000,
            "the lobby connection should have been closed, not kept relaying"
        );

        let survival = survival_task.await.unwrap();
        assert_eq!(survival.forwarded.username, "Notch");
        assert_eq!(
            survival.forwarded.player_uuid,
            offline_uuid("Notch"),
            "the same identity must be forwarded to the new backend"
        );
    })
    .await;
}

#[tokio::test]
async fn switching_to_an_unknown_server_keeps_the_player_put() {
    within(async {
        let lobby = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let lobby_addr = lobby.local_addr().unwrap().to_string();

        let lobby_task = tokio::spawn(async move {
            let mut side = backend_login(&lobby, None).await;
            side.writer
                .write_packet(&RawPacket::new(CB_FINISH_CONFIGURATION, Vec::new()))
                .await
                .unwrap();
            // After the failed switch the player is still ours, so we can still
            // reach them.
            side.writer
                .write_packet(&RawPacket::new(0x42, b"STILL-HERE".to_vec()))
                .await
                .unwrap();
            side
        });

        let cfg = config(&[("lobby", &lobby_addr)], &["lobby"], &[], -1);
        let proxy = start_proxy(cfg, 1).await;

        let mut client = client_login(proxy, "Notch", "mc.example.com", &[]).await;
        client.finish_configuration().await;

        client.send_command("server nosuchserver").await;

        // An error message, and no Start Configuration.
        let payload = client.read_until(play_clientbound::SYSTEM_CHAT).await;
        // Payload is a nameless NBT string component.
        assert_eq!(payload[0], 0x08, "system chat carries an NBT component");
        let len = u16::from_be_bytes([payload[1], payload[2]]) as usize;
        let text = std::str::from_utf8(&payload[3..3 + len]).unwrap();
        assert!(
            text.contains("nosuchserver"),
            "the player should be told which server failed, got: {}",
            text
        );

        let payload = client.read_until(0x42).await;
        assert_eq!(payload, b"STILL-HERE");

        lobby_task.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn unrelated_commands_are_passed_through() {
    within(async {
        let lobby = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let lobby_addr = lobby.local_addr().unwrap().to_string();

        let lobby_task = tokio::spawn(async move {
            let mut side = backend_login(&lobby, None).await;
            side.writer
                .write_packet(&RawPacket::new(CB_FINISH_CONFIGURATION, Vec::new()))
                .await
                .unwrap();

            // The client's finish-configuration ack, then the command.
            loop {
                let packet = side.reader.read_packet().await.unwrap();
                if packet.id == play_serverbound::CHAT_COMMAND {
                    return read_string(&packet.data).unwrap().0;
                }
            }
        });

        let cfg = config(&[("lobby", &lobby_addr)], &["lobby"], &[], -1);
        let proxy = start_proxy(cfg, 1).await;

        let mut client = client_login(proxy, "Notch", "mc.example.com", &[]).await;
        client.finish_configuration().await;
        client.send_command("gamemode creative").await;

        let seen = lobby_task.await.unwrap();
        assert_eq!(
            seen, "gamemode creative",
            "only /server is the proxy's business"
        );
    })
    .await;
}

#[tokio::test]
async fn haproxy_v2_client_address_reaches_the_backend() {
    within(async {
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap().to_string();
        let task = tokio::spawn(async move { backend_login(&backend, None).await });

        let mut cfg = Config::default();
        cfg.bind = "127.0.0.1:0".into();
        cfg.protocol_version = PROTOCOL;
        cfg.servers = ServersSection {
            try_order: vec!["lobby".into()],
            servers: [("lobby".to_string(), backend_addr)].into_iter().collect(),
        };
        cfg.advanced = Advanced {
            compression_threshold: -1,
            haproxy_protocol: true,
            login_ratelimit: 0,
            connections_per_ip: 0,
            ..Advanced::default()
        };
        let cfg = Arc::new(cfg.with_secret(SECRET));

        let proxy = start_proxy(cfg, 1).await;

        // A PROXY v2 header claiming the player is at 203.0.113.7.
        let mut header = vec![
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
        ];
        header.push(0x21); // version 2, PROXY
        header.push(0x11); // AF_INET, STREAM
        let mut body = Vec::new();
        body.extend_from_slice(&[203, 0, 113, 7]);
        body.extend_from_slice(&[10, 0, 0, 1]);
        body.extend_from_slice(&51234u16.to_be_bytes());
        body.extend_from_slice(&25565u16.to_be_bytes());
        header.extend_from_slice(&(body.len() as u16).to_be_bytes());
        header.extend_from_slice(&body);

        client_login(proxy, "Notch", "mc.example.com", &header).await;

        let observed = task.await.unwrap();
        assert_eq!(
            observed.forwarded.client_address, "203.0.113.7",
            "the real client address must be forwarded, not the balancer's"
        );
    })
    .await;
}

#[tokio::test]
async fn status_ping_works() {
    within(async {
        let cfg = config(&[("lobby", "127.0.0.1:1")], &["lobby"], &[], 256);
        let proxy = start_proxy(cfg, 1).await;

        let stream = TcpStream::connect(proxy).await.unwrap();
        let (rh, wh) = stream.into_split();
        let mut reader = FrameReader::new(rh);
        let mut writer = FrameWriter::new(wh);

        writer
            .write_packet(&RawPacket::new(
                0x00,
                HandshakePacket {
                    protocol_version: PROTOCOL,
                    server_address: "localhost".into(),
                    server_port: 25565,
                    next_state: 1,
                }
                .encode(),
            ))
            .await
            .unwrap();
        writer
            .write_packet(&RawPacket::new(0x00, Vec::new()))
            .await
            .unwrap();

        let packet = reader.read_packet().await.unwrap();
        let json = read_string(&packet.data).unwrap().0;
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["version"]["protocol"], PROTOCOL);
        assert_eq!(value["players"]["max"], 42);
        assert_eq!(value["description"]["text"], "Flow test MOTD");

        let mut ping = Vec::new();
        ping.extend_from_slice(&1234567890i64.to_be_bytes());
        writer
            .write_packet(&RawPacket::new(0x01, ping))
            .await
            .unwrap();
        let packet = reader.read_packet().await.unwrap();
        assert_eq!(
            i64::from_be_bytes(packet.data[..8].try_into().unwrap()),
            1234567890
        );
    })
    .await;
}

// -------------------------------------------------- hardening and registry

#[tokio::test]
async fn a_mismatched_protocol_version_is_refused_at_login() {
    within(async {
        // The backend is never scripted: the proxy must reject the client
        // before dialling it at all.
        let cfg = config(&[("lobby", "127.0.0.1:1")], &["lobby"], &[], -1);
        let proxy = start_proxy(cfg, 1).await;

        let stream = TcpStream::connect(proxy).await.unwrap();
        let (rh, wh) = stream.into_split();
        let mut reader = FrameReader::new(rh);
        let mut writer = FrameWriter::new(wh);

        writer
            .write_packet(&RawPacket::new(
                0x00,
                HandshakePacket {
                    protocol_version: 767, // 1.21.1
                    server_address: "mc.example.com".into(),
                    server_port: 25565,
                    next_state: 2,
                }
                .encode(),
            ))
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
        assert_eq!(packet.id, login::CB_DISCONNECT);
        let reason = read_string(&packet.data).unwrap().0;
        assert!(
            reason.contains("769") && reason.contains("767"),
            "the message should name both versions, got: {}",
            reason
        );
    })
    .await;
}

#[tokio::test]
async fn a_silent_connection_is_dropped_by_the_read_timeout() {
    within(async {
        let mut cfg = Config::default();
        cfg.protocol_version = PROTOCOL;
        cfg.servers = ServersSection {
            try_order: vec!["lobby".into()],
            servers: [("lobby".to_string(), "127.0.0.1:1".to_string())]
                .into_iter()
                .collect(),
        };
        cfg.advanced = Advanced {
            read_timeout: 150,
            login_ratelimit: 0,
            connections_per_ip: 0,
            ..Advanced::default()
        };
        let proxy = start_proxy(Arc::new(cfg.with_secret(SECRET)), 1).await;

        // Connect and say nothing at all.
        let stream = TcpStream::connect(proxy).await.unwrap();
        let (rh, _wh) = stream.into_split();
        let mut reader = FrameReader::new(rh);

        // The proxy should close on us rather than hold the socket forever.
        let closed = tokio::time::timeout(Duration::from_secs(5), reader.read_frame()).await;
        assert!(
            matches!(closed, Ok(Err(_))),
            "the proxy should have dropped the idle connection"
        );
    })
    .await;
}

#[tokio::test]
async fn login_ratelimit_rejects_a_rapid_second_attempt() {
    within(async {
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let _ = backend_login(&backend, None).await;
            std::future::pending::<()>().await;
        });

        let mut c = Config::default();
        c.protocol_version = PROTOCOL;
        c.servers = ServersSection {
            try_order: vec!["lobby".into()],
            servers: [("lobby".to_string(), backend_addr)].into_iter().collect(),
        };
        c.advanced = Advanced {
            compression_threshold: -1,
            login_ratelimit: 60_000,
            connections_per_ip: 0,
            ..Advanced::default()
        };
        let proxy = start_proxy(Arc::new(c.with_secret(SECRET)), 2).await;

        // First login is fine.
        client_login(proxy, "Notch", "mc.example.com", &[]).await;

        // Second one from the same address is throttled.
        let stream = TcpStream::connect(proxy).await.unwrap();
        let (rh, wh) = stream.into_split();
        let mut reader = FrameReader::new(rh);
        let mut writer = FrameWriter::new(wh);
        writer
            .write_packet(&RawPacket::new(
                0x00,
                HandshakePacket {
                    protocol_version: PROTOCOL,
                    server_address: "mc.example.com".into(),
                    server_port: 25565,
                    next_state: 2,
                }
                .encode(),
            ))
            .await
            .unwrap();
        writer
            .write_packet(&RawPacket::new(
                login::SB_LOGIN_START,
                LoginStart {
                    username: "jeb_".into(),
                    uuid: offline_uuid("jeb_"),
                }
                .encode(),
            ))
            .await
            .unwrap();

        let packet = reader.read_packet().await.unwrap();
        assert_eq!(packet.id, login::CB_DISCONNECT);
        let reason = read_string(&packet.data).unwrap().0;
        assert!(
            reason.contains("too many login attempts"),
            "got: {}",
            reason
        );
    })
    .await;
}

#[tokio::test]
async fn a_player_is_registered_and_removed() {
    within(async {
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let _side = backend_login(&backend, None).await;
            std::future::pending::<()>().await;
        });

        let cfg = config(&[("lobby", &backend_addr)], &["lobby"], &[], -1);
        let (proxy, ctx) = start_proxy_ctx(cfg, 1).await;

        let client = client_login(proxy, "Notch", "mc.example.com", &[]).await;
        let reg: &Registry = &ctx.registry;

        assert!(eventually(|| reg.count() == 1).await, "player never registered");
        let handle = reg.get("notch").expect("lookup should be case-insensitive");
        assert_eq!(handle.username, "Notch");
        assert_eq!(handle.current_server(), "lobby");

        drop(client);
        assert!(
            eventually(|| reg.count() == 0).await,
            "player was not removed on disconnect"
        );
    })
    .await;
}

#[tokio::test]
async fn a_duplicate_name_is_refused_when_kicking_is_disabled() {
    within(async {
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let _side = backend_login(&backend, None).await;
            std::future::pending::<()>().await;
        });

        let cfg = config(&[("lobby", &backend_addr)], &["lobby"], &[], -1);
        let (proxy, ctx) = start_proxy_ctx(cfg, 2).await;

        let _first = client_login(proxy, "Notch", "mc.example.com", &[]).await;
        assert!(eventually(|| ctx.registry.count() == 1).await);

        let stream = TcpStream::connect(proxy).await.unwrap();
        let (rh, wh) = stream.into_split();
        let mut reader = FrameReader::new(rh);
        let mut writer = FrameWriter::new(wh);
        writer
            .write_packet(&RawPacket::new(
                0x00,
                HandshakePacket {
                    protocol_version: PROTOCOL,
                    server_address: "mc.example.com".into(),
                    server_port: 25565,
                    next_state: 2,
                }
                .encode(),
            ))
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
        assert_eq!(packet.id, login::CB_DISCONNECT);
        let reason = read_string(&packet.data).unwrap().0;
        assert!(reason.contains("already connected"), "got: {}", reason);
    })
    .await;
}

#[tokio::test]
async fn status_reports_the_live_player_count() {
    within(async {
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let _side = backend_login(&backend, None).await;
            std::future::pending::<()>().await;
        });

        let cfg = config(&[("lobby", &backend_addr)], &["lobby"], &[], -1);
        let (proxy, ctx) = start_proxy_ctx(cfg, 2).await;

        let _client = client_login(proxy, "Notch", "mc.example.com", &[]).await;
        assert!(eventually(|| ctx.registry.count() == 1).await);

        let stream = TcpStream::connect(proxy).await.unwrap();
        let (rh, wh) = stream.into_split();
        let mut reader = FrameReader::new(rh);
        let mut writer = FrameWriter::new(wh);
        writer
            .write_packet(&RawPacket::new(
                0x00,
                HandshakePacket {
                    protocol_version: PROTOCOL,
                    server_address: "localhost".into(),
                    server_port: 25565,
                    next_state: 1,
                }
                .encode(),
            ))
            .await
            .unwrap();
        writer
            .write_packet(&RawPacket::new(0x00, Vec::new()))
            .await
            .unwrap();

        let packet = reader.read_packet().await.unwrap();
        let json = read_string(&packet.data).unwrap().0;
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["players"]["online"], 1);
    })
    .await;
}

// ---------------------------------------------- BungeeCord plugin channel

/// Sends a BungeeCord plugin message from the backend to the proxy.
async fn send_bungee(side: &mut BackendSide, body: &[u8]) {
    let mut payload = Vec::new();
    flow_proxy::protocol::types::write_string(&mut payload, bungee::CHANNEL);
    payload.extend_from_slice(body);
    side.writer
        .write_packet(&RawPacket::new(play_clientbound::CUSTOM_PAYLOAD, payload))
        .await
        .unwrap();
}

/// Reads the proxy's reply on the BungeeCord channel.
async fn read_bungee_reply(side: &mut BackendSide) -> (String, Vec<String>, Option<i32>) {
    loop {
        let packet = side.reader.read_packet().await.unwrap();
        if packet.id == play_serverbound::CUSTOM_PAYLOAD {
            let (channel, used) = read_string(&packet.data).unwrap();
            if bungee::is_bungee_channel(&channel) {
                return bungee::decode_response(&packet.data[used..]).unwrap();
            }
        }
    }
}

#[tokio::test]
async fn a_plugin_can_move_a_player_with_connect() {
    within(async {
        let lobby = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let survival = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let lobby_addr = lobby.local_addr().unwrap().to_string();
        let survival_addr = survival.local_addr().unwrap().to_string();

        let lobby_task = tokio::spawn(async move {
            let mut side = backend_login(&lobby, None).await;
            side.writer
                .write_packet(&RawPacket::new(CB_FINISH_CONFIGURATION, Vec::new()))
                .await
                .unwrap();
            // Wait for the client to reach Play, then ask the proxy to move it.
            side.reader.read_packet().await.unwrap();
            send_bungee(&mut side, &BungeeMessage::connect_request("survival")).await;
            std::future::pending::<()>().await;
        });

        let survival_task = tokio::spawn(async move {
            let mut side = backend_login(&survival, None).await;
            side.writer
                .write_packet(&RawPacket::new(CB_FINISH_CONFIGURATION, Vec::new()))
                .await
                .unwrap();
            side.writer
                .write_packet(&RawPacket::new(0x42, b"ON-SURVIVAL".to_vec()))
                .await
                .unwrap();
            side
        });

        let cfg = config(
            &[("lobby", &lobby_addr), ("survival", &survival_addr)],
            &["lobby"],
            &[],
            -1,
        );
        let (proxy, ctx) = start_proxy_ctx(cfg, 1).await;

        let mut client = client_login(proxy, "Notch", "mc.example.com", &[]).await;
        client.finish_configuration().await;

        // The proxy should ask us to reconfigure, driven entirely by the plugin.
        client.accept_configuration_switch().await;
        client.finish_configuration().await;

        let payload = client.read_until(0x42).await;
        assert_eq!(payload, b"ON-SURVIVAL");

        assert!(
            eventually(|| ctx
                .registry
                .get("Notch")
                .map(|p| p.current_server() == "survival")
                .unwrap_or(false))
            .await,
            "the registry should reflect the new server"
        );

        lobby_task.abort();
        let _ = survival_task.await;
    })
    .await;
}

#[tokio::test]
async fn a_plugin_can_query_the_proxy() {
    within(async {
        let lobby = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let lobby_addr = lobby.local_addr().unwrap().to_string();

        let lobby_task = tokio::spawn(async move {
            let mut side = backend_login(&lobby, None).await;
            side.writer
                .write_packet(&RawPacket::new(CB_FINISH_CONFIGURATION, Vec::new()))
                .await
                .unwrap();
            side.reader.read_packet().await.unwrap(); // client reached Play

            let mut buf = Vec::new();
            flow_proxy::protocol::javaio::write_utf(&mut buf, "GetServer");
            send_bungee(&mut side, &buf).await;
            let get_server = read_bungee_reply(&mut side).await;

            send_bungee(&mut side, &BungeeMessage::player_count_request("ALL")).await;
            let count = read_bungee_reply(&mut side).await;

            let mut buf = Vec::new();
            flow_proxy::protocol::javaio::write_utf(&mut buf, "GetServers");
            send_bungee(&mut side, &buf).await;
            let servers = read_bungee_reply(&mut side).await;

            (get_server, count, servers)
        });

        let cfg = config(
            &[("lobby", &lobby_addr), ("survival", "127.0.0.1:1")],
            &["lobby"],
            &[],
            -1,
        );
        let proxy = start_proxy(cfg, 1).await;

        let mut client = client_login(proxy, "Notch", "mc.example.com", &[]).await;
        client.finish_configuration().await;

        let (get_server, count, servers) = lobby_task.await.unwrap();

        assert_eq!(get_server.0, "GetServer");
        assert_eq!(get_server.1, vec!["lobby"]);

        assert_eq!(count.0, "PlayerCount");
        assert_eq!(count.2, Some(1), "one player is online");

        assert_eq!(servers.0, "GetServers");
        assert_eq!(servers.1, vec!["lobby, survival"]);
    })
    .await;
}

#[tokio::test]
async fn glist_reports_players_per_server() {
    within(async {
        let lobby = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let lobby_addr = lobby.local_addr().unwrap().to_string();

        let lobby_task = tokio::spawn(async move {
            let mut side = backend_login(&lobby, None).await;
            side.writer
                .write_packet(&RawPacket::new(CB_FINISH_CONFIGURATION, Vec::new()))
                .await
                .unwrap();
            std::future::pending::<()>().await;
        });

        let cfg = config(&[("lobby", &lobby_addr)], &["lobby"], &[], -1);
        let proxy = start_proxy(cfg, 1).await;

        let mut client = client_login(proxy, "Notch", "mc.example.com", &[]).await;
        client.finish_configuration().await;
        client.send_command("glist").await;

        let payload = client.read_until(play_clientbound::SYSTEM_CHAT).await;
        let len = u16::from_be_bytes([payload[1], payload[2]]) as usize;
        let text = std::str::from_utf8(&payload[3..3 + len]).unwrap();
        assert!(text.contains("Notch"), "got: {}", text);
        assert!(text.contains("lobby"), "got: {}", text);
        assert!(text.contains("Total players online: 1"), "got: {}", text);

        lobby_task.abort();
    })
    .await;
}

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use uuid::Uuid;

use crate::config::Config;
use crate::protocol::connection::{FrameReader, FrameWriter};
use crate::protocol::forwarding::{
    build_forwarding_payload, negotiate_version, ForwardingData, VELOCITY_CHANNEL,
};
use crate::protocol::handshake::HandshakePacket;
use crate::protocol::login::{self as login, LoginStart, LoginSuccess};
use crate::protocol::packet::RawPacket;
use crate::protocol::state::ProtocolState;
use crate::protocol::status::{self as status, PingRequest, PingResponse, StatusResponse};
use crate::protocol::types::{read_string, write_string};

/// How many login-state packets we will read from the backend before giving up.
/// Generous enough for compression, several plugin requests and cookie
/// requests, but bounded so a misbehaving backend cannot spin forever.
const MAX_BACKEND_LOGIN_PACKETS: usize = 32;

/// What the client told us in the handshake. The backend handshake mirrors
/// this rather than using our configured version, otherwise a client on a
/// different build gets a version mismatch straight from the backend.
#[derive(Debug, Clone)]
struct HandshakeInfo {
    protocol_version: i32,
    server_address: String,
    server_port: u16,
}

/// The backend connection, handed back once its login has completed.
struct BackendConnection {
    reader: FrameReader<OwnedReadHalf>,
    writer: FrameWriter<OwnedWriteHalf>,
    success: LoginSuccess,
}

pub struct ClientSession {
    reader: FrameReader<OwnedReadHalf>,
    writer: FrameWriter<OwnedWriteHalf>,
    client_addr: SocketAddr,
    config: Arc<Config>,
    state: ProtocolState,
    handshake: Option<HandshakeInfo>,
}

impl ClientSession {
    pub fn new(client: TcpStream, client_addr: SocketAddr, config: Arc<Config>) -> Self {
        let (read_half, write_half) = client.into_split();
        Self {
            reader: FrameReader::new(read_half),
            writer: FrameWriter::new(write_half),
            client_addr,
            config,
            state: ProtocolState::Handshaking,
            handshake: None,
        }
    }

    pub async fn run(mut self) {
        tracing::debug!("[{}] New connection", self.client_addr);

        loop {
            let packet = match self.reader.read_packet().await {
                Ok(pkt) => pkt,
                Err(e) => {
                    tracing::debug!("[{}] Connection closed: {}", self.client_addr, e);
                    return;
                }
            };

            match self.state {
                ProtocolState::Handshaking => {
                    if let Err(e) = self.handle_handshake(packet) {
                        tracing::warn!("[{}] Handshake error: {:#}", self.client_addr, e);
                        return;
                    }
                }

                ProtocolState::Status => match self.handle_status(packet).await {
                    Ok(true) => return, // pong sent, the client is done
                    Ok(false) => {}
                    Err(e) => {
                        tracing::debug!("[{}] Status error: {:#}", self.client_addr, e);
                        return;
                    }
                },

                ProtocolState::Login => {
                    match self.handle_login(packet).await {
                        Ok((backend, username)) => {
                            let addr = self.client_addr;
                            relay(self, backend, username.clone()).await;
                            tracing::info!("[{}] {} disconnected", addr, username);
                        }
                        Err(e) => {
                            tracing::warn!("[{}] Login failed: {:#}", self.client_addr, e);
                            // Tell the client why, instead of dropping the
                            // socket and leaving it on a generic timeout.
                            self.disconnect_during_login(&format!("{:#}", e)).await;
                        }
                    }
                    return;
                }
            }
        }
    }

    fn handle_handshake(&mut self, packet: RawPacket) -> anyhow::Result<()> {
        if packet.id != 0x00 {
            anyhow::bail!("expected Handshake (0x00), got 0x{:02X}", packet.id);
        }

        let (handshake, _) = HandshakePacket::decode(&packet.data)?;
        tracing::debug!(
            "[{}] Handshake: protocol={}, vhost={}:{}, next_state={}",
            self.client_addr,
            handshake.protocol_version,
            handshake.server_address,
            handshake.server_port,
            handshake.next_state
        );

        self.state = ProtocolState::from_next_state(handshake.next_state)
            .ok_or_else(|| anyhow::anyhow!("invalid next_state: {}", handshake.next_state))?;

        self.handshake = Some(HandshakeInfo {
            protocol_version: handshake.protocol_version,
            server_address: handshake.server_address,
            server_port: handshake.server_port,
        });

        Ok(())
    }

    /// Returns `Ok(true)` when the status exchange is finished.
    async fn handle_status(&mut self, packet: RawPacket) -> anyhow::Result<bool> {
        match packet.id {
            status::SB_STATUS_REQUEST => {
                let json = serde_json::json!({
                    "version": {
                        "name": self.config.version_name,
                        "protocol": self.config.protocol_version
                    },
                    "players": { "max": self.config.max_players, "online": 0 },
                    "description": { "text": self.config.motd },
                    "enforcesSecureChat": false
                });
                let payload = StatusResponse { json_response: json }.encode();
                self.writer
                    .write_packet(&RawPacket::new(status::CB_STATUS_RESPONSE, payload))
                    .await?;
                Ok(false)
            }
            status::SB_PING_REQUEST => {
                let ping = PingRequest::decode(&packet.data)?;
                let payload = PingResponse { payload: ping.payload }.encode();
                self.writer
                    .write_packet(&RawPacket::new(status::CB_PONG, payload))
                    .await?;
                Ok(true)
            }
            other => anyhow::bail!("unexpected packet 0x{:02X} in Status state", other),
        }
    }

    /// Drives the client through login and returns the ready backend
    /// connection plus the player's name.
    async fn handle_login(
        &mut self,
        packet: RawPacket,
    ) -> anyhow::Result<(BackendConnection, String)> {
        if packet.id != login::SB_LOGIN_START {
            anyhow::bail!("expected Login Start (0x00), got 0x{:02X}", packet.id);
        }

        let login_start = LoginStart::decode(&packet.data)?;
        let username = login_start.username.clone();

        // This proxy does not run Mojang authentication, so the authoritative
        // UUID is the offline one derived from the name. Trusting the value the
        // client sent would let anyone choose their own identity.
        let uuid = login::offline_uuid(&username);

        tracing::info!("[{}] Login start: {} ({})", self.client_addr, username, uuid);

        let handshake = self
            .handshake
            .clone()
            .ok_or_else(|| anyhow::anyhow!("login without a preceding handshake"))?;

        // Talk to the backend first. Its Login Success carries the profile we
        // hand to the client, and there is no point compressing toward the
        // client until we know the login actually succeeded.
        let mut backend = self
            .backend_login(&handshake, &username, uuid)
            .await
            .map_err(|e| anyhow::anyhow!("backend login failed: {:#}", e))?;

        tracing::info!(
            "[{}] Backend accepted {} as {}",
            self.client_addr,
            username,
            backend.success.uuid
        );

        // Compression toward the client. This must precede Login Success, and
        // both of our halves have to switch together.
        let threshold = self.config.compression_threshold;
        if threshold >= 0 {
            let payload = login::SetCompression { threshold }.encode();
            self.writer
                .write_packet(&RawPacket::new(login::CB_SET_COMPRESSION, payload))
                .await?;
            self.writer.set_threshold(threshold);
            self.reader.set_threshold(threshold);
        }

        // Login Success is 0x02. The original code sent it as 0x03, which the
        // client reads as Set Compression -- the direct cause of players never
        // getting past the login screen.
        let success = LoginSuccess {
            uuid: backend.success.uuid,
            username: backend.success.username.clone(),
            properties: std::mem::take(&mut backend.success.properties),
        };
        self.writer
            .write_packet(&RawPacket::new(login::CB_LOGIN_SUCCESS, success.encode()))
            .await?;

        // The client acknowledges, which moves it into Configuration.
        let ack = self.reader.read_packet().await?;
        if ack.id != login::SB_LOGIN_ACKNOWLEDGED {
            anyhow::bail!("expected Login Acknowledged (0x03), got 0x{:02X}", ack.id);
        }

        tracing::info!("[{}] {} logged in, relaying", self.client_addr, username);

        Ok((backend, username))
    }

    /// Runs the full login handshake against the backend, including Velocity
    /// modern forwarding.
    async fn backend_login(
        &self,
        handshake: &HandshakeInfo,
        username: &str,
        uuid: Uuid,
    ) -> anyhow::Result<BackendConnection> {
        let backend_addr = &self.config.backend.address;
        let stream = TcpStream::connect(backend_addr)
            .await
            .map_err(|e| anyhow::anyhow!("cannot reach backend {}: {}", backend_addr, e))?;
        stream.set_nodelay(true).ok();

        let (read_half, write_half) = stream.into_split();
        let mut reader = FrameReader::new(read_half);
        let mut writer = FrameWriter::new(write_half);

        let backend_handshake = HandshakePacket {
            protocol_version: handshake.protocol_version,
            server_address: handshake.server_address.clone(),
            server_port: handshake.server_port,
            next_state: status::NEXT_STATE_LOGIN,
        };
        writer
            .write_packet(&RawPacket::new(0x00, backend_handshake.encode()))
            .await?;

        let login_start = LoginStart {
            username: username.to_string(),
            uuid,
        };
        writer
            .write_packet(&RawPacket::new(login::SB_LOGIN_START, login_start.encode()))
            .await?;

        // Velocity forwards the bare IP, which is what Paper uses as the
        // player's socket address.
        let client_ip = self.client_addr.ip().to_string();

        for _ in 0..MAX_BACKEND_LOGIN_PACKETS {
            let packet = reader.read_packet().await?;

            match packet.id {
                login::CB_SET_COMPRESSION => {
                    let threshold = login::SetCompression::decode(&packet.data)?.threshold;
                    tracing::debug!("[{}] Backend compression threshold {}", username, threshold);
                    // Every later frame on this connection uses the compressed
                    // format. Ignoring this desynchronised the stream and made
                    // the very next packet unparseable.
                    reader.set_threshold(threshold);
                    writer.set_threshold(threshold);
                }

                login::CB_LOGIN_PLUGIN_REQUEST => {
                    let request = login::LoginPluginRequest::decode(&packet.data)?;

                    let response = if request.channel == VELOCITY_CHANNEL {
                        // The single data byte is the highest version the
                        // backend supports.
                        let requested = request.data.first().copied().unwrap_or(1) as i32;
                        let version = negotiate_version(requested, false);
                        tracing::debug!(
                            "[{}] Velocity forwarding: backend offered v{}, answering v{}",
                            username,
                            requested,
                            version
                        );

                        let data = ForwardingData {
                            client_address: client_ip.clone(),
                            player_uuid: uuid,
                            username: username.to_string(),
                            properties: Vec::new(),
                            player_key: None,
                        };

                        login::LoginPluginResponse {
                            message_id: request.message_id,
                            successful: true,
                            data: build_forwarding_payload(
                                self.config.forwarding_secret.as_bytes(),
                                version,
                                &data,
                            ),
                        }
                    } else {
                        tracing::debug!(
                            "[{}] Declining unknown login channel '{}'",
                            username,
                            request.channel
                        );
                        login::LoginPluginResponse {
                            message_id: request.message_id,
                            successful: false,
                            data: Vec::new(),
                        }
                    };

                    writer
                        .write_packet(&RawPacket::new(
                            login::SB_LOGIN_PLUGIN_RESPONSE,
                            response.encode(),
                        ))
                        .await?;
                }

                login::CB_COOKIE_REQUEST => {
                    // 1.20.5+. We keep no cookie store, so answer "absent"
                    // rather than leave the backend waiting forever.
                    let (key, _) = read_string(&packet.data)?;
                    let mut payload = Vec::new();
                    write_string(&mut payload, &key);
                    payload.push(0x00);
                    writer
                        .write_packet(&RawPacket::new(login::SB_COOKIE_RESPONSE, payload))
                        .await?;
                }

                login::CB_LOGIN_SUCCESS => {
                    let success = LoginSuccess::decode(&packet.data)?;

                    // The backend stays in Login state until we acknowledge.
                    // Without this it never enters Configuration and the player
                    // hangs right after the login screen.
                    writer
                        .write_packet(&RawPacket::new(login::SB_LOGIN_ACKNOWLEDGED, Vec::new()))
                        .await?;

                    return Ok(BackendConnection { reader, writer, success });
                }

                login::CB_ENCRYPTION_REQUEST => anyhow::bail!(
                    "backend requested encryption, so it is running in online-mode. \
                     Set online-mode=false in server.properties and enable \
                     proxies.velocity in paper-global.yml"
                ),

                login::CB_DISCONNECT => {
                    let reason = login::LoginDisconnect::decode_reason(&packet.data)
                        .unwrap_or_else(|_| "unknown reason".to_string());
                    anyhow::bail!("backend rejected the login: {}", reason);
                }

                other => {
                    anyhow::bail!("unexpected packet 0x{:02X} from backend during login", other)
                }
            }
        }

        anyhow::bail!(
            "backend sent no Login Success within {} packets",
            MAX_BACKEND_LOGIN_PACKETS
        )
    }

    /// Sends a Login Disconnect so the client shows a real reason.
    async fn disconnect_during_login(&mut self, reason: &str) {
        let payload = login::LoginDisconnect::encode_text(reason);
        let _ = self
            .writer
            .write_packet(&RawPacket::new(login::CB_DISCONNECT, payload))
            .await;
    }
}

/// Relays Configuration and Play frames in both directions until either side
/// closes.
///
/// This works frame by frame rather than on raw bytes, because the two sides
/// compress independently: a byte-level copy would hand the client frames still
/// in the backend's compression format.
async fn relay(session: ClientSession, backend: BackendConnection, username: String) {
    let mut client_rx = session.reader;
    let mut client_tx = session.writer;
    let mut backend_rx = backend.reader;
    let mut backend_tx = backend.writer;

    let upstream = tokio::spawn(async move {
        while let Ok(frame) = client_rx.read_frame().await {
            if backend_tx.write_frame(&frame).await.is_err() {
                break;
            }
        }
    });

    let downstream = tokio::spawn(async move {
        while let Ok(frame) = backend_rx.read_frame().await {
            if client_tx.write_frame(&frame).await.is_err() {
                break;
            }
        }
    });

    tokio::select! {
        _ = upstream => {},
        _ = downstream => {},
    }

    tracing::debug!("Relay for {} ended", username);
}

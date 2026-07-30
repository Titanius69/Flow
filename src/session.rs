use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::config::{Config, ForwardingMode};
use crate::limiter::{ConnectionGuard, Limiter};
use crate::protocol::connection::{FrameReader, FrameWriter};
use crate::protocol::forwarding::{
    build_forwarding_payload, negotiate_version, ForwardingData, VELOCITY_CHANNEL,
};
use crate::protocol::handshake::HandshakePacket;
use crate::protocol::login::{self as login, LoginStart, LoginSuccess};
use crate::protocol::nbt;
use crate::protocol::packet::RawPacket;
use crate::protocol::packets::{
    config_serverbound, play_clientbound, play_serverbound, PROTOCOL_VERSION,
};
use crate::protocol::plugin_message::{self as bungee, BungeeMessage};
use crate::protocol::state::ProtocolState;
use crate::protocol::status::{self as status, PingRequest, PingResponse, StatusResponse};
use crate::protocol::types::{read_string, write_string};
use crate::protocol::varint::read_varint;
use crate::registry::{PlayerHandle, ProxyCommand, Registry};

/// How many login-state packets we will read from a backend before giving up.
const MAX_BACKEND_LOGIN_PACKETS: usize = 32;

/// How long to wait for the client to answer Start Configuration during a
/// server switch.
const CONFIG_ACK_TIMEOUT: Duration = Duration::from_secs(15);

/// Buffered frames per direction, bounded so a slow peer applies backpressure.
const FRAME_CHANNEL_CAPACITY: usize = 256;

/// Pending cross-session commands per player.
const COMMAND_CHANNEL_CAPACITY: usize = 32;

/// Hooks fired as players come and go, so plugins can observe and intervene
/// without the session module depending on the plugin host.
pub trait EventSink: Send + Sync {
    fn on_join(&self, _player: &PlayerHandle, _server: &str) {}
    fn on_leave(&self, _player: &PlayerHandle) {}
    fn on_switch(&self, _player: &PlayerHandle, _from: &str, _to: &str) {}
    /// Returns true if the command was consumed and must not reach the backend.
    fn on_command(&self, _player: &PlayerHandle, _command: &str) -> bool {
        false
    }
}

/// The default sink, used when no plugins are loaded.
pub struct NoEvents;
impl EventSink for NoEvents {}

/// Everything a session needs that is shared across the whole proxy.
pub struct ProxyContext {
    pub config: Arc<Config>,
    pub registry: Arc<Registry>,
    pub limiter: Arc<Limiter>,
    pub events: Arc<dyn EventSink>,
}

impl ProxyContext {
    pub fn new(config: Arc<Config>) -> Arc<Self> {
        let limiter = Limiter::new(config.limits());
        Arc::new(Self {
            config,
            registry: Arc::new(Registry::new()),
            limiter,
            events: Arc::new(NoEvents),
        })
    }

    pub fn with_events(config: Arc<Config>, events: Arc<dyn EventSink>) -> Arc<Self> {
        Self::with_parts(config, Arc::new(Registry::new()), events)
    }

    /// Builds a context around a registry that already exists, so plugins and
    /// sessions observe the same set of players.
    pub fn with_parts(
        config: Arc<Config>,
        registry: Arc<Registry>,
        events: Arc<dyn EventSink>,
    ) -> Arc<Self> {
        let limiter = Limiter::new(config.limits());
        Arc::new(Self {
            config,
            registry,
            limiter,
            events,
        })
    }
}

/// What the client told us in the handshake.
#[derive(Debug, Clone)]
struct HandshakeInfo {
    protocol_version: i32,
    server_address: String,
    server_port: u16,
}

/// Which state the *client* is in after login. The same packet id means
/// different things in Configuration and Play, so command and plugin-message
/// interception must only happen in Play.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientPlayState {
    Configuration,
    Play,
}

struct BackendConnection {
    reader: FrameReader<OwnedReadHalf>,
    writer: FrameWriter<OwnedWriteHalf>,
    #[allow(dead_code)]
    success: LoginSuccess,
}

struct LoginOutcome {
    backend: BackendConnection,
    server_name: String,
    username: String,
    uuid: Uuid,
    handshake: HandshakeInfo,
}

pub struct ClientSession {
    reader: FrameReader<OwnedReadHalf>,
    writer: FrameWriter<OwnedWriteHalf>,
    client_addr: SocketAddr,
    ctx: Arc<ProxyContext>,
    state: ProtocolState,
    handshake: Option<HandshakeInfo>,
    /// Released when the session ends.
    _guard: Option<ConnectionGuard>,
}

impl ClientSession {
    pub fn new(client: TcpStream, client_addr: SocketAddr, ctx: Arc<ProxyContext>) -> Self {
        Self::with_guard(client, client_addr, ctx, None)
    }

    pub fn with_guard(
        client: TcpStream,
        client_addr: SocketAddr,
        ctx: Arc<ProxyContext>,
        guard: Option<ConnectionGuard>,
    ) -> Self {
        let (read_half, write_half) = client.into_split();
        let mut reader = FrameReader::new(read_half);
        reader.set_read_timeout(ctx.config.read_timeout());

        Self {
            reader,
            writer: FrameWriter::new(write_half),
            client_addr,
            ctx,
            state: ProtocolState::Handshaking,
            handshake: None,
            _guard: guard,
        }
    }

    pub async fn run(mut self) {
        tracing::debug!("[{}] New connection", self.client_addr);

        let outcome = loop {
            let packet = match self.reader.read_packet().await {
                Ok(pkt) => pkt,
                Err(e) => {
                    tracing::debug!("[{}] Connection closed: {}", self.client_addr, e);
                    break None;
                }
            };

            match self.state {
                ProtocolState::Handshaking => {
                    if let Err(e) = self.handle_handshake(packet) {
                        tracing::warn!("[{}] Handshake error: {:#}", self.client_addr, e);
                        break None;
                    }
                }

                ProtocolState::Status => match self.handle_status(packet).await {
                    Ok(true) => break None,
                    Ok(false) => {}
                    Err(e) => {
                        tracing::debug!("[{}] Status error: {:#}", self.client_addr, e);
                        break None;
                    }
                },

                ProtocolState::Login => match self.handle_login(packet).await {
                    Ok(outcome) => break Some(outcome),
                    Err(e) => {
                        tracing::warn!("[{}] Login failed: {:#}", self.client_addr, e);
                        self.disconnect_during_login(&format!("{:#}", e)).await;
                        break None;
                    }
                },
            }
        };

        let Some(outcome) = outcome else { return };

        Player::new(
    self.reader,
    self.writer,
    outcome.backend,
    outcome.server_name,
    outcome.username,
    outcome.uuid,
    self.client_addr,
    self.ctx,
    outcome.handshake,
)
.run()
.await;
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

    async fn handle_status(&mut self, packet: RawPacket) -> anyhow::Result<bool> {
        match packet.id {
            status::SB_STATUS_REQUEST => {
                let json = serde_json::json!({
                    "version": {
                        "name": self.ctx.config.version_name,
                        "protocol": self.ctx.config.protocol_version
                    },
                    "players": {
                        "max": self.ctx.config.show_max_players,
                        "online": self.ctx.registry.count()
                    },
                    "description": { "text": self.ctx.config.motd },
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

    async fn handle_login(&mut self, packet: RawPacket) -> anyhow::Result<LoginOutcome> {
        if packet.id != login::SB_LOGIN_START {
            anyhow::bail!("expected Login Start (0x00), got 0x{:02X}", packet.id);
        }

        let handshake = self
            .handshake
            .clone()
            .ok_or_else(|| anyhow::anyhow!("login without a preceding handshake"))?;

        // Reject other protocol versions outright. The Configuration and Play
        // packet IDs compiled into this build belong to one version, so letting
        // a mismatched client through would not fail loudly: it would send and
        // receive plausible-looking packets with the wrong meanings.
        if handshake.protocol_version != PROTOCOL_VERSION {
            anyhow::bail!(
                "this proxy speaks Minecraft {} (protocol {}), but your client sent \
                 protocol {}",
                self.ctx.config.version_name,
                PROTOCOL_VERSION,
                handshake.protocol_version
            );
        }

        if let Err(wait) = self.ctx.limiter.check_login(self.client_addr.ip()) {
            anyhow::bail!(
                "too many login attempts, try again in {} second(s)",
                wait.as_secs() + 1
            );
        }

        let login_start = LoginStart::decode(&packet.data)?;
        let username = login_start.username.clone();

        if !is_valid_username(&username) {
            anyhow::bail!("invalid username");
        }

        // This proxy performs no Mojang authentication, so the authoritative
        // UUID is the offline one derived from the name.
        let uuid = login::offline_uuid(&username);

        // Duplicate names are possible in offline mode, and two sessions with
        // one identity corrupt state on the backend.
        if let Some(existing) = self.ctx.registry.get(&username) {
            if self.ctx.config.kick_existing_players {
                existing.send(ProxyCommand::Kick(
                    "You logged in from another location".to_string(),
                ));
            } else {
                anyhow::bail!("that name is already connected");
            }
        }

        let route = self.ctx.config.route_for(&handshake.server_address);
        let (server_name, mut backend) = self
            .connect_with_failover(&route, &handshake, &username, uuid)
            .await?;

        let threshold = self.ctx.config.advanced.compression_threshold;
        if threshold >= 0 {
            let payload = login::SetCompression { threshold }.encode();
            self.writer
                .write_packet(&RawPacket::new(login::CB_SET_COMPRESSION, payload))
                .await?;
            self.writer.set_threshold(threshold);
            self.reader.set_threshold(threshold);
        }

        let success = LoginSuccess {
            uuid: backend.success.uuid,
            username: backend.success.username.clone(),
            properties: std::mem::take(&mut backend.success.properties),
        };
        self.writer
            .write_packet(&RawPacket::new(login::CB_LOGIN_SUCCESS, success.encode()))
            .await?;

        let ack = self.reader.read_packet().await?;
        if ack.id != login::SB_LOGIN_ACKNOWLEDGED {
            anyhow::bail!("expected Login Acknowledged (0x03), got 0x{:02X}", ack.id);
        }

        Ok(LoginOutcome {
            backend,
            server_name,
            username,
            uuid,
            handshake,
        })
    }

    async fn connect_with_failover(
        &self,
        route: &[String],
        handshake: &HandshakeInfo,
        username: &str,
        uuid: Uuid,
    ) -> anyhow::Result<(String, BackendConnection)> {
        let mut last_error: Option<anyhow::Error> = None;

        for name in route {
            let Some(address) = self.ctx.config.server_address(name) else {
                tracing::warn!("route references unknown server '{}'", name);
                continue;
            };

            match backend_login(
                &self.ctx.config,
                address,
                handshake,
                username,
                uuid,
                self.client_addr,
            )
            .await
            {
                Ok(backend) => return Ok((name.clone(), backend)),
                Err(e) => {
                    tracing::warn!("[{}] backend '{}' refused: {:#}", username, name, e);
                    last_error = Some(e);
                    if !self
                        .ctx
                        .config
                        .advanced
                        .failover_on_unexpected_server_disconnect
                    {
                        break;
                    }
                }
            }
        }

        Err(match last_error {
            Some(e) => anyhow::anyhow!("no backend accepted the login: {:#}", e),
            None => anyhow::anyhow!("no usable server in the route"),
        })
    }

    async fn disconnect_during_login(&mut self, reason: &str) {
        let payload = login::LoginDisconnect::encode_text(reason);
        let _ = self
            .writer
            .write_packet(&RawPacket::new(login::CB_DISCONNECT, payload))
            .await;
    }
}

/// Mojang usernames are 3-16 characters of `[A-Za-z0-9_]`. Anything else is
/// either a broken client or an attempt to confuse downstream name handling.
fn is_valid_username(name: &str) -> bool {
    (3..=16).contains(&name.len())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
}

async fn backend_login(
    config: &Config,
    address: &str,
    handshake: &HandshakeInfo,
    username: &str,
    uuid: Uuid,
    client_addr: SocketAddr,
) -> anyhow::Result<BackendConnection> {
    let stream = tokio::time::timeout(
        Duration::from_millis(config.advanced.connection_timeout),
        TcpStream::connect(address),
    )
    .await
    .map_err(|_| anyhow::anyhow!("timed out connecting to {}", address))?
    .map_err(|e| anyhow::anyhow!("cannot reach {}: {}", address, e))?;
    stream.set_nodelay(true).ok();

    let (read_half, write_half) = stream.into_split();
    let mut reader = FrameReader::new(read_half);
    reader.set_read_timeout(config.read_timeout());
    let mut writer = FrameWriter::new(write_half);

    writer
        .write_packet(&RawPacket::new(
            0x00,
            HandshakePacket {
                protocol_version: handshake.protocol_version,
                server_address: handshake.server_address.clone(),
                server_port: handshake.server_port,
                next_state: status::NEXT_STATE_LOGIN,
            }
            .encode(),
        ))
        .await?;

    writer
        .write_packet(&RawPacket::new(
            login::SB_LOGIN_START,
            LoginStart {
                username: username.to_string(),
                uuid,
            }
            .encode(),
        ))
        .await?;

    // Velocity forwards the bare IP, which is what Paper uses as the player's
    // socket address. With haproxy-protocol enabled this is the real client
    // address rather than the load balancer's.
    let client_ip = client_addr.ip().to_string();

    for _ in 0..MAX_BACKEND_LOGIN_PACKETS {
        let packet = reader.read_packet().await?;

        match packet.id {
            login::CB_SET_COMPRESSION => {
                let threshold = login::SetCompression::decode(&packet.data)?.threshold;
                reader.set_threshold(threshold);
                writer.set_threshold(threshold);
            }

            login::CB_LOGIN_PLUGIN_REQUEST => {
                let request = login::LoginPluginRequest::decode(&packet.data)?;

                let response = if request.channel == VELOCITY_CHANNEL
                    && config.player_info_forwarding_mode == ForwardingMode::Modern
                {
                    let requested = request.data.first().copied().unwrap_or(1) as i32;
                    let version = negotiate_version(requested, false);

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
                            config.forwarding_secret().as_bytes(),
                            version,
                            &data,
                        ),
                    }
                } else {
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
                writer
                    .write_packet(&RawPacket::new(login::SB_LOGIN_ACKNOWLEDGED, Vec::new()))
                    .await?;

                return Ok(BackendConnection {
                    reader,
                    writer,
                    success,
                });
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

            other => anyhow::bail!("unexpected packet 0x{:02X} from backend during login", other),
        }
    }

    anyhow::bail!(
        "backend sent no Login Success within {} packets",
        MAX_BACKEND_LOGIN_PACKETS
    )
}

/// Reads frames off a socket into a channel.
///
/// Reads live in their own task rather than in a `select!` arm because
/// `read_frame` is not cancellation-safe: dropping it midway through a frame
/// would leave a partly-consumed length prefix and corrupt the stream.
fn spawn_frame_reader(
    mut reader: FrameReader<OwnedReadHalf>,
    tx: mpsc::Sender<Vec<u8>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok(frame) = reader.read_frame().await {
            if tx.send(frame).await.is_err() {
                break;
            }
        }
    })
}

pub struct Player {
    client_tx: FrameWriter<OwnedWriteHalf>,
    client_frames: mpsc::Receiver<Vec<u8>>,
    _client_reader_task: JoinHandle<()>,

    backend_tx: FrameWriter<OwnedWriteHalf>,
    backend_frames: mpsc::Receiver<Vec<u8>>,
    backend_reader_task: JoinHandle<()>,

    commands: mpsc::Receiver<ProxyCommand>,
    handle: PlayerHandle,

    username: String,
    uuid: Uuid,
    client_addr: SocketAddr,
    ctx: Arc<ProxyContext>,
    handshake: HandshakeInfo,
    client_state: ClientPlayState,

    server_name: String,
    joined: bool,
}

impl Player {
    #[allow(clippy::too_many_arguments)]
    fn new(
        client_reader: FrameReader<OwnedReadHalf>,
        client_tx: FrameWriter<OwnedWriteHalf>,
        backend: BackendConnection,
        server_name: String,
        username: String,
        uuid: Uuid,
        client_addr: SocketAddr,
        ctx: Arc<ProxyContext>,
        handshake: HandshakeInfo,
    ) -> Self {
        let (ctx_tx, client_frames) = mpsc::channel(FRAME_CHANNEL_CAPACITY);
        let client_reader_task = spawn_frame_reader(client_reader, ctx_tx);

        let (btx, backend_frames) = mpsc::channel(FRAME_CHANNEL_CAPACITY);
        let backend_reader_task = spawn_frame_reader(backend.reader, btx);

        let (command_tx, commands) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);

        let handle = PlayerHandle {
            username: username.clone(),
            uuid,
            addr: client_addr,
            server: Arc::new(Mutex::new(server_name.clone())),
            commands: command_tx,
        };

        if let Some(displaced) = ctx.registry.insert(handle.clone()) {
            displaced.send(ProxyCommand::Kick(
                "You logged in from another location".to_string(),
            ));
        }

        // Az on_join hívás ELTÁVOLÍTVA – már nem itt hívjuk

        if ctx.config.advanced.log_player_connections {
            tracing::info!(
                "[{}] {} ({}) joined via '{}'",
                client_addr,
                username,
                uuid,
                server_name
            );
        }

        Self {
            client_tx,
            client_frames,
            _client_reader_task: client_reader_task,
            backend_tx: backend.writer,
            backend_frames,
            backend_reader_task,
            commands,
            handle,
            username,
            uuid,
            client_addr,
            ctx,
            handshake,
            client_state: ClientPlayState::Configuration,
            server_name,
            joined: false,
        }
    }

    fn current_server(&self) -> String {
        self.handle.current_server()
    }

    pub async fn run(mut self) {
        loop {
            tokio::select! {
                frame = self.client_frames.recv() => match frame {
                    Some(frame) => {
                        if let Err(e) = self.on_client_frame(frame).await {
                            tracing::debug!("[{}] client frame error: {:#}", self.username, e);
                            break;
                        }
                    }
                    None => break,
                },

                frame = self.backend_frames.recv() => match frame {
                    Some(frame) => {
                        if let Err(e) = self.on_backend_frame(frame).await {
                            tracing::debug!("[{}] backend frame error: {:#}", self.username, e);
                            break;
                        }
                    }
                    None => {
                        if !self.handle_backend_loss().await {
                            break;
                        }
                    }
                },

                command = self.commands.recv() => match command {
                    Some(command) => {
                        if !self.on_command(command).await {
                            break;
                        }
                    }
                    None => break,
                },
            }
        }

        self.ctx.events.on_leave(&self.handle);
        self.ctx
            .registry
            .remove_if_same(&self.username, &self.handle.commands);

        if self.ctx.config.advanced.log_player_connections {
            tracing::info!("[{}] {} disconnected", self.client_addr, self.username);
        }
        self.backend_reader_task.abort();
    }

    /// Returns false when the session should end.
    async fn on_command(&mut self, command: ProxyCommand) -> bool {
        match command {
            ProxyCommand::Message(text) => {
                let _ = self.send_system_message(&text).await;
                true
            }
            ProxyCommand::Connect(server) => {
                if let Err(e) = self.switch_to(&server).await {
                    let _ = self
                        .send_system_message(&format!("Could not connect to '{}': {:#}", server, e))
                        .await;
                }
                true
            }
            ProxyCommand::Kick(reason) => {
                let _ = self.kick(&reason).await;
                false
            }
        }
    }

async fn on_client_frame(&mut self, frame: Vec<u8>) -> anyhow::Result<()> {
    let (id, offset) = read_varint(&frame)?;
    let payload = &frame[offset..];

    match self.client_state {
        ClientPlayState::Configuration => {
            if id == config_serverbound::FINISH_CONFIGURATION {
                self.client_state = ClientPlayState::Play;

                // Az on_join eseményt itt hívjuk meg, ha még nem volt
                if !self.joined {
                    self.joined = true;
                    self.ctx.events.on_join(&self.handle, &self.server_name);
                }
            }
        }
        ClientPlayState::Play => {
            if id == play_serverbound::CHAT_COMMAND {
                if let Ok((command, _)) = read_string(payload) {
                    if self.try_handle_command(&command).await? {
                        return Ok(());
                    }
                }
            } else if id == play_serverbound::CONFIGURATION_ACKNOWLEDGED {
                self.client_state = ClientPlayState::Configuration;
            }
        }
    }

    self.backend_tx.write_frame(&frame).await
}

    async fn on_backend_frame(&mut self, frame: Vec<u8>) -> anyhow::Result<()> {
        // Intercept the BungeeCord plugin channel so backend plugins can drive
        // the proxy. Only in Play: the same id means something else in
        // Configuration.
        if self.ctx.config.advanced.bungee_plugin_message_channel
            && self.client_state == ClientPlayState::Play
        {
            if let Ok((id, offset)) = read_varint(&frame) {
                if id == play_clientbound::CUSTOM_PAYLOAD {
                    if let Ok((channel, used)) = read_string(&frame[offset..]) {
                        if bungee::is_bungee_channel(&channel) {
                            let body = frame[offset + used..].to_vec();
                            self.handle_bungee(&channel, &body).await;
                            return Ok(());
                        }
                    }
                }
            }
        }

        self.client_tx.write_frame(&frame).await
    }

    /// Handles one BungeeCord plugin message from the backend.
    async fn handle_bungee(&mut self, channel: &str, body: &[u8]) {
        let message = match BungeeMessage::decode(body) {
            Ok(message) => message,
            Err(e) => {
                tracing::debug!("[{}] malformed plugin message: {:#}", self.username, e);
                return;
            }
        };

        let registry = Arc::clone(&self.ctx.registry);

        match message {
            BungeeMessage::Connect { server } => {
                if let Err(e) = self.switch_to(&server).await {
                    tracing::debug!("[{}] plugin Connect failed: {:#}", self.username, e);
                    let _ = self
                        .send_system_message(&format!("Could not connect to '{}': {:#}", server, e))
                        .await;
                }
            }

            BungeeMessage::ConnectOther { player, server } => {
                if let Some(target) = registry.get(&player) {
                    target.send(ProxyCommand::Connect(server));
                }
            }

            BungeeMessage::Message { player, message } => {
                if player.eq_ignore_ascii_case("ALL") {
                    for target in registry.all() {
                        target.send(ProxyCommand::Message(message.clone()));
                    }
                } else if let Some(target) = registry.get(&player) {
                    target.send(ProxyCommand::Message(message));
                }
            }

            BungeeMessage::KickPlayer { player, reason } => {
                if let Some(target) = registry.get(&player) {
                    target.send(ProxyCommand::Kick(reason));
                }
            }

            BungeeMessage::Ip => {
                let reply = bungee::response_ip(
                    &self.client_addr.ip().to_string(),
                    self.client_addr.port(),
                );
                self.reply_bungee(channel, &reply).await;
            }

            BungeeMessage::GetServer => {
                let reply = bungee::response_get_server(&self.current_server());
                self.reply_bungee(channel, &reply).await;
            }

            BungeeMessage::GetServers => {
                let reply = bungee::response_get_servers(&self.ctx.config.server_names());
                self.reply_bungee(channel, &reply).await;
            }

            BungeeMessage::PlayerCount { server } => {
                let count = registry.count_on(&server) as i32;
                let reply = bungee::response_player_count(&server, count);
                self.reply_bungee(channel, &reply).await;
            }

            BungeeMessage::PlayerList { server } => {
                let names = registry.names_on(&server);
                let reply = bungee::response_player_list(&server, &names);
                self.reply_bungee(channel, &reply).await;
            }

            BungeeMessage::Unsupported { subchannel } => {
                tracing::debug!(
                    "[{}] unsupported plugin subchannel '{}'",
                    self.username,
                    subchannel
                );
            }
        }
    }

    /// Sends a reply back to the backend on the same plugin channel.
    async fn reply_bungee(&mut self, channel: &str, body: &[u8]) {
        let mut payload = Vec::new();
        write_string(&mut payload, channel);
        payload.extend_from_slice(body);
        let _ = self
            .backend_tx
            .write_packet(&RawPacket::new(play_serverbound::CUSTOM_PAYLOAD, payload))
            .await;
    }

    /// Returns true if the proxy consumed the command.
    async fn try_handle_command(&mut self, command: &str) -> anyhow::Result<bool> {
        if self.ctx.events.on_command(&self.handle, command) {
            return Ok(true);
        }

        let mut parts = command.split_whitespace();
        let Some(verb) = parts.next() else {
            return Ok(false);
        };

        match verb {
            "server" => match parts.next() {
                None => {
                    let names = self.ctx.config.server_names();
                    let message = format!(
                        "You are on '{}'. Available: {}",
                        self.current_server(),
                        names.join(", ")
                    );
                    self.send_system_message(&message).await?;
                }
                Some(target) => {
                    let target = target.to_string();
                    if let Err(e) = self.switch_to(&target).await {
                        tracing::warn!(
                            "[{}] switch to '{}' failed: {:#}",
                            self.username,
                            target,
                            e
                        );
                        let msg = format!("Could not connect to '{}': {:#}", target, e);
                        self.send_system_message(&msg).await?;
                    }
                }
            },

            "glist" => {
                let mut lines = Vec::new();
                let mut total = 0;
                for name in self.ctx.config.server_names() {
                    let players = self.ctx.registry.names_on(&name);
                    total += players.len();
                    if !players.is_empty() {
                        lines.push(format!("[{}] ({}): {}", name, players.len(), players.join(", ")));
                    }
                }
                lines.push(format!("Total players online: {}", total));
                self.send_system_message(&lines.join("\n")).await?;
            }

            _ => return Ok(false),
        }

        Ok(true)
    }

    async fn switch_to(&mut self, target: &str) -> anyhow::Result<()> {
        if target == self.current_server() {
            self.send_system_message(&format!("Already connected to '{}'", target))
                .await?;
            return Ok(());
        }

        let address = self
            .ctx
            .config
            .server_address(target)
            .ok_or_else(|| anyhow::anyhow!("no such server"))?
            .to_string();

        if self.client_state != ClientPlayState::Play {
            anyhow::bail!("cannot switch servers while the client is still configuring");
        }

        // Log in first: if the target refuses, the player keeps their current
        // session and nothing has been disturbed.
        let backend = backend_login(
            &self.ctx.config,
            &address,
            &self.handshake,
            &self.username,
            self.uuid,
            self.client_addr,
        )
        .await?;

        self.perform_switch(backend, target.to_string()).await
    }

    async fn perform_switch(
        &mut self,
        backend: BackendConnection,
        target: String,
    ) -> anyhow::Result<()> {
        self.client_tx
            .write_packet(&RawPacket::new(
                play_clientbound::START_CONFIGURATION,
                Vec::new(),
            ))
            .await?;

        // Wait for the acknowledgement, discarding the Play packets still in
        // flight: they belong to the old server's session. The new backend is
        // already sending Configuration packets, but we do not read them until
        // the swap completes, so TCP backpressure holds them for us.
        let deadline = tokio::time::Instant::now() + CONFIG_ACK_TIMEOUT;
        loop {
            let frame = tokio::time::timeout_at(deadline, self.client_frames.recv())
                .await
                .map_err(|_| {
                    anyhow::anyhow!("client did not acknowledge the configuration switch")
                })?
                .ok_or_else(|| anyhow::anyhow!("client disconnected during the switch"))?;

            let (id, _) = read_varint(&frame)?;
            if id == play_serverbound::CONFIGURATION_ACKNOWLEDGED {
                break;
            }
        }

        self.client_state = ClientPlayState::Configuration;

        // Abort the old reader before replacing the channel, otherwise it could
        // push a stale frame into the new stream.
        self.backend_reader_task.abort();

        let (btx, backend_frames) = mpsc::channel(FRAME_CHANNEL_CAPACITY);
        self.backend_reader_task = spawn_frame_reader(backend.reader, btx);
        self.backend_frames = backend_frames;
        self.backend_tx = backend.writer;

        let previous = self.current_server();
        self.handle.set_current_server(&target);

        if self.ctx.config.advanced.log_player_connections {
            tracing::info!(
                "[{}] {} moved from '{}' to '{}'",
                self.client_addr,
                self.username,
                previous,
                target
            );
        }
        self.ctx.events.on_switch(&self.handle, &previous, &target);

        Ok(())
    }

    /// Returns true if the player was moved elsewhere and the session continues.
    async fn handle_backend_loss(&mut self) -> bool {
        if !self
            .ctx
            .config
            .advanced
            .failover_on_unexpected_server_disconnect
        {
            return false;
        }

        // Failover needs Start Configuration, which is a Play packet.
        if self.client_state != ClientPlayState::Play {
            return false;
        }

        let current = self.current_server();
        tracing::warn!(
            "[{}] backend '{}' closed unexpectedly, attempting failover",
            self.username,
            current
        );

        let route: Vec<String> = self
            .ctx
            .config
            .route_for(&self.handshake.server_address)
            .into_iter()
            .filter(|name| name != &current)
            .collect();

        for name in route {
            let Some(address) = self.ctx.config.server_address(&name).map(|s| s.to_string())
            else {
                continue;
            };

            match backend_login(
                &self.ctx.config,
                &address,
                &self.handshake,
                &self.username,
                self.uuid,
                self.client_addr,
            )
            .await
            {
                Ok(backend) => {
                    if self.perform_switch(backend, name.clone()).await.is_ok() {
                        let _ = self
                            .send_system_message(&format!("Moved to '{}'", name))
                            .await;
                        return true;
                    }
                }
                Err(e) => {
                    tracing::warn!("[{}] failover to '{}' failed: {:#}", self.username, name, e)
                }
            }
        }

        false
    }

    async fn send_system_message(&mut self, message: &str) -> anyhow::Result<()> {
        if self.client_state != ClientPlayState::Play {
            return Ok(());
        }
        let mut payload = nbt::text_component(message);
        payload.push(0x00); // not an action bar overlay
        self.client_tx
            .write_packet(&RawPacket::new(play_clientbound::SYSTEM_CHAT, payload))
            .await
    }

    async fn kick(&mut self, reason: &str) -> anyhow::Result<()> {
        if self.client_state != ClientPlayState::Play {
            return Ok(());
        }
        let payload = nbt::text_component(reason);
        self.client_tx
            .write_packet(&RawPacket::new(play_clientbound::DISCONNECT, payload))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::is_valid_username;

    #[test]
    fn username_validation() {
        assert!(is_valid_username("Notch"));
        assert!(is_valid_username("jeb_"));
        assert!(is_valid_username("a_1234567890XYZ"));

        assert!(!is_valid_username("ab"), "too short");
        assert!(!is_valid_username("a".repeat(17).as_str()), "too long");
        assert!(!is_valid_username("has space"));
        assert!(!is_valid_username("emoji\u{1F600}"));
        assert!(!is_valid_username("semi;colon"));
        assert!(!is_valid_username(""));
    }
}

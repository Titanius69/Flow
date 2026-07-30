use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// How player information reaches the backend.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum ForwardingMode {
    /// No forwarding: the backend sees the proxy as the player.
    None,
    /// Velocity modern forwarding.
    #[default]
    Modern,
}

/// The `[servers]` table. Velocity keeps the `try` order inside it alongside
/// the server definitions, so this table is deliberately mixed-type.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct ServersSection {
    /// Order in which servers are attempted for a player with no forced host.
    #[serde(rename = "try", default)]
    pub try_order: Vec<String>,
    /// name -> "host:port"
    #[serde(flatten, default)]
    pub servers: HashMap<String, String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "kebab-case", default)]
pub struct Advanced {
    /// Compression threshold offered to clients, in bytes. `-1` disables it.
    pub compression_threshold: i32,
    /// Accept a HAProxy PROXY protocol header (v1 or v2) before the handshake.
    pub haproxy_protocol: bool,
    /// TCP connect timeout to a backend, in milliseconds.
    pub connection_timeout: u64,
    /// Drop a connection that sends nothing for this long, in milliseconds.
    /// `0` disables it, which leaves the proxy open to idle-socket exhaustion.
    pub read_timeout: u64,
    /// Maximum concurrent connections. `0` disables the limit.
    pub connection_limit: usize,
    /// Maximum concurrent connections from one address. `0` disables.
    pub connections_per_ip: usize,
    /// Minimum milliseconds between login attempts from one address.
    pub login_ratelimit: u64,
    /// Handle the BungeeCord plugin message channel for backend plugins.
    pub bungee_plugin_message_channel: bool,
    /// Try the next server in the list when one fails during login.
    pub failover_on_unexpected_server_disconnect: bool,
    /// Log joins, server switches and disconnects at info level.
    pub log_player_connections: bool,
}

impl Default for Advanced {
    fn default() -> Self {
        Self {
            compression_threshold: 256,
            haproxy_protocol: false,
            connection_timeout: 5000,
            read_timeout: 30000,
            connection_limit: 1000,
            connections_per_ip: 4,
            login_ratelimit: 3000,
            bungee_plugin_message_channel: true,
            failover_on_unexpected_server_disconnect: true,
            log_player_connections: true,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "kebab-case", default)]
pub struct Config {
    pub bind: String,
    pub motd: String,
    pub show_max_players: i32,
    /// Only `false` is supported: the proxy performs no Mojang authentication.
    pub online_mode: bool,
    /// Disconnect an existing session when the same name logs in again.
    pub kick_existing_players: bool,
    /// Directory scanned for `.fpkg` plugin packages.
    pub plugins_directory: String,
    pub player_info_forwarding_mode: ForwardingMode,
    /// Path to a file holding the forwarding secret, as Velocity does.
    pub forwarding_secret_file: Option<String>,
    /// Inline alternative to `forwarding-secret-file`.
    pub forwarding_secret: Option<String>,
    /// Protocol version advertised in the ping (769 = 1.21.4).
    pub protocol_version: i32,
    /// Version name shown in the ping.
    pub version_name: String,
    pub servers: ServersSection,
    /// vhost -> server names to try, matched on the address the client used.
    pub forced_hosts: HashMap<String, Vec<String>>,
    pub advanced: Advanced,

    /// Resolved at load time from the secret file or the inline value.
    #[serde(skip)]
    resolved_secret: String,
}

impl Default for Config {
    fn default() -> Self {
        let mut servers = HashMap::new();
        servers.insert("lobby".to_string(), "127.0.0.1:25566".to_string());

        Self {
            bind: "0.0.0.0:25577".to_string(),
            motd: "A Flow-Proxy Server".to_string(),
            show_max_players: 500,
            online_mode: false,
            kick_existing_players: false,
            plugins_directory: "plugins".to_string(),
            player_info_forwarding_mode: ForwardingMode::Modern,
            forwarding_secret_file: Some("forwarding.secret".to_string()),
            forwarding_secret: None,
            protocol_version: crate::protocol::packets::PROTOCOL_VERSION,
            version_name: "1.21.4".to_string(),
            servers: ServersSection {
                try_order: vec!["lobby".to_string()],
                servers,
            },
            forced_hosts: HashMap::new(),
            advanced: Advanced::default(),
            resolved_secret: String::new(),
        }
    }
}

impl Config {
    /// Loads the config, writing out a default one if the file is missing.
    pub fn load_or_create<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let path = path.as_ref();

        if !path.exists() {
            let default = Config::default();
            let toml_str =
                toml::to_string_pretty(&default).context("failed to serialize default config")?;
            fs::write(path, toml_str)
                .with_context(|| format!("failed to write default config to {:?}", path))?;
            tracing::warn!(
                "No config found at {:?}. A default one has been created. \
                 Review the [servers] table and the forwarding secret before use.",
                path
            );
        }

        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read config at {:?}", path))?;
        let mut config: Config = toml::from_str(&content)
            .with_context(|| format!("failed to parse config at {:?}", path))?;

        config.resolve_secret()?;
        config.validate()?;
        Ok(config)
    }

    /// Reads the secret from `forwarding-secret-file`, falling back to the
    /// inline `forwarding-secret`.
    fn resolve_secret(&mut self) -> anyhow::Result<()> {
        if let Some(file) = &self.forwarding_secret_file {
            let path = Path::new(file);
            if path.exists() {
                let secret = fs::read_to_string(path)
                    .with_context(|| format!("failed to read secret file {:?}", path))?;
                // A trailing newline is easy to add by accident and would make
                // the HMAC differ from the backend's for no visible reason.
                self.resolved_secret = secret.trim().to_string();
                return Ok(());
            }
            if self.forwarding_secret.is_none()
                && self.player_info_forwarding_mode == ForwardingMode::Modern
            {
                anyhow::bail!(
                    "forwarding-secret-file {:?} does not exist and no inline \
                     forwarding-secret is set",
                    path
                );
            }
        }

        self.resolved_secret = self.forwarding_secret.clone().unwrap_or_default();
        Ok(())
    }

    /// The secret used to sign forwarding payloads.
    pub fn forwarding_secret(&self) -> &str {
        &self.resolved_secret
    }

    /// Builds a config with an inline secret, for tests.
    pub fn with_secret(mut self, secret: &str) -> Self {
        self.forwarding_secret = Some(secret.to_string());
        self.forwarding_secret_file = None;
        self.resolved_secret = secret.to_string();
        self
    }

    /// Catches the misconfigurations that would otherwise surface as a
    /// confusing mid-login kick.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.online_mode {
            anyhow::bail!(
                "online-mode = true is not supported: this proxy performs no Mojang \
                 authentication. Set online-mode = false."
            );
        }

        if self.servers.servers.is_empty() {
            anyhow::bail!("the [servers] table is empty; define at least one backend");
        }

        if self.servers.try_order.is_empty() {
            anyhow::bail!(
                "servers.try is empty; list at least one server name, e.g. try = [\"lobby\"]"
            );
        }

        for name in &self.servers.try_order {
            if !self.servers.servers.contains_key(name) {
                anyhow::bail!("servers.try references unknown server '{}'", name);
            }
        }

        for (host, names) in &self.forced_hosts {
            if names.is_empty() {
                anyhow::bail!("forced host '{}' lists no servers", host);
            }
            for name in names {
                if !self.servers.servers.contains_key(name) {
                    anyhow::bail!("forced host '{}' references unknown server '{}'", host, name);
                }
            }
        }

        if self.player_info_forwarding_mode == ForwardingMode::Modern {
            if self.resolved_secret.is_empty() {
                anyhow::bail!(
                    "player-info-forwarding-mode is MODERN but the forwarding secret is \
                     empty. It must match paper-global.yml -> proxies.velocity.secret."
                );
            }
            if self.resolved_secret == "ChangeThisSecretToMatchYourBackendConfig" {
                tracing::warn!(
                    "The forwarding secret is still the default placeholder. The backend \
                     will reject every login until it matches its velocity secret."
                );
            }
        }

        if self.protocol_version != crate::protocol::packets::PROTOCOL_VERSION {
            tracing::warn!(
                "protocol-version is set to {} but the Configuration and Play packet IDs \
                 compiled into this build are for {}. Server switching will misbehave.",
                self.protocol_version,
                crate::protocol::packets::PROTOCOL_VERSION
            );
        }

        Ok(())
    }

    /// The rate limits derived from the advanced section.
    pub fn limits(&self) -> crate::limiter::Limits {
        crate::limiter::Limits {
            connection_limit: self.advanced.connection_limit,
            connections_per_ip: self.advanced.connections_per_ip,
            login_ratelimit: std::time::Duration::from_millis(self.advanced.login_ratelimit),
        }
    }

    /// The idle read timeout, or `None` when disabled.
    pub fn read_timeout(&self) -> Option<std::time::Duration> {
        match self.advanced.read_timeout {
            0 => None,
            ms => Some(std::time::Duration::from_millis(ms)),
        }
    }

    /// All configured server names, sorted for stable output.
    pub fn server_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.servers.servers.keys().cloned().collect();
        names.sort_unstable();
        names
    }

    /// Resolves the address of a named server.
    pub fn server_address(&self, name: &str) -> Option<&str> {
        self.servers.servers.get(name).map(|s| s.as_str())
    }

    /// The ordered list of server names to attempt for a client that connected
    /// via `vhost`.
    ///
    /// A matching forced host wins outright; Velocity does not fall back to the
    /// try list in that case, and neither do we, because a forced host is a
    /// routing decision rather than a preference.
    pub fn route_for(&self, vhost: &str) -> Vec<String> {
        let host = normalise_host(vhost);

        for (pattern, names) in &self.forced_hosts {
            if normalise_host(pattern) == host {
                return names.clone();
            }
        }

        self.servers.try_order.clone()
    }
}

/// Lowercases and strips any port and trailing dot, so that `MC.Example.COM.`
/// and `mc.example.com:25565` match the same forced host.
fn normalise_host(host: &str) -> String {
    // Legacy BungeeCord forwarding appends NUL-separated fields to the vhost.
    let host = host.split('\0').next().unwrap_or(host);
    let host = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    host.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
bind = "0.0.0.0:8659"
motd = "SolarNetwork"
show-max-players = 500
online-mode = false
player-info-forwarding-mode = "MODERN"
forwarding-secret = "shhh"
protocol-version = 769
version-name = "1.21.4"

[servers]
lobby = "10.0.0.1:8440"
survival = "10.0.0.2:8441"
try = ["lobby", "survival"]

[forced-hosts]
"survival.example.com" = ["survival"]

[advanced]
compression-threshold = 256
haproxy-protocol = true
"#;

    fn sample() -> Config {
        let mut c: Config = toml::from_str(SAMPLE).unwrap();
        c.resolve_secret().unwrap();
        c
    }

    #[test]
    fn try_is_parsed_out_of_the_servers_table() {
        let c = sample();
        assert_eq!(c.servers.try_order, vec!["lobby", "survival"]);
        // `try` must not also be captured as a server entry.
        assert_eq!(c.servers.servers.len(), 2);
        assert_eq!(c.server_address("lobby"), Some("10.0.0.1:8440"));
        assert_eq!(c.server_address("survival"), Some("10.0.0.2:8441"));
        assert!(!c.servers.servers.contains_key("try"));
    }

    #[test]
    fn advanced_section_is_read() {
        let c = sample();
        assert!(c.advanced.haproxy_protocol);
        assert_eq!(c.advanced.compression_threshold, 256);
        // Unspecified keys keep their defaults.
        assert_eq!(c.advanced.connection_timeout, 5000);
        assert!(c.advanced.failover_on_unexpected_server_disconnect);
    }

    #[test]
    fn unsupported_velocity_keys_are_ignored_not_fatal() {
        // A real Velocity config carries sections we do not implement; loading
        // must not fail on them.
        let extra = format!(
            "{}\n[query]\nenabled = false\n\n[packet-limiter]\ninterval = 7\n",
            SAMPLE
        );
        let c: Config = toml::from_str(&extra).unwrap();
        assert_eq!(c.bind, "0.0.0.0:8659");
    }

    #[test]
    fn forced_host_routing() {
        let c = sample();
        assert_eq!(c.route_for("survival.example.com"), vec!["survival"]);
        // Port and case must not defeat the match.
        assert_eq!(c.route_for("Survival.Example.com:8659"), vec!["survival"]);
        // Anything else falls back to the try order.
        assert_eq!(c.route_for("play.example.com"), vec!["lobby", "survival"]);
    }

    #[test]
    fn validation_rejects_unknown_server_in_try() {
        let mut c = sample();
        c.servers.try_order = vec!["nope".into()];
        assert!(c.validate().is_err());
    }

    #[test]
    fn validation_rejects_unknown_server_in_forced_host() {
        let mut c = sample();
        c.forced_hosts
            .insert("x.example.com".into(), vec!["ghost".into()]);
        assert!(c.validate().is_err());
    }

    #[test]
    fn validation_rejects_online_mode() {
        let mut c = sample();
        c.online_mode = true;
        assert!(c.validate().is_err());
    }

    #[test]
    fn validation_rejects_empty_secret_in_modern_mode() {
        let mut c = sample();
        c.resolved_secret = String::new();
        assert!(c.validate().is_err());
    }

    #[test]
    fn valid_config_passes() {
        assert!(sample().validate().is_ok());
    }

    #[test]
    fn secret_file_wins_and_is_trimmed() {
        let dir = std::env::temp_dir().join(format!("flowcfg{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let secret_path = dir.join("forwarding.secret");
        fs::write(&secret_path, "from-file\n").unwrap();

        let mut c = sample();
        c.forwarding_secret_file = Some(secret_path.to_string_lossy().to_string());
        c.forwarding_secret = Some("inline".into());
        c.resolve_secret().unwrap();
        assert_eq!(c.forwarding_secret(), "from-file");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_secret_file_with_no_inline_value_is_an_error() {
        let mut c = sample();
        c.forwarding_secret_file = Some("/nonexistent/forwarding.secret".into());
        c.forwarding_secret = None;
        assert!(c.resolve_secret().is_err());
    }
}

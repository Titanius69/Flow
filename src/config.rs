use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BackendConfig {
    /// Address of the backend Minecraft server (host:port).
    pub address: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Config {
    /// Address the proxy listens on.
    pub bind: String,
    /// MOTD shown in the server list.
    pub motd: String,
    /// Max players reported in the server list.
    pub max_players: i32,
    /// Protocol version advertised in the ping (769 = 1.21.4).
    pub protocol_version: i32,
    /// Version name shown in the server list ping.
    pub version_name: String,
    /// The backend server connections are forwarded to.
    pub backend: BackendConfig,
    /// Secret for Velocity "modern" player info forwarding. Must match the
    /// backend's `paper-global.yml` -> `proxies.velocity.secret`.
    pub forwarding_secret: String,
    /// Compression threshold offered to clients, in bytes. Packets at least
    /// this large are deflated. `-1` disables compression toward clients.
    /// This is independent of whatever the backend negotiates with us.
    #[serde(default = "default_compression_threshold")]
    pub compression_threshold: i32,
}

fn default_compression_threshold() -> i32 {
    256
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:25577".to_string(),
            motd: "A Flow-Proxy Server".to_string(),
            max_players: 100,
            protocol_version: 769,
            version_name: "1.21.4".to_string(),
            backend: BackendConfig {
                address: "127.0.0.1:25566".to_string(),
            },
            forwarding_secret: "ChangeThisSecretToMatchYourBackendConfig".to_string(),
            compression_threshold: default_compression_threshold(),
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
                 Review `forwarding_secret` and `backend.address` before use.",
                path
            );
        }

        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read config at {:?}", path))?;
        let config: Config = toml::from_str(&content)
            .with_context(|| format!("failed to parse config at {:?}", path))?;

        config.validate()?;
        Ok(config)
    }

    /// Catches the misconfigurations that otherwise show up as a confusing
    /// mid-login kick rather than a startup error.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.forwarding_secret.trim().is_empty() {
            anyhow::bail!(
                "forwarding_secret is empty. Set it to the same value as \
                 paper-global.yml -> proxies.velocity.secret on the backend."
            );
        }
        if self.forwarding_secret == "ChangeThisSecretToMatchYourBackendConfig" {
            tracing::warn!(
                "forwarding_secret is still the default placeholder. The backend \
                 will reject every login until this matches its velocity secret."
            );
        }
        Ok(())
    }
}

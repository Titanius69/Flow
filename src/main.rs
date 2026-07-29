use std::sync::Arc;
use tokio::net::TcpListener;

use flow_proxy::config::Config;
use flow_proxy::session::ClientSession;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "flow_proxy=info,tokio=warn".into()),
        )
        .init();

    let config = Arc::new(Config::load_or_create("flow-proxy.toml")?);
    tracing::info!(
        "Flow-Proxy {} starting on {} -> backend {} (protocol {} / {})",
        env!("CARGO_PKG_VERSION"),
        config.bind,
        config.backend.address,
        config.protocol_version,
        config.version_name
    );

    let listener = TcpListener::bind(&config.bind).await?;
    tracing::info!("Listening on {}", config.bind);

    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                // A single failed accept must not take the whole proxy down.
                tracing::warn!("accept failed: {}", e);
                continue;
            }
        };

        if let Err(e) = stream.set_nodelay(true) {
            tracing::warn!("Failed to set TCP_NODELAY for {}: {}", addr, e);
        }

        let config = Arc::clone(&config);
        tokio::spawn(async move {
            ClientSession::new(stream, addr, config).run().await;
        });
    }
}

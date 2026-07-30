use std::sync::Arc;
use tokio::net::TcpListener;

use flow_proxy::config::Config;
use flow_proxy::haproxy;
use flow_proxy::plugins::PluginHost;
use flow_proxy::registry::Registry;
use flow_proxy::session::{ClientSession, ProxyContext};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "flow_proxy=info,tokio=warn".into()),
        )
        .init();

    let config = Arc::new(Config::load_or_create("flow-proxy.toml")?);

    // Plugins share the registry with the sessions, so they see players appear
    // and disappear without any extra plumbing.
    let registry = Arc::new(Registry::new());
    let plugins = Arc::new(PluginHost::load_all(
        std::path::Path::new(&config.plugins_directory),
        Arc::clone(&registry),
    )?);
    if plugins.count() > 0 {
        tracing::info!("Plugins: {}", plugins.names().join(", "));
    }

    let ctx = ProxyContext::with_parts(
        Arc::clone(&config),
        registry,
        Arc::clone(&plugins) as Arc<dyn flow_proxy::session::EventSink>,
    );

    tracing::info!(
        "Flow-Proxy {} on {} (protocol {} / {})",
        env!("CARGO_PKG_VERSION"),
        config.bind,
        config.protocol_version,
        config.version_name
    );
    for name in &config.servers.try_order {
        if let Some(addr) = config.server_address(name) {
            tracing::info!("  try: {} -> {}", name, addr);
        }
    }
    for (host, names) in &config.forced_hosts {
        tracing::info!("  forced host: {} -> {:?}", host, names);
    }
    if config.advanced.haproxy_protocol {
        tracing::info!("  expecting a HAProxy PROXY protocol header on every connection");
    }

    let listener = TcpListener::bind(&config.bind).await?;
    tracing::info!("Listening on {}", config.bind);

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                // A single failed accept must not take the whole proxy down.
                tracing::warn!("accept failed: {}", e);
                continue;
            }
        };

        if let Err(e) = stream.set_nodelay(true) {
            tracing::warn!("Failed to set TCP_NODELAY for {}: {}", peer, e);
        }

        // Account for the connection before doing any work on it, so a flood
        // is turned away at the door rather than after a backend dial.
        let guard = match ctx.limiter.accept(peer.ip()) {
            Ok(guard) => guard,
            Err(reason) => {
                tracing::debug!("[{}] refused: {:?}", peer, reason);
                continue;
            }
        };

        let ctx = Arc::clone(&ctx);
        tokio::spawn(async move {
            let enabled = ctx.config.advanced.haproxy_protocol;
            match haproxy::resolve_client_address(stream, peer, enabled).await {
                Ok(Some((stream, addr))) => {
                    ClientSession::with_guard(stream, addr, ctx, Some(guard))
                        .run()
                        .await;
                }
                // A health check from the load balancer: nothing to serve.
                Ok(None) => {}
                Err(e) => tracing::debug!("[{}] rejected: {:#}", peer, e),
            }
        });
    }
}

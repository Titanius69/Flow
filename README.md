# Flow-Proxy

Experimental Velocity-like Minecraft proxy in Rust.

Targets protocol **769 (Minecraft 1.21.4)** and forwards players to a Paper
backend using Velocity "modern" player info forwarding.

## Features

- Server list ping handled by the proxy (configurable MOTD, player count, version)
- Velocity modern forwarding with HMAC-SHA256 signing and version negotiation
- Packet compression on both sides, negotiated independently per connection
- Vanilla-compatible offline-mode UUIDs
- Frame-level relay for the Configuration and Play states

## Requirements

The backend must be configured for modern forwarding:

```properties
# server.properties
online-mode=false
```

```yaml
# config/paper-global.yml
proxies:
  velocity:
    enabled: true
    online-mode: false
    secret: 'your-secret-here'
```

Keep the backend port unreachable from the internet. With `online-mode=false`,
anyone who can connect to it directly can join as any player.

## Configuration

`flow-proxy.toml` is created on first run:

```toml
bind = "0.0.0.0:25577"
motd = "A Flow-Proxy Server"
max_players = 100
protocol_version = 769
version_name = "1.21.4"
forwarding_secret = "your-secret-here"   # must match Paper's velocity secret
compression_threshold = 256              # -1 disables compression to clients

[backend]
address = "127.0.0.1:25566"
```

## Usage

```sh
cargo run --release
RUST_LOG=flow_proxy=debug cargo run   # verbose login tracing
cargo test
```

## Limitations

Experimental, and not a Velocity replacement:

- Single backend only — no server switching or `/server` command
- No Mojang authentication, so players are offline-mode
- No plugin API, commands, or player list
- Forwarding versions 2–4 are implemented but unusable without online mode,
  since they require a Mojang-signed player key

## License

MIT
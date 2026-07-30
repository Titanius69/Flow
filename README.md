# Flow-Proxy

Experimental Velocity-like Minecraft proxy in Rust.

Protocol **769 (Minecraft 1.21.4)**. Routes players across multiple Paper
backends with Velocity modern forwarding, sits behind HAProxy, and runs plugins
written in Rust.

## Features

- Server list ping, answered by the proxy with the live player count
- Velocity modern forwarding, HMAC-SHA256 signed, with version negotiation
- Multiple backends: `try` order, `[forced-hosts]` routing, failover
- Runtime server switching with `/server`, `/glist`, and no reconnect
- BungeeCord plugin channel (`bungeecord:main`) so backend plugins can move
  players, message them, and query the proxy
- Rust plugin API with `.fpkg` packages, compiled at startup
- HAProxy PROXY protocol v1 and v2 inbound
- Idle timeouts, connection limits and login rate limiting
- Per-connection compression, negotiated independently with each peer

## Backend setup (Paper)

Each backend needs all three:

```properties
# server.properties
online-mode=false
server-ip=127.0.0.1
```

```yaml
# config/paper-global.yml
proxies:
  velocity:
    enabled: true
    online-mode: true
    secret: 'your-secret-here'
```

The secret must match the proxy's byte for byte. Keep backend ports unreachable
from the internet: with `online-mode=false`, anyone who can connect directly can
join as any player.

## Configuration

See `flow-proxy.toml.example`. The format follows Velocity's, so an existing
`velocity.toml` is mostly copy-pasteable.

**Honored keys:** `bind`, `motd`, `show-max-players`, `online-mode`,
`kick-existing-players`, `player-info-forwarding-mode`,
`forwarding-secret-file`, `plugins-directory`, `[servers]` including `try`,
`[forced-hosts]`, and in `[advanced]`: `compression-threshold`,
`haproxy-protocol`, `connection-timeout`, `read-timeout`, `connection-limit`,
`connections-per-ip`, `login-ratelimit`, `bungee-plugin-message-channel`,
`failover-on-unexpected-server-disconnect`, `log-player-connections`.

**Silently ignored:** everything else, including `[query]`, `[packet-limiter]`,
`ping-passthrough` and `compression-level`. A real `velocity.toml` loads without
error, but those options do nothing here.

## Usage

```sh
cargo run --release
RUST_LOG=flow_proxy=debug cargo run   # verbose login, switch and plugin tracing
cargo test --workspace
```

## Plugins

Plugins are Rust `cdylib`s, packaged as `.fpkg` and **compiled by the proxy at
startup**. That is deliberate: Rust has no stable ABI, so a pre-compiled plugin
built by a different toolchain could disagree with the proxy about type layout
in ways no version check can catch. Building both with the same compiler removes
that class of failure — at the cost of needing a Rust toolchain on the server.

```sh
cargo run -p fpkg -- new greeter        # scaffold
cargo run -p fpkg -- check greeter      # validate
cargo run -p fpkg -- pack greeter -o plugins/greeter.fpkg
```

Drop the `.fpkg` in `plugins/` and start the proxy. Builds are cached by package
hash, so an unchanged plugin is compiled once.

```rust
use flow_plugin_api::prelude::*;

#[derive(Default)]
struct Greeter;

impl Plugin for Greeter {
    fn on_enable(&mut self, api: &Api) {
        api.info("greeter starting up");
    }

    fn on_join(&mut self, api: &Api, player: &PlayerRef) {
        api.send_message(player.username, "Welcome!");
    }

    fn on_command(&mut self, api: &Api, player: &PlayerRef, command: &str) -> bool {
        if command == "hub" {
            api.connect_player(player.username, "lobby");
            return true; // consumed, never reaches the backend
        }
        false
    }
}

flow_plugin!(Greeter);
```

Events: `on_enable`, `on_disable`, `on_join`, `on_leave`, `on_switch`,
`on_command`. Host API: logging, `send_message`, `connect_player`,
`kick_player`, `player_count`, `player_names`, `current_server`. A full example
is in `examples/hello-plugin`.

A package holds source, not binaries:

```text
manifest.toml    id, version, library name, api-version
Cargo.toml       must build a cdylib and depend on the API placeholder
src/**
```

**Plugins are trusted code.** They run in-process with no sandbox: a plugin can
read anything the proxy can and can block the runtime. Panics are contained by
`catch_unwind` at the boundary, but memory-unsafe code in a plugin is
memory-unsafe in the proxy.

## Security notes

- `read-timeout`, `connection-limit`, `connections-per-ip` and `login-ratelimit`
  exist because without them a single host can exhaust file descriptors and
  amplify the load onto Paper. Setting any to `0` disables it.
- Compressed frames are bounded by the size they declare. Zlib reaches roughly
  1000:1 on repetitive input, so an unbounded inflate turns a 2 KB frame into an
  out-of-memory kill.
- Clients on other protocol versions are refused at login. The Configuration and
  Play packet IDs compiled in belong to one version, so a mismatched client
  would not fail loudly — it would exchange plausible packets with the wrong
  meanings.
- Usernames are validated before they reach a backend or the registry.

## Testing

```sh
cargo test --workspace     # unit, end-to-end, robustness, plugin system
cargo +nightly fuzz run decoders     # see fuzz/README.md
```

`tests/robustness.rs` sweeps every decoder with malformed input on each run;
`tests/plugin_system.rs` packs, compiles, loads and drives a real plugin through
the FFI boundary.

## Limitations

Not a Velocity replacement:

- **Protocol 769 only.** Configuration and Play packet IDs live in one table in
  `src/protocol/packets.rs`, taken from version-pinned data rather than memory.
  Supporting another version means adding another table.
- **Server switching is tested against mock backends, not a real client.** The
  sequencing is verified; whether the IDs match a real 1.21.4 client is not.
- No Mojang authentication, so players are offline-mode. Forwarding versions 2–4
  are implemented but unusable without it, since they need a signed player key.
- No tab list, no cross-server chat, no tab completion for proxy commands.
- Failover needs the client in Play state; a backend lost during configuration
  ends the session.
- Building plugins at startup requires cargo on the server.

## Design notes

- `RawPacket` has no async read/write helpers on purpose. Framing and
  compression live in `protocol::connection`, so nothing can read from a socket
  while bypassing the compression state.
- Socket reads run in their own tasks feeding channels rather than directly in a
  `select!` arm: `read_frame` is not cancellation-safe, and dropping it mid-frame
  would desynchronise the stream. Channel receives are safe to cancel.
- During a switch the new backend is fully logged in before the client is
  disturbed, so a refused target leaves the player where they were.
- The `flow-plugin-api` source is embedded in the proxy binary and written out at
  startup, so a deployed server can build plugins without the proxy's source
  tree.

## License

MIT

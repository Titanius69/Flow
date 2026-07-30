# Flow-Proxy Plugin API Documentation

**Repository:** [https://github.com/Titanius69/Flow](https://github.com/Titanius69/Flow)

---

## Introduction

Flow-Proxy is an experimental Velocity-like Minecraft proxy written in Rust, targeting protocol **769 (Minecraft 1.21.4)**. The plugin API allows you to extend the proxy's functionality with Rust plugins packaged as `.fpkg` files. Plugins are compiled and loaded automatically when the proxy starts.

**Important:** Plugins are compiled together with the proxy using the same Rust toolchain, eliminating ABI compatibility issues.

---

## Quick Start

### 1. Create a plugin project

Use the `fpkg` tool:

```bash
fpkg new my-plugin
```

This creates a `my-plugin` directory with the necessary files.

### 2. Develop the plugin

Edit `src/lib.rs`:

```rust
use flow_plugin_api::prelude::*;

#[derive(Default)]
struct MyPlugin;

impl Plugin for MyPlugin {
    fn on_enable(&mut self, api: &Api) {
        api.info("My plugin enabled!");
    }
}

flow_plugin!(MyPlugin);
```

### 3. Package the plugin

```bash
fpkg pack my-plugin -o plugins/my-plugin.fpkg
```

### 4. Start the proxy

Place the `.fpkg` file in the proxy's `plugins` directory and start the proxy. The plugin will be automatically compiled and loaded.

---

## Plugin Structure

### `Cargo.toml`

```toml
[package]
name = "my_plugin"
version = "0.1.0"
edition = "2021"

[lib]
name = "my_plugin"
crate-type = ["cdylib"]

[dependencies]
flow-plugin-api = { path = "$FLOW_PLUGIN_API" }
```

**Note:** The `$FLOW_PLUGIN_API` placeholder is automatically replaced by the proxy with the correct API path.

### `manifest.toml`

```toml
[plugin]
id = "my-plugin"           # Unique identifier (alphanumeric, -, _ only)
name = "My Plugin"         # Display name
version = "0.1.0"          # Version
authors = ["Your Name"]    # Authors
description = "..."        # Description
api-version = 1            # API version (currently 1)
library = "my_plugin"      # cdylib name (must match Cargo.toml [lib] name)
```

### `src/lib.rs`

```rust
use flow_plugin_api::prelude::*;

#[derive(Default)]
struct MyPlugin;

impl Plugin for MyPlugin {
    // Implement optional methods...
}

flow_plugin!(MyPlugin);
```

---

## API Reference

### `Plugin` Trait

Every plugin must implement the `Plugin` trait.

```rust
pub trait Plugin: Send + 'static {
    fn on_enable(&mut self, _api: &Api) {}
    fn on_disable(&mut self, _api: &Api) {}
    fn on_join(&mut self, _api: &Api, _player: &PlayerRef) {}
    fn on_leave(&mut self, _api: &Api, _player: &PlayerRef) {}
    fn on_switch(&mut self, _api: &Api, _player: &PlayerRef, _from: &str, _to: &str) {}
    fn on_command(&mut self, _api: &Api, _player: &PlayerRef, _command: &str) -> bool {
        false
    }
}
```

#### Method Details

| Method | When Called | Note |
|--------|-------------|------|
| `on_enable` | When the plugin is loaded | Initialize state here |
| `on_disable` | When the proxy shuts down | Free resources |
| `on_join` | When a player joins | **Called only in Play state** |
| `on_leave` | When a player leaves | - |
| `on_switch` | When a player switches servers | `from` and `to` parameters |
| `on_command` | When a player types a command | Return `true` to prevent forwarding to backend |

### `PlayerRef` Struct

```rust
pub struct PlayerRef<'a> {
    pub username: &'a str,
    pub uuid: &'a str,
    pub server: &'a str,
}
```

| Field | Description |
|-------|-------------|
| `username` | Player's username |
| `uuid` | Player's UUID (as string) |
| `server` | Current server name |

### `Api` Struct

The `Api` provides access to host functions.

#### Logging

```rust
api.error("Error message");
api.warn("Warning");
api.info("Information");
api.debug("Debug message");
```

#### Player Management

```rust
// Send a message to a player or everyone
let success = api.send_message("Notch", "Hello!");
let success = api.send_message("ALL", "Server starting!");

// Move a player to another server
api.connect_player("Notch", "survival");

// Kick a player
api.kick_player("Notch", "You've been banned!");

// Get online player count
let count = api.player_count();

// List online players (on a specific server or all)
let names = api.player_names("");      // All servers
let names = api.player_names("lobby"); // Only on lobby

// Get a player's current server
if let Some(server) = api.current_server("Notch") {
    println!("Notch is on {}", server);
}
```

---

## Events

### `on_join`

Called when a player joins the proxy and has reached the Play state.

```rust
fn on_join(&mut self, api: &Api, player: &PlayerRef) {
    api.send_message(
        player.username,
        &format!("Welcome, {}!", player.username)
    );
}
```

### `on_leave`

Called when a player leaves.

```rust
fn on_leave(&mut self, api: &Api, player: &PlayerRef) {
    api.info(&format!("{} left", player.username));
}
```

### `on_switch`

Called when a player switches servers.

```rust
fn on_switch(&mut self, api: &Api, player: &PlayerRef, from: &str, to: &str) {
    api.send_message(
        player.username,
        &format!("Moved: {} → {}", from, to)
    );
}
```

### `on_command`

Called when a player types a command.

```rust
fn on_command(&mut self, api: &Api, player: &PlayerRef, command: &str) -> bool {
    match command {
        "hub" => {
            api.connect_player(player.username, "lobby");
            true // Command is consumed, not forwarded to backend
        }
        "count" => {
            let count = api.player_count();
            api.send_message(player.username, &format!("Online: {}", count));
            true
        }
        _ => false // Command is forwarded to the backend
    }
}
```

---

## Full Example Plugin

```rust
use flow_plugin_api::prelude::*;

#[derive(Default)]
struct Greeter {
    join_count: u32,
}

impl Plugin for Greeter {
    fn on_enable(&mut self, api: &Api) {
        api.info("Greeter plugin enabled!");
    }

    fn on_disable(&mut self, api: &Api) {
        api.info(&format!("Total joins: {}", self.join_count));
    }

    fn on_join(&mut self, api: &Api, player: &PlayerRef) {
        self.join_count += 1;
        api.send_message(
            player.username,
            &format!("Welcome, {}! (You are #{})", player.username, self.join_count)
        );
    }

    fn on_switch(&mut self, api: &Api, player: &PlayerRef, from: &str, to: &str) {
        api.debug(&format!("{}: {} → {}", player.username, from, to));
    }

    fn on_command(&mut self, api: &Api, player: &PlayerRef, command: &str) -> bool {
        match command {
            "hub" => {
                api.connect_player(player.username, "lobby");
                true
            }
            "count" => {
                let names = api.player_names("");
                let count = api.player_count();
                api.send_message(
                    player.username,
                    &format!("Online ({}) : {}", count, names.join(", "))
                );
                true
            }
            "whoami" => {
                api.send_message(
                    player.username,
                    &format!("You are {} on {}.", player.username, player.server)
                );
                true
            }
            _ => false
        }
    }
}

flow_plugin!(Greeter);
```

---

## Packaging and Installation

### Tools

The `fpkg` command-line tool is part of the proxy:

```bash
# Create a new plugin
fpkg new <id> [--dir <path>]

# Validate a plugin source directory
fpkg check [<dir>]

# Package a plugin
fpkg pack [<dir>] [-o <file>]

# View package information
fpkg info <file.fpkg>
```

### Examples

```bash
# Create a new plugin
fpkg new my-plugin --dir ./plugins/my-plugin

# Package it
cd ./plugins/my-plugin
fpkg pack -o ../my-plugin.fpkg

# Inspect the package
fpkg info ../my-plugin.fpkg
```

---

## Debugging

### Logging

Set the `RUST_LOG` environment variable:

```bash
# Plugin logs only
RUST_LOG=flow_proxy=info,plugin=debug ./flow-proxy

# All logs
RUST_LOG=debug ./flow-proxy
```

### Common Errors

1. **"plugin speaks ABI X but this proxy speaks Y"**  
   The plugin targets a different API version. Update `api-version` in `manifest.toml`.

2. **"cargo build failed"**  
   Check `Cargo.toml` syntax and dependencies.

3. **"the build produced no *.dll"**  
   Ensure `Cargo.toml` contains `[lib] crate-type = ["cdylib"]`.

4. **Messages not appearing**  
   Verify that the backend Paper server has BungeeCord plugin channel enabled.

---

## Tips & Tricks

### State Persistence

Plugin state persists throughout the proxy's lifetime:

```rust
#[derive(Default)]
struct MyPlugin {
    player_count: u32,
    last_join: Option<String>,
}
```

### Performance

- Avoid blocking operations in event handlers.
- Use `tokio::spawn` for long-running tasks.
- Keep `on_command` fast (no network operations).

### Security

- Plugins have **full access** to the proxy's memory.
- Only load plugins from trusted sources.
- Plugins **do not run in a sandbox**.

---

## Supported Versions

| Proxy Version | API Version | Minecraft Protocol |
|---------------|-------------|-------------------|
| 0.3.0+        | 1           | 769 (1.21.4)      |

---

## Additional Resources

- **Source Code:** [https://github.com/Titanius69/Flow](https://github.com/Titanius69/Flow)
- **API Source:** `crates/flow-plugin-api/`
- **Example Plugin:** `examples/hello-plugin/`

---

## License

MIT License — see the [repository](https://github.com/Titanius69/Flow) for details.
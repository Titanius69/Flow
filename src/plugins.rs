//! Loading and running plugins.
//!
//! At startup each `.fpkg` in the plugins directory is extracted, compiled with
//! `cargo`, and loaded with `dlopen`. Compiling on the spot is what keeps this
//! sound: Rust has no stable ABI, so a pre-compiled plugin built by a different
//! toolchain could disagree with the proxy about type layout in ways no version
//! check can detect. Building both with the same compiler removes that class of
//! failure.
//!
//! What it does *not* remove: a plugin runs in-process with no sandbox. It can
//! read any memory the proxy can, and it can block the runtime. Plugins are
//! trusted code, in the same sense that a Bukkit plugin is.

use std::ffi::c_void;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use anyhow::Context;
use libloading::Library;
use sha2::{Digest, Sha256};

use flow_plugin_api::{
    event_kind, log_level, FpEvent, FpHost, FpOwnedStr, FpStr, ABI_VERSION, EVENT_HANDLED,
};
use fpkg::{Manifest, API_PATH_TOKEN};

use crate::registry::{PlayerHandle, ProxyCommand, Registry};
use crate::session::EventSink;

/// The API crate source is embedded so a deployed proxy can build plugins
/// without its own source tree being present on the server.
const API_LIB_RS: &str = include_str!("../crates/flow-plugin-api/src/lib.rs");
const API_CARGO_TOML: &str = r#"[package]
name = "flow-plugin-api"
version = "1.0.0"
edition = "2021"

[dependencies]
"#;

/// Host state handed to plugins as an opaque pointer.
struct HostState {
    registry: Arc<Registry>,
}

impl HostState {
    /// # Safety
    /// `ctx` must be the pointer the host installed in `FpHost::ctx`.
    unsafe fn from_ctx<'a>(ctx: *mut c_void) -> Option<&'a HostState> {
        if ctx.is_null() {
            None
        } else {
            Some(&*(ctx as *const HostState))
        }
    }
}

fn owned_string(text: String) -> FpOwnedStr {
    let mut bytes = std::mem::ManuallyDrop::new(text.into_bytes());
    FpOwnedStr {
        ptr: bytes.as_mut_ptr(),
        len: bytes.len(),
        capacity: bytes.capacity(),
    }
}

extern "C" fn host_free_string(owned: FpOwnedStr) {
    if owned.ptr.is_null() {
        return;
    }
    // Reclaim the allocation the host made in `owned_string`.
    unsafe {
        drop(Vec::from_raw_parts(owned.ptr, owned.len, owned.capacity));
    }
}

extern "C" fn host_log(_ctx: *mut c_void, level: u32, message: FpStr) {
    let message = unsafe { message.as_str() };
    match level {
        log_level::ERROR => tracing::error!(target: "plugin", "{}", message),
        log_level::WARN => tracing::warn!(target: "plugin", "{}", message),
        log_level::DEBUG => tracing::debug!(target: "plugin", "{}", message),
        _ => tracing::info!(target: "plugin", "{}", message),
    }
}

/// Applies `command` to one player, or to everyone when the name is `ALL`.
fn dispatch_command(state: &HostState, player: &str, command: ProxyCommand) -> bool {
    if player.eq_ignore_ascii_case("ALL") {
        let mut any = false;
        for handle in state.registry.all() {
            any |= handle.send(command.clone());
        }
        return any;
    }

    match state.registry.get(player) {
        Some(handle) => handle.send(command),
        None => false,
    }
}

extern "C" fn host_send_message(ctx: *mut c_void, player: FpStr, message: FpStr) -> bool {
    let Some(state) = (unsafe { HostState::from_ctx(ctx) }) else {
        return false;
    };
    let player = unsafe { player.as_str() };
    let message = unsafe { message.as_str() }.to_string();
    dispatch_command(state, player, ProxyCommand::Message(message))
}

extern "C" fn host_connect_player(ctx: *mut c_void, player: FpStr, server: FpStr) -> bool {
    let Some(state) = (unsafe { HostState::from_ctx(ctx) }) else {
        return false;
    };
    let player = unsafe { player.as_str() };
    let server = unsafe { server.as_str() }.to_string();
    dispatch_command(state, player, ProxyCommand::Connect(server))
}

extern "C" fn host_kick_player(ctx: *mut c_void, player: FpStr, reason: FpStr) -> bool {
    let Some(state) = (unsafe { HostState::from_ctx(ctx) }) else {
        return false;
    };
    let player = unsafe { player.as_str() };
    let reason = unsafe { reason.as_str() }.to_string();
    dispatch_command(state, player, ProxyCommand::Kick(reason))
}

extern "C" fn host_player_count(ctx: *mut c_void) -> u32 {
    match unsafe { HostState::from_ctx(ctx) } {
        Some(state) => state.registry.count() as u32,
        None => 0,
    }
}

extern "C" fn host_player_names(ctx: *mut c_void, server: FpStr) -> FpOwnedStr {
    let Some(state) = (unsafe { HostState::from_ctx(ctx) }) else {
        return FpOwnedStr::NULL;
    };
    let server = unsafe { server.as_str() };
    let filter = if server.is_empty() { "ALL" } else { server };
    owned_string(state.registry.names_on(filter).join(","))
}

extern "C" fn host_current_server(ctx: *mut c_void, player: FpStr) -> FpOwnedStr {
    let Some(state) = (unsafe { HostState::from_ctx(ctx) }) else {
        return FpOwnedStr::NULL;
    };
    let player = unsafe { player.as_str() };
    match state.registry.get(player) {
        Some(handle) => owned_string(handle.current_server()),
        None => owned_string(String::new()),
    }
}

type AbiVersionFn = unsafe extern "C" fn() -> u32;
type InitFn = unsafe extern "C" fn(*const FpHost) -> u32;
type EventFn = unsafe extern "C" fn(*const FpEvent) -> u32;
type ShutdownFn = unsafe extern "C" fn();

struct LoadedPlugin {
    manifest: Manifest,
    event: EventFn,
    shutdown: ShutdownFn,
    /// Declared last so it is dropped last: the function pointers above are
    /// only valid while the library is mapped.
    _library: Library,
}

pub struct PluginHost {
    plugins: Vec<LoadedPlugin>,
    /// Kept alive because `host.ctx` points into it.
    _state: Arc<HostState>,
    host: Box<FpHost>,
}

// The host vtable and state are immutable after construction, and the registry
// behind them is internally synchronised.
unsafe impl Send for PluginHost {}
unsafe impl Sync for PluginHost {}

impl PluginHost {
    /// Loads every `.fpkg` in `dir`. A plugin that fails to build or load is
    /// reported and skipped rather than stopping the proxy.
    pub fn load_all(dir: &Path, registry: Arc<Registry>) -> anyhow::Result<Self> {
    let state = Arc::new(HostState { registry });

    let host = Box::new(FpHost {
        abi_version: ABI_VERSION,
        ctx: Arc::as_ptr(&state) as *mut c_void,
        log: host_log,
        send_message: host_send_message,
        connect_player: host_connect_player,
        kick_player: host_kick_player,
        player_count: host_player_count,
        player_names: host_player_names,
        current_server: host_current_server,
        free_string: host_free_string,
    });

    let mut plugins = Vec::new();

    if !dir.exists() {
        fs::create_dir_all(dir)
            .with_context(|| format!("failed to create {}", dir.display()))?;
        return Ok(Self {
            plugins,
            _state: state,
            host,
        });
    }

    let cache = dir.join(".cache");
    let api_dir = prepare_api_crate(&cache)?;

    let mut packages: Vec<PathBuf> = fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|e| e == "fpkg").unwrap_or(false))
        .collect();
    packages.sort();

    // ─── ITT A KÉRT RÉSZ ────────────────────────────────────────────────
    for package in packages {
        match load_one(&package, &cache, &api_dir, &host) {
            Ok(plugin) => {
                tracing::info!(
                    "Loaded plugin {} {} ({})",
                    plugin.manifest.plugin.name,
                    plugin.manifest.plugin.version,
                    package.file_name().unwrap_or_default().to_string_lossy()
                );
                plugins.push(plugin);
            }
            Err(e) => tracing::error!(
                "Failed to load {}: {:#}",
                package.file_name().unwrap_or_default().to_string_lossy(),
                e
            ),
        }
    }
    // ─────────────────────────────────────────────────────────────────────

    Ok(Self {
        plugins,
        _state: state,
        host,
    })
}

    pub fn count(&self) -> usize {
        self.plugins.len()
    }

    pub fn names(&self) -> Vec<String> {
        self.plugins
            .iter()
            .map(|p| p.manifest.plugin.id.clone())
            .collect()
    }

    /// Calls `fp_shutdown` on every plugin.
    pub fn shutdown(&self) {
        for plugin in &self.plugins {
            unsafe { (plugin.shutdown)() };
        }
    }

    fn dispatch(&self, event: &FpEvent) -> bool {
        let mut handled = false;
        for plugin in &self.plugins {
            // Safety: the plugin was verified to speak our ABI at load time,
            // and the macro on the plugin side wraps its handler in
            // `catch_unwind` so a panic cannot unwind into us.
            let result = unsafe { (plugin.event)(event as *const FpEvent) };
            if result == EVENT_HANDLED {
                handled = true;
                break;
            }
        }
        handled
    }

    /// Suppresses unused warnings on the host vtable in builds without plugins.
    pub fn abi_version(&self) -> u32 {
        self.host.abi_version
    }
}

impl EventSink for PluginHost {
    fn on_join(&self, player: &PlayerHandle, server: &str) {
        let uuid = player.uuid.to_string();
        let event = FpEvent {
            kind: event_kind::JOIN,
            player: FpStr::from_str(&player.username),
            uuid: FpStr::from_str(&uuid),
            server: FpStr::from_str(server),
            from: FpStr::EMPTY,
            text: FpStr::EMPTY,
        };
        self.dispatch(&event);
    }

    fn on_leave(&self, player: &PlayerHandle) {
        let uuid = player.uuid.to_string();
        let server = player.current_server();
        let event = FpEvent {
            kind: event_kind::LEAVE,
            player: FpStr::from_str(&player.username),
            uuid: FpStr::from_str(&uuid),
            server: FpStr::from_str(&server),
            from: FpStr::EMPTY,
            text: FpStr::EMPTY,
        };
        self.dispatch(&event);
    }

    fn on_switch(&self, player: &PlayerHandle, from: &str, to: &str) {
        let uuid = player.uuid.to_string();
        let event = FpEvent {
            kind: event_kind::SWITCH,
            player: FpStr::from_str(&player.username),
            uuid: FpStr::from_str(&uuid),
            server: FpStr::from_str(to),
            from: FpStr::from_str(from),
            text: FpStr::EMPTY,
        };
        self.dispatch(&event);
    }

    fn on_command(&self, player: &PlayerHandle, command: &str) -> bool {
        let uuid = player.uuid.to_string();
        let server = player.current_server();
        let event = FpEvent {
            kind: event_kind::COMMAND,
            player: FpStr::from_str(&player.username),
            uuid: FpStr::from_str(&uuid),
            server: FpStr::from_str(&server),
            from: FpStr::EMPTY,
            text: FpStr::from_str(command),
        };
        self.dispatch(&event)
    }
}

/// Materialises the API crate from the source embedded in this binary.
fn prepare_api_crate(cache: &Path) -> anyhow::Result<PathBuf> {
    let dir = cache.join("flow-plugin-api");
    fs::create_dir_all(dir.join("src"))?;

    // Only rewrite when the content differs, so cargo does not see a changed
    // mtime and rebuild every plugin on every start.
    write_if_changed(&dir.join("Cargo.toml"), API_CARGO_TOML)?;
    write_if_changed(&dir.join("src/lib.rs"), API_LIB_RS)?;

    Ok(dir)
}

fn write_if_changed(path: &Path, contents: &str) -> anyhow::Result<()> {
    if let Ok(existing) = fs::read_to_string(path) {
        if existing == contents {
            return Ok(());
        }
    }
    fs::write(path, contents).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn load_one(
    package: &Path,
    cache: &Path,
    api_dir: &Path,
    host: &FpHost,
) -> anyhow::Result<LoadedPlugin> {
    let bytes = fs::read(package)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let hash = hasher.finalize();
    let short: String = hash.iter().take(6).map(|b| format!("{:02x}", b)).collect();

    let manifest = fpkg::read_manifest(package)?;
    let build_dir = cache.join(format!("{}-{}", manifest.plugin.id, short));
    let library_path = build_dir
        .join("target/release")
        .join(manifest.library_file_name());
    let stamp = build_dir.join(".built");

    // The directory name carries the package hash, so an unchanged plugin is
    // never rebuilt and a changed one never reuses a stale artefact.
    if !stamp.exists() || !library_path.exists() {
        tracing::info!("Building plugin {} ...", manifest.plugin.id);
        let _ = fs::remove_dir_all(&build_dir);
        fpkg::unpack(package, &build_dir)?;
        patch_cargo_manifest(&build_dir, api_dir)?;
        build(&build_dir)?;
        fs::write(&stamp, "")?;
    }

    if !library_path.exists() {
        anyhow::bail!(
            "the build produced no {} in {}",
            manifest.library_file_name(),
            library_path.display()
        );
    }

    // Safety: the library was just compiled from source we extracted, by the
    // same toolchain as this binary.
    let library = unsafe { Library::new(&library_path) }
        .with_context(|| format!("failed to load {}", library_path.display()))?;

    unsafe {
        let abi: libloading::Symbol<AbiVersionFn> = library
            .get(b"fp_abi_version\0")
            .context("the library exports no fp_abi_version; is flow_plugin! missing?")?;
        let reported = abi();
        if reported != ABI_VERSION {
            anyhow::bail!(
                "plugin speaks ABI {} but this proxy speaks {}",
                reported,
                ABI_VERSION
            );
        }

        let init: libloading::Symbol<InitFn> = library
            .get(b"fp_init\0")
            .context("the library exports no fp_init")?;
        let event: EventFn = *library
            .get(b"fp_event\0")
            .context("the library exports no fp_event")?;
        let shutdown: ShutdownFn = *library
            .get(b"fp_shutdown\0")
            .context("the library exports no fp_shutdown")?;

        let code = init(host as *const FpHost);
        if code != 0 {
            anyhow::bail!("fp_init returned {}", code);
        }

        Ok(LoadedPlugin {
            manifest,
            event,
            shutdown,
            _library: library,
        })
    }
}

/// Points the plugin's API dependency at the crate we materialised.
fn patch_cargo_manifest(build_dir: &Path, api_dir: &Path) -> anyhow::Result<()> {
    let path = build_dir.join("Cargo.toml");
    let mut text = fs::read_to_string(&path)?;

    if !text.contains(API_PATH_TOKEN) {
        anyhow::bail!(
            "Cargo.toml does not contain the {} placeholder",
            API_PATH_TOKEN
        );
    }

    // Ha nincs [workspace] tábla, hozzáadjuk
    if !text.contains("[workspace]") {
        text.push_str("\n\n[workspace]\n");
    }

    let api_path = api_dir
        .canonicalize()
        .unwrap_or_else(|_| api_dir.to_path_buf());
    let escaped = api_path.to_string_lossy().replace('\\', "\\\\");

    fs::write(&path, text.replace(API_PATH_TOKEN, &escaped))?;
    Ok(())
}

fn build(dir: &Path) -> anyhow::Result<()> {
    // Abszolút útvonal a build könyvtárhoz
    let dir_abs = std::fs::canonicalize(dir)
        .unwrap_or_else(|_| std::env::current_dir().unwrap().join(dir));
    let manifest_path = dir_abs.join("Cargo.toml");
    let target_dir = dir_abs.join("target");

    let output = Command::new("cargo")
        .arg("build")
        .arg("--release")
        .arg("--manifest-path")
        .arg(&manifest_path)
        .arg("--target-dir")
        .arg(&target_dir)
        .output()
        .context("failed to run cargo")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    tracing::debug!("cargo stdout:\n{}", stdout);
    tracing::debug!("cargo stderr:\n{}", stderr);

    if !output.status.success() {
        anyhow::bail!("cargo build failed:\n{}", stderr);
    }

    // Ellenőrizd, hogy a target/release létezik-e
    let release_dir = target_dir.join("release");
    if !release_dir.exists() {
        // Ha nem, nézd meg, mi van a target_dir-ben
        if target_dir.exists() {
            let entries: Vec<_> = std::fs::read_dir(&target_dir)
                .into_iter()
                .flat_map(|r| r)
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect();
            tracing::debug!("Contents of target dir: {:?}", entries);
        } else {
            tracing::debug!("Target directory does not exist: {}", target_dir.display());
        }
        anyhow::bail!("Build succeeded but target/release directory is missing at {}", release_dir.display());
    }

    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_strings_survive_a_round_trip() {
        let owned = owned_string("Notch,jeb_".to_string());
        let text = unsafe {
            std::str::from_utf8(std::slice::from_raw_parts(owned.ptr, owned.len))
                .unwrap()
                .to_string()
        };
        assert_eq!(text, "Notch,jeb_");
        host_free_string(owned);
    }

    #[test]
    fn freeing_a_null_string_is_a_no_op() {
        host_free_string(FpOwnedStr::NULL);
    }

    #[test]
    fn host_calls_with_a_null_context_do_not_crash() {
        assert_eq!(host_player_count(std::ptr::null_mut()), 0);
        assert!(!host_send_message(
            std::ptr::null_mut(),
            FpStr::from_str("Notch"),
            FpStr::from_str("hi")
        ));
    }

    #[test]
    fn host_functions_reach_the_registry() {
        use std::sync::Mutex;
        use uuid::Uuid;

        let registry = Arc::new(Registry::new());
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        registry.insert(PlayerHandle {
            username: "Notch".into(),
            uuid: Uuid::nil(),
            addr: "127.0.0.1:1".parse().unwrap(),
            server: Arc::new(Mutex::new("lobby".into())),
            commands: tx,
        });

        let state = Arc::new(HostState {
            registry: Arc::clone(&registry),
        });
        let ctx = Arc::as_ptr(&state) as *mut c_void;

        assert_eq!(host_player_count(ctx), 1);

        let names = host_player_names(ctx, FpStr::from_str(""));
        let text = unsafe {
            std::str::from_utf8(std::slice::from_raw_parts(names.ptr, names.len))
                .unwrap()
                .to_string()
        };
        host_free_string(names);
        assert_eq!(text, "Notch");

        let server = host_current_server(ctx, FpStr::from_str("notch"));
        let text = unsafe {
            std::str::from_utf8(std::slice::from_raw_parts(server.ptr, server.len))
                .unwrap()
                .to_string()
        };
        host_free_string(server);
        assert_eq!(text, "lobby");

        assert!(host_send_message(
            ctx,
            FpStr::from_str("Notch"),
            FpStr::from_str("hello")
        ));
        match rx.try_recv().unwrap() {
            ProxyCommand::Message(m) => assert_eq!(m, "hello"),
            other => panic!("expected a message, got {:?}", other),
        }

        // A name that is not online must fail rather than panic.
        assert!(!host_kick_player(
            ctx,
            FpStr::from_str("Nobody"),
            FpStr::from_str("bye")
        ));
    }
}

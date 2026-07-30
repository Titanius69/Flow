//! The full plugin path: pack a source directory into an `.fpkg`, let the host
//! compile it with cargo, load the resulting cdylib, and drive it through the
//! FFI boundary.
//!
//! This actually invokes cargo, so it is slower than the rest of the suite. It
//! is also the only test that exercises the unsafe boundary, which is exactly
//! the part that cannot be reasoned about from the source alone.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use flow_proxy::plugins::PluginHost;
use flow_proxy::registry::{PlayerHandle, ProxyCommand, Registry};
use flow_proxy::session::EventSink;
use tokio::sync::mpsc;
use uuid::Uuid;

/// The example plugin shipped with the proxy.
fn example_plugin_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/hello-plugin")
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("flow-plugin-test-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Registers a fake player and returns the channel its commands arrive on.
fn add_player(
    registry: &Registry,
    name: &str,
    server: &str,
) -> (PlayerHandle, mpsc::Receiver<ProxyCommand>) {
    let (tx, rx) = mpsc::channel(16);
    let handle = PlayerHandle {
        username: name.to_string(),
        uuid: Uuid::nil(),
        addr: "127.0.0.1:25565".parse().unwrap(),
        server: Arc::new(Mutex::new(server.to_string())),
        commands: tx,
    };
    registry.insert(handle.clone());
    (handle, rx)
}

#[test]
fn a_packaged_plugin_is_built_loaded_and_driven() {
    let dir = temp_dir("full");
    let plugins_dir = dir.join("plugins");
    std::fs::create_dir_all(&plugins_dir).unwrap();

    // 1. Package the example plugin exactly as `fpkg pack` would.
    let manifest = fpkg::pack(&example_plugin_dir(), &plugins_dir.join("hello.fpkg"))
        .expect("the example plugin must be packable");
    assert_eq!(manifest.plugin.id, "hello");

    // 2. Load it: this extracts, rewrites the API path, runs cargo, and dlopens
    //    the result.
    let registry = Arc::new(Registry::new());
    let host = PluginHost::load_all(&plugins_dir, Arc::clone(&registry))
        .expect("loading should not fail");

    assert_eq!(
        host.count(),
        1,
        "the plugin failed to build or load; run with RUST_LOG=debug for cargo's output"
    );
    assert_eq!(host.names(), vec!["hello"]);

    // 3. A join should reach the plugin, which greets the player back through
    //    the host API.
    let (notch, mut notch_rx) = add_player(&registry, "Notch", "lobby");
    host.on_join(&notch, "lobby");

    match notch_rx.try_recv().expect("the plugin should have sent a message") {
        ProxyCommand::Message(text) => {
            assert!(text.contains("Welcome, Notch"), "got: {}", text);
            assert!(
                text.contains("lobby"),
                "the event should carry the server name, got: {}",
                text
            );
        }
        other => panic!("expected a message, got {:?}", other),
    }

    // 4. A command the plugin claims must be consumed, and must act.
    let handled = host.on_command(&notch, "hub");
    assert!(handled, "/hub should be consumed by the plugin");
    match notch_rx.try_recv().expect("the plugin should have moved the player") {
        ProxyCommand::Connect(server) => assert_eq!(server, "lobby"),
        other => panic!("expected a connect, got {:?}", other),
    }

    // 5. A command it does not claim must fall through to the backend.
    assert!(
        !host.on_command(&notch, "gamemode creative"),
        "unrelated commands must not be swallowed"
    );
    assert!(notch_rx.try_recv().is_err());

    // 6. Host queries reflect live proxy state, not a snapshot from load time.
    let (_jeb, _jeb_rx) = add_player(&registry, "jeb_", "survival");
    assert!(host.on_command(&notch, "count"));
    match notch_rx.try_recv().unwrap() {
        ProxyCommand::Message(text) => {
            assert!(text.contains('2'), "expected two players, got: {}", text);
            assert!(text.contains("Notch") && text.contains("jeb_"), "got: {}", text);
        }
        other => panic!("expected a message, got {:?}", other),
    }

    // 7. Switch events carry both sides.
    host.on_switch(&notch, "lobby", "survival");
    host.on_leave(&notch);

    host.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_build_cache_survives_a_reload() {
    let dir = temp_dir("cache");
    let plugins_dir = dir.join("plugins");
    std::fs::create_dir_all(&plugins_dir).unwrap();
    fpkg::pack(&example_plugin_dir(), &plugins_dir.join("hello.fpkg")).unwrap();

    let registry = Arc::new(Registry::new());

    let first = std::time::Instant::now();
    let host = PluginHost::load_all(&plugins_dir, Arc::clone(&registry)).unwrap();
    assert_eq!(host.count(), 1);
    let cold = first.elapsed();
    host.shutdown();
    drop(host);

    // The package is unchanged, so the second load must reuse the compiled
    // artefact rather than invoking cargo again.
    let second = std::time::Instant::now();
    let host = PluginHost::load_all(&plugins_dir, registry).unwrap();
    assert_eq!(host.count(), 1);
    let warm = second.elapsed();
    host.shutdown();

    assert!(
        warm < cold,
        "a reload should hit the cache: cold {:?}, warm {:?}",
        cold,
        warm
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_missing_plugins_directory_is_created_not_fatal() {
    let dir = temp_dir("absent");
    let plugins_dir = dir.join("does-not-exist-yet");

    let host = PluginHost::load_all(&plugins_dir, Arc::new(Registry::new()))
        .expect("an absent plugins directory is normal on a fresh install");
    assert_eq!(host.count(), 0);
    assert!(plugins_dir.exists());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_broken_package_is_skipped_rather_than_stopping_the_proxy() {
    let dir = temp_dir("broken");
    let plugins_dir = dir.join("plugins");
    std::fs::create_dir_all(&plugins_dir).unwrap();

    // Not a zip at all.
    std::fs::write(plugins_dir.join("garbage.fpkg"), b"this is not a package").unwrap();
    // A good one alongside it.
    fpkg::pack(&example_plugin_dir(), &plugins_dir.join("hello.fpkg")).unwrap();

    let host = PluginHost::load_all(&plugins_dir, Arc::new(Registry::new()))
        .expect("one bad package must not abort startup");
    assert_eq!(host.count(), 1, "the working plugin should still load");

    host.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}

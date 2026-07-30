//! The proxy-wide player registry.
//!
//! Anything that acts on a player *other than* the one whose task is running
//! needs this: kicking a duplicate login, a backend plugin asking to move
//! someone, `/glist`, or a cross-server message. Each player registers a
//! command channel so other tasks can ask it to do something without touching
//! its sockets.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;
use uuid::Uuid;

/// Something another task wants this player's session to do.
#[derive(Debug, Clone)]
pub enum ProxyCommand {
    /// Show a chat line.
    Message(String),
    /// Move to another backend.
    Connect(String),
    /// Disconnect with a reason.
    Kick(String),
}

/// A handle to a connected player, cheap to clone.
#[derive(Debug, Clone)]
pub struct PlayerHandle {
    pub username: String,
    pub uuid: Uuid,
    pub addr: SocketAddr,
    /// The backend the player is currently on. Shared so a switch is visible to
    /// every holder of the handle without re-registering.
    pub server: Arc<Mutex<String>>,
    pub commands: mpsc::Sender<ProxyCommand>,
}

impl PlayerHandle {
    pub fn current_server(&self) -> String {
        self.server.lock().expect("registry mutex poisoned").clone()
    }

    pub fn set_current_server(&self, name: &str) {
        *self.server.lock().expect("registry mutex poisoned") = name.to_string();
    }

    /// Sends a command, returning false if the session has already ended.
    pub fn send(&self, command: ProxyCommand) -> bool {
        self.commands.try_send(command).is_ok()
    }
}

#[derive(Default)]
pub struct Registry {
    // Keyed by lowercased username: Minecraft names are case-insensitive for
    // lookup purposes, and plugins are inconsistent about casing.
    players: Mutex<HashMap<String, PlayerHandle>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a player, returning the handle it displaced if the name was
    /// already connected.
    pub fn insert(&self, handle: PlayerHandle) -> Option<PlayerHandle> {
        let key = handle.username.to_lowercase();
        self.players
            .lock()
            .expect("registry mutex poisoned")
            .insert(key, handle)
    }

    /// Removes a player, but only if the registered handle is still the one
    /// that belongs to this session.
    ///
    /// Without the channel comparison, a player who reconnects while the old
    /// session is still shutting down would have their *new* entry removed by
    /// the old session's cleanup.
    pub fn remove_if_same(&self, username: &str, commands: &mpsc::Sender<ProxyCommand>) {
        let key = username.to_lowercase();
        let mut players = self.players.lock().expect("registry mutex poisoned");
        if let Some(existing) = players.get(&key) {
            if existing.commands.same_channel(commands) {
                players.remove(&key);
            }
        }
    }

    pub fn get(&self, username: &str) -> Option<PlayerHandle> {
        self.players
            .lock()
            .expect("registry mutex poisoned")
            .get(&username.to_lowercase())
            .cloned()
    }

    pub fn all(&self) -> Vec<PlayerHandle> {
        self.players
            .lock()
            .expect("registry mutex poisoned")
            .values()
            .cloned()
            .collect()
    }

    pub fn count(&self) -> usize {
        self.players.lock().expect("registry mutex poisoned").len()
    }

    /// Names of players on one backend, or on all of them when `server` is
    /// `"ALL"`, which is what the BungeeCord channel uses.
    pub fn names_on(&self, server: &str) -> Vec<String> {
        let mut names: Vec<String> = self
            .all()
            .into_iter()
            .filter(|p| server.eq_ignore_ascii_case("ALL") || p.current_server() == server)
            .map(|p| p.username)
            .collect();
        names.sort_unstable();
        names
    }

    pub fn count_on(&self, server: &str) -> usize {
        self.names_on(server).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handle(name: &str, server: &str) -> (PlayerHandle, mpsc::Receiver<ProxyCommand>) {
        let (tx, rx) = mpsc::channel(8);
        (
            PlayerHandle {
                username: name.to_string(),
                uuid: Uuid::nil(),
                addr: "127.0.0.1:1234".parse().unwrap(),
                server: Arc::new(Mutex::new(server.to_string())),
                commands: tx,
            },
            rx,
        )
    }

    #[test]
    fn lookup_is_case_insensitive() {
        let reg = Registry::new();
        let (h, _rx) = handle("Notch", "lobby");
        reg.insert(h);
        assert!(reg.get("notch").is_some());
        assert!(reg.get("NOTCH").is_some());
    }

    #[test]
    fn duplicate_login_returns_the_displaced_handle() {
        let reg = Registry::new();
        let (first, _rx1) = handle("Notch", "lobby");
        let (second, _rx2) = handle("notch", "lobby");
        assert!(reg.insert(first).is_none());
        let displaced = reg.insert(second).expect("the first session");
        assert_eq!(displaced.username, "Notch");
        assert_eq!(reg.count(), 1);
    }

    #[test]
    fn stale_cleanup_does_not_evict_a_reconnected_player() {
        let reg = Registry::new();
        let (first, _rx1) = handle("Notch", "lobby");
        let first_commands = first.commands.clone();
        reg.insert(first);

        let (second, _rx2) = handle("Notch", "lobby");
        reg.insert(second);

        // The first session now shuts down and cleans up after itself.
        reg.remove_if_same("Notch", &first_commands);

        assert_eq!(reg.count(), 1, "the reconnected session must survive");
    }

    #[test]
    fn removal_by_the_owning_session_works() {
        let reg = Registry::new();
        let (h, _rx) = handle("Notch", "lobby");
        let commands = h.commands.clone();
        reg.insert(h);
        reg.remove_if_same("Notch", &commands);
        assert_eq!(reg.count(), 0);
    }

    #[test]
    fn filtering_by_server() {
        let reg = Registry::new();
        let (a, _ra) = handle("Notch", "lobby");
        let (b, _rb) = handle("jeb_", "survival");
        let (c, _rc) = handle("Dinnerbone", "lobby");
        reg.insert(a);
        reg.insert(b);
        reg.insert(c);

        assert_eq!(reg.names_on("lobby"), vec!["Dinnerbone", "Notch"]);
        assert_eq!(reg.count_on("survival"), 1);
        assert_eq!(reg.count_on("ALL"), 3);
        assert_eq!(reg.count_on("all"), 3);
    }

    #[test]
    fn a_switch_is_visible_through_the_handle() {
        let reg = Registry::new();
        let (h, _rx) = handle("Notch", "lobby");
        reg.insert(h);

        reg.get("Notch").unwrap().set_current_server("survival");
        assert_eq!(reg.count_on("survival"), 1);
        assert_eq!(reg.count_on("lobby"), 0);
    }
}

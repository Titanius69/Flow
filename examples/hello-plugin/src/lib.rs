//! Example Flow-Proxy plugin.
//!
//! Build it into a package with:
//!
//! ```text
//! fpkg pack examples/hello-plugin -o plugins/hello.fpkg
//! ```
//!
//! then start the proxy: it compiles and loads the plugin on the way up.

use flow_plugin_api::prelude::*;

#[derive(Default)]
struct Hello {
    joins: u32,
}

impl Plugin for Hello {
    fn on_enable(&mut self, api: &Api) {
        api.info("hello plugin enabled");
    }

    fn on_disable(&mut self, api: &Api) {
        api.info(&format!("hello plugin saw {} joins", self.joins));
    }

    fn on_join(&mut self, api: &Api, player: &PlayerRef) {
        self.joins += 1;
        api.send_message(
            player.username,
            &format!("Welcome, {}! You are on {}.", player.username, player.server),
        );
    }

    fn on_switch(&mut self, api: &Api, player: &PlayerRef, from: &str, to: &str) {
        api.debug(&format!("{} moved {} -> {}", player.username, from, to));
    }

    fn on_command(&mut self, api: &Api, player: &PlayerRef, command: &str) -> bool {
        match command {
            "hub" => {
                api.connect_player(player.username, "lobby");
                true
            }
            "count" => {
                let names = api.player_names("");
                api.send_message(
                    player.username,
                    &format!("{} online: {}", api.player_count(), names.join(", ")),
                );
                true
            }
            _ => false,
        }
    }
}

flow_plugin!(Hello);

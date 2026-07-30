//! Packet IDs for the Configuration and Play states, protocol **769**
//! (Minecraft 1.21.4).
//!
//! Unlike Handshake/Status/Login, these IDs are not stable across versions:
//! they are assigned by registration order in the server jar, so adding or
//! removing a packet shifts everything after it. The upstream protocol
//! documentation explicitly warns against hardcoding them.
//!
//! They are therefore collected here, in one table, rather than scattered
//! through the proxy. The values were taken from the version-pinned
//! `minecraft-data` definitions for 1.21.4 (`data/pc/1.21.4/protocol.json`),
//! not from memory.
//!
//! **Supporting another protocol version means adding another table and
//! selecting on the client's version.** The proxy only claims 769.

/// The protocol version these IDs describe.
pub const PROTOCOL_VERSION: i32 = 769;

/// Play state, server -> client.
pub mod play_clientbound {
    /// Moves the client back into Configuration state. This is what makes a
    /// server switch possible without dropping the connection.
    pub const START_CONFIGURATION: i32 = 0x70;
    /// A chat line rendered to the player. Payload is an NBT text component
    /// plus an "overlay" boolean.
    pub const SYSTEM_CHAT: i32 = 0x73;
    /// Kick with an NBT text component reason.
    pub const DISCONNECT: i32 = 0x1D;
    /// Plugin message from the backend. Carries the BungeeCord channel.
    pub const CUSTOM_PAYLOAD: i32 = 0x19;
}

/// Play state, client -> server.
pub mod play_serverbound {
    /// A command typed by the player, without the leading slash.
    pub const CHAT_COMMAND: i32 = 0x05;
    /// A command carrying signed arguments.
    pub const CHAT_COMMAND_SIGNED: i32 = 0x06;
    /// The client's answer to START_CONFIGURATION. Seeing this means the client
    /// has left Play state.
    pub const CONFIGURATION_ACKNOWLEDGED: i32 = 0x0E;
    /// Plugin message to the backend.
    pub const CUSTOM_PAYLOAD: i32 = 0x14;
}

/// Configuration state, client -> server.
pub mod config_serverbound {
    /// The client's answer to the server's Finish Configuration. Seeing this
    /// means the client has entered Play state.
    pub const FINISH_CONFIGURATION: i32 = 0x03;
}

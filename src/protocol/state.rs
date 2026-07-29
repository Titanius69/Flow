/// The protocol state of a connection during the handshake phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolState {
    Handshaking,
    Status,
    Login,
    // Configuration and Play are relayed frame-by-frame, so they need no
    // dedicated state here.
}

impl ProtocolState {
    /// Maps a next-state value from the Handshake packet.
    ///
    /// 1.20.5 added value 3 (Transfer), which behaves like Login as far as the
    /// proxy is concerned. Rejecting it would break clients arriving via a
    /// `transfer` packet from another server.
    pub fn from_next_state(next_state: i32) -> Option<Self> {
        match next_state {
            1 => Some(ProtocolState::Status),
            2 | 3 => Some(ProtocolState::Login),
            _ => None,
        }
    }
}

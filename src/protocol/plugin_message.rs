//! The BungeeCord plugin message channel.
//!
//! Backend plugins talk to the proxy by sending a plugin message on
//! `bungeecord:main` (called `BungeeCord` before namespaced channels). The
//! payload begins with a subchannel name and then subchannel-specific fields,
//! all written with Java's `DataOutputStream`.
//!
//! This is how hub plugins move players, so without it a server-selector GUI
//! has no way to reach the proxy at all.

use super::javaio::{read_int, read_utf, write_int, write_utf};

/// The modern namespaced channel.
pub const CHANNEL: &str = "bungeecord:main";
/// The pre-1.13 channel name, still used by some plugins.
pub const CHANNEL_LEGACY: &str = "BungeeCord";

/// True if `channel` is the BungeeCord channel under either name.
pub fn is_bungee_channel(channel: &str) -> bool {
    channel == CHANNEL || channel == CHANNEL_LEGACY
}

/// A request from a backend plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BungeeMessage {
    /// Move the sending player to another server.
    Connect { server: String },
    /// Move a named player to another server.
    ConnectOther { player: String, server: String },
    /// Ask for the sending player's address.
    Ip,
    /// Ask how many players are on a server, or on all servers.
    PlayerCount { server: String },
    /// Ask which players are on a server, or on all servers.
    PlayerList { server: String },
    /// Ask for the configured server names.
    GetServers,
    /// Ask which server the sending player is on.
    GetServer,
    /// Send a chat message to a player, or to everyone.
    Message { player: String, message: String },
    /// Disconnect a player.
    KickPlayer { player: String, reason: String },
    /// A subchannel we do not implement. Kept rather than treated as an error
    /// so it can be logged once instead of dropping the connection.
    Unsupported { subchannel: String },
}

impl BungeeMessage {
    pub fn decode(data: &[u8]) -> anyhow::Result<Self> {
        let (subchannel, mut offset) = read_utf(data)?;

        let next_string = |offset: &mut usize| -> anyhow::Result<String> {
            let (s, n) = read_utf(&data[*offset..])?;
            *offset += n;
            Ok(s)
        };

        let message = match subchannel.as_str() {
            "Connect" => BungeeMessage::Connect {
                server: next_string(&mut offset)?,
            },
            "ConnectOther" => {
                let player = next_string(&mut offset)?;
                let server = next_string(&mut offset)?;
                BungeeMessage::ConnectOther { player, server }
            }
            "IP" => BungeeMessage::Ip,
            "PlayerCount" => BungeeMessage::PlayerCount {
                server: next_string(&mut offset)?,
            },
            "PlayerList" => BungeeMessage::PlayerList {
                server: next_string(&mut offset)?,
            },
            "GetServers" => BungeeMessage::GetServers,
            "GetServer" => BungeeMessage::GetServer,
            "Message" | "MessageRaw" => {
                let player = next_string(&mut offset)?;
                let message = next_string(&mut offset)?;
                BungeeMessage::Message { player, message }
            }
            "KickPlayer" => {
                let player = next_string(&mut offset)?;
                let reason = next_string(&mut offset)?;
                BungeeMessage::KickPlayer { player, reason }
            }
            other => BungeeMessage::Unsupported {
                subchannel: other.to_string(),
            },
        };

        Ok(message)
    }

    /// Builds a `Connect` request, as a backend plugin would.
    pub fn connect_request(server: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        write_utf(&mut buf, "Connect");
        write_utf(&mut buf, server);
        buf
    }

    /// Builds a `ConnectOther` request.
    pub fn connect_other_request(player: &str, server: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        write_utf(&mut buf, "ConnectOther");
        write_utf(&mut buf, player);
        write_utf(&mut buf, server);
        buf
    }

    /// Builds a `PlayerCount` request.
    pub fn player_count_request(server: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        write_utf(&mut buf, "PlayerCount");
        write_utf(&mut buf, server);
        buf
    }
}

/// `PlayerCount` reply: the server asked about, then the count.
pub fn response_player_count(server: &str, count: i32) -> Vec<u8> {
    let mut buf = Vec::new();
    write_utf(&mut buf, "PlayerCount");
    write_utf(&mut buf, server);
    write_int(&mut buf, count);
    buf
}

/// `PlayerList` reply: the server asked about, then a comma-separated list.
pub fn response_player_list(server: &str, players: &[String]) -> Vec<u8> {
    let mut buf = Vec::new();
    write_utf(&mut buf, "PlayerList");
    write_utf(&mut buf, server);
    write_utf(&mut buf, &players.join(", "));
    buf
}

/// `GetServers` reply: a comma-separated list of configured server names.
pub fn response_get_servers(servers: &[String]) -> Vec<u8> {
    let mut buf = Vec::new();
    write_utf(&mut buf, "GetServers");
    write_utf(&mut buf, &servers.join(", "));
    buf
}

/// `GetServer` reply: the name of the server the player is on.
pub fn response_get_server(server: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    write_utf(&mut buf, "GetServer");
    write_utf(&mut buf, server);
    buf
}

/// `IP` reply: the player's address and port.
pub fn response_ip(ip: &str, port: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    write_utf(&mut buf, "IP");
    write_utf(&mut buf, ip);
    write_int(&mut buf, port as i32);
    buf
}

/// Reads back a reply: the subchannel, its string fields and its numeric field.
///
/// The shape is chosen by subchannel rather than guessed from the bytes. A
/// guess cannot work: an `int` of 12 starts with two zero bytes, which is
/// indistinguishable from a zero-length string, so a reader that tries strings
/// first silently mis-parses every small number.
pub fn decode_response(data: &[u8]) -> anyhow::Result<(String, Vec<String>, Option<i32>)> {
    let (subchannel, mut offset) = read_utf(data)?;
    let mut strings = Vec::new();
    let mut number = None;

    let take_string = |offset: &mut usize| -> anyhow::Result<String> {
        let (s, n) = read_utf(&data[*offset..])?;
        *offset += n;
        Ok(s)
    };

    match subchannel.as_str() {
        "PlayerCount" => {
            strings.push(take_string(&mut offset)?);
            number = Some(read_int(&data[offset..])?.0);
        }
        "IP" | "IPOther" => {
            strings.push(take_string(&mut offset)?);
            number = Some(read_int(&data[offset..])?.0);
        }
        "PlayerList" => {
            strings.push(take_string(&mut offset)?);
            strings.push(take_string(&mut offset)?);
        }
        "GetServers" | "GetServer" => {
            strings.push(take_string(&mut offset)?);
        }
        _ => {
            // Unknown reply shape: return what is there without guessing.
            while offset < data.len() {
                match take_string(&mut offset) {
                    Ok(s) => strings.push(s),
                    Err(_) => break,
                }
            }
        }
    }

    Ok((subchannel, strings, number))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_names() {
        assert!(is_bungee_channel("bungeecord:main"));
        assert!(is_bungee_channel("BungeeCord"));
        assert!(!is_bungee_channel("velocity:player_info"));
    }

    #[test]
    fn connect_round_trip() {
        let data = BungeeMessage::connect_request("survival");
        assert_eq!(
            BungeeMessage::decode(&data).unwrap(),
            BungeeMessage::Connect {
                server: "survival".into()
            }
        );
    }

    #[test]
    fn connect_other_round_trip() {
        let data = BungeeMessage::connect_other_request("Notch", "lobby");
        assert_eq!(
            BungeeMessage::decode(&data).unwrap(),
            BungeeMessage::ConnectOther {
                player: "Notch".into(),
                server: "lobby".into()
            }
        );
    }

    #[test]
    fn argument_less_subchannels() {
        let mut buf = Vec::new();
        write_utf(&mut buf, "GetServers");
        assert_eq!(BungeeMessage::decode(&buf).unwrap(), BungeeMessage::GetServers);

        let mut buf = Vec::new();
        write_utf(&mut buf, "IP");
        assert_eq!(BungeeMessage::decode(&buf).unwrap(), BungeeMessage::Ip);
    }

    #[test]
    fn unknown_subchannel_is_reported_not_fatal() {
        let mut buf = Vec::new();
        write_utf(&mut buf, "Forward");
        write_utf(&mut buf, "ALL");
        match BungeeMessage::decode(&buf).unwrap() {
            BungeeMessage::Unsupported { subchannel } => assert_eq!(subchannel, "Forward"),
            other => panic!("expected Unsupported, got {:?}", other),
        }
    }

    #[test]
    fn missing_arguments_are_an_error_not_a_panic() {
        let mut buf = Vec::new();
        write_utf(&mut buf, "Connect");
        assert!(BungeeMessage::decode(&buf).is_err());
    }

    #[test]
    fn player_count_reply_round_trips() {
        let data = response_player_count("lobby", 12);
        let (sub, strings, number) = decode_response(&data).unwrap();
        assert_eq!(sub, "PlayerCount");
        assert_eq!(strings, vec!["lobby"]);
        assert_eq!(number, Some(12));
    }

    #[test]
    fn player_list_reply_round_trips() {
        let data = response_player_list("ALL", &["Notch".into(), "jeb_".into()]);
        let (sub, strings, _) = decode_response(&data).unwrap();
        assert_eq!(sub, "PlayerList");
        assert_eq!(strings, vec!["ALL", "Notch, jeb_"]);
    }

    #[test]
    fn a_small_int_is_not_mistaken_for_a_string() {
        // 12 encodes as 00 00 00 0C; the leading zeros look exactly like an
        // empty string to a reader that guesses.
        let data = response_player_count("lobby", 12);
        let (_, strings, number) = decode_response(&data).unwrap();
        assert_eq!(strings, vec!["lobby"], "no phantom empty string");
        assert_eq!(number, Some(12));

        let data = response_player_count("lobby", 0);
        assert_eq!(decode_response(&data).unwrap().2, Some(0));
    }

    #[test]
    fn ip_reply_round_trips() {
        let data = response_ip("203.0.113.7", 51234);
        let (sub, strings, number) = decode_response(&data).unwrap();
        assert_eq!(sub, "IP");
        assert_eq!(strings, vec!["203.0.113.7"]);
        assert_eq!(number, Some(51234));
    }
}

#![no_main]
//! Throws arbitrary bytes at every packet decoder.

use libfuzzer_sys::fuzz_target;

use flow_proxy::protocol::forwarding::verify_forwarding_payload;
use flow_proxy::protocol::handshake::HandshakePacket;
use flow_proxy::protocol::login::{
    LoginDisconnect, LoginPluginRequest, LoginStart, LoginSuccess, SetCompression,
};
use flow_proxy::protocol::packet::RawPacket;
use flow_proxy::protocol::plugin_message::BungeeMessage;
use flow_proxy::protocol::status::PingRequest;
use flow_proxy::protocol::types::{read_byte_array, read_long, read_string, read_ushort, read_uuid};
use flow_proxy::protocol::varint::read_varint;

fuzz_target!(|data: &[u8]| {
    let _ = read_varint(data);
    let _ = read_string(data);
    let _ = read_uuid(data);
    let _ = read_ushort(data);
    let _ = read_long(data);
    let _ = read_byte_array(data);
    let _ = RawPacket::decode(data);
    let _ = HandshakePacket::decode(data);
    let _ = LoginStart::decode(data);
    let _ = LoginSuccess::decode(data);
    let _ = LoginPluginRequest::decode(data);
    let _ = SetCompression::decode(data);
    let _ = LoginDisconnect::decode_reason(data);
    let _ = PingRequest::decode(data);
    let _ = verify_forwarding_payload(b"secret", data);
    let _ = BungeeMessage::decode(data);
});

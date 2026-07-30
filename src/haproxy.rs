//! HAProxy PROXY protocol support (inbound).
//!
//! When the proxy sits behind HAProxy or a similar load balancer, the TCP peer
//! address is the balancer's, not the player's. The PROXY protocol prefixes the
//! connection with a header carrying the original addresses.
//!
//! This matters beyond logging: the address goes into the Velocity forwarding
//! payload, so without it every player appears to the backend as coming from
//! the balancer, breaking per-IP bans and rate limits.
//!
//! Both v2 (binary, the default HAProxy emits) and v1 (ASCII) are accepted.
//! Reading is strictly bounded: the header is consumed exactly, leaving the
//! Minecraft handshake as the next bytes on the socket.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::TcpStream;

/// The 12-byte v2 signature.
const V2_SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// v1 headers start with this and are at least 15 bytes ("PROXY UNKNOWN\r\n"),
/// so reading the first 12 bytes to detect the version can never overrun them.
const V1_PREFIX: &[u8] = b"PROXY ";

/// A v1 header is capped by the specification at 107 bytes.
const V1_MAX_LEN: usize = 107;

/// The outcome of reading a header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyHeader {
    /// A proxied connection: this is the original client address.
    Proxied(SocketAddr),
    /// A health check or a connection the balancer made on its own behalf.
    /// The real peer address should be used.
    Local,
}

/// Reads and consumes a PROXY protocol header from the front of `stream`.
///
/// Errors if the header is absent or malformed; when the option is enabled the
/// header is mandatory, and silently treating a missing one as "no proxy" would
/// let a client spoof its own address by simply not sending it.
pub async fn read_header<R: AsyncRead + Unpin>(stream: &mut R) -> anyhow::Result<ProxyHeader> {
    let mut head = [0u8; 12];
    stream.read_exact(&mut head).await?;

    if head == V2_SIGNATURE {
        read_v2(stream).await
    } else if head.starts_with(V1_PREFIX) {
        read_v1(stream, &head).await
    } else {
        anyhow::bail!(
            "expected a PROXY protocol header but the connection started with {:02X?}. \
             Disable haproxy-protocol if there is no load balancer in front of the proxy.",
            &head[..4]
        )
    }
}

/// Consumes the PROXY protocol header when `enabled` and returns the address
/// the rest of the proxy should treat as the client's.
///
/// Returns `Ok(None)` for a LOCAL header, which is how a load balancer performs
/// health checks: there is no player behind it.
pub async fn resolve_client_address(
    mut stream: TcpStream,
    peer: SocketAddr,
    enabled: bool,
) -> anyhow::Result<Option<(TcpStream, SocketAddr)>> {
    if !enabled {
        return Ok(Some((stream, peer)));
    }

    match read_header(&mut stream).await? {
        ProxyHeader::Proxied(real) => {
            tracing::debug!("[{}] PROXY protocol: real client is {}", peer, real);
            Ok(Some((stream, real)))
        }
        ProxyHeader::Local => Ok(None),
    }
}

async fn read_v2<R: AsyncRead + Unpin>(stream: &mut R) -> anyhow::Result<ProxyHeader> {
    let mut meta = [0u8; 4];
    stream.read_exact(&mut meta).await?;

    let version = meta[0] >> 4;
    let command = meta[0] & 0x0F;
    let family = meta[1] >> 4;
    let transport = meta[1] & 0x0F;
    let len = u16::from_be_bytes([meta[2], meta[3]]) as usize;

    if version != 2 {
        anyhow::bail!("unsupported PROXY protocol version {}", version);
    }

    // The declared length must be consumed in full whatever we do with it,
    // otherwise the leftover bytes would be parsed as Minecraft packets.
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;

    // 0x00 = LOCAL (health checks), 0x01 = PROXY.
    if command == 0x00 {
        return Ok(ProxyHeader::Local);
    }
    if command != 0x01 {
        anyhow::bail!("unknown PROXY v2 command 0x{:02X}", command);
    }

    // Only stream transports carry a Minecraft connection.
    if transport != 0x01 {
        anyhow::bail!("PROXY v2 transport 0x{:02X} is not a stream", transport);
    }

    match family {
        // AF_INET
        0x01 => {
            if body.len() < 12 {
                anyhow::bail!("PROXY v2 IPv4 block truncated: {} bytes", body.len());
            }
            let src = Ipv4Addr::new(body[0], body[1], body[2], body[3]);
            let port = u16::from_be_bytes([body[8], body[9]]);
            Ok(ProxyHeader::Proxied(SocketAddr::new(IpAddr::V4(src), port)))
        }
        // AF_INET6
        0x02 => {
            if body.len() < 36 {
                anyhow::bail!("PROXY v2 IPv6 block truncated: {} bytes", body.len());
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&body[..16]);
            let port = u16::from_be_bytes([body[32], body[33]]);
            Ok(ProxyHeader::Proxied(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(octets)),
                port,
            )))
        }
        // AF_UNIX carries no useful address for us; anything else is unspec.
        _ => Ok(ProxyHeader::Local),
    }
    // Any TLVs after the address block are inside `len` and already consumed.
}

async fn read_v1<R: AsyncRead + Unpin>(
    stream: &mut R,
    already_read: &[u8],
) -> anyhow::Result<ProxyHeader> {
    let mut line = already_read.to_vec();

    // Read one byte at a time up to the CRLF. Over-reading would eat into the
    // handshake, and the header is short enough that this is cheap.
    loop {
        if line.len() > V1_MAX_LEN {
            anyhow::bail!("PROXY v1 header exceeds {} bytes", V1_MAX_LEN);
        }
        if line.ends_with(b"\r\n") {
            break;
        }
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await?;
        line.push(byte[0]);
    }

    let line = std::str::from_utf8(&line[..line.len() - 2])
        .map_err(|_| anyhow::anyhow!("PROXY v1 header is not valid UTF-8"))?;

    let fields: Vec<&str> = line.split(' ').collect();
    // "PROXY UNKNOWN" may omit the addresses entirely.
    if fields.len() >= 2 && fields[1] == "UNKNOWN" {
        return Ok(ProxyHeader::Local);
    }
    if fields.len() != 6 {
        anyhow::bail!("malformed PROXY v1 header: {:?}", line);
    }

    let ip: IpAddr = fields[2]
        .parse()
        .map_err(|_| anyhow::anyhow!("bad source address in PROXY v1 header: {}", fields[2]))?;
    let port: u16 = fields[4]
        .parse()
        .map_err(|_| anyhow::anyhow!("bad source port in PROXY v1 header: {}", fields[4]))?;

    match (fields[1], ip) {
        ("TCP4", IpAddr::V4(_)) | ("TCP6", IpAddr::V6(_)) => {}
        (proto, _) => anyhow::bail!("PROXY v1 protocol {} does not match the address", proto),
    }

    Ok(ProxyHeader::Proxied(SocketAddr::new(ip, port)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v2_header(family: u8, command: u8, body: &[u8]) -> Vec<u8> {
        let mut out = V2_SIGNATURE.to_vec();
        out.push(0x20 | command);
        out.push((family << 4) | 0x01);
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    #[tokio::test]
    async fn v2_ipv4() {
        let mut body = Vec::new();
        body.extend_from_slice(&[203, 0, 113, 7]); // source
        body.extend_from_slice(&[10, 0, 0, 1]); // destination
        body.extend_from_slice(&51234u16.to_be_bytes());
        body.extend_from_slice(&25565u16.to_be_bytes());

        let mut data = v2_header(0x01, 0x01, &body);
        data.extend_from_slice(b"HANDSHAKE");

        let mut cursor = &data[..];
        let header = read_header(&mut cursor).await.unwrap();
        assert_eq!(
            header,
            ProxyHeader::Proxied("203.0.113.7:51234".parse().unwrap())
        );
        // The handshake bytes must be left untouched.
        assert_eq!(cursor, b"HANDSHAKE");
    }

    #[tokio::test]
    async fn v2_ipv6() {
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&addr.octets());
        body.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        body.extend_from_slice(&40000u16.to_be_bytes());
        body.extend_from_slice(&25565u16.to_be_bytes());

        let data = v2_header(0x02, 0x01, &body);
        let mut cursor = &data[..];
        let header = read_header(&mut cursor).await.unwrap();
        assert_eq!(
            header,
            ProxyHeader::Proxied(SocketAddr::new(IpAddr::V6(addr), 40000))
        );
    }

    #[tokio::test]
    async fn v2_trailing_tlvs_are_consumed() {
        let mut body = Vec::new();
        body.extend_from_slice(&[192, 168, 1, 2]);
        body.extend_from_slice(&[192, 168, 1, 1]);
        body.extend_from_slice(&1234u16.to_be_bytes());
        body.extend_from_slice(&25565u16.to_be_bytes());
        // A PP2_TYPE_ALPN TLV appended after the addresses.
        body.extend_from_slice(&[0x01, 0x00, 0x03, b'm', b'c', b'j']);

        let mut data = v2_header(0x01, 0x01, &body);
        data.extend_from_slice(b"NEXT");

        let mut cursor = &data[..];
        let header = read_header(&mut cursor).await.unwrap();
        assert_eq!(
            header,
            ProxyHeader::Proxied("192.168.1.2:1234".parse().unwrap())
        );
        assert_eq!(cursor, b"NEXT", "TLVs must not leak into the packet stream");
    }

    #[tokio::test]
    async fn v2_local_is_a_health_check() {
        let data = v2_header(0x00, 0x00, &[]);
        let mut cursor = &data[..];
        assert_eq!(read_header(&mut cursor).await.unwrap(), ProxyHeader::Local);
    }

    #[tokio::test]
    async fn v1_ipv4() {
        let mut data = b"PROXY TCP4 203.0.113.7 10.0.0.1 51234 25565\r\n".to_vec();
        data.extend_from_slice(b"HANDSHAKE");

        let mut cursor = &data[..];
        let header = read_header(&mut cursor).await.unwrap();
        assert_eq!(
            header,
            ProxyHeader::Proxied("203.0.113.7:51234".parse().unwrap())
        );
        assert_eq!(cursor, b"HANDSHAKE");
    }

    #[tokio::test]
    async fn v1_unknown() {
        let data = b"PROXY UNKNOWN\r\n".to_vec();
        let mut cursor = &data[..];
        assert_eq!(read_header(&mut cursor).await.unwrap(), ProxyHeader::Local);
    }

    #[tokio::test]
    async fn a_plain_minecraft_handshake_is_rejected() {
        // A raw client connecting to a haproxy-enabled listener must be
        // refused, not silently trusted.
        let data = vec![0x10, 0x00, 0xF9, 0x05, 0x09, b'l', b'o', b'c', 0, 0, 0, 0, 0];
        let mut cursor = &data[..];
        assert!(read_header(&mut cursor).await.is_err());
    }

    #[tokio::test]
    async fn v1_protocol_and_address_must_agree() {
        let data = b"PROXY TCP6 203.0.113.7 10.0.0.1 51234 25565\r\n".to_vec();
        let mut cursor = &data[..];
        assert!(read_header(&mut cursor).await.is_err());
    }
}

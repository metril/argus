//! Transparent-gateway entry mode.
//!
//! The OS redirects client TCP (typically 80/443) to a dedicated listener; the client has no
//! proxy configuration. This entry layer works out `(host, port)` and hands the stream to the
//! same pipeline as explicit mode ([`ConnectionHandler::intercept_and_serve`] /
//! `serve_http`):
//!
//! * The original destination comes from an [`OriginalDst`] (production: `SO_ORIGINAL_DST` /
//!   `IP6T_SO_ORIGINAL_DST`, Linux only).
//! * TLS (first byte `0x16`): the ClientHello is read into a buffer, parsed for SNI with rustls'
//!   [`Acceptor`](rustls::server::Acceptor), and replayed to the TLS acceptor, so nothing is lost.
//!   No SNI, an unparsable hello or a host on the passthrough list means an opaque tunnel.
//! * Plain HTTP: served directly; the target host comes from each request's `Host` header and
//!   falls back to the original destination address.
//! * Anything else (and HTTP on port 443) is tunnelled to the original destination untouched.
//! * Loop guard: connections whose original destination is the proxy itself are refused.

use crate::connection::{
    read_at_least, ConnectionHandler, ConnectionTarget, HeadError, Origin, Prefixed,
};
use crate::{Error, Result};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tracing::debug;

/// Largest ClientHello we are willing to buffer.
const MAX_CLIENT_HELLO: usize = 32 * 1024;

/// Where an accepted (redirected) connection was originally headed.
pub trait OriginalDst: Send + Sync + 'static {
    fn original_dst(&self, stream: &TcpStream) -> io::Result<SocketAddr>;
}

/// Production implementation: reads `SO_ORIGINAL_DST` (IPv4) or `IP6T_SO_ORIGINAL_DST` (IPv6) from
/// the accepted socket. Only Linux supports this; elsewhere every lookup fails with
/// `Unsupported`.
#[derive(Debug, Default, Clone, Copy)]
pub struct KernelOriginalDst;

/// Whether this build can read the kernel's original destination.
pub const KERNEL_ORIGINAL_DST_SUPPORTED: bool = cfg!(target_os = "linux");

#[cfg(target_os = "linux")]
impl OriginalDst for KernelOriginalDst {
    fn original_dst(&self, stream: &TcpStream) -> io::Result<SocketAddr> {
        let sock = socket2::SockRef::from(stream);
        // A dual-stack IPv6 listener sees redirected IPv4 as v4-mapped; the option family follows
        // the original packet, not the socket.
        let addr = match stream.local_addr()?.ip().to_canonical() {
            std::net::IpAddr::V4(_) => sock.original_dst_v4()?,
            std::net::IpAddr::V6(_) => sock.original_dst_v6()?,
        };
        addr.as_socket().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "non-IP original destination")
        })
    }
}

#[cfg(not(target_os = "linux"))]
impl OriginalDst for KernelOriginalDst {
    fn original_dst(&self, _stream: &TcpStream) -> io::Result<SocketAddr> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "transparent mode needs Linux SO_ORIGINAL_DST",
        ))
    }
}

/// True when `dst` is the proxy itself: the accepted socket's own address (a client that dialled
/// the transparent port directly), or one of the proxy's listening ports on a local address.
pub fn is_self(dst: SocketAddr, local: SocketAddr, own_ports: &[u16]) -> bool {
    let dst_ip = dst.ip().to_canonical();
    let local_ip = local.ip().to_canonical();
    (dst_ip == local_ip && dst.port() == local.port())
        || (own_ports.contains(&dst.port())
            && (dst_ip.is_loopback() || dst_ip == local_ip || dst_ip.is_unspecified()))
}

/// What the first bytes of a redirected connection look like.
#[derive(Debug, PartialEq, Eq)]
enum Hello {
    Sni(String),
    NoSni,
    NotTls,
}

fn looks_like_http(buf: &[u8]) -> bool {
    const METHODS: [&[u8]; 8] = [
        b"GET ",
        b"POST ",
        b"HEAD ",
        b"PUT ",
        b"DELETE ",
        b"OPTIONS ",
        b"PATCH ",
        b"TRACE ",
    ];
    METHODS.iter().any(|m| buf.starts_with(m))
}

/// Parse a ClientHello out of `buf` (reading more from `stream` as needed, never discarding
/// anything: `buf` keeps every byte for replay).
async fn read_client_hello(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    limit: Duration,
) -> Result<Hello> {
    let fut = async {
        let mut acceptor = rustls::server::Acceptor::default();
        let mut fed = 0usize;
        loop {
            if fed < buf.len() {
                let mut rest = &buf[fed..];
                match acceptor.read_tls(&mut rest) {
                    Ok(n) if n > 0 => fed += n,
                    _ => return Ok(Hello::NotTls),
                }
            }
            match acceptor.accept() {
                Ok(Some(accepted)) => {
                    let hello = accepted.client_hello();
                    return Ok(match hello.server_name() {
                        Some(n) if !n.is_empty() => {
                            Hello::Sni(n.trim_end_matches('.').to_ascii_lowercase())
                        }
                        _ => Hello::NoSni,
                    });
                }
                Ok(None) => {}
                Err(_) => return Ok(Hello::NotTls),
            }
            if fed >= buf.len() {
                if buf.len() > MAX_CLIENT_HELLO {
                    return Ok(Hello::NotTls);
                }
                if stream.read_buf(buf).await? == 0 {
                    return Ok(Hello::NotTls);
                }
            }
        }
    };
    tokio::time::timeout(limit, fut)
        .await
        .map_err(|_| Error::Timeout)?
}

fn head_err(e: HeadError) -> Error {
    match e {
        HeadError::Timeout => Error::Timeout,
        HeadError::Io(e) => Error::Io(e),
        HeadError::Closed => Error::Connection("closed before first bytes".into()),
        HeadError::TooLarge => Error::Connection("first bytes too large".into()),
    }
}

/// Entry layer for the transparent listener.
pub struct TransparentEntry {
    original_dst: Arc<dyn OriginalDst>,
    /// Ports the proxy itself listens on (explicit and transparent), for the loop guard.
    own_ports: Vec<u16>,
}

impl TransparentEntry {
    pub fn new(original_dst: Arc<dyn OriginalDst>, own_ports: Vec<u16>) -> Self {
        Self {
            original_dst,
            own_ports,
        }
    }

    /// Handle one redirected connection end to end.
    pub async fn handle(&self, h: &ConnectionHandler, mut stream: TcpStream) -> Result<()> {
        let _ = stream.set_nodelay(true);
        let dst = self
            .original_dst
            .original_dst(&stream)
            .map_err(|e| Error::Connection(format!("original destination unavailable: {e}")))?;
        let local = stream.local_addr()?;
        if is_self(dst, local, &self.own_ports) {
            return Err(Error::Connection(format!(
                "refusing connection from {} whose destination {dst} is the proxy itself",
                h.client_addr
            )));
        }

        let limit = h.shared.timeouts.handshake;
        let mut buf = Vec::with_capacity(2048);
        read_at_least(&mut stream, &mut buf, 1, limit)
            .await
            .map_err(head_err)?;

        let target = |host: String, intercept_tls: bool| ConnectionTarget {
            host,
            port: dst.port(),
            client_addr: h.client_addr,
            intercept_tls,
        };

        if buf[0] == 0x16 {
            let hello = read_client_hello(&mut stream, &mut buf, limit).await?;
            let io = Prefixed::new(buf, stream);
            return match hello {
                Hello::Sni(host) => {
                    let passthrough = h.shared.passthrough.matches(&host);
                    debug!(
                        "transparent TLS {host}:{} from {} ({})",
                        dst.port(),
                        h.client_addr,
                        if passthrough {
                            "passthrough"
                        } else {
                            "intercept"
                        }
                    );
                    let intercept = h.shared.mitm.is_some() && !passthrough;
                    h.intercept_and_serve(io, target(host, intercept)).await
                }
                // No hostname to dial or to mint a certificate for: opaque tunnel to the original
                // destination address.
                Hello::NoSni | Hello::NotTls => {
                    debug!(
                        "transparent TLS without SNI to {dst} from {}",
                        h.client_addr
                    );
                    h.intercept_and_serve(io, target(dst.ip().to_string(), false))
                        .await
                }
            };
        }

        // Short or slow first bytes are not HTTP; fall through to the tunnel with what we have.
        let _ = read_at_least(&mut stream, &mut buf, 8, limit).await;
        let io = Prefixed::new(buf.clone(), stream);
        if dst.port() != 443 && looks_like_http(&buf) {
            debug!("transparent HTTP to {dst} from {}", h.client_addr);
            return h.serve_http(io, Origin::plain(dst)).await;
        }
        debug!(
            "transparent non-TLS/non-HTTP to {dst} from {}",
            h.client_addr
        );
        h.intercept_and_serve(io, target(dst.ip().to_string(), false))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn loop_guard_detects_the_proxy_itself() {
        let local = sa("192.168.1.1:3129");
        let ports = [8080, 3129];
        assert!(is_self(sa("192.168.1.1:3129"), local, &ports));
        assert!(is_self(sa("127.0.0.1:8080"), local, &ports));
        assert!(is_self(sa("192.168.1.1:8080"), local, &ports));
        assert!(is_self(sa("[::ffff:127.0.0.1]:8080"), local, &ports));
        assert!(!is_self(sa("93.184.216.34:443"), local, &ports));
        assert!(!is_self(sa("127.0.0.1:443"), local, &ports));
        assert!(!is_self(sa("93.184.216.34:8080"), local, &ports));
    }

    #[test]
    fn http_method_sniffing() {
        assert!(looks_like_http(b"GET / HTTP/1.1\r\n"));
        assert!(looks_like_http(b"OPTIONS * HTTP/1.1"));
        assert!(!looks_like_http(b"SSH-2.0-OpenSSH"));
        assert!(!looks_like_http(b"\x16\x03\x01"));
    }
}

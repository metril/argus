//! WebSocket proxying.
//!
//! The client's upgrade request is forwarded upstream (over TLS for `wss`) and, when the origin
//! answers `101`, both upgraded streams are spliced byte-for-byte. Extensions and subprotocols
//! negotiated end to end therefore keep working, and the proxy never re-frames messages.

use crate::authority;
use crate::connection::IdleIo;
use crate::filtering::{refused_response, ProxyContext};
use crate::inject::{full_body, ProxyBody};
use crate::policy::DestPolicy;
use crate::request_ctx::RequestCtx;
use crate::{Error, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::header::{HeaderMap, HeaderName, HOST};
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tokio_rustls::TlsConnector;
use tracing::debug;

/// Check if a request is a WebSocket upgrade request
pub fn is_websocket_upgrade(headers: &hyper::HeaderMap) -> bool {
    headers
        .get(hyper::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
        && headers
            .get(hyper::header::CONNECTION)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_lowercase().contains("upgrade"))
            .unwrap_or(false)
}

/// Extract the target WebSocket URL from the request
pub fn extract_ws_target(uri: &hyper::Uri, headers: &hyper::HeaderMap) -> Result<String> {
    let host = uri
        .host()
        .or_else(|| {
            headers
                .get(hyper::header::HOST)
                .and_then(|v| v.to_str().ok())
        })
        .ok_or_else(|| Error::Http("Missing host in WebSocket request".to_string()))?;

    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    // Determine scheme based on port or assume wss
    let scheme = if uri.port_u16().unwrap_or(443) == 80 {
        "ws"
    } else {
        "wss"
    };

    Ok(format!("{}://{}{}", scheme, host, path))
}

/// Object-safe duplex stream (plain TCP or TLS) used for upstream WebSocket connections.
pub trait WsIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> WsIo for T {}

/// How WebSocket upgrades dial upstream: same trust roots as the HTTP client (built-in web roots
/// plus the configured extra CAs) and an optional fixed-IP override matching
/// `UpstreamOptions::resolve_all_to`.
pub struct WsUpstream {
    tls: TlsConnector,
    policy: Arc<DestPolicy>,
    resolve_all_to: Option<IpAddr>,
    dial_timeout: Duration,
    /// Spliced connections close after this long without traffic.
    idle_timeout: std::sync::atomic::AtomicU64,
    /// Spliced connections end when the proxy shuts down.
    shutdown: Option<broadcast::Sender<()>>,
}

impl WsUpstream {
    pub fn new(
        roots: Arc<crate::roots::RootsHandle>,
        policy: Arc<DestPolicy>,
        resolve_all_to: Option<IpAddr>,
        dial_timeout: Duration,
    ) -> Result<Self> {
        // Verified against the live root set on every handshake.
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Tls(format!("Failed to select TLS versions: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(crate::roots::LiveVerifier::new(roots, None)))
        .with_no_client_auth();
        Ok(Self {
            tls: TlsConnector::from(Arc::new(config)),
            policy,
            resolve_all_to,
            dial_timeout,
            idle_timeout: std::sync::atomic::AtomicU64::new(300_000),
            shutdown: None,
        })
    }

    /// Idle timeout for spliced connections, and the proxy shutdown signal that ends them.
    pub fn with_lifecycle(mut self, idle: Duration, shutdown: broadcast::Sender<()>) -> Self {
        self.set_idle_timeout(idle);
        self.shutdown = Some(shutdown);
        self
    }

    /// Change the idle timeout; applies to connections spliced from now on.
    pub fn set_idle_timeout(&self, idle: Duration) {
        self.idle_timeout.store(
            idle.as_millis().min(u64::MAX as u128) as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// The idle timeout new spliced connections get.
    pub fn idle_timeout(&self) -> Duration {
        Duration::from_millis(self.idle_timeout.load(std::sync::atomic::Ordering::Relaxed))
    }

    async fn dial(&self, host: &str, port: u16, tls: bool) -> Result<Box<dyn WsIo>> {
        let connect = async {
            // Resolve once, check the policy on the resolved address, connect to exactly that.
            let addr = self.policy.resolve(host, port, self.resolve_all_to).await?;
            let tcp = TcpStream::connect(addr).await.map_err(Error::Io)?;
            let _ = tcp.set_nodelay(true);
            if !tls {
                return Ok::<Box<dyn WsIo>, Error>(Box::new(tcp));
            }
            let name = ServerName::try_from(host.to_string())
                .map_err(|e| Error::Tls(format!("Invalid server name {host}: {e}")))?;
            let stream = self
                .tls
                .connect(name, tcp)
                .await
                .map_err(|e| Error::Tls(format!("Upstream TLS handshake failed: {e}")))?;
            Ok(Box::new(stream))
        };
        tokio::time::timeout(self.dial_timeout, connect)
            .await
            .map_err(|_| Error::Timeout)?
    }
}

/// Resolved upstream target of an upgrade request.
#[derive(Debug, PartialEq, Eq)]
struct Target {
    host: String,
    port: u16,
    tls: bool,
    path_and_query: String,
}

impl Target {
    /// `http(s)://host[:port]/path` form used for filter matching (adblock matches http(s) URLs).
    fn check_url(&self) -> String {
        let scheme = if self.tls { "https" } else { "http" };
        let default = if self.tls { 443 } else { 80 };
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == default {
            format!("{scheme}://{host}{}", self.path_and_query)
        } else {
            format!("{scheme}://{host}:{}{}", self.port, self.path_and_query)
        }
    }
}

/// Work out where an upgrade request should go: absolute-form URI, else `Host` header, else the
/// CONNECT target (`fallback`). `default_tls` applies when the URI carries no scheme.
fn resolve_target(
    uri: &Uri,
    headers: &HeaderMap,
    default_tls: bool,
    fallback: Option<&(String, u16)>,
) -> Option<Target> {
    let tls = match uri.scheme_str() {
        Some("https") | Some("wss") => true,
        Some("http") | Some("ws") => false,
        _ => default_tls,
    };
    let named = authority::of_request(uri, headers);
    // Behind CONNECT / transparent entry the accepted target fixes the port; the host the request
    // names was already checked against the connection's certificate.
    let (host, port) = match (named, fallback) {
        (Some((h, _)), Some((_, fp))) => (h, Some(*fp)),
        (Some((h, p)), None) => (h, p),
        (None, Some((fh, fp))) => (fh.clone(), Some(*fp)),
        (None, None) => return None,
    };
    let port = port.unwrap_or(if tls { 443 } else { 80 });
    let path_and_query = uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    Some(Target {
        host,
        port,
        tls,
        path_and_query,
    })
}

/// Copy both ways until either side closes, `idle` passes with no traffic, or the proxy shuts
/// down.
async fn splice<C, U>(
    client: C,
    mut upstream: U,
    idle: Duration,
    shutdown: Option<broadcast::Receiver<()>>,
) -> std::io::Result<(u64, u64)>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let mut client = IdleIo::new(client, idle);
    let copy = tokio::io::copy_bidirectional(&mut client, &mut upstream);
    match shutdown {
        Some(mut rx) => tokio::select! {
            r = copy => r,
            _ = rx.recv() => Err(std::io::Error::other("proxy shutting down")),
        },
        None => copy.await,
    }
}

fn status_response(status: StatusCode, msg: &'static str) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .body(full_body(Bytes::from_static(msg.as_bytes())))
        .expect("static response")
}

/// Handle a WebSocket upgrade request: filter, dial upstream, forward the handshake, then splice.
///
/// `default_tls` is true for decrypted (MITM) traffic, whose origin-form URIs carry no scheme.
pub async fn proxy_upgrade(
    ws: &WsUpstream,
    ctx: &ProxyContext,
    rctx: &RequestCtx,
    mut req: Request<Incoming>,
    default_tls: bool,
    fallback: Option<(String, u16)>,
) -> Result<Response<ProxyBody>> {
    let Some(target) = resolve_target(req.uri(), req.headers(), default_tls, fallback.as_ref())
    else {
        return Ok(status_response(
            StatusCode::BAD_REQUEST,
            "Invalid WebSocket target",
        ));
    };

    let check_url = target.check_url();
    let origin = req
        .headers()
        .get(hyper::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .unwrap_or(&check_url)
        .to_string();
    // A host in `full` bypass is forwarded as-is: no filtering, no log event, just the counter.
    let bypass_full = ctx.bypass().mode_of(&target.host) == Some(common::bypass::BypassMode::Full);
    if bypass_full {
        ctx.bypass().note_bypassed();
    }
    if !bypass_full && ctx.should_block_with(rctx, &check_url, &origin, "websocket") {
        debug!("Blocked WebSocket to {}", check_url);
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header("x-adblock", "blocked")
            .header("cache-control", "no-store")
            .body(full_body(Bytes::from_static(b"Blocked")))
            .expect("static response"));
    }

    let io = match ws.dial(&target.host, target.port, target.tls).await {
        Ok(io) => io,
        Err(Error::DestinationRefused(why)) => {
            common::faults::note(common::faults::Fault::PolicyRefusal, &target.host);
            debug!("Refused WebSocket to {}: {}", check_url, why);
            return Ok(refused_response());
        }
        Err(e) => {
            debug!("WebSocket upstream dial to {} failed: {}", check_url, e);
            return Ok(status_response(
                StatusCode::BAD_GATEWAY,
                "WebSocket upstream unavailable",
            ));
        }
    };

    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .map_err(|e| Error::Connection(format!("WebSocket upstream handshake: {e}")))?;
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });

    // Forward the client's handshake (Sec-WebSocket-* and the Upgrade pair included).
    let mut up_req = Request::builder()
        .method(Method::GET)
        .uri(target.path_and_query.as_str())
        .body(Empty::<Bytes>::new())
        .map_err(|e| Error::Http(format!("Bad upgrade request: {e}")))?;
    {
        let headers = up_req.headers_mut();
        for (name, value) in req.headers() {
            // The forwarded request has no body: framing headers of the client's request would
            // make the origin wait for one.
            if name == HeaderName::from_static("proxy-authorization")
                || name == HeaderName::from_static("proxy-connection")
                || name == HeaderName::from_static(crate::ext_bridge::SESSION_HEADER)
                || name == HeaderName::from_static(crate::ext_bridge::RELAY_HEADER)
                || name == HOST
                || name == hyper::header::CONTENT_LENGTH
                || name == hyper::header::TRANSFER_ENCODING
            {
                continue;
            }
            headers.append(name.clone(), value.clone());
        }
        // Host is rebuilt from the accepted target, never taken from the client.
        let default = if target.tls { 443 } else { 80 };
        let host = authority::url_host(&target.host);
        let value = if target.port == default {
            host
        } else {
            format!("{host}:{}", target.port)
        };
        if let Ok(v) = value.parse() {
            headers.insert(HOST, v);
        }
    }

    let mut resp = match tokio::time::timeout(ws.dial_timeout, sender.send_request(up_req)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            debug!("WebSocket upstream request failed: {}", e);
            return Ok(status_response(
                StatusCode::BAD_GATEWAY,
                "WebSocket upstream error",
            ));
        }
        Err(_) => {
            return Ok(status_response(
                StatusCode::GATEWAY_TIMEOUT,
                "WebSocket upstream timeout",
            ))
        }
    };

    if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        // Origin refused the upgrade: hand its answer back unchanged.
        return Ok(resp.map(|b| b.map_err(std::io::Error::other).boxed_unsync()));
    }

    let up_upgrade = hyper::upgrade::on(&mut resp);
    let client_upgrade = hyper::upgrade::on(&mut req);
    let desc = check_url.clone();
    let idle = ws.idle_timeout();
    let shutdown = ws.shutdown.as_ref().map(|tx| tx.subscribe());
    tokio::spawn(async move {
        match tokio::try_join!(client_upgrade, up_upgrade) {
            Ok((client, upstream)) => {
                let client = TokioIo::new(client);
                let upstream = TokioIo::new(upstream);
                match splice(client, upstream, idle, shutdown).await {
                    Ok((up, down)) => debug!("WebSocket {} closed (up {up}B, down {down}B)", desc),
                    Err(e) => debug!("WebSocket {} ended: {}", desc, e),
                }
            }
            Err(e) => debug!("WebSocket upgrade failed for {}: {}", desc, e),
        }
    });

    let mut out = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
    *out.headers_mut().expect("builder headers") = resp.headers().clone();
    out.body(full_body(Bytes::new()))
        .map_err(|e| Error::Http(format!("Bad upgrade response: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::HeaderMap;

    #[test]
    fn test_is_websocket_upgrade() {
        let mut headers = HeaderMap::new();
        headers.insert(hyper::header::UPGRADE, "websocket".parse().unwrap());
        headers.insert(hyper::header::CONNECTION, "Upgrade".parse().unwrap());

        assert!(is_websocket_upgrade(&headers));
    }

    #[test]
    fn test_is_not_websocket_upgrade() {
        let headers = HeaderMap::new();
        assert!(!is_websocket_upgrade(&headers));
    }

    #[test]
    fn test_extract_ws_target() {
        let uri = "https://example.com:443/ws".parse::<hyper::Uri>().unwrap();
        let headers = HeaderMap::new();

        let target = extract_ws_target(&uri, &headers).unwrap();
        // Note: port is not included in output since uri.host() doesn't include it
        assert_eq!(target, "wss://example.com/ws");
    }

    #[test]
    fn test_extract_ws_target_with_host_header() {
        let uri = "/ws".parse::<hyper::Uri>().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(hyper::header::HOST, "example.com".parse().unwrap());

        let target = extract_ws_target(&uri, &headers).unwrap();
        assert_eq!(target, "wss://example.com/ws");
    }

    #[test]
    fn target_from_host_header_and_scheme_default() {
        let uri: Uri = "/chat?x=1".parse().unwrap();
        let mut h = HeaderMap::new();
        h.insert(HOST, "example.com:8080".parse().unwrap());
        let t = resolve_target(&uri, &h, false, None).unwrap();
        assert_eq!(
            t,
            Target {
                host: "example.com".into(),
                port: 8080,
                tls: false,
                path_and_query: "/chat?x=1".into()
            }
        );
        assert_eq!(t.check_url(), "http://example.com:8080/chat?x=1");
    }

    #[test]
    fn target_mitm_fallback_and_default_ports() {
        let uri: Uri = "/ws".parse().unwrap();
        let fb = ("example.com".to_string(), 443);
        let t = resolve_target(&uri, &HeaderMap::new(), true, Some(&fb)).unwrap();
        assert!(t.tls && t.port == 443);
        assert_eq!(t.check_url(), "https://example.com/ws");
        assert!(resolve_target(&uri, &HeaderMap::new(), true, None).is_none());
    }

    #[test]
    fn target_absolute_ws_scheme_and_ipv6() {
        let uri: Uri = "ws://[::1]:9000/s".parse().unwrap();
        let t = resolve_target(&uri, &HeaderMap::new(), true, None).unwrap();
        assert!(!t.tls);
        assert_eq!(t.host, "::1");
        assert_eq!(t.check_url(), "http://[::1]:9000/s");
    }

    #[test]
    fn accepted_target_port_beats_hostile_host_port() {
        let uri: Uri = "/ws".parse().unwrap();
        let mut h = HeaderMap::new();
        h.insert(HOST, "example.com:6379".parse().unwrap());
        let fb = ("example.com".to_string(), 443);
        let t = resolve_target(&uri, &h, true, Some(&fb)).unwrap();
        assert_eq!((t.host.as_str(), t.port), ("example.com", 443));
        // Same for an absolute-form URI naming another port.
        let abs: Uri = "wss://example.com:22/ws".parse().unwrap();
        let t = resolve_target(&abs, &HeaderMap::new(), true, Some(&fb)).unwrap();
        assert_eq!(t.port, 443);
        // Without an accepted target the request's own port is used.
        let t = resolve_target(&uri, &h, true, None).unwrap();
        assert_eq!(t.port, 6379);
    }

    #[test]
    fn bracketed_ipv6_host_header() {
        let uri: Uri = "/ws".parse().unwrap();
        let mut h = HeaderMap::new();
        h.insert(HOST, "[2001:db8::1]:8443".parse().unwrap());
        let t = resolve_target(&uri, &h, true, None).unwrap();
        assert_eq!((t.host.as_str(), t.port), ("2001:db8::1", 8443));
    }

    #[tokio::test]
    async fn splice_ends_after_idle_timeout() {
        let (client, _client_peer) = tokio::io::duplex(64);
        let (upstream, _upstream_peer) = tokio::io::duplex(64);
        let r = splice(client, upstream, Duration::from_millis(100), None).await;
        assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn splice_ends_on_shutdown() {
        let (client, _client_peer) = tokio::io::duplex(64);
        let (upstream, _upstream_peer) = tokio::io::duplex(64);
        let (tx, rx) = broadcast::channel(1);
        let task = tokio::spawn(splice(
            client,
            upstream,
            Duration::from_secs(3600),
            Some(rx),
        ));
        tx.send(()).unwrap();
        assert!(task.await.unwrap().is_err());
    }
}

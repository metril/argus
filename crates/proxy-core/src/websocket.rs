//! WebSocket proxying.
//!
//! The client's upgrade request is forwarded upstream by the upstream client (over TLS for `wss`) and, when the origin
//! answers `101`, both upgraded streams are spliced byte-for-byte. Extensions and subprotocols
//! negotiated end to end therefore keep working, and the proxy never re-frames messages.

use crate::authority;
use crate::connection::IdleIo;
use crate::filtering::{refused_response, ProxyContext};
use crate::inject::{full_body, ProxyBody};
use crate::request_ctx::RequestCtx;
use crate::{Error, Result};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::{HeaderMap, HeaderName, HOST};
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::broadcast;
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

/// Lifecycle of upstream WebSocket upgrades: the handshake deadline, how long a spliced
/// connection may sit idle, and the proxy shutdown signal that ends it. The connection itself is
/// made by the upstream client (see [`crate::upstream::UpstreamRequest::send_upgrade`]).
pub struct WsUpstream {
    dial_timeout: Duration,
    /// Spliced connections close after this long without traffic.
    idle_timeout: std::sync::atomic::AtomicU64,
    /// Spliced connections end when the proxy shuts down.
    shutdown: Option<broadcast::Sender<()>>,
}

impl WsUpstream {
    pub fn new(dial_timeout: Duration) -> Self {
        Self {
            dial_timeout,
            idle_timeout: std::sync::atomic::AtomicU64::new(300_000),
            shutdown: None,
        }
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
    cancel: Option<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>>,
) -> std::io::Result<(u64, u64)>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let mut client = IdleIo::new(client, idle);
    let copy = tokio::io::copy_bidirectional(&mut client, &mut upstream);
    // `cancel` ends the splice when its owner is gone (an extension session that was closed or
    // revoked); `shutdown` when the proxy stops.
    let cancelled = async {
        match cancel {
            Some(c) => c.await,
            None => std::future::pending().await,
        }
    };
    let down = async {
        match shutdown {
            Some(mut rx) => {
                let _ = rx.recv().await;
            }
            None => std::future::pending().await,
        }
    };
    tokio::select! {
        r = copy => r,
        _ = down => Err(std::io::Error::other("proxy shutting down")),
        _ = cancelled => Err(std::io::Error::other("the extension session ended")),
    }
}

fn status_response(status: StatusCode, msg: &'static str) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .body(full_body(Bytes::from_static(msg.as_bytes())))
        .expect("static response")
}

/// Splice the downstream upgrade with the upstream stream `up` in a background task, ending on
/// idle, shutdown, or the end of the extension session the connection authenticated as.
fn spawn_splice<U>(
    ws: &WsUpstream,
    ctx: &ProxyContext,
    rctx: &RequestCtx,
    desc: String,
    client_upgrade: hyper::upgrade::OnUpgrade,
    up: impl std::future::Future<Output = std::result::Result<U, String>> + Send + 'static,
) where
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let idle = ws.idle_timeout();
    let shutdown = ws.shutdown.as_ref().map(|tx| tx.subscribe());
    // A splice on a connection that authenticated as an extension session ends with that session.
    let cancel: Option<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>> =
        rctx.ext.map(|session| {
            let hub = ctx.internal().gm.ext().clone();
            Box::pin(async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    if !hub.is_live(session) {
                        return;
                    }
                }
            }) as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        });
    tokio::spawn(async move {
        let (client, upstream) = tokio::join!(client_upgrade, up);
        match (client, upstream) {
            (Ok(client), Ok(upstream)) => {
                let client = TokioIo::new(client);
                match splice(client, upstream, idle, shutdown, cancel).await {
                    Ok((up, down)) => debug!("WebSocket {} closed (up {up}B, down {down}B)", desc),
                    Err(e) => debug!("WebSocket {} ended: {}", desc, e),
                }
            }
            (Err(e), _) => debug!("WebSocket upgrade failed for {}: {}", desc, e),
            (_, Err(e)) => debug!("WebSocket upstream upgrade failed for {}: {}", desc, e),
        }
    });
}

/// The handshake goes through the same wreq client as HTTP (emulation of the browser behind the
/// request when browser-like upstream is on, in-handshake certificate verification, the downstream
/// connection's pool group and device TLS sessions, the upstream proxy, and the destination
/// policy), as an HTTP/1.1 upgrade with the browser's headers untouched and in order. The two
/// upgraded streams are then spliced byte-for-byte, so `Sec-WebSocket-Extensions` (for example
/// permessage-deflate) negotiated by the origin is exactly what the browser was offered.
async fn upgrade(
    ws: &WsUpstream,
    ctx: &ProxyContext,
    rctx: &RequestCtx,
    mut req: Request<Incoming>,
    target: &Target,
    check_url: &str,
    client: crate::upstream::UpstreamClient,
) -> Result<Response<ProxyBody>> {
    // Literals are judged here; names are judged on what they resolve to, in the client's resolver.
    if let Err(why) = ctx.policy().check_literal(&target.host, target.port) {
        common::faults::note(common::faults::Fault::PolicyRefusal, &target.host);
        debug!("Refused WebSocket to {}: {}", check_url, why);
        return Ok(refused_response());
    }
    let scheme = if target.tls { "https" } else { "http" };
    let host = authority::url_host(&target.host);
    let authority_of = |h: &str| format!("{h}:{}", target.port);
    let mut dial_host = host.clone();
    let mut host_override = None;
    // Code-only resolve override: IP literals skip the resolver, so aim them at it explicitly.
    if let (Some(over), Ok(_)) = (ctx.resolve_all_to(), target.host.parse::<IpAddr>()) {
        dial_host = authority::url_host(&over.to_string());
        host_override = Some(authority_of(&host));
    }
    let url = format!(
        "{scheme}://{}{}",
        authority_of(&dial_host),
        target.path_and_query
    );
    let mut rb = client.request(Method::GET, url);
    if let Some(s) = rctx.upstream_scope() {
        rb = rb.scope(s);
    }
    if let Some(h) = host_override {
        rb = rb.header(HOST, h);
    }
    for (name, value) in req.headers() {
        if name == HeaderName::from_static("proxy-authorization")
            || name == HeaderName::from_static("proxy-connection")
            || name == HeaderName::from_static(crate::ext_bridge::RELAY_HEADER)
            || name == HOST
            || name == hyper::header::CONTENT_LENGTH
            || name == hyper::header::TRANSFER_ENCODING
        {
            continue;
        }
        rb = rb.header(name.clone(), value.clone());
    }
    let sent = match tokio::time::timeout(ws.dial_timeout, rb.send_upgrade()).await {
        Ok(r) => r,
        Err(_) => {
            return Ok(status_response(
                StatusCode::GATEWAY_TIMEOUT,
                "WebSocket upstream timeout",
            ))
        }
    };
    let (resp, upgraded) = match sent {
        Ok(r) => r,
        Err(e) if crate::policy::is_refusal(&e) => {
            common::faults::note(common::faults::Fault::PolicyRefusal, &target.host);
            debug!("Refused WebSocket to {} (resolved): {}", check_url, e);
            return Ok(refused_response());
        }
        Err(e) => {
            common::faults::note(common::faults::Fault::UpstreamError, &target.host);
            debug!("WebSocket upstream to {} failed: {}", check_url, e);
            return Ok(status_response(
                StatusCode::BAD_GATEWAY,
                "WebSocket upstream unavailable",
            ));
        }
    };
    let status = resp.status();
    let headers = resp.headers().clone();
    let Some(upgraded) = upgraded else {
        // The origin refused the upgrade: hand its answer back unchanged.
        let mut out = Response::builder().status(status);
        *out.headers_mut().expect("builder headers") = headers;
        let body = http_body_util::StreamBody::new(futures_util::TryStreamExt::map_ok(
            resp.bytes_stream(),
            hyper::body::Frame::data,
        ))
        .boxed_unsync();
        return out
            .body(body)
            .map_err(|e| Error::Http(format!("Bad upgrade response: {e}")));
    };
    spawn_splice(
        ws,
        ctx,
        rctx,
        check_url.to_string(),
        hyper::upgrade::on(&mut req),
        async move { Ok(upgraded) },
    );
    let mut out = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
    *out.headers_mut().expect("builder headers") = headers;
    out.body(full_body(Bytes::new()))
        .map_err(|e| Error::Http(format!("Bad upgrade response: {e}")))
}

/// Handle a WebSocket upgrade request: filter, upgrade upstream, forward the handshake, then splice.
///
/// `default_tls` is true for decrypted (MITM) traffic, whose origin-form URIs carry no scheme.
pub async fn proxy_upgrade(
    ws: &WsUpstream,
    ctx: &ProxyContext,
    rctx: &RequestCtx,
    req: Request<Incoming>,
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

    let client = ctx.ws_client(target.port);
    upgrade(ws, ctx, rctx, req, &target, &check_url, client).await
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
        let r = splice(client, upstream, Duration::from_millis(100), None, None).await;
        assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn splice_ends_when_its_extension_session_is_cancelled() {
        let (client, _client_peer) = tokio::io::duplex(64);
        let (upstream, _upstream_peer) = tokio::io::duplex(64);
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(splice(
            client,
            upstream,
            Duration::from_secs(3600),
            None,
            Some(Box::pin(async move {
                let _ = rx.await;
            })),
        ));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!task.is_finished(), "an idle healthy splice keeps running");
        tx.send(()).unwrap();
        let r = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("the splice ends")
            .unwrap();
        assert!(r.unwrap_err().to_string().contains("session ended"));
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
            None,
        ));
        tx.send(()).unwrap();
        assert!(task.await.unwrap().is_err());
    }
}

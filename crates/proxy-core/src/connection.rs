//! Connection handling.
//!
//! Two stages keep the entry mode separate from the interception logic:
//!
//! 1. **Entry** ([`ConnectionHandler::resolve_entry`] for explicit-proxy mode,
//!    [`crate::transparent::TransparentEntry`] for the transparent listener): works out what the
//!    client asked for and produces a [`ConnectionTarget`] plus the
//!    stream, with any bytes read past the request head replayed.
//! 2. **Serve** ([`ConnectionHandler::intercept_and_serve`]): given a target and a stream, either
//!    terminates TLS (MITM) and serves HTTP/1.1 or h2, or tunnels bytes. It does not care how the
//!    connection arrived.

use crate::authority;
use crate::filtering::ProxyContext;
use crate::inject::{full_body, ProxyBody};
use crate::mitm::MitmHandler;
use crate::request_ctx::ConnCtx;
use crate::{tls, Error, Result};
use bytes::Bytes;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, trace};

/// Maximum size of a CONNECT request head.
pub const MAX_HEAD_BYTES: usize = 16 * 1024;

/// Per-connection time limits, derived from `performance.*` config.
#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    /// Reading the initial request head, TLS handshake and upstream dials
    /// (`connection_timeout_secs`).
    pub handshake: Duration,
    /// HTTP/1 keep-alive: how long to wait for the next request's headers (`request_timeout_secs`).
    pub header_read: Duration,
    /// Opaque tunnels: close after this long with no bytes either way (5x `request_timeout_secs`).
    pub tunnel_idle: Duration,
}

impl Timeouts {
    pub fn from_config(perf: &crate::config::PerformanceSettings) -> Self {
        let handshake = Duration::from_secs(perf.connection_timeout_secs.max(1));
        let request = Duration::from_secs(perf.request_timeout_secs.max(1));
        Self {
            handshake,
            header_read: request,
            tunnel_idle: request * 5,
        }
    }
}

/// Everything a connection needs that is shared by all connections.
pub struct ConnectionShared {
    /// The CA-backed handler; set lazily when MITM is first enabled.
    pub mitm: arc_swap::ArcSwapOption<MitmHandler>,
    pub enable_http2: bool,
    pub enable_websockets: bool,
    /// Shared filtering + upstream-forwarding context (engine handle + pooled HTTP client).
    pub ctx: Arc<ProxyContext>,
    /// Live-swappable time limits (`performance.*`).
    pub timeouts: Arc<arc_swap::ArcSwap<Timeouts>>,
    #[cfg(feature = "websockets")]
    pub ws: arc_swap::ArcSwapOption<crate::websocket::WsUpstream>,
}

/// What the client asked for, independent of how the connection arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionTarget {
    pub host: String,
    pub port: u16,
    pub client_addr: SocketAddr,
    /// Terminate TLS and filter (true) or tunnel opaquely (false).
    pub intercept_tls: bool,
}

/// Where decrypted/plain HTTP requests are headed (origin-form URIs carry no host of their own).
#[derive(Clone)]
pub(crate) struct Origin {
    scheme: &'static str,
    authority: Option<(String, u16)>,
    /// Intercepted TLS: requests may only name the connection's host or a name its leaf
    /// certificate covers (answered with 421 otherwise).
    strict_host: bool,
}

impl Origin {
    /// Plain HTTP whose host comes from each request's `Host` header, falling back to `dst`.
    pub(crate) fn plain(dst: SocketAddr) -> Self {
        Self {
            scheme: "http",
            authority: Some((dst.ip().to_string(), dst.port())),
            strict_host: false,
        }
    }
}

/// Result of the explicit-proxy entry step.
pub enum Entry<IO> {
    /// A CONNECT target to intercept or tunnel.
    Target(ConnectionTarget, IO),
    /// Plain HTTP inside a SOCKS5 tunnel to `host:port` (extension listener).
    PlainTo(IO, String, u16),
    /// Plain proxy-style HTTP; the stream replays the bytes already read.
    PlainHttp(IO),
}

pub struct ConnectionHandler {
    pub(crate) client_addr: SocketAddr,
    pub(crate) shared: Arc<ConnectionShared>,
    /// Built once per connection; every request on it (plain, MITM h1/h2, WebSocket) shares it.
    conn: Arc<ConnCtx>,
}

impl ConnectionHandler {
    pub fn new(client_addr: SocketAddr, shared: Arc<ConnectionShared>) -> Self {
        let conn = Arc::new(ConnCtx::new(shared.ctx.profiles(), client_addr));
        Self {
            client_addr,
            shared,
            conn,
        }
    }

    /// Mark the connection as accepted on the extension-only listener: it must authenticate as a
    /// live extension session (`407` otherwise) and is bound to that session.
    pub fn on_ext_listener(self) -> Self {
        self.conn.mark_ext_listener();
        self
    }

    fn ext_hub(&self) -> &Arc<crate::ext_bridge::ExtHub> {
        self.shared.ctx.internal().gm.ext()
    }

    /// Resolves when the extension session this connection authenticated as is gone (never
    /// before it authenticated: that needs a request, and an unauthenticated connection gets a
    /// `407` and is closed).
    pub async fn ext_session_closed(&self) {
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if self
                .conn
                .ext_session()
                .is_some_and(|s| !self.ext_hub().is_live(s))
            {
                return;
            }
        }
    }

    /// Bind the connection to the session `sid` names (and the cookie store `store`).
    fn ext_bind(&self, sid: &str, store: &str) -> bool {
        let hub = self.ext_hub();
        let Some(session) = hub.authenticate(sid) else {
            return false;
        };
        self.conn.set_ext(
            self.shared.ctx.profiles(),
            session,
            store,
            hub.pinned_profile(session),
        );
        true
    }

    /// Authenticate `Proxy-Authorization` as an extension session and bind the connection.
    /// `false`: no valid credentials (the caller answers `407`).
    fn ext_authenticate(&self, auth: Option<&[u8]>) -> bool {
        if let Some(s) = self.conn.ext_session() {
            return self.ext_hub().is_live(s);
        }
        let Some((sid, store)) = auth.and_then(ext_creds_from_proxy_auth) else {
            return false;
        };
        let hub = self.ext_hub();
        let Some(session) = hub.authenticate(&sid) else {
            return false;
        };
        self.conn.set_ext(
            self.shared.ctx.profiles(),
            session,
            &store,
            hub.pinned_profile(session),
        );
        true
    }

    /// A handler for a connection accepted by the listener owning `flags`.
    pub fn with_listener(
        client_addr: SocketAddr,
        shared: Arc<ConnectionShared>,
        flags: Arc<crate::listener_flags::ListenerFlags>,
        transparent: bool,
    ) -> Self {
        let h = Self::new(client_addr, shared);
        h.conn.set_listener(Some(flags), transparent);
        h
    }

    /// Mark this connection as arriving on the transparent listener (request log mode).
    pub(crate) fn mark_transparent(&self) {
        self.conn.set_listener(self.conn.listener_flags(), true);
    }

    /// Whether TLS to a host should be intercepted: MITM is available and on for this
    /// listener, the host is not bypassed and the bypass fail-safe is not holding decryption
    /// back (an enabled first-party list has not loaded yet).
    pub(crate) fn intercepts(&self, host: &str) -> bool {
        let bypass = self.shared.ctx.bypass();
        self.shared.mitm.load().is_some()
            && self.conn.mitm_on()
            && !bypass.failsafe_active()
            && bypass.mode_of(host).is_none()
    }

    /// Whether a host-level rule of the connection's profile blocks `target` (recorded as a
    /// blocked event). Used for `no_decrypt` bypass, where only the host is visible.
    fn host_blocked(&self, target: &ConnectionTarget) -> bool {
        let rctx = self.conn.current(
            self.shared.ctx.profiles(),
            self.shared.ctx.require_device_token(),
        );
        let profile = rctx.profile.load();
        if !profile.engine.is_enabled() || !rctx.adblock_on() {
            return false;
        }
        let url = format!("https://{}/", target.host);
        let verdict = profile
            .engine
            .check_deferred_q(&filter_engine::Query::new(&url, "", "other"));
        if !verdict.blocked {
            return false;
        }
        profile.engine.record_verdict_meta(
            verdict,
            &url,
            "",
            "other",
            &profile.label,
            "CONNECT",
            if rctx.transparent {
                filter_engine::EventMode::Transparent
            } else {
                filter_engine::EventMode::Explicit
            },
        );
        true
    }

    /// Record a CONNECT-level event (opaque tunnel, failed handshake) in the request log.
    fn log_connection(
        &self,
        action: filter_engine::EventAction,
        target: &ConnectionTarget,
        source: Option<&str>,
        error_kind: Option<filter_engine::ErrorKind>,
    ) {
        // `full` bypass leaves no trace in the request log.
        if self.shared.ctx.bypass().mode_of(&target.host) == Some(common::bypass::BypassMode::Full)
        {
            return;
        }
        let rctx = self.conn.current(
            self.shared.ctx.profiles(),
            self.shared.ctx.require_device_token(),
        );
        let profile = rctx.profile.load();
        let bypass = self.shared.ctx.bypass();
        let source = source
            .map(str::to_string)
            .or_else(|| bypass.lookup(&target.host).map(|h| h.source))
            .or_else(|| bypass.failsafe_active().then(|| "failsafe".to_string()));
        let url = if target.port == 443 {
            format!("https://{}", target.host)
        } else {
            format!("{}:{}", target.host, target.port)
        };
        profile.engine.record_request(&filter_engine::EventRef {
            action,
            method: "CONNECT",
            url: &url,
            source_host: "",
            request_type: "tunnel",
            rule: source.as_deref().unwrap_or(""),
            list_id: None,
            client: Some(profile.label.as_ref()),
            status: None,
            error_kind,
            cert_fp: None,
            mode: if rctx.transparent {
                filter_engine::EventMode::Transparent
            } else {
                filter_engine::EventMode::Explicit
            },
        });
    }

    /// Handle an incoming connection
    pub async fn handle(&self, stream: TcpStream) -> Result<()> {
        trace!("Handling connection from {}", self.client_addr);
        let _ = stream.set_nodelay(true);
        match self.resolve_entry(stream).await? {
            Entry::Target(target, io) => self.intercept_and_serve(io, target).await,
            Entry::PlainHttp(io) => self.serve_http(io, plain_origin()).await,
            Entry::PlainTo(io, host, port) => {
                self.serve_http(
                    io,
                    Origin {
                        scheme: "http",
                        authority: Some((host, port)),
                        strict_host: false,
                    },
                )
                .await
            }
        }
    }

    /// Entry step for the explicit-proxy mode: decide between CONNECT and plain HTTP, read and
    /// parse the CONNECT head (across any number of TCP segments, bounded in size and time) and
    /// acknowledge it. Bytes past the head are preserved in the returned stream.
    pub async fn resolve_entry(&self, mut stream: TcpStream) -> Result<Entry<Prefixed<TcpStream>>> {
        let limit = self.shared.timeouts.load().handshake;
        let mut buf = Vec::with_capacity(1024);

        // (a SOCKS5 greeting is only three bytes; on the extension listener look at the first)
        let first = if self.conn.is_ext_listener() { 1 } else { 8 };
        match read_at_least(&mut stream, &mut buf, first, limit).await {
            Ok(()) => {}
            Err(HeadError::Closed) => {
                return Err(Error::Connection("closed before request".into()))
            }
            Err(e) => return Err(self.reject(&mut stream, e).await),
        }

        // The extension listener also speaks SOCKS5 (Firefox: one set of credentials per request,
        // which its shared HTTP proxy-credential cache cannot do).
        if self.conn.is_ext_listener() && buf[0] == 0x05 {
            return self.socks5_entry(stream, buf, limit).await;
        }
        if buf.len() < 8 {
            match read_at_least(&mut stream, &mut buf, 8, limit).await {
                Ok(()) => {}
                Err(HeadError::Closed) => {
                    return Err(Error::Connection("closed before request".into()))
                }
                Err(e) => return Err(self.reject(&mut stream, e).await),
            }
        }

        if !buf.starts_with(b"CONNECT ") {
            // Plain proxy request: its first request may carry the device token. (On the
            // extension listener it carries the session credentials, checked per request.)
            if !self.conn.is_ext_listener() {
                self.conn.await_token();
            }
            return Ok(Entry::PlainHttp(Prefixed::new(buf, stream)));
        }

        let head_len = match read_head(&mut stream, &mut buf, MAX_HEAD_BYTES, limit).await {
            Ok(n) => n,
            Err(e) => return Err(self.reject(&mut stream, e).await),
        };
        let (host, port) = match parse_connect(&buf[..head_len]) {
            Ok(t) => t,
            Err(e) => {
                let _ = stream
                    .write_all(b"HTTP/1.1 400 Bad Request\r\nconnection: close\r\ncontent-length: 0\r\n\r\n")
                    .await;
                return Err(e);
            }
        };
        // The extension listener: only a live session's credentials in the CONNECT head open
        // a tunnel; everything inside it is bound to that session.
        if self.conn.is_ext_listener() && !self.ext_authenticate(proxy_auth_value(&buf[..head_len]))
        {
            let _ = stream.write_all(EXT_AUTH_REQUIRED_RAW).await;
            return Err(Error::Connection(format!(
                "extension credentials required from {}",
                self.client_addr
            )));
        }
        // Device token: only the CONNECT head decides; nothing inside the tunnel can.
        let profiles = self.shared.ctx.profiles();
        let digest = proxy_auth_value(&buf[..head_len])
            .and_then(crate::profiles::digest_from_proxy_auth)
            .filter(|_| !self.conn.is_ext_listener());
        let known = digest.is_some_and(|d| ConnCtx::token_known(profiles, &d));
        if let Some(d) = digest {
            self.conn.set_token(profiles, d);
        }
        if self.shared.ctx.require_device_token() && !known && !self.conn.is_ext_listener() {
            let _ = stream.write_all(PROXY_AUTH_REQUIRED_RAW).await;
            return Err(Error::Connection(format!(
                "device token required from {}",
                self.client_addr
            )));
        }
        let leftover = buf.split_off(head_len);

        debug!("CONNECT {}:{} from {}", host, port, self.client_addr);
        let intercept_tls = self.intercepts(&host);

        // Destination policy, answered with a 403 before the tunnel is established. Intercepted
        // connections only need the literal check here (every request is checked again when it
        // is forwarded); opaque tunnels resolve now. The dial itself re-resolves and re-checks.
        let ctx = &self.shared.ctx;
        let refused = if intercept_tls {
            ctx.policy().check_literal(&host, port).is_err()
        } else {
            matches!(
                tokio::time::timeout(
                    limit,
                    ctx.policy().resolve(&host, port, ctx.resolve_all_to())
                )
                .await,
                Ok(Err(crate::policy::ResolveError::Refused(_)))
            )
        };
        if refused {
            common::faults::note(common::faults::Fault::PolicyRefusal, &host);
            debug!("Refused CONNECT to {host}:{port} from {}", self.client_addr);
            let _ = stream
                .write_all(
                    b"HTTP/1.1 403 Forbidden\r\nx-adblock: destination-refused\r\nconnection: close\r\ncontent-length: 19\r\n\r\nDestination refused",
                )
                .await;
            return Err(Error::DestinationRefused(format!("{host}:{port}")));
        }
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .map_err(|e| Error::Connection(format!("Failed to send 200 response: {}", e)))?;

        let target = ConnectionTarget {
            host,
            port,
            client_addr: self.client_addr,
            intercept_tls,
        };
        Ok(Entry::Target(target, Prefixed::new(leftover, stream)))
    }

    /// SOCKS5 (RFC 1928) with username/password (RFC 1929) on the extension listener: the user
    /// name is `ext`, the password `sid[:store]`. Only `CONNECT` is served; the requested
    /// `host:port` then goes through exactly the checks of an HTTP `CONNECT`.
    async fn socks5_entry(
        &self,
        mut stream: TcpStream,
        mut buf: Vec<u8>,
        limit: Duration,
    ) -> Result<Entry<Prefixed<TcpStream>>> {
        macro_rules! need {
            ($n:expr) => {
                if let Err(e) = read_at_least(&mut stream, &mut buf, $n, limit).await {
                    return Err(self.reject(&mut stream, e).await);
                }
            };
        }
        let fail =
            |what: &str| Error::Connection(format!("socks5 from {}: {what}", self.client_addr));
        // greeting
        need!(2);
        let n = buf[1] as usize;
        need!(2 + n);
        if !buf[2..2 + n].contains(&2) {
            let _ = stream.write_all(&[5, 0xff]).await;
            return Err(fail("no username/password method"));
        }
        buf.drain(..2 + n);
        stream.write_all(&[5, 2]).await?;
        // credentials
        need!(2);
        let ulen = buf[1] as usize;
        need!(3 + ulen);
        let plen = buf[2 + ulen] as usize;
        need!(3 + ulen + plen);
        let user = String::from_utf8_lossy(&buf[2..2 + ulen]).to_string();
        let pass = String::from_utf8_lossy(&buf[3 + ulen..3 + ulen + plen]).to_string();
        let version_ok = buf[0] == 1;
        buf.drain(..3 + ulen + plen);
        let (sid, store) = pass.split_once(':').unwrap_or((pass.as_str(), ""));
        let store_ok = store.len() <= 40 && store.bytes().all(|b| b.is_ascii_alphanumeric());
        if !(version_ok && user == "ext" && store_ok && self.ext_bind(sid, store)) {
            let _ = stream.write_all(&[1, 1]).await;
            return Err(fail("credentials refused"));
        }
        stream.write_all(&[1, 0]).await?;
        // request
        need!(5);
        let reply = |code: u8| [5, code, 0, 1, 0, 0, 0, 0, 0, 0];
        if buf[0] != 5 || buf[1] != 1 {
            let _ = stream.write_all(&reply(7)).await;
            return Err(fail("only CONNECT is served"));
        }
        let (host, used) = match buf[3] {
            1 => {
                need!(4 + 4 + 2);
                (
                    std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]).to_string(),
                    8,
                )
            }
            3 => {
                let l = buf[4] as usize;
                need!(5 + l + 2);
                (String::from_utf8_lossy(&buf[5..5 + l]).to_string(), 5 + l)
            }
            4 => {
                need!(4 + 16 + 2);
                let mut o = [0u8; 16];
                o.copy_from_slice(&buf[4..20]);
                (std::net::Ipv6Addr::from(o).to_string(), 20)
            }
            _ => {
                let _ = stream.write_all(&reply(8)).await;
                return Err(fail("unknown address type"));
            }
        };
        let port = u16::from_be_bytes([buf[used], buf[used + 1]]);
        let leftover = buf.split_off(used + 2);
        let host = authority::normalize_host(&host).unwrap_or(host);
        debug!("SOCKS5 CONNECT {host}:{port} from {}", self.client_addr);
        let intercept_tls = self.intercepts(&host);
        let ctx = &self.shared.ctx;
        let refused = if intercept_tls {
            ctx.policy().check_literal(&host, port).is_err()
        } else {
            matches!(
                tokio::time::timeout(
                    limit,
                    ctx.policy().resolve(&host, port, ctx.resolve_all_to())
                )
                .await,
                Ok(Err(crate::policy::ResolveError::Refused(_)))
            )
        };
        if refused {
            common::faults::note(common::faults::Fault::PolicyRefusal, &host);
            let _ = stream.write_all(&reply(2)).await;
            return Err(Error::DestinationRefused(format!("{host}:{port}")));
        }
        stream.write_all(&reply(0)).await?;
        let mut leftover = leftover;
        // What follows decides: a TLS ClientHello is intercepted (or tunnelled) like a CONNECT,
        // anything else is plain HTTP to this host.
        if leftover.is_empty() {
            let _ = read_at_least(&mut stream, &mut leftover, 1, limit).await;
        }
        if leftover.first() == Some(&0x16) || leftover.is_empty() {
            let target = ConnectionTarget {
                host,
                port,
                client_addr: self.client_addr,
                intercept_tls,
            };
            return Ok(Entry::Target(target, Prefixed::new(leftover, stream)));
        }
        Ok(Entry::PlainTo(Prefixed::new(leftover, stream), host, port))
    }

    /// Best-effort error reply for a failed head read; returns the error to propagate.
    async fn reject(&self, stream: &mut TcpStream, e: HeadError) -> Error {
        let (line, err) = match e {
            HeadError::TooLarge => (
                "HTTP/1.1 431 Request Header Fields Too Large",
                Error::Connection("request head too large".into()),
            ),
            HeadError::Timeout => ("HTTP/1.1 408 Request Timeout", Error::Timeout),
            HeadError::Closed => return Error::Connection("closed mid-request".into()),
            HeadError::Io(e) => return Error::Io(e),
        };
        let _ = stream
            .write_all(
                format!("{line}\r\nconnection: close\r\ncontent-length: 0\r\n\r\n").as_bytes(),
            )
            .await;
        err
    }

    /// Shared serve step: intercept TLS (MITM) or tunnel, for any entry mode.
    pub async fn intercept_and_serve<IO>(&self, io: IO, target: ConnectionTarget) -> Result<()>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mitm = match (self.shared.mitm.load_full(), target.intercept_tls) {
            (Some(m), true) => m,
            _ => return self.tunnel(io, &target).await,
        };
        // Extended Validation sites are tunnelled: an intercepting certificate would replace the
        // assurance the site paid for. The verdict is cached per host.
        let ctx = &self.shared.ctx;
        // (The reserved panel host is answered by the proxy itself and cannot be probed.)
        if ctx.bypass().ev_no_decrypt() && !ctx.is_panel_host(&target.host) {
            use crate::ev::EvVerdict;
            match ctx
                .ev_verdict(
                    &target.host,
                    target.port,
                    self.shared.timeouts.load().handshake,
                )
                .await
            {
                EvVerdict::Ev => return self.tunnel_with(io, &target, Some("ev")).await,
                // The probe could not tell: tunnel rather than risk decrypting an EV site.
                EvVerdict::Unknown => {
                    return self.tunnel_with(io, &target, Some("ev_unknown")).await
                }
                EvVerdict::NotEv => {}
            }
        }
        let cert = mitm.handle_connect(&target.host, target.port).await?;
        // A listener with HTTP/2 off must not offer h2 in ALPN: it gets the h1-only config.
        let acceptor = TlsAcceptor::from(if self.conn.http2_on() {
            cert.server_config.clone()
        } else {
            cert.server_config_h1.clone()
        });
        let tls_stream = tls::accept_tls(&acceptor, io, self.shared.timeouts.load().handshake)
            .await
            .inspect_err(|e| {
                debug!("TLS handshake failed for {}: {}", target.host, e);
                let kind = if matches!(e, Error::ClientRejectedCert(_)) {
                    filter_engine::ErrorKind::ClientRejectedCert
                } else {
                    filter_engine::ErrorKind::Other
                };
                self.log_connection(filter_engine::EventAction::Error, &target, None, Some(kind));
            })?;
        trace!("TLS handshake complete for {}", target.host);

        let use_http2 = self.conn.http2_on()
            && tls_stream
                .get_ref()
                .1
                .alpn_protocol()
                .is_some_and(crate::http2::is_http2_protocol);
        let origin = Origin {
            scheme: "https",
            authority: Some((target.host.clone(), target.port)),
            strict_host: true,
        };

        if use_http2 {
            let shared = self.shared.clone();
            let conn = self.conn.clone();
            let service = move |req| {
                let shared = shared.clone();
                let conn = conn.clone();
                let origin = origin.clone();
                async move { handle_request(shared, conn, req, origin).await }
            };
            crate::http2::serve_http2(tls_stream, service).await
        } else {
            self.serve_http(tls_stream, origin).await
        }
    }

    /// Serve HTTP/1.1 (with upgrade support) over `io`.
    pub(crate) async fn serve_http<IO>(&self, io: IO, origin: Origin) -> Result<()>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let shared = self.shared.clone();
        let client_addr = self.client_addr;
        let conn = self.conn.clone();
        let service = service_fn(move |req| {
            let shared = shared.clone();
            let conn = conn.clone();
            let origin = origin.clone();
            async move { handle_request(shared, conn, req, origin).await }
        });

        http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(self.shared.timeouts.load().header_read)
            .serve_connection(TokioIo::new(io), service)
            .with_upgrades()
            .await
            .map_err(|err| {
                debug!("HTTP/1 connection error from {}: {}", client_addr, err);
                Error::Connection(format!("Connection error: {}", err))
            })
    }

    /// Opaque tunnel (no interception) to the target.
    async fn tunnel<IO>(&self, client: IO, target: &ConnectionTarget) -> Result<()>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.tunnel_with(client, target, None).await
    }

    /// [`Self::tunnel`], with `source` (why it is a tunnel, e.g. `ev`) recorded on its events.
    async fn tunnel_with<IO>(
        &self,
        client: IO,
        target: &ConnectionTarget,
        source: Option<&str>,
    ) -> Result<()>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let t = **self.shared.timeouts.load();
        let bypass = self.shared.ctx.bypass();
        match bypass.mode_of(&target.host) {
            Some(common::bypass::BypassMode::Full) => bypass.note_bypassed(),
            // No interception, but a host the engine blocks stays blocked.
            Some(common::bypass::BypassMode::NoDecrypt) if self.host_blocked(target) => {
                return Err(Error::Connection(format!(
                    "{} is blocked (host-level rule)",
                    target.host
                )));
            }
            // Fail-safe: everything is tunnelled, so hostname (SNI) blocking is all that is left.
            None if bypass.failsafe_active() && self.host_blocked(target) => {
                return Err(Error::Connection(format!(
                    "{} is blocked (host-level rule)",
                    target.host
                )));
            }
            _ => {}
        }
        // Resolve once, check the policy on the resolved address and connect to exactly that
        // address (DNS rebinding cannot swap it afterwards).
        let ctx = &self.shared.ctx;
        let dial = async {
            let addr = ctx
                .policy()
                .resolve(&target.host, target.port, ctx.resolve_all_to())
                .await?;
            TcpStream::connect(addr).await.map_err(Error::from)
        };
        let mut server = match tokio::time::timeout(t.handshake, dial).await {
            Ok(Ok(s)) => s,
            Ok(Err(e @ Error::DestinationRefused(_))) => {
                common::faults::note(common::faults::Fault::PolicyRefusal, &target.host);
                self.log_connection(filter_engine::EventAction::Blocked, target, source, None);
                debug!("Refused tunnel to {}:{}: {e}", target.host, target.port);
                return Err(e);
            }
            Ok(Err(e)) => {
                let kind = match &e {
                    Error::Io(io) => crate::upstream::classify_io(io),
                    _ => filter_engine::ErrorKind::Other,
                };
                self.log_connection(
                    filter_engine::EventAction::Error,
                    target,
                    source,
                    Some(kind),
                );
                return Err(Error::Connection(format!(
                    "Failed to connect to {}:{}: {}",
                    target.host, target.port, e
                )));
            }
            Err(_) => {
                self.log_connection(
                    filter_engine::EventAction::Error,
                    target,
                    source,
                    Some(filter_engine::ErrorKind::UpstreamTimeout),
                );
                return Err(Error::Timeout);
            }
        };
        let _ = server.set_nodelay(true);
        self.log_connection(
            filter_engine::EventAction::Passthrough,
            target,
            source,
            None,
        );
        let mut client = IdleIo::new(client, t.tunnel_idle);
        match tokio::io::copy_bidirectional(&mut client, &mut server).await {
            Ok((up, down)) => {
                debug!(
                    "Tunnel {}:{} closed (up {up}B, down {down}B)",
                    target.host, target.port
                );
                Ok(())
            }
            Err(e) => Err(Error::Connection(format!("Tunnel error: {}", e))),
        }
    }
}

const EXT_AUTH_REQUIRED_RAW: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\nproxy-authenticate: Basic realm=\"argus-ext\"\r\nconnection: close\r\ncontent-length: 0\r\n\r\n";

fn ext_auth_required() -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header("proxy-authenticate", "Basic realm=\"argus-ext\"")
        .header("connection", "close")
        .body(full_body(Bytes::new()))
        .expect("static response")
}

/// `(sid, store token)` of `Proxy-Authorization: Basic base64("ext:" + sid [+ ":" + store])`. The
/// store token is opaque (a Firefox container or private window; empty for the default store).
fn ext_creds_from_proxy_auth(value: &[u8]) -> Option<(String, String)> {
    use base64::Engine as _;
    let v = value.trim_ascii();
    let rest = v
        .get(..6)
        .filter(|p| p.eq_ignore_ascii_case(b"basic "))
        .map(|_| v[6..].trim_ascii())?;
    if rest.len() > 128 {
        return None;
    }
    let mut buf = [0u8; 96];
    let n = base64::engine::general_purpose::STANDARD
        .decode_slice(rest, &mut buf)
        .ok()?;
    let creds = std::str::from_utf8(&buf[..n]).ok()?;
    let rest = creds.strip_prefix("ext:")?;
    let (sid, store) = rest.split_once(':').unwrap_or((rest, ""));
    (store.len() <= 40 && store.bytes().all(|b| b.is_ascii_alphanumeric()))
        .then(|| (sid.to_string(), store.to_string()))
}

const PROXY_AUTH_REQUIRED_RAW: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\nproxy-authenticate: Basic realm=\"argus\"\r\nconnection: close\r\ncontent-length: 0\r\n\r\n";

fn proxy_auth_required() -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header("proxy-authenticate", "Basic realm=\"argus\"")
        .header("connection", "close")
        .body(full_body(Bytes::new()))
        .expect("static response")
}

/// Value of the `Proxy-Authorization` header in a raw request head.
fn proxy_auth_value(head: &[u8]) -> Option<&[u8]> {
    head.split(|&b| b == b'\n').skip(1).find_map(|line| {
        let line = line.trim_ascii_end();
        let (name, value) = line.split_at(line.iter().position(|&b| b == b':')?);
        name.trim_ascii()
            .eq_ignore_ascii_case(b"proxy-authorization")
            .then(|| value[1..].trim_ascii())
    })
}

fn plain_origin() -> Origin {
    Origin {
        scheme: "http",
        authority: None,
        strict_host: false,
    }
}

/// Handle a single HTTP request (plain proxying or decrypted MITM traffic).
async fn handle_request(
    shared: Arc<ConnectionShared>,
    conn: Arc<ConnCtx>,
    mut req: Request<Incoming>,
    origin: Origin,
) -> Result<Response<ProxyBody>> {
    let profiles = shared.ctx.profiles();
    let require = shared.ctx.require_device_token() && !conn.is_ext_listener();
    // The extension listener: the connection must be (or become, with this request's
    // credentials) bound to a live extension session. Nothing else is served.
    if conn.is_ext_listener() {
        let hub = shared.ctx.internal().gm.ext();
        let ok = match conn.ext_session() {
            Some(s) => hub.is_live(s),
            None => req
                .headers()
                .get(hyper::header::PROXY_AUTHORIZATION)
                .and_then(|v| ext_creds_from_proxy_auth(v.as_bytes()))
                .and_then(|(sid, store)| hub.authenticate(&sid).map(|s| (s, store)))
                .map(|(s, store)| conn.set_ext(profiles, s, &store, hub.pinned_profile(s)))
                .is_some(),
        };
        if !ok {
            return Ok(ext_auth_required());
        }
    }
    // Plain proxy connections: the first request's `Proxy-Authorization` picks the device. It is
    // never read again, and never on a decrypted (tunnelled) connection.
    if conn.take_awaiting() {
        let digest = req
            .headers()
            .get(hyper::header::PROXY_AUTHORIZATION)
            .and_then(|v| crate::profiles::digest_from_proxy_auth(v.as_bytes()));
        if let Some(d) = digest {
            conn.set_token(profiles, d);
        }
        if require && !digest.is_some_and(|d| ConnCtx::token_known(profiles, &d)) {
            conn.await_token();
            return Ok(proxy_auth_required());
        }
    }
    // Never forwarded upstream.
    req.headers_mut().remove(hyper::header::PROXY_AUTHORIZATION);
    let rctx = conn.current(profiles, require);
    if let Some(l) = &rctx.listener {
        l.note_request();
    }
    if conn.is_revoked() {
        return Ok(proxy_auth_required());
    }
    trace!(
        "Request from {}: {} {} {:?}",
        rctx.client_addr,
        req.method(),
        req.uri(),
        req.version()
    );

    // An intercepted connection serves its own host and the names its certificate covers (what
    // browsers coalesce onto one h2 connection); anything else must use a fresh connection.
    if origin.strict_host {
        if let Some((cert_host, _)) = &origin.authority {
            let names = authority::named_hosts(req.uri(), req.headers());
            let covered = names
                .iter()
                .all(|h| authority::covered_by_cert(cert_host, h));
            // A bypassed host must never be served over this decrypted connection, even when
            // the certificate happens to cover it: the browser has to open its own (tunnelled)
            // connection for it.
            let bypassed_other = names.iter().any(|h| {
                !h.eq_ignore_ascii_case(cert_host) && shared.ctx.bypass().mode_of(h).is_some()
            });
            if !covered || bypassed_other {
                debug!(
                    "421 for {:?} on connection to {cert_host} from {}",
                    req.uri().authority(),
                    rctx.client_addr
                );
                return Ok(Response::builder()
                    .status(StatusCode::MISDIRECTED_REQUEST)
                    .body(full_body(Bytes::from_static(b"Misdirected Request")))
                    .expect("static response"));
            }
        }
    }

    #[cfg(feature = "websockets")]
    if rctx
        .listener
        .as_ref()
        .map_or(shared.enable_websockets, |l| l.websockets())
        && crate::websocket::is_websocket_upgrade(req.headers())
    {
        if let Some(ws) = shared.ws.load_full() {
            return crate::websocket::proxy_upgrade(
                &ws,
                &shared.ctx,
                &rctx,
                req,
                origin.scheme == "https",
                origin.authority,
            )
            .await;
        }
    }

    if req.method() == Method::CONNECT {
        debug!("CONNECT reached the HTTP handler from {}", rctx.client_addr);
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(full_body(Bytes::from_static(b"CONNECT not allowed here")))
            .expect("static response"));
    }

    shared
        .ctx
        .forward_with(req, origin.scheme, origin.authority, &rctx)
        .await
}

// ---------------------------------------------------------------------------------------------
// Request head reading and CONNECT parsing
// ---------------------------------------------------------------------------------------------

#[derive(Debug)]
pub enum HeadError {
    TooLarge,
    Timeout,
    Closed,
    Io(std::io::Error),
}

/// Read until `buf` holds at least `n` bytes (bounded by `timeout`).
pub(crate) async fn read_at_least<R: AsyncRead + Unpin>(
    io: &mut R,
    buf: &mut Vec<u8>,
    n: usize,
    timeout: Duration,
) -> std::result::Result<(), HeadError> {
    let fut = async {
        while buf.len() < n {
            if io.read_buf(buf).await.map_err(HeadError::Io)? == 0 {
                return Err(HeadError::Closed);
            }
        }
        Ok(())
    };
    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| HeadError::Timeout)?
}

/// Read until the header terminator (`\r\n\r\n`) is in `buf`, returning the head length (the
/// terminator included). Bytes read past the head stay in `buf`. The size limit and the single
/// overall deadline defend against oversized and slow-drip heads.
pub async fn read_head<R: AsyncRead + Unpin>(
    io: &mut R,
    buf: &mut Vec<u8>,
    max: usize,
    timeout: Duration,
) -> std::result::Result<usize, HeadError> {
    let fut = async {
        let mut scanned = 0usize;
        loop {
            if let Some(pos) = find_head_end(buf, scanned) {
                return Ok(pos + 4);
            }
            scanned = buf.len().saturating_sub(3);
            if buf.len() > max {
                return Err(HeadError::TooLarge);
            }
            if io.read_buf(buf).await.map_err(HeadError::Io)? == 0 {
                return Err(HeadError::Closed);
            }
        }
    };
    let n = tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| HeadError::Timeout)??;
    if n > max {
        return Err(HeadError::TooLarge);
    }
    Ok(n)
}

fn find_head_end(buf: &[u8], from: usize) -> Option<usize> {
    buf.get(from..)?
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + from)
}

/// Parse `CONNECT host:port HTTP/1.x` (IPv6 literals must be bracketed). Missing port means 443.
pub fn parse_connect(head: &[u8]) -> Result<(String, u16)> {
    let invalid = |what: &str| Error::Connection(format!("Invalid CONNECT request: {what}"));
    let text = std::str::from_utf8(head).map_err(|_| invalid("not UTF-8"))?;
    let line = text.lines().next().unwrap_or("");
    let mut parts = line.split_whitespace();
    if parts.next() != Some("CONNECT") {
        return Err(invalid("method"));
    }
    let target = parts.next().ok_or_else(|| invalid("missing target"))?;
    if !parts.next().is_some_and(|v| v.starts_with("HTTP/1.")) {
        return Err(invalid("version"));
    }

    let (host, port) = if let Some(rest) = target.strip_prefix('[') {
        let (h, after) = rest.split_once(']').ok_or_else(|| invalid("bracket"))?;
        match after {
            "" => (h, None),
            a => (
                h,
                Some(a.strip_prefix(':').ok_or_else(|| invalid("target"))?),
            ),
        }
    } else {
        match target.matches(':').count() {
            0 => (target, None),
            1 => {
                let (h, p) = target.split_once(':').unwrap();
                (h, Some(p))
            }
            _ => return Err(invalid("unbracketed IPv6")),
        }
    };
    if host.is_empty() {
        return Err(invalid("empty host"));
    }
    let port = match port {
        None => 443,
        Some(p) => match p.parse::<u16>() {
            Ok(p) if p != 0 => p,
            _ => return Err(invalid("port")),
        },
    };
    let host = authority::normalize_host(host).ok_or_else(|| invalid("host"))?;
    Ok((host, port))
}

// ---------------------------------------------------------------------------------------------
// IO adapters
// ---------------------------------------------------------------------------------------------

pub use io::{IdleIo, Prefixed};

mod io {
    use bytes::{Buf, Bytes};
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{ready, Context, Poll};
    use std::time::Duration;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio::time::{Instant, Sleep};

    /// A stream that first replays bytes already read from it.
    pub struct Prefixed<IO> {
        prefix: Bytes,
        inner: IO,
    }

    impl<IO> Prefixed<IO> {
        pub fn new(prefix: impl Into<Bytes>, inner: IO) -> Self {
            Self {
                prefix: prefix.into(),
                inner,
            }
        }
    }

    impl<IO: AsyncRead + Unpin> AsyncRead for Prefixed<IO> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if !self.prefix.is_empty() {
                let n = self.prefix.len().min(buf.remaining());
                buf.put_slice(&self.prefix[..n]);
                self.prefix.advance(n);
                return Poll::Ready(Ok(()));
            }
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl<IO: AsyncWrite + Unpin> AsyncWrite for Prefixed<IO> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }
        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// Fails reads/writes with `TimedOut` once no I/O has completed for `idle`.
    pub struct IdleIo<IO> {
        inner: IO,
        sleep: Pin<Box<Sleep>>,
        idle: Duration,
    }

    impl<IO> IdleIo<IO> {
        pub fn new(inner: IO, idle: Duration) -> Self {
            Self {
                inner,
                sleep: Box::pin(tokio::time::sleep(idle)),
                idle,
            }
        }

        fn touch(&mut self) {
            self.sleep.as_mut().reset(Instant::now() + self.idle);
        }

        fn check(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Error> {
            ready!(self.sleep.as_mut().poll(cx));
            Poll::Ready(std::io::ErrorKind::TimedOut.into())
        }
    }

    impl<IO: AsyncRead + Unpin> AsyncRead for IdleIo<IO> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            match Pin::new(&mut self.inner).poll_read(cx, buf) {
                Poll::Ready(r) => {
                    self.touch();
                    Poll::Ready(r)
                }
                Poll::Pending => self.check(cx).map(Err),
            }
        }
    }

    impl<IO: AsyncWrite + Unpin> AsyncWrite for IdleIo<IO> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            match Pin::new(&mut self.inner).poll_write(cx, buf) {
                Poll::Ready(r) => {
                    self.touch();
                    Poll::Ready(r)
                }
                Poll::Pending => self.check(cx).map(Err),
            }
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }
        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::ReadBuf;

    /// Yields at most `chunk` bytes per read, then EOF (or pends forever if `stall`).
    struct Chunked {
        data: Vec<u8>,
        pos: usize,
        chunk: usize,
        stall: bool,
    }

    impl AsyncRead for Chunked {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.pos >= self.data.len() {
                return if self.stall {
                    Poll::Pending
                } else {
                    Poll::Ready(Ok(()))
                };
            }
            let n = self
                .chunk
                .min(buf.remaining())
                .min(self.data.len() - self.pos);
            let start = self.pos;
            buf.put_slice(&self.data[start..start + n]);
            self.pos += n;
            Poll::Ready(Ok(()))
        }
    }

    fn chunked(data: &[u8], chunk: usize, stall: bool) -> Chunked {
        Chunked {
            data: data.to_vec(),
            pos: 0,
            chunk,
            stall,
        }
    }

    const T: Duration = Duration::from_secs(5);

    #[tokio::test]
    async fn split_connect_head_is_assembled_and_leftover_kept() {
        let raw =
            b"CONNECT example.com:8443 HTTP/1.1\r\nHost: example.com:8443\r\n\r\n\x16\x03\x01hello";
        for chunk in [1, 3, 7, 64] {
            let mut r = chunked(raw, chunk, true);
            let mut buf = Vec::new();
            read_at_least(&mut r, &mut buf, 8, T).await.unwrap();
            assert!(buf.starts_with(b"CONNECT "));
            let n = read_head(&mut r, &mut buf, MAX_HEAD_BYTES, T)
                .await
                .unwrap();
            assert_eq!(
                parse_connect(&buf[..n]).unwrap(),
                ("example.com".to_string(), 8443),
                "chunk {chunk}"
            );
            // Anything past the head must survive for the TLS handshake.
            let head_end = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
            assert_eq!(n, head_end);
            assert!(raw[head_end..].starts_with(&buf[n..]));
        }
    }

    #[tokio::test]
    async fn oversize_head_is_rejected() {
        let mut raw = b"CONNECT a.b:443 HTTP/1.1\r\nX: ".to_vec();
        raw.extend(std::iter::repeat_n(b'a', MAX_HEAD_BYTES * 2));
        let mut r = chunked(&raw, 4096, true);
        let mut buf = Vec::new();
        let err = read_head(&mut r, &mut buf, MAX_HEAD_BYTES, T)
            .await
            .unwrap_err();
        assert!(matches!(err, HeadError::TooLarge), "{err:?}");
    }

    #[tokio::test]
    async fn slow_head_times_out() {
        let mut r = chunked(b"CONNECT a.b:443 HTTP/1.1\r\n", 5, true);
        let mut buf = Vec::new();
        let err = read_head(&mut r, &mut buf, MAX_HEAD_BYTES, Duration::from_millis(50))
            .await
            .unwrap_err();
        assert!(matches!(err, HeadError::Timeout), "{err:?}");
    }

    #[tokio::test]
    async fn closed_mid_head_is_reported() {
        let mut r = chunked(b"CONNECT a.b:443 HT", 4, false);
        let mut buf = Vec::new();
        let err = read_head(&mut r, &mut buf, MAX_HEAD_BYTES, T)
            .await
            .unwrap_err();
        assert!(matches!(err, HeadError::Closed), "{err:?}");
    }

    #[test]
    fn parse_connect_targets() {
        let p = |t: &str| parse_connect(format!("CONNECT {t} HTTP/1.1\r\n\r\n").as_bytes());
        assert_eq!(p("a.com:443").unwrap(), ("a.com".into(), 443));
        assert_eq!(p("a.com").unwrap(), ("a.com".into(), 443));
        assert_eq!(p("10.0.0.1:8443").unwrap(), ("10.0.0.1".into(), 8443));
        assert_eq!(p("[::1]:9000").unwrap(), ("::1".into(), 9000));
        assert_eq!(p("[::1]").unwrap(), ("::1".into(), 443));
        assert!(p("::1:443").is_err());
        assert!(p("a.com:notaport").is_err());
        assert!(p("a.com:0").is_err());
        assert!(p(":443").is_err());
        assert!(parse_connect(b"GET / HTTP/1.1\r\n\r\n").is_err());
        assert!(parse_connect(b"CONNECT a.com:443\r\n\r\n").is_err());
    }

    #[tokio::test]
    async fn prefixed_replays_then_reads_inner() {
        use tokio::io::AsyncReadExt;
        let mut p = Prefixed::new(b"abc".to_vec(), chunked(b"def", 2, false));
        let mut out = Vec::new();
        p.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"abcdef");
    }

    #[test]
    fn connection_ctx_carries_real_client_addr_and_default_profile() {
        let engine = Arc::new(filter_engine::SharedEngine::new());
        let ctx = Arc::new(ProxyContext::new(engine, reqwest::Client::new(), true));
        let shared = Arc::new(ConnectionShared {
            mitm: Default::default(),
            enable_http2: false,
            enable_websockets: false,
            ctx: ctx.clone(),
            timeouts: Arc::new(arc_swap::ArcSwap::from_pointee(Timeouts::from_config(
                &crate::config::ProxyConfig::default().performance,
            ))),
            #[cfg(feature = "websockets")]
            ws: Default::default(),
        });
        let addr: SocketAddr = "203.0.113.7:4242".parse().unwrap();
        let h = ConnectionHandler::new(addr, shared);
        let rctx = h.conn.current(ctx.profiles(), false);
        assert_eq!(rctx.client_addr, addr);
        assert!(rctx.auth_user.is_none());
        assert!(Arc::ptr_eq(&rctx.profile, ctx.default_profile()));
    }

    /// A header inside a tunnelled / transparent connection can never switch the profile.
    #[tokio::test]
    async fn header_on_a_tunnelled_connection_cannot_switch_profile() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let engine = Arc::new(filter_engine::SharedEngine::new());
        engine.install(filter_engine::compile_engine(&["/ads/\n".to_string()]));
        let ctx = Arc::new(ProxyContext::new(engine, reqwest::Client::new(), true));
        // Token "tok" maps to a profile that blocks nothing; the default (by address) blocks /ads/.
        let open = Arc::new(filter_engine::SharedEngine::new());
        let slot = Arc::new(filter_engine::ArcSwap::from_pointee(crate::Profile::new(
            1, 0, open,
        )));
        ctx.profiles().publish(
            crate::ProfileTable::builder(ctx.default_profile().clone())
                .profile(1, slot)
                .token(crate::token_digest(b"tok"), 1)
                .build(),
        );
        let shared = Arc::new(ConnectionShared {
            mitm: Default::default(),
            enable_http2: false,
            enable_websockets: false,
            ctx,
            timeouts: Arc::new(arc_swap::ArcSwap::from_pointee(Timeouts::from_config(
                &crate::config::ProxyConfig::default().performance,
            ))),
            #[cfg(feature = "websockets")]
            ws: Default::default(),
        });
        let h = ConnectionHandler::new("203.0.113.7:4242".parse().unwrap(), shared);
        let (mut client, server) = tokio::io::duplex(8192);
        let origin = Origin::plain("127.0.0.1:9".parse().unwrap());
        let serve = tokio::spawn(async move { h.serve_http(server, origin).await });
        let auth = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "u:tok");
        let req = format!(
            "GET /ads/x HTTP/1.1\r\nHost: example.test\r\nProxy-Authorization: Basic {auth}\r\nConnection: close\r\n\r\n"
        );
        client.write_all(req.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        let _ = serve.await;
        let head = String::from_utf8_lossy(&out);
        // Blocked by the default profile (no upstream dial): the token in the header was ignored.
        assert!(head.starts_with("HTTP/1.1 "), "{head}");
        assert!(!head.starts_with("HTTP/1.1 502"), "went upstream: {head}");
    }
}

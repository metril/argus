//! Connection handling.
//!
//! Two stages keep the entry mode separate from the interception logic:
//!
//! 1. **Entry** ([`ConnectionHandler::resolve_entry`]): works out what the client asked for
//!    (CONNECT today; a transparent listener later) and produces a [`ConnectionTarget`] plus the
//!    stream, with any bytes read past the request head replayed.
//! 2. **Serve** ([`ConnectionHandler::intercept_and_serve`]): given a target and a stream, either
//!    terminates TLS (MITM) and serves HTTP/1.1 or h2, or tunnels bytes. It does not care how the
//!    connection arrived.

use crate::filtering::ProxyContext;
use crate::inject::{full_body, ProxyBody};
use crate::mitm::MitmHandler;
use crate::request_ctx::RequestCtx;
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
use tracing::{debug, trace, warn};

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
    pub mitm: Option<Arc<MitmHandler>>,
    pub enable_http2: bool,
    pub enable_websockets: bool,
    /// Shared filtering + upstream-forwarding context (engine handle + pooled HTTP client).
    pub ctx: Arc<ProxyContext>,
    pub timeouts: Timeouts,
    #[cfg(feature = "websockets")]
    pub ws: Option<Arc<crate::websocket::WsUpstream>>,
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
struct Origin {
    scheme: &'static str,
    authority: Option<(String, u16)>,
}

/// Result of the entry step.
pub enum Entry<IO> {
    /// A CONNECT (or, later, transparent) target to intercept or tunnel.
    Target(ConnectionTarget, IO),
    /// Plain proxy-style HTTP; the stream replays the bytes already read.
    PlainHttp(IO),
}

pub struct ConnectionHandler {
    client_addr: SocketAddr,
    shared: Arc<ConnectionShared>,
    /// Built once per connection; every request on it (plain, MITM h1/h2, WebSocket) shares it.
    rctx: Arc<RequestCtx>,
}

impl ConnectionHandler {
    pub fn new(client_addr: SocketAddr, shared: Arc<ConnectionShared>) -> Self {
        let rctx = Arc::new(shared.ctx.request_ctx_for(client_addr, None));
        Self {
            client_addr,
            shared,
            rctx,
        }
    }

    /// Handle an incoming connection
    pub async fn handle(&self, stream: TcpStream) -> Result<()> {
        trace!("Handling connection from {}", self.client_addr);
        let _ = stream.set_nodelay(true);
        match self.resolve_entry(stream).await? {
            Entry::Target(target, io) => self.intercept_and_serve(io, target).await,
            Entry::PlainHttp(io) => self.serve_http(io, plain_origin()).await,
        }
    }

    /// Entry step for the explicit-proxy mode: decide between CONNECT and plain HTTP, read and
    /// parse the CONNECT head (across any number of TCP segments, bounded in size and time) and
    /// acknowledge it. Bytes past the head are preserved in the returned stream.
    pub async fn resolve_entry(&self, mut stream: TcpStream) -> Result<Entry<Prefixed<TcpStream>>> {
        let limit = self.shared.timeouts.handshake;
        let mut buf = Vec::with_capacity(1024);

        match read_at_least(&mut stream, &mut buf, 8, limit).await {
            Ok(()) => {}
            Err(HeadError::Closed) => {
                return Err(Error::Connection("closed before request".into()))
            }
            Err(e) => return Err(self.reject(&mut stream, e).await),
        }

        if !buf.starts_with(b"CONNECT ") {
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
        let leftover = buf.split_off(head_len);

        debug!("CONNECT {}:{} from {}", host, port, self.client_addr);
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .map_err(|e| Error::Connection(format!("Failed to send 200 response: {}", e)))?;

        let target = ConnectionTarget {
            host,
            port,
            client_addr: self.client_addr,
            intercept_tls: self.shared.mitm.is_some(),
        };
        Ok(Entry::Target(target, Prefixed::new(leftover, stream)))
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
        let mitm = match (&self.shared.mitm, target.intercept_tls) {
            (Some(m), true) => m,
            _ => return self.tunnel(io, &target).await,
        };

        let cert = mitm.handle_connect(&target.host, target.port).await?;
        let acceptor = TlsAcceptor::from(cert.server_config.clone());
        let tls_stream = tls::accept_tls(&acceptor, io, self.shared.timeouts.handshake)
            .await
            .inspect_err(|e| debug!("TLS handshake failed for {}: {}", target.host, e))?;
        trace!("TLS handshake complete for {}", target.host);

        let use_http2 = tls_stream
            .get_ref()
            .1
            .alpn_protocol()
            .is_some_and(crate::http2::is_http2_protocol);
        let origin = Origin {
            scheme: "https",
            authority: Some((target.host.clone(), target.port)),
        };

        if use_http2 {
            let shared = self.shared.clone();
            let rctx = self.rctx.clone();
            let service = move |req| {
                let shared = shared.clone();
                let rctx = rctx.clone();
                let origin = origin.clone();
                async move { handle_request(shared, rctx, req, origin).await }
            };
            crate::http2::serve_http2(tls_stream, service).await
        } else {
            self.serve_http(tls_stream, origin).await
        }
    }

    /// Serve HTTP/1.1 (with upgrade support) over `io`.
    async fn serve_http<IO>(&self, io: IO, origin: Origin) -> Result<()>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let shared = self.shared.clone();
        let client_addr = self.client_addr;
        let rctx = self.rctx.clone();
        let service = service_fn(move |req| {
            let shared = shared.clone();
            let rctx = rctx.clone();
            let origin = origin.clone();
            async move { handle_request(shared, rctx, req, origin).await }
        });

        http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(self.shared.timeouts.header_read)
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
        let t = &self.shared.timeouts;
        let addr = (target.host.as_str(), target.port);
        let mut server = match tokio::time::timeout(t.handshake, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                return Err(Error::Connection(format!(
                    "Failed to connect to {}:{}: {}",
                    target.host, target.port, e
                )))
            }
            Err(_) => return Err(Error::Timeout),
        };
        let _ = server.set_nodelay(true);
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

fn plain_origin() -> Origin {
    Origin {
        scheme: "http",
        authority: None,
    }
}

/// Handle a single HTTP request (plain proxying or decrypted MITM traffic).
async fn handle_request(
    shared: Arc<ConnectionShared>,
    rctx: Arc<RequestCtx>,
    req: Request<Incoming>,
    origin: Origin,
) -> Result<Response<ProxyBody>> {
    trace!(
        "Request from {}: {} {} {:?}",
        rctx.client_addr,
        req.method(),
        req.uri(),
        req.version()
    );

    #[cfg(feature = "websockets")]
    if shared.enable_websockets && crate::websocket::is_websocket_upgrade(req.headers()) {
        if let Some(ws) = &shared.ws {
            return crate::websocket::proxy_upgrade(
                ws,
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
        warn!("CONNECT reached the HTTP handler from {}", rctx.client_addr);
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
async fn read_at_least<R: AsyncRead + Unpin>(
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
    Ok((host.to_string(), port))
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
            mitm: None,
            enable_http2: false,
            enable_websockets: false,
            ctx: ctx.clone(),
            timeouts: Timeouts::from_config(&crate::config::ProxyConfig::default().performance),
            #[cfg(feature = "websockets")]
            ws: None,
        });
        let addr: SocketAddr = "203.0.113.7:4242".parse().unwrap();
        let h = ConnectionHandler::new(addr, shared);
        assert_eq!(h.rctx.client_addr, addr);
        assert!(h.rctx.auth_user.is_none());
        assert!(Arc::ptr_eq(&h.rctx.profile, ctx.default_profile()));
    }
}

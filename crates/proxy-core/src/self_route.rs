//! Requests that name the web UI endpoint are handed to the web server in this process: never
//! filtered, intercepted or logged, and the web server sees the real client address (rate
//! limits and audit stay per client).
//!
//! A request is only routed there when the client could reach the web UI directly: see
//! `NetPolicy::is_web_ui` (bind address and client address decide, and a connection whose
//! destination is already known is judged by that destination, never by a `Host` header).
//! Nothing is dialled, so no new path to the web UI exists, and it is not a proxy, so it cannot
//! loop.

use crate::inject::ProxyBody;
use hyper::body::Incoming;
use hyper::{Request, Response};
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};

/// Any bidirectional byte stream.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Io for T {}

/// The web server, as the proxy sees it.
pub trait WebUiHandoff: Send + Sync {
    /// Serve a whole connection (the client's bytes, TLS or plain) as if it had been accepted
    /// by the web UI listener; `peer` is the real client, `port` the web UI port.
    fn stream(&self, io: Box<dyn Io>, peer: SocketAddr, port: u16);
    /// Serve one plain-HTTP request (WebSocket upgrades included).
    fn request(
        &self,
        req: Request<Incoming>,
        peer: SocketAddr,
        port: u16,
    ) -> futures_util::future::BoxFuture<'static, Response<ProxyBody>>;
}

//! Requests that name the web UI endpoint (this host, the web UI port) are routed straight to
//! the web UI listener: never filtered, intercepted or logged. It cannot loop (the web UI is not
//! a proxy) and reaches nothing the client could not already reach directly.

use crate::inject::ProxyBody;
use crate::{Error, Result};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;

/// Forward one plain-HTTP request (WebSocket upgrades included) to the web UI at `addr`.
pub(crate) async fn forward(
    addr: SocketAddr,
    mut req: Request<Incoming>,
    dial: Duration,
) -> Result<Response<ProxyBody>> {
    let stream = tokio::time::timeout(dial, TcpStream::connect(addr))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(Error::from)?;
    let _ = stream.set_nodelay(true);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| Error::Connection(format!("web UI handshake: {e}")))?;
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    // Origin-form target; the client's `Host` header is kept.
    let pq = req
        .uri()
        .path_and_query()
        .map_or_else(|| "/".to_string(), |p| p.as_str().to_string());
    *req.uri_mut() = pq
        .parse()
        .map_err(|_| Error::Connection("bad request target".into()))?;
    req.headers_mut().remove("proxy-connection");
    let client_up = req
        .headers()
        .contains_key(hyper::header::UPGRADE)
        .then(|| hyper::upgrade::on(&mut req));
    let mut resp = sender
        .send_request(req)
        .await
        .map_err(|e| Error::Connection(format!("web UI request: {e}")))?;
    if let (Some(client_up), true) = (
        client_up,
        resp.status() == hyper::StatusCode::SWITCHING_PROTOCOLS,
    ) {
        let server_up = hyper::upgrade::on(&mut resp);
        tokio::spawn(async move {
            if let (Ok(c), Ok(s)) = (client_up.await, server_up.await) {
                let (mut c, mut s) = (TokioIo::new(c), TokioIo::new(s));
                let _ = tokio::io::copy_bidirectional(&mut c, &mut s).await;
            }
        });
    }
    Ok(resp.map(|b| b.map_err(std::io::Error::other).boxed_unsync()))
}

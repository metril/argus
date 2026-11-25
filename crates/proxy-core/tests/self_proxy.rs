//! Requests that name the web UI endpoint are handed to the web server in-process with the real
//! client address (unfiltered, not intercepted, not logged); the proxy's own ports stay refused.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use filter_engine::SharedEngine;
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use proxy_core::config::ProxyConfig;
use proxy_core::inject::{full_body, ProxyBody};
use proxy_core::self_route::{Io, WebUiHandoff};
use proxy_core::upstream::UpstreamOptions;
use proxy_core::{ProxyContext, ProxyServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Stand-in web server: records the peer of every handoff and echoes.
#[derive(Default)]
struct FakeWeb {
    peers: parking_lot::Mutex<Vec<SocketAddr>>,
}

impl WebUiHandoff for FakeWeb {
    fn stream(&self, mut io: Box<dyn Io>, peer: SocketAddr, _port: u16) {
        self.peers.lock().push(peer);
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            while let Ok(n) = io.read(&mut buf).await {
                if n == 0 || io.write_all(&buf[..n]).await.is_err() {
                    return;
                }
            }
        });
    }

    fn request(
        &self,
        mut req: Request<Incoming>,
        peer: SocketAddr,
        _port: u16,
    ) -> futures_util::future::BoxFuture<'static, Response<ProxyBody>> {
        self.peers.lock().push(peer);
        let upgrade = req
            .headers()
            .contains_key(hyper::header::UPGRADE)
            .then(|| hyper::upgrade::on(&mut req));
        Box::pin(async move {
            if let Some(up) = upgrade {
                tokio::spawn(async move {
                    if let Ok(u) = up.await {
                        let mut u = TokioIo::new(u);
                        let mut buf = [0u8; 64];
                        while let Ok(n) = u.read(&mut buf).await {
                            if n == 0 || u.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                });
                return Response::builder()
                    .status(101)
                    .header("upgrade", "websocket")
                    .header("connection", "Upgrade")
                    .body(full_body(Bytes::new()))
                    .unwrap();
            }
            Response::new(full_body(Bytes::from(format!("peer={}", peer.ip()))))
        })
    }
}

/// Proxy on 127.0.0.1 that knows `webui` as the web UI endpoint (bound to `bind`).
async fn proxy(bind: &str, web: Arc<FakeWeb>) -> (u16, u16) {
    let ui = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    };
    let mut config = ProxyConfig::default();
    config.proxy.host = "127.0.0.1".into();
    config.mitm.enabled = false;
    let engine = Arc::new(SharedEngine::new());
    let ctx = Arc::new(
        ProxyContext::with_upstream(engine, &UpstreamOptions::from_config(&config), false).unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = ProxyServer::new(config, ctx).unwrap();
    server.control().set_webui_listener(bind, ui).await;
    server.control().set_web_server(web);
    let (tx, _) = tokio::sync::broadcast::channel(1);
    tokio::spawn(async move {
        let _ = server.serve(listener, tx).await;
    });
    (port, ui)
}

async fn get_via(proxy_port: u16, url: &str) -> reqwest::Response {
    reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://127.0.0.1:{proxy_port}")).unwrap())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
        .get(url)
        .send()
        .await
        .unwrap()
}

fn is_refused(r: &reqwest::Response) -> bool {
    r.status() == 403
        && r.headers()
            .get("x-adblock")
            .is_some_and(|v| v == "destination-refused")
}

async fn read_some(s: &mut TcpStream) -> String {
    let mut buf = [0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
        .await
        .expect("timeout")
        .unwrap();
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

#[tokio::test]
async fn plain_get_reaches_the_web_server_with_the_real_client_address() {
    let web = Arc::new(FakeWeb::default());
    let (p, ui) = proxy("0.0.0.0", web.clone()).await;
    let r = get_via(p, &format!("http://127.0.0.1:{ui}/api/v1/health")).await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.text().await.unwrap(), "peer=127.0.0.1");
    let r = get_via(p, &format!("http://localhost:{ui}/api/v1/health")).await;
    assert_eq!(r.status(), 200);
    let peers = web.peers.lock().clone();
    assert_eq!(peers.len(), 2);
    // The peer is the client's own socket, not the proxy's dial.
    assert!(peers.iter().all(|a| a.ip().is_loopback() && a.port() != ui));
}

#[tokio::test]
async fn connect_hands_the_stream_over_with_the_real_peer() {
    let web = Arc::new(FakeWeb::default());
    let (p, ui) = proxy("127.0.0.1", web.clone()).await;
    let mut s = TcpStream::connect(("127.0.0.1", p)).await.unwrap();
    let me = s.local_addr().unwrap();
    s.write_all(
        format!("CONNECT 127.0.0.1:{ui} HTTP/1.1\r\nHost: 127.0.0.1:{ui}\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    assert!(read_some(&mut s).await.starts_with("HTTP/1.1 200"));
    s.write_all(b"hello-tunnel").await.unwrap();
    assert_eq!(read_some(&mut s).await, "hello-tunnel");
    assert_eq!(web.peers.lock().as_slice(), &[me]);
}

#[tokio::test]
async fn websocket_upgrade_is_handed_over() {
    let web = Arc::new(FakeWeb::default());
    let (p, ui) = proxy("0.0.0.0", web).await;
    let mut s = TcpStream::connect(("127.0.0.1", p)).await.unwrap();
    s.write_all(
        format!("GET http://127.0.0.1:{ui}/ext/channel HTTP/1.1\r\nHost: 127.0.0.1:{ui}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    assert!(read_some(&mut s).await.starts_with("HTTP/1.1 101"));
    s.write_all(b"ping").await.unwrap();
    assert_eq!(read_some(&mut s).await, "ping");
}

#[tokio::test]
async fn the_proxys_own_port_is_still_refused() {
    let (p, _) = proxy("0.0.0.0", Arc::new(FakeWeb::default())).await;
    let r = get_via(p, &format!("http://127.0.0.1:{p}/")).await;
    assert!(is_refused(&r), "{}", r.status());
    let mut s = TcpStream::connect(("127.0.0.1", p)).await.unwrap();
    s.write_all(
        format!("CONNECT 127.0.0.1:{p} HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let head = read_some(&mut s).await;
    assert!(head.starts_with("HTTP/1.1 403"), "{head}");
}

#[tokio::test]
async fn a_host_header_cannot_name_the_web_ui_on_a_known_destination() {
    // Plain request to the proxy port itself carrying a web UI `Host`: not self-routed on its
    // own say-so when the connection's destination is known (SOCKS/transparent use Origin
    // authority); in explicit mode the absolute URI names the destination, so a mismatching
    // Host header is ignored.
    let web = Arc::new(FakeWeb::default());
    let (p, ui) = proxy("0.0.0.0", web.clone()).await;
    let mut s = TcpStream::connect(("127.0.0.1", p)).await.unwrap();
    s.write_all(
        format!("GET http://203.0.113.1:80/ HTTP/1.1\r\nHost: 127.0.0.1:{ui}\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(3), read_some(&mut s)).await;
    assert!(web.peers.lock().is_empty());
}

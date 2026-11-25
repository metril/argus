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
    proxy_with(bind, web, |_| {}).await
}

async fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

/// [`proxy`] with extra settings applied to the config.
async fn proxy_with(
    bind: &str,
    web: Arc<FakeWeb>,
    tweak: impl FnOnce(&mut ProxyConfig),
) -> (u16, u16) {
    let ui = free_port().await;
    let mut config = ProxyConfig::default();
    config.proxy.host = "127.0.0.1".into();
    config.mitm.enabled = false;
    tweak(&mut config);
    let engine = Arc::new(SharedEngine::new());
    let ctx = Arc::new(
        ProxyContext::with_upstream(engine, &UpstreamOptions::from_config(&config), false).unwrap(),
    );
    ctx.set_require_device_token(config.proxy.require_device_token);
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
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
async fn proxy_port_as_the_url_reaches_the_web_ui() {
    let web = Arc::new(FakeWeb::default());
    let (p, _) = proxy("0.0.0.0", web.clone()).await;
    // Direct (origin-form) request.
    let r = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
        .get(format!("http://127.0.0.1:{p}/api/v1/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    // Proxied (absolute-URI) request to the proxy's own port.
    let r = get_via(p, &format!("http://127.0.0.1:{p}/api/v1/health")).await;
    assert_eq!(r.status(), 200);
    assert_eq!(web.peers.lock().len(), 2);
    // CONNECT to the proxy port is handed over, never looped.
    let mut s = TcpStream::connect(("127.0.0.1", p)).await.unwrap();
    s.write_all(
        format!("CONNECT 127.0.0.1:{p} HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let head = read_some(&mut s).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(web.peers.lock().len(), 3);
}

#[tokio::test]
async fn proxy_port_is_refused_when_the_web_ui_is_not_reachable_by_the_client() {
    // Web UI on loopback only: a client that arrived on a LAN address cannot use it.
    let Some(lan) = lan_ip() else { return };
    let web = Arc::new(FakeWeb::default());
    let (p, _) = proxy("127.0.0.1", web.clone()).await;
    let sock = tokio::net::TcpSocket::new_v4().unwrap();
    sock.bind(SocketAddr::new(lan, 0)).unwrap();
    let mut s = sock.connect(SocketAddr::new(lan, p)).await.unwrap();
    s.write_all(
        format!("GET /api/v1/health HTTP/1.1\r\nHost: {lan}:{p}\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    let head = read_some(&mut s).await;
    assert!(!head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(web.peers.lock().is_empty());
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

/// A non-loopback address of this host, if it has one (no packet is sent).
fn lan_ip() -> Option<std::net::IpAddr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?;
    let ip = s.local_addr().ok()?.ip();
    (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}

#[tokio::test]
async fn remote_style_client_is_routed_only_to_the_address_it_arrived_on() {
    let Some(lan) = lan_ip() else { return };
    let web = Arc::new(FakeWeb::default());
    let (p, ui) = proxy("0.0.0.0", web.clone()).await;
    let connect = |target: String| async move {
        let sock = tokio::net::TcpSocket::new_v4().unwrap();
        sock.bind(SocketAddr::new(lan, 0)).unwrap();
        let mut s = sock.connect(SocketAddr::new(lan, p)).await.unwrap();
        s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let head = read_some(&mut s).await;
        (head, s.local_addr().unwrap())
    };
    // The address it arrived on: handed over, with its real (non-loopback) address.
    let (head, me) = connect(format!("{lan}:{ui}")).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(web.peers.lock().as_slice(), &[me]);
    // Loopback is not reachable for it; the miss is refused, never dialled or handed over.
    let (head, _) = connect(format!("127.0.0.1:{ui}")).await;
    assert!(head.starts_with("HTTP/1.1 403"), "{head}");
    // Another address of this host (a different interface) is not self either.
    let (head, _) = connect(format!("169.254.1.1:{ui}")).await;
    assert!(!head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(web.peers.lock().len(), 1);
}

/// A LAN-side client of a proxy whose web UI is loopback-only.
async fn lan_client(lan: std::net::IpAddr, p: u16) -> TcpStream {
    let sock = tokio::net::TcpSocket::new_v4().unwrap();
    sock.bind(SocketAddr::new(lan, 0)).unwrap();
    sock.connect(SocketAddr::new(lan, p)).await.unwrap()
}

#[tokio::test]
async fn loops_onto_the_proxy_port_stay_refused_with_a_web_ui_configured() {
    let Some(lan) = lan_ip() else { return };
    let web = Arc::new(FakeWeb::default());
    let (p, _) = proxy("127.0.0.1", web.clone()).await;
    // CONNECT to the proxy port: refused, not handed over and not dialled.
    for target in [format!("127.0.0.1:{p}"), format!("{lan}:{p}")] {
        let mut s = lan_client(lan, p).await;
        s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let head = read_some(&mut s).await;
        assert!(head.starts_with("HTTP/1.1 403"), "CONNECT {target}: {head}");
    }
    // Absolute URIs naming the proxy port: refused, never forwarded.
    for target in [format!("127.0.0.1:{p}"), format!("{lan}:{p}")] {
        let mut s = lan_client(lan, p).await;
        s.write_all(
            format!("GET http://{target}/ HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
        let head = read_some(&mut s).await;
        assert!(head.starts_with("HTTP/1.1 403"), "GET {target}: {head}");
    }
    assert!(web.peers.lock().is_empty());
}

#[tokio::test]
async fn socks_on_the_extension_listener_never_reaches_the_proxy_port() {
    let web = Arc::new(FakeWeb::default());
    let ext = free_port().await;
    let (p, _) = proxy_with("127.0.0.1", web.clone(), |c| c.proxy.ext_port = Some(ext)).await;
    // The extension listener comes up after the explicit one.
    let mut s = None;
    for _ in 0..50 {
        if let Ok(c) = TcpStream::connect(("127.0.0.1", ext)).await {
            s = Some(c);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let mut s = s.expect("extension listener");
    // Greeting offering username/password, then made-up credentials, then CONNECT to the
    // proxy port.
    s.write_all(&[5, 1, 2]).await.unwrap();
    let mut b = [0u8; 2];
    s.read_exact(&mut b).await.unwrap();
    let mut out = Vec::new();
    if b == [5, 2] {
        let (u, pw) = (b"ext:bogus", b"x");
        s.write_all(&[&[1, u.len() as u8][..], u, &[pw.len() as u8], pw].concat())
            .await
            .unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut out)).await;
        let mut req = vec![5, 1, 0, 1, 127, 0, 0, 1];
        req.extend_from_slice(&p.to_be_bytes());
        let _ = s.write_all(&req).await;
    }
    // Whatever the reply, the web UI never sees it.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(web.peers.lock().is_empty());
}

#[tokio::test]
async fn proxy_port_opened_directly_skips_the_device_token_for_the_web_ui() {
    let web = Arc::new(FakeWeb::default());
    let (p, _) = proxy_with("0.0.0.0", web.clone(), |c| {
        c.proxy.require_device_token = true
    })
    .await;
    // A browser opening the proxy port directly reaches the web UI (its own login applies).
    let r = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
        .get(format!("http://127.0.0.1:{p}/api/v1/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    // Proxying anything else still needs the token.
    let r = get_via(p, "http://203.0.113.1/").await;
    assert_eq!(r.status(), 407);
    assert_eq!(web.peers.lock().len(), 1);
}

#[tokio::test]
async fn explicit_proxy_refuses_to_dial_the_extension_listener() {
    // On a LAN address (private destinations are allowed by default), so only the own-listener
    // rule can refuse it; loopback would be refused anyway.
    let Some(lan) = lan_ip() else { return };
    let web = Arc::new(FakeWeb::default());
    let ext = free_port().await;
    let (p, _) = proxy_with("127.0.0.1", web.clone(), |c| {
        c.proxy.host = "0.0.0.0".into();
        c.proxy.ext_port = Some(ext);
    })
    .await;
    let mut ok = false;
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", ext)).await.is_ok() {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ok, "extension listener");
    let mut s = TcpStream::connect(("127.0.0.1", p)).await.unwrap();
    s.write_all(format!("CONNECT {lan}:{ext} HTTP/1.1\r\nHost: {lan}:{ext}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let head = read_some(&mut s).await;
    assert!(head.starts_with("HTTP/1.1 403"), "{head}");
}

//! Requests that name the web UI endpoint are routed to it (unfiltered, not intercepted, not
//! logged); the proxy's own ports stay refused.

use std::sync::Arc;
use std::time::Duration;

use filter_engine::SharedEngine;
use proxy_core::config::ProxyConfig;
use proxy_core::upstream::UpstreamOptions;
use proxy_core::{ProxyContext, ProxyServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Stand-in web UI: plain answer, or a 101 followed by an echo for upgrade requests.
async fn web_ui() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();
                if head.contains("upgrade: websocket") {
                    let _ = s
                        .write_all(b"HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\n\r\n")
                        .await;
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                } else if head.starts_with("connect ") || !head.starts_with("get ") {
                    // Raw tunnel check: echo the bytes.
                    let _ = s.write_all(&buf[..n]).await;
                } else {
                    let _ = s
                        .write_all(
                            b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                        )
                        .await;
                }
            });
        }
    });
    port
}

/// Proxy on 127.0.0.1 that knows `webui` as the web UI endpoint.
async fn proxy(webui: u16) -> u16 {
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
    server
        .control()
        .set_webui_listener("127.0.0.1", webui)
        .await;
    let (tx, _) = tokio::sync::broadcast::channel(1);
    tokio::spawn(async move {
        let _ = server.serve(listener, tx).await;
    });
    port
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
async fn plain_get_to_the_web_ui_endpoint_is_routed() {
    let ui = web_ui().await;
    let p = proxy(ui).await;
    let r = get_via(p, &format!("http://127.0.0.1:{ui}/api/v1/health")).await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.text().await.unwrap(), "ok");
    let r = get_via(p, &format!("http://localhost:{ui}/api/v1/health")).await;
    assert_eq!(r.status(), 200);
}

#[tokio::test]
async fn connect_to_the_web_ui_endpoint_tunnels() {
    let ui = web_ui().await;
    let p = proxy(ui).await;
    let mut s = TcpStream::connect(("127.0.0.1", p)).await.unwrap();
    s.write_all(
        format!("CONNECT 127.0.0.1:{ui} HTTP/1.1\r\nHost: 127.0.0.1:{ui}\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    assert!(read_some(&mut s).await.starts_with("HTTP/1.1 200"));
    s.write_all(b"hello-tunnel").await.unwrap();
    assert_eq!(read_some(&mut s).await, "hello-tunnel");
}

#[tokio::test]
async fn websocket_upgrade_to_the_web_ui_endpoint_is_routed() {
    let ui = web_ui().await;
    let p = proxy(ui).await;
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
    let ui = web_ui().await;
    let p = proxy(ui).await;
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

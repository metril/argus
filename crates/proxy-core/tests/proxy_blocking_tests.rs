//! End-to-end test that the proxy actually blocks (network-free).
//!
//! Spins up a real origin server + the real `ProxyServer` with an engine compiled from a single
//! block rule, then drives traffic through the proxy: an allowed request is forwarded to the
//! origin; a blocked host returns `204` without ever contacting an origin.

use std::sync::Arc;
use std::time::Duration;

use filter_engine::{compile_engine, SharedEngine};
use proxy_core::config::{
    AdblockSettings, MitmSettings, PerformanceSettings, ProxyConfig, ProxySettings,
    UserscriptSettings, WebUiSettings,
};
use proxy_core::{ProxyContext, ProxyServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Grab a currently-free localhost port.
async fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

/// Minimal HTTP/1.1 origin that answers every request with `200 OK` / "origin-hello".
async fn spawn_origin(listener: TcpListener) {
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf).await;
                let body = b"origin-hello";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.write_all(body).await;
                let _ = stream.flush().await;
            });
        }
    });
}

async fn wait_until_listening(port: u16) {
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("proxy on port {port} never came up");
}

fn test_config(proxy_port: u16) -> ProxyConfig {
    ProxyConfig {
        proxy: ProxySettings {
            host: "127.0.0.1".to_string(),
            port: proxy_port,
            enable_http2: false,
            enable_http3: false,
            enable_websockets: false,
        },
        mitm: MitmSettings {
            enabled: false,
            ca_cert_path: std::env::temp_dir().join("blk-test-ca.crt"),
            ca_key_path: std::env::temp_dir().join("blk-test-ca.key"),
            cert_cache_size: 10,
            cert_ttl_days: 1,
            cert_idle_timeout_secs: 60,
        },
        performance: PerformanceSettings {
            max_connections: 100,
            max_cert_generations: 10,
            max_html_buffers: 10,
            connection_timeout_secs: 5,
            request_timeout_secs: 10,
            connection_rate_limit: Some(1000),
        },
        adblock: AdblockSettings::default(),
        userscripts: UserscriptSettings::default(),
        webui: WebUiSettings::default(),
    }
}

#[tokio::test]
async fn proxy_blocks_matching_host_and_forwards_others() {
    // Origin server.
    let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = origin_listener.local_addr().unwrap().port();
    spawn_origin(origin_listener).await;

    // Engine that blocks anything on `blocked.test`.
    let engine = Arc::new(SharedEngine::new());
    engine.install(compile_engine(&["||blocked.test^\n".to_string()]));

    let ctx = Arc::new(ProxyContext::new(engine, reqwest::Client::new(), true));

    // Real proxy server.
    let proxy_port = free_port().await;
    let server = ProxyServer::new(test_config(proxy_port), ctx).unwrap();
    tokio::spawn(async move {
        let _ = server.start().await;
    });
    wait_until_listening(proxy_port).await;

    // Client that routes through our proxy.
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://127.0.0.1:{proxy_port}")).unwrap())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    // Allowed request → forwarded to the origin.
    let allowed = client
        .get(format!("http://127.0.0.1:{origin_port}/index.html"))
        .send()
        .await
        .expect("allowed request should succeed");
    assert_eq!(allowed.status(), 200);
    assert_eq!(allowed.text().await.unwrap(), "origin-hello");

    // Blocked host → 204, and it never reaches any origin (the host doesn't even resolve).
    let blocked = client
        .get("http://blocked.test/ads.js")
        .send()
        .await
        .expect("blocked request should still get a synthetic response");
    assert_eq!(blocked.status(), 204, "blocked host must return 204 No Content");
    assert_eq!(blocked.headers().get("x-adblock").unwrap(), "blocked");
}

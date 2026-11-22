//! End-to-end test that the proxy actually blocks (network-free).
//!
//! Spins up a real origin server + the real `ProxyServer` with an engine compiled from a single
//! block rule, then drives traffic through the proxy: an allowed request is forwarded to the
//! origin; a blocked host gets a synthetic response without ever contacting an origin.

use std::sync::Arc;
use std::time::Duration;

use filter_engine::{compile_engine, SharedEngine};
use proxy_core::config::{
    AdblockSettings, MitmSettings, PerformanceSettings, ProxyConfig, ProxySettings,
    UserscriptSettings, WebUiSettings,
};
use proxy_core::{ProxyContext, ProxyServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Start the proxy on an already-bound port-0 listener (kept open, so no bind-then-drop race).
/// Returns the proxy port; connections queue in the backlog until the server accepts.
async fn spawn_proxy(ctx: Arc<ProxyContext>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = ProxyServer::new(test_config(port), ctx).unwrap();
    let (tx, _) = tokio::sync::broadcast::channel(1);
    tokio::spawn(async move {
        let _ = server.serve(listener, tx).await;
    });
    port
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

fn test_config(proxy_port: u16) -> ProxyConfig {
    ProxyConfig {
        proxy: ProxySettings {
            host: "127.0.0.1".to_string(),
            port: proxy_port,
            enable_http2: false,
            transparent_port: None,
            tls_passthrough_hosts: Vec::new(),
            block_private_destinations: false,
            allowed_destinations: Vec::new(),
            allowed_clients: proxy_core::config::default_allowed_clients(),
            enable_websockets: false,
            extra_upstream_ca_paths: Vec::new(),
            require_device_token: false,
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
        script_control: Default::default(),
        webui: WebUiSettings::default(),
        dns: Default::default(),
    }
}

/// Origin that serves a small HTML document with `Content-Type: text/html`.
async fn spawn_html_origin(listener: TcpListener) {
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf).await;
                let body =
                    b"<html><head><title>t</title></head><body><div class=\"sponsored\">ad</div></body></html>";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.write_all(body).await;
                let _ = stream.flush().await;
            });
        }
    });
}

#[tokio::test]
async fn proxy_injects_cosmetics_and_answers_dynamic_endpoint() {
    let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = origin_listener.local_addr().unwrap().port();
    spawn_html_origin(origin_listener).await;

    // Generic class-hiding rule (delivered via the dynamic class/id path).
    let engine = Arc::new(SharedEngine::new());
    engine.install(compile_engine(&["##.sponsored\n".to_string()]));
    let ctx = Arc::new(
        ProxyContext::new(engine, reqwest::Client::new(), true).with_policy(Arc::new(
            proxy_core::policy::DestPolicy::new(false, &["127.0.0.0/8".to_string()]).unwrap(),
        )),
    );

    let proxy_port = spawn_proxy(ctx).await;

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://127.0.0.1:{proxy_port}")).unwrap())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    // HTML response gets the dynamic-hiding helper injected, original content preserved.
    let page = client
        .get(format!("http://127.0.0.1:{origin_port}/"))
        .header("sec-fetch-dest", "document")
        .send()
        .await
        .expect("html request");
    assert_eq!(page.status(), 200);
    let html = page.text().await.unwrap();
    assert!(html.contains("__ab_cfg"), "boot not injected: {html}");
    let i = html.find("id=\"__ab_cfg\">").unwrap() + "id=\"__ab_cfg\">".len();
    let cfg: serde_json::Value =
        serde_json::from_str(&html[i..i + html[i..].find("</script>").unwrap()]).unwrap();
    let token = cfg["t"].as_str().unwrap().to_string();
    assert!(
        html.contains("class=\"sponsored\""),
        "original content lost"
    );

    // The dynamic endpoint resolves generic selectors for reported class tokens, served locally.
    let cc = client
        .post(format!("http://127.0.0.1:{origin_port}/__adblock__/cc"))
        .header("x-adblock-token", token)
        .json(&serde_json::json!({
            "url": format!("http://127.0.0.1:{origin_port}/"),
            "classes": ["sponsored"],
            "ids": []
        }))
        .send()
        .await
        .expect("cc request");
    assert_eq!(cc.status(), 200);
    let body: serde_json::Value = cc.json().await.unwrap();
    let sels = body["selectors"].as_array().expect("selectors array");
    assert!(
        sels.iter()
            .any(|s| s.as_str().unwrap_or("").contains(".sponsored")),
        "expected .sponsored selector, got {body}"
    );
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

    let ctx = Arc::new(
        ProxyContext::new(engine, reqwest::Client::new(), true).with_policy(Arc::new(
            proxy_core::policy::DestPolicy::new(false, &["127.0.0.0/8".to_string()]).unwrap(),
        )),
    );

    // Real proxy server.
    let proxy_port = spawn_proxy(ctx).await;

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

    // Blocked host → synthetic response, and it never reaches any origin (the host doesn't even resolve).
    let blocked = client
        .get("http://blocked.test/ads.js")
        .send()
        .await
        .expect("blocked request should still get a synthetic response");
    assert_eq!(
        blocked.status(),
        200,
        "blocked script gets an empty 200 JS body"
    );
    assert_eq!(blocked.headers().get("x-adblock").unwrap(), "blocked");
}

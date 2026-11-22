//! Destination policy through the real server without the test resolve override: hostnames are
//! judged on what they resolve to, and the proxy's own listener can never be a destination.

use std::sync::Arc;
use std::time::Duration;

use filter_engine::SharedEngine;
use proxy_core::config::ProxyConfig;
use proxy_core::upstream::UpstreamOptions;
use proxy_core::{ProxyContext, ProxyServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn origin() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf).await;
                let _ = s
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                    )
                    .await;
            });
        }
    });
    port
}

/// Proxy on 127.0.0.1:0 with `tweak` applied to the config; returns its port.
async fn proxy(tweak: impl FnOnce(&mut ProxyConfig)) -> u16 {
    let mut config = ProxyConfig::default();
    config.proxy.host = "127.0.0.1".into();
    config.mitm.enabled = false;
    tweak(&mut config);
    let engine = Arc::new(SharedEngine::new());
    let ctx = Arc::new(
        ProxyContext::with_upstream(engine, &UpstreamOptions::from_config(&config), false).unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = ProxyServer::new(config, ctx).unwrap();
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

#[tokio::test]
async fn name_resolving_to_loopback_is_refused() {
    let origin = origin().await;
    let p = proxy(|_| {}).await;
    let r = get_via(p, &format!("http://localhost:{origin}/")).await;
    assert!(is_refused(&r), "{}", r.status());
    let r = get_via(p, &format!("http://127.0.0.1:{origin}/")).await;
    assert!(is_refused(&r), "{}", r.status());
}

#[tokio::test]
async fn allowed_destinations_override_the_refusal() {
    let origin = origin().await;
    let p = proxy(|c| c.proxy.allowed_destinations = vec!["127.0.0.0/8".into()]).await;
    for host in ["localhost", "127.0.0.1"] {
        let r = get_via(p, &format!("http://{host}:{origin}/")).await;
        assert_eq!(r.status(), 200, "{host}");
        assert_eq!(r.text().await.unwrap(), "ok");
    }
}

#[tokio::test]
async fn own_listener_is_never_a_destination() {
    let p = proxy(|c| c.proxy.allowed_destinations = vec!["127.0.0.0/8".into()]).await;
    for host in ["localhost", "127.0.0.1"] {
        let r = get_via(p, &format!("http://{host}:{p}/")).await;
        assert!(is_refused(&r), "{host}: {}", r.status());
    }
}

#[tokio::test]
async fn private_destinations_are_refused_only_when_configured() {
    let p = proxy(|c| c.proxy.block_private_destinations = true).await;
    for host in [
        "10.1.2.3",
        "192.168.1.1",
        "172.16.0.9",
        "100.64.0.1",
        "[fd00::1]",
    ] {
        let r = get_via(p, &format!("http://{host}:80/")).await;
        assert!(is_refused(&r), "{host}: {}", r.status());
    }
}

#[tokio::test]
async fn invalid_cidr_config_is_rejected_at_startup() {
    let mut config = ProxyConfig::default();
    config.mitm.enabled = false;
    config.proxy.allowed_clients = vec!["not-a-cidr".into()];
    let ctx = Arc::new(ProxyContext::new(
        Arc::new(SharedEngine::new()),
        reqwest::Client::new(),
        false,
    ));
    assert!(ProxyServer::new(config.clone(), ctx.clone()).is_err());
    config.proxy.allowed_clients = vec![];
    config.proxy.allowed_destinations = vec!["10.0.0.0/33".into()];
    assert!(ProxyServer::new(config, ctx).is_err());
}

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
    let ctx = Arc::new(ProxyContext::new(Arc::new(SharedEngine::new()), false));
    assert!(ProxyServer::new(config.clone(), ctx.clone()).is_err());
    config.proxy.allowed_clients = vec![];
    config.proxy.allowed_destinations = vec!["10.0.0.0/33".into()];
    assert!(ProxyServer::new(config, ctx).is_err());
}

// ---- DNS sinkholes: a public name that resolves to 0.0.0.0, `::` or loopback -----------------

use proxy_core::config::BlockResponse;
use proxy_core::dns::{BackendResult, DnsBackend, DnsCacheConfig, DnsFailure, FailKind};
use std::net::IpAddr;
use std::pin::Pin;

/// A DNS backend answering fixed addresses, never touching the network.
struct FixedDns(Vec<(&'static str, IpAddr)>);

impl DnsBackend for FixedDns {
    fn lookup(
        &self,
        name: &str,
    ) -> Pin<Box<dyn std::future::Future<Output = BackendResult> + Send>> {
        let r = match self.0.iter().find(|(n, _)| *n == name) {
            Some((_, ip)) => Ok((vec![*ip], Duration::from_secs(60))),
            None => Err(DnsFailure::new(FailKind::NotFound, "no such name")),
        };
        Box::pin(async move { r })
    }
}

/// Proxy (plain HTTP, no MITM) whose DNS answers come from `answers`: its port, context and
/// engine (for the request log).
async fn proxy_with_dns(
    mode: BlockResponse,
    answers: Vec<(&'static str, IpAddr)>,
) -> (u16, Arc<ProxyContext>, Arc<SharedEngine>) {
    let mut config = ProxyConfig::default();
    config.proxy.host = "127.0.0.1".into();
    config.proxy.block_response = mode;
    config.mitm.enabled = false;
    let engine = Arc::new(SharedEngine::new());
    let ctx = Arc::new(
        ProxyContext::with_upstream(
            engine.clone(),
            &UpstreamOptions::from_config(&config),
            false,
        )
        .unwrap(),
    );
    ctx.dns().expect("dns").reconfigure_with(
        Arc::new(FixedDns(answers)),
        DnsCacheConfig {
            capacity: 16,
            min_ttl: Duration::ZERO,
            max_ttl: Duration::from_secs(60),
            negative_ttl: Duration::ZERO,
        },
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = ProxyServer::new(config, ctx.clone()).unwrap();
    let (tx, _) = tokio::sync::broadcast::channel(1);
    tokio::spawn(async move {
        let _ = server.serve(listener, tx).await;
    });
    (port, ctx, engine)
}

fn sinks() -> Vec<(&'static str, IpAddr)> {
    vec![
        ("localhost", "127.0.0.1".parse().unwrap()),
        ("v4.sink.test", "0.0.0.0".parse().unwrap()),
        ("v6.sink.test", "::".parse().unwrap()),
        ("lo.sink.test", "127.0.0.1".parse().unwrap()),
        ("lo6.sink.test", "::1".parse().unwrap()),
        // Link-local is refused too, but it is not a sinkhole answer.
        ("meta.sink.test", "169.254.169.254".parse().unwrap()),
    ]
}

async fn raw_get(proxy_port: u16, url: &str) -> Vec<u8> {
    let host = url.split('/').nth(2).unwrap();
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .unwrap();
    s.write_all(
        format!("GET {url} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
    out
}

#[tokio::test]
async fn sinkholed_name_is_aborted_not_answered_under_fail() {
    let (p, _ctx, _) = proxy_with_dns(BlockResponse::Fail, sinks()).await;
    for name in [
        "v4.sink.test",
        "v6.sink.test",
        "lo.sink.test",
        "lo6.sink.test",
    ] {
        // The connection is closed without a response: nothing for the page to count as loaded.
        let out = raw_get(p, &format!("http://{name}/")).await;
        assert!(out.is_empty(), "{name}: {}", String::from_utf8_lossy(&out));
        let err = reqwest::Client::builder()
            .proxy(reqwest::Proxy::http(format!("http://127.0.0.1:{p}")).unwrap())
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap()
            .get(format!("http://{name}/"))
            .send()
            .await
            .expect_err(name);
        assert!(!err.is_timeout(), "{name}: {err}");
    }
}

#[tokio::test]
async fn non_sinkhole_refusals_keep_the_403_under_fail() {
    let origin = origin().await;
    let (p, _ctx, _) = proxy_with_dns(BlockResponse::Fail, sinks()).await;
    // Link-local (cloud metadata) and loopback by the name `localhost` are policy refusals, not
    // sinkholes: they keep the explicit 403.
    for url in [
        "http://meta.sink.test/".to_string(),
        format!("http://localhost:{origin}/"),
        format!("http://127.0.0.1:{origin}/"),
    ] {
        let r = get_via(p, &url).await;
        assert!(is_refused(&r), "{url}: {}", r.status());
    }
}

#[tokio::test]
async fn sinkholed_name_keeps_the_403_under_synthetic() {
    let (p, _ctx, _) = proxy_with_dns(BlockResponse::Synthetic, sinks()).await;
    let r = get_via(p, "http://v4.sink.test/").await;
    assert!(is_refused(&r), "{}", r.status());
}

#[tokio::test]
async fn sinkhole_setting_applies_live() {
    let (p, ctx, _) = proxy_with_dns(BlockResponse::Synthetic, sinks()).await;
    assert!(is_refused(&get_via(p, "http://v4.sink.test/").await));
    ctx.set_block_response(BlockResponse::Fail);
    assert!(raw_get(p, "http://v4.sink.test/").await.is_empty());
    ctx.set_block_response(BlockResponse::Synthetic);
    assert!(is_refused(&get_via(p, "http://v4.sink.test/").await));
}

#[tokio::test]
async fn sinkholed_name_is_logged_with_its_reason_and_outcome() {
    let (p, _ctx, engine) = proxy_with_dns(BlockResponse::Fail, sinks()).await;
    assert!(raw_get(p, "http://v4.sink.test/x").await.is_empty());
    let ev = engine
        .recent_requests(10)
        .into_iter()
        .find(|e| e.url.contains("v4.sink.test"))
        .expect("logged");
    assert_eq!(ev.rule.as_deref(), Some("sinkholed-upstream"));
    assert_eq!(ev.outcome, Some(filter_engine::EventOutcome::Aborted));
    assert_eq!(ev.action, filter_engine::EventAction::Blocked);
    assert_eq!(ev.status, None);
}

#[tokio::test]
async fn sinkholed_connect_gets_a_502_that_closes_under_fail() {
    let (p, _ctx, _) = proxy_with_dns(BlockResponse::Fail, sinks()).await;
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", p))
        .await
        .unwrap();
    s.write_all(b"CONNECT v4.sink.test:443 HTTP/1.1\r\nHost: v4.sink.test:443\r\n\r\n")
        .await
        .unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
    let text = String::from_utf8_lossy(&out).to_ascii_lowercase();
    assert!(text.starts_with("http/1.1 502"), "{text}");
    assert!(
        text.contains("connection: close") && text.contains("sinkholed-upstream"),
        "{text}"
    );
}

#[tokio::test]
async fn sinkholed_documents_and_images_keep_their_answer_under_fail() {
    let (p, _ctx, _) = proxy_with_dns(BlockResponse::Fail, sinks()).await;
    for dest in ["document", "iframe", "image"] {
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", p))
            .await
            .unwrap();
        s.write_all(
            format!("GET http://v4.sink.test/ HTTP/1.1\r\nHost: v4.sink.test\r\nSec-Fetch-Dest: {dest}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
        let text = String::from_utf8_lossy(&out).to_ascii_lowercase();
        assert!(text.starts_with("http/1.1 403"), "{dest}: {text}");
        assert!(text.contains("destination-refused"), "{dest}: {text}");
    }
    // A script to the same name is aborted.
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", p))
        .await
        .unwrap();
    s.write_all(b"GET http://v4.sink.test/a.js HTTP/1.1\r\nHost: v4.sink.test\r\nSec-Fetch-Dest: script\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
    assert!(out.is_empty());
}

#[test]
fn sinkhole_classification() {
    use common::net_policy::Refusal;
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    let r = Refusal::Reserved;
    for a in ["0.0.0.0", "::", "127.0.0.1", "::1", "::ffff:127.0.0.1"] {
        assert_eq!(
            r.for_resolved_name("ads.example.com", ip(a)),
            Refusal::Sinkhole,
            "{a}"
        );
    }
    // Local names and non-sinkhole reserved answers keep their refusal.
    assert_eq!(
        r.for_resolved_name("localhost", ip("127.0.0.1")),
        Refusal::Reserved
    );
    assert_eq!(
        r.for_resolved_name("a.localhost", ip("127.0.0.1")),
        Refusal::Reserved
    );
    assert_eq!(
        r.for_resolved_name("router", ip("0.0.0.0")),
        Refusal::Reserved
    );
    assert_eq!(
        r.for_resolved_name("x.example.com", ip("169.254.169.254")),
        Refusal::Reserved
    );
    assert_eq!(
        Refusal::Private.for_resolved_name("x.example.com", ip("0.0.0.0")),
        Refusal::Private
    );
}

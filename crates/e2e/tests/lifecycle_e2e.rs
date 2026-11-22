//! Restart, live profile edits and live timeout changes against the real proxy.

use std::sync::Arc;
use std::time::Duration;

use e2e::{EntryMode, MockResponse, TestOrigin, TestProxy};
use filter_engine::{compile_engine, SharedEngine};
use proxy_core::Profile;

fn client_trusting(ca_pem: &[u8], proxy: &TestProxy) -> reqwest::Client {
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem).unwrap())
        .proxy(reqwest::Proxy::all(proxy.url()).unwrap())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

#[tokio::test]
async fn restart_on_same_data_dir_keeps_the_installed_ca_working() {
    let origin = TestOrigin::start().await;
    origin.route("/hi", MockResponse::ok("hi"));
    let first = TestProxy::start(EntryMode::Explicit, &origin, &[])
        .await
        .unwrap();
    let installed_ca = first.ca_pem.clone();
    let url = origin.https_url("restart.test", "/hi");
    let c1 = client_trusting(&installed_ca, &first);
    assert_eq!(c1.get(&url).send().await.unwrap().status(), 200);

    // Restart: new proxy process state, same CA files on disk.
    let dir = first.stop();
    let second = TestProxy::start_in(EntryMode::Explicit, &origin, &[], dir)
        .await
        .unwrap();
    assert_eq!(second.ca_pem, installed_ca, "CA must not be regenerated");
    // A client that only ever trusted the original CA still connects, with a freshly issued leaf.
    let c2 = client_trusting(&installed_ca, &second);
    let resp = c2.get(&url).send().await.unwrap();
    assert_eq!(resp.text().await.unwrap(), "hi");
    assert_eq!(second.mitm.as_ref().unwrap().generation_count(), 1);
}

#[tokio::test]
async fn upstream_request_timeout_is_live_and_yields_504() {
    let origin = TestOrigin::start().await;
    origin.route(
        "/slow",
        MockResponse::ok("late").delayed(Duration::from_secs(30)),
    );
    origin.route("/fast", MockResponse::ok("fast"));
    let proxy = TestProxy::start(EntryMode::Explicit, &origin, &[])
        .await
        .unwrap();
    proxy.ctx.set_request_timeout(Duration::from_millis(150));
    let c = client_trusting(&proxy.ca_pem, &proxy);
    let slow = c
        .get(origin.https_url("t.test", "/slow"))
        .send()
        .await
        .unwrap();
    assert_eq!(slow.status(), 504);
    let fast = c
        .get(origin.https_url("t.test", "/fast"))
        .send()
        .await
        .unwrap();
    assert_eq!(fast.status(), 200);
}

#[tokio::test]
async fn profile_swap_applies_to_open_connections() {
    let origin = TestOrigin::start().await;
    origin.route("/ad.js", MockResponse::ok("ad"));
    let proxy = TestProxy::start(EntryMode::Explicit, &origin, &[])
        .await
        .unwrap();
    let c = client_trusting(&proxy.ca_pem, &proxy);
    let url = origin.https_url("swap.test", "/ad.js");
    let resp = c.get(&url).send().await.unwrap();
    assert!(resp.headers().get("x-adblock").is_none());

    let engine = Arc::new(SharedEngine::new());
    engine.install(compile_engine(&["||swap.test^\n".to_string()]));
    let slot = proxy.ctx.default_profile();
    let generation = slot.load().generation + 1;
    slot.store(Arc::new(Profile {
        id: slot.load().id,
        generation,
        engine,
    }));
    // Same pooled client => same connection, same RequestCtx.
    let resp = c.get(&url).send().await.unwrap();
    assert_eq!(resp.headers()["x-adblock"], "blocked");
}

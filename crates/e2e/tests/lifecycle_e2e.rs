//! Restart, live profile edits and live timeout changes against the real proxy.

use std::sync::Arc;
use std::time::Duration;

use e2e::{EntryMode, HttpVersion, MockResponse, TestClient, TestOrigin, TestProxy};
use filter_engine::{compile_engine, SharedEngine};
use proxy_core::Profile;

/// Run `$body(mode)` once per entry mode as `<name>::explicit` / `<name>::transparent`.
macro_rules! both_modes {
    ($name:ident, $body:ident) => {
        mod $name {
            use super::*;
            #[tokio::test]
            async fn explicit() {
                $body(EntryMode::Explicit).await
            }
            #[tokio::test]
            async fn transparent() {
                $body(EntryMode::Transparent).await
            }
        }
    };
}

fn client(proxy: &TestProxy) -> TestClient {
    TestClient::new(proxy, HttpVersion::Auto)
}

async fn restart_keeps_ca(mode: EntryMode) {
    let origin = TestOrigin::start().await;
    origin.route("/hi", MockResponse::ok("hi"));
    let first = TestProxy::start(mode, &origin, &[]).await.unwrap();
    let installed_ca = first.ca_pem.clone();
    let url = origin.https_url("restart.test", "/hi");
    let c1 = client(&first);
    assert_eq!(c1.get(&url).await.status(), 200);

    // Restart: new proxy process state, same CA files on disk.
    let dir = first.stop();
    let second = TestProxy::start_in(mode, &origin, &[], dir).await.unwrap();
    assert_eq!(second.ca_pem, installed_ca, "CA must not be regenerated");
    // A client that only ever trusted the original CA still connects, with a freshly issued leaf.
    let c2 = client(&second);
    let resp = c2.get(&url).await;
    assert_eq!(resp.text().await.unwrap(), "hi");
    assert_eq!(second.mitm.as_ref().unwrap().generation_count(), 1);
}

async fn live_timeout_yields_504(mode: EntryMode) {
    let origin = TestOrigin::start().await;
    origin.route(
        "/slow",
        MockResponse::ok("late").delayed(Duration::from_secs(30)),
    );
    origin.route("/fast", MockResponse::ok("fast"));
    let proxy = TestProxy::start(mode, &origin, &[]).await.unwrap();
    proxy.ctx.set_request_timeout(Duration::from_millis(150));
    let c = client(&proxy);
    let slow = c.get(&origin.https_url("t.test", "/slow")).await;
    assert_eq!(slow.status(), 504);
    let fast = c.get(&origin.https_url("t.test", "/fast")).await;
    assert_eq!(fast.status(), 200);
}

async fn profile_swap_applies(mode: EntryMode) {
    let origin = TestOrigin::start().await;
    origin.route("/ad.js", MockResponse::ok("ad"));
    let proxy = TestProxy::start(mode, &origin, &[]).await.unwrap();
    let c = client(&proxy);
    let url = origin.https_url("swap.test", "/ad.js");
    let resp = c.get(&url).await;
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
    let resp = c.get(&url).await;
    assert_eq!(resp.headers()["x-adblock"], "blocked");
}

both_modes!(
    restart_on_same_data_dir_keeps_the_installed_ca_working,
    restart_keeps_ca
);
both_modes!(
    upstream_request_timeout_is_live_and_yields_504,
    live_timeout_yields_504
);
both_modes!(
    profile_swap_applies_to_open_connections,
    profile_swap_applies
);

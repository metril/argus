//! Per-listener switches: the explicit and transparent listeners follow their own settings.

use e2e::{EntryMode, MockResponse, TestEnv};

async fn blocked(env: &TestEnv) -> bool {
    env.origin.route("/a.js", MockResponse::ok("origin-body"));
    e2e::was_blocked(
        &env.client()
            .try_get(&env.origin.https_url("ads.test", "/a.js"))
            .await,
    )
}

/// Ad blocking off on the transparent listener only (global setting on).
fn transparent_adblock_off(c: &mut proxy_core::config::ProxyConfig) {
    c.adblock.enabled = true;
    c.proxy.transparent.enable_adblock = Some(false);
}

#[tokio::test]
async fn explicit_listener_keeps_blocking_when_only_transparent_has_it_off() {
    let env = TestEnv::start_tweaked(
        EntryMode::Explicit,
        &["||ads.test^"],
        &transparent_adblock_off,
    )
    .await;
    assert!(blocked(&env).await);
}

#[tokio::test]
async fn transparent_listener_lets_everything_through_when_its_adblock_is_off() {
    let env = TestEnv::start_tweaked(
        EntryMode::Transparent,
        &["||ads.test^"],
        &transparent_adblock_off,
    )
    .await;
    assert!(!blocked(&env).await);
    // Still logged as an allowed, transparent request.
    let all = env.proxy.engine.recent_requests(5);
    assert!(
        all.iter().any(|e| e.url.contains("ads.test")
            && e.action == filter_engine::EventAction::Allowed
            && e.mode == filter_engine::EventMode::Transparent),
        "{all:?}"
    );
}

#[tokio::test]
async fn explicit_adblock_off_does_not_affect_the_transparent_listener() {
    let off_explicit = |c: &mut proxy_core::config::ProxyConfig| {
        c.adblock.enabled = true;
        c.proxy.explicit.enable_adblock = Some(false);
    };
    let t = TestEnv::start_tweaked(EntryMode::Transparent, &["||ads.test^"], &off_explicit).await;
    assert!(blocked(&t).await);
    let e = TestEnv::start_tweaked(EntryMode::Explicit, &["||ads.test^"], &off_explicit).await;
    assert!(!blocked(&e).await);
}

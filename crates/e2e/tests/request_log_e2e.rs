//! The request log through the real proxy, in both entry modes: allowed, blocked and tunnelled
//! requests are recorded (and broadcast) with their method, status and entry mode.

use e2e::{e2e_test, EntryMode, HttpVersion, MockResponse, TestClient, TestEnv};
use filter_engine::{EventAction, EventMode};

fn expected_mode(env: &TestEnv) -> EventMode {
    match env.mode {
        EntryMode::Explicit => EventMode::Explicit,
        EntryMode::Transparent => EventMode::Transparent,
    }
}

e2e_test!(
    allowed_and_blocked_requests_are_logged_with_mode,
    rules = ["||ads.test^"],
    |env| {
        env.origin.route("/ok", MockResponse::ok("fine"));
        env.origin.route("/ad.js", MockResponse::ok("ad"));
        let mut live = env.proxy.engine.subscribe_requests();

        let ok = env
            .client()
            .get(&env.origin.https_url("good.test", "/ok"))
            .await;
        assert_eq!(ok.status(), 200);
        let ad = env
            .client()
            .get(&env.origin.https_url("ads.test", "/ad.js"))
            .await;
        assert_eq!(
            ad.headers().get("x-adblock").map(|v| v.as_bytes()),
            Some(&b"blocked"[..])
        );

        let all = env.proxy.engine.recent_requests(10);
        let mode = expected_mode(&env);
        let allowed = all
            .iter()
            .find(|e| e.url.contains("good.test") && e.url.ends_with("/ok"))
            .unwrap_or_else(|| panic!("no allowed event in {all:?}"));
        assert_eq!(allowed.action, EventAction::Allowed);
        assert_eq!(allowed.status, Some(200));
        assert_eq!(allowed.method, "GET");
        assert_eq!(allowed.mode, mode);
        assert!(allowed.rule.is_none());

        let blocked = all
            .iter()
            .find(|e| e.url.contains("ads.test"))
            .unwrap_or_else(|| panic!("no blocked event in {all:?}"));
        assert_eq!(blocked.action, EventAction::Blocked);
        assert_eq!(blocked.method, "GET");
        assert_eq!(blocked.mode, mode);
        assert_eq!(blocked.rule.as_deref(), Some("||ads.test^"));

        // The blocked-only view is unchanged: allowed requests never enter it.
        let only_blocked = env.proxy.engine.recent_blocked(10);
        assert_eq!(only_blocked.len(), 1);
        assert_eq!(only_blocked[0].action, EventAction::Blocked);

        // Live subscribers saw both, in order.
        let first = live.try_recv().expect("allowed event broadcast");
        let second = live.try_recv().expect("blocked event broadcast");
        assert_eq!(
            (first.event.action, second.event.action),
            (EventAction::Allowed, EventAction::Blocked)
        );
    }
);

e2e_test!(
    tunnelled_passthrough_is_logged,
    rules = Vec::<&str>::new(),
    passthrough = ["pinned.test"],
    |env| {
        env.origin.route("/p", MockResponse::ok("direct"));
        let origin_ca = env.origin.ca_pem().as_bytes();
        let direct = TestClient::trusting(&env.proxy, HttpVersion::Http1, &[origin_ca]);
        let resp = direct.get(&env.origin.https_url("pinned.test", "/p")).await;
        assert_eq!(resp.status(), 200);
        let all = env.proxy.engine.recent_requests(10);
        let t = all
            .iter()
            .find(|e| e.action == EventAction::Passthrough)
            .unwrap_or_else(|| panic!("no passthrough event in {all:?}"));
        assert_eq!(t.method, "CONNECT");
        assert!(t.url.contains("pinned.test"), "{}", t.url);
        assert_eq!(t.mode, expected_mode(&env));
    }
);

e2e_test!(
    internal_endpoints_are_logged_once,
    rules = Vec::<&str>::new(),
    |env| {
        let url = env
            .origin
            .https_url("app.test", "/__adblock__/does-not-exist");
        let r = env.client().get(&url).await;
        let status = r.status().as_u16();
        let hits: Vec<_> = env
            .proxy
            .engine
            .recent_requests(50)
            .into_iter()
            .filter(|e| e.url.contains("/__adblock__/does-not-exist"))
            .collect();
        assert_eq!(hits.len(), 1, "served by Argus, logged once: {hits:?}");
        assert_eq!(hits[0].status, Some(status));
        assert_eq!(hits[0].request_type, "internal");
        assert_eq!(hits[0].mode, expected_mode(&env));
    }
);

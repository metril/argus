//! `/logs/requests` (filtered snapshot) and `/logs/stream` (SSE): scopes, filters, lag.

mod common;

use common::TestContext;
use filter_engine::{EventAction, EventMode, EventRef};
use serde_json::Value;
use std::net::SocketAddr;
use std::time::Duration;

fn ev<'a>(action: EventAction, url: &'a str, client: &'a str, mode: EventMode) -> EventRef<'a> {
    EventRef {
        action,
        method: "GET",
        url,
        source_host: "page.test",
        request_type: "script",
        rule: if action == EventAction::Blocked {
            "||ads.test^"
        } else {
            ""
        },
        list_id: None,
        client: Some(client),
        status: (action == EventAction::Allowed).then_some(200),
        mode,
        error_kind: None,
        cert_fp: None,
    }
}

fn seed(ctx: &TestContext) {
    let e = &ctx.state.shared_engine;
    e.record_request(&ev(
        EventAction::Allowed,
        "https://good.test/a",
        "1",
        EventMode::Explicit,
    ));
    e.record_request(&ev(
        EventAction::Blocked,
        "https://ads.test/b.js",
        "1",
        EventMode::Transparent,
    ));
    e.record_request(&ev(
        EventAction::Allowed,
        "https://other.test/c",
        "2",
        EventMode::Transparent,
    ));
    e.record_request(&ev(
        EventAction::Passthrough,
        "https://pinned.test",
        "2",
        EventMode::Explicit,
    ));
}

async fn snapshot(ctx: &TestContext, tok: &str, query: &str) -> Value {
    let r = ctx
        .bearer("GET", &format!("/api/v1/logs/requests{query}"), tok)
        .await;
    r.assert_status_ok();
    r.json()
}

fn urls(v: &Value) -> Vec<String> {
    v["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["url"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn snapshot_needs_stats_read_and_filters() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    seed(&ctx);
    let weak = ctx.token(&admin, &["lists:read"]).await;
    for p in ["/api/v1/logs/requests", "/api/v1/logs/stream"] {
        ctx.bearer("GET", p, &weak).await.assert_status_forbidden();
    }
    let tok = ctx.token(&admin, &["logs:read"]).await;

    let all = snapshot(&ctx, &tok, "").await;
    assert_eq!(all["total"], 4);
    // Newest first, with the full shape.
    assert_eq!(urls(&all)[0], "https://pinned.test");
    let blocked = &all["entries"][2];
    assert_eq!(blocked["action"], "blocked");
    assert_eq!(blocked["mode"], "transparent");
    assert_eq!(blocked["rule"], "||ads.test^");
    assert_eq!(blocked["method"], "GET");
    assert_eq!(all["entries"][3]["status"], 200);

    assert_eq!(
        urls(&snapshot(&ctx, &tok, "?action=allowed").await).len(),
        2
    );
    assert_eq!(
        urls(&snapshot(&ctx, &tok, "?action=blocked").await),
        ["https://ads.test/b.js"]
    );
    assert_eq!(urls(&snapshot(&ctx, &tok, "?mode=explicit").await).len(), 2);
    assert_eq!(urls(&snapshot(&ctx, &tok, "?client=2").await).len(), 2);
    assert_eq!(
        urls(&snapshot(&ctx, &tok, "?q=OTHER").await),
        ["https://other.test/c"]
    );
    assert_eq!(
        urls(&snapshot(&ctx, &tok, "?client=1&action=allowed&mode=explicit").await),
        ["https://good.test/a"]
    );
    let page = snapshot(&ctx, &tok, "?limit=3&page=2").await;
    assert_eq!(
        (urls(&page).len(), page["has_more"].as_bool()),
        (1, Some(false))
    );
    // Unknown enum values are a client error, not an empty result.
    ctx.bearer("GET", "/api/v1/logs/requests?action=nope", &tok)
        .await
        .assert_status_bad_request();
}

/// Serve the router on a real socket (the SSE body never ends, so the in-process transport
/// cannot read it).
async fn serve(ctx: &TestContext) -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let app = ctx
        .router
        .clone()
        .into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move {
        let _ = axum::serve(l, app).await;
    });
    addr
}

/// Read body chunks until `pred` holds for everything received so far.
async fn read_until(resp: &mut reqwest::Response, pred: impl Fn(&str) -> bool) -> String {
    let mut got = String::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !pred(&got) {
            let chunk = resp.chunk().await.unwrap().expect("stream ended");
            got.push_str(&String::from_utf8_lossy(&chunk));
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out; got {got:?}"));
    got
}

#[tokio::test]
async fn stream_delivers_only_matching_events() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let tok = ctx.token(&admin, &["logs:read"]).await;
    let addr = serve(&ctx).await;
    let mut resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/logs/stream?action=blocked&mode=transparent&q=ads"
        ))
        .bearer_auth(&tok)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()["content-type"].to_str().unwrap(),
        "text/event-stream"
    );
    // The response is out, so the handler has subscribed: events recorded now are seen.
    seed(&ctx);
    let e = &ctx.state.shared_engine;
    e.record_request(&ev(
        EventAction::Blocked,
        "https://other-ad.test/",
        "1",
        EventMode::Explicit,
    ));
    e.record_request(&ev(
        EventAction::Blocked,
        "https://ads.test/last.js",
        "1",
        EventMode::Transparent,
    ));
    let got = read_until(&mut resp, |s| s.contains("last.js")).await;
    assert!(got.contains("event: request"), "{got}");
    assert!(got.contains("https://ads.test/b.js"), "{got}");
    // Wrong action, wrong mode and a non-matching `q` never come through.
    for bad in ["good.test", "other.test", "pinned.test", "other-ad.test"] {
        assert!(!got.contains(bad), "{bad} leaked: {got}");
    }
    let data = got
        .lines()
        .find(|l| l.starts_with("data:") && l.contains("b.js"))
        .unwrap();
    let v: Value = serde_json::from_str(data.trim_start_matches("data:").trim()).unwrap();
    assert_eq!(
        (v["action"].as_str(), v["mode"].as_str()),
        (Some("blocked"), Some("transparent"))
    );
}

#[tokio::test]
async fn slow_stream_gets_a_lagged_event_instead_of_an_error() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let tok = ctx.token(&admin, &["logs:read"]).await;
    let addr = serve(&ctx).await;
    let mut resp = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/logs/stream"))
        .bearer_auth(&tok)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    // Current-thread runtime: the server task cannot run during this synchronous burst, so the
    // subscriber falls further behind than the broadcast buffer holds.
    for i in 0..(filter_engine::events::BROADCAST_CAPACITY + 200) {
        ctx.state.shared_engine.record_request(&ev(
            EventAction::Allowed,
            &format!("https://flood.test/{i}"),
            "1",
            EventMode::Explicit,
        ));
    }
    let got = read_until(&mut resp, |s| s.contains("event: lagged")).await;
    let line = got
        .lines()
        .skip_while(|l| !l.starts_with("event: lagged"))
        .nth(1)
        .unwrap();
    let v: Value = serde_json::from_str(line.trim_start_matches("data:").trim()).unwrap();
    assert!(v["skipped"].as_u64().unwrap() >= 200, "{line}");
    // The stream keeps going after the notice.
    ctx.state.shared_engine.record_request(&ev(
        EventAction::Allowed,
        "https://after.test/",
        "1",
        EventMode::Explicit,
    ));
    read_until(&mut resp, |s| s.contains("after.test")).await;
}

// ---- review fixes ----

async fn open_stream(addr: SocketAddr, secret: &str) -> reqwest::Response {
    reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/logs/stream"))
        .bearer_auth(secret)
        .send()
        .await
        .unwrap()
}

/// True once the server ends the stream (EOF) within `within`.
async fn ends(resp: &mut reqwest::Response, within: Duration) -> bool {
    tokio::time::timeout(within, async {
        loop {
            match resp.chunk().await {
                Ok(Some(_)) => {}
                _ => return,
            }
        }
    })
    .await
    .is_ok()
}

#[tokio::test]
async fn stream_ends_when_its_token_is_revoked() {
    let ctx = TestContext::new().await.unwrap();
    ctx.state
        .log_streams
        .set_recheck_every(Duration::from_millis(100));
    let admin = ctx.admin().await;
    let r = admin
        .post("/api/v1/tokens")
        .json(&serde_json::json!({"name": "w", "scopes": ["logs:read"]}))
        .await;
    let v: Value = r.json();
    let (secret, id) = (
        v["secret"].as_str().unwrap().to_string(),
        v["token"]["id"].as_str().unwrap().to_string(),
    );
    let addr = serve(&ctx).await;
    let mut resp = open_stream(addr, &secret).await;
    assert_eq!(resp.status(), 200);
    assert!(
        !ends(&mut resp, Duration::from_millis(400)).await,
        "stream stays open while the token is valid"
    );
    admin
        .delete(&format!("/api/v1/tokens/{id}"))
        .await
        .assert_status_success();
    assert!(
        ends(&mut resp, Duration::from_secs(5)).await,
        "revoked token: stream closed"
    );
}

#[tokio::test]
async fn stream_ends_when_the_user_is_disabled_or_demoted() {
    for demote in [false, true] {
        let ctx = TestContext::new().await.unwrap();
        ctx.state
            .log_streams
            .set_recheck_every(Duration::from_millis(100));
        let admin = ctx.admin().await;
        let user = ctx
            .user(&admin, if demote { "dem" } else { "dis" }, "user")
            .await;
        let secret = ctx.token(&user, &["logs:read"]).await;
        let uid = user.get("/api/v1/auth/me").await.json::<Value>()["id"]
            .as_str()
            .unwrap()
            .to_string();
        let addr = serve(&ctx).await;
        let mut resp = open_stream(addr, &secret).await;
        assert_eq!(resp.status(), 200);
        let body = if demote {
            serde_json::json!({"role": "viewer"})
        } else {
            serde_json::json!({"enabled": false})
        };
        admin
            .patch(&format!("/api/v1/users/{uid}"))
            .json(&body)
            .await
            .assert_status_ok();
        assert!(
            ends(&mut resp, Duration::from_secs(5)).await,
            "demote={demote}: stream closed"
        );
    }
}

#[tokio::test]
async fn stream_slots_are_capped_per_user_and_in_total_and_freed_on_close() {
    let ctx = TestContext::new().await.unwrap();
    ctx.state.log_streams.set(3, 2);
    let admin = ctx.admin().await;
    let other = ctx.user(&admin, "other", "user").await;
    let (ta, to) = (
        ctx.token(&admin, &["logs:read"]).await,
        ctx.token(&other, &["logs:read"]).await,
    );
    let addr = serve(&ctx).await;
    let s1 = open_stream(addr, &ta).await;
    let _s2 = open_stream(addr, &ta).await;
    assert!(s1.status() == 200 && _s2.status() == 200);
    // Per user: the third stream of the same account is refused.
    assert_eq!(open_stream(addr, &ta).await.status(), 429);
    // Another account still fits (total 3) ...
    let _s3 = open_stream(addr, &to).await;
    assert_eq!(_s3.status(), 200);
    // ... and then the server-wide cap is reached.
    assert_eq!(open_stream(addr, &to).await.status(), 429);
    // Closing a stream frees its slot.
    drop(s1);
    let mut freed = false;
    for _ in 0..100 {
        if open_stream(addr, &ta).await.status() == 200 {
            freed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(freed, "slot released after the stream closed");
}

#[tokio::test]
async fn logs_need_logs_read_which_viewers_lack() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let viewer = ctx.user(&admin, "viewer1", "viewer").await;
    let user = ctx.user(&admin, "user001", "user").await;
    viewer
        .get("/api/v1/logs/requests")
        .await
        .assert_status_forbidden();
    user.get("/api/v1/logs/requests").await.assert_status_ok();
    admin.get("/api/v1/logs/requests").await.assert_status_ok();
    // `stats:read` no longer opens the log.
    let tok = ctx.token(&admin, &["stats:read"]).await;
    for p in ["/api/v1/logs/requests", "/api/v1/logs/stream"] {
        ctx.bearer("GET", p, &tok).await.assert_status_forbidden();
    }
    use api_types::{Scope, UserRole};
    assert!(!UserRole::Viewer.scopes().contains(&Scope::LogsRead));
    assert!(UserRole::User.scopes().contains(&Scope::LogsRead));
    assert!(UserRole::Admin.scopes().contains(&Scope::LogsRead));
}

#[tokio::test]
async fn text_filter_uses_the_events_prebuilt_lowercase_text() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let tok = ctx.token(&admin, &["logs:read"]).await;
    let addr = serve(&ctx).await;
    let mut resp = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/logs/stream?q=MiXeD"))
        .bearer_auth(&tok)
        .send()
        .await
        .unwrap();
    ctx.state.shared_engine.record_request(&ev(
        EventAction::Allowed,
        "https://Example.test/MIXED/Path",
        "1",
        EventMode::Explicit,
    ));
    let got = read_until(&mut resp, |s| s.contains("MIXED/Path")).await;
    assert!(got.contains("event: request"), "{got}");
}

#[tokio::test]
async fn error_events_carry_a_machine_readable_error_kind_in_both_endpoints() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let tok = ctx.token(&admin, &["logs:read"]).await;
    let kinds = [
        filter_engine::ErrorKind::ClientRejectedCert,
        filter_engine::ErrorKind::UpstreamTimeout,
        filter_engine::ErrorKind::UpstreamReset,
        filter_engine::ErrorKind::UpstreamTls,
        filter_engine::ErrorKind::Other,
    ];
    let addr = serve(&ctx).await;
    let mut resp = open_stream(addr, &tok).await;
    for (i, k) in kinds.iter().enumerate() {
        let url = format!("https://err{i}.test");
        let mut e = ev(EventAction::Error, &url, "1", EventMode::Explicit);
        e.error_kind = Some(*k);
        ctx.state.shared_engine.record_request(&e);
    }
    ctx.state.shared_engine.record_request(&ev(
        EventAction::Allowed,
        "https://fine.test/",
        "1",
        EventMode::Explicit,
    ));
    let snap = snapshot(&ctx, &tok, "?action=error").await;
    let got: Vec<_> = snap["entries"]
        .as_array()
        .unwrap()
        .iter()
        .rev()
        .map(|e| e["error_kind"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        got,
        [
            "client_rejected_cert",
            "upstream_timeout",
            "upstream_reset",
            "upstream_tls",
            "other"
        ]
    );
    // Non-error events have none.
    let all = snapshot(&ctx, &tok, "?action=allowed").await;
    assert_eq!(all["entries"][0]["error_kind"], Value::Null);
    // The live stream carries the same field.
    let text = read_until(&mut resp, |s| s.contains("fine.test")).await;
    assert!(
        text.contains("\"error_kind\":\"client_rejected_cert\""),
        "{text}"
    );
}

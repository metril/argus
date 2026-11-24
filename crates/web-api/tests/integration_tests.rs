//! Functional tests for the v1 API: health, auth flows, config, lists, rules, stats, userscripts,
//! users, sessions, audit and the shared conventions (error envelope, pagination, ETag).

mod common;

use axum::http::StatusCode;
use common::{extract_access_token, extract_refresh_token, TestContext, PASSWORD};
use cookie::Cookie;
use serde_json::{json, Value};

const SCRIPT: &str = r#"
// ==UserScript==
// @name        Test Script
// @namespace   test
// @version     1.0.0
// @description A test userscript
// @match       *://*.example.com/*
// @grant       none
// ==/UserScript==

console.log("Hello from test script!");
"#;

// ---------------------------------------------------------------- health / public

#[tokio::test]
async fn health_and_public_routes_need_no_credentials() {
    let ctx = TestContext::new().await.unwrap();
    let r = ctx.server.get("/api/v1/health").await;
    r.assert_status_ok();
    assert_eq!(r.json::<Value>()["status"], "healthy");
    // CA may or may not exist in the test env, but auth must never reject it.
    let ca = ctx.server.get("/api/v1/ca.crt").await.status_code();
    assert_ne!(ca, StatusCode::UNAUTHORIZED);
    assert_ne!(ca, StatusCode::FORBIDDEN);
    ctx.server
        .get("/api/v1/openapi.json")
        .await
        .assert_status_ok();
    ctx.server.get("/api/v1/docs/").await.assert_status_ok();
}

#[tokio::test]
async fn metrics_require_system_read() {
    let ctx = TestContext::new().await.unwrap();
    ctx.server
        .get("/api/v1/system/metrics")
        .await
        .assert_status_unauthorized();
    let admin = ctx.admin().await;
    let r = admin.get("/api/v1/system/metrics").await;
    r.assert_status_ok();
    assert!(r.json::<Value>()["proxy"]["connections"]["total"].is_number());
    let m: Value = admin.get("/api/v1/system/metrics").await.json();
    assert_eq!(m["storage"]["deferred_dropped"], 0);
    assert_eq!(m["storage"]["deferred_failed"], 0);
    let p = admin.get("/api/v1/system/metrics/prometheus").await;
    p.assert_status_ok();
    assert!(p.text().contains("argus_filter_blocked_total"));
    assert!(p.text().contains("argus_db_deferred_dropped_total"));
    admin.get("/api/v1/system/status").await.assert_status_ok();
}

#[tokio::test]
async fn old_unversioned_paths_are_gone_with_envelope_404() {
    let ctx = TestContext::new().await.unwrap();
    let r = ctx.server.get("/api/health").await;
    r.assert_status_not_found();
    assert_eq!(r.json::<Value>()["error"]["code"], "not_found");
}

// ---------------------------------------------------------------- auth

#[tokio::test]
async fn first_user_is_admin_and_registration_then_closes() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let me = admin.get("/api/v1/auth/me").await;
    me.assert_status_ok();
    let me: Value = me.json();
    assert_eq!(me["role"], "admin");
    assert!(me["scopes"].as_array().unwrap().len() > 20);

    let second = ctx
        .server
        .post("/api/v1/auth/register")
        .json(&json!({"username": "second", "password": PASSWORD, "password_confirm": PASSWORD}))
        .await;
    second.assert_status_forbidden();
    assert_eq!(
        second.json::<Value>()["error"]["code"],
        "registration_closed"
    );
}

#[tokio::test]
async fn register_validates_with_field_details() {
    let ctx = TestContext::new().await.unwrap();
    let r = ctx
        .server
        .post("/api/v1/auth/register")
        .json(&json!({"username": "ab", "password": "weak", "password_confirm": "weak"}))
        .await;
    r.assert_status_bad_request();
    let body: Value = r.json();
    assert_eq!(body["error"]["code"], "validation_failed");
    let fields: Vec<&str> = body["error"]["details"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["field"].as_str().unwrap())
        .collect();
    assert!(
        fields.contains(&"username") && fields.contains(&"password"),
        "{fields:?}"
    );
}

#[tokio::test]
async fn malformed_body_uses_error_envelope() {
    let ctx = TestContext::new().await.unwrap();
    let r = ctx
        .server
        .post("/api/v1/auth/login")
        .bytes("{not json".into())
        .content_type("application/json")
        .await;
    r.assert_status_bad_request();
    assert_eq!(r.json::<Value>()["error"]["code"], "invalid_body");
}

#[tokio::test]
async fn login_wrong_password_and_unknown_user() {
    let ctx = TestContext::new().await.unwrap();
    ctx.admin().await;
    for (u, p) in [
        ("admin_user", "WrongPassword123!"),
        ("nobody_here", PASSWORD),
    ] {
        let r = ctx
            .server
            .post("/api/v1/auth/login")
            .json(&json!({"username": u, "password": p}))
            .await;
        r.assert_status_unauthorized();
        assert_eq!(r.json::<Value>()["error"]["code"], "unauthorized");
    }
}

#[tokio::test]
async fn logout_ends_the_session_immediately() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let out = admin.post("/api/v1/auth/logout").await;
    out.assert_status_ok();
    assert!(out
        .headers()
        .get_all("set-cookie")
        .iter()
        .any(|c| c.to_str().unwrap().contains("Max-Age=0")));
    admin
        .get("/api/v1/auth/me")
        .await
        .assert_status_unauthorized();
}

#[tokio::test]
async fn refresh_rotates_and_replay_revokes_the_session() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let r = ctx
        .server
        .post("/api/v1/auth/refresh")
        .add_cookie(Cookie::new("refresh_token", admin.refresh.clone()))
        .await;
    r.assert_status_ok();
    let new_access = extract_access_token(&r).unwrap();
    assert!(extract_refresh_token(&r).is_some());
    ctx.server
        .get("/api/v1/auth/me")
        .add_cookie(Cookie::new("access_token", new_access.clone()))
        .await
        .assert_status_ok();

    // Replaying the old refresh token is treated as theft: the session dies.
    let replay = ctx
        .server
        .post("/api/v1/auth/refresh")
        .add_cookie(Cookie::new("refresh_token", admin.refresh.clone()))
        .await;
    replay.assert_status_unauthorized();
    ctx.server
        .get("/api/v1/auth/me")
        .add_cookie(Cookie::new("access_token", new_access))
        .await
        .assert_status_unauthorized();
}

#[tokio::test]
async fn change_password_signs_out_other_sessions() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let other = ctx.login("admin_user").await;

    let bad = admin
        .post("/api/v1/auth/password")
        .json(&json!({"current_password": "WrongPassword123!", "new_password": "NewPassword456!"}))
        .await;
    bad.assert_status_forbidden();

    admin
        .post("/api/v1/auth/password")
        .json(&json!({"current_password": PASSWORD, "new_password": "NewPassword456!"}))
        .await
        .assert_status_ok();
    admin.get("/api/v1/auth/me").await.assert_status_ok();
    other
        .get("/api/v1/auth/me")
        .await
        .assert_status_unauthorized();
    ctx.server
        .post("/api/v1/auth/login")
        .json(&json!({"username": "admin_user", "password": "NewPassword456!"}))
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn sessions_list_and_revoke_self_and_admin() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let bob = ctx.user(&admin, "bob_user", "user").await;

    let mine: Value = bob.get("/api/v1/auth/sessions").await.json();
    assert_eq!(mine["total"], 1);
    assert_eq!(mine["items"][0]["current"], true);
    let bob_sid = mine["items"][0]["id"].as_str().unwrap().to_string();

    // Bob cannot use the admin listing; admin sees both users' sessions.
    bob.get("/api/v1/admin/sessions")
        .await
        .assert_status_forbidden();
    let all: Value = admin.get("/api/v1/admin/sessions").await.json();
    assert_eq!(all["total"], 2);

    // Bob cannot revoke the admin's session through the self route (404, not found for him).
    let admin_sid = all["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["username"] == "admin_user")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    bob.delete(&format!("/api/v1/auth/sessions/{admin_sid}"))
        .await
        .assert_status_not_found();

    admin
        .delete(&format!("/api/v1/admin/sessions/{bob_sid}"))
        .await
        .assert_status_ok();
    bob.get("/api/v1/auth/me")
        .await
        .assert_status_unauthorized();
}

#[tokio::test]
async fn sessions_survive_restart_and_revocation_is_durable() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let keep = ctx.login("admin_user").await;
    let revoked = ctx.login("admin_user").await;
    revoked.post("/api/v1/auth/logout").await.assert_status_ok();
    let path = ctx.api_config.session.storage_path.clone();
    let secret_path = ctx.api_config.auth.jwt_secret_path.clone();
    let (a, k, r) = (
        admin.access.clone(),
        keep.access.clone(),
        revoked.access.clone(),
    );
    drop(admin);
    drop(keep);
    drop(revoked);
    drop(ctx.server);
    drop(ctx.router);
    drop(ctx.state);

    // Re-open the same on-disk stores in a fresh state.
    let mut cfg = web_api::config::ApiConfig::default();
    cfg.session.storage_path = path;
    cfg.auth.bcrypt_cost = 4;
    cfg.auth.jwt_secret_path = secret_path;
    let engine = std::sync::Arc::new(filter_engine::SharedEngine::new());
    let store = web_api::ListStore::open(&ctx.temp_dir.path().join("filters2")).unwrap();
    let client = reqwest::Client::new();
    let svc = web_api::ListService::new(
        web_api::ListServiceConfig::default(),
        store,
        engine.clone(),
        client.clone(),
    );
    let mgr = std::sync::Arc::new(
        userscript_engine::UserscriptManager::new(ctx.temp_dir.path().join("us2")).unwrap(),
    );
    let storage = std::sync::Arc::new(
        userscript_engine::UserscriptStorage::new(ctx.temp_dir.path().join("uss2")).unwrap(),
    );
    let rt = std::sync::Arc::new(userscript_engine::UserscriptRuntime::new(
        mgr.clone(),
        storage,
    ));
    let state = web_api::state::build_state(
        cfg.clone(),
        ::common::config::ProxyConfig::default(),
        engine,
        svc,
        client,
        mgr,
        rt,
        ctx.temp_dir.path().join("proxy.toml"),
        std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1)),
    )
    .await
    .unwrap();
    let server = axum_test::TestServer::new(web_api::create_router(state, &cfg)).unwrap();
    for (tok, expect) in [(a, true), (k, true), (r, false)] {
        let resp = server
            .get("/api/v1/auth/me")
            .add_cookie(Cookie::new("access_token", tok))
            .await;
        assert_eq!(resp.status_code() == StatusCode::OK, expect);
    }
}

// ---------------------------------------------------------------- users

#[tokio::test]
async fn user_management_and_last_admin_protection() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let bob = ctx.user(&admin, "bob_user", "user").await;
    let bob_id = bob.get("/api/v1/auth/me").await.json::<Value>()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let admin_id = admin.get("/api/v1/auth/me").await.json::<Value>()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let list: Value = admin.get("/api/v1/users").await.json();
    assert_eq!(list["total"], 2);
    bob.get("/api/v1/users").await.assert_status_forbidden();

    // Duplicate usernames conflict.
    let dup = admin
        .post("/api/v1/users")
        .json(&json!({"username": "bob_user", "password": PASSWORD, "role": "viewer"}))
        .await;
    assert_eq!(dup.status_code(), StatusCode::CONFLICT);

    // The last admin can be neither demoted, disabled nor deleted.
    for body in [json!({"role": "user"}), json!({"enabled": false})] {
        let r = admin
            .patch(&format!("/api/v1/users/{admin_id}"))
            .json(&body)
            .await;
        assert_eq!(r.status_code(), StatusCode::CONFLICT);
        assert_eq!(r.json::<Value>()["error"]["code"], "last_admin");
    }
    assert_eq!(
        admin
            .delete(&format!("/api/v1/users/{admin_id}"))
            .await
            .status_code(),
        StatusCode::CONFLICT
    );

    // Promote Bob, and then the original admin may be demoted.
    admin
        .patch(&format!("/api/v1/users/{bob_id}"))
        .json(&json!({"role": "admin"}))
        .await
        .assert_status_ok();
    admin
        .patch(&format!("/api/v1/users/{admin_id}"))
        .json(&json!({"role": "viewer"}))
        .await
        .assert_status_ok();
    // Role changes apply to existing sessions at once.
    admin.get("/api/v1/users").await.assert_status_forbidden();

    // Disabling a user kills their sessions; deleting removes the account.
    bob.patch(&format!("/api/v1/users/{admin_id}"))
        .json(&json!({"role": "admin"}))
        .await
        .assert_status_ok();
    admin
        .patch(&format!("/api/v1/users/{bob_id}"))
        .json(&json!({"enabled": false}))
        .await
        .assert_status_ok();
    bob.get("/api/v1/auth/me")
        .await
        .assert_status_unauthorized();
    admin
        .delete(&format!("/api/v1/users/{bob_id}"))
        .await
        .assert_status_ok();
    admin
        .get(&format!("/api/v1/users/{bob_id}"))
        .await
        .assert_status_not_found();
}

// ---------------------------------------------------------------- config

#[tokio::test]
async fn config_get_update_with_etag() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let got = admin.get("/api/v1/config").await;
    got.assert_status_ok();
    let etag = got.header("etag").to_str().unwrap().to_string();
    assert!(got.json::<Value>()["port"].is_number());

    // No If-Match -> 428; stale -> 412; correct -> 200 and a new ETag.
    let body = json!({"port": 9090, "max_connections": 2000});
    let r = admin.put("/api/v1/config").json(&body).await;
    assert_eq!(r.status_code(), StatusCode::PRECONDITION_REQUIRED);
    assert_eq!(r.json::<Value>()["error"]["code"], "precondition_required");
    let r = admin
        .put("/api/v1/config")
        .add_header("if-match", "\"stale\"")
        .json(&body)
        .await;
    assert_eq!(r.status_code(), StatusCode::PRECONDITION_FAILED);
    let ok = admin
        .put("/api/v1/config")
        .add_header("if-match", etag.clone())
        .json(&body)
        .await;
    ok.assert_status_ok();
    assert_eq!(ok.json::<Value>()["port"], 9090);
    assert_ne!(ok.header("etag").to_str().unwrap(), etag);
    // The old ETag is now stale (lost-update protection).
    let again = admin
        .put("/api/v1/config")
        .add_header("if-match", etag)
        .json(&body)
        .await;
    assert_eq!(again.status_code(), StatusCode::PRECONDITION_FAILED);
}

/// `max_connections = 0` (auto) reports the derived number; saving the echoed value back leaves
/// the stored setting at 0, while a different value pins it.
#[tokio::test]
async fn max_connections_auto_reports_derived_value_and_is_not_pinned_by_saving() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let derived = ::common::config::derive_max_connections() as u64;
    assert_eq!(
        ctx.state
            .proxy_state
            .config
            .read()
            .performance
            .max_connections,
        0
    );

    let got = admin.get("/api/v1/config").await;
    got.assert_status_ok();
    assert_eq!(got.json::<Value>()["max_connections"], derived);

    // The dashboard echoes the effective value back with another edit.
    let r = put_config(
        &admin,
        json!({"max_connections": derived, "request_timeout_secs": 45}),
    )
    .await;
    r.assert_status_ok();
    let body = r.json::<Value>();
    assert_eq!(body["max_connections"], derived);
    assert_eq!(body["restart_required"], json!([]));
    assert_eq!(
        ctx.state
            .proxy_state
            .config
            .read()
            .performance
            .max_connections,
        0
    );
    // Saved to the overlay (only what differs from the base file); the base is untouched.
    let overlay = ctx.state.overlay_path.read().clone();
    let saved = std::fs::read_to_string(&overlay).unwrap();
    assert!(saved.contains("request_timeout_secs = 45"), "{saved}");
    assert!(!saved.contains("max_connections"), "{saved}");
    let base = std::fs::read_to_string(ctx.temp_dir.path().join("proxy.toml")).unwrap();
    assert!(!base.contains("request_timeout_secs = 45"), "{base}");

    let r = put_config(&admin, json!({"max_connections": derived - 1})).await;
    r.assert_status_ok();
    assert_eq!(
        r.json::<Value>()["restart_required"],
        json!(["max_connections"])
    );
    assert_eq!(
        ctx.state
            .proxy_state
            .config
            .read()
            .performance
            .max_connections,
        derived as usize - 1
    );
}

async fn put_config(sess: &common::Sess, body: Value) -> axum_test::TestResponse {
    let etag = sess
        .get("/api/v1/config")
        .await
        .header("etag")
        .to_str()
        .unwrap()
        .to_string();
    sess.put("/api/v1/config")
        .add_header("if-match", etag)
        .json(&body)
        .await
}

#[tokio::test]
async fn config_reports_restart_required_and_validates() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let r = put_config(
        &admin,
        json!({
            "transparent_port": 3129,
            "tls_passthrough_hosts": ["bank.example", "*.pinned.example"],
            "block_private_destinations": true,
            "allowed_destinations": ["10.0.0.0/8"],
            "allowed_clients": ["192.168.0.0/16", "fd00::/8"]
        }),
    )
    .await;
    r.assert_status_ok();
    let body: Value = r.json();
    assert_eq!(
        body["restart_required"],
        json!([
            "transparent_port",
            "tls_passthrough_hosts",
            "block_private_destinations",
            "allowed_destinations",
            "allowed_clients"
        ])
    );
    assert_eq!(body["applied"], json!([]));
    let again = put_config(
        &admin,
        json!({"block_private_destinations": true, "transparent_port": 0}),
    )
    .await;
    assert_eq!(
        again.json::<Value>()["restart_required"],
        json!(["transparent_port"])
    );
    assert_eq!(
        put_config(&admin, json!({"allowed_clients": ["10.0.0.0/33"]}))
            .await
            .status_code(),
        400
    );
    assert_eq!(
        put_config(&admin, json!({"port": 0})).await.status_code(),
        400
    );
}

#[tokio::test]
async fn config_applies_live_settings() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    assert!(ctx.state.shared_engine.is_enabled());
    let r = put_config(
        &admin,
        json!({"enable_adblock": false, "request_timeout_secs": 7, "auto_update": false,
               "update_interval_hours": 2, "port": 9191}),
    )
    .await;
    r.assert_status_ok();
    let body: Value = r.json();
    let applied: Vec<&str> = body["applied"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    for f in [
        "enable_adblock",
        "request_timeout_secs",
        "auto_update",
        "update_interval_hours",
    ] {
        assert!(applied.contains(&f), "{f}: {applied:?}");
    }
    assert_eq!(body["restart_required"], json!(["port"]));
    assert!(!ctx.state.shared_engine.is_enabled());
    assert_eq!(
        ctx.state
            .proxy_state
            .request_timeout_ms
            .load(std::sync::atomic::Ordering::Relaxed),
        7000
    );
    assert_eq!(
        ctx.state.list_service.schedule(),
        (false, std::time::Duration::from_secs(2 * 3600))
    );
    admin.post("/api/v1/config/reload").await.assert_status_ok();
}

#[tokio::test]
async fn schedule_get_and_set() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    admin
        .put("/api/v1/lists/schedule")
        .json(&json!({"auto_update": true, "interval_hours": 6}))
        .await
        .assert_status_ok();
    let s: Value = admin.get("/api/v1/lists/schedule").await.json();
    assert_eq!(s, json!({"auto_update": true, "interval_hours": 6}));
    assert_eq!(
        admin
            .put("/api/v1/lists/schedule")
            .json(&json!({"interval_hours": 0}))
            .await
            .status_code(),
        400
    );
}

#[tokio::test]
async fn proxy_stats_and_filter_stats() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let p: Value = admin.get("/api/v1/stats/proxy").await.json();
    assert!(p["connections"]["total"].is_number());
    // Upstream/DNS/policy failures are visible in the API, not only in debug logs.
    ::common::faults::note(::common::faults::Fault::UpstreamTimeout, "slow.test");
    ::common::faults::note(::common::faults::Fault::DnsFailure, "nx.test");
    ::common::faults::note(::common::faults::Fault::PolicyRefusal, "lo.test");
    ::common::faults::note(::common::faults::Fault::UpstreamError, "bad.test");
    let p: Value = admin.get("/api/v1/stats/proxy").await.json();
    for k in [
        "upstream_timeouts",
        "upstream_errors",
        "dns_failures",
        "destination_refusals",
    ] {
        assert!(p["faults"][k].as_u64().unwrap() >= 1, "{k}: {p}");
    }
    let f: Value = admin.get("/api/v1/stats/filter").await.json();
    assert!(f["total_requests"].is_number() && f["top_blocked_domains"].is_array());
    let recent: Value = admin.get("/api/v1/stats/blocked/recent").await.json();
    assert_eq!(recent["total"], 0);
    assert!(recent["entries"].is_array());
}

// ---------------------------------------------------------------- lists

#[tokio::test]
async fn list_urls_to_internal_destinations_are_refused_with_a_stable_code() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    for url in [
        "http://[::1]/x.txt",
        "https://[::ffff:127.0.0.1]/x.txt",
        "https://[fd00::1]/x.txt",
        "https://[fe80::1]/x.txt",
        "http://10.0.0.1/x.txt",
        "http://100.64.0.1/x.txt",
        "http://169.254.169.254/latest/meta-data",
        // A name that resolves to loopback.
        "https://localhost/x.txt",
    ] {
        let resp = admin
            .post("/api/v1/lists")
            .json(&json!({"id": "t", "name": "T", "url": url}))
            .await;
        resp.assert_status_bad_request();
        let body: Value = resp.json();
        assert_eq!(
            body["error"]["code"], "fetch_destination_not_allowed",
            "{url}: {body}"
        );
    }
    for url in ["ftp://example.com/x.txt", "file:///etc/passwd"] {
        let resp = admin
            .post("/api/v1/lists")
            .json(&json!({"id": "t", "name": "T", "url": url}))
            .await;
        resp.assert_status_bad_request();
        let body: Value = resp.json();
        assert_eq!(body["error"]["code"], "invalid_fetch_url", "{url}: {body}");
    }
    // The same applies when changing the URL of an existing list.
    admin
        .post("/api/v1/lists")
        .json(&json!({"id": "ok", "name": "Ok", "url": "https://example.com/x.txt", "enabled": false}))
        .await
        .assert_status(StatusCode::CREATED);
    admin
        .put("/api/v1/lists/ok")
        .json(&json!({"url": "http://[::1]:8080/x"}))
        .await
        .assert_status_bad_request();
}

#[tokio::test]
async fn lists_ssrf_protection_and_crud() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    for url in ["http://localhost/f.txt", "https://192.168.1.1/f.txt"] {
        admin
            .post("/api/v1/lists")
            .json(&json!({"id": "t", "name": "T", "url": url}))
            .await
            .assert_status_bad_request();
    }
    let add = admin
        .post("/api/v1/lists")
        .json(&json!({"id": "my-list", "name": "Mine", "url": "https://example.com/x.txt", "enabled": false}))
        .await;
    assert_eq!(add.status_code(), StatusCode::CREATED);
    let dup = admin
        .post("/api/v1/lists")
        .json(&json!({"id": "my-list", "name": "Dup", "url": "https://example.com/x.txt"}))
        .await;
    assert_eq!(dup.status_code(), StatusCode::CONFLICT);

    let page: Value = admin.get("/api/v1/lists?limit=1").await.json();
    assert_eq!(page["limit"], 1);
    assert!(page["total"].as_u64().unwrap() >= 1);
    assert!(page["items"].as_array().unwrap().len() <= 1);
    let status: Value = admin.get("/api/v1/lists/my-list/status").await.json();
    assert_eq!(status["id"], "my-list");

    let upd: Value = admin
        .put("/api/v1/lists/my-list")
        .json(&json!({"name": "Renamed"}))
        .await
        .json();
    assert_eq!(upd["name"], "Renamed");
    admin
        .post("/api/v1/lists/my-list/refresh")
        .await
        .assert_status(StatusCode::ACCEPTED);
    admin
        .post("/api/v1/lists/refresh")
        .await
        .assert_status(StatusCode::ACCEPTED);
    admin
        .post("/api/v1/lists/nope/refresh")
        .await
        .assert_status_not_found();
    admin
        .delete("/api/v1/lists/my-list")
        .await
        .assert_status_ok();
    admin
        .get("/api/v1/lists/my-list")
        .await
        .assert_status_not_found();
}

// ---------------------------------------------------------------- rules / engine

#[tokio::test]
async fn custom_rules_use_if_match() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let got = admin.get("/api/v1/rules/custom").await;
    assert_eq!(got.json::<Value>()["rules"], "");
    let etag = got.header("etag").to_str().unwrap().to_string();

    let body = json!({"rules": "||my.ads^\n@@||good.example^"});
    assert_eq!(
        admin
            .put("/api/v1/rules/custom")
            .json(&body)
            .await
            .status_code(),
        StatusCode::PRECONDITION_REQUIRED
    );
    admin
        .put("/api/v1/rules/custom")
        .add_header("if-match", etag.clone())
        .json(&body)
        .await
        .assert_status_ok();
    assert_eq!(
        admin
            .put("/api/v1/rules/custom")
            .add_header("if-match", etag)
            .json(&body)
            .await
            .status_code(),
        StatusCode::PRECONDITION_FAILED
    );
    assert_eq!(
        admin.get("/api/v1/rules/custom").await.json::<Value>()["rules"],
        "||my.ads^\n@@||good.example^"
    );
}

#[tokio::test]
async fn rules_validate_and_url_test_do_not_install() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let v: Value = admin
        .post("/api/v1/rules/validate")
        .json(&json!({"rules": "! c\n||ads.example^\nexample.com##.banner\n"}))
        .await
        .json();
    assert_eq!(v["rejected"], 0);
    assert_eq!(v["accepted"], 2);
    assert_eq!(v["lines"][0]["line"], 2);
    // Nothing was stored.
    assert_eq!(
        admin.get("/api/v1/rules/custom").await.json::<Value>()["rules"],
        ""
    );

    // Install a real engine and test a URL against it.
    ctx.state
        .shared_engine
        .install(filter_engine::compile_engine(&[
            "||ads.example.com^\n".to_string()
        ]));
    let t: Value = admin
        .post("/api/v1/rules/test")
        .json(&json!({"url": "https://ads.example.com/x.js", "source_url": "https://site.example/", "resource_type": "script"}))
        .await
        .json();
    assert_eq!(t["blocked"], true);
    assert_eq!(t["matched_rule"], "||ads.example.com^");
    let ok: Value = admin
        .post("/api/v1/rules/test")
        .json(&json!({"url": "https://fine.example/x.js"}))
        .await
        .json();
    assert_eq!(ok["blocked"], false);
    // Stats are not touched by dry-run tests.
    assert_eq!(ctx.state.filter_stats.snapshot().total_requests, 0);
}

#[tokio::test]
async fn engine_status_and_reload() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let s: Value = admin.get("/api/v1/engine/status").await.json();
    assert!(s["build_count"].is_number() && s["building"].is_boolean());
    let r = admin.post("/api/v1/engine/reload").await;
    r.assert_status(StatusCode::ACCEPTED);
    assert_eq!(r.json::<Value>()["building"], true);
}

#[tokio::test]
async fn reset_stats_requires_admin_scope() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let bob = ctx.user(&admin, "bob_user", "user").await;
    bob.post("/api/v1/stats/filter/reset")
        .await
        .assert_status_forbidden();
    admin
        .post("/api/v1/stats/filter/reset")
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn viewer_can_read_but_not_write() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let v = ctx.user(&admin, "viewer_user", "viewer").await;
    v.get("/api/v1/lists").await.assert_status_ok();
    let w = v
        .post("/api/v1/lists")
        .json(&json!({"id": "x", "name": "X", "url": "https://example.com/x.txt"}))
        .await;
    w.assert_status_forbidden();
    let b: Value = w.json();
    assert_eq!(b["error"]["code"], "insufficient_scope");
    assert!(b["error"]["message"]
        .as_str()
        .unwrap()
        .contains("lists:write"));
    v.get("/api/v1/tokens").await.assert_status_forbidden();
}

// ---------------------------------------------------------------- userscripts

#[tokio::test]
async fn userscript_lifecycle() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let r = admin
        .post("/api/v1/userscripts")
        .json(&json!({"source": SCRIPT}))
        .await;
    assert_eq!(r.status_code(), StatusCode::CREATED);
    let created: Value = r.json();
    assert_eq!(created["name"], "Test Script");
    let id = created["id"]
        .as_str()
        .unwrap()
        .replace(' ', "%20")
        .replace(':', "%3A");

    assert_eq!(
        admin.get("/api/v1/userscripts").await.json::<Value>()["total"],
        1
    );
    assert!(admin
        .get(&format!("/api/v1/userscripts/{id}/source"))
        .await
        .json::<Value>()["source"]
        .as_str()
        .unwrap()
        .contains("Hello"));
    let en: Value = admin
        .put(&format!("/api/v1/userscripts/{id}/enabled"))
        .json(&json!({"enabled": false}))
        .await
        .json();
    assert_eq!(en["enabled"], false);
    assert_eq!(
        admin.get("/api/v1/userscripts/stats").await.json::<Value>()["total_scripts"],
        1
    );
    admin
        .delete(&format!("/api/v1/userscripts/{id}"))
        .await
        .assert_status_ok();
    admin
        .get(&format!("/api/v1/userscripts/{id}"))
        .await
        .assert_status_not_found();
}

#[tokio::test]
async fn userscript_rejects_bad_sources() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    for src in ["console.log('no metadata');", ""] {
        admin
            .post("/api/v1/userscripts")
            .json(&json!({"source": src}))
            .await
            .assert_status_bad_request();
    }
}

// ---------------------------------------------------------------- CA

#[tokio::test]
async fn ca_info_and_downloads() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    // Generate a CA and point the config at it.
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Test CA");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let cert = params.self_signed(&key).unwrap();
    let path = ctx.temp_dir.path().join("ca.crt");
    std::fs::write(&path, cert.pem()).unwrap();
    ctx.state.proxy_state.config.write().mitm.ca_cert_path = path;

    let info: Value = admin.get("/api/v1/ca").await.json();
    assert!(info["subject"].as_str().unwrap().contains("Test CA"));
    assert_eq!(info["fingerprint_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(info["expired"], false);
    let pem = ctx.server.get("/api/v1/ca.crt").await;
    pem.assert_status_ok();
    assert!(pem.text().contains("BEGIN CERTIFICATE"));
    let der = ctx.server.get("/api/v1/ca.der").await;
    der.assert_status_ok();
    assert_eq!(der.as_bytes().as_ref(), cert.der().as_ref());
}

// ---------------------------------------------------------------- pagination / request id

#[tokio::test]
async fn pagination_is_uniform_and_request_id_is_echoed() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    for n in 0..3 {
        ctx.user(&admin, &format!("user_{n}"), "viewer").await;
    }
    let p1: Value = admin.get("/api/v1/users?limit=2&page=1").await.json();
    let p2: Value = admin.get("/api/v1/users?limit=2&page=2").await.json();
    assert_eq!(
        (
            p1["total"].clone(),
            p1["items"].as_array().unwrap().len(),
            p1["has_more"].clone()
        ),
        (json!(4), 2, json!(true))
    );
    assert_eq!(
        (
            p2["items"].as_array().unwrap().len(),
            p2["has_more"].clone()
        ),
        (2, json!(false))
    );
    admin
        .get("/api/v1/users?limit=abc")
        .await
        .assert_status_bad_request();

    let r = ctx
        .server
        .get("/api/v1/health")
        .add_header("x-request-id", "req-123")
        .await;
    assert_eq!(r.header("x-request-id"), "req-123");
    assert!(ctx
        .server
        .get("/api/v1/health")
        .await
        .headers()
        .contains_key("x-request-id"));
}

// ---------------------------------------------------------------- audit

#[tokio::test]
async fn audit_records_changes_without_secrets() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    admin
        .post("/api/v1/lists")
        .json(&json!({"id": "aud", "name": "Aud", "url": "https://example.com/x.txt"}))
        .await
        .assert_status(StatusCode::CREATED);
    let secret = ctx.token(&admin, &["lists:read"]).await;
    ctx.bearer("POST", "/api/v1/lists/refresh", &secret)
        .await
        .assert_status_forbidden();

    let log: Value = admin.get("/api/v1/audit?limit=100").await.json();
    let items = log["items"].as_array().unwrap();
    let find = |route: &str, status: u64| {
        items
            .iter()
            .find(|e| e["route"] == route && e["status"] == status)
            .unwrap_or_else(|| panic!("no audit entry for {route} {status}: {log}"))
            .clone()
    };
    let add = find("/api/v1/lists", 201);
    assert_eq!(add["actor_type"], "user");
    assert_eq!(add["actor_name"], "admin_user");
    assert_eq!(add["scope"], "lists:write");
    assert_eq!(add["method"], "POST");
    assert!(add["request_id"].is_string());
    let denied = find("/api/v1/lists/refresh", 403);
    assert_eq!(denied["actor_type"], "token");
    assert_eq!(denied["outcome"], "denied");
    // Login is audited with the named actor; secrets never appear.
    assert!(items
        .iter()
        .any(|e| e["route"] == "/api/v1/auth/register" && e["actor_name"] == "admin_user"));
    assert!(!log.to_string().contains(&secret) && !log.to_string().contains(PASSWORD));

    // Filtering and the scope gate on the audit log itself.
    let only: Value = admin.get("/api/v1/audit?outcome=denied").await.json();
    assert!(only["items"]
        .as_array()
        .unwrap()
        .iter()
        .all(|e| e["outcome"] == "denied"));
    let bob = ctx.user(&admin, "bob_user", "user").await;
    bob.get("/api/v1/audit").await.assert_status_forbidden();
}

#[tokio::test]
async fn audit_log_is_bounded() {
    let ctx = TestContext::with_config(|c| c.audit.max_entries = 5)
        .await
        .unwrap();
    let admin = ctx.admin().await;
    for _ in 0..140 {
        admin
            .post("/api/v1/stats/filter/reset")
            .await
            .assert_status_ok();
    }
    ctx.state.audit.prune();
    assert!(ctx.state.audit.len() <= 5);
}

// ---------------------------------------------------------------- formats, reports, catalogue

#[tokio::test]
async fn list_format_allowlist_and_catalogue() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let add = admin
        .post("/api/v1/lists")
        .json(
            &json!({"id": "h", "name": "H", "url": "https://example.com/h.txt",
            "enabled": false, "format": "hosts", "allowlist": true}),
        )
        .await;
    assert_eq!(add.status_code(), StatusCode::CREATED);
    let l: Value = add.json();
    assert_eq!(
        (l["format"].as_str(), l["allowlist"].as_bool()),
        (Some("hosts"), Some(true))
    );
    admin
        .post("/api/v1/lists")
        .json(&json!({"id": "bad", "name": "B", "url": "https://example.com/b.txt", "format": "nope"}))
        .await
        .assert_status_bad_request();
    let u: Value = admin
        .put("/api/v1/lists/h")
        .json(&json!({"format": "auto", "allowlist": false}))
        .await
        .json();
    assert_eq!(
        (u["format"].as_str(), u["allowlist"].as_bool()),
        (Some("auto"), Some(false))
    );

    let cat: Value = admin.get("/api/v1/lists/catalogue").await.json();
    assert_eq!(cat["source"], "builtin");
    assert!(cat["fetched_at"].is_null());
    let cat = cat["entries"].as_array().unwrap();
    assert!(cat.len() >= 10 && cat.iter().all(|e| e["added"] == false));
    let added = admin.post("/api/v1/lists/catalogue/adaway").await;
    assert_eq!(added.status_code(), StatusCode::CREATED);
    let a: Value = added.json();
    assert_eq!(
        (a["format"].as_str(), a["enabled"].as_bool()),
        (Some("hosts"), Some(true))
    );
    assert_eq!(
        admin
            .post("/api/v1/lists/catalogue/adaway")
            .await
            .status_code(),
        StatusCode::CONFLICT
    );
    admin
        .post("/api/v1/lists/catalogue/nope")
        .await
        .assert_status_not_found();
    let cat: Value = admin.get("/api/v1/lists/catalogue").await.json();
    assert!(cat["entries"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["id"] == "adaway" && e["added"] == true));
}

fn catalogue_doc(
    ctx: &TestContext,
    signer: &list_service::testkit::Signer,
) -> std::sync::Arc<list_service::SignedDoc<list_service::FilterCatalogueEntry>> {
    let doc = list_service::SignedDoc::new(
        "filters",
        None,
        list_service::ArgusConfig {
            base_url: "http://unused.test".into(),
            public_key: signer.public_key(),
            cache_dir: None,
        },
    );
    assert!(ctx.state.filter_catalogue.set(doc.clone()).is_ok());
    doc
}

#[tokio::test]
async fn a_signed_catalogue_is_served_and_adds_with_its_format() {
    use list_service::testkit::{filters_json, Signer};
    let ctx = TestContext::new().await.unwrap();
    let signer = Signer::new();
    let doc = catalogue_doc(&ctx, &signer);
    let admin = ctx.admin().await;

    // A copy signed with the wrong key is refused: the built-in catalogue still serves.
    let text = filters_json("ubo");
    let bad = Signer::new().sign(&text, "v2026.11.23", "filters.json");
    assert!(doc.apply(text.clone(), bad, None).await.is_err());
    let cat: Value = admin.get("/api/v1/lists/catalogue").await.json();
    assert_eq!(cat["source"], "builtin");

    let sig = signer.sign(&text, "v2026.11.23", "filters.json");
    doc.apply(text, sig, None).await.unwrap();
    let cat: Value = admin.get("/api/v1/lists/catalogue").await.json();
    assert_eq!(cat["source"], "signed");
    assert_eq!(cat["version"], "v2026.11.23");
    assert!(cat["fetched_at"].is_string());
    let e = &cat["entries"][0];
    assert_eq!(
        (e["id"].as_str(), e["format"].as_str(), e["source"].as_str()),
        (Some("fx"), Some("ubo"), Some("signed"))
    );
    assert_eq!(
        (e["region"].as_str(), e["noncommercial"].as_bool()),
        (Some("de"), Some(true))
    );
    assert_eq!(cat["entries"].as_array().unwrap().len(), 1);

    let added = admin.post("/api/v1/lists/catalogue/fx").await;
    assert_eq!(added.status_code(), StatusCode::CREATED);
    let a: Value = added.json();
    assert_eq!(
        (a["format"].as_str(), a["enabled"].as_bool()),
        (Some("ubo"), Some(true))
    );
    // Built-in ids are not in the signed catalogue.
    admin
        .post("/api/v1/lists/catalogue/adaway")
        .await
        .assert_status_not_found();
    let cat: Value = admin.get("/api/v1/lists/catalogue").await.json();
    assert_eq!(cat["entries"][0]["added"], true);
}

#[tokio::test]
async fn list_trust_is_exposed_audited_and_changes_rule_state() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let l = filter_engine::FilterList::new(
        "ag".into(),
        "AG".into(),
        "https://127.0.0.1:1/ag.txt".into(),
    );
    ctx.state.filter_store.upsert(&l).unwrap();
    ctx.state
        .filter_store
        .put_content(
            "ag",
            "||ads.example^\n||x.example^$replace=/a/b/\n||y.example^$stealth\n",
        )
        .unwrap();
    ctx.state.list_service.reload_now().await;

    let one: Value = admin.get("/api/v1/lists/ag").await.json();
    assert_eq!(one["trusted"], false);
    let e: Value = admin.get("/api/v1/rules/ext").await.json();
    let states: Vec<(&str, &str)> = e["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| (i["kind"].as_str().unwrap(), i["state"].as_str().unwrap()))
        .collect();
    assert!(
        states.contains(&("replace", "dropped_untrusted")),
        "{states:?}"
    );
    assert!(
        e["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["state"] == "unsupported" && i["reason"].is_string()),
        "{e}"
    );
    let b: Value = admin.get("/api/v1/engine/build").await.json();
    assert_eq!(
        b["ext_stats"]["per_kind"]["replace"]["dropped_untrusted"],
        1
    );
    assert_eq!(b["ext_stats"]["dropped_untrusted_by_list"]["ag"], 1);

    let u: Value = admin
        .put("/api/v1/lists/ag")
        .json(&json!({"trusted": true}))
        .await
        .json();
    assert_eq!(u["trusted"], true);
    ctx.state.list_service.wait_idle().await;
    ctx.state.list_service.reload_now().await;
    let b: Value = admin.get("/api/v1/engine/build").await.json();
    assert_eq!(b["ext_stats"]["per_kind"]["replace"]["active"], 1);
    let log: Value = admin.get("/api/v1/audit?limit=100").await.json();
    assert!(
        log["items"].as_array().unwrap().iter().any(|a| a["route"]
            .as_str()
            .is_some_and(|r| r.ends_with("#trusted=true"))
            && a["target"] == "ag"
            && a["scope"] == "lists:write"),
        "{log}"
    );
}

#[tokio::test]
async fn reports_build_summary_and_ext_rules_reflect_a_real_build() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    // Content comes from the store; the unreachable origin makes the build fall back to it.
    let mut l = filter_engine::FilterList::new(
        "ag".into(),
        "AG".into(),
        "https://127.0.0.1:1/ag.txt".into(),
    );
    l.format = filter_engine::ListFormat::Adguard;
    ctx.state.filter_store.upsert(&l).unwrap();
    ctx.state
        .filter_store
        .put_content("ag", "! Title: Test list\n||ads.example^\n||x.example^$replace=/a/b/\nexample.com##.banner\n")
        .unwrap();
    ctx.state.list_service.reload_now().await;

    let r: Value = admin.get("/api/v1/lists/ag/report").await.json();
    assert_eq!(r["format"], "adguard");
    assert_eq!(r["meta"]["title"], "Test list");
    assert_eq!(
        (
            r["network"].as_u64(),
            r["cosmetic"].as_u64(),
            r["ext"].as_u64()
        ),
        (Some(1), Some(1), Some(1))
    );
    assert!(r["content_sha"].is_string() && r["issues"].is_array() && r["deduped"].is_number());
    admin
        .get("/api/v1/lists/nope/report")
        .await
        .assert_status_not_found();

    let b: Value = admin.get("/api/v1/engine/build").await.json();
    assert_eq!(b["state"]["state"], "idle");
    assert_eq!(b["building"], false);
    assert_eq!(b["ext_counts"]["replace"], 1);
    assert_eq!(b["domain_set"], 1);
    assert!(b["built_at"].is_string() && b["last_build_at"].is_string());

    let e: Value = admin.get("/api/v1/rules/ext").await.json();
    assert_eq!(e["total"], 1);
    assert_eq!(e["items"][0]["kind"], "replace");
    assert!(e["items"][0]["raw"].as_str().unwrap().contains("$replace"));
    assert_eq!(
        admin
            .get("/api/v1/rules/ext?kind=cookie")
            .await
            .json::<Value>()["total"],
        0
    );

    // Custom rules report appears once custom rules are built.
    admin
        .get("/api/v1/rules/custom/report")
        .await
        .assert_status_not_found();
    let etag = admin.get("/api/v1/rules/custom").await.header("etag");
    admin
        .put("/api/v1/rules/custom")
        .add_header("If-Match", etag.to_str().unwrap())
        .json(&json!({"rules": "||mine.example^\n"}))
        .await
        .assert_status_ok();
    ctx.state.list_service.reload_now().await;
    let c: Value = admin.get("/api/v1/rules/custom/report").await.json();
    assert_eq!(c["id"], "custom");
    assert_eq!(c["network"], 1);
}

#[tokio::test]
async fn recent_blocked_reports_real_events_with_filters() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    ctx.state
        .shared_engine
        .install(filter_engine::compile_engine(&[
            "||ads.example.com^\n||trk.example.net^\n".to_string(),
        ]));
    let e = &ctx.state.shared_engine;
    e.check_for(
        "https://ads.example.com/a.js",
        "https://p.test/",
        "script",
        "0",
    );
    e.check_for(
        "https://trk.example.net/t.js",
        "https://p.test/",
        "script",
        "kid",
    );
    e.check_for("https://fine.test/x.js", "https://p.test/", "script", "0");
    let all: Value = admin.get("/api/v1/stats/blocked/recent").await.json();
    assert_eq!(all["total"], 2);
    assert_eq!(all["entries"][0]["url"], "https://trk.example.net/t.js");
    assert_eq!(all["entries"][0]["client"], "kid");
    assert_eq!(all["entries"][0]["source_host"], "p.test");
    let by_client: Value = admin
        .get("/api/v1/stats/blocked/recent?client=0")
        .await
        .json();
    assert_eq!(by_client["total"], 1);
    assert_eq!(by_client["entries"][0]["rule"], "||ads.example.com^");
    let by_host: Value = admin
        .get("/api/v1/stats/blocked/recent?host=EXAMPLE.net")
        .await
        .json();
    assert_eq!(by_host["total"], 1);
    let none: Value = admin
        .get("/api/v1/stats/blocked/recent?list_id=zzz")
        .await
        .json();
    assert_eq!(none["total"], 0);
    let p: Value = admin
        .get("/api/v1/stats/blocked/recent?limit=1&page=2")
        .await
        .json();
    assert_eq!(
        (
            p["has_more"].as_bool(),
            p["entries"].as_array().unwrap().len()
        ),
        (Some(false), 1)
    );
}

#[tokio::test]
async fn validate_uses_the_real_conversion_pipeline() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let v: Value = admin
        .post("/api/v1/rules/validate")
        .json(&json!({"format": "hosts",
            "rules": "# c\n127.0.0.1 localhost\n0.0.0.0 ad.example\nnot a host line here\n"}))
        .await
        .json();
    assert_eq!(v["format"], "hosts");
    let out = |i: usize| v["lines"][i]["outcome"].as_str().unwrap().to_string();
    assert_eq!(out(0), "skipped"); // localhost entry: recognised, inexpressible
    assert_eq!(out(1), "accepted");
    assert_eq!(out(2), "rejected");
    assert_eq!(
        (v["rejected"].as_u64(), v["skipped"].as_u64()),
        (Some(1), Some(1))
    );

    let v: Value = admin
        .post("/api/v1/rules/validate")
        .json(
            &json!({"format": "adguard", "rules": "||x.example^$replace=/a/b/\n||ads.example^\n"}),
        )
        .await
        .json();
    assert_eq!(v["lines"][0]["outcome"], "handed_off");
    assert_eq!(v["lines"][0]["accepted"], true);
    assert_eq!(v["handed_off"], 1);

    let v: Value = admin
        .post("/api/v1/rules/validate")
        .json(&json!({"rules": "||a.example^\n", "allowlist": true, "format": "abp"}))
        .await
        .json();
    assert_eq!(v["accepted"], 1);
    admin
        .post("/api/v1/rules/validate")
        .json(&json!({"rules": "x", "format": "bogus"}))
        .await
        .assert_status_bad_request();
}

#[tokio::test]
async fn recent_blocked_urls_drop_query_strings_and_need_stats_read() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    ctx.state
        .shared_engine
        .install(filter_engine::compile_engine(&[
            "||ads.example.com^\n".to_string()
        ]));
    ctx.state.shared_engine.check_for(
        "https://ads.example.com/a.js?token=SECRET&u=1#frag",
        "https://p.test/",
        "script",
        "0",
    );
    let r = admin.get("/api/v1/stats/blocked/recent").await;
    r.assert_status_ok();
    let text = r.text();
    assert!(!text.contains("SECRET"), "{text}");
    let v: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["entries"][0]["url"], "https://ads.example.com/a.js");
    // A token without `stats:read` is refused.
    let secret = ctx.token(&admin, &["lists:read"]).await;
    ctx.bearer("GET", "/api/v1/stats/blocked/recent", &secret)
        .await
        .assert_status_forbidden();
}

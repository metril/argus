//! `PATCH /tokens/{id}`, `POST /tokens/{id}/regenerate`, purpose and profile validation.

mod common;

use axum::http::StatusCode;
use common::TestContext;
use serde_json::{json, Value};

async fn create(sess: &common::Sess, body: Value) -> Value {
    let r = sess.post("/api/v1/tokens").json(&body).await;
    assert_eq!(r.status_code(), StatusCode::CREATED, "{}", r.text());
    r.json()
}

#[tokio::test]
async fn create_takes_purpose_and_validates_profiles() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let pid = admin
        .post("/api/v1/profiles")
        .json(&json!({"name": "Kids"}))
        .await
        .json::<Value>()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let v = create(
        &admin,
        json!({"name": "m", "scopes": ["stats:read"], "purpose": "monitoring", "profiles": [pid]}),
    )
    .await;
    assert_eq!(v["token"]["purpose"], "monitoring");
    assert_eq!(v["token"]["profiles"], json!([pid]));
    let hint = v["token"]["secret_hint"].as_str().unwrap();
    let secret = v["secret"].as_str().unwrap();
    assert!(hint.starts_with("abk_") && secret.ends_with(&hint[hint.len() - 4..]));
    assert_ne!(hint, secret);
    // Unknown and malformed profile ids are refused.
    for bad in ["99999", "nope"] {
        let r = admin
            .post("/api/v1/tokens")
            .json(&json!({"name": "x", "scopes": ["stats:read"], "profiles": [bad]}))
            .await;
        assert!(r.status_code().is_client_error(), "{bad}: {}", r.text());
    }
    // Default purpose and list shape.
    let v = create(&admin, json!({"name": "d", "scopes": ["stats:read"]})).await;
    assert_eq!(v["token"]["purpose"], "custom");
    let list: Value = admin.get("/api/v1/tokens").await.json();
    assert!(list["items"][0]["secret_hint"].is_string());
    assert!(list["items"][0].get("digest").is_none());
}

#[tokio::test]
async fn patch_narrows_and_edits_but_never_widens() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    ctx.user(&admin, "alice", "user").await;
    let alice = ctx.login("alice").await;
    let v = create(
        &alice,
        json!({"name": "a", "scopes": ["stats:read", "lists:read"]}),
    )
    .await;
    let id = v["token"]["id"].as_str().unwrap();
    let url = format!("/api/v1/tokens/{id}");
    let r = alice
        .patch(&url)
        .json(
            &json!({"name": "renamed", "scopes": ["stats:read"], "expires_in_days": 7,
                      "purpose": "monitoring"}),
        )
        .await;
    assert_eq!(r.status_code(), StatusCode::OK, "{}", r.text());
    let t: Value = r.json();
    assert_eq!(t["name"], "renamed");
    assert_eq!(t["scopes"], json!(["stats:read"]));
    assert!(t["expires_at"].is_string() && t["updated_at"].is_string());
    assert_eq!(t["purpose"], "monitoring");
    let r = alice
        .patch(&url)
        .json(&json!({"never_expires": true}))
        .await;
    assert!(r.json::<Value>()["expires_at"].is_null());
    // Alice (User role) does not hold config:write or users:admin: cannot widen to them.
    for scope in ["config:write", "users:admin"] {
        let r = alice.patch(&url).json(&json!({"scopes": [scope]})).await;
        r.assert_status(StatusCode::FORBIDDEN);
        assert_eq!(r.json::<Value>()["error"]["code"], "scope_escalation");
    }
    // Conflicting or empty edits are refused.
    alice
        .patch(&url)
        .json(&json!({"expires_in_days": 3, "never_expires": true}))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    assert!(alice
        .patch(&url)
        .json(&json!({"scopes": []}))
        .await
        .status_code()
        .is_client_error());
    // Someone else's token is invisible on the self route, editable on the admin route.
    admin
        .patch(&url)
        .json(&json!({"name": "x"}))
        .await
        .assert_status(StatusCode::NOT_FOUND);
    let r = admin
        .patch(&format!("/api/v1/admin/tokens/{id}"))
        .json(&json!({"name": "by-admin"}))
        .await;
    assert_eq!(r.json::<Value>()["name"], "by-admin");
    alice
        .patch(&format!("/api/v1/admin/tokens/{id}"))
        .json(&json!({"name": "no"}))
        .await
        .assert_status(StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn an_edit_may_keep_scopes_the_editor_no_longer_holds_but_not_add_them() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    ctx.user(&admin, "alice", "user").await;
    let alice = ctx.login("alice").await;
    let u = ctx
        .state
        .session_store
        .get_user_by_username("alice")
        .unwrap()
        .unwrap();
    // A token that kept a scope its owner has since lost (a demotion).
    let (info, _) = ctx
        .state
        .tokens
        .create(
            "kept".into(),
            vec![api_types::Scope::StatsRead, api_types::Scope::ConfigWrite],
            None,
            u.id,
            u.username,
            None,
            api_types::TokenPurpose::Custom,
        )
        .unwrap();
    let url = format!("/api/v1/tokens/{}", info.id);
    // Narrowing around the scope alice no longer holds, and leaving it as it is, both pass.
    let r = alice
        .patch(&url)
        .json(&json!({"scopes": ["stats:read", "lists:read", "config:write"]}))
        .await;
    assert_eq!(r.status_code(), StatusCode::OK, "{}", r.text());
    let t: Value = r.json();
    assert!(t["scopes"]
        .as_array()
        .unwrap()
        .contains(&json!("config:write")));
    // Adding one she does not hold is still refused.
    let r = alice
        .patch(&url)
        .json(&json!({"scopes": ["stats:read", "config:write", "users:admin"]}))
        .await;
    assert_code(r, StatusCode::FORBIDDEN, "scope_escalation").await;
    // Once removed, the scope is no longer the token's, so it cannot be put back.
    let r = alice
        .patch(&url)
        .json(&json!({"scopes": ["stats:read"]}))
        .await;
    assert_eq!(r.status_code(), StatusCode::OK, "{}", r.text());
    let r = alice
        .patch(&url)
        .json(&json!({"scopes": ["stats:read", "config:write"]}))
        .await;
    assert_code(r, StatusCode::FORBIDDEN, "scope_escalation").await;
}

#[tokio::test]
async fn a_restricted_token_cannot_widen_profiles_through_patch() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let mut ids = vec![];
    for n in ["One", "Two"] {
        let r = admin
            .post("/api/v1/profiles")
            .json(&json!({"name": n}))
            .await;
        ids.push(r.json::<Value>()["id"].as_str().unwrap().to_string());
    }
    let parent = create(
        &admin,
        json!({"name": "p", "scopes": ["tokens:self", "stats:read"], "profiles": [ids[0]]}),
    )
    .await;
    let secret = parent["secret"].as_str().unwrap();
    // A token made by the restricted token inherits, and is checked, the same way.
    let r = ctx
        .bearer("POST", "/api/v1/tokens", secret)
        .json(&json!({"name": "c", "scopes": ["stats:read"]}))
        .await;
    r.assert_status(StatusCode::CREATED);
    let child_id = r.json::<Value>()["token"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let url = format!("/api/v1/tokens/{child_id}");
    let r = ctx
        .bearer("PATCH", &url, secret)
        .json(&json!({"profiles": [ids[1]]}))
        .await;
    r.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(r.json::<Value>()["error"]["code"], "scope_escalation");
    ctx.bearer("PATCH", &url, secret)
        .json(&json!({"clear_profiles": true}))
        .await
        .assert_status(StatusCode::FORBIDDEN);
    ctx.bearer("PATCH", &url, secret)
        .json(&json!({"profiles": [ids[0]], "name": "ok"}))
        .await
        .assert_status_ok();
    // Narrowing a token the admin owns: drop the restriction (unrestricted caller).
    let id = parent["token"]["id"].as_str().unwrap();
    let r = admin
        .patch(&format!("/api/v1/tokens/{id}"))
        .json(&json!({"clear_profiles": true}))
        .await;
    assert!(r.json::<Value>()["profiles"].is_null());
}

#[tokio::test]
async fn regenerate_returns_a_new_secret_and_old_one_follows_the_grace_rule() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let v = create(&admin, json!({"name": "r", "scopes": ["stats:read"]})).await;
    let id = v["token"]["id"].as_str().unwrap();
    let old = v["secret"].as_str().unwrap().to_string();
    let url = format!("/api/v1/tokens/{id}/regenerate");
    // Over 7 days is refused.
    admin
        .post(&url)
        .json(&json!({"grace_secs": 604801}))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    let r = admin.post(&url).json(&json!({"grace_secs": 3600})).await;
    assert_eq!(r.status_code(), StatusCode::OK, "{}", r.text());
    let r: Value = r.json();
    let new = r["secret"].as_str().unwrap().to_string();
    assert_ne!(new, old);
    assert_eq!(r["token"]["id"], id);
    assert!(r["token"]["prev_valid_until"].is_string());
    for s in [&old, &new] {
        ctx.bearer("GET", "/api/v1/stats/filter", s)
            .await
            .assert_status_ok();
    }
    // Revoking kills both.
    admin
        .delete(&format!("/api/v1/tokens/{id}"))
        .await
        .assert_status_ok();
    for s in [&old, &new] {
        ctx.bearer("GET", "/api/v1/stats/filter", s)
            .await
            .assert_status(StatusCode::UNAUTHORIZED);
    }
    admin
        .post(&url)
        .json(&json!({}))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn regenerate_without_grace_stops_the_old_secret_at_once() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let v = create(&admin, json!({"name": "r", "scopes": ["stats:read"]})).await;
    let id = v["token"]["id"].as_str().unwrap();
    let old = v["secret"].as_str().unwrap();
    let r: Value = admin
        .post(&format!("/api/v1/tokens/{id}/regenerate"))
        .json(&json!({}))
        .await
        .json();
    ctx.bearer("GET", "/api/v1/stats/filter", old)
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    ctx.bearer("GET", "/api/v1/stats/filter", r["secret"].as_str().unwrap())
        .await
        .assert_status_ok();
    // Another user cannot regenerate it.
    ctx.user(&admin, "bob", "user").await;
    ctx.login("bob")
        .await
        .post(&format!("/api/v1/tokens/{id}/regenerate"))
        .json(&json!({}))
        .await
        .assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn extension_token_scopes_equal_the_template() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    ctx.user(&admin, "alice", "user").await;
    let v: Value = ctx
        .server
        .post("/api/v1/auth/extension-token")
        .json(&json!({"username": "alice", "password": common::PASSWORD, "browser": "Chrome"}))
        .await
        .json();
    let t = ctx
        .state
        .tokens
        .get(v["token_id"].as_str().unwrap())
        .unwrap();
    let mut got = t.stored.scopes.clone();
    got.sort();
    let mut want = api_types::scopes::TEMPLATE_BROWSER_EXTENSION.to_vec();
    want.sort();
    assert_eq!(got, want);
    assert!(got.contains(&api_types::Scope::BypassSite));
    assert_eq!(t.stored.purpose, api_types::TokenPurpose::Extension);
}

/// Make a token for a session and return `(id, secret)`.
async fn mk(sess: &common::Sess, body: Value) -> (String, String) {
    let v = create(sess, body).await;
    (
        v["token"]["id"].as_str().unwrap().to_string(),
        v["secret"].as_str().unwrap().to_string(),
    )
}

async fn assert_code(r: axum_test::TestResponse, status: StatusCode, code: &str) {
    assert_eq!(r.status_code(), status, "{}", r.text());
    assert_eq!(r.json::<Value>()["error"]["code"], code);
}

#[tokio::test]
async fn a_narrow_token_cannot_touch_a_broader_sibling() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let (broad, _) = mk(
        &admin,
        json!({"name": "broad", "scopes": ["tokens:self", "stats:read", "lists:read"]}),
    )
    .await;
    let (narrow, nsecret) = mk(
        &admin,
        json!({"name": "narrow", "scopes": ["tokens:self", "stats:read"]}),
    )
    .await;
    let r = ctx
        .bearer(
            "POST",
            &format!("/api/v1/tokens/{broad}/regenerate"),
            &nsecret,
        )
        .json(&json!({}))
        .await;
    assert_code(r, StatusCode::FORBIDDEN, "token_outside_grant").await;
    for body in [
        json!({"name": "x"}),
        json!({"scopes": ["lists:read"]}),
        json!({"never_expires": true}),
    ] {
        let r = ctx
            .bearer("PATCH", &format!("/api/v1/tokens/{broad}"), &nsecret)
            .json(&body)
            .await;
        assert_code(r, StatusCode::FORBIDDEN, "token_outside_grant").await;
    }
    // Within its own grant it may rename and narrow a sibling, but not widen it.
    let (within, _) = mk(
        &admin,
        json!({"name": "w", "scopes": ["tokens:self", "stats:read"]}),
    )
    .await;
    let r = ctx
        .bearer("PATCH", &format!("/api/v1/tokens/{within}"), &nsecret)
        .json(&json!({"name": "renamed", "scopes": ["stats:read"]}))
        .await;
    assert_eq!(r.status_code(), StatusCode::OK, "{}", r.text());
    let r = ctx
        .bearer("PATCH", &format!("/api/v1/tokens/{within}"), &nsecret)
        .json(&json!({"scopes": ["lists:read"]}))
        .await;
    assert_code(r, StatusCode::FORBIDDEN, "scope_escalation").await;
    // And a token can regenerate itself.
    let r = ctx
        .bearer(
            "POST",
            &format!("/api/v1/tokens/{narrow}/regenerate"),
            &nsecret,
        )
        .json(&json!({}))
        .await;
    assert_eq!(r.status_code(), StatusCode::OK, "{}", r.text());
    let fresh = r.json::<Value>()["secret"].as_str().unwrap().to_string();
    ctx.bearer("GET", "/api/v1/tokens", &fresh)
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn an_expiring_token_cannot_extend_or_remove_a_siblings_expiry() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let (_, short) = mk(
        &admin,
        json!({"name": "short", "scopes": ["tokens:self", "stats:read"], "expires_in_days": 7}),
    )
    .await;
    let (forever, _) = mk(
        &admin,
        json!({"name": "forever", "scopes": ["tokens:self", "stats:read"]}),
    )
    .await;
    let url = format!("/api/v1/tokens/{forever}");
    for body in [
        json!({"never_expires": true}),
        json!({"expires_in_days": 30}),
    ] {
        let r = ctx.bearer("PATCH", &url, &short).json(&body).await;
        assert_code(r, StatusCode::FORBIDDEN, "expiry_outside_grant").await;
    }
    ctx.bearer("PATCH", &url, &short)
        .json(&json!({"expires_in_days": 3}))
        .await
        .assert_status_ok();
    // Regenerating a never-expiring sibling would hand out a longer-lived secret.
    let (other, _) = mk(
        &admin,
        json!({"name": "o", "scopes": ["tokens:self", "stats:read"]}),
    )
    .await;
    let regen = format!("/api/v1/tokens/{other}/regenerate");
    let r = ctx.bearer("POST", &regen, &short).json(&json!({})).await;
    assert_code(r, StatusCode::FORBIDDEN, "expiry_outside_grant").await;
    ctx.bearer("POST", &regen, &short)
        .json(&json!({"expires_in_days": 2}))
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn a_restricted_token_cannot_touch_an_unrestricted_sibling() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let p1 = admin
        .post("/api/v1/profiles")
        .json(&json!({"name": "One"}))
        .await
        .json::<Value>()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (_, rsecret) = mk(
        &admin,
        json!({"name": "r", "scopes": ["tokens:self", "stats:read"], "profiles": [p1]}),
    )
    .await;
    let (open, _) = mk(
        &admin,
        json!({"name": "u", "scopes": ["tokens:self", "stats:read"]}),
    )
    .await;
    let r = ctx
        .bearer("PATCH", &format!("/api/v1/tokens/{open}"), &rsecret)
        .json(&json!({"name": "x"}))
        .await;
    assert_code(r, StatusCode::FORBIDDEN, "token_outside_grant").await;
    let r = ctx
        .bearer(
            "POST",
            &format!("/api/v1/tokens/{open}/regenerate"),
            &rsecret,
        )
        .json(&json!({}))
        .await;
    assert_code(r, StatusCode::FORBIDDEN, "token_outside_grant").await;
    let (same, _) = mk(
        &admin,
        json!({"name": "s", "scopes": ["tokens:self"], "profiles": [p1]}),
    )
    .await;
    ctx.bearer("PATCH", &format!("/api/v1/tokens/{same}"), &rsecret)
        .json(&json!({"name": "ok"}))
        .await
        .assert_status_ok();
}

fn expired_token(ctx: &TestContext, scopes: Vec<api_types::Scope>) -> (String, String) {
    let admin = ctx
        .state
        .session_store
        .get_user_by_username("admin_user")
        .unwrap()
        .unwrap();
    let (info, secret) = ctx
        .state
        .tokens
        .create(
            "old".into(),
            scopes,
            None,
            admin.id,
            admin.username,
            Some(chrono::Utc::now() - chrono::Duration::seconds(5)),
            api_types::TokenPurpose::Custom,
        )
        .unwrap();
    (info.id, secret)
}

#[tokio::test]
async fn an_expired_token_is_revived_only_by_regenerate_with_an_expiry() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let (id, old) = expired_token(&ctx, vec![api_types::Scope::StatsRead]);
    let url = format!("/api/v1/tokens/{id}");
    for body in [
        json!({"never_expires": true}),
        json!({"expires_in_days": 5}),
        json!({"name": "x"}),
    ] {
        assert_code(
            admin.patch(&url).json(&body).await,
            StatusCode::CONFLICT,
            "token_expired",
        )
        .await;
    }
    let regen = format!("{url}/regenerate");
    assert_code(
        admin.post(&regen).json(&json!({"grace_secs": 60})).await,
        StatusCode::CONFLICT,
        "token_expired",
    )
    .await;
    let r = admin
        .post(&regen)
        .json(&json!({"grace_secs": 60, "expires_in_days": 5}))
        .await;
    assert_eq!(r.status_code(), StatusCode::OK, "{}", r.text());
    let r: Value = r.json();
    assert!(r["token"]["expires_at"].is_string());
    let new = r["secret"].as_str().unwrap();
    ctx.bearer("GET", "/api/v1/stats/filter", new)
        .await
        .assert_status_ok();
    // The old secret does not come back to life with the grace window.
    ctx.bearer("GET", "/api/v1/stats/filter", &old)
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    // A live token: the expiry fields are optional and replace the expiry when given.
    let r: Value = admin
        .post(&regen)
        .json(&json!({"never_expires": true}))
        .await
        .json();
    assert!(r["token"]["expires_at"].is_null());
}

#[tokio::test]
async fn a_revoked_token_cannot_be_revived() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let (id, _) = mk(&admin, json!({"name": "r", "scopes": ["stats:read"]})).await;
    admin
        .delete(&format!("/api/v1/tokens/{id}"))
        .await
        .assert_status_ok();
    admin
        .post(&format!("/api/v1/tokens/{id}/regenerate"))
        .json(&json!({"expires_in_days": 5}))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    admin
        .patch(&format!("/api/v1/tokens/{id}"))
        .json(&json!({"expires_in_days": 5}))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn widening_a_longer_lived_sibling_is_refused_but_narrowing_is_not() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let (_, caller) = mk(
        &admin,
        json!({"name": "c", "scopes": ["tokens:self", "stats:read", "lists:read"], "expires_in_days": 7}),
    )
    .await;
    let (sib, _) = mk(
        &admin,
        json!({"name": "s", "scopes": ["tokens:self", "stats:read"], "expires_in_days": 90}),
    )
    .await;
    let url = format!("/api/v1/tokens/{sib}");
    let widen = json!({"scopes": ["tokens:self", "stats:read", "lists:read"]});
    let r = ctx.bearer("PATCH", &url, &caller).json(&widen).await;
    assert_code(r, StatusCode::FORBIDDEN, "expiry_outside_grant").await;
    // Widening while shortening the sibling to within the caller's lifetime is fine.
    let r = ctx
        .bearer("PATCH", &url, &caller)
        .json(&json!({"scopes": ["tokens:self", "stats:read", "lists:read"], "expires_in_days": 3}))
        .await;
    assert_eq!(r.status_code(), StatusCode::OK, "{}", r.text());
    // Narrowing and renaming alone stay allowed on a longer-lived sibling.
    let (sib2, _) = mk(
        &admin,
        json!({"name": "s2", "scopes": ["tokens:self", "stats:read"], "expires_in_days": 90}),
    )
    .await;
    ctx.bearer("PATCH", &format!("/api/v1/tokens/{sib2}"), &caller)
        .json(&json!({"name": "r", "scopes": ["stats:read"]}))
        .await
        .assert_status_ok();
}

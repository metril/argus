//! Extension sign-in (`POST /auth/extension-token`), `DELETE /tokens/self`, and `expires_at`.

mod common;

use axum::http::{Method, StatusCode};
use common::{TestContext, PASSWORD};
use serde_json::{json, Value};

async fn mint(ctx: &TestContext, user: &str, extra: Value) -> axum_test::TestResponse {
    let mut b = json!({"username": user, "password": PASSWORD, "browser": "Chrome"});
    for (k, v) in extra.as_object().unwrap() {
        b[k] = v.clone();
    }
    ctx.server
        .post("/api/v1/auth/extension-token")
        .json(&b)
        .await
}

#[tokio::test]
async fn mints_a_token_with_exactly_the_extension_scopes_and_no_session() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    ctx.user(&admin, "alice", "user").await;
    let r = mint(&ctx, "alice", json!({})).await;
    r.assert_status_ok();
    assert!(r.headers().get("set-cookie").is_none());
    let v: Value = r.json();
    assert_eq!(v["user"]["username"], "alice");
    let secret = v["token"].as_str().unwrap();
    let id = v["token_id"].as_str().unwrap();
    let info = ctx.state.tokens.get(id).unwrap();
    assert_eq!(info.stored.name, "Extension · Chrome");
    assert!(info.stored.expires_at.is_none());
    let mut scopes: Vec<String> = info
        .stored
        .scopes
        .iter()
        .map(|s| s.as_str().to_string())
        .collect();
    scopes.sort();
    assert_eq!(
        scopes,
        [
            "logs:read",
            "rules:site",
            "stats:read",
            "userscripts:bridge"
        ]
    );
    let me: Value = ctx.bearer("GET", "/api/v1/auth/me", secret).await.json();
    assert_eq!(me["username"], "alice");
}

#[tokio::test]
async fn bad_credentials_are_401_and_a_role_without_the_scopes_is_403() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    ctx.user(&admin, "vera", "viewer").await;
    let r = ctx
        .server
        .post("/api/v1/auth/extension-token")
        .json(
            &json!({"username": "admin_user", "password": "WrongPassword1!", "browser": "Chrome"}),
        )
        .await;
    r.assert_status(StatusCode::UNAUTHORIZED);
    mint(&ctx, "nobody", json!({}))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    let r = mint(&ctx, "vera", json!({})).await;
    r.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(r.json::<Value>()["error"]["code"], "insufficient_role");
}

#[tokio::test]
async fn replace_token_id_revokes_only_your_own_token() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    ctx.user(&admin, "alice", "user").await;
    let first: Value = mint(&ctx, "alice", json!({})).await.json();
    let other: Value = mint(&ctx, "admin_user", json!({})).await.json();
    // Another user's id is ignored.
    let second: Value = mint(
        &ctx,
        "alice",
        json!({"replace_token_id": other["token_id"]}),
    )
    .await
    .json();
    ctx.bearer("GET", "/api/v1/auth/me", other["token"].as_str().unwrap())
        .await
        .assert_status_ok();
    ctx.bearer("GET", "/api/v1/auth/me", first["token"].as_str().unwrap())
        .await
        .assert_status_ok();
    let third: Value = mint(
        &ctx,
        "alice",
        json!({"replace_token_id": second["token_id"]}),
    )
    .await
    .json();
    ctx.bearer("GET", "/api/v1/auth/me", second["token"].as_str().unwrap())
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    ctx.bearer("GET", "/api/v1/auth/me", third["token"].as_str().unwrap())
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn delete_self_revokes_the_calling_token_only_for_tokens() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let v: Value = mint(&ctx, "admin_user", json!({})).await.json();
    let secret = v["token"].as_str().unwrap();
    ctx.bearer("DELETE", "/api/v1/tokens/self", secret)
        .await
        .assert_status_ok();
    ctx.bearer("GET", "/api/v1/auth/me", secret)
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    // A cookie session has no token to revoke.
    admin
        .delete("/api/v1/tokens/self")
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    ctx.server
        .delete("/api/v1/tokens/self")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn extension_origins_may_call_the_two_extension_routes() {
    let ctx = TestContext::new().await.unwrap();
    let preflight = |path: &'static str, origin: &'static str, method: &'static str| {
        ctx.server
            .method(Method::OPTIONS, path)
            .add_header("origin", origin)
            .add_header("access-control-request-method", method)
    };
    let r = preflight(
        "/api/v1/auth/extension-token",
        "chrome-extension://abc",
        "POST",
    )
    .await;
    assert_eq!(
        r.header("access-control-allow-origin"),
        "chrome-extension://abc"
    );
    let r = preflight("/api/v1/tokens/self", "moz-extension://abc", "DELETE").await;
    assert_eq!(
        r.header("access-control-allow-origin"),
        "moz-extension://abc"
    );
    let r = preflight("/api/v1/tokens", "moz-extension://abc", "POST").await;
    assert!(r.headers().get("access-control-allow-origin").is_none());
}

#[tokio::test]
async fn expires_at_must_be_future_and_exclusive_with_days() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let post = |extra: Value| {
        let mut b = json!({"name": "t", "scopes": ["lists:read"]});
        for (k, v) in extra.as_object().unwrap() {
            b[k] = v.clone();
        }
        admin.post("/api/v1/tokens").json(&b)
    };
    post(json!({"expires_at": "2000-01-01T00:00:00Z"}))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    post(json!({"expires_at": "not a date"}))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    post(json!({"expires_at": "2999-01-01T00:00:00Z", "expires_in_days": 5}))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    let r = post(json!({"expires_at": "2999-01-01T00:00:00+02:00"})).await;
    r.assert_status(StatusCode::CREATED);
    let at = r.json::<Value>()["token"]["expires_at"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(at.starts_with("2998-12-31T22:00:00"), "{at}");
}

#[tokio::test]
async fn extension_token_reads_stats_and_switches_sites_but_site_scope_is_narrow() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    ctx.user(&admin, "alice", "user").await;
    let v: Value = mint(&ctx, "alice", json!({})).await.json();
    let ext = v["token"].as_str().unwrap();
    ctx.bearer("GET", "/api/v1/stats/filter", ext)
        .await
        .assert_status_ok();
    ctx.bearer("GET", "/api/v1/stats/blocked/recent", ext)
        .await
        .assert_status_ok();
    ctx.bearer("PUT", "/api/v1/rules/site-exceptions/shop.test", ext)
        .await
        .assert_status_ok();
    let st: Value = ctx
        .bearer("GET", "/api/v1/rules/site-exceptions/shop.test", ext)
        .await
        .json();
    assert_eq!(st, json!({"site": "shop.test", "disabled": true}));
    ctx.bearer("DELETE", "/api/v1/rules/site-exceptions/shop.test", ext)
        .await
        .assert_status_ok();
    // A public suffix is refused: one click must not switch blocking off for a whole suffix.
    for suffix in ["com", "co.uk", "herokuapp.com"] {
        ctx.bearer(
            "PUT",
            &format!("/api/v1/rules/site-exceptions/{suffix}"),
            ext,
        )
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    }
    ctx.bearer(
        "PUT",
        "/api/v1/rules/site-exceptions/foo.herokuapp.com",
        ext,
    )
    .await
    .assert_status_ok();
    ctx.bearer(
        "DELETE",
        "/api/v1/rules/site-exceptions/foo.herokuapp.com",
        ext,
    )
    .await
    .assert_status_ok();
    // rules:site does not open the rest of the rules.
    ctx.bearer("PUT", "/api/v1/rules/custom", ext)
        .await
        .assert_status(StatusCode::FORBIDDEN);
    // A token without rules:site is refused, with a scope error (the extension re-signs in).
    let old = ctx
        .token(&admin, &["logs:read", "userscripts:bridge"])
        .await;
    for m in ["GET", "PUT", "DELETE"] {
        let r = ctx
            .bearer(m, "/api/v1/rules/site-exceptions/shop.test", &old)
            .await;
        r.assert_status(StatusCode::FORBIDDEN);
        assert_eq!(r.json::<Value>()["error"]["code"], "insufficient_scope");
    }
    ctx.bearer("GET", "/api/v1/stats/filter", &old)
        .await
        .assert_status(StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn re_signing_in_upgrades_an_older_extension_token() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let alice = ctx.user(&admin, "alice", "user").await;
    let r = alice
        .post("/api/v1/tokens")
        .json(&json!({"name": "Extension · Chrome", "scopes": ["logs:read", "userscripts:bridge"]}))
        .await;
    r.assert_status(StatusCode::CREATED);
    let old: Value = r.json();
    let (id, secret) = (
        old["token"]["id"].as_str().unwrap(),
        old["secret"].as_str().unwrap(),
    );
    let new: Value = mint(&ctx, "alice", json!({"replace_token_id": id}))
        .await
        .json();
    ctx.bearer("GET", "/api/v1/auth/me", secret)
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    ctx.bearer(
        "GET",
        "/api/v1/stats/filter",
        new["token"].as_str().unwrap(),
    )
    .await
    .assert_status_ok();
}

#[tokio::test]
async fn rules_write_still_switches_sites_and_rules_site_still_cannot_edit_rules() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let w = ctx.token(&admin, &["rules:write"]).await;
    for m in ["PUT", "DELETE"] {
        ctx.bearer(m, "/api/v1/rules/site-exceptions/shop.test", &w)
            .await
            .assert_status_ok();
    }
    ctx.bearer("GET", "/api/v1/rules/site-exceptions/shop.test", &w)
        .await
        .assert_status_ok();
    let r = ctx.token(&admin, &["rules:read"]).await;
    ctx.bearer("GET", "/api/v1/rules/site-exceptions/shop.test", &r)
        .await
        .assert_status_ok();
    ctx.bearer("PUT", "/api/v1/rules/site-exceptions/shop.test", &r)
        .await
        .assert_status(StatusCode::FORBIDDEN);
    let site = ctx.token(&admin, &["rules:site"]).await;
    ctx.bearer("PUT", "/api/v1/rules/custom", &site)
        .await
        .assert_status(StatusCode::FORBIDDEN);
    // The web UI's session (role bundle) keeps working.
    admin
        .put("/api/v1/rules/site-exceptions/shop.test")
        .await
        .assert_status_ok();
}

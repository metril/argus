//! Integration tests for the Web API
//!
//! Tests all API endpoints including authentication, proxy management,
//! filter management, and userscript management.

mod common;

use axum_test::TestServer;
use common::{extract_access_token, extract_refresh_token, TestContext};
use cookie::Cookie;
use serde_json::json;

// ============================================================================
// Health Endpoint Tests
// ============================================================================

#[tokio::test]
async fn test_health_check() {
    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let server = TestServer::new(ctx.router).expect("Failed to create test server");

    let response = server.get("/api/health").await;

    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    assert_eq!(body["status"], "healthy");
    assert!(body["version"].is_string());
}

#[tokio::test]
async fn test_metrics_endpoint() {
    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let server = TestServer::new(ctx.router).expect("Failed to create test server");

    let response = server.get("/api/metrics").await;

    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    assert!(body["proxy"]["connections"]["total"].is_number());
    assert!(body["filter"]["total_requests"].is_number());
}

#[tokio::test]
async fn test_ca_download_is_public() {
    // The CA certificate endpoint must be reachable WITHOUT authentication so any
    // device can fetch and trust it by URL. Whether the cert file exists in the
    // test environment or not, the auth layer must never reject the request.
    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let server = TestServer::new(ctx.router).expect("Failed to create test server");

    let response = server.get("/api/ca.crt").await;

    let status = response.status_code();
    assert_ne!(status, axum::http::StatusCode::UNAUTHORIZED);
    assert_ne!(status, axum::http::StatusCode::FORBIDDEN);
    // Either the cert is served (200) or it isn't generated yet (404) — both prove
    // the route is wired and public.
    assert!(
        status == axum::http::StatusCode::OK || status == axum::http::StatusCode::NOT_FOUND,
        "unexpected status for /api/ca.crt: {status}"
    );
}

// ============================================================================
// Authentication Tests
// ============================================================================

#[tokio::test]
async fn test_register_first_user_becomes_admin() {
    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let server = TestServer::new(ctx.router).expect("Failed to create test server");

    let response = server
        .post("/api/auth/register")
        .json(&json!({
            "username": "admin_user",
            "password": "SecurePassword123!", "password_confirm": "SecurePassword123!"
        }))
        .await;

    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    assert_eq!(body["user"]["username"], "admin_user");
    assert_eq!(body["user"]["role"], "admin");

    // Check cookies are set
    let access_token = extract_access_token(&response);
    let refresh_token = extract_refresh_token(&response);
    assert!(access_token.is_some());
    assert!(refresh_token.is_some());
}

#[tokio::test]
async fn test_register_second_user_becomes_user() {
    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let server = TestServer::new(ctx.router.clone()).expect("Failed to create test server");

    // Register first user (admin)
    server
        .post("/api/auth/register")
        .json(&json!({
            "username": "admin_user",
            "password": "SecurePassword123!", "password_confirm": "SecurePassword123!"
        }))
        .await
        .assert_status_ok();

    // Register second user
    let response = server
        .post("/api/auth/register")
        .json(&json!({
            "username": "regular_user",
            "password": "SecurePassword123!", "password_confirm": "SecurePassword123!"
        }))
        .await;

    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    assert_eq!(body["user"]["username"], "regular_user");
    assert_eq!(body["user"]["role"], "user");
}

#[tokio::test]
async fn test_register_duplicate_username() {
    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let server = TestServer::new(ctx.router.clone()).expect("Failed to create test server");

    // Register first user
    server
        .post("/api/auth/register")
        .json(&json!({
            "username": "test_user",
            "password": "SecurePassword123!", "password_confirm": "SecurePassword123!"
        }))
        .await
        .assert_status_ok();

    // Try to register with same username
    let response = server
        .post("/api/auth/register")
        .json(&json!({
            "username": "test_user",
            "password": "DifferentPassword123!", "password_confirm": "DifferentPassword123!"
        }))
        .await;

    response.assert_status_bad_request();
}

#[tokio::test]
async fn test_register_weak_password() {
    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let server = TestServer::new(ctx.router).expect("Failed to create test server");

    let response = server
        .post("/api/auth/register")
        .json(&json!({
            "username": "test_user",
            "password": "weak", "password_confirm": "weak"
        }))
        .await;

    response.assert_status_bad_request();
}

#[tokio::test]
async fn test_login_success() {
    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let server = TestServer::new(ctx.router.clone()).expect("Failed to create test server");

    // Register
    server
        .post("/api/auth/register")
        .json(&json!({
            "username": "login_test",
            "password": "SecurePassword123!", "password_confirm": "SecurePassword123!"
        }))
        .await
        .assert_status_ok();

    // Login
    let response = server
        .post("/api/auth/login")
        .json(&json!({
            "username": "login_test",
            "password": "SecurePassword123!", "password_confirm": "SecurePassword123!"
        }))
        .await;

    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    assert_eq!(body["user"]["username"], "login_test");
    assert!(extract_access_token(&response).is_some());
}

#[tokio::test]
async fn test_login_wrong_password() {
    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let server = TestServer::new(ctx.router.clone()).expect("Failed to create test server");

    // Register
    server
        .post("/api/auth/register")
        .json(&json!({
            "username": "login_test",
            "password": "SecurePassword123!", "password_confirm": "SecurePassword123!"
        }))
        .await
        .assert_status_ok();

    // Login with wrong password
    let response = server
        .post("/api/auth/login")
        .json(&json!({
            "username": "login_test",
            "password": "WrongPassword123!", "password_confirm": "WrongPassword123!"
        }))
        .await;

    response.assert_status_unauthorized();
}

#[tokio::test]
async fn test_login_nonexistent_user() {
    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let server = TestServer::new(ctx.router).expect("Failed to create test server");

    let response = server
        .post("/api/auth/login")
        .json(&json!({
            "username": "nonexistent",
            "password": "SomePassword123!", "password_confirm": "SomePassword123!"
        }))
        .await;

    response.assert_status_unauthorized();
}

#[tokio::test]
async fn test_me_endpoint() {
    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let server = TestServer::new(ctx.router.clone()).expect("Failed to create test server");

    // Register and get token
    let reg_response = server
        .post("/api/auth/register")
        .json(&json!({
            "username": "me_test",
            "password": "SecurePassword123!", "password_confirm": "SecurePassword123!"
        }))
        .await;
    reg_response.assert_status_ok();

    let access_token = extract_access_token(&reg_response).expect("No access token");

    // Access me endpoint
    let response = server
        .get("/api/auth/me")
        .add_cookie(Cookie::new("access_token", access_token))
        .await;

    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    assert_eq!(body["username"], "me_test");
}

#[tokio::test]
async fn test_me_endpoint_unauthorized() {
    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let server = TestServer::new(ctx.router).expect("Failed to create test server");

    let response = server.get("/api/auth/me").await;

    response.assert_status_unauthorized();
}

#[tokio::test]
async fn test_logout() {
    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let server = TestServer::new(ctx.router.clone()).expect("Failed to create test server");

    // Register
    let reg_response = server
        .post("/api/auth/register")
        .json(&json!({
            "username": "logout_test",
            "password": "SecurePassword123!", "password_confirm": "SecurePassword123!"
        }))
        .await;
    reg_response.assert_status_ok();

    let access_token = extract_access_token(&reg_response).expect("No access token");

    // Logout
    let response = server
        .post("/api/auth/logout")
        .add_cookie(Cookie::new("access_token", access_token))
        .await;

    response.assert_status_ok();

    // Check that cookies are cleared (max-age=0)
    let cookies: Vec<_> = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();

    assert!(cookies.iter().any(|c| c.contains("Max-Age=0")));
}

#[tokio::test]
async fn test_refresh_token() {
    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let server = TestServer::new(ctx.router.clone()).expect("Failed to create test server");

    // Register
    let reg_response = server
        .post("/api/auth/register")
        .json(&json!({
            "username": "refresh_test",
            "password": "SecurePassword123!", "password_confirm": "SecurePassword123!"
        }))
        .await;
    reg_response.assert_status_ok();

    let refresh_token = extract_refresh_token(&reg_response).expect("No refresh token");

    // Refresh token
    let response = server
        .post("/api/auth/refresh")
        .add_cookie(Cookie::new("refresh_token", refresh_token))
        .await;

    response.assert_status_ok();
    assert!(extract_access_token(&response).is_some());
}

// ============================================================================
// Proxy Management Tests
// ============================================================================

#[tokio::test]
async fn test_get_proxy_config_requires_auth() {
    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let server = TestServer::new(ctx.router).expect("Failed to create test server");

    let response = server.get("/api/proxy/config").await;
    response.assert_status_unauthorized();
}

#[tokio::test]
async fn test_get_proxy_config() {
    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let server = TestServer::new(ctx.router.clone()).expect("Failed to create test server");

    // Register and get token
    let reg_response = server
        .post("/api/auth/register")
        .json(&json!({
            "username": "proxy_test",
            "password": "SecurePassword123!", "password_confirm": "SecurePassword123!"
        }))
        .await;
    let access_token = extract_access_token(&reg_response).expect("No access token");

    // Get config
    let response = server
        .get("/api/proxy/config")
        .add_cookie(Cookie::new("access_token", access_token))
        .await;

    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    assert!(body["host"].is_string());
    assert!(body["port"].is_number());
}

#[tokio::test]
async fn test_update_proxy_config() {
    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let server = TestServer::new(ctx.router.clone()).expect("Failed to create test server");

    // Register admin
    let reg_response = server
        .post("/api/auth/register")
        .json(&json!({
            "username": "admin_proxy",
            "password": "SecurePassword123!", "password_confirm": "SecurePassword123!"
        }))
        .await;
    let access_token = extract_access_token(&reg_response).expect("No access token");

    // Update config
    let response = server
        .put("/api/proxy/config")
        .add_cookie(Cookie::new("access_token", access_token))
        .json(&json!({
            "port": 9090,
            "max_connections": 2000
        }))
        .await;

    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    assert_eq!(body["port"], 9090);
    assert_eq!(body["max_connections"], 2000);
}

#[tokio::test]
async fn test_update_proxy_config_applies_live_settings() {
    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let server = TestServer::new(ctx.router.clone()).expect("Failed to create test server");
    let reg_response = server
        .post("/api/auth/register")
        .json(&json!({
            "username": "live_cfg",
            "password": "SecurePassword123!", "password_confirm": "SecurePassword123!"
        }))
        .await;
    let access_token = extract_access_token(&reg_response).expect("No access token");
    assert!(ctx.state.shared_engine.is_enabled());

    let response = server
        .put("/api/proxy/config")
        .add_cookie(Cookie::new("access_token", access_token))
        .json(&json!({
            "enable_adblock": false,
            "request_timeout_secs": 7,
            "auto_update": false,
            "update_interval_hours": 2,
            "port": 9191
        }))
        .await;
    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    assert_eq!(body["port"], 9191);
    assert_eq!(body["request_timeout_secs"], 7);
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
        assert!(applied.contains(&f), "{f} should be applied: {applied:?}");
    }
    assert_eq!(body["restart_required"], json!(["port"]));

    // The running proxy handles actually changed.
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
}

#[tokio::test]
async fn test_update_proxy_config_validation() {
    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let server = TestServer::new(ctx.router.clone()).expect("Failed to create test server");

    // Register
    let reg_response = server
        .post("/api/auth/register")
        .json(&json!({
            "username": "validation_test",
            "password": "SecurePassword123!", "password_confirm": "SecurePassword123!"
        }))
        .await;
    let access_token = extract_access_token(&reg_response).expect("No access token");

    // Try invalid port
    let response = server
        .put("/api/proxy/config")
        .add_cookie(Cookie::new("access_token", access_token))
        .json(&json!({
            "port": 0
        }))
        .await;

    response.assert_status_bad_request();
}

#[tokio::test]
async fn test_get_proxy_stats() {
    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let server = TestServer::new(ctx.router.clone()).expect("Failed to create test server");

    // Register
    let reg_response = server
        .post("/api/auth/register")
        .json(&json!({
            "username": "stats_test",
            "password": "SecurePassword123!", "password_confirm": "SecurePassword123!"
        }))
        .await;
    let access_token = extract_access_token(&reg_response).expect("No access token");

    // Get stats
    let response = server
        .get("/api/proxy/stats")
        .add_cookie(Cookie::new("access_token", access_token))
        .await;

    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    assert!(body["connections"]["total"].is_number());
    assert!(body["requests"]["total"].is_number());
}

// ============================================================================
// Filter Management Tests
// ============================================================================

#[tokio::test]
async fn test_list_filter_lists() {
    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let server = TestServer::new(ctx.router.clone()).expect("Failed to create test server");

    // Register
    let reg_response = server
        .post("/api/auth/register")
        .json(&json!({
            "username": "filter_test",
            "password": "SecurePassword123!", "password_confirm": "SecurePassword123!"
        }))
        .await;
    let access_token = extract_access_token(&reg_response).expect("No access token");

    // List filters
    let response = server
        .get("/api/filters/lists")
        .add_cookie(Cookie::new("access_token", access_token))
        .await;

    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    assert!(body["data"].is_array());
    assert!(body["total"].is_number());
    assert!(body["page"].is_number());
}

#[tokio::test]
async fn test_add_filter_list_ssrf_protection() {
    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let server = TestServer::new(ctx.router.clone()).expect("Failed to create test server");

    // Register
    let reg_response = server
        .post("/api/auth/register")
        .json(&json!({
            "username": "ssrf_test",
            "password": "SecurePassword123!", "password_confirm": "SecurePassword123!"
        }))
        .await;
    let access_token = extract_access_token(&reg_response).expect("No access token");

    // Try to add filter list with localhost URL (should fail)
    let response = server
        .post("/api/filters/lists")
        .add_cookie(Cookie::new("access_token", access_token.clone()))
        .json(&json!({
            "id": "test-list",
            "name": "Test List",
            "url": "http://localhost/filters.txt"
        }))
        .await;

    response.assert_status_bad_request();

    // Try with private IP
    let response = server
        .post("/api/filters/lists")
        .add_cookie(Cookie::new("access_token", access_token.clone()))
        .json(&json!({
            "id": "test-list",
            "name": "Test List",
            "url": "https://192.168.1.1/filters.txt"
        }))
        .await;

    response.assert_status_bad_request();

    // Try with internal hostname
    let response = server
        .post("/api/filters/lists")
        .add_cookie(Cookie::new("access_token", access_token))
        .json(&json!({
            "id": "test-list",
            "name": "Test List",
            "url": "https://internal.corp.local/filters.txt"
        }))
        .await;

    response.assert_status_bad_request();
}

#[tokio::test]
async fn test_add_filter_list_valid_url() {
    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let server = TestServer::new(ctx.router.clone()).expect("Failed to create test server");

    // Register
    let reg_response = server
        .post("/api/auth/register")
        .json(&json!({
            "username": "filter_add_test",
            "password": "SecurePassword123!", "password_confirm": "SecurePassword123!"
        }))
        .await;
    let access_token = extract_access_token(&reg_response).expect("No access token");

    // Add filter list with valid URL
    let response = server
        .post("/api/filters/lists")
        .add_cookie(Cookie::new("access_token", access_token))
        .json(&json!({
            "id": "easylist",
            "name": "EasyList",
            "url": "https://easylist.to/easylist/easylist.txt"
        }))
        .await;

    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    assert_eq!(body["id"], "easylist");
    assert_eq!(body["name"], "EasyList");
}

/// Regression test for the reported bug: a list added by the user must still be there when the
/// listing is reloaded (it used to vanish because the handlers were stubs).
#[tokio::test]
async fn test_added_filter_list_appears_in_listing() {
    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let server = TestServer::new(ctx.router.clone()).expect("Failed to create test server");

    let reg_response = server
        .post("/api/auth/register")
        .json(&json!({
            "username": "persist_test",
            "password": "SecurePassword123!", "password_confirm": "SecurePassword123!"
        }))
        .await;
    let access_token = extract_access_token(&reg_response).expect("No access token");

    // Add a list.
    let add = server
        .post("/api/filters/lists")
        .add_cookie(Cookie::new("access_token", access_token.clone()))
        .json(&json!({
            "id": "my-list",
            "name": "My Custom List",
            "url": "https://example.com/custom.txt"
        }))
        .await;
    add.assert_status_ok();

    // Re-list: the added list must be present (the original symptom was it disappearing).
    let list = server
        .get("/api/filters/lists")
        .add_cookie(Cookie::new("access_token", access_token.clone()))
        .await;
    list.assert_status_ok();
    let body: serde_json::Value = list.json();
    let arr = body["data"].as_array().expect("data is array");
    assert!(
        arr.iter().any(|l| l["id"] == "my-list"),
        "the added list must appear in the listing, got: {body}"
    );

    // Fetch it directly too.
    let one = server
        .get("/api/filters/lists/my-list")
        .add_cookie(Cookie::new("access_token", access_token.clone()))
        .await;
    one.assert_status_ok();
    assert_eq!(one.json::<serde_json::Value>()["name"], "My Custom List");

    // Adding the same id again must conflict, not silently clobber.
    let dup = server
        .post("/api/filters/lists")
        .add_cookie(Cookie::new("access_token", access_token))
        .json(&json!({"id": "my-list", "name": "Dup", "url": "https://example.com/x.txt"}))
        .await;
    assert_eq!(dup.status_code(), 409, "duplicate id should conflict");
}

#[tokio::test]
async fn test_custom_rules_get_and_update() {
    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let server = TestServer::new(ctx.router.clone()).expect("Failed to create test server");

    let reg = server
        .post("/api/auth/register")
        .json(&json!({
            "username": "rules_test",
            "password": "SecurePassword123!", "password_confirm": "SecurePassword123!"
        }))
        .await;
    let token = extract_access_token(&reg).expect("No access token");

    // Initially empty.
    let got = server
        .get("/api/filters/custom-rules")
        .add_cookie(Cookie::new("access_token", token.clone()))
        .await;
    got.assert_status_ok();
    assert_eq!(got.json::<serde_json::Value>()["rules"], "");

    // Update.
    let put = server
        .put("/api/filters/custom-rules")
        .add_cookie(Cookie::new("access_token", token.clone()))
        .json(&json!({ "rules": "||my.ads^\n@@||good.example^" }))
        .await;
    put.assert_status_ok();

    // Persisted and returned.
    let got2 = server
        .get("/api/filters/custom-rules")
        .add_cookie(Cookie::new("access_token", token))
        .await;
    assert_eq!(
        got2.json::<serde_json::Value>()["rules"],
        "||my.ads^\n@@||good.example^"
    );
}

#[tokio::test]
async fn test_get_filter_stats() {
    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let server = TestServer::new(ctx.router.clone()).expect("Failed to create test server");

    // Register
    let reg_response = server
        .post("/api/auth/register")
        .json(&json!({
            "username": "filter_stats",
            "password": "SecurePassword123!", "password_confirm": "SecurePassword123!"
        }))
        .await;
    let access_token = extract_access_token(&reg_response).expect("No access token");

    // Get stats
    let response = server
        .get("/api/filters/stats")
        .add_cookie(Cookie::new("access_token", access_token))
        .await;

    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    assert!(body["total_requests"].is_number());
    assert!(body["blocked_requests"].is_number());
}

#[tokio::test]
async fn test_reset_filter_stats_requires_admin() {
    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let server = TestServer::new(ctx.router.clone()).expect("Failed to create test server");

    // Register first user (admin)
    server
        .post("/api/auth/register")
        .json(&json!({
            "username": "admin_user",
            "password": "SecurePassword123!", "password_confirm": "SecurePassword123!"
        }))
        .await;

    // Register second user (regular)
    let reg_response = server
        .post("/api/auth/register")
        .json(&json!({
            "username": "regular_user",
            "password": "SecurePassword123!", "password_confirm": "SecurePassword123!"
        }))
        .await;
    let access_token = extract_access_token(&reg_response).expect("No access token");

    // Try to reset stats as regular user (should fail)
    let response = server
        .post("/api/filters/stats/reset")
        .add_cookie(Cookie::new("access_token", access_token))
        .await;

    response.assert_status_forbidden();
}

// ============================================================================
// Userscript Management Tests
// ============================================================================

#[tokio::test]
async fn test_list_userscripts() {
    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let server = TestServer::new(ctx.router.clone()).expect("Failed to create test server");

    // Register
    let reg_response = server
        .post("/api/auth/register")
        .json(&json!({
            "username": "userscript_test",
            "password": "SecurePassword123!", "password_confirm": "SecurePassword123!"
        }))
        .await;
    let access_token = extract_access_token(&reg_response).expect("No access token");

    // List userscripts
    let response = server
        .get("/api/userscripts")
        .add_cookie(Cookie::new("access_token", access_token))
        .await;

    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    assert!(body["data"].is_array());
    assert!(body["total"].is_number());
}

#[tokio::test]
async fn test_install_userscript() {
    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let server = TestServer::new(ctx.router.clone()).expect("Failed to create test server");

    // Register
    let reg_response = server
        .post("/api/auth/register")
        .json(&json!({
            "username": "install_test",
            "password": "SecurePassword123!", "password_confirm": "SecurePassword123!"
        }))
        .await;
    let access_token = extract_access_token(&reg_response).expect("No access token");

    let userscript_source = r#"
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

    // Install userscript
    let response = server
        .post("/api/userscripts")
        .add_cookie(Cookie::new("access_token", access_token))
        .json(&json!({
            "source": userscript_source
        }))
        .await;

    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    assert_eq!(body["name"], "Test Script");
    assert_eq!(body["version"], "1.0.0");
}

#[tokio::test]
async fn test_install_invalid_userscript() {
    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let server = TestServer::new(ctx.router.clone()).expect("Failed to create test server");

    // Register
    let reg_response = server
        .post("/api/auth/register")
        .json(&json!({
            "username": "invalid_script_test",
            "password": "SecurePassword123!", "password_confirm": "SecurePassword123!"
        }))
        .await;
    let access_token = extract_access_token(&reg_response).expect("No access token");

    // Try to install invalid userscript (missing metadata)
    let response = server
        .post("/api/userscripts")
        .add_cookie(Cookie::new("access_token", access_token))
        .json(&json!({
            "source": "console.log('no metadata');"
        }))
        .await;

    response.assert_status_bad_request();
}

#[tokio::test]
async fn test_install_empty_userscript() {
    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let server = TestServer::new(ctx.router.clone()).expect("Failed to create test server");

    // Register
    let reg_response = server
        .post("/api/auth/register")
        .json(&json!({
            "username": "empty_script_test",
            "password": "SecurePassword123!", "password_confirm": "SecurePassword123!"
        }))
        .await;
    let access_token = extract_access_token(&reg_response).expect("No access token");

    // Try to install empty userscript
    let response = server
        .post("/api/userscripts")
        .add_cookie(Cookie::new("access_token", access_token))
        .json(&json!({
            "source": ""
        }))
        .await;

    response.assert_status_bad_request();
}

#[tokio::test]
async fn test_get_userscript_stats() {
    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let server = TestServer::new(ctx.router.clone()).expect("Failed to create test server");

    // Register
    let reg_response = server
        .post("/api/auth/register")
        .json(&json!({
            "username": "userscript_stats",
            "password": "SecurePassword123!", "password_confirm": "SecurePassword123!"
        }))
        .await;
    let access_token = extract_access_token(&reg_response).expect("No access token");

    // Get stats
    let response = server
        .get("/api/userscripts/stats")
        .add_cookie(Cookie::new("access_token", access_token))
        .await;

    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    assert!(body["total_scripts"].is_number());
    assert!(body["enabled_scripts"].is_number());
}

// ============================================================================
// Authorization Tests
// ============================================================================

#[tokio::test]
async fn test_viewer_cannot_modify() {
    // This test verifies role-based access control
    // Since viewers don't exist yet in the registration flow,
    // this is a placeholder for when that feature is added
    let ctx = TestContext::new()
        .await
        .expect("Failed to create test context");
    let _server = TestServer::new(ctx.router).expect("Failed to create test server");

    // TODO: Once viewer role can be assigned, test that viewers cannot modify
}

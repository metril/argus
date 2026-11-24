//! The web UI's static fallback: client-side routes get the app shell, missing assets and API
//! paths do not.

mod common;

use axum::http::StatusCode;
use common::TestContext;

async fn ctx_with_dist() -> (TestContext, tempfile::TempDir) {
    let dist = tempfile::TempDir::new().unwrap();
    std::fs::write(dist.path().join("index.html"), "<html>APP SHELL</html>").unwrap();
    let p = dist.path().to_path_buf();
    let ctx = TestContext::with_config(move |c| {
        c.webui.enabled = true;
        c.webui.dist_path = p;
    })
    .await
    .unwrap();
    (ctx, dist)
}

#[tokio::test]
async fn app_routes_get_the_shell_and_missing_assets_and_api_paths_do_not() {
    let (ctx, _dist) = ctx_with_dist().await;
    // A script page whose id is a URL (a dot in the last decoded segment).
    let r = ctx
        .server
        .get("/userscripts/https%3A%2F%2Fgreasyfork.org%2Fx.user.js")
        .await;
    assert_eq!(r.status_code(), StatusCode::OK);
    assert!(r.text().contains("APP SHELL"));
    // A missing asset is a real 404.
    ctx.server
        .get("/missing.js")
        .await
        .assert_status(StatusCode::NOT_FOUND);
    // API paths never fall back to the shell.
    let r = ctx.server.get("/api/v1/nope.json").await;
    assert_eq!(r.status_code(), StatusCode::NOT_FOUND);
    assert!(!r.text().contains("APP SHELL"));
    // Traversal attempts serve the shell, never a file outside dist.
    let r = ctx.server.get("/userscripts/..%2F..%2Fetc%2Fpasswd").await;
    assert_eq!(r.status_code(), StatusCode::OK);
    assert!(r.text().contains("APP SHELL"));
    assert!(!r.text().contains("root:"));
}

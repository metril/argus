//! Registration status, DNS settings, user info extras, the time series and the built-in defaults.

mod common;

use axum::http::StatusCode;
use common::TestContext;
use serde_json::{json, Value};

async fn put(sess: &common::Sess, body: Value) -> axum_test::TestResponse {
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
async fn registration_status_is_public_and_closes_after_the_first_account() {
    let ctx = TestContext::new().await.unwrap();
    let r: Value = ctx.server.get("/api/v1/auth/registration").await.json();
    assert_eq!(r, json!({"open": true, "first_run": true}));
    let _admin = ctx.admin().await;
    let r: Value = ctx.server.get("/api/v1/auth/registration").await.json();
    assert_eq!(r, json!({"open": false, "first_run": false}));
}

#[tokio::test]
async fn dns_settings_validate_persist_and_show_in_config() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let got: Value = admin.get("/api/v1/config").await.json();
    assert_eq!(got["dns"]["cache_size"], 4096);
    assert_eq!(got["dns"]["servers"], json!([]));

    let r = put(
        &admin,
        json!({"dns": {"servers": ["1.1.1.1", "[2606:4700:4700::1111]:53", "9.9.9.9:5353"], "min_ttl_secs": 20, "max_ttl_secs": 600}}),
    )
    .await;
    r.assert_status_ok();
    let b: Value = r.json();
    assert_eq!(b["dns"]["servers"].as_array().unwrap().len(), 3);
    assert_eq!(
        (
            b["dns"]["min_ttl_secs"].clone(),
            b["dns"]["max_ttl_secs"].clone()
        ),
        (json!(20), json!(600))
    );
    // No running proxy here: reported as needing a restart rather than silently dropped.
    assert_eq!(b["restart_required"], json!(["dns"]));
    let overlay = std::fs::read_to_string(ctx.state.overlay_path.read().clone()).unwrap();
    assert!(
        overlay.contains("[dns]") && overlay.contains("1.1.1.1"),
        "{overlay}"
    );

    for bad in [
        json!({"dns": {"servers": ["not-an-ip"]}}),
        json!({"dns": {"servers": ["1.1.1.1:notaport"]}}),
        json!({"dns": {"min_ttl_secs": 100, "max_ttl_secs": 50}}),
        json!({"dns": {"cache_size": 0}}),
    ] {
        let r = put(&admin, bad.clone()).await;
        assert_eq!(r.status_code(), StatusCode::BAD_REQUEST, "{bad}");
    }
    // A rejected update changed nothing.
    let after: Value = admin.get("/api/v1/config").await.json();
    assert_eq!(after["dns"]["max_ttl_secs"], 600);
}

#[tokio::test]
async fn users_show_session_count_and_default_profile() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let me: Value = admin.get("/api/v1/auth/me").await.json();
    let id = me["id"].as_str().unwrap();
    let list: Value = admin.get("/api/v1/users").await.json();
    let row = &list["items"][0];
    assert!(row["session_count"].as_u64().unwrap() >= 1);
    assert_eq!(row["default_profile"], Value::Null);

    let url = format!("/api/v1/users/{id}");
    let r = admin
        .patch(&url)
        .json(&json!({"default_profile": "0"}))
        .await;
    r.assert_status_ok();
    assert_eq!(r.json::<Value>()["default_profile"], "0");
    let got: Value = admin.get(&url).await.json();
    assert_eq!(got["default_profile"], "0");
    assert!(got["session_count"].as_u64().unwrap() >= 1);
    admin
        .patch(&url)
        .json(&json!({"default_profile": "424242"}))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    let cleared: Value = admin
        .patch(&url)
        .json(&json!({"default_profile": ""}))
        .await
        .json();
    assert_eq!(cleared["default_profile"], Value::Null);
}

#[tokio::test]
async fn timeseries_ranges_shapes_and_scope() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    for (range, n, step) in [("6h", 12, 1800), ("24h", 48, 1800), ("7d", 28, 21600)] {
        let v: Value = admin
            .get(&format!("/api/v1/stats/timeseries?range={range}"))
            .await
            .json();
        assert_eq!(v["range"], range);
        assert_eq!(v["bucket_secs"], step);
        let pts = v["points"].as_array().unwrap();
        assert_eq!(pts.len(), n, "{range}");
        assert!(pts[0]["ts"].as_i64().unwrap() < pts[n - 1]["ts"].as_i64().unwrap());
        assert!(pts[0].get("requests").is_some() && pts[0].get("blocked").is_some());
    }
    let dflt: Value = admin.get("/api/v1/stats/timeseries").await.json();
    assert_eq!(dflt["range"], "6h");
    admin
        .get("/api/v1/stats/timeseries?range=1y")
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    let weak = ctx.token(&admin, &["lists:read"]).await;
    ctx.bearer("GET", "/api/v1/stats/timeseries", &weak)
        .await
        .assert_status_forbidden();
}

#[tokio::test]
async fn config_defaults_are_the_built_in_values_in_the_config_shape() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    // Change things, then ask for the defaults: they do not follow the live config.
    put(
        &admin,
        json!({"request_timeout_secs": 99, "dns": {"cache_size": 7}}),
    )
    .await
    .assert_status_ok();
    let d: Value = admin.get("/api/v1/config/defaults").await.json();
    let live: Value = admin.get("/api/v1/config").await.json();
    let d_keys: Vec<_> = d.as_object().unwrap().keys().cloned().collect();
    for k in live.as_object().unwrap().keys().filter(|k| *k != "bind") {
        assert!(d_keys.contains(k), "default is missing `{k}`");
    }
    assert_eq!(d["port"], 8080);
    assert_eq!(d["request_timeout_secs"], 60);
    assert_eq!(d["dns"]["cache_size"], 4096);
    assert_eq!(d["transparent_port"], Value::Null);
    let weak = ctx.token(&admin, &["lists:read"]).await;
    ctx.bearer("GET", "/api/v1/config/defaults", &weak)
        .await
        .assert_status_forbidden();
}

#[tokio::test]
async fn spa_routes_get_the_app_shell_with_200_but_missing_assets_stay_404() {
    let dist = tempfile::tempdir().unwrap();
    std::fs::write(dist.path().join("index.html"), "<html>shell</html>").unwrap();
    std::fs::create_dir(dist.path().join("assets")).unwrap();
    std::fs::write(dist.path().join("assets/app.js"), "1;").unwrap();
    let path = dist.path().to_path_buf();
    let ctx = TestContext::with_config(move |c| {
        c.webui.enabled = true;
        c.webui.dist_path = path;
    })
    .await
    .unwrap();
    for deep in ["/", "/userscripts", "/logs", "/admin/users/42", "/proxy"] {
        let r = ctx.server.get(deep).await;
        assert_eq!(r.status_code(), StatusCode::OK, "{deep}");
        assert_eq!(r.text(), "<html>shell</html>", "{deep}");
    }
    ctx.server.get("/assets/app.js").await.assert_text("1;");
    ctx.server
        .get("/assets/missing.js")
        .await
        .assert_status_not_found();
    // The API keeps its own 404, and a deep link is not confused with it.
    let r = ctx.server.get("/api/v1/nope").await;
    assert_eq!(r.status_code(), StatusCode::NOT_FOUND);
    assert!(r.text().contains("error"), "{}", r.text());
}

#[tokio::test]
async fn cursor_list_counts_carry_the_letters_present() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    for scope in ["apple.com", "avocado.com", "cherry.com", "9lives.com"] {
        admin
            .post("/api/v1/policy/site-rules")
            .json(&json!({"scope": scope, "preset": {"kind": "default"}}))
            .await
            .assert_status(StatusCode::CREATED);
    }
    let v: Value = admin.get("/api/v1/policy/site-rules?limit=1").await.json();
    assert_eq!(
        v["counts"]["letters"],
        json!(["#", "A", "C"]),
        "all pages, not just this one"
    );
    let v: Value = admin.get("/api/v1/policy/site-rules?q=cher").await.json();
    assert_eq!(
        v["counts"]["letters"],
        json!(["C"]),
        "follows the search text"
    );
    for url in [
        "/api/v1/lists?q=zzzz",
        "/api/v1/userscripts",
        "/api/v1/devices",
    ] {
        let v: Value = admin.get(url).await.json();
        assert!(v["counts"]["letters"].is_array(), "{url}");
    }
}

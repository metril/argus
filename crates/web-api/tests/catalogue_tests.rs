//! The filter catalogue API: status, collections with counts, apply (dry run and real), disable.

mod common;

use axum::http::StatusCode;
use common::TestContext;
use list_service::testkit::{filters_with_collections, Signer};
use serde_json::{json, Value};

const COLLECTIONS: &str = r#"[
    {"id":"rec","name":"Recommended","description":"d","warning":"may break","lists":["a","b"]},
    {"id":"mix","name":"Mixed","lists":["c","nope"]}
]"#;

/// A context whose filter catalogue verifies with a fresh key and holds a signed release.
async fn ctx_with_catalogue() -> TestContext {
    let ctx = TestContext::with_fetch_allowed(&["127.0.0.1"])
        .await
        .unwrap();
    let s = Signer::new();
    let cfg = list_service::ArgusConfig {
        base_url: "http://127.0.0.1:1".into(),
        public_key: s.public_key(),
        cache_dir: None,
    };
    ctx.state
        .filter_catalogue()
        .set_config_source(move || cfg.clone());
    let text = filters_with_collections(COLLECTIONS);
    let sig = s.sign(&text, "v2026.11.23", "filters.json");
    ctx.state
        .filter_catalogue()
        .apply(text, sig, None)
        .await
        .unwrap();
    ctx
}

fn install(ctx: &TestContext, id: &str, enabled: bool, trusted: bool) {
    let mut l = filter_engine::FilterList::new(
        id.into(),
        id.into(),
        format!("https://127.0.0.1:1/{id}.txt"),
    );
    l.enabled = enabled;
    l.trusted = trusted;
    ctx.state.filter_store.upsert(&l).unwrap();
}

fn ids(v: &Value) -> Vec<&str> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap())
        .collect()
}

async fn apply(admin: &common::Sess, id: &str, dry: bool) -> Value {
    let r = admin
        .post(&format!("/api/v1/lists/catalogue/collections/{id}/apply"))
        .json(&json!({"dry_run": dry}))
        .await;
    r.assert_status_ok();
    r.json()
}

#[tokio::test]
async fn the_catalogue_reports_status_and_collections_with_counts() {
    let ctx = ctx_with_catalogue().await;
    let admin = ctx.admin().await;
    let c: Value = admin.get("/api/v1/lists/catalogue").await.json();
    assert_eq!(c["version"], "v2026.11.23");
    assert_eq!(c["status"]["version"], "v2026.11.23");
    assert_eq!(c["status"]["origin"], "fetched");
    assert_eq!(c["status"]["url"], "http://127.0.0.1:1/filters.json");
    assert!(c["status"]["last_error"].is_null());
    let cols = c["collections"].as_array().unwrap();
    assert_eq!(cols.len(), 2);
    assert_eq!(cols[0]["id"], "rec");
    assert_eq!(cols[0]["warning"], "may break");
    assert_eq!(
        (cols[0]["installed"].as_u64(), cols[0]["enabled"].as_u64()),
        (Some(0), Some(0))
    );
    assert_eq!(cols[0]["total"], 2);
    assert_eq!(cols[1]["lists"], json!(["c"]), "the unknown id is gone");

    install(&ctx, "a", true, false);
    install(&ctx, "b", false, false);
    let c: Value = admin.get("/api/v1/lists/catalogue").await.json();
    let rec = &c["collections"][0];
    assert_eq!(
        (rec["installed"].as_u64(), rec["enabled"].as_u64()),
        (Some(2), Some(1))
    );
}

#[tokio::test]
async fn a_failed_check_is_visible_in_the_status() {
    let ctx = ctx_with_catalogue().await;
    let admin = ctx.admin().await;
    let r = admin.post("/api/v1/lists/catalogue/refresh").await;
    r.assert_status_ok();
    let st: Value = r.json();
    assert!(st["last_error"].is_string(), "{st}");
    assert!(st["last_checked"].is_string());
    assert!(st["last_ok"].is_null());
    assert_eq!(
        st["version"], "v2026.11.23",
        "the verified copy stays in force"
    );
    let c: Value = admin.get("/api/v1/lists/catalogue").await.json();
    assert_eq!(c["status"]["last_error"], st["last_error"]);
}

#[tokio::test]
async fn a_dry_run_changes_nothing_and_apply_adds_aligns_trust_and_rebuilds_once() {
    let ctx = ctx_with_catalogue().await;
    let admin = ctx.admin().await;
    let svc = &ctx.state.list_service;
    let before = svc.build_count();

    let d = apply(&admin, "rec", true).await;
    assert_eq!(d["dry_run"], true);
    assert_eq!(ids(&d["add"]), ["a", "b"]);
    assert_eq!(
        ids(&d["trust"]),
        ["a"],
        "only a is trusted in the catalogue"
    );
    assert!(d["enable"].as_array().unwrap().is_empty());
    svc.wait_idle().await;
    assert_eq!(svc.build_count(), before, "a dry run rebuilds nothing");
    assert!(ctx.state.filter_store.get("a").unwrap().is_none());

    let r = apply(&admin, "rec", false).await;
    assert_eq!(r["dry_run"], false);
    assert_eq!(ids(&r["add"]), ["a", "b"]);
    svc.wait_idle().await;
    assert_eq!(svc.build_count(), before + 1, "exactly one rebuild");
    let (a, b) = (
        ctx.state.filter_store.get("a").unwrap().unwrap(),
        ctx.state.filter_store.get("b").unwrap().unwrap(),
    );
    assert!(a.enabled && a.trusted && b.enabled && !b.trusted);
    let log: Value = admin.get("/api/v1/audit?limit=100").await.json();
    assert!(
        log["items"].as_array().unwrap().iter().any(|e| e["route"]
            .as_str()
            .is_some_and(|r| r.ends_with("#trusted=true"))
            && e["target"] == "a"
            && e["scope"] == "lists:write"),
        "{log}"
    );

    // Applying again is a no-op: everything is already on.
    let again = apply(&admin, "rec", false).await;
    assert_eq!(ids(&again["already"]), ["a", "b"]);
    assert!(again["add"].as_array().unwrap().is_empty());
    svc.wait_idle().await;
    assert_eq!(svc.build_count(), before + 1, "nothing changed, no rebuild");
}

#[tokio::test]
async fn apply_enables_disabled_lists_and_aligns_trust_both_ways() {
    let ctx = ctx_with_catalogue().await;
    let admin = ctx.admin().await;
    // a is untrusted here but trusted in the catalogue; b is trusted here but not there.
    install(&ctx, "a", false, false);
    install(&ctx, "b", false, true);
    let d = apply(&admin, "rec", true).await;
    assert_eq!(ids(&d["enable"]), ["a", "b"]);
    assert_eq!(ids(&d["trust"]), ["a", "b"]);
    assert!(d["add"].as_array().unwrap().is_empty());
    apply(&admin, "rec", false).await;
    ctx.state.list_service.wait_idle().await;
    let (a, b) = (
        ctx.state.filter_store.get("a").unwrap().unwrap(),
        ctx.state.filter_store.get("b").unwrap().unwrap(),
    );
    assert!(a.enabled && a.trusted);
    assert!(b.enabled && !b.trusted);
    let log: Value = admin.get("/api/v1/audit?limit=100").await.json();
    let routes: Vec<&str> = log["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["route"].as_str())
        .collect();
    assert!(
        routes.iter().any(|r| r.ends_with("#trusted=true")),
        "{routes:?}"
    );
    assert!(
        routes.iter().any(|r| r.ends_with("#trusted=false")),
        "{routes:?}"
    );
}

#[tokio::test]
async fn an_enabled_list_is_left_alone_even_if_its_trust_differs() {
    let ctx = ctx_with_catalogue().await;
    let admin = ctx.admin().await;
    install(&ctx, "a", true, false);
    let d = apply(&admin, "rec", true).await;
    assert_eq!(ids(&d["already"]), ["a"]);
    assert_eq!(ids(&d["add"]), ["b"]);
    assert!(d["trust"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn disable_turns_the_collection_off_without_deleting_and_rebuilds_once() {
    let ctx = ctx_with_catalogue().await;
    let admin = ctx.admin().await;
    install(&ctx, "a", true, true);
    install(&ctx, "b", false, false);
    install(&ctx, "keep", true, false);
    let svc = &ctx.state.list_service;
    let before = svc.build_count();
    let r = admin
        .post("/api/v1/lists/catalogue/collections/rec/disable")
        .await;
    r.assert_status_ok();
    let body: Value = r.json();
    assert_eq!(ids(&body["disabled"]), ["a"]);
    svc.wait_idle().await;
    assert_eq!(svc.build_count(), before + 1);
    let a = ctx.state.filter_store.get("a").unwrap().unwrap();
    assert!(!a.enabled && a.trusted, "off, not deleted");
    assert!(ctx.state.filter_store.get("keep").unwrap().unwrap().enabled);
    let c: Value = admin.get("/api/v1/lists/catalogue").await.json();
    assert_eq!(c["collections"][0]["installed"], 2);
    assert_eq!(c["collections"][0]["enabled"], 0);
}

#[tokio::test]
async fn unknown_collections_are_404_and_writes_need_lists_write() {
    let ctx = ctx_with_catalogue().await;
    let admin = ctx.admin().await;
    admin
        .post("/api/v1/lists/catalogue/collections/nope/apply")
        .json(&json!({"dry_run": true}))
        .await
        .assert_status(StatusCode::NOT_FOUND);
    admin
        .post("/api/v1/lists/catalogue/collections/nope/disable")
        .await
        .assert_status(StatusCode::NOT_FOUND);
    let viewer = ctx.user(&admin, "viewer_user", "viewer").await;
    viewer
        .get("/api/v1/lists/catalogue")
        .await
        .assert_status_ok();
    for p in [
        "/api/v1/lists/catalogue/refresh",
        "/api/v1/lists/catalogue/collections/rec/disable",
    ] {
        viewer.post(p).await.assert_status(StatusCode::FORBIDDEN);
    }
    viewer
        .post("/api/v1/lists/catalogue/collections/rec/apply")
        .json(&json!({"dry_run": false}))
        .await
        .assert_status(StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_failed_write_midway_still_audits_and_rebuilds_what_was_written() {
    use std::sync::atomic::Ordering;
    let ctx = ctx_with_catalogue().await;
    let admin = ctx.admin().await;
    let svc = &ctx.state.list_service;
    let before = svc.build_count();
    // The second write fails: a (trusted) is already in.
    ctx.state
        .fail_collection_write_at
        .store(1, Ordering::Relaxed);
    let r = admin
        .post("/api/v1/lists/catalogue/collections/rec/apply")
        .json(&json!({"dry_run": false}))
        .await;
    r.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    let body: Value = r.json();
    assert_eq!(body["error"]["code"], "collection_partial");
    assert!(body["error"]["message"].as_str().unwrap().contains("\"a\""));
    svc.wait_idle().await;
    assert_eq!(
        svc.build_count(),
        before + 1,
        "one rebuild for what was written"
    );
    assert!(ctx.state.filter_store.get("a").unwrap().unwrap().trusted);
    assert!(ctx.state.filter_store.get("b").unwrap().is_none());
    let log: Value = admin.get("/api/v1/audit?limit=100").await.json();
    assert!(
        log["items"].as_array().unwrap().iter().any(|e| e["route"]
            .as_str()
            .is_some_and(|r| r.ends_with("#trusted=true"))
            && e["target"] == "a"),
        "{log}"
    );

    // Disable fails midway the same way, after turning the first list off.
    install(&ctx, "b", true, false);
    ctx.state.filter_store.set_enabled("a", true).unwrap();
    let before = svc.build_count();
    let r = admin
        .post("/api/v1/lists/catalogue/collections/rec/disable")
        .await;
    r.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    svc.wait_idle().await;
    assert_eq!(svc.build_count(), before + 1);
    assert!(!ctx.state.filter_store.get("a").unwrap().unwrap().enabled);
    assert!(ctx.state.filter_store.get("b").unwrap().unwrap().enabled);
}

#[tokio::test]
async fn a_list_reusing_a_catalogue_id_with_another_url_is_never_touched() {
    let ctx = ctx_with_catalogue().await;
    let admin = ctx.admin().await;
    let mut mine = filter_engine::FilterList::new(
        "a".into(),
        "mine".into(),
        "https://127.0.0.1:1/other.txt".into(),
    );
    mine.enabled = false;
    ctx.state.filter_store.upsert(&mine).unwrap();
    install(&ctx, "b", false, false);

    let d = apply(&admin, "rec", true).await;
    assert_eq!(d["conflict"][0]["id"], "a");
    assert!(d["conflict"][0]["reason"].is_string());
    assert_eq!(ids(&d["enable"]), ["b"]);
    assert!(d["trust"].as_array().unwrap().is_empty());

    let r = apply(&admin, "rec", false).await;
    assert_eq!(r["conflict"][0]["id"], "a");
    ctx.state.list_service.wait_idle().await;
    let a = ctx.state.filter_store.get("a").unwrap().unwrap();
    assert!(!a.enabled && !a.trusted && a.name == "mine");

    // Counts and disable ignore it too.
    ctx.state.filter_store.set_enabled("a", true).unwrap();
    let c: Value = admin.get("/api/v1/lists/catalogue").await.json();
    assert_eq!(c["collections"][0]["installed"], 1);
    assert_eq!(c["collections"][0]["enabled"], 1);
    let off: Value = admin
        .post("/api/v1/lists/catalogue/collections/rec/disable")
        .await
        .json();
    assert_eq!(ids(&off["disabled"]), ["b"]);
    assert!(ctx.state.filter_store.get("a").unwrap().unwrap().enabled);
}

#[tokio::test]
async fn a_profile_restricted_token_cannot_apply_disable_or_refresh() {
    let ctx = ctx_with_catalogue().await;
    let admin = ctx.admin().await;
    let r = admin
        .post("/api/v1/profiles")
        .json(&json!({"name": "kids"}))
        .await;
    r.assert_status(StatusCode::CREATED);
    let pid = r.json::<Value>()["id"].as_str().unwrap().to_string();
    let r = admin
        .post("/api/v1/tokens")
        .json(&json!({"name": "r", "scopes": ["lists:read", "lists:write"], "profiles": [pid]}))
        .await;
    r.assert_status(StatusCode::CREATED);
    let t = r.json::<Value>()["secret"].as_str().unwrap().to_string();
    for p in [
        "/api/v1/lists/catalogue/collections/rec/apply",
        "/api/v1/lists/catalogue/collections/rec/disable",
        "/api/v1/lists/catalogue/refresh",
    ] {
        ctx.bearer("POST", p, &t)
            .json(&json!({"dry_run": false}))
            .await
            .assert_status(StatusCode::FORBIDDEN);
    }
    assert!(ctx.state.filter_store.get("a").unwrap().is_none());
}

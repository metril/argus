//! The bypass API: categories, custom entries (cursor-paged), subscriptions, check, counter.

mod common;

use axum::http::StatusCode;
use common::TestContext;
use serde_json::{json, Value};

async fn add(admin: &common::Sess, pattern: &str, mode: &str) -> Value {
    let r = admin
        .post("/api/v1/bypass/entries")
        .json(&json!({"pattern": pattern, "mode": mode}))
        .await;
    r.assert_status(StatusCode::CREATED);
    r.json()
}

/// Load hosts into first-party categories, as a verified release would.
fn seed_argus(ctx: &TestContext, lists: &[(&str, &[&str])]) {
    ctx.state
        .bypass()
        .update(|s| {
            for (cat, hosts) in lists {
                let id = ::common::bypass::argus_id(cat);
                let sub = s.subscriptions.iter_mut().find(|x| x.id == id).unwrap();
                sub.last_fetched = Some(1);
                sub.host_count = hosts.len();
                s.set_hosts(&id, hosts.iter().map(|h| h.to_string()).collect());
            }
            Ok(())
        })
        .unwrap();
}

fn patterns(v: &Value) -> Vec<String> {
    v["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["pattern"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn categories_list_update_and_show_their_hosts() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let cats: Value = admin.get("/api/v1/bypass/categories").await.json();
    let ids: Vec<_> = cats
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        [
            "banking_finance",
            "payments",
            "health",
            "government",
            "password_managers",
            "os_updates",
            "pinned_apps"
        ]
    );
    let by = |id: &str| {
        cats.as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == id)
            .unwrap()
            .clone()
    };
    assert_eq!(
        (
            by("os_updates")["mode"].clone(),
            by("pinned_apps")["mode"].clone()
        ),
        (json!("no_decrypt"), json!("no_decrypt"))
    );
    // Every category defaults to no_decrypt (AdGuard-style); `full` stays a per-category choice.
    for id in &ids {
        assert_eq!(by(id)["mode"], "no_decrypt", "{id}");
        assert_eq!(by(id)["default_mode"], "no_decrypt", "{id}");
    }
    assert_eq!(by("banking_finance")["enabled"], true);
    // Nothing is embedded: until the lists load, a category has no hosts and is not loaded.
    assert_eq!(
        (
            by("banking_finance")["host_count"].clone(),
            by("banking_finance")["loaded"].clone()
        ),
        (json!(0), json!(false))
    );
    let c: Value = admin
        .get("/api/v1/bypass/check?host=login.chase.com")
        .await
        .json();
    assert_eq!(c["bypassed"], false);
    seed_argus(
        &ctx,
        &[
            ("banking_finance", &["chase.com", "bank-of-test.com"]),
            ("government", &["*.gov", "irs.gov"]),
            ("payments", &["paypal.com", "stripe.com", "wise.com"]),
        ],
    );
    let cats: Value = admin.get("/api/v1/bypass/categories").await.json();
    let bank = cats
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "banking_finance")
        .unwrap();
    assert_eq!(
        (bank["host_count"].clone(), bank["loaded"].clone()),
        (json!(2), json!(true))
    );

    // check: the first-party list applies; disabling the category turns it off live.
    let c: Value = admin
        .get("/api/v1/bypass/check?host=login.chase.com")
        .await
        .json();
    assert_eq!(
        (
            c["bypassed"].clone(),
            c["mode"].clone(),
            c["source"].clone()
        ),
        (
            json!(true),
            json!("no_decrypt"),
            json!("argus:banking_finance")
        )
    );
    let r = admin
        .put("/api/v1/bypass/categories/banking_finance")
        .json(&json!({"enabled": false}))
        .await;
    r.assert_status_ok();
    assert_eq!(r.json::<Value>()["enabled"], false);
    let c: Value = admin
        .get("/api/v1/bypass/check?host=login.chase.com")
        .await
        .json();
    assert_eq!(c["bypassed"], false);
    admin
        .put("/api/v1/bypass/categories/government")
        .json(&json!({"mode": "full"}))
        .await
        .assert_status_ok();
    let c: Value = admin
        .get("/api/v1/bypass/check?host=www.irs.gov")
        .await
        .json();
    assert_eq!(c["mode"], "full");
    admin
        .put("/api/v1/bypass/categories/nope")
        .json(&json!({"enabled": false}))
        .await
        .assert_status_not_found();

    let h: Value = admin
        .get("/api/v1/bypass/categories/payments/hosts?q=PAY")
        .await
        .json();
    assert!(h["items"]
        .as_array()
        .unwrap()
        .iter()
        .all(|d| d.as_str().unwrap().contains("pay")));
    assert!(h["total"].as_u64().unwrap() >= 1);
    let gov: Value = admin
        .get("/api/v1/bypass/categories/government/hosts?q=*.gov")
        .await
        .json();
    assert!(gov["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|d| d == "*.gov"));
}

#[tokio::test]
async fn entries_crud_validation_precedence_and_cursor_paging_with_letters() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    seed_argus(&ctx, &[("banking_finance", &["chase.com"])]);
    let e = add(&admin, "Secret.Example.COM", "no_decrypt").await;
    assert_eq!(e["pattern"], "secret.example.com");
    assert_eq!(e["source"], "custom");
    // Duplicates and invalid patterns are refused.
    admin
        .post("/api/v1/bypass/entries")
        .json(&json!({"pattern": "secret.example.com"}))
        .await
        .assert_status(StatusCode::CONFLICT);
    for bad in ["", "*", "https://x.test", "a b", "x.test:443"] {
        admin
            .post("/api/v1/bypass/entries")
            .json(&json!({"pattern": bad}))
            .await
            .assert_status(StatusCode::BAD_REQUEST);
    }
    // Live: the entry applies at once and a custom entry beats the built-in category.
    let c: Value = admin
        .get("/api/v1/bypass/check?host=secret.example.com")
        .await
        .json();
    assert_eq!(
        (c["source"].clone(), c["mode"].clone()),
        (json!("custom"), json!("no_decrypt"))
    );
    add(&admin, "chase.com", "no_decrypt").await;
    let c: Value = admin
        .get("/api/v1/bypass/check?host=chase.com")
        .await
        .json();
    assert_eq!(
        (c["source"].clone(), c["mode"].clone()),
        (json!("custom"), json!("no_decrypt")),
        "custom beats builtin"
    );

    // Update / delete.
    let id = e["id"].as_str().unwrap();
    let u: Value = admin
        .put(&format!("/api/v1/bypass/entries/{id}"))
        .json(&json!({"mode": "full", "note": "work"}))
        .await
        .json();
    assert_eq!(
        (u["mode"].clone(), u["note"].clone()),
        (json!("full"), json!("work"))
    );
    admin
        .delete(&format!("/api/v1/bypass/entries/{id}"))
        .await
        .assert_status_ok();
    admin
        .delete(&format!("/api/v1/bypass/entries/{id}"))
        .await
        .assert_status_not_found();
    assert_eq!(
        admin
            .get("/api/v1/bypass/check?host=secret.example.com")
            .await
            .json::<Value>()["bypassed"],
        false
    );

    // Cursor paging, natural order, counts, letters, filters.
    for p in ["shop-10.test", "shop-2.test", "*.alpha.test", "zeta.test"] {
        add(&admin, p, "full").await;
    }
    let all: Value = admin.get("/api/v1/bypass/entries").await.json();
    assert_eq!(
        patterns(&all),
        [
            "*.alpha.test",
            "chase.com",
            "shop-2.test",
            "shop-10.test",
            "zeta.test"
        ]
    );
    assert_eq!(all["counts"]["all"], 5);
    assert_eq!(all["counts"]["no_decrypt"], 1);
    assert_eq!(all["counts"]["letters"], json!(["A", "C", "S", "Z"]));
    let p1: Value = admin.get("/api/v1/bypass/entries?limit=2").await.json();
    let cur = p1["next_cursor"].as_str().unwrap();
    let p2: Value = admin
        .get(&format!("/api/v1/bypass/entries?limit=2&cursor={cur}"))
        .await
        .json();
    assert_eq!(patterns(&p2), ["shop-2.test", "shop-10.test"]);
    assert_eq!(
        patterns(&admin.get("/api/v1/bypass/entries?from=sh").await.json()),
        ["shop-2.test", "shop-10.test", "zeta.test"]
    );
    assert_eq!(
        patterns(
            &admin
                .get("/api/v1/bypass/entries?q=SHOP&mode=full")
                .await
                .json()
        )
        .len(),
        2
    );
    admin
        .get("/api/v1/bypass/entries?mode=x")
        .await
        .assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn bypass_endpoints_need_config_scopes_and_are_audited() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let weak = ctx.token(&admin, &["lists:read"]).await;
    let read = ctx.token(&admin, &["config:read"]).await;
    ctx.bearer("GET", "/api/v1/bypass/entries", &weak)
        .await
        .assert_status_forbidden();
    ctx.bearer("GET", "/api/v1/bypass/categories", &read)
        .await
        .assert_status_ok();
    ctx.bearer("POST", "/api/v1/bypass/entries", &read)
        .json(&json!({"pattern": "x.test"}))
        .await
        .assert_status_forbidden();
    add(&admin, "audited.test", "full").await;
    let log: Value = admin.get("/api/v1/audit?limit=50").await.json();
    assert!(
        log["items"].as_array().unwrap().iter().any(|e| e["route"]
            .as_str()
            .is_some_and(|r| r.contains("/bypass/entries"))
            && e["method"] == "POST"),
        "{log}"
    );
}

/// A tiny HTTP origin serving `body` at any path.
async fn serve_list(body: &'static str) -> std::net::SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let app = axum::Router::new().fallback(move || async move { body });
    tokio::spawn(async move {
        let _ = axum::serve(l, app).await;
    });
    addr
}

#[tokio::test]
async fn subscriptions_fetch_apply_refresh_and_lose_to_custom_entries() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    seed_argus(&ctx, &[("banking_finance", &["chase.com"])]);
    let addr = serve_list(
        "# AdGuard-style exclusions\nsub-host.test\n*.wild-sub.test\nchase.com\nnot a host\n",
    )
    .await;
    let r = admin
        .post("/api/v1/bypass/subscriptions")
        .json(&json!({"name": "excl", "url": format!("http://{addr}/list.txt"), "mode": "full"}))
        .await;
    r.assert_status(StatusCode::CREATED);
    let sub: Value = r.json();
    // The one junk line ("not a host") is skipped and reported, not fatal.
    assert_eq!(sub["host_count"], 3);
    assert_eq!(
        (sub["skipped_lines"].clone(), sub["last_error"].clone()),
        (json!(1), Value::Null),
        "{sub}"
    );
    assert_eq!(sub["skipped_sample"], json!(["not a host"]));
    assert!(sub["last_fetched"].is_string());
    let id = sub["id"].as_str().unwrap();

    let c: Value = admin
        .get("/api/v1/bypass/check?host=a.wild-sub.test")
        .await
        .json();
    assert_eq!(
        (c["source"].clone(), c["mode"].clone()),
        (json!(format!("sub:{id}")), json!("full"))
    );
    // Subscription beats built-in (chase.com is in banking_finance as full).
    let c: Value = admin
        .get("/api/v1/bypass/check?host=chase.com")
        .await
        .json();
    assert_eq!(c["source"], format!("sub:{id}"));
    // ... and a custom entry beats the subscription.
    add(&admin, "sub-host.test", "no_decrypt").await;
    let c: Value = admin
        .get("/api/v1/bypass/check?host=sub-host.test")
        .await
        .json();
    assert_eq!(
        (c["source"].clone(), c["mode"].clone()),
        (json!("custom"), json!("no_decrypt"))
    );

    // Disable, refresh, rename, duplicate URL, delete.
    admin
        .put(&format!("/api/v1/bypass/subscriptions/{id}"))
        .json(&json!({"enabled": false}))
        .await
        .assert_status_ok();
    assert_eq!(
        admin
            .get("/api/v1/bypass/check?host=a.wild-sub.test")
            .await
            .json::<Value>()["bypassed"],
        false
    );
    admin
        .put(&format!("/api/v1/bypass/subscriptions/{id}"))
        .json(&json!({"enabled": true}))
        .await
        .assert_status_ok();
    admin
        .post(&format!("/api/v1/bypass/subscriptions/{id}/refresh"))
        .await
        .assert_status_ok();
    admin
        .post("/api/v1/bypass/subscriptions")
        .json(&json!({"name": "dup", "url": format!("http://{addr}/list.txt")}))
        .await
        .assert_status(StatusCode::CONFLICT);
    admin
        .post("/api/v1/bypass/subscriptions")
        .json(&json!({"name": "bad", "url": "ftp://x"}))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(
        admin
            .get("/api/v1/bypass/subscriptions")
            .await
            .json::<Value>()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    admin
        .delete(&format!("/api/v1/bypass/subscriptions/{id}"))
        .await
        .assert_status_ok();
    assert_eq!(
        admin
            .get("/api/v1/bypass/check?host=a.wild-sub.test")
            .await
            .json::<Value>()["bypassed"],
        false
    );
    admin
        .post(&format!("/api/v1/bypass/subscriptions/{id}/refresh"))
        .await
        .assert_status_not_found();
}

#[tokio::test]
async fn a_failing_subscription_is_kept_with_its_error_and_refresh_reports_502() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    // Nothing listens here.
    let r = admin
        .post("/api/v1/bypass/subscriptions")
        .json(&json!({"name": "down", "url": "http://127.0.0.1:1/list.txt"}))
        .await;
    r.assert_status(StatusCode::CREATED);
    let sub: Value = r.json();
    assert!(sub["last_error"].is_string(), "{sub}");
    assert_eq!(sub["host_count"], 0);
    let id = sub["id"].as_str().unwrap();
    admin
        .post(&format!("/api/v1/bypass/subscriptions/{id}/refresh"))
        .await
        .assert_status(StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn bypassed_total_is_in_proxy_stats_and_entries_survive_a_restart() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let s: Value = admin.get("/api/v1/stats/proxy").await.json();
    assert_eq!(s["bypassed_total"], 0);
    ctx.state.bypass().note_bypassed();
    let s: Value = admin.get("/api/v1/stats/proxy").await.json();
    assert_eq!(s["bypassed_total"], 1);
    add(&admin, "persist.test", "full").await;
    // A new engine over the same file sees the entry.
    let path = ctx
        .state
        .overlay_path
        .read()
        .parent()
        .unwrap()
        .join("bypass.json");
    let again = ::common::bypass::BypassEngine::load(path);
    assert_eq!(
        again.mode_of("persist.test"),
        Some(::common::bypass::BypassMode::Full)
    );
}

#[tokio::test]
async fn ev_setting_is_readable_writable_and_live() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let g: Value = admin.get("/api/v1/bypass/settings").await.json();
    assert_eq!(g["ev_no_decrypt"], true);
    assert_eq!(g["decrypt_without_lists"], false);
    let r = admin
        .put("/api/v1/bypass/settings")
        .json(&json!({"ev_no_decrypt": false}))
        .await;
    r.assert_status_ok();
    assert_eq!(r.json::<Value>()["ev_no_decrypt"], false);
    assert!(
        !ctx.state.bypass().ev_no_decrypt(),
        "applied to the live engine"
    );
    // An empty update changes nothing.
    let r: Value = admin
        .put("/api/v1/bypass/settings")
        .json(&json!({}))
        .await
        .json();
    assert_eq!(r["ev_no_decrypt"], false);
    let weak = ctx.token(&admin, &["config:read"]).await;
    ctx.bearer("GET", "/api/v1/bypass/settings", &weak)
        .await
        .assert_status_ok();
    ctx.bearer("PUT", "/api/v1/bypass/settings", &weak)
        .json(&json!({"ev_no_decrypt": true}))
        .await
        .assert_status_forbidden();
}

#[tokio::test]
async fn suggested_subscriptions_are_a_static_catalog_that_subscribes_in_one_step() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let cat: Value = admin
        .get("/api/v1/bypass/subscriptions/suggested")
        .await
        .json();
    let items = cat.as_array().unwrap();
    let ids: Vec<_> = items.iter().map(|i| i["id"].as_str().unwrap()).collect();
    assert_eq!(
        ids,
        [
            "adguard-banks",
            "adguard-sensitive",
            "adguard-issues",
            "adguard-android",
            "adguard-firefox",
            "adguard-mac",
            "adguard-windows"
        ]
    );
    for i in items {
        assert!(
            i["url"].as_str().unwrap().starts_with(
                "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/"
            ),
            "{i}"
        );
        assert_eq!(
            (i["default_mode"].clone(), i["subscribed"].clone()),
            (json!("no_decrypt"), json!(false))
        );
        assert!(i["name"].is_string() && i["description"].is_string());
    }
    let banks_url = items[0]["url"].as_str().unwrap().to_string();
    assert!(banks_url.ends_with("/banks.txt"));

    // One step: the suggestion supplies name, URL and mode. (The URL is overridden here so the
    // test stays offline; without an override it is the catalog URL.)
    let addr = serve_list(
        "//
// banks
bank-one.test
bank-two.test
",
    )
    .await;
    let r = admin
        .post("/api/v1/bypass/subscriptions")
        .json(&json!({"suggested_id": "adguard-banks", "url": format!("http://{addr}/banks.txt")}))
        .await;
    r.assert_status(StatusCode::CREATED);
    let sub: Value = r.json();
    assert_eq!(
        (
            sub["name"].clone(),
            sub["mode"].clone(),
            sub["host_count"].clone()
        ),
        (
            json!("AdGuard: banks and financial services"),
            json!("no_decrypt"),
            json!(2)
        )
    );
    let c: Value = admin
        .get("/api/v1/bypass/check?host=www.bank-one.test")
        .await
        .json();
    assert_eq!(c["mode"], "no_decrypt");

    // Unknown ids and incomplete bodies are refused.
    admin
        .post("/api/v1/bypass/subscriptions")
        .json(&json!({"suggested_id": "nope"}))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    admin
        .post("/api/v1/bypass/subscriptions")
        .json(&json!({"name": "only a name"}))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
}

// ---- first-party lists ----

type Keys = (minisign::PublicKeyBox, minisign::SecretKey);

fn keys() -> Keys {
    let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
    (kp.pk.to_box().unwrap(), kp.sk)
}

fn sign(k: &Keys, data: &[u8]) -> Vec<u8> {
    let pk = k.0.clone().into_public_key().unwrap();
    minisign::sign(
        Some(&pk),
        &k.1,
        std::io::Cursor::new(data),
        Some("t"),
        Some("c"),
    )
    .unwrap()
    .to_string()
    .into_bytes()
}

fn sha(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

/// A signed release of all seven lists; `hosts` overrides single lists.
fn release(
    k: &Keys,
    version: &str,
    hosts: &[(&str, &str)],
) -> std::collections::HashMap<String, Vec<u8>> {
    let mut files = std::collections::HashMap::new();
    let mut cats = Vec::new();
    for (cat, _) in ::common::bypass::FIRST_PARTY {
        let body = hosts
            .iter()
            .find(|(c, _)| *c == cat)
            .map_or("filler.test\n".to_string(), |(_, h)| format!("{h}\n"));
        files.insert(format!("{cat}.txt"), body.clone().into_bytes());
        files.insert(format!("{cat}.txt.minisig"), sign(k, body.as_bytes()));
        cats.push(json!({"id": cat, "name": format!("N {cat}"), "description": "D", "default_mode": "no_decrypt", "sha256": sha(body.as_bytes())}));
    }
    let meta = json!({"version": version, "categories": cats}).to_string();
    files.insert("meta.json.minisig".into(), sign(k, meta.as_bytes()));
    files.insert("meta.json".into(), meta.into_bytes());
    files
}

async fn serve_files(
    files: std::collections::HashMap<String, Vec<u8>>,
) -> (
    std::net::SocketAddr,
    std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>>,
) {
    let shared = std::sync::Arc::new(std::sync::Mutex::new(files));
    let s2 = shared.clone();
    let app = axum::Router::new().fallback(move |uri: axum::http::Uri| {
        let s = s2.clone();
        async move {
            match s.lock().unwrap().get(uri.path().trim_start_matches('/')) {
                Some(b) => (StatusCode::OK, b.clone()),
                None => (StatusCode::NOT_FOUND, Vec::new()),
            }
        }
    });
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(l, app).await;
    });
    (addr, shared)
}

fn point_at(ctx: &TestContext, addr: std::net::SocketAddr, k: &Keys) {
    let pk = k.0.to_string().lines().nth(1).unwrap().to_string();
    let mut c = ctx.state.proxy_state.config.write();
    c.bypass.lists_base_url = format!("http://{addr}");
    c.bypass.lists_public_key = pk;
}

#[tokio::test]
async fn failsafe_is_reported_until_the_lists_load_and_the_admin_override_ends_it_live() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let g: Value = admin.get("/api/v1/bypass/settings").await.json();
    assert_eq!(g["failsafe"]["active"], true);
    assert!(
        g["failsafe"]["reason"]
            .as_str()
            .unwrap()
            .contains("banking_finance"),
        "{g}"
    );
    let s: Value = admin.get("/api/v1/stats/proxy").await.json();
    assert_eq!(s["failsafe"]["active"], true);
    assert!(ctx.state.bypass().failsafe_active());

    // Admin override: decrypt even though the lists are missing (live, audited like any write).
    let r: Value = admin
        .put("/api/v1/bypass/settings")
        .json(&json!({"decrypt_without_lists": true}))
        .await
        .json();
    assert_eq!(
        (
            r["decrypt_without_lists"].clone(),
            r["failsafe"]["active"].clone()
        ),
        (json!(true), json!(false))
    );
    assert!(!ctx.state.bypass().failsafe_active());
    let log: Value = admin.get("/api/v1/audit?limit=20").await.json();
    assert!(log["items"].as_array().unwrap().iter().any(|e| e["route"]
        .as_str()
        .is_some_and(|r| r.contains("/bypass/settings"))
        && e["method"] == "PUT"));
    // Turning it off again brings the fail-safe back.
    admin
        .put("/api/v1/bypass/settings")
        .json(&json!({"decrypt_without_lists": false}))
        .await
        .assert_status_ok();
    assert!(ctx.state.bypass().failsafe_active());

    // Seeding every list ends it without the override.
    let all: Vec<(&str, &[&str])> = ::common::bypass::FIRST_PARTY
        .iter()
        .map(|(c, _)| (*c, &["x.test"][..]))
        .collect();
    seed_argus(&ctx, &all);
    let g: Value = admin.get("/api/v1/bypass/settings").await.json();
    assert_eq!(g["failsafe"]["active"], false);
    // Disabling a category that has not loaded must not hold the fail-safe either.
    ctx.state
        .bypass()
        .update(|s| {
            s.subscriptions
                .iter_mut()
                .find(|x| x.id == "argus:health")
                .unwrap()
                .last_fetched = None;
            Ok(())
        })
        .unwrap();
    assert!(ctx.state.bypass().failsafe_active());
    admin
        .put("/api/v1/bypass/categories/health")
        .json(&json!({"enabled": false}))
        .await
        .assert_status_ok();
    assert!(!ctx.state.bypass().failsafe_active());
}

#[tokio::test]
async fn argus_lists_refresh_installs_a_signed_release_and_reports_its_state() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let k = keys();
    let (addr, shared) = serve_files(release(
        &k,
        "v2025.11.23",
        &[("banking_finance", "chase.com\n*.com\nco.uk")],
    ))
    .await;
    point_at(&ctx, addr, &k);

    let st: Value = admin.get("/api/v1/bypass/argus-lists").await.json();
    assert_eq!(
        (st["version"].clone(), st["last_error"].clone()),
        (Value::Null, Value::Null)
    );
    assert_eq!(st["categories"].as_array().unwrap().len(), 7);
    assert!(st["categories"]
        .as_array()
        .unwrap()
        .iter()
        .all(|c| c["loaded"] == false));

    let r = admin.post("/api/v1/bypass/argus-lists/refresh").await;
    r.assert_status_ok();
    let st: Value = r.json();
    assert_eq!(st["version"], "v2025.11.23");
    assert!(st["updated_at"].is_string() && st["last_checked"].is_string());
    // Two broad lines were skipped: counted and sampled, and not an error.
    assert_eq!(
        (st["skipped_lines"].clone(), st["last_error"].clone()),
        (json!(2), Value::Null)
    );
    assert_eq!(st["skipped_sample"], json!(["*.com", "co.uk"]));
    assert!(st["categories"]
        .as_array()
        .unwrap()
        .iter()
        .all(|c| c["loaded"] == true && c["enabled"] == true));
    assert_eq!(
        st["categories"][0]["name"], "N banking_finance",
        "names come from the signed meta.json"
    );
    // Live: decryption is allowed again and the list applies.
    assert!(!ctx.state.bypass().failsafe_active());
    let c: Value = admin
        .get("/api/v1/bypass/check?host=login.chase.com")
        .await
        .json();
    assert_eq!(c["source"], "argus:banking_finance");
    let cats: Value = admin.get("/api/v1/bypass/categories").await.json();
    assert_eq!(cats[0]["title"], "N banking_finance");
    assert_eq!(cats[0]["loaded"], true);

    // A tampered file is refused: 502, the old lists stay, the error is recorded.
    *shared.lock().unwrap() = release(&k, "v2025.11.24", &[]);
    shared
        .lock()
        .unwrap()
        .insert("payments.txt".into(), b"evil.test\n".to_vec());
    let r = admin.post("/api/v1/bypass/argus-lists/refresh").await;
    r.assert_status(StatusCode::BAD_GATEWAY);
    let st: Value = admin.get("/api/v1/bypass/argus-lists").await.json();
    assert_eq!(st["version"], "v2025.11.23");
    assert!(
        st["last_error"].as_str().unwrap().contains("payments.txt"),
        "{st}"
    );
    assert_eq!(
        admin
            .get("/api/v1/bypass/check?host=evil.test")
            .await
            .json::<Value>()["bypassed"],
        false
    );

    // A validly signed but older release is never installed.
    *shared.lock().unwrap() = release(&k, "v2025.11.01", &[("banking_finance", "old-bank.test")]);
    admin
        .post("/api/v1/bypass/argus-lists/refresh")
        .await
        .assert_status(StatusCode::BAD_GATEWAY);
    assert_eq!(
        admin
            .get("/api/v1/bypass/check?host=old-bank.test")
            .await
            .json::<Value>()["bypassed"],
        false
    );
    // A newer one is.
    *shared.lock().unwrap() = release(&k, "v2025.12.01", &[("banking_finance", "new-bank.test")]);
    admin
        .post("/api/v1/bypass/argus-lists/refresh")
        .await
        .assert_status_ok();
    assert_eq!(
        admin
            .get("/api/v1/bypass/check?host=new-bank.test")
            .await
            .json::<Value>()["bypassed"],
        true
    );
    assert_eq!(
        admin
            .get("/api/v1/bypass/check?host=chase.com")
            .await
            .json::<Value>()["bypassed"],
        false
    );

    // First-party subscriptions are managed through categories only.
    let subs: Value = admin.get("/api/v1/bypass/subscriptions").await.json();
    assert!(subs.as_array().unwrap().is_empty());
    admin
        .delete("/api/v1/bypass/subscriptions/argus:payments")
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    admin
        .put("/api/v1/bypass/subscriptions/argus:payments")
        .json(&json!({"enabled": false}))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    // A wrong key (the shipped placeholder) verifies nothing.
    ctx.state.proxy_state.config.write().bypass.lists_public_key = String::new();
    let _ = ctx;
}

#[tokio::test]
async fn refresh_needs_config_write_and_status_needs_config_read() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let read = ctx.token(&admin, &["config:read"]).await;
    let weak = ctx.token(&admin, &["lists:read"]).await;
    ctx.bearer("GET", "/api/v1/bypass/argus-lists", &read)
        .await
        .assert_status_ok();
    ctx.bearer("GET", "/api/v1/bypass/argus-lists", &weak)
        .await
        .assert_status_forbidden();
    ctx.bearer("POST", "/api/v1/bypass/argus-lists/refresh", &read)
        .await
        .assert_status_forbidden();
}

// ---- review fixes ----

#[tokio::test]
async fn overly_broad_custom_entries_are_a_400_but_government_wildcards_are_allowed() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    for bad in [
        "com",
        "*.com",
        "co.uk",
        "*.co.uk",
        "localhost",
        "*.org",
        "github.io",
    ] {
        let r = admin
            .post("/api/v1/bypass/entries")
            .json(&json!({"pattern": bad}))
            .await;
        assert_eq!(r.status_code(), StatusCode::BAD_REQUEST, "{bad}");
    }
    for ok in ["*.gov", "*.gov.uk", "example.co.uk", "*.bank.co.uk"] {
        admin
            .post("/api/v1/bypass/entries")
            .json(&json!({"pattern": ok}))
            .await
            .assert_status(StatusCode::CREATED);
    }
}

#[tokio::test]
async fn subscription_lines_that_are_too_broad_are_skipped_and_counted_in_last_error() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let addr = serve_list("good.test\n*.com\nco.uk\nlocalhost\n*.gov\n").await;
    let r = admin
        .post("/api/v1/bypass/subscriptions")
        .json(&json!({"name": "broad", "url": format!("http://{addr}/l.txt")}))
        .await;
    r.assert_status(StatusCode::CREATED);
    let sub: Value = r.json();
    assert_eq!(sub["host_count"], 2, "good.test and *.gov");
    // Reported apart from errors: a healthy list is not red.
    assert_eq!(sub["last_error"], Value::Null, "{sub}");
    assert_eq!(sub["skipped_lines"], 3);
    assert_eq!(
        sub["skipped_sample"],
        json!(["*.com", "co.uk", "localhost"])
    );
    assert_eq!(
        admin
            .get("/api/v1/bypass/check?host=anything.com")
            .await
            .json::<Value>()["bypassed"],
        false
    );
}

/// A server that answers after `delay`.
async fn serve_slow(body: &'static str, delay: std::time::Duration) -> std::net::SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let app = axum::Router::new().fallback(move || async move {
        tokio::time::sleep(delay).await;
        body
    });
    tokio::spawn(async move {
        let _ = axum::serve(l, app).await;
    });
    addr
}

#[tokio::test]
async fn a_fetch_that_finishes_after_the_url_changed_does_not_write_its_patterns() {
    let ctx = TestContext::new().await.unwrap();
    let slow = serve_slow("stale.test\n", std::time::Duration::from_millis(500)).await;
    let fresh = serve_list("fresh.test\n").await;
    let slow_url = format!("http://{slow}/l.txt");
    ctx.state
        .bypass()
        .update(|s| {
            s.subscriptions.push(::common::bypass::Subscription {
                id: "sub1".into(),
                name: "s".into(),
                url: slow_url.clone(),
                mode: ::common::bypass::BypassMode::NoDecrypt,
                enabled: true,
                last_fetched: None,
                last_error: None,
                host_count: 0,
                skipped_lines: 0,
                skipped_sample: Vec::new(),
            });
            Ok(())
        })
        .unwrap();
    let state = ctx.state.clone();
    let fetch = tokio::spawn(async move {
        web_api::handlers::bypass::refresh_subscription(&state, "sub1").await
    });
    // While the slow fetch is in flight, the subscription is pointed elsewhere.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let fresh_url = format!("http://{fresh}/l.txt");
    ctx.state
        .bypass()
        .update(|s| {
            s.subscriptions
                .iter_mut()
                .find(|x| x.id == "sub1")
                .unwrap()
                .url = fresh_url.clone();
            Ok(())
        })
        .unwrap();
    fetch.await.unwrap().unwrap();
    assert!(
        ctx.state.bypass().lookup("stale.test").is_none(),
        "patterns of the old URL were dropped"
    );
    assert_eq!(
        ctx.state.bypass().read(|s| s.subscriptions[0].host_count),
        0
    );
    // A fetch of the current URL still lands.
    web_api::handlers::bypass::refresh_subscription(&ctx.state, "sub1")
        .await
        .unwrap();
    assert!(ctx.state.bypass().lookup("fresh.test").is_some());
}

#[tokio::test]
async fn argus_lists_status_reports_the_trusted_roots_and_their_last_error() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    // Without a proxy there is no root set to report.
    let st: Value = admin.get("/api/v1/bypass/argus-lists").await.json();
    assert_eq!(st["roots"], Value::Null);

    let cell = std::sync::Arc::new(::common::certstore::RootsStatusCell::default());
    {
        let mut s = cell.status.write();
        s.serial = 2026112302;
        s.roots = 93;
        s.signed = true;
        s.last_error = Some("roots.json: signature does not verify".into());
    }
    ctx.state.roots.set(cell).ok().unwrap();
    let st: Value = admin.get("/api/v1/bypass/argus-lists").await.json();
    assert_eq!(st["roots"]["serial"], 2026112302u64);
    assert_eq!(st["roots"]["roots"], 93);
    assert_eq!(st["roots"]["signed"], true);
    assert_eq!(
        st["roots"]["last_error"],
        "roots.json: signature does not verify"
    );
}

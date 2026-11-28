//! `/bypass/sites/{host}`: the extension's per-site "don't decrypt this site".

mod common;

use axum::http::StatusCode;
use common::TestContext;
use serde_json::{json, Value};

const P: &str = "/api/v1/bypass/sites";

fn seed_argus(ctx: &TestContext, cat: &str, hosts: &[&str]) {
    ctx.state
        .bypass()
        .update(|s| {
            let id = ::common::bypass::argus_id(cat);
            // Every first-party list counts as loaded, so the fail-safe is off.
            for x in s
                .subscriptions
                .iter_mut()
                .filter(|x| x.id.starts_with("argus:"))
            {
                x.last_fetched = Some(1);
            }
            s.set_hosts(&id, hosts.iter().map(|h| h.to_string()).collect());
            Ok(())
        })
        .unwrap();
}

fn mode_of(ctx: &TestContext, host: &str) -> Option<::common::bypass::BypassMode> {
    ctx.state.bypass().mode_of(host)
}

#[tokio::test]
async fn put_get_delete_walk_the_states_and_are_idempotent() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    seed_argus(&ctx, "banking_finance", &[]);
    let g: Value = admin.get(&format!("{P}/Shop.Example.COM.")).await.json();
    assert_eq!(g["host"], "shop.example.com");
    assert_eq!(
        (g["bypassed"].as_bool(), g["source"].as_str()),
        (Some(false), Some("none"))
    );
    assert_eq!(g["removable"], false);

    for _ in 0..2 {
        let r = admin.put(&format!("{P}/shop.example.com")).await;
        r.assert_status_ok();
        let v: Value = r.json();
        assert_eq!(v["bypassed"], true);
        assert_eq!(v["mode"], "no_decrypt");
        assert_eq!(v["source"], "extension");
        assert_eq!(v["removable"], true);
    }
    // One entry only, live in the lookup, exact host only.
    let entries: Value = admin.get("/api/v1/bypass/entries").await.json();
    assert_eq!(entries["total"], 1, "{entries}");
    assert_eq!(entries["items"][0]["source"], "extension");
    assert_eq!(entries["items"][0]["mode"], "no_decrypt");
    assert!(mode_of(&ctx, "shop.example.com").is_some());
    assert!(
        mode_of(&ctx, "www.shop.example.com").is_none(),
        "subdomains are not covered"
    );
    assert!(mode_of(&ctx, "example.com").is_none());

    for _ in 0..2 {
        let r = admin.delete(&format!("{P}/shop.example.com")).await;
        r.assert_status_ok();
        let v: Value = r.json();
        assert_eq!(
            (v["bypassed"].as_bool(), v["removable"].as_bool()),
            (Some(false), Some(false))
        );
    }
    assert!(mode_of(&ctx, "shop.example.com").is_none());
}

#[tokio::test]
async fn an_already_bypassed_host_is_not_duplicated_and_foreign_entries_are_never_removed() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    seed_argus(&ctx, "banking_finance", &["bank.test"]);
    admin
        .post("/api/v1/bypass/entries")
        .json(&json!({"pattern": "manual.test", "mode": "no_decrypt"}))
        .await
        .assert_status(StatusCode::CREATED);

    // Category (a plain list entry also covers subdomains in a category).
    let v: Value = admin.put(&format!("{P}/www.bank.test")).await.json();
    assert_eq!(v["source"], "category");
    assert_eq!(v["name"], "Banking and finance");
    assert_eq!(v["removable"], false);
    let d = admin.delete(&format!("{P}/www.bank.test")).await;
    d.assert_status(StatusCode::CONFLICT);
    assert_eq!(d.json::<Value>()["error"]["code"], "not_extension_entry");

    // Manual entry.
    let v: Value = admin.put(&format!("{P}/manual.test")).await.json();
    assert_eq!(
        (v["source"].as_str(), v["removable"].as_bool()),
        (Some("manual"), Some(false))
    );
    admin
        .delete(&format!("{P}/manual.test"))
        .await
        .assert_status(StatusCode::CONFLICT);

    // Nothing was added or removed.
    let entries: Value = admin.get("/api/v1/bypass/entries").await.json();
    assert_eq!(entries["total"], 1, "{entries}");
    assert_eq!(entries["items"][0]["source"], "custom");
    assert!(mode_of(&ctx, "manual.test").is_some());
}

#[tokio::test]
async fn a_subscription_match_is_named_and_the_failsafe_is_reported_but_removable_stays_false() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    ctx.state
        .bypass()
        .update(|s| {
            s.subscriptions.push(::common::bypass::Subscription {
                id: "s1".into(),
                name: "My exclusions".into(),
                url: "http://x.test/l".into(),
                mode: ::common::bypass::BypassMode::NoDecrypt,
                enabled: true,
                last_fetched: Some(1),
                last_error: None,
                host_count: 1,
                skipped_lines: 0,
                skipped_sample: vec![],
            });
            s.set_hosts("s1", vec!["subbed.test".into()]);
            Ok(())
        })
        .unwrap();
    let v: Value = admin.get(&format!("{P}/subbed.test")).await.json();
    assert_eq!(
        (v["source"].as_str(), v["name"].as_str()),
        (Some("subscription"), Some("My exclusions"))
    );
    admin
        .delete(&format!("{P}/subbed.test"))
        .await
        .assert_status(StatusCode::CONFLICT);

    // Fail-safe: an enabled first-party list that has never loaded.
    ctx.state
        .bypass()
        .update(|s| {
            for x in s
                .subscriptions
                .iter_mut()
                .filter(|x| x.id.starts_with("argus:"))
            {
                x.last_fetched = None;
            }
            s.decrypt_without_lists = false;
            Ok(())
        })
        .unwrap();
    let v: Value = admin.get(&format!("{P}/other.test")).await.json();
    assert_eq!(
        (v["bypassed"].as_bool(), v["source"].as_str()),
        (Some(true), Some("failsafe"))
    );
    assert!(v["name"].as_str().unwrap().contains("waiting"));
    // The fail-safe does not stop an entry being made, and removing it leaves the fail-safe.
    let v: Value = admin.put(&format!("{P}/other.test")).await.json();
    assert_eq!(
        (v["source"].as_str(), v["removable"].as_bool()),
        (Some("extension"), Some(true))
    );
    let v: Value = admin.delete(&format!("{P}/other.test")).await.json();
    assert_eq!(v["source"], "failsafe");
    // Idempotent delete under the fail-safe.
    admin
        .delete(&format!("{P}/other.test"))
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn host_validation() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    for bad in [
        "https%3A%2F%2Fa.test",
        "a.test%3A8080",
        "a.test%2Fpath",
        "*.a.test",
        "%2A.a.test",
        "a..test",
        ".a.test",
        "com",
        "co.uk",
        "singlelabel",
        "localhost",
        "foo.localhost",
        "printer.local",
        "x.internal",
        "127.0.0.1",
        "0.0.0.0",
        "%5B%3A%3A1%5D",
        "169.254.1.1",
        "a%20b.test",
        "user%40a.test",
        "a.test%3Fq",
        "a.test%23f",
        "::ffff:127.0.0.1",
        "::ffff:0.0.0.0",
        "::ffff:169.254.1.1",
        "::ffff:224.0.0.1",
        "%5B::ffff:7f00:1%5D",
        &"a".repeat(64),
        &format!("{}.test", "a.".repeat(130)),
    ] {
        let r = admin.put(&format!("{P}/{bad}")).await;
        assert_eq!(
            r.status_code(),
            StatusCode::BAD_REQUEST,
            "{bad}: {}",
            r.text()
        );
        admin
            .get(&format!("{P}/{bad}"))
            .await
            .assert_status(StatusCode::BAD_REQUEST);
        admin
            .delete(&format!("{P}/{bad}"))
            .await
            .assert_status(StatusCode::BAD_REQUEST);
    }
    let entries: Value = admin.get("/api/v1/bypass/entries").await.json();
    assert_eq!(entries["total"], 0);
    // Accepted and normalised.
    for (raw, want) in [
        ("EXAMPLE.org.", "example.org"),
        ("b%C3%BCcher.example", "xn--bcher-kva.example"),
        ("192.168.1.10", "192.168.1.10"),
        ("2001%3Adb8%3A%3A1", "2001:db8::1"),
        ("%5B2001%3ADB8%3A%3A2%5D", "2001:db8::2"),
    ] {
        let r = admin.put(&format!("{P}/{raw}")).await;
        assert_eq!(r.status_code(), StatusCode::OK, "{raw}: {}", r.text());
        assert_eq!(r.json::<Value>()["host"], want);
        assert!(mode_of(&ctx, want).is_some(), "{want}");
    }
}

#[tokio::test]
async fn the_argus_host_itself_is_refused() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let r = admin
        .put(&format!("{P}/argus.home.example"))
        .add_header("host", "argus.home.example:8080")
        .await;
    assert_eq!(r.status_code(), StatusCode::BAD_REQUEST, "{}", r.text());
    admin
        .put(&format!("{P}/other.home.example"))
        .add_header("host", "argus.home.example:8080")
        .await
        .assert_status_ok();
}

async fn restricted(admin: &common::Sess, pid: &str, scopes: &[&str]) -> String {
    let r = admin
        .post("/api/v1/tokens")
        .json(&json!({"name": "r", "scopes": scopes, "profiles": [pid]}))
        .await;
    r.assert_status(StatusCode::CREATED);
    r.json::<Value>()["secret"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn authorisation_matrix() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let url = format!("{P}/matrix.test");

    for scopes in [&["bypass:site"][..], &["config:write"][..]] {
        let t = ctx.token(&admin, scopes).await;
        ctx.bearer("GET", &url, &t).await.assert_status_ok();
        ctx.bearer("PUT", &url, &t).await.assert_status_ok();
        ctx.bearer("DELETE", &url, &t).await.assert_status_ok();
    }
    // Only the per-site routes: bypass:site opens nothing else in the bypass list.
    let site = ctx.token(&admin, &["bypass:site"]).await;
    for (m, p) in [
        ("GET", "/api/v1/bypass/entries"),
        ("POST", "/api/v1/bypass/entries"),
        ("GET", "/api/v1/bypass/categories"),
        ("GET", "/api/v1/bypass/check?host=a.test"),
    ] {
        ctx.bearer(m, p, &site).await.assert_status_forbidden();
    }
    for scopes in [
        &["config:read"][..],
        &["lists:read"][..],
        &["rules:site"][..],
    ] {
        let t = ctx.token(&admin, scopes).await;
        for m in ["GET", "PUT", "DELETE"] {
            let r = ctx.bearer(m, &url, &t).await;
            assert_eq!(r.status_code(), StatusCode::FORBIDDEN, "{scopes:?} {m}");
            assert_eq!(r.json::<Value>()["error"]["code"], "insufficient_scope");
        }
    }
    for m in ["GET", "PUT", "DELETE"] {
        let r = match m {
            "GET" => ctx.server.get(&url).await,
            "PUT" => ctx.server.put(&url).await,
            _ => ctx.server.delete(&url).await,
        };
        r.assert_status(StatusCode::UNAUTHORIZED);
    }
    assert!(mode_of(&ctx, "matrix.test").is_none());

    // A profile-restricted extension token may use exactly these routes (the list is global).
    let p = admin
        .post("/api/v1/profiles")
        .json(&json!({"name": "kids"}))
        .await;
    let pid = p.json::<Value>()["id"].as_str().unwrap().to_string();
    // Restricted to another profile: reads only (the list is global).
    let rt = restricted(&admin, &pid, &["bypass:site"]).await;
    ctx.bearer("GET", &url, &rt).await.assert_status_ok();
    for m in ["PUT", "DELETE"] {
        let r = ctx.bearer(m, &url, &rt).await;
        assert_eq!(r.status_code(), StatusCode::FORBIDDEN, "{m}");
        assert_eq!(r.json::<Value>()["error"]["code"], "profile_restricted");
    }
    // Restricted token whose profiles include the default profile: allowed.
    let r0 = restricted(&admin, "0", &["bypass:site"]).await;
    ctx.bearer("PUT", &url, &r0).await.assert_status_ok();
    ctx.bearer("DELETE", &url, &r0).await.assert_status_ok();
    ctx.bearer("GET", "/api/v1/bypass/entries", &rt)
        .await
        .assert_status_forbidden();
    // config:write-only restricted token stays out.
    let rw = restricted(&admin, &pid, &["config:write"]).await;
    for m in ["GET", "PUT", "DELETE"] {
        let r = ctx.bearer(m, &url, &rw).await;
        assert_eq!(r.status_code(), StatusCode::FORBIDDEN, "{m}");
        assert_eq!(r.json::<Value>()["error"]["code"], "profile_restricted");
    }
    assert!(mode_of(&ctx, "matrix.test").is_none());
}

#[tokio::test]
async fn changes_are_audited_with_the_actor_and_target_and_the_entry_names_who_added_it() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let t = ctx.token(&admin, &["bypass:site"]).await;
    ctx.bearer("PUT", &format!("{P}/audit.test"), &t)
        .await
        .assert_status_ok();
    ctx.bearer("DELETE", &format!("{P}/audit.test"), &t)
        .await
        .assert_status_ok();
    let log: Value = admin.get("/api/v1/audit?limit=50").await.json();
    let hit = |m: &str| {
        log["items"].as_array().unwrap().iter().find(|e| {
            e["method"] == m
                && e["route"]
                    .as_str()
                    .is_some_and(|r| r.contains("/bypass/sites/"))
        })
    };
    for m in ["PUT", "DELETE"] {
        let e = hit(m).unwrap_or_else(|| panic!("{m}: {log}"));
        assert_eq!(e["actor_type"], "token");
        assert_eq!(e["target"], "audit.test");
        assert_eq!(e["scope"], "bypass:site|config:write");
        assert_eq!(e["outcome"], "success");
    }
    ctx.bearer("PUT", &format!("{P}/noted.test"), &t)
        .await
        .assert_status_ok();
    let entries: Value = admin.get("/api/v1/bypass/entries").await.json();
    let note = entries["items"][0]["note"].as_str().unwrap();
    assert!(
        note.contains("extension") && note.contains("token"),
        "{note}"
    );
}

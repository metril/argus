//! Script policy API: settings, rules, temporary grants, explain/preview, import/export,
//! reports, scope enforcement and audit.

mod common;

use axum::http::StatusCode;
use common::TestContext;
use serde_json::{json, Value};

const B: &str = "/api/v1/policy";

fn preset(kind: &str) -> Value {
    json!({"kind": kind})
}

async fn enable(admin: &common::Sess) {
    let cur: Value = admin.get(&format!("{B}/settings")).await.json();
    let mut s = cur["settings"].clone();
    s["enabled"] = json!(true);
    admin
        .put(&format!("{B}/settings"))
        .json(&s)
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn settings_default_and_update_bump_generation() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let cur: Value = admin.get(&format!("{B}/settings")).await.json();
    let s = &cur["settings"];
    assert_eq!(s["enabled"], false);
    assert_eq!(s["global"]["kind"], "default");
    // Shipped default: first-party everything, third-party scripts/plugins/workers/pings blocked.
    let third: Vec<&str> = s["default_profile"]["third_party"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(!third.contains(&"script") && !third.contains(&"object") && !third.contains(&"ping"));
    assert!(third.contains(&"image") && third.contains(&"connect"));
    let g0 = cur["generation"].as_u64().unwrap();
    enable(&admin).await;
    let after: Value = admin.get(&format!("{B}/settings")).await.json();
    assert_eq!(after["settings"]["enabled"], true);
    assert!(after["generation"].as_u64().unwrap() > g0);
    // Unknown preset / bad profile rejected.
    let mut bad = after["settings"].clone();
    bad["global"] = json!({"kind": "paranoid"});
    admin
        .put(&format!("{B}/settings"))
        .json(&bad)
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    let mut bad = after["settings"].clone();
    bad["default_profile"]["page"] = json!(["script"]);
    admin
        .put(&format!("{B}/settings"))
        .json(&bad)
        .await
        .assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn site_rules_crud_filter_and_validation() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let create = |scope: &str, kind: &str| {
        admin
            .post(&format!("{B}/site-rules"))
            .json(&json!({"scope": scope, "preset": preset(kind), "note": "n"}))
    };
    let r: Value = {
        let resp = create("example.com", "trusted").await;
        resp.assert_status(StatusCode::CREATED);
        resp.json()
    };
    assert_eq!(r["scope"], "site:example.com");
    create("host:www.evil.net", "untrusted")
        .await
        .assert_status(StatusCode::CREATED);
    // Duplicate scope, bad scope, global scope, custom without profile.
    create("example.com", "untrusted")
        .await
        .assert_status(StatusCode::CONFLICT);
    create("site:www.example.com", "trusted")
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    create("*", "trusted")
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    create("other.org", "custom")
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    admin
        .post(&format!("{B}/site-rules"))
        .json(
            &json!({"scope": "x.org", "preset": {"kind": "custom", "profile": {
            "page": ["inline-script"], "first_party": ["script"], "third_party": []}}}),
        )
        .await
        .assert_status(StatusCode::CREATED);

    let all: Value = admin.get(&format!("{B}/site-rules")).await.json();
    assert_eq!(all["total"], 3);
    let q: Value = admin.get(&format!("{B}/site-rules?q=EVIL")).await.json();
    assert_eq!(q["total"], 1);
    let q: Value = admin
        .get(&format!("{B}/site-rules?preset=custom"))
        .await
        .json();
    assert_eq!(q["items"][0]["scope"], "site:x.org");
    let page: Value = admin.get(&format!("{B}/site-rules?limit=2")).await.json();
    assert_eq!(page["items"].as_array().unwrap().len(), 2);
    assert_eq!(page["has_more"], true);

    let id = r["id"].as_str().unwrap();
    let upd: Value = {
        let resp = admin
            .put(&format!("{B}/site-rules/{id}"))
            .json(&json!({"preset": preset("untrusted")}))
            .await;
        resp.assert_status_ok();
        resp.json()
    };
    assert_eq!(upd["preset"]["kind"], "untrusted");
    admin
        .delete(&format!("{B}/site-rules/{id}"))
        .await
        .assert_status_ok();
    admin
        .delete(&format!("{B}/site-rules/{id}"))
        .await
        .assert_status_not_found();
    admin
        .put(&format!("{B}/site-rules/nope"))
        .json(&json!({"preset": preset("trusted")}))
        .await
        .assert_status_not_found();
}

#[tokio::test]
async fn source_rules_crud_and_filter() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let body = json!({"page": "example.com", "source": "host:cdn.example.net",
                      "caps": ["script", "font"], "effect": "allow"});
    let r: Value = {
        let resp = admin.post(&format!("{B}/source-rules")).json(&body).await;
        resp.assert_status(StatusCode::CREATED);
        resp.json()
    };
    assert_eq!(r["effect"], "allow");
    admin
        .post(&format!("{B}/source-rules"))
        .json(&body)
        .await
        .assert_status(StatusCode::CONFLICT);
    // Page-level capability, unknown capability, bad effect.
    for (caps, effect) in [
        (json!(["eval"]), "allow"),
        (json!(["lasers"]), "allow"),
        (json!(["script"]), "maybe"),
    ] {
        admin
            .post(&format!("{B}/source-rules"))
            .json(&json!({"page": "a.org", "source": "*", "caps": caps, "effect": effect}))
            .await
            .assert_status(StatusCode::BAD_REQUEST);
    }
    admin
        .post(&format!("{B}/source-rules"))
        .json(
            &json!({"page": "*", "source": "site:ads.example", "caps": ["ping"], "effect": "deny"}),
        )
        .await
        .assert_status(StatusCode::CREATED);
    let l: Value = admin
        .get(&format!("{B}/source-rules?site=cdn"))
        .await
        .json();
    assert_eq!(l["total"], 1);
    let l: Value = admin
        .get(&format!("{B}/source-rules?effect=deny"))
        .await
        .json();
    assert_eq!(l["items"][0]["source"], "site:ads.example");
    let l: Value = admin
        .get(&format!("{B}/source-rules?page_scope=site:example.com"))
        .await
        .json();
    assert_eq!(l["total"], 1);

    let id = r["id"].as_str().unwrap();
    let u: Value = admin
        .put(&format!("{B}/source-rules/{id}"))
        .json(&json!({"caps": ["script"]}))
        .await
        .json();
    assert_eq!(u["caps"], json!(["script"]));
    admin
        .put(&format!("{B}/source-rules/{id}"))
        .json(&json!({"caps": []}))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    admin
        .delete(&format!("{B}/source-rules/{id}"))
        .await
        .assert_status_ok();
    admin
        .delete(&format!("{B}/source-rules/{id}"))
        .await
        .assert_status_not_found();
}

#[tokio::test]
async fn temp_grants_grant_list_revoke() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let g: Value = {
        let resp = admin
            .post(&format!("{B}/temp"))
            .json(&json!({"page": "example.com", "kind": "site", "preset": preset("trusted"), "ttl_secs": 3600}))
            .await;
        resp.assert_status(StatusCode::CREATED);
        resp.json()
    };
    assert!(g["remaining_secs"].as_u64().unwrap() > 3500);
    admin
        .post(&format!("{B}/temp"))
        .json(
            &json!({"page": "example.com", "kind": "source", "source": "host:cdn.net",
                      "caps": ["script"], "until_restart": true}),
        )
        .await
        .assert_status(StatusCode::CREATED);
    // Needs an expiry; bad kinds rejected.
    for body in [
        json!({"page": "example.com", "kind": "site", "preset": preset("trusted")}),
        json!({"page": "example.com", "kind": "site"}),
        json!({"page": "example.com", "kind": "weird", "ttl_secs": 5}),
        json!({"page": "example.com", "kind": "source", "caps": ["script"], "ttl_secs": 5}),
        json!({"page": "example.com", "kind": "site", "preset": preset("trusted"), "until_restart": true, "persist": true}),
    ] {
        admin
            .post(&format!("{B}/temp"))
            .json(&body)
            .await
            .assert_status(StatusCode::BAD_REQUEST);
    }
    let l: Value = admin.get(&format!("{B}/temp")).await.json();
    assert_eq!(l.as_array().unwrap().len(), 2);
    admin
        .delete(&format!("{B}/temp/{}", g["id"].as_str().unwrap()))
        .await
        .assert_status_ok();
    admin
        .delete(&format!("{B}/temp/{}", g["id"].as_str().unwrap()))
        .await
        .assert_status_not_found();
    assert_eq!(
        admin
            .get(&format!("{B}/temp"))
            .await
            .json::<Value>()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    admin.delete(&format!("{B}/temp")).await.assert_status_ok();
    assert!(admin
        .get(&format!("{B}/temp"))
        .await
        .json::<Value>()
        .as_array()
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn explain_and_preview() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    // Master switch off: nothing enforced.
    let e: Value = admin
        .get(&format!("{B}/explain?url=https://www.example.com/page"))
        .await
        .json();
    assert_eq!(e["enabled"], false);
    assert!(e["csp_header"].is_null());

    enable(&admin).await;
    let e: Value = admin
        .get(&format!("{B}/explain?url=https://www.example.com/page"))
        .await
        .json();
    assert_eq!(e["site"], "example.com");
    assert_eq!(
        e["csp_header"],
        "script-src 'self' *.example.com example.com 'unsafe-inline' 'unsafe-eval'; \
         worker-src 'self' *.example.com example.com blob:; \
         object-src 'self' *.example.com example.com"
    );
    assert!(e["network_enforce"]
        .as_array()
        .unwrap()
        .contains(&json!("script")));
    assert!(e["notes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|n| n.as_str().unwrap().starts_with("ping:")));

    // Preview: allow a CDN, without saving.
    let p: Value = admin
        .post(&format!("{B}/preview"))
        .json(&json!({"url": "https://www.example.com/", "add_source_rule": {
            "page": "example.com", "source": "host:cdn.example.net", "caps": ["script"], "effect": "allow"}}))
        .await
        .json();
    assert_eq!(p["changed"], true);
    assert_eq!(p["csp_removed"].as_array().unwrap().len(), 1);
    assert!(p["csp_added"][0]
        .as_str()
        .unwrap()
        .contains("cdn.example.net"));
    let again: Value = admin
        .get(&format!("{B}/explain?url=https://www.example.com/"))
        .await
        .json();
    assert_eq!(
        again["csp_header"], e["csp_header"],
        "preview must not persist"
    );
    // Preview: trusting the site removes the CSP; no-op preview changes nothing.
    let p: Value = admin
        .post(&format!("{B}/preview"))
        .json(
            &json!({"url": "https://www.example.com/", "add_site_rule": {
            "scope": "example.com", "preset": preset("trusted")}}),
        )
        .await
        .json();
    assert!(p["after"]["csp_header"].is_null());
    let p: Value = admin
        .post(&format!("{B}/preview"))
        .json(&json!({"url": "https://www.example.com/"}))
        .await
        .json();
    assert_eq!(p["changed"], false);

    // A saved rule shows up as matched, and a temp grant as active.
    admin
        .post(&format!("{B}/site-rules"))
        .json(&json!({"scope": "example.com", "preset": preset("untrusted")}))
        .await
        .assert_status(StatusCode::CREATED);
    admin
        .post(&format!("{B}/temp"))
        .json(&json!({"page": "example.com", "kind": "site", "preset": preset("trusted"), "ttl_secs": 60}))
        .await
        .assert_status(StatusCode::CREATED);
    let e: Value = admin
        .get(&format!("{B}/explain?url=https://www.example.com/"))
        .await
        .json();
    assert_eq!(e["matched_site_rules"].as_array().unwrap().len(), 1);
    assert_eq!(e["active_temps"].as_array().unwrap().len(), 1);
    assert!(
        e["csp_header"].is_null(),
        "temp trust overrides the untrusted rule"
    );

    admin
        .get(&format!("{B}/explain?url=ftp://x"))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    admin
        .get(&format!("{B}/explain"))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn export_import_round_trip() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    enable(&admin).await;
    admin
        .post(&format!("{B}/site-rules"))
        .json(&json!({"scope": "example.com", "preset": preset("trusted"), "note": "mine"}))
        .await
        .assert_status(StatusCode::CREATED);
    admin
        .post(&format!("{B}/source-rules"))
        .json(
            &json!({"page": "*", "source": "host:cdn.net", "caps": ["script"], "effect": "allow"}),
        )
        .await
        .assert_status(StatusCode::CREATED);
    let doc: Value = admin.get(&format!("{B}/export")).await.json();
    assert_eq!(doc["version"], 1);
    // Wipe, then import and compare.
    for kind in ["site-rules", "source-rules"] {
        let l: Value = admin.get(&format!("{B}/{kind}")).await.json();
        for it in l["items"].as_array().unwrap() {
            admin
                .delete(&format!("{B}/{kind}/{}", it["id"].as_str().unwrap()))
                .await
                .assert_status_ok();
        }
    }
    admin
        .post(&format!("{B}/import"))
        .json(&json!({"mode": "replace", "document": doc}))
        .await
        .assert_status_ok();
    let again: Value = admin.get(&format!("{B}/export")).await.json();
    assert_eq!(again, doc);
    // Merge is idempotent; bad modes and documents are rejected.
    admin
        .post(&format!("{B}/import"))
        .json(&json!({"mode": "merge", "document": doc}))
        .await
        .assert_status_ok();
    assert_eq!(admin.get(&format!("{B}/export")).await.json::<Value>(), doc);
    admin
        .post(&format!("{B}/import"))
        .json(&json!({"mode": "nope", "document": doc}))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    let mut bad = doc.clone();
    bad["version"] = json!(7);
    admin
        .post(&format!("{B}/import"))
        .json(&json!({"mode": "replace", "document": bad}))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(admin.get(&format!("{B}/export")).await.json::<Value>(), doc);
}

#[tokio::test]
async fn reports_list_blocked_sources_with_suggestions() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let empty: Value = admin.get(&format!("{B}/reports")).await.json();
    assert_eq!(empty["total"], 0);
    ctx.state.policy.record_block(
        script_policy::DEFAULT_PROFILE,
        "www.example.com",
        script_policy::BlockEvent {
            cap: script_policy::Capability::Script,
            source: Some("cdn.net".into()),
            sample: Some("https://cdn.net/a.js".into()),
            via: script_policy::Via::Network,
        },
    );
    ctx.state.policy.record_block(
        script_policy::DEFAULT_PROFILE,
        "other.org",
        script_policy::BlockEvent {
            cap: script_policy::Capability::Font,
            source: Some("f.net".into()),
            sample: None,
            via: script_policy::Via::Network,
        },
    );
    let r: Value = admin
        .get(&format!("{B}/reports?site=example.com"))
        .await
        .json();
    assert_eq!(r["total"], 1);
    let item = &r["items"][0]["items"][0];
    assert_eq!(item["capability"], "script");
    assert_eq!(item["suggested_allow"]["source"], "host:cdn.net");
    assert_eq!(r["items"][0]["page"], "www.example.com");
    assert_eq!(
        admin.get(&format!("{B}/reports")).await.json::<Value>()["total"],
        2
    );
}

#[tokio::test]
async fn scopes_are_enforced_and_writes_are_audited() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let reader = ctx.token(&admin, &["policy:read"]).await;
    let writer = ctx.token(&admin, &["policy:write", "policy:read"]).await;
    let other = ctx.token(&admin, &["lists:read"]).await;

    ctx.bearer("GET", &format!("{B}/settings"), &reader)
        .await
        .assert_status_ok();
    ctx.bearer("GET", &format!("{B}/explain?url=https://a.com/"), &reader)
        .await
        .assert_status_ok();
    ctx.bearer("GET", &format!("{B}/export"), &reader)
        .await
        .assert_status_ok();
    ctx.bearer("PUT", &format!("{B}/settings"), &reader)
        .await
        .assert_status_forbidden();
    ctx.bearer("POST", &format!("{B}/site-rules"), &reader)
        .json(&json!({"scope": "a.com", "preset": preset("trusted")}))
        .await
        .assert_status_forbidden();
    ctx.bearer("DELETE", &format!("{B}/temp"), &reader)
        .await
        .assert_status_forbidden();
    ctx.bearer("GET", &format!("{B}/settings"), &other)
        .await
        .assert_status_forbidden();
    ctx.bearer("GET", &format!("{B}/reports"), &other)
        .await
        .assert_status_forbidden();

    ctx.bearer("POST", &format!("{B}/site-rules"), &writer)
        .json(&json!({"scope": "a.com", "preset": preset("trusted")}))
        .await
        .assert_status(StatusCode::CREATED);
    ctx.bearer("POST", &format!("{B}/site-rules"), &reader)
        .json(&json!({"scope": "b.com", "preset": preset("trusted")}))
        .await
        .assert_status_forbidden();

    let log: Value = admin.get("/api/v1/audit?limit=100").await.json();
    let items = log["items"].as_array().unwrap();
    let ok = items
        .iter()
        .find(|e| e["route"] == "/api/v1/policy/site-rules" && e["status"] == 201)
        .unwrap_or_else(|| panic!("no audit entry for site rule creation: {log}"));
    assert_eq!(ok["actor_type"], "token");
    assert_eq!(ok["scope"], "policy:write");
    assert_eq!(ok["method"], "POST");
    let denied = items
        .iter()
        .find(|e| e["route"] == "/api/v1/policy/settings" && e["status"] == 403)
        .expect("denied write is audited");
    assert_eq!(denied["outcome"], "denied");
}

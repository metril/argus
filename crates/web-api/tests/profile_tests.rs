//! Profiles and devices API, profile-restricted tokens and the `?profile=` parameter.

mod common;

use axum::http::StatusCode;
use common::TestContext;
use serde_json::{json, Value};

const P: &str = "/api/v1/profiles";
const D: &str = "/api/v1/devices";
const ALL_PROFILE_SCOPES: [&str; 11] = [
    "profiles:read",
    "profiles:write",
    "devices:read",
    "devices:write",
    "policy:read",
    "policy:write",
    "scripts:read",
    "scripts:write",
    "rules:read",
    "rules:write",
    "rules:site",
];

/// Mint a token restricted to `profiles` (ids) for `sess`.
async fn restricted(sess: &common::Sess, scopes: &[&str], profiles: &[&str]) -> String {
    let resp = sess
        .post("/api/v1/tokens")
        .json(&json!({"name": "r", "scopes": scopes, "profiles": profiles}))
        .await;
    resp.assert_status(StatusCode::CREATED);
    resp.json::<Value>()["secret"].as_str().unwrap().to_string()
}

async fn mk_profile(admin: &common::Sess, name: &str) -> String {
    let r = admin.post(P).json(&json!({"name": name})).await;
    assert_eq!(r.status_code(), StatusCode::CREATED, "{}", r.text());
    r.json::<Value>()["id"].as_str().unwrap().to_string()
}

async fn mk_device(admin: &common::Sess, name: &str, profile: &str, ips: &[&str]) -> String {
    let r = admin
        .post(D)
        .json(&json!({"name": name, "profile_id": profile, "ips": ips}))
        .await;
    assert_eq!(r.status_code(), StatusCode::CREATED, "{}", r.text());
    r.json::<Value>()["id"].as_str().unwrap().to_string()
}

fn code(v: &Value) -> &str {
    v["error"]["code"].as_str().unwrap_or("")
}

// Written before the enforcement fix; it failed (200 instead of 403) on the old code.
#[tokio::test]
async fn restricted_token_cannot_touch_the_default_profile() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let p = mk_profile(&admin, "five").await;
    let t = restricted(&admin, &["policy:read", "scripts:read"], &[p.as_str()]).await;
    for path in ["/api/v1/policy/site-rules", "/api/v1/userscripts"] {
        ctx.bearer("GET", path, &t)
            .await
            .assert_status(StatusCode::FORBIDDEN);
    }
}

#[tokio::test]
async fn profile_crud_validation_and_default_protection() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;

    // Default profile is listed, readable, and protected.
    let list: Value = admin.get(P).await.json();
    assert_eq!(list["items"][0]["id"], "0");
    assert_eq!(list["items"][0]["name"], "default");
    admin.get(&format!("{P}/0")).await.assert_status_ok();
    admin
        .put(&format!("{P}/0"))
        .json(&json!({"name": "x"}))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    admin
        .delete(&format!("{P}/0"))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    let r = admin.post(P).json(&json!({"name": "default"})).await;
    assert!(r.status_code().is_client_error(), "{}", r.text());

    // Create, read, update, delete.
    admin
        .post("/api/v1/lists")
        .json(&json!({"id": "l1", "name": "L1", "url": "https://example.com/l1.txt"}))
        .await
        .assert_status(StatusCode::CREATED);
    let r = admin
        .post(P)
        .json(&json!({"name": "Kids", "description": "d", "lists": ["l1"], "rules": "||ads.example^"}))
        .await;
    r.assert_status(StatusCode::CREATED);
    let p: Value = r.json();
    let id = p["id"].as_str().unwrap().to_string();
    assert_eq!(p["lists"], json!(["l1"]));
    let u: Value = admin
        .put(&format!("{P}/{id}"))
        .json(&json!({"name": "Kids 2", "rules": ""}))
        .await
        .json();
    assert_eq!(u["name"], "Kids 2");
    assert_eq!(u["lists"], json!(["l1"]));
    assert_eq!(u["rules"], "");
    // Duplicate name (case-insensitive) -> 409.
    admin
        .post(P)
        .json(&json!({"name": "kids 2"}))
        .await
        .assert_status(StatusCode::CONFLICT);

    // Validation -> 400; malformed id -> 400; unknown -> 404.
    for body in [
        json!({"name": ""}),
        json!({"name": "a/b"}),
        json!({"name": "ok", "lists": ["nope"]}),
        json!({"name": "ok", "rules": "x".repeat(300_000)}),
    ] {
        admin
            .post(P)
            .json(&body)
            .await
            .assert_status(StatusCode::BAD_REQUEST);
    }
    for bad in ["abc", "-1", "1.5"] {
        admin
            .get(&format!("{P}/{bad}"))
            .await
            .assert_status(StatusCode::BAD_REQUEST);
    }
    admin
        .get(&format!("{P}/99999"))
        .await
        .assert_status(StatusCode::NOT_FOUND);
    admin
        .put(&format!("{P}/{id}"))
        .json(&json!({"lists": ["nope"]}))
        .await
        .assert_status(StatusCode::BAD_REQUEST);

    // Delete with a device -> 409; without -> 200 then 404.
    let dev = mk_device(&admin, "tab", &id, &["10.1.1.1"]).await;
    admin
        .delete(&format!("{P}/{id}"))
        .await
        .assert_status(StatusCode::CONFLICT);
    admin.delete(&format!("{D}/{dev}")).await.assert_status_ok();
    admin.delete(&format!("{P}/{id}")).await.assert_status_ok();
    admin
        .delete(&format!("{P}/{id}"))
        .await
        .assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn devices_crud_validation_and_token_shown_once() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let pid = mk_profile(&admin, "Kids").await;
    let dev = mk_device(&admin, "tablet", &pid, &["10.1.1.1", "192.168.5.0/24"]).await;

    // Validation.
    for body in [
        json!({"name": "", "profile_id": pid}),
        json!({"name": "x", "profile_id": "abc"}),
        json!({"name": "x", "profile_id": "424242"}),
        json!({"name": "x", "profile_id": pid, "ips": ["not-an-ip"]}),
        json!({"name": "x", "profile_id": pid, "ips": ["127.0.0.1"]}),
    ] {
        let r = admin.post(D).json(&body).await;
        assert_eq!(
            r.status_code(),
            StatusCode::BAD_REQUEST,
            "{body} {}",
            r.text()
        );
    }
    admin
        .post(D)
        .json(&json!({"name": "dup", "profile_id": pid, "ips": ["10.1.1.1"]}))
        .await
        .assert_status(StatusCode::CONFLICT);
    admin
        .get(&format!("{D}/abc"))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    admin
        .get(&format!("{D}/777"))
        .await
        .assert_status(StatusCode::NOT_FOUND);

    // Update name, profile and addresses.
    let pid2 = mk_profile(&admin, "Guests").await;
    let u: Value = admin
        .put(&format!("{D}/{dev}"))
        .json(&json!({"name": "tablet 2", "profile_id": pid2, "ips": ["10.1.1.9"]}))
        .await
        .json();
    assert_eq!(u["profile_id"], pid2);
    assert_eq!(u["ips"], json!(["10.1.1.9/32"]));

    // Token: shown once, never again.
    let r = admin.post(&format!("{D}/{dev}/token")).await;
    r.assert_status(StatusCode::CREATED);
    assert_eq!(r.header("cache-control"), "no-store");
    let token = r.json::<Value>()["token"].as_str().unwrap().to_string();
    assert!(token.len() > 16);
    let got = admin.get(&format!("{D}/{dev}")).await.text();
    let list = admin.get(D).await.text();
    let audit = admin.get("/api/v1/audit?limit=200").await.text();
    for body in [&got, &list, &audit] {
        assert!(!body.contains(&token), "token leaked: {body}");
    }
    let d: Value = serde_json::from_str(&got).unwrap();
    assert_eq!(d["has_token"], true);
    assert_eq!(d["token_hint"], token[token.len() - 4..]);
    assert!(d.get("token").is_none() && d.get("token_digest").is_none());
    assert!(audit.contains("/devices/{device_id}/token"));

    // Reissue replaces it; revoke clears it; revoking again is 404.
    let r2 = admin.post(&format!("{D}/{dev}/token")).await;
    assert_ne!(r2.json::<Value>()["token"].as_str().unwrap(), token);
    admin
        .delete(&format!("{D}/{dev}/token"))
        .await
        .assert_status_ok();
    let d: Value = admin.get(&format!("{D}/{dev}")).await.json();
    assert_eq!(d["has_token"], false);
    admin
        .delete(&format!("{D}/{dev}/token"))
        .await
        .assert_status(StatusCode::NOT_FOUND);
    admin
        .post("/api/v1/devices/777/token")
        .await
        .assert_status(StatusCode::NOT_FOUND);
}

/// Profile-scoped operations: routes under a profile-scoped scope family (or the per-profile
/// site exceptions) or already taking a profile parameter, as `(METHOD, path, has_param)`.
fn profile_scoped_ops(doc: &Value) -> Vec<(String, String, bool)> {
    let mut out = Vec::new();
    for (path, item) in doc["paths"].as_object().unwrap() {
        for (m, op) in item.as_object().unwrap() {
            let scopes: Vec<String> = op["security"][0]["bearer_auth"]
                .as_array()
                .map(|a| a.iter().map(|v| v.as_str().unwrap().to_string()).collect())
                .unwrap_or_default();
            let scoped = scopes
                .iter()
                .any(|s| s.starts_with("policy:") || s.starts_with("scripts:"))
                || path.starts_with("/api/v1/rules/site-exceptions");
            let has_param = op["parameters"].as_array().is_some_and(|ps| {
                ps.iter()
                    .any(|p| p["name"] == "profile" || p["name"] == "profile_id")
            });
            if scoped || has_param {
                out.push((m.to_uppercase(), path.clone(), has_param));
            }
        }
    }
    out
}

/// Table-driven over the published spec so a new profile-scoped route cannot be forgotten: it
/// must declare the profile parameter (i.e. use `ProfileParam`) and then refuse other profiles.
#[tokio::test]
async fn every_profile_scoped_route_takes_a_profile_and_refuses_other_profiles() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let p1 = mk_profile(&admin, "One").await;
    let p2 = mk_profile(&admin, "Two").await;
    let doc: Value = ctx.server.get("/api/v1/openapi.json").await.json();
    let ops = profile_scoped_ops(&doc);
    assert!(ops.len() >= 40, "only {} profile-scoped routes", ops.len());
    let tok = restricted(&admin, &ALL_PROFILE_SCOPES, &[&p1]).await;
    let any_param = regex::Regex::new(r"\{[^}]+\}").unwrap();

    for (m, path, has_param) in &ops {
        // The device list's `profile` is a filter over what the caller may see (other profiles
        // are refused, but no profile at all just lists the permitted devices).
        if m == "GET" && path == "/api/v1/devices" {
            continue;
        }
        assert!(
            has_param,
            "{m} {path} is profile-scoped but takes no profile (use ProfileParam)"
        );
        let full = path.replace("{profile_id}", &p2);
        let full = any_param.replace_all(&full, "x").into_owned();
        let send = |url: String| {
            let r = ctx.bearer(m, &url, &tok);
            if matches!(m.as_str(), "POST" | "PUT" | "PATCH") {
                r.json(&json!({}))
            } else {
                r
            }
        };
        if path.contains("{profile_id}") {
            // Path-addressed (profiles): the other profile is refused.
            let st = send(full.clone()).await.status_code();
            assert_eq!(st, StatusCode::FORBIDDEN, "{m} {path} on another profile");
            continue;
        }
        let r = send(format!("{full}?profile={p2}")).await;
        assert_eq!(
            r.status_code(),
            StatusCode::FORBIDDEN,
            "{m} {path} ?profile=other: {}",
            r.text()
        );
        let st = send(full.clone()).await.status_code();
        assert_eq!(st, StatusCode::FORBIDDEN, "{m} {path} default profile");
        let st = send(format!("{full}?profile=zzz")).await.status_code();
        assert_eq!(st, StatusCode::BAD_REQUEST, "{m} {path} malformed profile");
        let st = send(format!("{full}?profile={p1}")).await.status_code();
        assert_ne!(st, StatusCode::FORBIDDEN, "{m} {path} own profile");
    }
}

#[tokio::test]
async fn restricted_token_sees_and_edits_only_its_profiles_and_devices() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let p1 = mk_profile(&admin, "One").await;
    let p2 = mk_profile(&admin, "Two").await;
    let d1 = mk_device(&admin, "d1", &p1, &["10.0.0.1"]).await;
    let d2 = mk_device(&admin, "d2", &p2, &["10.0.0.2"]).await;
    let t = restricted(&admin, &ALL_PROFILE_SCOPES, &[&p1]).await;
    let call = |m: &str, path: String| ctx.bearer(m, &path, &t);

    let list: Value = call("GET", P.into()).await.json();
    let ids: Vec<&str> = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec![p1.as_str()]);
    let devs: Value = call("GET", D.into()).await.json();
    assert_eq!(devs["total"], 1);
    assert_eq!(devs["items"][0]["id"], d1);

    call("GET", format!("{P}/{p1}")).await.assert_status_ok();
    for (m, path) in [
        ("GET", format!("{P}/{p2}")),
        ("PUT", format!("{P}/{p2}")),
        ("DELETE", format!("{P}/{p2}")),
        ("GET", format!("{P}/0")),
        ("GET", format!("{D}/{d2}")),
        ("PUT", format!("{D}/{d2}")),
        ("DELETE", format!("{D}/{d2}")),
        ("POST", format!("{D}/{d2}/token")),
        ("DELETE", format!("{D}/{d2}/token")),
    ] {
        let r = call(m, path.clone()).json(&json!({})).await;
        assert_eq!(r.status_code(), StatusCode::FORBIDDEN, "{m} {path}");
    }
    // Cannot create profiles, nor create/move devices into profiles it lacks.
    call("POST", P.into())
        .json(&json!({"name": "New"}))
        .await
        .assert_status(StatusCode::FORBIDDEN);
    call("POST", D.into())
        .json(&json!({"name": "n", "profile_id": p2}))
        .await
        .assert_status(StatusCode::FORBIDDEN);
    call("PUT", format!("{D}/{d1}"))
        .json(&json!({"profile_id": p2}))
        .await
        .assert_status(StatusCode::FORBIDDEN);
    // Own device and profile: allowed, including a token.
    call("PUT", format!("{D}/{d1}"))
        .json(&json!({"name": "renamed"}))
        .await
        .assert_status_ok();
    call("POST", format!("{D}/{d1}/token"))
        .await
        .assert_status(StatusCode::CREATED);
    call("POST", D.into())
        .json(&json!({"name": "mine", "profile_id": p1}))
        .await
        .assert_status(StatusCode::CREATED);
    call("PUT", format!("{P}/{p1}"))
        .json(&json!({"description": "x"}))
        .await
        .assert_status_ok();
    // The other device is untouched.
    let d: Value = admin.get(&format!("{D}/{d2}")).await.json();
    assert_eq!(d["name"], "d2");
}

#[tokio::test]
async fn restricted_token_global_resources() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let p1 = mk_profile(&admin, "One").await;
    let all = [
        "lists:read",
        "lists:write",
        "rules:read",
        "rules:write",
        "rules:site",
        "config:read",
        "config:write",
        "stats:read",
        "stats:reset",
        "engine:reload",
        "users:read",
        "audit:read",
        "tokens:self",
    ];
    let t = restricted(&admin, &all, &[&p1]).await;
    // Reads of lists, config and stats are allowed.
    for path in ["/api/v1/lists", "/api/v1/config", "/api/v1/stats/filter"] {
        let s = ctx.bearer("GET", path, &t).await.status_code();
        assert_ne!(s, StatusCode::FORBIDDEN, "GET {path}");
    }
    // Global writes, users, audit and the default profile's custom rules are refused.
    for (m, path) in [
        ("POST", "/api/v1/lists"),
        ("POST", "/api/v1/lists/refresh"),
        ("PUT", "/api/v1/rules/custom"),
        ("PUT", "/api/v1/config"),
        ("POST", "/api/v1/engine/reload"),
        ("POST", "/api/v1/stats/filter/reset"),
        ("GET", "/api/v1/users"),
        ("GET", "/api/v1/audit"),
        ("GET", "/api/v1/rules/custom"),
    ] {
        let r = ctx.bearer(m, path, &t).json(&json!({})).await;
        assert_eq!(r.status_code(), StatusCode::FORBIDDEN, "{m} {path}");
        assert_eq!(code(&r.json::<Value>()), "profile_restricted", "{m} {path}");
    }
    // With access to the default profile the custom rules are readable.
    let t0 = restricted(&admin, &["rules:read"], &["0", &p1]).await;
    ctx.bearer("GET", "/api/v1/rules/custom", &t0)
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn restricted_token_cannot_mint_a_wider_token() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let p1 = mk_profile(&admin, "One").await;
    let p2 = mk_profile(&admin, "Two").await;
    let t = restricted(&admin, &["tokens:self", "policy:read"], &[&p1]).await;
    let mint = |body: Value| ctx.bearer("POST", "/api/v1/tokens", &t).json(&body);
    // Wider -> refused.
    mint(json!({"name": "w", "scopes": ["policy:read"], "profiles": [p1, p2]}))
        .await
        .assert_status(StatusCode::FORBIDDEN);
    // An unrestricted request inherits the parent's restriction.
    let r = mint(json!({"name": "i", "scopes": ["policy:read"]})).await;
    r.assert_status(StatusCode::CREATED);
    let body: Value = r.json();
    assert_eq!(body["token"]["profiles"], json!([p1]));
    let child = body["secret"].as_str().unwrap().to_string();
    ctx.bearer(
        "GET",
        &format!("/api/v1/policy/site-rules?profile={p2}"),
        &child,
    )
    .await
    .assert_status(StatusCode::FORBIDDEN);
    // An empty list is narrower (no profile at all), never wider.
    let r = mint(json!({"name": "e", "scopes": ["policy:read"], "profiles": []})).await;
    r.assert_status(StatusCode::CREATED);
    let none = r.json::<Value>()["secret"].as_str().unwrap().to_string();
    ctx.bearer(
        "GET",
        &format!("/api/v1/policy/site-rules?profile={p1}"),
        &none,
    )
    .await
    .assert_status(StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn profile_parameter_isolates_userscripts_policy_and_exceptions() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let p1 = mk_profile(&admin, "One").await;
    let p2 = mk_profile(&admin, "Two").await;
    let source = "// ==UserScript==\n// @name Iso\n// @namespace iso\n// @version 1\n// @match https://example.com/*\n// ==/UserScript==\n1;";

    // Userscripts: plan and confirm in p1 only.
    let plan: Value = admin
        .post(&format!("/api/v1/userscripts/plan?profile={p1}"))
        .json(&json!({"source": source}))
        .await
        .json();
    let plan_id = plan["plan_id"].as_str().unwrap();
    // A plan made for p1 cannot be confirmed under p2.
    admin
        .post(&format!(
            "/api/v1/userscripts/plan/{plan_id}/confirm?profile={p2}"
        ))
        .json(&json!({}))
        .await
        .assert_status(StatusCode::NOT_FOUND);
    let r = admin
        .post(&format!(
            "/api/v1/userscripts/plan/{plan_id}/confirm?profile={p1}"
        ))
        .json(&json!({}))
        .await;
    r.assert_status(StatusCode::CREATED);
    let sid = r.json::<Value>()["id"].as_str().unwrap().to_string();
    let scripts = |q: String| {
        let admin = &admin;
        async move {
            admin
                .get(&format!("/api/v1/userscripts{q}"))
                .await
                .json::<Value>()["total"]
                .as_u64()
                .unwrap()
        }
    };
    assert_eq!(scripts(format!("?profile={p1}")).await, 1);
    assert_eq!(scripts(format!("?profile={p2}")).await, 0);
    assert_eq!(scripts(String::new()).await, 0);
    admin
        .get(&format!("/api/v1/userscripts/{sid}?profile={p2}"))
        .await
        .assert_status(StatusCode::NOT_FOUND);
    admin
        .delete(&format!("/api/v1/userscripts/{sid}?profile={p2}"))
        .await
        .assert_status(StatusCode::NOT_FOUND);
    admin
        .get(&format!("/api/v1/userscripts/{sid}?profile={p1}"))
        .await
        .assert_status_ok();

    // Script policy rules.
    admin
        .post(&format!("/api/v1/policy/site-rules?profile={p1}"))
        .json(&json!({"scope": "example.com", "preset": {"kind": "trusted"}}))
        .await
        .assert_status(StatusCode::CREATED);
    let rules = |q: String| {
        let admin = &admin;
        async move {
            admin
                .get(&format!("/api/v1/policy/site-rules{q}"))
                .await
                .json::<Value>()["total"]
                .as_u64()
                .unwrap()
        }
    };
    assert_eq!(rules(format!("?profile={p1}")).await, 1);
    assert_eq!(rules(format!("?profile={p2}")).await, 0);
    assert_eq!(rules(String::new()).await, 0);

    // Site exceptions edit the profile's overlay rules, not the global custom rules.
    admin
        .put(&format!(
            "/api/v1/rules/site-exceptions/example.org?profile={p1}"
        ))
        .await
        .assert_status_ok();
    let pr: Value = admin.get(&format!("{P}/{p1}")).await.json();
    assert!(pr["rules"].as_str().unwrap().contains("example.org"));
    let g: Value = admin.get("/api/v1/rules/site-exceptions").await.json();
    assert_eq!(g["sites"], json!([]));
    admin
        .get("/api/v1/policy/site-rules?profile=424242")
        .await
        .assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn restricted_token_cannot_capture_other_devices_or_default_addresses() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let p1 = mk_profile(&admin, "One").await;
    let p2 = mk_profile(&admin, "Two").await;
    let d1 = mk_device(&admin, "d1", &p1, &["10.1.0.0/24"]).await;
    let _d2 = mk_device(&admin, "d2", &p2, &["10.2.0.0/16"]).await;
    let t = restricted(&admin, &ALL_PROFILE_SCOPES, &[&p1]).await;
    let post = |name: &str, ips: &[&str]| {
        ctx.bearer("POST", D, &t)
            .json(&json!({"name": name, "profile_id": p1, "ips": ips}))
    };
    // Inside another profile's range, covering it, or on unassigned (default) addresses.
    for ips in [
        &["10.2.3.4"][..],
        &["10.2.3.0/24"][..],
        &["10.0.0.0/8"][..],
        &["192.168.1.5"][..],
        &["10.1.0.5", "192.168.1.5"][..],
    ] {
        let r = post("x", ips).await;
        assert_eq!(
            r.status_code(),
            StatusCode::FORBIDDEN,
            "{ips:?}: {}",
            r.text()
        );
    }
    // A subnet of its own device's range is fine.
    post("ok", &["10.1.0.9"])
        .await
        .assert_status(StatusCode::CREATED);
    // Updating ips follows the same rule; leaving them alone does not matter.
    let r = ctx
        .bearer("PUT", &format!("{D}/{d1}"), &t)
        .json(&json!({"ips": ["10.1.0.0/24", "10.2.9.9"]}))
        .await;
    assert_eq!(r.status_code(), StatusCode::FORBIDDEN, "{}", r.text());
    ctx.bearer("PUT", &format!("{D}/{d1}"), &t)
        .json(&json!({"name": "renamed", "ips": ["10.1.0.0/24"]}))
        .await
        .assert_status_ok();
    // The victim still resolves to its own profile: nothing was stored.
    let devs: Value = admin.get(D).await.json();
    assert_eq!(devs["total"], 3);
    // Unrestricted callers may still nest (deliberate), identical nets conflict.
    admin
        .post(D)
        .json(&json!({"name": "nested", "profile_id": p1, "ips": ["10.2.3.4"]}))
        .await
        .assert_status(StatusCode::CREATED);
    admin
        .post(D)
        .json(&json!({"name": "dup", "profile_id": p1, "ips": ["10.2.3.4"]}))
        .await
        .assert_status(StatusCode::CONFLICT);
}

#[tokio::test]
async fn restricted_token_sees_only_its_profiles_blocked_requests() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let p1 = mk_profile(&admin, "One").await;
    ctx.state
        .shared_engine
        .install(filter_engine::compile_engine(
            &["||ads.test^\n".to_string()],
        ));
    let e = &ctx.state.shared_engine;
    e.check_for("https://ads.test/mine", "https://p.test/", "script", &p1);
    e.check_for("https://ads.test/theirs", "https://p.test/", "script", "0");
    e.check_for("https://ads.test/other", "https://p.test/", "script", "99");
    e.check("https://ads.test/anon", "https://p.test/", "script");
    let t = restricted(&admin, &["stats:read"], &[&p1]).await;
    let r: Value = ctx
        .bearer("GET", "/api/v1/stats/blocked/recent", &t)
        .await
        .json();
    assert_eq!(r["total"], 1, "{r}");
    assert_eq!(r["entries"][0]["url"], "https://ads.test/mine");
    assert_eq!(r["entries"][0]["client"], p1);
    let all: Value = admin.get("/api/v1/stats/blocked/recent").await.json();
    assert_eq!(all["total"], 4);
    // Aggregates that name domains are withheld too.
    let f: Value = ctx.bearer("GET", "/api/v1/stats/filter", &t).await.json();
    assert!(
        f["top_blocked_domains"].as_array().unwrap().is_empty(),
        "{f}"
    );
    let fa: Value = admin.get("/api/v1/stats/filter").await.json();
    assert!(!fa["top_blocked_domains"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn concurrent_site_exceptions_do_not_lose_updates() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let p1 = mk_profile(&admin, "One").await;
    let sites: Vec<String> = (0..24).map(|i| format!("s{i}.example")).collect();
    let url = |s: &str| format!("/api/v1/rules/site-exceptions/{s}?profile={p1}");
    let calls = sites.iter().map(|s| async { admin.put(&url(s)).await });
    let rs = futures_util::future::join_all(calls).await;
    for r in &rs {
        assert_eq!(r.status_code(), StatusCode::OK, "{}", r.text());
    }
    let got: Value = admin
        .get(&format!("/api/v1/rules/site-exceptions?profile={p1}"))
        .await
        .json();
    let n = got["sites"].as_array().map_or(0, |a| a.len());
    assert_eq!(n, sites.len(), "lost updates: {got}");
}

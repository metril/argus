//! Cursor paging of every list endpoint: ~450 rows served as three pages of 200, no repeats or
//! gaps, a cursor that returns the same page when replayed, and a filter combined with the
//! cursor. Each test owns its temp dir and stores, so they run in parallel.

mod common;

use std::collections::HashSet;

use axum::http::StatusCode;
use common::{Sess, TestContext};
use serde_json::{json, Value};

const N: usize = 450;

/// Follow `next_cursor` through `path` (200 per page). Returns the ids in order after checking:
/// no repeats, and replaying a cursor repeats its page and continues exactly where page one ended.
async fn walk(s: &Sess, path: &str, items: &str, id: impl Fn(&Value) -> String) -> Vec<String> {
    let sep = if path.contains('?') { '&' } else { '?' };
    let mut out: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0;
    let mut first_cursor: Option<String> = None;
    loop {
        let mut url = format!("{path}{sep}limit=200");
        if let Some(c) = &cursor {
            url.push_str(&format!("&cursor={c}"));
        }
        let r = s.get(&url).await;
        assert_eq!(r.status_code(), StatusCode::OK, "{url}: {}", r.text());
        let v: Value = r.json();
        let page: Vec<String> = v[items].as_array().unwrap().iter().map(&id).collect();
        assert!(page.len() <= 200);
        out.extend(page);
        pages += 1;
        assert!(pages <= 10, "runaway paging on {path}");
        first_cursor = first_cursor.or_else(|| v["next_cursor"].as_str().map(String::from));
        match v["next_cursor"].as_str() {
            Some(c) => {
                assert_eq!(v["has_more"], true);
                cursor = Some(c.to_string());
            }
            None => {
                assert_eq!(v["has_more"], false);
                break;
            }
        }
    }
    let uniq: HashSet<_> = out.iter().collect();
    assert_eq!(uniq.len(), out.len(), "duplicates on {path}");
    if let Some(c) = first_cursor {
        let a: Value = s
            .get(&format!("{path}{sep}limit=200&cursor={c}"))
            .await
            .json();
        let b: Value = s
            .get(&format!("{path}{sep}limit=200&cursor={c}"))
            .await
            .json();
        assert_eq!(a[items], b[items], "unstable cursor on {path}");
        let first: Vec<String> = a[items].as_array().unwrap().iter().map(&id).collect();
        assert_eq!(first, out[200..200 + first.len()], "cursor skipped rows");
    }
    out
}

/// Walk and require exactly `n` rows.
async fn walk_n(
    s: &Sess,
    path: &str,
    items: &str,
    n: usize,
    id: impl Fn(&Value) -> String,
) -> Vec<String> {
    let ids = walk(s, path, items, id).await;
    assert_eq!(ids.len(), n, "{path}");
    ids
}

fn field(k: &'static str) -> impl Fn(&Value) -> String {
    move |v| v[k].as_str().unwrap_or_default().to_string()
}

fn text(v: &Value) -> String {
    v.as_str().unwrap().to_string()
}

#[tokio::test]
async fn bypass_hosts_page_and_filter() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let hosts: Vec<String> = (0..N).map(|i| format!("bank{i}.example")).collect();
    ctx.state.bypass().update_volatile(|s| {
        s.set_hosts("argus:banking_finance", hosts.clone());
    });
    let base = "/api/v1/bypass/categories/banking_finance/hosts";
    let all = walk_n(&admin, base, "items", N, text).await;
    // Natural order: bank2 before bank10.
    assert_eq!(all[2], "bank2.example");
    let v: Value = admin.get(&format!("{base}?limit=200")).await.json();
    assert_eq!(v["total"], N);
    // Filter + cursor: hosts containing "7".
    let want = hosts.iter().filter(|h| h.contains('7')).count();
    let got = walk_n(&admin, &format!("{base}?q=7"), "items", want, text).await;
    assert!(got.iter().all(|h| h.contains('7')));
}

#[tokio::test]
async fn ext_rules_page_and_filter() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let mut l = filter_engine::FilterList::new(
        "ag".into(),
        "AG".into(),
        "https://127.0.0.1:1/ag.txt".into(),
    );
    l.format = filter_engine::ListFormat::Adguard;
    ctx.state.filter_store.upsert(&l).unwrap();
    let body: String = (0..N)
        .map(|i| format!("||x{i}.example^$replace=/a/b/\n"))
        .collect();
    ctx.state.filter_store.put_content("ag", &body).unwrap();
    ctx.state.list_service.reload_now().await;

    let base = "/api/v1/rules/ext";
    let all = walk_n(&admin, base, "items", N, field("raw")).await;
    let want = all.iter().filter(|r| r.contains("x7")).count();
    walk_n(&admin, &format!("{base}?q=x7"), "items", want, field("raw")).await;
    walk_n(
        &admin,
        &format!("{base}?list=ag&kind=replace"),
        "items",
        N,
        field("raw"),
    )
    .await;
    walk_n(
        &admin,
        &format!("{base}?list=other"),
        "items",
        0,
        field("raw"),
    )
    .await;
    // Legacy `page` still works.
    let v: Value = admin.get(&format!("{base}?page=3&limit=200")).await.json();
    assert_eq!(
        (v["items"].as_array().unwrap().len(), v["page"].as_u64()),
        (50, Some(3))
    );
    admin
        .get(&format!("{base}?cursor=!!"))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn users_page() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    for i in 0..N - 1 {
        admin
            .post("/api/v1/users")
            .json(&json!({"username": format!("user{i:03}"), "password": common::PASSWORD, "role": "viewer"}))
            .await
            .assert_status(StatusCode::CREATED);
    }
    let ids = walk_n(&admin, "/api/v1/users", "items", N, field("id")).await;
    // Oldest first: the admin account leads.
    let first: Value = admin.get("/api/v1/users?limit=1").await.json();
    assert_eq!(first["items"][0]["username"], "admin_user");
    assert_eq!(first["items"][0]["id"], ids[0].as_str());
}

#[tokio::test]
async fn sessions_page() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let me = ctx.state.session_store.get_all_users().unwrap()[0].id;
    for i in 0..N {
        ctx.state
            .session_manager
            .create_session(
                uuid::Uuid::new_v4(),
                me,
                "admin_user".into(),
                format!("jti{i}"),
                None,
                None,
                3600,
            )
            .unwrap();
    }
    // Plus the admin's own live login.
    walk_n(
        &admin,
        "/api/v1/admin/sessions",
        "items",
        N + 1,
        field("id"),
    )
    .await;
    walk_n(
        &admin,
        &format!("/api/v1/admin/sessions?user_id={me}"),
        "items",
        N + 1,
        field("id"),
    )
    .await;
    walk_n(&admin, "/api/v1/auth/sessions", "items", N + 1, field("id")).await;
}

#[tokio::test]
async fn tokens_page() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    for i in 0..N {
        admin
            .post("/api/v1/tokens")
            .json(&json!({"name": format!("t{i}"), "scopes": ["config:read"]}))
            .await
            .assert_status(StatusCode::CREATED);
    }
    walk_n(&admin, "/api/v1/tokens", "items", N, field("id")).await;
    walk_n(&admin, "/api/v1/admin/tokens", "items", N, field("id")).await;
}

#[tokio::test]
async fn profiles_page_and_search() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    for i in 0..N {
        admin
            .post("/api/v1/profiles")
            .json(&json!({"name": format!("prof-{i}")}))
            .await
            .assert_status(StatusCode::CREATED);
    }
    let all = walk(&admin, "/api/v1/profiles", "items", field("name")).await;
    assert!(all.len() >= N);
    let pos = |n: &str| all.iter().position(|x| x == n).unwrap();
    assert!(pos("prof-2") < pos("prof-10"), "natural order");
    let want = all.iter().filter(|n| n.contains("-7")).count();
    let got = walk_n(
        &admin,
        "/api/v1/profiles?q=-7",
        "items",
        want,
        field("name"),
    )
    .await;
    assert!(got.iter().all(|n| n.contains("-7")));
}

#[tokio::test]
async fn devices_page_and_filter() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let pid = admin
        .post("/api/v1/profiles")
        .json(&json!({"name": "kids"}))
        .await
        .json::<Value>()["id"]
        .as_str()
        .unwrap()
        .to_string();
    for i in 0..N {
        admin
            .post("/api/v1/devices")
            .json(&json!({"name": format!("dev-{i}"), "profile_id": pid, "ips": [format!("10.1.{}.{}", i / 250, i % 250 + 1)]}))
            .await
            .assert_status(StatusCode::CREATED);
    }
    walk_n(&admin, "/api/v1/devices", "items", N, field("id")).await;
    let want = (0..N).filter(|i| format!("dev-{i}").contains("-7")).count();
    walk_n(&admin, "/api/v1/devices?q=-7", "items", want, field("id")).await;
}

#[tokio::test]
async fn site_and_source_rules_page_and_filter() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    for i in 0..N {
        admin
            .post("/api/v1/policy/site-rules")
            .json(&json!({"scope": format!("shop{i}.com"), "preset": {"kind": "trusted"}}))
            .await
            .assert_status(StatusCode::CREATED);
        admin
            .post("/api/v1/policy/source-rules")
            .json(&json!({"page": "*", "source": format!("site:cdn{i}.example"), "caps": ["script"], "effect": "deny"}))
            .await
            .assert_status(StatusCode::CREATED);
    }
    let site = "/api/v1/policy/site-rules";
    walk_n(&admin, site, "items", N, field("id")).await;
    let want = (0..N)
        .filter(|i| format!("shop{i}.com").contains("shop7"))
        .count();
    walk_n(
        &admin,
        &format!("{site}?q=shop7"),
        "items",
        want,
        field("id"),
    )
    .await;

    let src = "/api/v1/policy/source-rules";
    walk_n(&admin, src, "items", N, field("id")).await;
    let want = (0..N)
        .filter(|i| format!("cdn{i}.example").contains("cdn7"))
        .count();
    walk_n(
        &admin,
        &format!("{src}?site=cdn7&effect=deny"),
        "items",
        want,
        field("id"),
    )
    .await;
}

fn audit_entry(
    at: chrono::DateTime<chrono::Utc>,
    who: &str,
    method: &str,
    route: &str,
) -> api_types::AuditEntry {
    api_types::AuditEntry {
        id: String::new(),
        at: at.to_rfc3339(),
        actor_type: "user".into(),
        actor_id: None,
        actor_name: Some(who.into()),
        method: method.into(),
        route: route.into(),
        scope: "x:write".into(),
        target: None,
        status: 200,
        outcome: "success".into(),
        ip: None,
        user_agent: None,
        request_id: None,
    }
}

#[tokio::test]
async fn audit_page_and_server_filters() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let base = chrono::Utc::now() - chrono::Duration::hours(2);
    for i in 0..N {
        ctx.state
            .audit
            .append(audit_entry(
                base + chrono::Duration::seconds(i as i64),
                if i % 3 == 0 { "alice" } else { "bob" },
                if i % 2 == 0 { "POST" } else { "DELETE" },
                &format!("/api/v1/thing{}", i % 5),
            ))
            .unwrap();
    }
    let all = walk(&admin, "/api/v1/audit?actor=alice", "items", field("id")).await;
    assert_eq!(all.len(), N.div_ceil(3));
    let del = walk(
        &admin,
        "/api/v1/audit?actor=alice&action=delete",
        "items",
        field("id"),
    )
    .await;
    assert_eq!(
        del.len(),
        (0..N).filter(|i| i % 3 == 0 && i % 2 == 1).count()
    );
    let q = walk(
        &admin,
        "/api/v1/audit?q=THING3&actor=bob",
        "items",
        field("id"),
    )
    .await;
    assert_eq!(q.len(), (0..N).filter(|i| i % 3 != 0 && i % 5 == 3).count());
    let since = (base + chrono::Duration::seconds(400))
        .to_rfc3339()
        .replace('+', "%2B");
    let recent = walk(
        &admin,
        &format!("/api/v1/audit?actor=alice&since={since}"),
        "items",
        field("id"),
    )
    .await;
    assert_eq!(recent.len(), (400..N).filter(|i| i % 3 == 0).count());

    // Newest first; an append between pages does not shift the cursor.
    let p1: Value = admin.get("/api/v1/audit?actor=alice&limit=5").await.json();
    let cur = p1["next_cursor"].as_str().unwrap().to_string();
    let ids: Vec<String> = p1["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(field("id"))
        .collect();
    assert!(ids.windows(2).all(|w| w[0] > w[1]));
    ctx.state
        .audit
        .append(audit_entry(
            chrono::Utc::now(),
            "alice",
            "POST",
            "/api/v1/new",
        ))
        .unwrap();
    let p2: Value = admin
        .get(&format!("/api/v1/audit?actor=alice&limit=5&cursor={cur}"))
        .await
        .json();
    let first2 = p2["items"][0]["id"].as_str().unwrap();
    assert!(first2 < ids.last().unwrap().as_str());
    admin
        .get("/api/v1/audit?cursor=zz")
        .await
        .assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn request_log_seed_is_not_clamped_to_200_and_honours_since() {
    use filter_engine::{EventAction, EventMode, EventRef};
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    for i in 0..N {
        let url = format!("https://h{i}.test/");
        ctx.state.shared_engine.record_request(&EventRef {
            action: EventAction::Allowed,
            method: "GET",
            url: &url,
            source_host: "page.test",
            request_type: "script",
            rule: "",
            list_id: None,
            client: Some("1"),
            status: Some(200),
            mode: EventMode::Explicit,
            error_kind: None,
            cert_fp: None,
        });
    }
    let v: Value = admin.get("/api/v1/logs/requests?limit=300").await.json();
    assert_eq!(v["entries"].as_array().unwrap().len(), 300);
    assert_eq!(v["has_more"], true);
    let future = (chrono::Utc::now() + chrono::Duration::hours(1))
        .to_rfc3339()
        .replace('+', "%2B");
    let v: Value = admin
        .get(&format!("/api/v1/logs/requests?limit=300&since={future}"))
        .await
        .json();
    assert_eq!(v["entries"].as_array().unwrap().len(), 0);
    let past = (chrono::Utc::now() - chrono::Duration::hours(1))
        .to_rfc3339()
        .replace('+', "%2B");
    let v: Value = admin
        .get(&format!("/api/v1/logs/requests?limit=1000&since={past}"))
        .await
        .json();
    assert_eq!(v["entries"].as_array().unwrap().len(), N);
}

#[tokio::test]
async fn cursor_row_deleted_between_pages_loses_and_repeats_nothing() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    for i in 0..9 {
        admin
            .post("/api/v1/policy/site-rules")
            .json(&json!({"scope": format!("del{i}.com"), "preset": {"kind": "trusted"}}))
            .await
            .assert_status(StatusCode::CREATED);
    }
    let base = "/api/v1/policy/site-rules?limit=3";
    let p1: Value = admin.get(base).await.json();
    let first: Vec<String> = p1["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(field("id"))
        .collect();
    // Delete the row the cursor points at.
    admin
        .delete(&format!("/api/v1/policy/site-rules/{}", first[2]))
        .await
        .assert_status_ok();
    let cur = p1["next_cursor"].as_str().unwrap();
    let p2: Value = admin.get(&format!("{base}&cursor={cur}")).await.json();
    let second: Vec<String> = p2["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(field("id"))
        .collect();
    let scopes: Vec<String> = p2["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(field("scope"))
        .collect();
    assert_eq!(second.len(), 3);
    assert!(second.iter().all(|i| !first.contains(i)), "no repeats");
    assert_eq!(
        scopes,
        ["site:del3.com", "site:del4.com", "site:del5.com"],
        "no gap"
    );
}

#[tokio::test]
async fn ext_rules_cursor_is_refused_after_a_rebuild() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let mut l = filter_engine::FilterList::new(
        "ag".into(),
        "AG".into(),
        "https://127.0.0.1:1/ag.txt".into(),
    );
    l.format = filter_engine::ListFormat::Adguard;
    ctx.state.filter_store.upsert(&l).unwrap();
    let body = |n: usize| -> String {
        (0..n)
            .map(|i| format!("||x{i}.example^$replace=/a/b/\n"))
            .collect()
    };
    ctx.state.filter_store.put_content("ag", &body(30)).unwrap();
    ctx.state.list_service.reload_now().await;
    let p1: Value = admin.get("/api/v1/rules/ext?limit=10").await.json();
    assert_eq!(p1["items"][0]["index"], 0);
    let cur = p1["next_cursor"].as_str().unwrap().to_string();
    let ok = admin
        .get(&format!("/api/v1/rules/ext?limit=10&cursor={cur}"))
        .await;
    ok.assert_status_ok();
    assert_eq!(ok.json::<Value>()["items"][0]["index"], 10);

    ctx.state.filter_store.put_content("ag", &body(31)).unwrap();
    ctx.state.list_service.reload_now().await;
    let r = admin
        .get(&format!("/api/v1/rules/ext?limit=10&cursor={cur}"))
        .await;
    r.assert_status(StatusCode::CONFLICT);
    assert_eq!(r.json::<Value>()["error"]["code"], "ext_rules_changed");
    admin
        .get("/api/v1/rules/ext?limit=10")
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn bypass_hosts_keep_their_old_limits() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let hosts: Vec<String> = (0..N).map(|i| format!("h{i}.example")).collect();
    ctx.state
        .bypass()
        .update_volatile(|s| s.set_hosts("argus:banking_finance", hosts));
    let base = "/api/v1/bypass/categories/banking_finance/hosts";
    // Old clients: no limit gives 200; limit=1000 gives everything in one response.
    let v: Value = admin.get(base).await.json();
    assert_eq!(v["items"].as_array().unwrap().len(), 200);
    let v: Value = admin.get(&format!("{base}?limit=1000")).await.json();
    assert_eq!(v["items"].as_array().unwrap().len(), N);
    assert_eq!(v["has_more"], false);
}

#[tokio::test]
async fn users_filter_and_cursor_combined() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    for i in 0..N - 1 {
        let role = if i % 2 == 0 { "viewer" } else { "user" };
        admin
            .post("/api/v1/users")
            .json(&json!({"username": format!("u{i:03}"), "password": common::PASSWORD, "role": role}))
            .await
            .assert_status(StatusCode::CREATED);
    }
    let want = (0..N - 1)
        .filter(|i| i % 2 == 0 && format!("u{i:03}").contains('7'))
        .count();
    walk_n(
        &admin,
        "/api/v1/users?q=7&roles=viewer",
        "items",
        want,
        field("id"),
    )
    .await;
    let others = walk(
        &admin,
        "/api/v1/users?roles=admin,user",
        "items",
        field("username"),
    )
    .await;
    assert_eq!(others.len(), 1 + (0..N - 1).filter(|i| i % 2 == 1).count());
}

#[tokio::test]
async fn userscript_storage_page_and_search() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let src = "// ==UserScript==\n// @name Paging\n// @namespace pg\n// @version 1.0\n// @match https://example.com/*\n// @grant GM_setValue\n// ==/UserScript==\nconsole.log(1);";
    let plan: Value = admin
        .post("/api/v1/userscripts/plan")
        .json(&json!({"source": src}))
        .await
        .json();
    let r = admin
        .post(&format!(
            "/api/v1/userscripts/plan/{}/confirm",
            plan["plan_id"].as_str().unwrap()
        ))
        .json(&json!({}))
        .await;
    let id = r.json::<Value>()["id"].as_str().unwrap().to_string();
    let space = userscript_engine::storage::ns(userscript_engine::DEFAULT_PROFILE, &id);
    let st = ctx.state.userscript_manager.storage();
    for i in 0..N {
        st.set_raw(&space, &format!("k{i:04}"), json!(i)).unwrap();
    }
    let enc: String = id
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    let base = format!("/api/v1/userscripts/{enc}/storage");
    walk_n(&admin, &base, "values", N, field("name")).await;
    // Old clients (no limit, no cursor) still get every value in one response.
    let all: Value = admin.get(&base).await.json();
    assert_eq!(all["values"].as_array().unwrap().len(), N);
    let v: Value = admin.get(&format!("{base}?limit=10")).await.json();
    assert_eq!(
        (v["total"].as_u64(), v["values"].as_array().map(Vec::len)),
        (Some(N as u64), Some(10))
    );
    assert!(v["used_bytes"].as_u64().unwrap() > 0);
    let want = (0..N).filter(|i| format!("k{i:04}").contains("77")).count();
    walk_n(
        &admin,
        &format!("{base}?q=77"),
        "values",
        want,
        field("name"),
    )
    .await;
}

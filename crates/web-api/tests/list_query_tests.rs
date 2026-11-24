//! Search, status/mode filters, sorting and counts of the site-rule and filter-list endpoints.
//! Each test owns its temp dir and stores, so they run in parallel.

mod common;

use axum::http::StatusCode;
use chrono::{Duration, Utc};
use common::TestContext;
use filter_engine::FilterList;
use list_service::ListStatus;
use serde_json::{json, Value};

fn ids(v: &Value) -> Vec<String> {
    v["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["id"].as_str().unwrap_or_default().to_string())
        .collect()
}

async fn add_rule(admin: &common::Sess, scope: &str, kind: &str) -> Value {
    let r = admin
        .post("/api/v1/policy/site-rules")
        .json(&json!({"scope": scope, "preset": {"kind": kind}}))
        .await;
    r.assert_status(StatusCode::CREATED);
    r.json()
}

fn scopes(v: &Value) -> Vec<String> {
    v["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            i["scope"]
                .as_str()
                .unwrap()
                .trim_start_matches("site:")
                .to_string()
        })
        .collect()
}

#[tokio::test]
async fn site_rules_filter_sort_and_count() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    for (scope, kind) in [
        ("shop-10.com", "trusted"),
        ("alpha.com", "untrusted"),
        ("shop-2.com", "default"),
        ("beta.org", "trusted"),
    ] {
        add_rule(&admin, scope, kind).await;
    }
    let get = |qs: &str| {
        let admin = &admin;
        let url = format!("/api/v1/policy/site-rules{qs}");
        async move { admin.get(&url).await.json::<Value>() }
    };

    let all = get("").await;
    assert_eq!(
        all["counts"],
        json!({"all": 4, "trusted": 2, "default": 1, "untrusted": 1, "custom": 0, "letters": ["A", "B", "S"]})
    );
    // Natural order: shop-2 before shop-10.
    assert_eq!(
        scopes(&all),
        ["alpha.com", "beta.org", "shop-2.com", "shop-10.com"]
    );
    assert_eq!(all["next_cursor"], Value::Null);
    assert_eq!(all["limit"], 40);
    assert!(all["items"][0]["updated_at"].as_u64().unwrap() > 0);

    // `q` is a case-insensitive substring; counts follow `q` but not `mode`.
    let q = get("?q=SHOP&mode=trusted").await;
    assert_eq!(scopes(&q), ["shop-10.com"]);
    assert_eq!(q["total"], 1);
    assert_eq!(
        q["counts"],
        json!({"all": 2, "trusted": 1, "default": 1, "untrusted": 0, "custom": 0, "letters": ["S"]})
    );
    assert_eq!(get("?preset=default").await["total"], 1, "older spelling");

    // `from` seeks by name prefix.
    assert_eq!(
        scopes(&get("?from=sh").await),
        ["shop-2.com", "shop-10.com"]
    );

    // `recent`: last changed first.
    let rules = get("").await;
    let id = rules["items"][3]["id"].as_str().unwrap().to_string(); // shop-10
    ctx.state
        .policy
        .mutate("default", |r, now| {
            r.site_rules.get_mut(&id).unwrap().updated_at = now + 1000;
            Ok(())
        })
        .unwrap();
    assert_eq!(scopes(&get("?sort=recent").await)[0], "shop-10.com");

    // Deprecated `page` still works.
    let p = get("?limit=1&page=2").await;
    assert_eq!(
        (scopes(&p), p["page"].as_u64()),
        (vec!["beta.org".to_string()], Some(2))
    );

    for bad in [
        "?mode=nope",
        "?sort=nope",
        "?cursor=%21%21",
        "?sort=recent&from=a",
    ] {
        admin
            .get(&format!("/api/v1/policy/site-rules{bad}"))
            .await
            .assert_status(StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn site_rule_cursor_is_stable_while_rows_are_inserted_and_deleted() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let mut made = Vec::new();
    for n in 1..=7 {
        made.push(add_rule(&admin, &format!("s{n:02}.com"), "default").await);
    }
    let p1: Value = admin.get("/api/v1/policy/site-rules?limit=3").await.json();
    assert_eq!(scopes(&p1), ["s01.com", "s02.com", "s03.com"]);
    assert_eq!(
        (p1["has_more"].as_bool(), p1["total"].as_u64()),
        (Some(true), Some(7))
    );
    let cursor = p1["next_cursor"].as_str().unwrap().to_string();

    // Between pages: one row before the cursor appears, the cursor's own row and a later one go.
    add_rule(&admin, "s00.com", "default").await;
    for gone in [&made[2], &made[4]] {
        admin
            .delete(&format!(
                "/api/v1/policy/site-rules/{}",
                gone["id"].as_str().unwrap()
            ))
            .await
            .assert_status_success();
    }
    let p2: Value = admin
        .get(&format!(
            "/api/v1/policy/site-rules?limit=3&cursor={cursor}"
        ))
        .await
        .json();
    assert_eq!(
        scopes(&p2),
        ["s04.com", "s06.com", "s07.com"],
        "no repeat, no skip"
    );
    assert_eq!(p2["next_cursor"], Value::Null);
    assert_eq!(p2["total"], 6, "total reflects the current data");
}

fn list(
    id: &str,
    name: &str,
    url: &str,
    enabled: bool,
    rules: usize,
    age_days: Option<i64>,
) -> FilterList {
    let mut l = FilterList::new(id.into(), name.into(), url.into());
    l.enabled = enabled;
    l.rule_count = rules;
    l.last_updated = age_days.map(|d| Utc::now() - Duration::days(d));
    l
}

#[tokio::test]
async fn filter_lists_search_status_sort_and_counts() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let store = &ctx.state.filter_store;
    // Unique marker so seeded default lists never interfere.
    for l in [
        list(
            "qa",
            "Qx Alpha",
            "https://a.test/qx-a.txt",
            true,
            10,
            Some(1),
        ),
        list(
            "qb",
            "Qx Bravo",
            "https://b.test/qx-b.txt",
            true,
            500,
            Some(30),
        ),
        list(
            "qc",
            "qx charlie",
            "https://c.test/other.txt",
            false,
            50,
            None,
        ),
        list(
            "qd",
            "Qx Delta",
            "https://d.test/qx-d.txt",
            true,
            5,
            Some(2),
        ),
    ] {
        store.upsert_durable(&l).unwrap();
    }
    store
        .set_status(
            "qd",
            &ListStatus {
                last_error: Some("boom".into()),
                ..Default::default()
            },
        )
        .unwrap();
    let get = |qs: &str| {
        let admin = &admin;
        let url = format!("/api/v1/lists?q=qx{qs}");
        async move { admin.get(&url).await.json::<Value>() }
    };

    let all = get("").await;
    assert_eq!(
        ids(&all),
        ["qa", "qb", "qc", "qd"],
        "default sort is by name"
    );
    // attn: qb is stale (30 days), qc is disabled so never-fetched is fine, qd has an error.
    assert_eq!(
        all["counts"],
        json!({"all": 4, "on": 3, "off": 1, "attn": 2, "letters": ["Q"]})
    );
    assert_eq!(all["items"][1]["attention"], true);
    assert_eq!(all["items"][2]["attention"], false);

    assert_eq!(ids(&get("&status=on").await), ["qa", "qb", "qd"]);
    assert_eq!(ids(&get("&status=off").await), ["qc"]);
    let attn = get("&status=attn").await;
    assert_eq!(ids(&attn), ["qb", "qd"]);
    assert_eq!(attn["counts"]["all"], 4, "counts ignore the status filter");
    assert_eq!(ids(&get("&sort=rules").await), ["qb", "qc", "qa", "qd"]);
    assert_eq!(ids(&get("&sort=updated").await), ["qa", "qd", "qb", "qc"]);

    // The URL is searched too; paging after filtering.
    let by_url: Value = admin.get("/api/v1/lists?q=other.txt").await.json();
    assert_eq!(ids(&by_url), ["qc"]);
    let p = get("&limit=2&page=2").await; // deprecated offset paging
    assert_eq!(
        (ids(&p), p["has_more"].as_bool(), p["total"].as_u64()),
        (
            vec!["qc".to_string(), "qd".to_string()],
            Some(false),
            Some(4)
        )
    );
    // Cursor paging and the `from` seek.
    let c1 = get("&limit=2").await;
    assert_eq!(ids(&c1), ["qa", "qb"]);
    let cur = c1["next_cursor"].as_str().unwrap();
    let c2 = get(&format!("&limit=2&cursor={cur}")).await;
    assert_eq!(ids(&c2), ["qc", "qd"]);
    assert_eq!(c2["next_cursor"], Value::Null);
    assert_eq!(ids(&get("&from=qx%20c").await), ["qc", "qd"]);
    // The older `enabled` filter still works.
    assert_eq!(ids(&get("&enabled=false").await), ["qc"]);

    for bad in ["&status=x", "&sort=x", "&cursor=%21", "&sort=rules&from=a"] {
        admin
            .get(&format!("/api/v1/lists?q=qx{bad}"))
            .await
            .assert_status(StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn filter_list_names_sort_naturally_and_cursor_survives_changes() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let store = &ctx.state.filter_store;
    for n in [1usize, 2, 10, 11, 3] {
        let id = format!("zz{n}");
        store
            .upsert_durable(&list(
                &id,
                &format!("zzlist-{n}"),
                "https://x.test/l.txt",
                true,
                n,
                Some(1),
            ))
            .unwrap();
    }
    let get = |qs: &str| {
        let admin = &admin;
        let url = format!("/api/v1/lists?q=zzlist{qs}");
        async move { admin.get(&url).await.json::<Value>() }
    };
    let p1 = get("&limit=2").await;
    assert_eq!(ids(&p1), ["zz1", "zz2"]);
    let cur = p1["next_cursor"].as_str().unwrap().to_string();
    // The cursor's row is removed and a new one lands before it.
    store.remove("zz2").unwrap();
    store
        .upsert_durable(&list(
            "zz0",
            "zzlist-0",
            "https://x.test/l.txt",
            true,
            1,
            Some(1),
        ))
        .unwrap();
    let p2 = get(&format!("&limit=10&cursor={cur}")).await;
    assert_eq!(
        ids(&p2),
        ["zz3", "zz10", "zz11"],
        "natural order, nothing repeated or skipped"
    );
}

fn script(name: &str, extra: &str) -> Value {
    json!({"source": format!(
        "// ==UserScript==\n// @name {name}\n// @namespace n\n// @version 1\n// @match https://e.test/*\n{extra}\n// ==/UserScript==\n1;"
    )})
}

fn names(v: &Value) -> Vec<String> {
    v["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["name"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn userscripts_search_status_sort_cursor_and_counts() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let mut id = std::collections::HashMap::new();
    for (name, extra) in [
        ("Shop 10", ""),
        ("Shop 2", ""),
        ("Zed", "// @run-at context-menu"),
        ("Alpha", ""),
    ] {
        let r = admin
            .post("/api/v1/userscripts")
            .json(&script(name, extra))
            .await;
        r.assert_status(StatusCode::CREATED);
        id.insert(name, r.json::<Value>()["id"].as_str().unwrap().to_string());
    }
    // Disable one.
    admin
        .put(&format!("/api/v1/userscripts/{}/enabled", id["Alpha"]))
        .json(&json!({"enabled": false}))
        .await
        .assert_status_ok();
    let get = |qs: &str| {
        let admin = &admin;
        let url = format!("/api/v1/userscripts{qs}");
        async move { admin.get(&url).await.json::<Value>() }
    };
    let all = get("").await;
    assert_eq!(
        names(&all),
        ["Alpha", "Shop 2", "Shop 10", "Zed"],
        "natural order"
    );
    assert_eq!(
        all["counts"],
        json!({"all": 4, "enabled": 3, "disabled": 1, "error": 1, "letters": ["A", "S", "Z"]})
    );
    assert_eq!(all["next_cursor"], Value::Null);
    assert_eq!(names(&get("?status=disabled").await), ["Alpha"]);
    assert_eq!(names(&get("?status=error").await), ["Zed"]);
    let q = get("?q=SHOP&status=enabled").await;
    assert_eq!(names(&q), ["Shop 2", "Shop 10"]);
    assert_eq!(q["counts"]["all"], 2);
    assert_eq!(names(&get("?from=sh").await), ["Shop 2", "Shop 10", "Zed"]);
    let p1 = get("?limit=2").await;
    let cur = p1["next_cursor"].as_str().unwrap();
    assert_eq!(
        names(&get(&format!("?limit=2&cursor={cur}")).await),
        ["Shop 10", "Zed"]
    );
    assert_eq!(
        names(&get("?limit=1&page=2").await),
        ["Shop 2"],
        "deprecated page"
    );
    assert_eq!(
        names(&get("?enabled=false").await),
        ["Alpha"],
        "older filter"
    );
    assert!(get("?sort=updated").await["items"][0]["updated_at"].is_string());
    for bad in [
        "?status=x",
        "?sort=x",
        "?cursor=%21",
        "?sort=updated&from=a",
    ] {
        admin
            .get(&format!("/api/v1/userscripts{bad}"))
            .await
            .assert_status(StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn devices_search_profile_filter_sort_and_counts() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let mk_profile = |name: &'static str| {
        let admin = &admin;
        async move {
            let r = admin
                .post("/api/v1/profiles")
                .json(&json!({"name": name}))
                .await;
            r.assert_status(StatusCode::CREATED);
            r.json::<Value>()["id"].as_str().unwrap().to_string()
        }
    };
    let (kids, work) = (mk_profile("kids").await, mk_profile("work").await);
    for (name, profile, ip) in [
        ("tv-10", &kids, "10.0.0.10"),
        ("tv-2", &kids, "10.0.0.2"),
        ("laptop", &work, "10.0.1.5"),
    ] {
        admin
            .post("/api/v1/devices")
            .json(&json!({"name": name, "profile_id": profile, "ips": [ip]}))
            .await
            .assert_status(StatusCode::CREATED);
    }
    let get = |qs: &str| {
        let admin = &admin;
        let url = format!("/api/v1/devices{qs}");
        async move { admin.get(&url).await.json::<Value>() }
    };
    let all = get("").await;
    assert_eq!(names(&all), ["laptop", "tv-2", "tv-10"], "natural order");
    assert_eq!(all["counts"]["all"], 3);
    assert_eq!(all["counts"]["by_profile"][&kids], 2);
    assert_eq!(all["counts"]["by_profile"][&work], 1);
    // Profile filter; counts still show every profile.
    let k = get(&format!("?profile={kids}")).await;
    assert_eq!(names(&k), ["tv-2", "tv-10"]);
    assert_eq!(k["total"], 2);
    assert_eq!(k["counts"]["by_profile"][&work], 1);
    // Search by name or address.
    assert_eq!(names(&get("?q=10.0.1").await), ["laptop"]);
    assert_eq!(names(&get("?q=TV").await), ["tv-2", "tv-10"]);
    // Cursor and from.
    let p1 = get("?limit=2").await;
    let cur = p1["next_cursor"].as_str().unwrap();
    assert_eq!(
        names(&get(&format!("?limit=2&cursor={cur}")).await),
        ["tv-10"]
    );
    assert_eq!(names(&get("?from=tv").await), ["tv-2", "tv-10"]);
    assert_eq!(
        names(&get("?limit=1&page=3").await),
        ["tv-10"],
        "deprecated page"
    );
    // last_seen sort works (nothing has connected: name order, none seen).
    let ls = get("?sort=last_seen").await;
    assert_eq!(ls["counts"]["seen"], 0);
    assert_eq!(names(&ls), ["laptop", "tv-2", "tv-10"]);
    for bad in ["?sort=x", "?cursor=%21", "?sort=last_seen&from=a"] {
        admin
            .get(&format!("/api/v1/devices{bad}"))
            .await
            .assert_status(StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn list_response_reports_duplicates_only_when_a_build_has_seen_the_download() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let store = &ctx.state.filter_store;
    let mut built = list(
        "da",
        "Dq Built",
        "https://a.test/dq-a.txt",
        true,
        10,
        Some(1),
    );
    built.duplicate_count = Some(90);
    // Downloaded since the last build, or never built: no duplicate figure.
    let fresh = list(
        "db",
        "Dq Fresh",
        "https://b.test/dq-b.txt",
        true,
        10,
        Some(1),
    );
    for l in [&built, &fresh] {
        store.upsert_durable(l).unwrap();
    }
    let r = admin.get("/api/v1/lists?q=dq").await.json::<Value>();
    assert_eq!(r["items"][0]["duplicate_count"], 90);
    assert_eq!(r["items"][1]["duplicate_count"], Value::Null);
}

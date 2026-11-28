//! `GET /lists/{id}/lines` and `POST /rules/validate`: every source line with the build's
//! verdict, stable paging, and agreement with the build. Each test owns its temp dir and stores.

mod common;

use std::collections::HashSet;

use axum::http::StatusCode;
use common::{Sess, TestContext};
use serde_json::{json, Value};

const MIXED: &str = "! Title: mixed\n\
    !#if ext_ublock\n||ads.test^\n!#else\n||never.test^\n!#endif\n\
    ||ads.test^\n||sub.ads.test^\n||t.test/banner^$script\n\
    example.com##.sponsor\n||x.test^$replace=/a/b/\n||u.test^$popunder\n\
    ||bad$$\n\n!#include inc.txt\n||last.test^\n";

async fn add(ctx: &TestContext, id: &str, text: &str, enabled: bool) {
    let mut l = filter_engine::FilterList::new(
        id.into(),
        id.into(),
        format!("https://127.0.0.1:1/{id}.txt"),
    );
    l.enabled = enabled;
    l.format = filter_engine::ListFormat::Abp;
    ctx.state.filter_store.upsert(&l).unwrap();
    ctx.state.filter_store.put_content(id, text).unwrap();
}

async fn walk(s: &Sess, path: &str, limit: usize) -> Vec<Value> {
    let sep = if path.contains('?') { '&' } else { '?' };
    let mut out = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..200 {
        let mut url = format!("{path}{sep}limit={limit}");
        if let Some(c) = &cursor {
            url.push_str(&format!("&cursor={c}"));
        }
        let r = s.get(&url).await;
        assert_eq!(r.status_code(), StatusCode::OK, "{url}: {}", r.text());
        let v: Value = r.json();
        out.extend(v["items"].as_array().unwrap().iter().cloned());
        match v["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_string()),
            None => return out,
        }
    }
    panic!("runaway paging");
}

#[tokio::test]
async fn paging_to_the_end_returns_every_line_once_with_true_numbers() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    add(&ctx, "m", MIXED, true).await;
    ctx.state
        .filter_store
        .put_include("m", "inc.txt", "||inc1.test^\n##.inc\n")
        .unwrap();
    ctx.state.list_service.reload_now().await;

    let all = walk(&admin, "/api/v1/lists/m/lines", 4).await;
    let first: Value = admin.get("/api/v1/lists/m/lines?limit=500").await.json();
    assert_eq!(first["has_more"], false);
    assert_eq!(first["in_build"], true);
    assert_eq!(all.len() as u64, first["total"].as_u64().unwrap());
    assert_eq!(all, first["items"].as_array().unwrap().clone());
    // Source numbers: ascending, and the rules sit on their own lines.
    let mut prev = 0;
    for l in &all {
        let n = l["line"].as_u64().unwrap();
        assert!(n >= prev && (1..=16).contains(&n), "{l}");
        prev = n;
    }
    let find =
        |status: &str| -> Vec<&Value> { all.iter().filter(|l| l["status"] == status).collect() };
    assert_eq!(find("inactive")[0]["line"], 5);
    assert_eq!(find("inactive")[0]["rule"], "||never.test^");
    let dup = find("duplicate");
    assert_eq!(dup[0]["line"], 7);
    assert_eq!(dup[0]["list"], "m", "repeated inside the same list");
    assert_eq!(find("covered")[0]["line"], 8);
    let ext = find("extended");
    assert!(ext
        .iter()
        .any(|l| l["kind"] == "replace" && l["line"] == 11));
    assert!(
        ext.iter()
            .any(|l| l["line"] == 12 && l["state"] == "not_applicable"),
        "$popunder is meaningless for a proxy: {ext:?}"
    );
    let bad = find("invalid");
    assert_eq!(bad[0]["line"], 13);
    assert_eq!(bad[0]["rule"], "||bad$$");
    assert_eq!(bad[0]["stage"], "compile");
    // Included rules carry the include line.
    let inc: Vec<_> = all
        .iter()
        .filter(|l| l["rule"] == "||inc1.test^" || l["rule"] == "##.inc")
        .collect();
    assert_eq!(inc.len(), 2);
    assert!(inc.iter().all(|l| l["line"] == 15));

    // Counts agree with the stored report.
    let rep: Value = admin.get("/api/v1/lists/m/report").await.json();
    let c = &first["counts"];
    assert_eq!(c["network"], rep["network"]);
    assert_eq!(c["cosmetic"], rep["cosmetic"]);
    assert_eq!(c["extended"], rep["ext"]);
    assert_eq!(c["duplicate"], rep["deduped"]);
    assert_eq!(c["covered"], rep["compressed"]);
    assert_eq!(c["all"].as_u64().unwrap() as usize, all.len());
    assert_eq!(first["total_lines"], 16);
}

#[tokio::test]
async fn status_filters_text_search_and_unknown_statuses() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    add(&ctx, "m", MIXED, true).await;
    ctx.state.list_service.reload_now().await;
    let all: Value = admin.get("/api/v1/lists/m/lines?limit=500").await.json();
    let count = |s: &str| all["counts"][s].as_u64().unwrap() as usize;
    for (q, n) in [
        ("network", count("network")),
        ("network,cosmetic", count("network") + count("cosmetic")),
        ("issues", count("issues")),
        ("applied", count("applied")),
        ("duplicate,covered", count("duplicate") + count("covered")),
        ("comment", count("comment")),
    ] {
        let v: Value = admin
            .get(&format!("/api/v1/lists/m/lines?status={q}&limit=500"))
            .await
            .json();
        assert_eq!(v["total"].as_u64().unwrap() as usize, n, "{q}");
        assert_eq!(v["items"].as_array().unwrap().len(), n, "{q}");
        // Filter counts always describe the whole list.
        assert_eq!(v["counts"], all["counts"], "{q}");
    }
    assert!(count("issues") >= 2 && count("applied") >= 4);
    let v: Value = admin
        .get("/api/v1/lists/m/lines?q=SUB.ADS&limit=500")
        .await
        .json();
    assert_eq!(v["total"], 1);
    assert_eq!(v["items"][0]["rule"], "||sub.ads.test^");
    let v: Value = admin
        .get("/api/v1/lists/m/lines?q=ads&status=network&limit=500")
        .await
        .json();
    assert_eq!(v["total"], 1, "q and status combine: {v}");
    admin
        .get("/api/v1/lists/m/lines?status=bogus")
        .await
        .assert_status_bad_request();
    admin
        .get("/api/v1/lists/nope/lines")
        .await
        .assert_status_not_found();
}

#[tokio::test]
async fn a_cursor_from_another_build_or_text_gets_409() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    add(&ctx, "m", MIXED, true).await;
    ctx.state.list_service.reload_now().await;
    let p1: Value = admin.get("/api/v1/lists/m/lines?limit=3").await.json();
    let cur = p1["next_cursor"].as_str().unwrap().to_string();
    admin
        .get(&format!("/api/v1/lists/m/lines?limit=3&cursor={cur}"))
        .await
        .assert_status_ok();
    ctx.state
        .filter_store
        .put_content("m", &format!("{MIXED}||another.test^\n"))
        .unwrap();
    ctx.state.list_service.reload_now().await;
    let r = admin
        .get(&format!("/api/v1/lists/m/lines?limit=3&cursor={cur}"))
        .await;
    r.assert_status(StatusCode::CONFLICT);
    assert_eq!(r.json::<Value>()["error"]["code"], "lines_changed");
    admin
        .get("/api/v1/lists/m/lines?cursor=%25%25")
        .await
        .assert_status_bad_request();
    // A fresh walk works.
    let all = walk(&admin, "/api/v1/lists/m/lines", 5).await;
    assert!(all.iter().any(|l| l["rule"] == "||another.test^"));
}

#[tokio::test]
async fn custom_rules_and_disabled_lists_are_viewable() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    add(&ctx, "on", "||dup.test^\n||on.test^\n", true).await;
    add(&ctx, "off", "||off.test^\n||off.test^\n", false).await;
    // Nothing yet: an empty page, not an error.
    let v: Value = admin.get("/api/v1/rules/custom/lines").await.json();
    assert_eq!(v["total"], 0);
    ctx.state
        .filter_store
        .set_custom_rules("! mine\n||dup.test^\n@@||ok.test^\n##.c\n")
        .unwrap();
    ctx.state.list_service.reload_now().await;

    let v: Value = admin
        .get("/api/v1/rules/custom/lines?limit=100")
        .await
        .json();
    assert_eq!(v["in_build"], true);
    let items = v["items"].as_array().unwrap();
    assert_eq!(items[0]["status"], "comment");
    let dup = items.iter().find(|l| l["rule"] == "||dup.test^").unwrap();
    assert_eq!(
        (dup["status"].as_str(), dup["list"].as_str()),
        (Some("duplicate"), Some("on"))
    );
    assert_eq!(dup["line"], 2);

    let v: Value = admin.get("/api/v1/lists/off/lines?limit=100").await.json();
    assert_eq!(v["in_build"], false, "not in the current build");
    assert_eq!(v["counts"]["network"], 1);
    assert_eq!(v["counts"]["duplicate"], 1);
    assert_eq!(v["items"][1]["list"], "off");
}

#[tokio::test]
async fn viewers_may_read_lines_anonymous_and_unscoped_may_not() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    add(&ctx, "m", "||a.test^\n", true).await;
    ctx.state.list_service.reload_now().await;
    let viewer = ctx.user(&admin, "viewer1", "viewer").await;
    viewer.get("/api/v1/lists/m/lines").await.assert_status_ok();
    ctx.server
        .get("/api/v1/lists/m/lines")
        .await
        .assert_status_unauthorized();
    let tok = ctx.token(&admin, &["stats:read"]).await;
    ctx.bearer("GET", "/api/v1/lists/m/lines", &tok)
        .await
        .assert_status_forbidden();
    let tok = ctx.token(&admin, &["lists:read"]).await;
    ctx.bearer("GET", "/api/v1/lists/m/lines", &tok)
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn validate_agrees_with_the_build() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    // The custom rules are built trusted; an ordinary list is not.
    ctx.state.filter_store.set_custom_rules(MIXED).unwrap();
    add(&ctx, "m", MIXED, true).await;
    ctx.state
        .filter_store
        .put_include("m", "inc.txt", "")
        .unwrap();
    ctx.state.list_service.reload_now().await;

    let build_custom: Value = admin
        .get("/api/v1/rules/custom/lines?limit=500")
        .await
        .json();
    let rep_m: Value = admin.get("/api/v1/lists/m/report").await.json();
    for (trusted, rep_ext_bad) in [
        (true, 0u64),
        (false, rep_m["ext_needs_trust"].as_u64().unwrap()),
    ] {
        let v: Value = admin
            .post("/api/v1/rules/validate")
            .json(&json!({"rules": MIXED, "trusted": trusted}))
            .await
            .json();
        let lines = v["lines"].as_array().unwrap();
        // The same rejections and extended rules as the build reports.
        assert_eq!(
            v["rejected"].as_u64().unwrap(),
            rep_m["conversion_errors"].as_u64().unwrap() + rep_m["rejected"].as_u64().unwrap()
        );
        assert_eq!(v["handed_off"], rep_m["ext"]);
        let needs = lines.iter().filter(|l| l["state"] == "needs_trust").count() as u64;
        assert_eq!(needs, rep_ext_bad, "trusted={trusted}");
        let dups = v["duplicates"].as_u64().unwrap();
        assert_eq!(
            dups,
            rep_m["deduped"].as_u64().unwrap() + rep_m["compressed"].as_u64().unwrap()
        );
        // `!#if` branches are honoured: the inactive line is not reported.
        assert!(lines.iter().all(|l| l["rule"] != "||never.test^"));
    }
    // Default: untrusted, the safe reading of third-party text; `trusted: true` is how the
    // custom rules are built.
    let needs = |v: &Value| {
        v["lines"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|l| l["state"] == "needs_trust")
            .count()
    };
    let v: Value = admin
        .post("/api/v1/rules/validate")
        .json(&json!({"rules": MIXED}))
        .await
        .json();
    assert_eq!(
        needs(&v),
        rep_m["ext_needs_trust"].as_u64().unwrap() as usize
    );
    assert!(needs(&v) >= 1);
    let t: Value = admin
        .post("/api/v1/rules/validate")
        .json(&json!({"rules": MIXED, "trusted": true}))
        .await
        .json();
    assert_eq!(
        needs(&t),
        build_custom["counts"]["needs_trust"].as_u64().unwrap() as usize
    );
    let ids: HashSet<u64> = v["lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["line"].as_u64().unwrap())
        .collect();
    assert!(
        ids.contains(&7) && ids.contains(&13),
        "true source line numbers: {ids:?}"
    );
}

#[tokio::test]
async fn attention_and_redundant_flags_follow_the_documented_rules() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    // 25 broken lines among 30: well over the threshold.
    let broken: String =
        (0..25).map(|i| format!("||bad{i}$$\n")).collect::<String>() + "||ok.test^\n";
    add(&ctx, "a-broken", &broken, true).await;
    add(&ctx, "b-clean", "||one.test^\n||two.test^\n", true).await;
    add(&ctx, "c-copy", "||one.test^\n||two.test^\n", true).await;
    ctx.state.list_service.reload_now().await;
    let lists: Value = admin.get("/api/v1/lists?limit=50").await.json();
    let by = |id: &str| -> Value {
        lists["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|l| l["id"] == id)
            .cloned()
            .unwrap()
    };
    assert_eq!(by("a-broken")["attention"], true);
    assert_eq!(
        by("b-clean")["attention"],
        true,
        "never fetched is old stuff: attention by the older rule"
    );
    assert_eq!(by("c-copy")["redundant"], true);
    assert_eq!(by("b-clean")["redundant"], false);
    let r: Value = admin.get("/api/v1/lists/c-copy/report").await.json();
    assert_eq!(r["redundant"], true);
    assert_eq!(r["redundant_count"], 2);
    assert_eq!(r["network"], 0);
    let r: Value = admin.get("/api/v1/lists/a-broken/report").await.json();
    assert_eq!(r["attention"], true);
    // The engine rejects them: counted apart from conversion errors; `error_count` is the old sum.
    assert_eq!(r["conversion_errors"], 0, "{r}");
    assert_eq!(r["rejected"], 25);
    assert_eq!(r["error_count"], 25);
    assert_eq!(r["issues"][0]["rule"], "||bad0$$");
    assert_eq!(r["issues"][0]["line"], 1);
    assert_eq!(r["issues"][0]["stage"], "compile");
}

#[tokio::test]
async fn custom_lines_need_rules_read_and_q_is_bounded() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    ctx.state
        .filter_store
        .set_custom_rules("||secret.test^\n")
        .unwrap();
    ctx.state.list_service.reload_now().await;
    let lists_only = ctx.token(&admin, &["lists:read"]).await;
    ctx.bearer("GET", "/api/v1/rules/custom/lines", &lists_only)
        .await
        .assert_status_forbidden();
    // `custom` is no longer a list id of the lists route.
    ctx.bearer("GET", "/api/v1/lists/custom/lines", &lists_only)
        .await
        .assert_status_not_found();
    let rules = ctx.token(&admin, &["rules:read"]).await;
    let r = ctx
        .bearer("GET", "/api/v1/rules/custom/lines", &rules)
        .await;
    r.assert_status_ok();
    assert_eq!(r.json::<Value>()["items"][0]["rule"], "||secret.test^");
    // The custom rules are not readable through lists:read in any other way either.
    admin
        .get(&format!("/api/v1/rules/custom/lines?q={}", "a".repeat(257)))
        .await
        .assert_status_bad_request();
    admin
        .get(&format!("/api/v1/rules/custom/lines?q={}", "a".repeat(256)))
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn profile_parameter_judges_against_the_profiles_list_set() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    add(&ctx, "a", "||dup.test^\n||a.test^\n", true).await;
    add(&ctx, "b", "||dup.test^\n||b.test^\n", true).await;
    ctx.state.list_service.reload_now().await;
    let r = admin
        .post("/api/v1/profiles")
        .json(&json!({"name": "only-b", "lists": ["b"], "rules": "||own.test^\n##.p"}))
        .await;
    assert_eq!(r.status_code(), StatusCode::CREATED, "{}", r.text());
    let pid = r.json::<Value>()["id"].as_str().unwrap().to_string();
    let global: Value = admin.get("/api/v1/lists/b/lines").await.json();
    assert_eq!(
        global["counts"]["duplicate"], 1,
        "second in the global build"
    );
    let prof: Value = admin
        .get(&format!("/api/v1/lists/b/lines?profile={pid}"))
        .await
        .json();
    assert_eq!(
        prof["counts"]["duplicate"], 0,
        "first and only in the profile"
    );
    assert_eq!(prof["in_build"], true);
    // A list the profile does not have is judged on its own.
    let a: Value = admin
        .get(&format!("/api/v1/lists/a/lines?profile={pid}"))
        .await
        .json();
    assert_eq!(a["in_build"], false);
    // The profile's own rules.
    let own: Value = admin
        .get(&format!("/api/v1/rules/custom/lines?profile={pid}"))
        .await
        .json();
    assert_eq!(own["counts"]["network"], 1);
    assert_eq!(own["counts"]["cosmetic"], 1);
    admin
        .get("/api/v1/lists/b/lines?profile=999")
        .await
        .assert_status_not_found();
}

#[tokio::test]
async fn the_cursor_names_the_generation_the_page_was_judged_under() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    add(&ctx, "m", MIXED, true).await;
    ctx.state.list_service.reload_now().await;
    let p1: Value = admin.get("/api/v1/lists/m/lines?limit=3").await.json();
    let cur = p1["next_cursor"].as_str().unwrap().to_string();
    // A different build lands (another list changes the engine) before the next page.
    add(&ctx, "n", "||n.test^\n", true).await;
    ctx.state.list_service.reload_now().await;
    let r = admin
        .get(&format!("/api/v1/lists/m/lines?limit=3&cursor={cur}"))
        .await;
    r.assert_status(StatusCode::CONFLICT);
    assert_eq!(r.json::<Value>()["error"]["code"], "lines_changed");
}

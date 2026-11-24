//! Userscript install/update/storage/export flows of the control-plane API.

mod common;

use axum::http::StatusCode;
use common::TestContext;
use serde_json::{json, Value};
use userscript_engine::install;
use userscript_engine::DEFAULT_PROFILE;

fn src(version: &str, extra: &str) -> String {
    format!(
        "// ==UserScript==\n// @name Plan Test\n// @namespace pt\n// @version {version}\n// @match https://example.com/*\n// @grant GM_setValue\n{extra}\n// ==/UserScript==\nconsole.log(1);"
    )
}

fn enc(id: &str) -> String {
    id.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

async fn plan(admin: &common::Sess, source: &str) -> Value {
    let r = admin
        .post("/api/v1/userscripts/plan")
        .json(&json!({"source": source}))
        .await;
    r.assert_status_ok();
    r.json()
}

async fn install_plain(admin: &common::Sess, source: &str) -> String {
    let p = plan(admin, source).await;
    let r = admin
        .post(&format!(
            "/api/v1/userscripts/plan/{}/confirm",
            p["plan_id"].as_str().unwrap()
        ))
        .json(&json!({}))
        .await;
    assert_eq!(r.status_code(), StatusCode::CREATED, "{}", r.text());
    r.json::<Value>()["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn plan_confirm_happy_path_and_summary() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let p = plan(&admin, &src("1.0", "")).await;
    assert_eq!(p["name"], "Plan Test");
    assert_eq!(p["already_installed"], false);
    assert_eq!(p["broad_match"], false);
    assert_eq!(p["connect_all"], false);
    assert!(p["grants"]
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g == "gm_setvalue"));
    let id = p["plan_id"].as_str().unwrap();
    let r = admin
        .post(&format!("/api/v1/userscripts/plan/{id}/confirm"))
        .json(&json!({"enable": false}))
        .await;
    assert_eq!(r.status_code(), StatusCode::CREATED);
    let s: Value = r.json();
    assert_eq!(s["enabled"], false);
    assert_eq!(s["version"], "1.0");
    assert_eq!(s["connect_all_approved"], false);
    // Planning again reports the installed one; confirming it updates it.
    let p2 = plan(&admin, &src("1.0", "")).await;
    assert_eq!(p2["already_installed"], true);
    assert_eq!(p2["installed_version"], "1.0");
    admin
        .post(&format!(
            "/api/v1/userscripts/plan/{}/confirm",
            p2["plan_id"].as_str().unwrap()
        ))
        .json(&json!({}))
        .await
        .assert_status_ok(); // confirming a plan for an installed script is an update
}

#[tokio::test]
async fn plan_input_validation_and_expiry() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    for body in [
        json!({}),
        json!({"source": "x", "url": "https://a.test/x.user.js"}),
    ] {
        admin
            .post("/api/v1/userscripts/plan")
            .json(&body)
            .await
            .assert_status_bad_request();
    }
    // Internal destinations are refused by the fetch policy.
    let r = admin
        .post("/api/v1/userscripts/plan")
        .json(&json!({"url": "http://127.0.0.1/x.user.js"}))
        .await;
    r.assert_status_bad_request();
    assert_eq!(
        r.json::<Value>()["error"]["code"],
        "fetch_destination_not_allowed"
    );
    admin
        .post("/api/v1/userscripts/plan")
        .json(&json!({"source": "not a userscript"}))
        .await
        .assert_status_bad_request();
    // Unknown and expired plans.
    let r = admin
        .post("/api/v1/userscripts/plan/nope/confirm")
        .json(&json!({}))
        .await;
    r.assert_status_not_found();
    let p = plan(&admin, &src("1.0", "")).await;
    ctx.state.userscript_plans.expire_all();
    admin
        .post(&format!(
            "/api/v1/userscripts/plan/{}/confirm",
            p["plan_id"].as_str().unwrap()
        ))
        .json(&json!({}))
        .await
        .assert_status_not_found();
}

#[tokio::test]
async fn plan_store_is_bounded() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let first = plan(&admin, &src("1.0", "")).await["plan_id"]
        .as_str()
        .unwrap()
        .to_string();
    for i in 0..40 {
        plan(&admin, &src(&format!("1.{i}"), "")).await;
    }
    assert!(ctx.state.userscript_plans.len() <= 32);
    admin
        .post(&format!("/api/v1/userscripts/plan/{first}/confirm"))
        .json(&json!({}))
        .await
        .assert_status_not_found();
}

#[tokio::test]
async fn connect_all_needs_explicit_approval_and_broad_match_is_flagged() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let source = "// ==UserScript==\n// @name Wide\n// @namespace w\n// @version 1\n// @match *://*/*\n// @grant GM_xmlhttpRequest\n// @connect *\n// ==/UserScript==\n1;";
    let p = plan(&admin, source).await;
    assert_eq!(p["broad_match"], true);
    assert_eq!(p["connect_all"], true);
    assert_eq!(p["network"], true);
    let id = p["plan_id"].as_str().unwrap();
    let r = admin
        .post(&format!("/api/v1/userscripts/plan/{id}/confirm"))
        .json(&json!({}))
        .await;
    r.assert_status(StatusCode::CREATED);
    assert_eq!(r.json::<Value>()["connect_all_approved"], false);

    // Approved on a fresh install.
    let ctx2 = TestContext::new().await.unwrap();
    let a2 = ctx2.admin().await;
    let id = plan(&a2, source).await["plan_id"]
        .as_str()
        .unwrap()
        .to_string();
    let r = a2
        .post(&format!("/api/v1/userscripts/plan/{id}/confirm"))
        .json(&json!({"allow_connect_all": true}))
        .await;
    r.assert_status(StatusCode::CREATED);
    assert_eq!(r.json::<Value>()["connect_all_approved"], true);

    // Approving something the script does not declare is rejected.
    let id = plan(&admin, &src("1.0", "")).await["plan_id"]
        .as_str()
        .unwrap()
        .to_string();
    admin
        .post(&format!("/api/v1/userscripts/plan/{id}/confirm"))
        .json(&json!({"allow_connect_all": true}))
        .await
        .assert_status_bad_request();
}

#[tokio::test]
async fn widening_update_stays_pending_until_approved() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let id = install_plain(&admin, &src("1.0", "")).await;
    let script = ctx.state.userscript_manager.get(&id).unwrap();
    let v2 = src("2.0", "// @match https://other.test/*");
    let up = install::plan_update(&script, &v2, None).unwrap();
    assert!(up.is_newer && up.diff.needs_reapproval());
    let origin = url::Url::parse("https://example.com/s.user.js").unwrap();
    // Even with apply=true a widening update is parked.
    let out = web_api::userscript_ops::stage_update(
        &ctx.state.userscript_manager,
        userscript_engine::DEFAULT_PROFILE,
        &script,
        up,
        install::Fetched::default(),
        true,
        &origin,
        chrono::Utc::now(),
    )
    .unwrap();
    assert!(matches!(
        out,
        web_api::userscript_ops::CheckOutcome::Pending(_)
    ));

    let s: Value = admin
        .get(&format!("/api/v1/userscripts/{}", enc(&id)))
        .await
        .json();
    assert_eq!(s["version"], "1.0");
    assert_eq!(s["pending_update"]["new_version"], "2.0");
    assert_eq!(s["pending_update"]["needs_reapproval"], true);
    assert_eq!(
        s["pending_update"]["diff"]["added_matches"][0],
        "@match https://other.test/*"
    );
    assert!(s["last_update_check"].is_string());

    let r = admin
        .post(&format!("/api/v1/userscripts/{}/update/approve", enc(&id)))
        .json(&json!({}))
        .await;
    r.assert_status_ok();
    let s: Value = r.json();
    assert_eq!(s["version"], "2.0");
    assert!(s["pending_update"].is_null());
    assert!(s["match_patterns"].as_array().unwrap().len() == 2);
    // Nothing left to approve.
    admin
        .post(&format!("/api/v1/userscripts/{}/update/approve", enc(&id)))
        .json(&json!({}))
        .await
        .assert_status_not_found();
}

#[tokio::test]
async fn non_widening_update_applies_and_pending_can_be_discarded() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let id = install_plain(&admin, &src("1.0", "")).await;
    let origin = url::Url::parse("https://example.com/s.user.js").unwrap();
    let mgr = &ctx.state.userscript_manager;

    let script = mgr.get(&id).unwrap();
    let up = install::plan_update(&script, &src("1.1", ""), None).unwrap();
    assert!(!up.diff.needs_reapproval());
    let out = web_api::userscript_ops::stage_update(
        mgr,
        userscript_engine::DEFAULT_PROFILE,
        &script,
        up,
        install::Fetched::default(),
        true,
        &origin,
        chrono::Utc::now(),
    )
    .unwrap();
    assert!(matches!(
        out,
        web_api::userscript_ops::CheckOutcome::Updated
    ));
    let s = mgr.get(&id).unwrap();
    assert_eq!(s.metadata.version.as_deref(), Some("1.1"));
    assert!(s.pending_update.is_none() && s.last_update_check.is_some());

    // Without `apply` the same kind of update is parked, then discarded.
    let up = install::plan_update(&s, &src("1.2", ""), None).unwrap();
    web_api::userscript_ops::stage_update(
        mgr,
        userscript_engine::DEFAULT_PROFILE,
        &s,
        up,
        install::Fetched::default(),
        false,
        &origin,
        chrono::Utc::now(),
    )
    .unwrap();
    let r = admin
        .delete(&format!("/api/v1/userscripts/{}/update", enc(&id)))
        .await;
    r.assert_status_ok();
    assert!(r.json::<Value>()["pending_update"].is_null());
    // A script without an update URL cannot be checked.
    admin
        .post(&format!("/api/v1/userscripts/{}/check-update", enc(&id)))
        .json(&json!({}))
        .await
        .assert_status_bad_request();
    admin
        .post("/api/v1/userscripts/missing/check-update")
        .json(&json!({}))
        .await
        .assert_status_not_found();
}

#[tokio::test]
async fn storage_view_and_clear() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let id = install_plain(&admin, &src("1.0", "")).await;
    let space = userscript_engine::storage::ns(DEFAULT_PROFILE, &id);
    let st = ctx.state.userscript_manager.storage();
    st.set_raw(&space, "a", json!("hello")).unwrap();
    st.set_raw(&space, "b", json!({"k": "x".repeat(500)}))
        .unwrap();
    let base = format!("/api/v1/userscripts/{}/storage", enc(&id));
    let v: Value = admin.get(&base).await.json();
    assert_eq!(v["values"].as_array().unwrap().len(), 2);
    assert_eq!(v["values"][0]["name"], "a");
    assert_eq!(v["values"][0]["preview"], "\"hello\"");
    assert_eq!(
        v["values"][1]["preview"].as_str().unwrap().chars().count(),
        200
    );
    assert!(v["used_bytes"].as_u64().unwrap() > 500);
    assert_eq!(v["quota_bytes"], 5 << 20);

    admin.delete(&format!("{base}/a")).await.assert_status_ok();
    admin
        .delete(&format!("{base}/a"))
        .await
        .assert_status_not_found();
    assert_eq!(
        admin.get(&base).await.json::<Value>()["values"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    admin.delete(&base).await.assert_status_ok();
    let v: Value = admin.get(&base).await.json();
    assert_eq!(v["used_bytes"], 0);
    admin
        .get("/api/v1/userscripts/missing/storage")
        .await
        .assert_status_not_found();
}

#[tokio::test]
async fn export_import_roundtrip_with_values() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let id = install_plain(&admin, &src("1.0", "")).await;
    let space = userscript_engine::storage::ns(DEFAULT_PROFILE, &id);
    ctx.state
        .userscript_manager
        .storage()
        .set_raw(&space, "k", json!({"n": 1}))
        .unwrap();

    let plain: Value = admin.get("/api/v1/userscripts/export").await.json();
    assert_eq!(plain["format"], "argus-userscripts-v1");
    assert!(plain["scripts"][0].get("values").is_none());
    let bundle: Value = admin
        .get("/api/v1/userscripts/export?values=true")
        .await
        .json();
    assert_eq!(bundle["scripts"][0]["values"]["k"], json!({"n": 1}));

    // Into a fresh instance.
    let ctx2 = TestContext::new().await.unwrap();
    let a2 = ctx2.admin().await;
    let r = a2.post("/api/v1/userscripts/import").json(&bundle).await;
    r.assert_status_ok();
    let res: Value = r.json();
    assert_eq!(res["results"][0]["status"], "installed", "{res}");
    assert_eq!(res["results"][0]["id"], id);
    let v: Value = a2
        .get(&format!("/api/v1/userscripts/{}/storage", enc(&id)))
        .await
        .json();
    assert_eq!(v["values"][0]["name"], "k");

    // Conflicts: skip by default, replace on request; bad scripts are reported per entry.
    let mut b2 = bundle.clone();
    b2["scripts"]
        .as_array_mut()
        .unwrap()
        .push(json!({"source": "junk"}));
    let res: Value = a2.post("/api/v1/userscripts/import").json(&b2).await.json();
    assert_eq!(res["results"][0]["status"], "skipped");
    assert_eq!(res["results"][1]["status"], "error");
    b2["on_conflict"] = json!("replace");
    let res: Value = a2.post("/api/v1/userscripts/import").json(&b2).await.json();
    assert_eq!(res["results"][0]["status"], "replaced");
    b2["on_conflict"] = json!("bogus");
    a2.post("/api/v1/userscripts/import")
        .json(&b2)
        .await
        .assert_status_bad_request();
    a2.post("/api/v1/userscripts/import")
        .json(&json!({"format": "other", "scripts": []}))
        .await
        .assert_status_bad_request();
}

#[tokio::test]
async fn scopes_and_audit() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let id = install_plain(&admin, &src("1.0", "")).await;
    let viewer = ctx.user(&admin, "viewer_user", "viewer").await;
    let base = format!("/api/v1/userscripts/{}", enc(&id));
    // A viewer reads but cannot write, see storage or export values.
    viewer.get("/api/v1/userscripts").await.assert_status_ok();
    viewer
        .get("/api/v1/userscripts/export")
        .await
        .assert_status_ok();
    viewer
        .get("/api/v1/userscripts/export?values=true")
        .await
        .assert_status_forbidden();
    viewer
        .get(&format!("{base}/storage"))
        .await
        .assert_status_forbidden();
    viewer
        .delete(&format!("{base}/storage"))
        .await
        .assert_status_forbidden();
    viewer
        .post("/api/v1/userscripts/plan")
        .json(&json!({"source": src("1.0", "")}))
        .await
        .assert_status_forbidden();
    viewer
        .post("/api/v1/userscripts/import")
        .json(&json!({"format": "argus-userscripts-v1", "scripts": []}))
        .await
        .assert_status_forbidden();
    // A scripts:read token cannot read storage or export values either.
    let tok = ctx.token(&admin, &["scripts:read"]).await;
    ctx.bearer("GET", &format!("{base}/storage"), &tok)
        .await
        .assert_status_forbidden();
    ctx.bearer("GET", "/api/v1/userscripts/export?values=true", &tok)
        .await
        .assert_status_forbidden();
    ctx.bearer("GET", "/api/v1/userscripts/export", &tok)
        .await
        .assert_status_ok();

    admin
        .delete(&format!("{base}/storage"))
        .await
        .assert_status_ok();
    let log: Value = admin.get("/api/v1/audit?limit=100").await.json();
    let items = log["items"].as_array().unwrap();
    for (route, method) in [
        ("/api/v1/userscripts/plan", "POST"),
        ("/api/v1/userscripts/plan/{plan_id}/confirm", "POST"),
        ("/api/v1/userscripts/{id}/storage", "DELETE"),
    ] {
        let e = items
            .iter()
            .find(|e| e["route"] == route && e["method"] == method && e["status"] != 403)
            .unwrap_or_else(|| panic!("no audit entry for {method} {route}"));
        assert_eq!(e["scope"], "scripts:write");
        assert_eq!(e["actor_name"], "admin_user");
    }
}

#[test]
fn broad_match_detection() {
    use web_api::userscript_ops::is_broad_match;
    for p in [
        "<all_urls>",
        "*://*/*",
        "*://*/",
        "http*://*/*",
        "https://*/*",
        "*",
    ] {
        assert!(is_broad_match(p), "{p}");
    }
    for p in [
        "https://example.com/*",
        "*://*.example.com/*",
        "https://*.com/*",
    ] {
        assert!(!is_broad_match(p), "{p}");
    }
}

fn data_js(code: &str) -> String {
    use base64::Engine;
    format!(
        "data:text/javascript;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(code)
    )
}

#[tokio::test]
async fn direct_source_replacement_route_is_gone() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let id = install_plain(&admin, &src("1.0", "")).await;
    let r = admin
        .put(&format!("/api/v1/userscripts/{}", enc(&id)))
        .json(&json!({"source": src("2.0", "// @grant GM_xmlhttpRequest\n// @connect *")}))
        .await;
    assert_ne!(
        r.status_code(),
        StatusCode::OK,
        "PUT swapped code without the plan/confirm contract"
    );
    let cur: Value = admin
        .get(&format!("/api/v1/userscripts/{}", enc(&id)))
        .await
        .json();
    assert_eq!(cur["version"], "1.0");
}

#[tokio::test]
async fn updating_an_installed_script_goes_through_plan_and_confirm() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    // Installed with @connect * approved.
    let p = plan(
        &admin,
        &src("1.0", "// @grant GM_xmlhttpRequest\n// @connect *"),
    )
    .await;
    let r = admin
        .post(&format!(
            "/api/v1/userscripts/plan/{}/confirm",
            p["plan_id"].as_str().unwrap()
        ))
        .json(&json!({"allow_connect_all": true}))
        .await;
    assert_eq!(r.status_code(), StatusCode::CREATED);
    let _id = r.json::<Value>()["id"].as_str().unwrap().to_string();
    // The new source adds a @require: the plan reports the update and that it needs approval,
    // and confirming fetches and stores the dependency.
    let up = src(
        "2.0",
        &format!(
            "// @grant GM_xmlhttpRequest\n// @connect *\n// @require {}",
            data_js("window.__lib = 1;")
        ),
    );
    let p = plan(&admin, &up).await;
    assert_eq!(p["already_installed"], true);
    assert_eq!(p["update"]["needs_reapproval"], true, "{p}");
    let r = admin
        .post(&format!(
            "/api/v1/userscripts/plan/{}/confirm",
            p["plan_id"].as_str().unwrap()
        ))
        .json(&json!({}))
        .await;
    assert_eq!(r.status_code(), StatusCode::OK, "{}", r.text());
    let s: Value = r.json();
    assert_eq!(s["version"], "2.0");
    assert_eq!(s["require_count"], 1, "the @require was fetched and stored");
    assert_eq!(
        s["connect_all_approved"], true,
        "an unchanged @connect * approval survives"
    );
    // A confirm built for an older state of the script is refused.
    let p = plan(&admin, &src("3.0", "")).await;
    let stale = plan(&admin, &src("3.1", "")).await;
    admin
        .post(&format!(
            "/api/v1/userscripts/plan/{}/confirm",
            p["plan_id"].as_str().unwrap()
        ))
        .json(&json!({}))
        .await
        .assert_status_ok();
    admin
        .post(&format!(
            "/api/v1/userscripts/plan/{}/confirm",
            stale["plan_id"].as_str().unwrap()
        ))
        .json(&json!({}))
        .await
        .assert_status(StatusCode::CONFLICT);
}

#[tokio::test]
async fn imported_scripts_arrive_disabled_and_unapproved_unless_confirmed() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let bundle = json!({
        "format": "argus-userscripts-v1",
        "scripts": [{
            "source": src("1.0", "// @grant GM_xmlhttpRequest\n// @connect *"),
            "enabled": true,
            "allow_connect_all": true,
            "assets": {"requires": [], "resources": []}
        }]
    });
    let res: Value = admin
        .post("/api/v1/userscripts/import")
        .json(&bundle)
        .await
        .json();
    let id = res["results"][0]["id"].as_str().unwrap().to_string();
    let s: Value = admin
        .get(&format!("/api/v1/userscripts/{}", enc(&id)))
        .await
        .json();
    assert_eq!(s["enabled"], false, "{res}");
    assert_eq!(s["connect_all_approved"], false);
    assert_eq!(res["results"][0]["pending_approval"], true);
    // Explicitly confirmed import keeps what the file says.
    admin
        .delete(&format!("/api/v1/userscripts/{}", enc(&id)))
        .await
        .assert_status_ok();
    let mut b = bundle.clone();
    b["approve"] = json!(true);
    admin
        .post("/api/v1/userscripts/import")
        .json(&b)
        .await
        .assert_status_ok();
    let s: Value = admin
        .get(&format!("/api/v1/userscripts/{}", enc(&id)))
        .await
        .json();
    assert_eq!(s["enabled"], true);
    assert_eq!(s["connect_all_approved"], true);
}

#[tokio::test]
async fn import_marks_pending_and_approve_clears_it_and_grants_connect() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let bundle = json!({
        "format": "argus-userscripts-v1",
        "scripts": [{
            "source": src("1.0", "// @grant GM_xmlhttpRequest\n// @connect *"),
            "enabled": true,
            "allow_connect_all": true,
            "assets": {"requires": [], "resources": []}
        }]
    });
    let res: Value = admin
        .post("/api/v1/userscripts/import")
        .json(&bundle)
        .await
        .json();
    let id = res["results"][0]["id"].as_str().unwrap().to_string();
    let url = format!("/api/v1/userscripts/{}", enc(&id));
    let s: Value = admin.get(&url).await.json();
    assert_eq!(s["pending_approval"], true);
    let page: Value = admin
        .get("/api/v1/userscripts?status=attention")
        .await
        .json();
    assert_eq!(page["total"], 1);
    assert_eq!(page["counts"]["attention"], 1);

    let r = admin
        .post(&format!("{url}/approve"))
        .json(&json!({"allow_connect_all": true}))
        .await;
    r.assert_status_ok();
    let s: Value = r.json();
    assert_eq!(s["pending_approval"], false);
    assert_eq!(s["enabled"], true);
    assert_eq!(s["connect_all_approved"], true);
    let page: Value = admin
        .get("/api/v1/userscripts?status=attention")
        .await
        .json();
    assert_eq!(page["total"], 0);

    // @connect * cannot be granted to a script that does not declare it.
    admin.delete(&url).await.assert_status_ok();
    let other = install_plain(&admin, &src("2.0", "")).await;
    let r = admin
        .post(&format!("/api/v1/userscripts/{}/approve", enc(&other)))
        .json(&json!({"allow_connect_all": true}))
        .await;
    assert_eq!(r.status_code(), StatusCode::BAD_REQUEST, "{}", r.text());
}

// ---------------------------------------------------------------- signed catalogue

fn catalogue_doc(
    ctx: &TestContext,
    signer: &list_service::testkit::Signer,
) -> std::sync::Arc<list_service::SignedDoc<list_service::UserscriptCatalogueEntry>> {
    let doc = list_service::SignedDoc::new(
        "userscripts",
        None,
        list_service::ArgusConfig {
            base_url: "http://unused.test".into(),
            public_key: signer.public_key(),
            cache_dir: None,
        },
    );
    assert!(ctx.state.userscript_catalogue.set(doc.clone()).is_ok());
    doc
}

/// A local origin serving one `.user.js`.
async fn serve_script(body: impl FnOnce(std::net::SocketAddr) -> String) -> std::net::SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let body = body(addr);
    let app = axum::Router::new().fallback(move || {
        let b = body.clone();
        async move { b }
    });
    tokio::spawn(async move {
        let _ = axum::serve(l, app).await;
    });
    addr
}

#[tokio::test]
async fn the_catalogue_is_empty_until_signed_then_serves_entries_to_readers() {
    use list_service::testkit::{userscripts_json, Signer};
    let ctx = TestContext::new().await.unwrap();
    let signer = Signer::new();
    let doc = catalogue_doc(&ctx, &signer);
    let admin = ctx.admin().await;
    let viewer = ctx.user(&admin, "viewer_user", "viewer").await;
    let c: Value = viewer.get("/api/v1/userscripts/catalogue").await.json();
    assert_eq!(c["source"], "unavailable");
    assert!(c["entries"].as_array().unwrap().is_empty());

    // A bad signature and a filters document under the userscripts name are refused.
    let text = userscripts_json("https://example.test/a.user.js");
    let bad = Signer::new().sign(&text, "v2026.11.23", "userscripts.json");
    assert!(doc.apply(text.clone(), bad, None).await.is_err());
    let wrong = list_service::testkit::filters_json("abp");
    let sig = signer.sign(&wrong, "v2026.11.23", "userscripts.json");
    assert!(doc.apply(wrong, sig, None).await.is_err());

    let sig = signer.sign(&text, "v2026.11.23", "userscripts.json");
    doc.apply(text, sig, None).await.unwrap();
    let c: Value = viewer.get("/api/v1/userscripts/catalogue").await.json();
    assert_eq!(
        (c["source"].as_str(), c["version"].as_str()),
        (Some("signed"), Some("v2026.11.23"))
    );
    assert_eq!(c["entries"][0]["id"], "us1");
    assert_eq!(c["entries"][0]["needs_gm"], "none");
    // Same scope as listing: a token without scripts:read is refused.
    let tok = ctx.token(&admin, &["lists:read"]).await;
    ctx.bearer("GET", "/api/v1/userscripts/catalogue", &tok)
        .await
        .assert_status_forbidden();
}

#[tokio::test]
async fn a_catalogue_script_installs_through_the_existing_plan_and_confirm() {
    use list_service::testkit::{userscripts_json, Signer};
    let ctx = TestContext::with_fetch_allowed(&["127.0.0.1"])
        .await
        .unwrap();
    let signer = Signer::new();
    let doc = catalogue_doc(&ctx, &signer);
    let addr = serve_script(|a| src("1.0", &format!("// @downloadURL http://{a}/a.user.js"))).await;
    let url = format!("http://{addr}/a.user.js");
    let text = userscripts_json(&url);
    let sig = signer.sign(&text, "v2026.11.23", "userscripts.json");
    doc.apply(text, sig, None).await.unwrap();
    let admin = ctx.admin().await;

    let c: Value = admin.get("/api/v1/userscripts/catalogue").await.json();
    let install_url = c["entries"][0]["install_url"].as_str().unwrap().to_string();
    let r = admin
        .post("/api/v1/userscripts/plan")
        .json(&json!({"url": install_url}))
        .await;
    r.assert_status_ok();
    let p: Value = r.json();
    let r = admin
        .post(&format!(
            "/api/v1/userscripts/plan/{}/confirm",
            p["plan_id"].as_str().unwrap()
        ))
        .json(&json!({}))
        .await;
    assert_eq!(r.status_code(), StatusCode::CREATED, "{}", r.text());
    let s: Value = r.json();
    // The UI matches "Installed" by @downloadURL/@updateURL.
    let got: Value = admin
        .get(&format!(
            "/api/v1/userscripts/{}",
            enc(s["id"].as_str().unwrap())
        ))
        .await
        .json();
    assert_eq!(got["update_url"], install_url.as_str());
}

//! The extension bridge endpoints: the WebSocket channel (hello, token, scope, origin), the menu
//! calls (scope, session binding), and the `browser_cookies` approval flag.

mod common;

use api_types::{
    ExtAuditEvent, ExtError, ExtGrant, ExtIdent, ExtMenuCommand, ExtMenuResponse, ExtOut,
    ExtTriggerRequest,
};
use axum::http::StatusCode;
use axum_test::{TestServer, WsMessage};
use common::TestContext;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::sync::Arc;
use web_api::{AppState, ExtBridge};

/// A bridge that remembers what it was asked and serves one bound document.
#[derive(Default)]
struct Fake {
    idents: Mutex<Vec<ExtIdent>>,
    texts: Mutex<Vec<String>>,
    triggers: Mutex<Vec<ExtTriggerRequest>>,
    closed: Mutex<Vec<u64>>,
    closed_tokens: Mutex<Vec<String>>,
    stores: Mutex<Vec<String>>,
    fallback: Mutex<bool>,
    outs: Mutex<Vec<tokio::sync::mpsc::Sender<ExtOut>>>,
}

const SID: &str = "0123456789abcdef0123456789abcdef";

#[async_trait::async_trait]
impl ExtBridge for Fake {
    fn open(&self, ident: ExtIdent) -> (u64, String, tokio::sync::mpsc::Receiver<ExtOut>) {
        self.idents.lock().push(ident);
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        self.outs.lock().push(tx);
        (7, SID.into(), rx)
    }
    async fn on_text(&self, _s: u64, t: &str) {
        self.texts.lock().push(t.into());
    }
    async fn on_binary(&self, _s: u64, _d: Vec<u8>) {}
    fn close(&self, s: u64) {
        self.closed.lock().push(s);
    }
    fn session_for(&self, sid: &str, token_id: &str) -> Option<u64> {
        let mine = self.idents.lock().iter().any(|i| i.token_id == token_id);
        (sid == SID && mine).then_some(7)
    }
    fn close_token(&self, token_id: &str) {
        self.closed_tokens.lock().push(token_id.into());
    }
    fn proxy_msg(&self) -> String {
        r#"{"t":"proxy","host":null,"port":3130}"#.into()
    }
    fn menu(&self, session: u64, store: &str, mdoc: &str) -> Result<ExtMenuResponse, ExtError> {
        self.stores.lock().push(store.into());
        match (session, mdoc) {
            (7, "bound") if !store.is_empty() => Err(ExtError::Forbidden),
            (7, "bound") => Ok(ExtMenuResponse {
                commands: vec![ExtMenuCommand {
                    script: "s".into(),
                    script_name: "S".into(),
                    cmd: "c1".into(),
                    name: "Do".into(),
                    access_key: String::new(),
                    title: String::new(),
                    auto_close: true,
                }],
                grants: vec![ExtGrant {
                    script: "s".into(),
                    script_name: "S".into(),
                    host: "a.test".into(),
                    patterns: vec!["*://*.a.test/*".into()],
                }],
            }),
            (7, "other") => Err(ExtError::Forbidden),
            _ => Err(ExtError::NotFound),
        }
    }
    fn trigger(
        &self,
        session: u64,
        store: &str,
        req: &ExtTriggerRequest,
    ) -> Result<bool, ExtError> {
        self.menu(session, store, &req.mdoc)?;
        self.triggers.lock().push(req.clone());
        Ok(true)
    }
    fn browser_fallback(&self, _p: &str, _s: &str) -> bool {
        *self.fallback.lock()
    }
    fn set_audit(&self, _sink: Arc<dyn Fn(ExtAuditEvent) + Send + Sync>) {}
}

fn ws_server(ctx: &TestContext) -> TestServer {
    TestServer::builder()
        .http_transport()
        .build(ctx.router.clone())
        .unwrap()
}

async fn with_bridge() -> (TestContext, Arc<Fake>) {
    let ctx = TestContext::new().await.unwrap();
    let fake = Arc::new(Fake::default());
    let b: Arc<dyn ExtBridge> = fake.clone();
    let _ = ctx.state.ext.set(b);
    (ctx, fake)
}

fn audit_rows(state: &AppState, needle: &str) -> usize {
    state
        .audit
        .query(&Default::default(), 0, 200)
        .0
        .iter()
        .filter(|e| e.route.contains(needle))
        .count()
}

#[tokio::test(start_paused = true)]
async fn a_channel_without_a_hello_is_closed_after_five_seconds() {
    let (ctx, _f) = with_bridge().await;
    let server = ws_server(&ctx);
    let mut ws = server
        .get_websocket("/api/v1/ext/channel")
        .await
        .into_websocket()
        .await;
    match ws.receive_message().await {
        WsMessage::Close(Some(f)) => assert_eq!(u16::from(f.code), 4408),
        m => panic!("expected a close, got {m:?}"),
    }
}

async fn hello(server: &TestServer, token: &str) -> axum_test::TestWebSocket {
    let mut ws = server
        .get_websocket("/api/v1/ext/channel")
        .await
        .into_websocket()
        .await;
    ws.send_text(json!({"t": "hello", "token": token, "v": 1}).to_string())
        .await;
    ws
}

#[tokio::test]
async fn hello_needs_a_live_token_with_the_bridge_scope() {
    let (ctx, fake) = with_bridge().await;
    let admin = ctx.admin().await;
    let server = ws_server(&ctx);

    // unknown token
    let mut ws = hello(&server, "abk_nope_nope").await;
    match ws.receive_message().await {
        WsMessage::Close(Some(f)) => assert_eq!(u16::from(f.code), 4401),
        m => panic!("{m:?}"),
    }
    // a token without the scope
    let weak = ctx.token(&admin, &["lists:read"]).await;
    let mut ws = hello(&server, &weak).await;
    match ws.receive_message().await {
        WsMessage::Close(Some(f)) => assert_eq!(u16::from(f.code), 4403),
        m => panic!("{m:?}"),
    }
    // malformed hello
    let mut ws = server
        .get_websocket("/api/v1/ext/channel")
        .await
        .into_websocket()
        .await;
    ws.send_text("not json").await;
    match ws.receive_message().await {
        WsMessage::Close(Some(f)) => assert_eq!(u16::from(f.code), 4400),
        m => panic!("{m:?}"),
    }
    assert!(fake.idents.lock().is_empty(), "nothing was registered");

    // a good token: welcome with the sid; frames reach the bridge; audited open and close
    let good = ctx.token(&admin, &["userscripts:bridge"]).await;
    let mut ws = hello(&server, &good).await;
    let w: Value = ws.receive_json().await;
    assert_eq!(w["t"], "welcome");
    assert_eq!(w["sid"], SID);
    assert_eq!(fake.idents.lock().len(), 1);
    ws.send_text(r#"{"t":"perms","origins":[]}"#).await;
    let out = fake.outs.lock()[0].clone();
    // the extension learns where its proxy listener is right after welcome
    assert_eq!(ws.receive_json::<Value>().await["port"], 3130);
    out.send(ExtOut::Text(r#"{"t":"proxy","port":3131}"#.into()))
        .await
        .unwrap();
    assert_eq!(ws.receive_text().await, r#"{"t":"proxy","port":3131}"#);
    ws.close().await;
    for _ in 0..100 {
        if !fake.closed.lock().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(*fake.closed.lock(), vec![7]);
    assert_eq!(fake.texts.lock().len(), 1);
    assert_eq!(audit_rows(&ctx.state, "ext/session_open"), 1);
    // a dropped socket is audited as a detach (the session may be resumed)
    for _ in 0..100 {
        if audit_rows(&ctx.state, "ext/session_detach") == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(audit_rows(&ctx.state, "ext/session_detach"), 1);

    // an explicit `bye` ends the session for good
    let mut ws = hello(&server, &good).await;
    let _: Value = ws.receive_json().await;
    ws.send_text(r#"{"t":"bye"}"#).await;
    for _ in 0..100 {
        if audit_rows(&ctx.state, "ext/session_close") == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(audit_rows(&ctx.state, "ext/session_close"), 1);
}

#[tokio::test]
async fn only_an_extension_origin_may_open_the_channel() {
    let (ctx, _f) = with_bridge().await;
    let r = ws_server(&ctx)
        .get_websocket("/api/v1/ext/channel")
        .add_header("origin", "https://evil.test")
        .await;
    r.assert_status(StatusCode::FORBIDDEN);
    // without a bridge the endpoint says so
    let bare = TestContext::new().await.unwrap();
    let r = ws_server(&bare).get_websocket("/api/v1/ext/channel").await;
    r.assert_status(StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn menu_calls_need_the_scope_and_the_callers_own_bound_session() {
    let (ctx, fake) = with_bridge().await;
    let admin = ctx.admin().await;
    let server = ws_server(&ctx);
    let good = ctx.token(&admin, &["userscripts:bridge"]).await;
    let other = ctx
        .token(&admin, &["userscripts:bridge", "lists:read"])
        .await;
    let weak = ctx.token(&admin, &["lists:read"]).await;
    let _ws = hello(&server, &good).await;
    let mut ws = _ws;
    let _: Value = ws.receive_json().await; // welcome: the session exists
    let get = |tok: &str, mdoc: &str, sid: Option<&str>| {
        let mut r = ctx.bearer("GET", &format!("/api/v1/ext/menu?mdoc={mdoc}"), tok);
        if let Some(s) = sid {
            r = r.add_header("x-argus-session", s);
        }
        r
    };
    // no scope
    get(&weak, "bound", Some(SID))
        .await
        .assert_status(StatusCode::FORBIDDEN);
    // no session header, wrong sid, another token's session
    let r = get(&good, "bound", None).await;
    r.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(r.json::<Value>()["error"]["code"], "ext_session_required");
    get(&good, "bound", Some("ffffffffffffffffffffffffffffffff"))
        .await
        .assert_status(StatusCode::FORBIDDEN);
    get(&other, "bound", Some(SID))
        .await
        .assert_status(StatusCode::FORBIDDEN);
    // a cookie login (not a token) cannot use the bridge
    admin
        .get("/api/v1/ext/menu?mdoc=bound")
        .await
        .assert_status(StatusCode::FORBIDDEN);
    // the bound document lists; a document bound elsewhere is refused; an unknown one 404s
    let r = get(&good, "bound", Some(SID)).await;
    r.assert_status_ok();
    let v: Value = r.json();
    assert_eq!(v["commands"][0]["cmd"], "c1");
    assert_eq!(v["grants"][0]["patterns"][0], "*://*.a.test/*");
    let r = get(&good, "other", Some(SID)).await;
    r.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(r.json::<Value>()["error"]["code"], "ext_document_not_bound");
    get(&good, "zzz", Some(SID))
        .await
        .assert_status(StatusCode::NOT_FOUND);
    // another container's tab (its store token) cannot see the document
    get(&good, "bound", Some(SID))
        .add_header("x-argus-store", "c1x")
        .await
        .assert_status(StatusCode::FORBIDDEN);
    assert_eq!(fake.stores.lock().last().unwrap(), "c1x");
    // a store header that is not an opaque token is ignored (default store)
    get(&good, "bound", Some(SID))
        .add_header("x-argus-store", "../../x")
        .await
        .assert_status_ok();

    // trigger: same rules
    let body = json!({"mdoc": "bound", "script": "s", "cmd": "c1"});
    let r = ctx
        .bearer("POST", "/api/v1/ext/menu/trigger", &good)
        .add_header("x-argus-session", SID)
        .json(&body)
        .await;
    r.assert_status_ok();
    assert_eq!(r.json::<Value>()["delivered"], true);
    assert_eq!(fake.triggers.lock().len(), 1);
    ctx.bearer("POST", "/api/v1/ext/menu/trigger", &good)
        .json(&body)
        .await
        .assert_status(StatusCode::FORBIDDEN);
    ctx.bearer("POST", "/api/v1/ext/menu/trigger", &weak)
        .add_header("x-argus-session", SID)
        .json(&body)
        .await
        .assert_status(StatusCode::FORBIDDEN);
    ctx.bearer("POST", "/api/v1/ext/menu/trigger", &good)
        .add_header("x-argus-session", SID)
        .json(&json!({"mdoc": "other", "script": "s", "cmd": "c1"}))
        .await
        .assert_status(StatusCode::FORBIDDEN);
    assert_eq!(
        fake.triggers.lock().len(),
        1,
        "refused triggers reach nothing"
    );
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

fn src(extra: &str) -> String {
    format!(
        "// ==UserScript==\n// @name Bridge Test\n// @namespace bt\n// @version 1.0\n// @match https://example.com/*\n{extra}\n// ==/UserScript==\nconsole.log(1);"
    )
}

#[tokio::test]
async fn browser_logins_are_approved_only_during_review() {
    let (ctx, fake) = with_bridge().await;
    let admin = ctx.admin().await;
    let plan = |source: String| {
        let admin = &admin;
        async move {
            let r = admin
                .post("/api/v1/userscripts/plan")
                .json(&json!({"source": source}))
                .await;
            r.assert_status_ok();
            r.json::<Value>()["plan_id"].as_str().unwrap().to_string()
        }
    };
    // a script with no network or cookie grant cannot be approved for browser logins
    let p = plan(src("// @grant GM_setValue")).await;
    let r = admin
        .post(&format!("/api/v1/userscripts/plan/{p}/confirm"))
        .json(&json!({"browser_cookies": true}))
        .await;
    assert_eq!(r.status_code(), StatusCode::BAD_REQUEST, "{}", r.text());
    // with a network grant the plan's confirmation grants it
    let p = plan(src("// @grant GM_xmlhttpRequest\n// @connect a.test")).await;
    let r = admin
        .post(&format!("/api/v1/userscripts/plan/{p}/confirm"))
        .json(&json!({"browser_cookies": true}))
        .await;
    assert_eq!(r.status_code(), StatusCode::CREATED, "{}", r.text());
    let s: Value = r.json();
    assert_eq!(s["browser_cookies_approved"], true);
    assert_eq!(s["browser_logins_unavailable"], false);
    let id = s["id"].as_str().unwrap().to_string();
    let url = format!("/api/v1/userscripts/{}", enc(&id));
    // the page of an approved script shows when its last request fell back
    *fake.fallback.lock() = true;
    let s: Value = admin.get(&url).await.json();
    assert_eq!(s["browser_logins_unavailable"], true);
    *fake.fallback.lock() = false;

    // outside a review: refused (409)
    let r = admin
        .post(&format!("{url}/approve"))
        .json(&json!({"browser_cookies": true}))
        .await;
    assert_eq!(r.status_code(), StatusCode::CONFLICT, "{}", r.text());
    assert_eq!(r.json::<Value>()["error"]["code"], "not_pending_approval");
    admin.delete(&url).await.assert_status_ok();

    // an imported script waits for review: the file cannot approve itself, the review can
    let bundle = |approve: bool| {
        json!({
            "format": "argus-userscripts-v1",
            "approve": approve,
            "scripts": [{
                "source": src("// @grant GM_cookie\n// @connect a.test"),
                "enabled": true,
                "browser_cookies": true,
                "assets": {"requires": [], "resources": []}
            }]
        })
    };
    let res: Value = admin
        .post("/api/v1/userscripts/import")
        .json(&bundle(false))
        .await
        .json();
    let s: Value = admin.get(&url).await.json();
    assert_eq!(s["browser_cookies_approved"], false, "{res}");
    let r = admin
        .post(&format!("{url}/approve"))
        .json(&json!({"browser_cookies": true}))
        .await;
    r.assert_status_ok();
    assert_eq!(r.json::<Value>()["browser_cookies_approved"], true);
    assert!(
        audit_rows(&ctx.state, "/userscripts/{id}/approve") >= 1,
        "approvals are audited"
    );
    // an explicitly approved import keeps what the file says
    admin.delete(&url).await.assert_status_ok();
    admin
        .post("/api/v1/userscripts/import")
        .json(&bundle(true))
        .await
        .assert_status_ok();
    let s: Value = admin.get(&url).await.json();
    assert_eq!(s["browser_cookies_approved"], true);
}

#[tokio::test]
async fn revoking_a_token_closes_its_live_channels_and_a_ping_backstop_catches_the_rest() {
    let (ctx, fake) = with_bridge().await;
    let admin = ctx.admin().await;
    let server = ws_server(&ctx);
    let tok = ctx.token(&admin, &["userscripts:bridge"]).await;
    // explicit revoke (the owner's own endpoint) tells the bridge
    let list: Value = admin.get("/api/v1/tokens").await.json();
    let id = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["scopes"] == json!(["userscripts:bridge"]))
        .map(|t| t["id"].as_str().unwrap().to_string())
        .expect("token id");
    // a live channel; then the token is revoked: the next pings notice even if close_token missed
    let mut ws = hello(&server, &tok).await;
    let _: Value = ws.receive_json().await;
    let _: Value = ws.receive_json().await;
    admin
        .delete(&format!("/api/v1/tokens/{id}"))
        .await
        .assert_status_ok();
    assert_eq!(*fake.closed_tokens.lock(), vec![id.clone()]);
    for _ in 0..3 {
        ws.send_text(r#"{"t":"ping"}"#).await;
    }
    match ws.receive_message().await {
        WsMessage::Close(Some(f)) => assert_eq!(u16::from(f.code), 4401),
        m => panic!("expected a close, got {m:?}"),
    }
}

fn log_event(
    ctx: &TestContext,
    session: u64,
    url: &str,
    action: filter_engine::EventAction,
    rule: &str,
) {
    ctx.state
        .shared_engine
        .record_request(&filter_engine::EventRef {
            action,
            method: "GET",
            url,
            source_host: "page.test",
            request_type: "script",
            rule,
            list_id: None,
            client: None,
            status: None,
            mode: filter_engine::EventMode::Explicit,
            error_kind: None,
            cert_fp: None,
            outcome: None,
            session: Some(session),
        });
}

#[tokio::test]
async fn the_log_is_session_scoped_paged_and_needs_a_session() {
    use filter_engine::EventAction::{Allowed, Blocked};
    let (ctx, _f) = with_bridge().await;
    let admin = ctx.admin().await;
    let server = ws_server(&ctx);
    let good = ctx
        .token(&admin, &["userscripts:bridge", "logs:read"])
        .await;
    let other = ctx.token(&admin, &["logs:read"]).await;
    let no_scope = ctx.token(&admin, &["userscripts:bridge"]).await;
    let mut ws = hello(&server, &good).await;
    let _: Value = ws.receive_json().await;

    log_event(
        &ctx,
        7,
        "https://ads.test/a.js?id=1",
        Blocked,
        "||ads.test^",
    );
    log_event(&ctx, 7, "https://page.test/b.js", Allowed, "");
    log_event(&ctx, 7, "https://cdn.test/c.js", Allowed, "");
    // Another session's traffic never shows.
    log_event(&ctx, 99, "https://secret.test/x", Blocked, "||secret.test^");

    let get = |tok: &str, q: &str, sid: Option<&str>| {
        let mut r = ctx.bearer("GET", &format!("/api/v1/ext/log{q}"), tok);
        if let Some(s) = sid {
            r = r.add_header("x-argus-session", s);
        }
        r
    };
    let r = get(&good, "", Some(SID)).await;
    r.assert_status_ok();
    let v: Value = r.json();
    let urls: Vec<&str> = v["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["url"].as_str().unwrap())
        .collect();
    assert_eq!(
        urls,
        [
            // The query is dropped unless the request log keeps queries.
            "https://ads.test/a.js",
            "https://page.test/b.js",
            "https://cdn.test/c.js"
        ]
    );
    let first = &v["entries"][0];
    assert_eq!(first["outcome"], "blocked");
    assert_eq!(first["rule"], "||ads.test^");
    assert_eq!(first["third_party"], true);
    assert_eq!(first["type"], "script");
    assert_eq!(first["source_host"], "page.test");
    assert_eq!(v["entries"][1]["third_party"], false);
    assert_eq!(v["entries"][1]["outcome"], "allowed");
    assert!(!v.to_string().contains("secret.test"));

    // paging by `since`
    let s1 = first["seq"].as_u64().unwrap();
    let v: Value = get(&good, &format!("?since={s1}"), Some(SID)).await.json();
    assert_eq!(v["entries"].as_array().unwrap().len(), 2);
    let next = v["next"].as_u64().unwrap();
    let v: Value = get(&good, &format!("?since={next}"), Some(SID))
        .await
        .json();
    assert!(v["entries"].as_array().unwrap().is_empty());
    assert_eq!(v["next"], next);
    log_event(&ctx, 7, "https://later.test/d.js", Allowed, "");
    let v: Value = get(&good, &format!("?since={next}"), Some(SID))
        .await
        .json();
    assert_eq!(v["entries"][0]["url"], "https://later.test/d.js");

    // no session, a wrong session, another token's session, and a missing scope
    get(&good, "", None)
        .await
        .assert_status(StatusCode::FORBIDDEN);
    get(&good, "", Some("ffffffffffffffffffffffffffffffff"))
        .await
        .assert_status(StatusCode::FORBIDDEN);
    get(&other, "", Some(SID))
        .await
        .assert_status(StatusCode::FORBIDDEN);
    get(&no_scope, "", Some(SID))
        .await
        .assert_status(StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn ext_rules_need_their_scope_and_accept_one_valid_line() {
    let (ctx, _f) = with_bridge().await;
    let admin = ctx.admin().await;
    let ext = ctx.token(&admin, &["rules:ext"]).await;
    let site = ctx.token(&admin, &["rules:site", "rules:read"]).await;
    let post = |tok: &str, op: &str, rule: &str| {
        ctx.bearer("POST", "/api/v1/ext/rules", tok)
            .json(&json!({"op": op, "rule": rule}))
    };
    // A token without rules:ext is refused.
    post(&site, "add", "||a.com^")
        .await
        .assert_status(StatusCode::FORBIDDEN);
    ctx.bearer("GET", "/api/v1/ext/rules?site=a.com", &site)
        .await
        .assert_status(StatusCode::FORBIDDEN);
    // rules:ext opens nothing else in the rules.
    ctx.bearer("PUT", "/api/v1/rules/custom", &ext)
        .await
        .assert_status(StatusCode::FORBIDDEN);
    ctx.bearer("GET", "/api/v1/rules/custom", &ext)
        .await
        .assert_status(StatusCode::FORBIDDEN);
    // Rejected input.
    let long = format!("||{}.test^", "a".repeat(2100));
    for bad in [
        "||a.com^\n||b.com^",
        "||a.com^\r||b.com^",
        "!#include other.txt",
        "!#if env_firefox",
        "! comment",
        "",
        "   ",
        "example.com##+js(abort-on-property-read, x)",
        "example.com##.a:has-text(x)",
        "##div",
        "||a.com^$replace=/a/b/",
        "||a.com^$csp=script-src 'none'",
        long.as_str(),
    ] {
        let r = post(&ext, "add", bad).await;
        r.assert_status(StatusCode::BAD_REQUEST);
    }
    post(&ext, "toggle", "||a.com^")
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(ctx.state.filter_store.get_custom_rules().unwrap(), "");

    // add -> list -> remove round trip
    let rule = "||ads.a.com^$script,third-party,domain=a.com";
    let v: Value = post(&ext, "add", rule).await.json();
    assert_eq!(v, json!({"rule_count": 1, "changed": true}));
    let v: Value = post(&ext, "add", rule).await.json();
    assert_eq!(v, json!({"rule_count": 1, "changed": false}));
    assert!(ctx
        .state
        .filter_store
        .get_custom_rules()
        .unwrap()
        .contains(rule));
    post(&ext, "add", "@@||other.com^$domain=b.com")
        .await
        .assert_status_ok();
    let v: Value = ctx
        .bearer("GET", "/api/v1/ext/rules?site=A.com", &ext)
        .await
        .json();
    assert_eq!(v["site"], "a.com");
    assert_eq!(v["rules"], json!([{"rule": rule, "exclusive": true}]));
    ctx.bearer("GET", "/api/v1/ext/rules?site=a.com/x", &ext)
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    let v: Value = post(&ext, "remove", rule).await.json();
    assert_eq!(v, json!({"rule_count": 1, "changed": true}));
    let v: Value = post(&ext, "remove", rule).await.json();
    assert_eq!(v["changed"], false);
    assert_eq!(
        ctx.state.filter_store.get_custom_rules().unwrap(),
        "@@||other.com^$domain=b.com\n"
    );
    // Audited with the rule text.
    assert_eq!(audit_rows(&ctx.state, "ext/rules#add"), 2);
    assert_eq!(audit_rows(&ctx.state, "ext/rules#remove"), 1);
    // The host's case does not matter on add or remove.
    post(&ext, "add", "||Example.com^").await.assert_status_ok();
    let v: Value = post(&ext, "remove", "||example.com^").await.json();
    assert_eq!(v["changed"], true);
}

#[tokio::test]
async fn cosmetic_rule_round_trip() {
    let (ctx, _f) = with_bridge().await;
    let admin = ctx.admin().await;
    let ext = ctx.token(&admin, &["rules:ext"]).await;
    let post = |op: &str, rule: &str| {
        ctx.bearer("POST", "/api/v1/ext/rules", &ext)
            .json(&json!({"op": op, "rule": rule}))
    };
    let rule = "a.com##.promo-banner";
    let v: Value = post("add", rule).await.json();
    assert_eq!(v, json!({"rule_count": 1, "changed": true}));
    let v: Value = post("add", "A.com##.promo-banner").await.json();
    assert_eq!(v["changed"], false);
    post("add", "##.sticky-ad").await.assert_status_ok();
    let v: Value = ctx
        .bearer("GET", "/api/v1/ext/rules?site=a.com", &ext)
        .await
        .json();
    assert_eq!(v["rules"], json!([{"rule": rule, "exclusive": true}]));
    post("remove", "##.sticky-ad").await.assert_status_ok();
    let v: Value = post("remove", rule).await.json();
    assert_eq!(v["changed"], true);
    assert_eq!(ctx.state.filter_store.get_custom_rules().unwrap(), "");
    for bad in ["a.com#@#.x", "a.com##.x:xpath(//a)", "##body", "com##.x"] {
        post("add", bad)
            .await
            .assert_status(StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn lifetime_totals_and_daily_categories_are_served() {
    let (ctx, _f) = with_bridge().await;
    let admin = ctx.admin().await;
    let tok = ctx.token(&admin, &["stats:read"]).await;
    let stats = ctx.state.filter_stats.clone();
    stats.record_blocked_by("script", "a.com", None, Some("||a.com^"));
    stats.record_blocked_by("image", "b.com", Some("easylist"), None);
    stats.record_allowed();
    let v: Value = ctx.bearer("GET", "/api/v1/stats/filter", &tok).await.json();
    assert_eq!(v["lifetime_total"], 3);
    assert_eq!(v["lifetime_blocked"], 2);
    let cats = &v["lifetime_by_category"];
    assert_eq!(
        cats["ads"].as_u64().unwrap() + cats["other"].as_u64().unwrap(),
        2
    );
    // A reset of the counters keeps the lifetime totals.
    stats.reset();
    ctx.state.daily.note_reset();
    let v: Value = ctx.bearer("GET", "/api/v1/stats/filter", &tok).await.json();
    assert_eq!(v["lifetime_blocked"], 2);
    assert_eq!(v["blocked_requests"], 0);
    for (range, n) in [("d7", 7), ("d30", 30), ("m12", 12)] {
        let v: Value = ctx
            .bearer(
                "GET",
                &format!("/api/v1/stats/timeseries?range={range}"),
                &tok,
            )
            .await
            .json();
        let pts = v["points"].as_array().unwrap();
        assert_eq!(pts.len(), n, "{range}");
        let blocked: u64 = pts.iter().map(|p| p["blocked"].as_u64().unwrap()).sum();
        assert_eq!(blocked, 2, "{range}");
        let last = pts.last().unwrap();
        assert!(last["by_category"]["other"].as_u64().is_some());
    }
}

#[tokio::test]
async fn the_session_log_keeps_the_query_only_when_asked_and_ignores_log_capacity() {
    use filter_engine::EventAction::Allowed;
    let (ctx, _f) = with_bridge().await;
    let admin = ctx.admin().await;
    let server = ws_server(&ctx);
    let good = ctx
        .token(&admin, &["userscripts:bridge", "logs:read"])
        .await;
    let mut ws = hello(&server, &good).await;
    let _: Value = ws.receive_json().await;
    // A request log of size zero still feeds the extension's own log.
    ctx.state.shared_engine.set_event_capacity(0);
    log_event(&ctx, 7, "https://a.test/p?token=secret#f", Allowed, "");
    ctx.state.shared_engine.set_recent_keep_query(true);
    log_event(&ctx, 7, "https://a.test/q?x=1", Allowed, "");
    let v: Value = ctx
        .bearer("GET", "/api/v1/ext/log", &good)
        .add_header("x-argus-session", SID)
        .await
        .json();
    let urls: Vec<&str> = v["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["url"].as_str().unwrap())
        .collect();
    assert_eq!(urls, ["https://a.test/p", "https://a.test/q?x=1"]);
}

#[tokio::test]
async fn removing_a_rule_is_held_to_the_same_allowlist_and_site_lookup_respects_boundaries() {
    let (ctx, _f) = with_bridge().await;
    let admin = ctx.admin().await;
    let ext = ctx.token(&admin, &["rules:ext"]).await;
    let post = |op: &str, rule: &str| {
        ctx.bearer("POST", "/api/v1/ext/rules", &ext)
            .json(&json!({"op": op, "rule": rule}))
    };
    // A line the extension could never have added cannot be removed by it.
    ctx.state
        .filter_store
        .set_custom_rules("##.a:has-text(x)\n@@*$document\n||ba.com^\n||a.com^$script\n")
        .unwrap();
    for line in ["##.a:has-text(x)", "@@*$document"] {
        let r = post("remove", line).await;
        r.assert_status(StatusCode::BAD_REQUEST);
        assert!(
            r.text().contains("accepted") || r.text().contains("rule"),
            "{}",
            r.text()
        );
    }
    assert!(ctx
        .state
        .filter_store
        .get_custom_rules()
        .unwrap()
        .contains("##.a:has-text(x)"));
    // Only whole hosts / subdomains match the site.
    let v: Value = ctx
        .bearer("GET", "/api/v1/ext/rules?site=a.com", &ext)
        .await
        .json();
    assert_eq!(
        v["rules"],
        json!([{"rule": "||a.com^$script", "exclusive": true}])
    );
    post("remove", "||a.com^$script").await.assert_status_ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_samples_neither_lose_nor_double_count_blocks() {
    let (ctx, _f) = with_bridge().await;
    let stats = ctx.state.filter_stats.clone();
    for _ in 0..500 {
        stats.record_blocked_by("script", "a.test", Some("easylist"), None);
        stats.record_allowed();
    }
    let runs: Vec<_> = (0..8)
        .map(|_| {
            let st = ctx.state.clone();
            tokio::spawn(async move { st.flush_stats().await })
        })
        .collect();
    for r in runs {
        r.await.unwrap();
    }
    let (total, blocked, cats) = ctx.state.daily.lifetime();
    assert_eq!((total, blocked), (1000, 500));
    assert_eq!(cats.iter().sum::<u64>(), 500);
}

#[tokio::test]
async fn site_rules_are_only_those_scoped_to_the_site() {
    let (ctx, _f) = with_bridge().await;
    let admin = ctx.admin().await;
    let ext = ctx.token(&admin, &["rules:ext"]).await;
    for r in [
        "a.com##.only-a",
        "a.com,b.com##.shared",
        "b.com##.other-b",
        "##.everywhere-ad",
        "||ads.a.com^",
        "||x.com^$domain=a.com|b.com",
        "||x.com^$domain=a.com,third-party",
        "||y.com^$domain=b.com",
        "||ba.com^",
        "||a.com^$domain=b.com",
    ] {
        ctx.bearer("POST", "/api/v1/ext/rules", &ext)
            .json(&json!({"op": "add", "rule": r}))
            .await
            .assert_status_ok();
    }
    let v: Value = ctx
        .bearer("GET", "/api/v1/ext/rules?site=a.com", &ext)
        .await
        .json();
    assert_eq!(
        v["rules"],
        json!([
            {"rule": "a.com##.only-a", "exclusive": true},
            {"rule": "a.com,b.com##.shared", "exclusive": false},
            {"rule": "||ads.a.com^", "exclusive": true},
            {"rule": "||x.com^$domain=a.com|b.com", "exclusive": false},
            {"rule": "||x.com^$domain=a.com,third-party", "exclusive": true},
        ])
    );
}

#[tokio::test]
async fn all_sites_hiding_cannot_blank_pages_or_hit_argus_ui() {
    let (ctx, _f) = with_bridge().await;
    let admin = ctx.admin().await;
    let ext = ctx.token(&admin, &["rules:ext"]).await;
    let add = |r: &str| {
        ctx.bearer("POST", "/api/v1/ext/rules", &ext)
            .json(&json!({"op": "add", "rule": r}))
    };
    for bad in [
        "##html.dark",
        "##body.x",
        "##.a > body.x",
        "##:root.x",
        "##[data-x*=\"abcd\"]",
        "##[data-x~=\"abcd\"]",
        "##[data-x=\"ab\"]",
        "##[lang=\"en-US\"]",
        "##[dir=\"ltr\"]",
        "##[style=\"display:none\"]",
        "##[class=\"abcd\"]",
        "##[id=\"abcd\"]",
        "##.x\\",
        "a.com##.x\\",
        "a.com##[id^=\"__argus\"]",
        "a.com##.argus-panel",
        "a.com##\\#__ab_cfg",
    ] {
        add(bad).await.assert_status(StatusCode::BAD_REQUEST);
    }
    for good in ["##.ad-slot", "##[data-ad=\"slot1\"]", "a.com##body.x"] {
        add(good).await.assert_status_ok();
    }
}

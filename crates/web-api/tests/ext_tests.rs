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

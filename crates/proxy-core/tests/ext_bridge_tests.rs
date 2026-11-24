//! The extension bridge hub: session binding, routing of credentialed calls, menus, jobs.
//! Every test builds its own hub, manager and temp dir (nothing shared).

use api_types::{ExtError, ExtIdent, ExtOut, ExtTriggerRequest};
use common::bypass::{BypassEngine, BypassMode, Entry};
use proxy_core::ext_bridge::{
    grant_patterns, job_frame, parse_job_frame, take_headers, ExtHub, Fallback, HubCtx, JobEvent,
    Perms, Route, Wait, F_CANCEL, F_DATA, F_END, F_HEAD, F_JOB, RELAY_HEADER,
};
use proxy_core::gm::{Caller, GmHost};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use userscript_engine::install::{finish_install, plan_install, Approvals, Fetched};
use userscript_engine::token::{self, TokenClaims};
use userscript_engine::{Userscript, UserscriptManager};

const ORIGIN: &str = "https://hit.test";

fn script_src(extra: &str) -> String {
    format!(
        "// ==UserScript==\n// @name n\n// @namespace t\n// @version 1.0\n// @match *://hit.test/*\n// @grant GM_xmlhttpRequest\n// @grant GM_cookie\n// @grant GM_registerMenuCommand\n// @connect api.test\n{extra}\n// ==/UserScript==\n1;\n"
    )
}

fn script(extra: &str, browser: bool) -> Userscript {
    finish_install(
        plan_install(&script_src(extra), None).unwrap(),
        Fetched::default(),
        Approvals {
            allow_connect_all: false,
            browser_cookies: browser,
        },
    )
    .unwrap()
}

struct Fx {
    _dir: tempfile::TempDir,
    m: Arc<UserscriptManager>,
    gm: GmHost,
    id: String,
    bypass: Arc<BypassEngine>,
}

fn fx(browser: bool) -> Fx {
    let dir = tempfile::tempdir().unwrap();
    let m = Arc::new(UserscriptManager::new(dir.path().to_path_buf()).unwrap());
    let s = script("", browser);
    let id = s.id.clone();
    m.install_script("default", s).unwrap();
    let gm = GmHost::new();
    let bypass = Arc::new(BypassEngine::in_memory());
    gm.ext().set_ctx(HubCtx {
        manager: m.clone(),
        profiles: None,
        bypass: bypass.clone(),
    });
    Fx {
        _dir: dir,
        m,
        gm,
        id,
        bypass,
    }
}

fn ident(token: &str) -> ExtIdent {
    ExtIdent {
        token_id: token.into(),
        user: "u".into(),
        profiles: None,
    }
}

async fn grant(hub: &ExtHub, session: u64, origins: &[&str]) {
    hub.on_text(
        session,
        &json!({"t": "perms", "origins": origins}).to_string(),
    )
    .await;
}

fn plan_for(f: &Fx, session: Option<u64>) -> proxy_core::gm::DocPlan {
    plan_in(f, session, "")
}

fn plan_in(f: &Fx, session: Option<u64>, store: &str) -> proxy_core::gm::DocPlan {
    let idx = f.m.index_for("default").clone();
    f.gm.plan_document_bound(
        &idx,
        "default",
        "hit.test",
        "https://hit.test/",
        ORIGIN,
        true,
        session,
        store,
    )
    .unwrap()
}

fn route(f: &Fx, s: &Userscript, mdoc: Option<&str>, anonymous: bool, host: &str) -> Route {
    f.gm.credentialed_route(s, "default", ORIGIN, anonymous, false, false, mdoc, host)
}

#[tokio::test]
async fn routing_matrix_only_a_fully_matching_call_reaches_the_browser() {
    let f = fx(true);
    let s = f.m.index_for("default").get(&f.id).unwrap().script.clone();
    let hub = f.gm.ext().clone();
    let (sess, sid, _rx) = hub.open(ident("t1"));
    grant(&hub, sess, &["*://*.api.test/*"]).await;

    // all match -> the session bound by the `sid` the browser sent
    let bound = hub.authenticate(&sid).expect("known sid authenticates");
    assert_eq!(bound, sess);
    let plan = plan_for(&f, Some(bound));
    assert!(plan.ext_bound);
    assert_eq!(
        route(&f, &s, plan.mdoc.as_deref(), false, "api.test"),
        Route::Ext(sess)
    );
    assert_eq!(
        route(&f, &s, plan.mdoc.as_deref(), false, "v1.api.test"),
        Route::Ext(sess),
        "a *.host permission covers subdomains"
    );

    // sid mismatch / unknown sid: no session at all
    assert_eq!(hub.authenticate("0123456789abcdef0123456789abcdef"), None);
    assert_eq!(hub.authenticate(""), None);
    assert_eq!(hub.authenticate(&sid[..sid.len() - 1]), None);
    let unbound = plan_for(&f, None);
    assert!(!unbound.ext_bound);
    assert!(
        unbound.mdoc.is_none(),
        "an unbound page has no public id and no record"
    );
    assert_eq!(
        route(&f, &s, unbound.mdoc.as_deref(), false, "api.test"),
        Route::Jar(Fallback::NoDocument)
    );
    // a request naming no document, or a made-up one
    assert_eq!(
        route(&f, &s, None, false, "api.test"),
        Route::Jar(Fallback::NoDocument)
    );
    assert_eq!(
        route(&f, &s, Some("deadbeef"), false, "api.test"),
        Route::Jar(Fallback::NoDocument)
    );
    // missing host permission
    assert_eq!(
        route(&f, &s, plan.mdoc.as_deref(), false, "other.test"),
        Route::Jar(Fallback::NoPermission)
    );
    // anonymous requests are never relayed; neither is a script without the approval flag
    assert_eq!(
        route(&f, &s, plan.mdoc.as_deref(), true, "api.test"),
        Route::Jar(Fallback::Anonymous)
    );
    let mut off = s.clone();
    off.browser_cookies = false;
    assert_eq!(
        route(&f, &off, plan.mdoc.as_deref(), false, "api.test"),
        Route::Jar(Fallback::NotApproved)
    );
    // the document of another profile or origin cannot be claimed
    assert_eq!(
        f.gm.credentialed_route(
            &s,
            "p9",
            ORIGIN,
            false,
            false,
            false,
            plan.mdoc.as_deref(),
            "api.test"
        ),
        Route::Jar(Fallback::NoDocument)
    );
    assert_eq!(
        f.gm.credentialed_route(
            &s,
            "default",
            "https://evil.test",
            false,
            false,
            false,
            plan.mdoc.as_deref(),
            "api.test"
        ),
        Route::Jar(Fallback::NoDocument)
    );
    // a second session (another browser) never receives this document's jobs
    let (other, _osid, _orx) = hub.open(ident("t2"));
    grant(&hub, other, &["<all_urls>"]).await;
    assert_eq!(
        route(&f, &s, plan.mdoc.as_deref(), false, "api.test"),
        Route::Ext(sess)
    );
    // the session goes away: the warning is recorded and calls fall back
    hub.close(sess);
    assert_eq!(
        route(&f, &s, plan.mdoc.as_deref(), false, "api.test"),
        Route::Jar(Fallback::Dead)
    );
    assert!(hub.browser_fallback("default", &f.id));
}

#[tokio::test]
async fn a_token_profile_restriction_limits_what_a_session_can_bind_and_pins_its_profile() {
    let f = fx(true);
    let hub = f.gm.ext();
    let (s, sid, _rx) = hub.open(ExtIdent {
        token_id: "t".into(),
        user: "u".into(),
        profiles: Some(vec!["3".into()]),
    });
    assert_eq!(hub.authenticate(&sid), Some(s));
    assert!(!hub.allows(s, "default"));
    assert!(hub.allows(s, "p3"));
    assert_eq!(hub.pinned_profile(s), Some(3));
    // a new connection gets a new secret, and an unrestricted token pins nothing
    let (s2, sid2, _rx2) = hub.open(ident("t"));
    assert_ne!(sid, sid2);
    assert!(hub.allows(s2, "default") && hub.pinned_profile(s2).is_none());
}

#[tokio::test]
async fn jobs_go_to_one_session_are_cancelled_on_drop_and_recheck_hops() {
    let f = fx(true);
    let hub = f.gm.ext().clone();
    let (sess, _sid, mut rx) = hub.open(ident("t1"));
    grant(&hub, sess, &["*://*.api.test/*"]).await;
    let (other, _osid, mut orx) = hub.open(ident("t2"));
    let h = hub
        .dispatch(
            sess,
            json!({"op": "xhr", "url": "https://api.test/x"}),
            "default",
            &f.id,
            "hit.test",
            None,
        )
        .await
        .unwrap();
    let Some(ExtOut::Binary(b)) = rx.recv().await else {
        panic!("job frame")
    };
    let (t, job, payload) = parse_job_frame(&b).unwrap();
    assert_eq!(t, F_JOB);
    let meta: serde_json::Value = serde_json::from_slice(payload).unwrap();
    assert_eq!(meta["hasBody"], false);
    let relay = meta["relay"].as_str().unwrap().to_string();
    assert!(orx.try_recv().is_err(), "the other session got nothing");

    // each hop is judged against the stored @connect
    let ok = url::Url::parse("https://api.test/y").unwrap();
    let denied = url::Url::parse("https://evil.test/y").unwrap();
    assert!(hub.check_relay(&relay, &ok, Some(sess), ""));
    assert!(!hub.check_relay(&relay, &denied, Some(sess), ""));
    assert!(!hub.check_relay("nope", &ok, Some(sess), ""));

    // answers of the session's own job arrive; the other session cannot answer it
    hub.on_binary(other, &job_frame(F_HEAD, job, b"{\"status\":200}"))
        .await;
    hub.on_binary(sess, &job_frame(F_HEAD, job, b"{\"status\":200}"))
        .await;
    hub.on_binary(sess, &job_frame(F_DATA, job, b"hi")).await;
    let mut h = h;
    assert!(matches!(h.rx.recv().await, Some(JobEvent::Head(_))));
    assert!(matches!(h.rx.recv().await, Some(JobEvent::Data(d)) if &d[..] == b"hi"));

    // dropping the handle (the page aborted) cancels the job and retires the relay token
    drop(h);
    let Some(ExtOut::Binary(c)) = rx.recv().await else {
        panic!("cancel frame")
    };
    let (t, j, _) = parse_job_frame(&c).unwrap();
    assert_eq!((t, j), (F_CANCEL, job));
    assert!(
        !hub.check_relay(&relay, &ok, Some(sess), ""),
        "relay token retired"
    );
    assert!(orx.try_recv().is_err());
}

#[tokio::test]
async fn relay_stops_when_the_flag_is_withdrawn_or_the_script_removed() {
    let f = fx(true);
    let hub = f.gm.ext().clone();
    let (sess, _sid, mut rx) = hub.open(ident("t1"));
    grant(&hub, sess, &["*://*.api.test/*"]).await;
    let _h = hub
        .dispatch(
            sess,
            json!({"op": "xhr"}),
            "default",
            &f.id,
            "hit.test",
            None,
        )
        .await
        .unwrap();
    let Some(ExtOut::Binary(b)) = rx.recv().await else {
        panic!()
    };
    let relay = serde_json::from_slice::<serde_json::Value>(parse_job_frame(&b).unwrap().2)
        .unwrap()["relay"]
        .as_str()
        .unwrap()
        .to_string();
    let u = url::Url::parse("https://api.test/").unwrap();
    assert!(hub.check_relay(&relay, &u, Some(sess), ""));
    let mut s = f.m.index_for("default").get(&f.id).unwrap().script.clone();
    s.browser_cookies = false;
    f.m.replace_script("default", s).unwrap();
    assert!(
        !hub.check_relay(&relay, &u, Some(sess), ""),
        "flag off: hops are refused"
    );
}

#[test]
fn the_relay_header_is_removed_whatever_its_number_and_no_session_header_exists() {
    let mut h = hyper::HeaderMap::new();
    h.append(RELAY_HEADER, "r1".parse().unwrap());
    h.append(RELAY_HEADER, "r2".parse().unwrap());
    h.append("accept", "x".parse().unwrap());
    assert_eq!(take_headers(&mut h).as_deref(), Some("r1"));
    assert!(h.get(RELAY_HEADER).is_none());
    assert_eq!(h.len(), 1);
}

fn entry(pattern: &str) -> Entry {
    Entry {
        id: pattern.into(),
        pattern: pattern.into(),
        mode: BypassMode::NoDecrypt,
        source: "custom".into(),
        note: None,
        updated_at: 0,
    }
}

// ---- menus ---------------------------------------------------------------------------------

fn gm_token(f: &Fx, profile: &str, origin: &str) -> String {
    let s = f.m.index_for(profile).get(&f.id).unwrap().script.clone();
    let caps = token::caps_hash(&s.metadata, s.allow_connect_all);
    token::mint(
        f.m.token_key(),
        &TokenClaims {
            profile,
            script_id: &s.id,
            script_version: "1.0",
            origin,
            caps_hash: &caps,
            exp: u64::MAX / 2,
        },
    )
}

fn sync(f: &Fx, mdoc: &str, cmds: serde_json::Value) -> (u16, serde_json::Value) {
    let c = Caller {
        manager: &f.m,
        host: "hit.test",
        origin: ORIGIN,
        profile: "default",
    };
    f.gm.json_call(
        &f.m,
        &c,
        "menu/sync",
        Some(&gm_token(f, "default", ORIGIN)),
        json!({"mdoc": mdoc, "cmds": cmds}).to_string().as_bytes(),
    )
}

fn cmd(id: &str) -> serde_json::Value {
    json!({"id": id, "name": format!("Name {id}"), "accessKey": "a", "title": "tip", "autoClose": false})
}

#[tokio::test]
async fn menu_sync_list_trigger_and_wait_are_bound_to_the_session() {
    let f = fx(true);
    let hub = f.gm.ext().clone();
    let (sess, sid, _rx) = hub.open(ident("t1"));
    let (other, _osid, _orx) = hub.open(ident("t2"));
    let plan = plan_for(&f, hub.authenticate(&sid));

    // sync needs the GM token; the answer says a live session serves the document
    let (st, body) = sync(
        &f,
        plan.mdoc.as_ref().unwrap(),
        json!([cmd("a1"), cmd("b1")]),
    );
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["result"]["ext"], true);
    // an unknown document, or a foreign one, is refused
    assert_eq!(sync(&f, "nope", json!([])).0, 404);
    let c = Caller {
        manager: &f.m,
        host: "hit.test",
        origin: "https://other.test",
        profile: "default",
    };
    let (st, _) = f.gm.json_call(
        &f.m,
        &c,
        "menu/sync",
        Some(&gm_token(&f, "default", "https://other.test")),
        json!({"mdoc": plan.mdoc.clone().unwrap(), "cmds": []})
            .to_string()
            .as_bytes(),
    );
    assert_eq!(st, 404, "another origin cannot touch the document's menu");
    // too many commands
    let many: Vec<_> = (0..65).map(|i| cmd(&format!("c{i}"))).collect();
    assert_eq!(sync(&f, plan.mdoc.as_ref().unwrap(), json!(many)).0, 413);

    // the popup of the bound session lists them
    let m = hub.menu(sess, "", plan.mdoc.as_ref().unwrap()).unwrap();
    assert_eq!(m.commands.len(), 2);
    assert_eq!(m.commands[0].cmd, "a1");
    assert!(!m.commands[0].auto_close);
    // another session, or an unknown document, does not
    assert_eq!(
        hub.menu(other, "", plan.mdoc.as_ref().unwrap()),
        Err(ExtError::Forbidden)
    );
    assert_eq!(hub.menu(sess, "", "zz"), Err(ExtError::NotFound));
    // trigger: refused for the wrong session, for unknown commands; queued otherwise
    let req = |cmd: &str| ExtTriggerRequest {
        mdoc: plan.mdoc.clone().unwrap(),
        script: f.id.clone(),
        cmd: cmd.into(),
    };
    assert_eq!(hub.trigger(other, "", &req("a1")), Err(ExtError::Forbidden));
    assert_eq!(hub.trigger(sess, "", &req("zzz")), Err(ExtError::NotFound));
    assert_eq!(
        hub.trigger(sess, "", &req("a1")),
        Ok(false),
        "nobody is waiting yet"
    );

    // the page's poll picks the queued command up at once
    let w = hub
        .menu_wait(
            "default",
            ORIGIN,
            &f.id,
            plan.mdoc.as_ref().unwrap(),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(w, Wait::Fire(vec!["a1".into()]));
    // a parked poll is woken by a trigger and reports delivery
    let h2 = hub.clone();
    let (id, mdoc) = (f.id.clone(), plan.mdoc.clone().unwrap());
    let parked = tokio::spawn(async move {
        h2.menu_wait("default", ORIGIN, &id, &mdoc, Duration::from_secs(5))
            .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(hub.trigger(sess, "", &req("b1")), Ok(true));
    assert_eq!(
        parked.await.unwrap().unwrap(),
        Wait::Fire(vec!["b1".into()])
    );
    // an idle poll ends empty
    let w = hub
        .menu_wait(
            "default",
            ORIGIN,
            &f.id,
            plan.mdoc.as_ref().unwrap(),
            Duration::from_millis(30),
        )
        .await
        .unwrap();
    assert_eq!(w, Wait::Fire(vec![]));
    // the session ends: the poll tells the runtime to mount its own button
    hub.close(sess);
    let w = hub
        .menu_wait(
            "default",
            ORIGIN,
            &f.id,
            plan.mdoc.as_ref().unwrap(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
    assert_eq!(w, Wait::NoExt);
    assert_eq!(
        hub.menu(sess, "", plan.mdoc.as_ref().unwrap()),
        Err(ExtError::Forbidden)
    );
}

#[tokio::test]
async fn an_unbound_page_leaves_no_record_and_cannot_evict_bound_ones() {
    let f = fx(true);
    let hub = f.gm.ext().clone();
    let (sess, sid, _rx) = hub.open(ident("t1"));
    let bound = plan_for(&f, hub.authenticate(&sid));
    let mdoc = bound.mdoc.clone().unwrap();
    for _ in 0..2000 {
        let p = plan_for(&f, None);
        assert!(
            p.mdoc.is_none() && !p.ext_bound,
            "no id, no Server-Timing value"
        );
    }
    assert!(
        hub.menu(sess, "", &mdoc).is_ok(),
        "the bound document survives unbound traffic"
    );
    // an unknown id (what an unbound page would have) is simply unknown
    let (st, _) = sync(&f, "deadbeefdeadbeefdeadbeefdeadbeef", json!([]));
    assert_eq!(st, 404);
}

#[tokio::test]
async fn each_session_evicts_only_its_own_oldest_documents() {
    let f = fx(true);
    let hub = f.gm.ext().clone();
    let (a, _asid, _arx) = hub.open(ident("ta"));
    let (b, _bsid, _brx) = hub.open(ident("tb"));
    let first_b = plan_for(&f, Some(b)).mdoc.unwrap();
    let first_a = plan_for(&f, Some(a)).mdoc.unwrap();
    for _ in 0..proxy_core::ext_bridge::MENU_DOCS_PER_SESSION + 5 {
        plan_for(&f, Some(a));
    }
    assert_eq!(
        hub.menu(a, "", &first_a),
        Err(ExtError::NotFound),
        "A's oldest was evicted"
    );
    assert!(
        hub.menu(b, "", &first_b).is_ok(),
        "B's document was not touched by A's traffic"
    );
}

#[tokio::test]
async fn grants_list_hosts_the_extension_lacks_permission_for() {
    let f = fx(true);
    let hub = f.gm.ext().clone();
    let (sess, sid, _rx) = hub.open(ident("t1"));
    let plan = plan_for(&f, hub.authenticate(&sid));
    let m = hub.menu(sess, "", plan.mdoc.as_ref().unwrap()).unwrap();
    assert_eq!(m.grants.len(), 1);
    assert_eq!(m.grants[0].host, "api.test");
    assert_eq!(m.grants[0].patterns, vec!["*://*.api.test/*".to_string()]);
    grant(&hub, sess, &["*://*.api.test/*"]).await;
    assert!(hub
        .menu(sess, "", plan.mdoc.as_ref().unwrap())
        .unwrap()
        .grants
        .is_empty());
}

#[tokio::test]
async fn a_finished_job_is_not_cancelled_when_its_handle_drops() {
    let f = fx(true);
    let hub = f.gm.ext().clone();
    let (sess, _sid, mut rx) = hub.open(ident("t1"));
    let mut h = hub
        .dispatch(
            sess,
            json!({"op": "xhr"}),
            "default",
            &f.id,
            "hit.test",
            None,
        )
        .await
        .unwrap();
    let Some(ExtOut::Binary(b)) = rx.recv().await else {
        panic!()
    };
    let job = parse_job_frame(&b).unwrap().1;
    hub.on_binary(sess, &job_frame(F_END, job, b"")).await;
    assert!(matches!(h.rx.recv().await, Some(JobEvent::End)));
    drop(h);
    tokio::task::yield_now().await;
    assert!(rx.try_recv().is_err(), "no cancel after a normal end");
}

#[tokio::test]
async fn closing_a_session_fails_its_jobs() {
    let f = fx(true);
    let hub = f.gm.ext().clone();
    let (sess, _sid, _rx) = hub.open(ident("t1"));
    let mut h = hub
        .dispatch(
            sess,
            json!({"op": "xhr"}),
            "default",
            &f.id,
            "hit.test",
            None,
        )
        .await
        .unwrap();
    hub.close(sess);
    assert!(matches!(h.rx.recv().await, Some(JobEvent::Error(_))));
}

// ---- slow readers, revocation, permissions, routing ----------------------------------------

async fn job(
    hub: &Arc<ExtHub>,
    sess: u64,
    f: &Fx,
    rx: &mut tokio::sync::mpsc::Receiver<ExtOut>,
) -> (proxy_core::ext_bridge::JobHandle, u32) {
    let (h, j, _) = job3(hub, sess, f, rx).await;
    (h, j)
}

async fn job3(
    hub: &Arc<ExtHub>,
    sess: u64,
    f: &Fx,
    rx: &mut tokio::sync::mpsc::Receiver<ExtOut>,
) -> (proxy_core::ext_bridge::JobHandle, u32, String) {
    let h = hub
        .dispatch(
            sess,
            json!({"op": "xhr", "url": "https://api.test/x"}),
            "default",
            &f.id,
            "hit.test",
            None,
        )
        .await
        .unwrap();
    let Some(ExtOut::Binary(b)) = rx.recv().await else {
        panic!("job frame")
    };
    let (_, j, payload) = parse_job_frame(&b).unwrap();
    let relay = serde_json::from_slice::<serde_json::Value>(payload).unwrap()["relay"]
        .as_str()
        .unwrap()
        .to_string();
    (h, j, relay)
}

#[tokio::test]
async fn a_stalled_reader_fails_its_own_job_and_blocks_nothing_else() {
    let f = fx(true);
    let hub = f.gm.ext().clone();
    let (sess, _sid, mut rx) = hub.open(ident("t"));
    let (mut a, ja) = job(&hub, sess, &f, &mut rx).await;
    let (mut b, jb) = job(&hub, sess, &f, &mut rx).await;
    // A's page never reads: far more chunks than its queue holds. Nothing may wait.
    let flood = async {
        hub.on_binary(sess, &job_frame(F_HEAD, ja, b"{\"status\":200}"))
            .await;
        for _ in 0..200 {
            hub.on_binary(sess, &job_frame(F_DATA, ja, &[7u8; 1024]))
                .await;
        }
        hub.on_binary(sess, &job_frame(F_END, ja, &[])).await;
    };
    tokio::time::timeout(Duration::from_secs(2), flood)
        .await
        .expect("the reader never waits");
    // pongs and B are served meanwhile
    hub.on_text(sess, r#"{"t":"ping"}"#).await;
    hub.on_binary(sess, &job_frame(F_HEAD, jb, b"{\"status\":200}"))
        .await;
    hub.on_binary(sess, &job_frame(F_END, jb, &[])).await;
    assert!(matches!(b.rx.recv().await, Some(JobEvent::Head(_))));
    assert!(matches!(b.rx.recv().await, Some(JobEvent::End)));
    let mut saw_pong = false;
    let mut cancel_a = false;
    while let Ok(o) = rx.try_recv() {
        match o {
            ExtOut::Text(t) if t.contains("pong") => saw_pong = true,
            ExtOut::Binary(x) => {
                let (t, j, _) = parse_job_frame(&x).unwrap();
                cancel_a |= t == F_CANCEL && j == ja;
            }
            _ => {}
        }
    }
    assert!(saw_pong, "the pong was queued");
    assert!(cancel_a, "the extension was told to cancel the stalled job");
    // A: what was queued, then the queue ends WITHOUT an End, and the handle says why
    let mut n = 0;
    while let Some(ev) = a.rx.recv().await {
        assert!(
            !matches!(ev, JobEvent::End),
            "a truncated body must never end normally"
        );
        n += 1;
    }
    assert!(n > 0 && n < 200 && a.overflowed());
    assert!(!b.overflowed());
}

#[tokio::test]
async fn close_token_closes_every_live_session_of_that_token_only() {
    let f = fx(true);
    let hub = f.gm.ext().clone();
    let (s1, _a, mut rx1) = hub.open(ident("tok"));
    let (s2, _b, mut rx2) = hub.open(ident("tok"));
    let (s3, _c, mut rx3) = hub.open(ident("other"));
    hub.close_token("tok");
    assert!(!hub.is_live(s1) && !hub.is_live(s2) && hub.is_live(s3));
    for rx in [&mut rx1, &mut rx2] {
        assert!(matches!(rx.recv().await, Some(ExtOut::Close(4401))));
    }
    assert!(rx3.try_recv().is_err());
}

#[test]
fn broad_permissions_never_give_relay_authority() {
    let p = Perms::from_origins(&[
        "<all_urls>".into(),
        "*://*/*".into(),
        "https://*/*".into(),
        "http://*/*".into(),
        "*://*.com/*".into(),
        "*://*.co.uk/*".into(),
        "https://*.api.test/*".into(),
        "https://one.test/*".into(),
    ]);
    assert!(!p.has("anything.test") && !p.has("a.com") && !p.has("x.co.uk"));
    assert!(p.has("v1.api.test") && p.has("api.test") && p.has("one.test"));
    assert!(
        !p.has("two.one.test"),
        "an exact host grant does not cover subdomains"
    );
}

#[test]
fn public_suffixes_are_never_offered_as_grants() {
    let g = grant_patterns(
        &[
            "com".into(),
            "co.uk".into(),
            "*.org".into(),
            "api.test".into(),
        ],
        "p.test",
    );
    assert_eq!(g.len(), 1);
    assert_eq!(g[0].0, "api.test");
}

#[tokio::test]
async fn the_browser_is_not_used_for_bypassed_local_or_manual_redirect_targets() {
    let f = fx(true);
    let s = f.m.index_for("default").get(&f.id).unwrap().script.clone();
    let hub = f.gm.ext().clone();
    let (sess, sid, _rx) = hub.open(ident("t"));
    grant(&hub, sess, &["*://*.api.test/*", "*://*.bank.test/*"]).await;
    let plan = plan_for(&f, hub.authenticate(&sid));
    let m = plan.mdoc.as_deref();
    assert_eq!(route(&f, &s, m, false, "api.test"), Route::Ext(sess));
    for h in [
        "127.0.0.1",
        "10.1.2.3",
        "192.168.0.9",
        "169.254.169.254",
        "[::1]",
        "localhost",
        "fd00::1",
        "100.64.0.1",
    ] {
        assert_eq!(
            route(&f, &s, m, false, h),
            Route::Jar(Fallback::LocalTarget),
            "{h}"
        );
    }
    f.bypass
        .update(|s| {
            s.entries.push(entry("bank.test"));
            Ok(())
        })
        .unwrap();
    assert_eq!(
        route(&f, &s, m, false, "bank.test"),
        Route::Jar(Fallback::Bypassed)
    );
    assert_eq!(
        f.gm.credentialed_route(&s, "default", ORIGIN, false, false, true, m, "api.test"),
        Route::Jar(Fallback::ManualRedirect)
    );
}

#[tokio::test]
async fn relay_hops_need_the_sessions_permission_and_a_decrypted_public_host() {
    let f = fx(true);
    let hub = f.gm.ext().clone();
    let (sess, _sid, mut rx) = hub.open(ident("t"));
    let (_h, _j, relay) = job3(&hub, sess, &f, &mut rx).await;
    let ok = url::Url::parse("https://api.test/y").unwrap();
    assert!(
        !hub.check_relay(&relay, &ok, Some(sess), ""),
        "no host permission held yet"
    );
    grant(&hub, sess, &["*://*.api.test/*"]).await;
    assert!(hub.check_relay(&relay, &ok, Some(sess), ""));
    grant(&hub, sess, &["<all_urls>", "*://*.api.test/*"]).await;
    for u in [
        "https://127.0.0.1/",
        "https://10.0.0.1/",
        "https://[::1]/",
        "https://localhost/",
    ] {
        assert!(
            !hub.check_relay(&relay, &url::Url::parse(u).unwrap(), Some(sess), ""),
            "{u}"
        );
    }
    f.bypass
        .update(|s| {
            s.entries.push(entry("api.test"));
            Ok(())
        })
        .unwrap();
    assert!(
        !hub.check_relay(&relay, &ok, Some(sess), ""),
        "a bypassed host cannot be checked, so it is refused"
    );
}

#[tokio::test]
async fn relay_hops_must_come_from_the_jobs_own_default_store_connection() {
    let f = fx(true);
    let hub = f.gm.ext().clone();
    let (sess, _sid, mut rx) = hub.open(ident("t"));
    let (other, _s2, _rx2) = hub.open(ident("t2"));
    grant(&hub, sess, &["*://*.api.test/*"]).await;
    let (_h, _j, relay) = job3(&hub, sess, &f, &mut rx).await;
    let ok = url::Url::parse("https://api.test/y").unwrap();
    assert!(hub.check_relay(&relay, &ok, Some(sess), ""));
    assert!(
        !hub.check_relay(&relay, &ok, None, ""),
        "no authenticated connection"
    );
    assert!(
        !hub.check_relay(&relay, &ok, Some(other), ""),
        "another session"
    );
    assert!(
        !hub.check_relay(&relay, &ok, Some(sess), "c1x"),
        "a container store"
    );
}

#[tokio::test]
async fn documents_and_menus_are_scoped_to_the_cookie_store() {
    let f = fx(true);
    let s = f.m.index_for("default").get(&f.id).unwrap().script.clone();
    let hub = f.gm.ext().clone();
    let (sess, _sid, _rx) = hub.open(ident("t"));
    grant(&hub, sess, &["*://*.api.test/*"]).await;
    let def = plan_in(&f, Some(sess), "");
    let boxed = plan_in(&f, Some(sess), "c1x");
    let (dm, bm) = (def.mdoc.clone().unwrap(), boxed.mdoc.clone().unwrap());
    assert!(hub.menu(sess, "", &dm).is_ok() && hub.menu(sess, "c1x", &bm).is_ok());
    assert_eq!(hub.menu(sess, "c1x", &dm), Err(ExtError::Forbidden));
    assert_eq!(hub.menu(sess, "", &bm), Err(ExtError::Forbidden));
    assert_eq!(hub.menu(sess, "zzz", &bm), Err(ExtError::Forbidden));
    let req = |m: &str| ExtTriggerRequest {
        mdoc: m.into(),
        script: f.id.clone(),
        cmd: "x".into(),
    };
    assert_eq!(hub.trigger(sess, "", &req(&bm)), Err(ExtError::Forbidden));
    assert_eq!(
        route(&f, &s, def.mdoc.as_deref(), false, "api.test"),
        Route::Ext(sess)
    );
    // a container's document is relayed too (with that store's cookies, by the extension) and
    // the job names the store token
    assert_eq!(
        route(&f, &s, boxed.mdoc.as_deref(), false, "api.test"),
        Route::Ext(sess)
    );
    assert_eq!(hub.doc_store(boxed.mdoc.as_deref()), "c1x");
    assert_eq!(hub.doc_store(def.mdoc.as_deref()), "");
    assert_eq!(hub.doc_store(None), "");
}

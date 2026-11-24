//! The extension bridge hub: session binding, routing of credentialed calls, menus, jobs.
//! Every test builds its own hub, manager and temp dir (nothing shared).

use api_types::{ExtError, ExtIdent, ExtOut, ExtTriggerRequest};
use common::bypass::{BypassEngine, BypassMode, Entry};
use proxy_core::ext_bridge::{
    build_hosts, job_frame, parse_job_frame, take_headers, ExtHub, Fallback, HubCtx, JobEvent,
    Route, Wait, F_CANCEL, F_DATA, F_END, F_HEAD, F_JOB, RELAY_HEADER, SESSION_HEADER,
};
use proxy_core::gm::{Caller, GmHost};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use userscript_engine::install::{finish_install, plan_install, Approvals, Fetched};
use userscript_engine::token::{self, TokenClaims};
use userscript_engine::{HostPolicy, Userscript, UserscriptManager};

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
    let idx = f.m.index_for("default").clone();
    f.gm.plan_document_bound(
        &idx,
        "default",
        "hit.test",
        "https://hit.test/",
        ORIGIN,
        true,
        session,
    )
    .unwrap()
}

fn route(f: &Fx, s: &Userscript, mdoc: Option<&str>, anonymous: bool, host: &str) -> Route {
    f.gm.credentialed_route(s, "default", ORIGIN, anonymous, false, mdoc, host)
}

#[tokio::test]
async fn routing_matrix_only_a_fully_matching_call_reaches_the_browser() {
    let f = fx(true);
    let s = f.m.index_for("default").get(&f.id).unwrap().script.clone();
    let hub = f.gm.ext().clone();
    let (sess, sid, _rx) = hub.open(ident("t1"));
    grant(&hub, sess, &["*://*.api.test/*"]).await;

    // all match -> the session bound by the `sid` the browser sent
    let bound = hub.bind(&sid, "default").expect("known sid binds");
    assert_eq!(bound, sess);
    let plan = plan_for(&f, Some(bound));
    assert!(plan.ext_bound);
    assert_eq!(
        route(&f, &s, Some(&plan.mdoc), false, "api.test"),
        Route::Ext(sess)
    );
    assert_eq!(
        route(&f, &s, Some(&plan.mdoc), false, "v1.api.test"),
        Route::Ext(sess),
        "a *.host permission covers subdomains"
    );

    // sid mismatch / unknown sid: no binding at all, and the document stays unbound
    assert_eq!(
        hub.bind("0123456789abcdef0123456789abcdef", "default"),
        None
    );
    assert_eq!(hub.bind("", "default"), None);
    assert_eq!(hub.bind(&sid[..sid.len() - 1], "default"), None);
    let unbound = plan_for(&f, None);
    assert!(!unbound.ext_bound);
    assert_eq!(
        route(&f, &s, Some(&unbound.mdoc), false, "api.test"),
        Route::Jar(Fallback::Unbound)
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
        route(&f, &s, Some(&plan.mdoc), false, "other.test"),
        Route::Jar(Fallback::NoPermission)
    );
    // anonymous requests are never relayed; neither is a script without the approval flag
    assert_eq!(
        route(&f, &s, Some(&plan.mdoc), true, "api.test"),
        Route::Jar(Fallback::Anonymous)
    );
    let mut off = s.clone();
    off.browser_cookies = false;
    assert_eq!(
        route(&f, &off, Some(&plan.mdoc), false, "api.test"),
        Route::Jar(Fallback::NotApproved)
    );
    // the document of another profile or origin cannot be claimed
    assert_eq!(
        f.gm.credentialed_route(&s, "p9", ORIGIN, false, false, Some(&plan.mdoc), "api.test"),
        Route::Jar(Fallback::NoDocument)
    );
    assert_eq!(
        f.gm.credentialed_route(
            &s,
            "default",
            "https://evil.test",
            false,
            false,
            Some(&plan.mdoc),
            "api.test"
        ),
        Route::Jar(Fallback::NoDocument)
    );
    // a second session (another browser) never receives this document's jobs
    let (other, _osid, _orx) = hub.open(ident("t2"));
    grant(&hub, other, &["<all_urls>"]).await;
    assert_eq!(
        route(&f, &s, Some(&plan.mdoc), false, "api.test"),
        Route::Ext(sess)
    );
    // the session goes away: the warning is recorded and calls fall back
    hub.close(sess);
    assert_eq!(
        route(&f, &s, Some(&plan.mdoc), false, "api.test"),
        Route::Jar(Fallback::Dead)
    );
    assert!(hub.browser_fallback("default", &f.id));
}

#[tokio::test]
async fn a_token_profile_restriction_limits_what_a_session_can_bind() {
    let f = fx(true);
    let hub = f.gm.ext();
    let (_s, sid, _rx) = hub.open(ExtIdent {
        token_id: "t".into(),
        user: "u".into(),
        profiles: Some(vec!["3".into()]),
    });
    assert_eq!(hub.bind(&sid, "default"), None);
    assert!(hub.bind(&sid, "p3").is_some());
    // a new connection gets a new secret
    let (_s2, sid2, _rx2) = hub.open(ident("t"));
    assert_ne!(sid, sid2);
}

#[tokio::test]
async fn jobs_go_to_one_session_are_cancelled_on_drop_and_recheck_hops() {
    let f = fx(true);
    let hub = f.gm.ext().clone();
    let (sess, _sid, mut rx) = hub.open(ident("t1"));
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
    assert!(hub.check_relay(&relay, &ok));
    assert!(!hub.check_relay(&relay, &denied));
    assert!(!hub.check_relay("nope", &ok));

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
    assert!(!hub.check_relay(&relay, &ok), "relay token retired");
    assert!(orx.try_recv().is_err());
}

#[tokio::test]
async fn relay_stops_when_the_flag_is_withdrawn_or_the_script_removed() {
    let f = fx(true);
    let hub = f.gm.ext().clone();
    let (sess, _sid, mut rx) = hub.open(ident("t1"));
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
    assert!(hub.check_relay(&relay, &u));
    let mut s = f.m.index_for("default").get(&f.id).unwrap().script.clone();
    s.browser_cookies = false;
    f.m.replace_script("default", s).unwrap();
    assert!(!hub.check_relay(&relay, &u), "flag off: hops are refused");
}

#[test]
fn both_bridge_headers_are_removed_whatever_their_number() {
    let mut h = hyper::HeaderMap::new();
    h.append(SESSION_HEADER, "sid1".parse().unwrap());
    h.append(SESSION_HEADER, "sid2".parse().unwrap());
    h.append(RELAY_HEADER, "r1".parse().unwrap());
    h.append("accept", "x".parse().unwrap());
    let (sid, relay) = take_headers(&mut h);
    assert_eq!(sid.as_deref(), Some("sid1"));
    assert_eq!(relay.as_deref(), Some("r1"));
    assert!(h.get(SESSION_HEADER).is_none() && h.get(RELAY_HEADER).is_none());
    assert_eq!(h.len(), 1);
}

#[test]
fn the_host_list_leaves_out_passthrough_hosts() {
    let pol = HostPolicy {
        any: false,
        exact: vec!["a.test".into(), "bank.test".into()],
        suffix: vec!["shop.test".into()],
    };
    let pass = vec!["bank.test".to_string(), "pay.shop.test".to_string()];
    let m = build_hosts(&pol, &pass);
    assert!(!m.wildcard);
    assert_eq!(m.hosts, vec!["a.test".to_string(), "shop.test".to_string()]);
    assert_eq!(
        m.exclude,
        vec!["pay.shop.test".to_string()],
        "a passthrough host below a listed one is excluded explicitly"
    );
    // a broad script: every host except the passthrough ones
    let wild = build_hosts(
        &HostPolicy {
            any: true,
            ..Default::default()
        },
        &pass,
    );
    assert!(wild.wildcard && wild.hosts.is_empty());
    assert_eq!(wild.exclude, pass);
    // nothing to tag: an empty (fail-safe) list
    assert!(build_hosts(&HostPolicy::default(), &pass).hosts.is_empty());
}

#[tokio::test]
async fn the_pushed_host_list_follows_scripts_and_bypass_entries() {
    let f = fx(true);
    let bypass = f.bypass.clone();
    // a second script on a host Argus passes through
    let bank = script_src("")
        .replace("*://hit.test/*", "*://bank.test/*")
        .replace("@name n", "@name bank");
    f.m.install_script(
        "default",
        finish_install(
            plan_install(&bank, None).unwrap(),
            Fetched::default(),
            Approvals::default(),
        )
        .unwrap(),
    )
    .unwrap();
    bypass
        .update(|s| {
            s.entries.push(Entry {
                id: "e1".into(),
                pattern: "bank.test".into(),
                mode: BypassMode::NoDecrypt,
                source: "custom".into(),
                note: None,
                updated_at: 0,
            });
            Ok(())
        })
        .unwrap();
    let hub = f.gm.ext().clone();
    let (sess, _sid, _rx) = hub.open(ident("t"));
    let msg = hub.hosts_for(sess).unwrap();
    assert_eq!(
        msg.hosts,
        vec!["hit.test".to_string()],
        "bank.test is passed through"
    );
    assert!(!msg.wildcard);
    // pushing sends the list as a text frame, then nothing until it changes
    let (sess2, _s2, mut rx2) = hub.open(ident("t"));
    hub.push_hosts(sess2, false).await;
    let Some(ExtOut::Text(t)) = rx2.recv().await else {
        panic!("hosts frame")
    };
    let v: serde_json::Value = serde_json::from_str(&t).unwrap();
    assert_eq!(v["t"], "hosts");
    assert_eq!(v["hosts"], json!(["hit.test"]));
    hub.push_hosts(sess2, false).await;
    assert!(rx2.try_recv().is_err());
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
    let plan = plan_for(&f, hub.bind(&sid, "default"));

    // sync needs the GM token; the answer says a live session serves the document
    let (st, body) = sync(&f, &plan.mdoc, json!([cmd("a1"), cmd("b1")]));
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
        json!({"mdoc": plan.mdoc, "cmds": []})
            .to_string()
            .as_bytes(),
    );
    assert_eq!(st, 404, "another origin cannot touch the document's menu");
    // too many commands
    let many: Vec<_> = (0..65).map(|i| cmd(&format!("c{i}"))).collect();
    assert_eq!(sync(&f, &plan.mdoc, json!(many)).0, 413);

    // the popup of the bound session lists them
    let m = hub.menu(sess, &plan.mdoc).unwrap();
    assert_eq!(m.commands.len(), 2);
    assert_eq!(m.commands[0].cmd, "a1");
    assert!(!m.commands[0].auto_close);
    // another session, or an unknown document, does not
    assert_eq!(hub.menu(other, &plan.mdoc), Err(ExtError::Forbidden));
    assert_eq!(hub.menu(sess, "zz"), Err(ExtError::NotFound));
    // trigger: refused for the wrong session, for unknown commands; queued otherwise
    let req = |cmd: &str| ExtTriggerRequest {
        mdoc: plan.mdoc.clone(),
        script: f.id.clone(),
        cmd: cmd.into(),
    };
    assert_eq!(hub.trigger(other, &req("a1")), Err(ExtError::Forbidden));
    assert_eq!(hub.trigger(sess, &req("zzz")), Err(ExtError::NotFound));
    assert_eq!(
        hub.trigger(sess, &req("a1")),
        Ok(false),
        "nobody is waiting yet"
    );

    // the page's poll picks the queued command up at once
    let w = hub
        .menu_wait("default", ORIGIN, &f.id, &plan.mdoc, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(w, Wait::Fire(vec!["a1".into()]));
    // a parked poll is woken by a trigger and reports delivery
    let h2 = hub.clone();
    let (id, mdoc) = (f.id.clone(), plan.mdoc.clone());
    let parked = tokio::spawn(async move {
        h2.menu_wait("default", ORIGIN, &id, &mdoc, Duration::from_secs(5))
            .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(hub.trigger(sess, &req("b1")), Ok(true));
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
            &plan.mdoc,
            Duration::from_millis(30),
        )
        .await
        .unwrap();
    assert_eq!(w, Wait::Fire(vec![]));
    // the session ends: the poll tells the runtime to mount its own button
    hub.close(sess);
    let w = hub
        .menu_wait("default", ORIGIN, &f.id, &plan.mdoc, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(w, Wait::NoExt);
    assert_eq!(hub.menu(sess, &plan.mdoc), Err(ExtError::Forbidden));
}

#[tokio::test]
async fn an_unbound_document_syncs_with_ext_false() {
    let f = fx(true);
    let plan = plan_for(&f, None);
    let (st, body) = sync(&f, &plan.mdoc, json!([cmd("a1")]));
    assert_eq!(st, 200);
    assert_eq!(body["result"]["ext"], false);
    let w =
        f.gm.ext()
            .menu_wait("default", ORIGIN, &f.id, &plan.mdoc, Duration::from_secs(1))
            .await
            .unwrap();
    assert_eq!(w, Wait::NoExt);
}

#[tokio::test]
async fn grants_list_hosts_the_extension_lacks_permission_for() {
    let f = fx(true);
    let hub = f.gm.ext().clone();
    let (sess, sid, _rx) = hub.open(ident("t1"));
    let plan = plan_for(&f, hub.bind(&sid, "default"));
    let m = hub.menu(sess, &plan.mdoc).unwrap();
    assert_eq!(m.grants.len(), 1);
    assert_eq!(m.grants[0].host, "api.test");
    assert_eq!(m.grants[0].patterns, vec!["*://*.api.test/*".to_string()]);
    grant(&hub, sess, &["*://*.api.test/*"]).await;
    assert!(hub.menu(sess, &plan.mdoc).unwrap().grants.is_empty());
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

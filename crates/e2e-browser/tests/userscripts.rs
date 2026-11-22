//! Userscripts in real Chromium through the production proxy: delivery order, matching, the GM
//! API, strict CSP, and what a hostile page can and cannot do.

use std::sync::Arc;

use e2e_browser::{eval_on, run_known, MockResponse, Session};
use serde_json::{json, Value};
use userscript_engine::install::Fetched;
use userscript_engine::storage::ns;

/// Declare a scenario: `$s` is an explicit-mode [`Session`] (skipped without a browser).
macro_rules! us_test {
    ($name:ident, |$s:ident| $body:block) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() {
            let Some($s) = Session::start(&[]).await else {
                return;
            };
            run_known(stringify!($name), async move {
                $body
                $s.finish().await;
            })
            .await;
        }
    };
}

fn script(name: &str, extra: &str, body: &str) -> String {
    format!(
        "// ==UserScript==\n// @name {name}\n// @namespace us\n// @version 1.0\n// @match *://us.test/*\n{extra}\n// ==/UserScript==\n{body}\n"
    )
}

fn page(head: &str, body: &str) -> String {
    format!("<!doctype html><html><head><meta charset=utf-8><title>t</title>{head}</head><body>{body}</body></html>")
}

fn html(s: &Session, path: &str, doc: String) {
    s.origin.route(path, MockResponse::html(doc));
}

/// Wait until the script's stored value for `name` equals `want`.
async fn wait_stored(s: &Session, id: &str, name: &str, want: Value) {
    let m = s.proxy.userscripts();
    for _ in 0..400 {
        if m.storage().get_raw(&ns("default", id), name).unwrap() == Some(want.clone()) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!(
        "stored {name} never became {want}: {:?}\n{}",
        m.storage().get_raw(&ns("default", id), name),
        s.dump()
    );
}

us_test!(document_start_runs_before_the_first_page_script, |s| {
    s.proxy.install_userscript(&script(
        "early",
        "// @run-at document-start\n// @grant none",
        "window.__early = 'yes';",
    ));
    html(
        &s,
        "/",
        page("<script>window.__seen = window.__early;</script>", "x"),
    );
    s.goto(&s.url("us.test", "/")).await;
    assert_eq!(s.eval("window.__seen").await, "yes");
    s.assert_clean().await;
});

us_test!(run_at_stages_are_ordered, |s| {
    for st in ["start", "body", "end", "idle"] {
        s.proxy.install_userscript(&script(
            &format!("ra-{st}"),
            &format!("// @run-at document-{st}\n// @grant none"),
            &format!("(window.__order = window.__order || []).push('{st}');"),
        ));
    }
    html(
        &s,
        "/",
        page(
            "<script>(window.__order = window.__order || []).push('head-inline');\
             addEventListener('load', () => __order.push('load'));</script>",
            "<script>__order.push('body-inline');</script>",
        ),
    );
    s.goto(&s.url("us.test", "/")).await;
    s.wait_for("idle", "window.__order.includes('idle')").await;
    let o: Vec<String> = serde_json::from_value(s.eval("window.__order").await).unwrap();
    let pos = |n: &str| {
        o.iter()
            .position(|x| x == n)
            .unwrap_or_else(|| panic!("{n} in {o:?}"))
    };
    assert!(pos("start") < pos("head-inline"), "{o:?}");
    assert!(pos("head-inline") < pos("body-inline"), "{o:?}");
    assert!(pos("body") < pos("end"), "{o:?}");
    assert!(pos("body-inline") < pos("end"), "{o:?}");
    assert!(pos("end") < pos("idle"), "{o:?}");
    s.assert_clean().await;
});

us_test!(
    match_exclude_and_noframes_are_respected_including_iframes,
    |s| {
        s.proxy.install_userscript(&script(
            "everywhere",
            "// @exclude *://us.test*/skip*\n// @grant none",
            "window.__A = 1;",
        ));
        s.proxy.install_userscript(&script(
            "top-only",
            "// @noframes\n// @grant none",
            "window.__B = 1;",
        ));
        html(&s, "/top", page("", "<iframe src=\"/frame\"></iframe>"));
        html(&s, "/frame", page("", "frame"));
        html(&s, "/skip", page("", "skipped"));
        s.origin.route("/", MockResponse::html(page("", "root")));
        s.goto(&s.url("us.test", "/top")).await;
        s.wait_for("top A+B", "window.__A === 1 && window.__B === 1")
            .await;
        s.wait_for(
        "frame A",
        "(() => { const w = document.querySelector('iframe').contentWindow; return w && w.__A === 1; })()",
    )
    .await;
        assert_eq!(
            s.eval("document.querySelector('iframe').contentWindow.__B")
                .await,
            Value::Null,
            "@noframes script must not run in the iframe"
        );
        s.goto(&s.url("us.test", "/skip")).await;
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert_eq!(s.eval("typeof window.__A").await, "undefined", "@exclude");
        // Another host: nothing is even injected.
        s.origin.route("/o", MockResponse::html(page("", "o")));
        s.goto(&s.url("us2.test", "/o")).await;
        assert_eq!(s.eval("typeof window.__A").await, "undefined");
        assert_eq!(
            s.eval("document.documentElement.outerHTML.includes('__adblock__/us')")
                .await,
            false
        );
    }
);

us_test!(
    values_persist_across_reloads_and_are_isolated_per_script,
    |s| {
        let a = s.proxy.install_userscript(&script(
        "counter-a",
        "// @grant GM_getValue\n// @grant GM_setValue\n// @grant GM.getValue",
        "const n = (GM_getValue('count', 0) || 0) + 1; GM_setValue('count', n); window.__count = n;\n\
         GM.getValue('count').then((v) => { window.__promised = v; });",
    ));
        s.proxy.install_userscript(&script(
            "counter-b",
            "// @grant GM_getValue",
            "window.__other = GM_getValue('count', 'none');",
        ));
        html(&s, "/", page("", "x"));
        for n in 1..=3 {
            s.goto(&s.url("us.test", "/")).await;
            s.wait_for("count", &format!("window.__count === {n}"))
                .await;
            wait_stored(&s, &a, "count", json!(n)).await;
        }
        assert_eq!(
            s.eval("window.__other").await,
            "none",
            "values are per script"
        );
        s.wait_for("promise form", "window.__promised === 3").await;
        s.assert_clean().await;
    }
);

us_test!(gm_add_style_applies_and_grant_none_has_no_gm_object, |s| {
    s.proxy.install_userscript(&script(
        "styler",
        "// @grant GM_addStyle",
        "GM_addStyle('#t { color: rgb(1, 2, 3) }'); window.__styled = 1;",
    ));
    s.proxy.install_userscript(&script(
        "plain",
        "// @grant none",
        "window.__none = [typeof GM, typeof GM_getValue, typeof GM_info, typeof unsafeWindow, unsafeWindow === window];\n\
         window.__shared = 'visible-to-page';",
    ));
    html(&s, "/", page("", "<p id=t>x</p>"));
    s.goto(&s.url("us.test", "/")).await;
    s.wait_for("both ran", "window.__styled === 1 && !!window.__shared")
        .await;
    assert_eq!(
        s.eval("getComputedStyle(document.getElementById('t')).color")
            .await,
        "rgb(1, 2, 3)"
    );
    assert_eq!(
        s.eval("window.__none").await,
        json!(["undefined", "undefined", "undefined", "object", true])
    );
    assert_eq!(s.eval("window.__shared").await, "visible-to-page");
    s.assert_clean().await;
});

us_test!(unsafe_window_and_gm_info_with_grants, |s| {
    s.proxy.install_userscript(&script(
        "uw",
        "// @grant GM_info",
        "unsafeWindow.__uw = 42; window.__info = [typeof GM_info, GM_info.script.name, unsafeWindow === window, typeof GM_getValue];",
    ));
    html(&s, "/", page("", "x"));
    s.goto(&s.url("us.test", "/")).await;
    s.wait_for("uw", "window.__uw === 42").await;
    assert_eq!(
        s.eval("window.__info").await,
        json!(["object", "uw", true, "undefined"])
    );
});

us_test!(xhr_cross_origin_get_and_post_follow_connect, |s| {
    s.origin.route("/data", MockResponse::ok("payload"));
    s.origin.route("/echo", MockResponse::ok("echoed"));
    s.origin.route("/never", MockResponse::ok("never"));
    let (api, deny, post) = (
        s.url("api.test", "/data"),
        s.url("deny.test", "/never"),
        s.url("api.test", "/echo"),
    );
    s.proxy.install_userscript(&script(
        "net",
        "// @grant GM_xmlhttpRequest\n// @connect api.test",
        &format!(
            "GM_xmlhttpRequest({{ method: 'GET', url: '{api}', onload: (r) => {{ window.__get = r.responseText + ':' + r.status; }}, onerror: () => {{ window.__get = 'error'; }} }});\n\
             GM_xmlhttpRequest({{ method: 'POST', url: '{post}', headers: {{ 'X-Test': 'yes', 'Content-Type': 'text/plain' }}, data: 'body!', onload: (r) => {{ window.__post = r.status + ':' + r.responseText; }}, onerror: () => {{ window.__post = 'error'; }} }});\n\
             GM_xmlhttpRequest({{ method: 'GET', url: '{deny}', onload: () => {{ window.__deny = 'loaded'; }}, onerror: () => {{ window.__deny = 'refused'; }} }});"
        ),
    ));
    html(&s, "/", page("", "x"));
    s.goto(&s.url("us.test", "/")).await;
    s.wait_for(
        "get+post+deny",
        "!!(window.__get && window.__post && window.__deny)",
    )
    .await;
    assert_eq!(s.eval("window.__get").await, "payload:200");
    assert_eq!(s.eval("window.__post").await, "200:echoed");
    assert_eq!(s.eval("window.__deny").await, "refused");
    let rec = s.origin.requests_for("/echo");
    assert_eq!(rec.len(), 1);
    assert_eq!(rec[0].body, b"body!");
    assert!(rec[0]
        .headers
        .iter()
        .any(|(n, v)| n.eq_ignore_ascii_case("x-test") && v == "yes"));
    assert!(
        s.origin.requests_for("/never").is_empty(),
        "unlisted host was never contacted"
    );
    // The refusal itself is logged by Chromium as a failed load of the endpoint (HTTP 403).
    assert!(s.violations().await.is_empty(), "no CSP violations");
});

us_test!(resources_and_requires_are_embedded_and_run_once, |s| {
    let mut f = Fetched::default();
    f.resources.insert(
        "css".into(),
        (b"body{color:red}".to_vec(), Some("text/css".into())),
    );
    f.requires.insert(
        "https://cdn.test/lib.js".into(),
        b"window.__libCount = (window.__libCount || 0) + 1; window.LIB = { ver: 7 };".to_vec(),
    );
    s.proxy.install_userscript_with(
        &script(
            "assets",
            "// @grant GM_getResourceText\n// @resource css https://cdn.test/a.css\n// @require https://cdn.test/lib.js",
            "window.__res = GM_getResourceText('css'); window.__lib = LIB.ver;",
        ),
        f,
        false,
    );
    html(&s, "/", page("", "x"));
    s.goto(&s.url("us.test", "/")).await;
    s.wait_for("assets", "window.__lib === 7").await;
    assert_eq!(s.eval("window.__res").await, "body{color:red}");
    assert_eq!(s.eval("window.__libCount").await, 1);
    s.assert_clean().await;
});

us_test!(value_change_listener_fires_across_two_tabs, |s| {
    s.proxy.install_userscript(&script(
        "vc",
        "// @grant GM_setValue\n// @grant GM_addValueChangeListener",
        "GM_addValueChangeListener('k', (n, o, nv, remote) => { window.__chg = [nv, remote]; });\n\
         window.__set = (v) => GM_setValue('k', v);",
    ));
    html(&s, "/", page("", "x"));
    s.goto(&s.url("us.test", "/")).await;
    s.wait_for("script ready", "typeof window.__set === 'function'")
        .await;
    let tab = s.new_tab().await;
    tab.goto(s.url("us.test", "/")).await.expect("tab goto");
    for _ in 0..200 {
        if eval_on(&tab, "typeof window.__set === 'function'").await == true {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    eval_on(&tab, "window.__set('from-tab2')").await;
    s.wait_for("change seen", "!!window.__chg").await;
    assert_eq!(s.eval("window.__chg").await, json!(["from-tab2", true]));
    s.assert_clean().await;
});

us_test!(a_syntax_error_does_not_break_other_scripts, |s| {
    s.proxy.install_userscript(&script(
        "bad",
        "// @grant none",
        "this is ((( not javascript",
    ));
    s.proxy
        .install_userscript(&script("good", "// @grant none", "window.__good = 1;"));
    html(&s, "/", page("", "x"));
    s.goto(&s.url("us.test", "/")).await;
    s.wait_for("good script", "window.__good === 1").await;
    assert!(s.violations().await.is_empty(), "no CSP violations");
});

async fn strict_csp_case(csp: &'static str, name: &'static str) {
    let inline = !csp.contains("default-src 'none'");
    let Some(s) = Session::start(&[]).await else {
        return;
    };
    run_known(name, async move {
        s.proxy.install_userscript(&script(
            "strict",
            "// @grant GM_setValue\n// @grant GM_getValue\n// @grant GM_addStyle",
            "GM_setValue('v', 5); GM_addStyle('#t { color: rgb(9, 8, 7) }'); window.__ran = GM_getValue('v', 0) === 5 ? 1 : 0;",
        ));
        s.origin.route(
            "/",
            MockResponse::html(page(
                if inline { "<script nonce=\"N0\">window.__page = 1;</script>" } else { "" },
                "<p id=t>x</p>",
            ))
            .header("content-security-policy", csp),
        );
        s.goto(&s.url("us.test", "/")).await;
        s.wait_for("script ran", "window.__ran === 1").await;
        assert_eq!(
            s.eval("getComputedStyle(document.getElementById('t')).color").await,
            "rgb(9, 8, 7)",
            "GM_addStyle under {csp}"
        );
        // The backend round trip works under the policy (connect-src).
        let id = s.proxy.userscripts().get_all()[0].id.clone();
        wait_stored(&s, &id, "v", json!(5)).await;
        s.assert_clean().await;
        s.finish().await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn strict_csp_nonce_only() {
    strict_csp_case("script-src 'nonce-N0'", "strict_csp_nonce_only").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn strict_csp_default_src_none() {
    strict_csp_case("default-src 'none'", "strict_csp_default_src_none").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn strict_csp_trusted_types() {
    strict_csp_case(
        "script-src 'self' 'nonce-N0'; require-trusted-types-for 'script'; trusted-types mypolicy",
        "strict_csp_trusted_types",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn strict_csp_strict_dynamic() {
    strict_csp_case(
        "script-src 'strict-dynamic' 'nonce-N0'",
        "strict_csp_strict_dynamic",
    )
    .await;
}

us_test!(hostile_page_cannot_use_or_steal_a_scripts_authority, |s| {
    let id = s.proxy.install_userscript(&script(
        "victim",
        "// @run-at document-start\n// @grant GM_setValue\n// @grant GM_getValue",
        "let n = 0; setInterval(() => { GM_setValue('tick', ++n); }, 50);\n\
         GM_setValue('hello', 'world');",
    ));
    html(
        &s,
        "/",
        page(
            "<script>window.__seen = []; window.__calls = 0;</script>",
            "x",
        ),
    );
    s.goto(&s.url("us.test", "/")).await;
    wait_stored(&s, &id, "hello", json!("world")).await;
    // The page now poisons every built-in the runtime could use, AFTER the runtime captured them.
    s.eval(
        "(() => { const rec = (...a) => { try { __seen.push(a.map(String).join('|')); } catch (_) {} };\
         const of = window.fetch; window.fetch = function (...a) { rec('fetch', a[0], JSON.stringify(a[1] || {})); return Reflect.apply(of, this, a); };\
         const op = JSON.parse; JSON.parse = function (...a) { rec('parse', a[0]); return Reflect.apply(op, this, a); };\
         const oc = Function.prototype.call, oa = Function.prototype.apply, ob = Function.prototype.bind;\
         Function.prototype.call = function (...a) { __calls++; return Reflect.apply(oc, this, a); };\
         Function.prototype.apply = function (...a) { __calls++; return Reflect.apply(oa, this, a); };\
         Function.prototype.bind = function (...a) { __calls++; return Reflect.apply(ob, this, a); };\
         const oj = Response.prototype.json; Response.prototype.json = function () { rec('json'); return Reflect.apply(oj, this, []); };\
         const ot = Response.prototype.text; Response.prototype.text = function () { rec('text'); return Reflect.apply(ot, this, []); };\
         const os = JSON.stringify; JSON.stringify = function (...a) { const r = Reflect.apply(os, this, a); rec('stringify', r); return r; };\
         const oh = Headers.prototype.get; Headers.prototype.get = function (...a) { rec('hget', a[0]); return Reflect.apply(oh, this, a); };\
         const xs = XMLHttpRequest.prototype.send; XMLHttpRequest.prototype.send = function (...a) { rec('xhr'); return Reflect.apply(xs, this, a); };\
         return 1; })()",
    )
    .await;
    let before = s
        .proxy
        .userscripts()
        .storage()
        .get_raw(&ns("default", &id), "tick")
        .unwrap();
    let n0 = before.and_then(|v| v.as_i64()).unwrap_or(0);
    wait_stored_at_least(&s, &id, "tick", n0 + 6).await;
    // Nothing the runtime did after the poisoning went through the page's hooks.
    let seen = s.eval("JSON.stringify(window.__seen)").await;
    let seen = seen.as_str().unwrap();
    assert!(
        !seen.contains("__adblock__/gm"),
        "runtime used the page's fetch: {seen}"
    );
    assert!(!seen.contains("v1."), "token reached page hooks: {seen}");
    // The page cannot find a token anywhere it can look.
    let leaks = s
        .eval(
            "(() => { const re = /v1\\.[A-Za-z0-9_-]{4,}\\.\\d{6,}\\./; const out = [];\
             if (re.test(document.documentElement.outerHTML)) out.push('dom');\
             for (const e of performance.getEntries()) if (re.test(e.name)) out.push('perf:' + e.name);\
             for (const k of Reflect.ownKeys(window)) { try { const v = window[k]; if (typeof v === 'string' && re.test(v)) out.push('win:' + String(k)); } catch (_) {} }\
             if (document.querySelector('script[src*=\"__adblock__/us\"]')) out.push('script element left');\
             return out; })()",
        )
        .await;
    assert_eq!(leaks, json!([]), "{leaks}");
    // Direct calls from page code (same origin, no valid token) are refused.
    let calls = s
        .eval(
            "(async () => { const r = [];\
             for (const t of [null, 'garbage', 'v1.dmljdGlt.9999999999.AAAA']) {\
               const h = { 'Content-Type': 'application/json' }; if (t) h['X-GM-Token'] = t;\
               const x = await fetch('/__adblock__/gm/v1/values/get', { method: 'POST', headers: h, body: '{\"names\":null}' });\
               r.push(x.status); }\
             const sc = performance.getEntries().map((e) => e.name).filter((n) => n.includes('/__adblock__/us/'));\
             r.push('bundle-urls:' + sc.length);\
             for (const u of sc) r.push((await fetch(u)).status);\
             return r; })()",
        )
        .await;
    let arr = calls.as_array().unwrap();
    assert_eq!(&arr[..3], &[json!(401), json!(401), json!(401)], "{calls}");
    for st in &arr[4..] {
        // A fetch() is refused (403: bundles load only as script elements); had it passed, the
        // single-use record would answer 404.
        assert!(
            st == &json!(403) || st == &json!(404),
            "bundle URLs are not readable by the page: {calls}"
        );
    }
});

async fn wait_stored_at_least(s: &Session, id: &str, name: &str, min: i64) {
    let m = s.proxy.userscripts();
    for _ in 0..400 {
        let v = m.storage().get_raw(&ns("default", id), name).unwrap();
        if v.and_then(|v| v.as_i64()).unwrap_or(0) >= min {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!("{name} never reached {min}\n{}", s.dump());
}

us_test!(
    hostile_page_can_still_observe_what_scripts_hand_to_promises,
    |s| {
        // Recorded limitation (docs/USERSCRIPT-PROTOCOL.md section 6): a page that poisons
        // `Promise.prototype.then` BEFORE a script uses the returned promise sees the script's data.
        s.proxy.install_userscript(&script(
        "leaky",
        "// @grant GM.setValue\n// @grant GM.getValue",
        "GM.setValue('s', 'SECRET').then(() => GM.getValue('s')).then((v) => { window.__got = v; });",
    ));
        html(
        &s,
        "/",
        page(
            "<script>window.__stolen = []; const ot = Promise.prototype.then;\
             Promise.prototype.then = function (a, b) { return ot.call(this, function (v) { try { __stolen.push(JSON.stringify(v)); } catch (_) {} return a ? a(v) : v; }, b); };</script>",
            "x",
        ),
    );
        s.goto(&s.url("us.test", "/")).await;
        s.wait_for("got", "window.__got === 'SECRET'").await;
        let stolen = s.eval("JSON.stringify(window.__stolen)").await;
        assert!(
            stolen.as_str().unwrap().contains("SECRET"),
            "expected the documented leak, got {stolen}"
        );
    }
);

// ---- a real-world-shaped script installed through the management API ----------------------

mod api {
    use super::*;
    use axum_test::TestServer;
    use cookie::Cookie;
    use web_api::config::ApiConfig;
    use web_api::state::build_state;
    use web_api::{create_router, ListService, ListServiceConfig, ListStore};

    pub struct Admin {
        server: TestServer,
        access: String,
        csrf: String,
        _dir: tempfile::TempDir,
    }

    fn cookie_from(resp: &axum_test::TestResponse, name: &str) -> String {
        resp.headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find_map(|s| {
                s.strip_prefix(&format!("{name}="))
                    .map(|r| r.split(';').next().unwrap_or("").to_string())
            })
            .unwrap_or_else(|| panic!("cookie {name}"))
    }

    /// The real API router over the proxy's own manager, with a registered administrator.
    pub async fn start(s: &Session) -> Admin {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        let mut cfg = ApiConfig::default();
        cfg.auth.jwt_secret_path = p.join("jwt_secret");
        cfg.session.storage_path = p.join("sessions");
        cfg.auth.bcrypt_cost = 4;
        let proxy_config = common::config::ProxyConfig::default();
        let config_path = p.join("proxy.toml");
        std::fs::write(&config_path, toml::to_string_pretty(&proxy_config).unwrap()).unwrap();
        let engine = Arc::new(filter_engine::SharedEngine::new());
        let http = reqwest::Client::new();
        let list_service = ListService::new(
            ListServiceConfig::default(),
            ListStore::open(&p.join("filters")).unwrap(),
            engine.clone(),
            http.clone(),
        );
        let manager = s.proxy.userscripts();
        let runtime = Arc::new(userscript_engine::UserscriptRuntime::new(
            manager.clone(),
            manager.storage_arc(),
        ));
        let state = build_state(
            cfg.clone(),
            proxy_config,
            engine,
            list_service,
            http,
            manager,
            runtime,
            config_path,
            Arc::new(std::sync::atomic::AtomicU64::new(60_000)),
        )
        .await
        .expect("api state");
        let server = TestServer::new(create_router(state, &cfg)).expect("server");
        let pw = "SecurePassword123!";
        let resp = server
            .post("/api/v1/auth/register")
            .json(&json!({"username": "admin_user", "password": pw, "password_confirm": pw}))
            .await;
        resp.assert_status_ok();
        Admin {
            access: cookie_from(&resp, "access_token"),
            csrf: cookie_from(&resp, "csrf_token"),
            server,
            _dir: dir,
        }
    }

    impl Admin {
        pub async fn post(&self, path: &str, body: Value) -> (u16, Value) {
            let r = self
                .server
                .post(path)
                .add_cookie(Cookie::new("access_token", self.access.clone()))
                .add_header("x-csrf-token", self.csrf.clone())
                .json(&body)
                .await;
            (r.status_code().as_u16(), r.json())
        }
    }
}

us_test!(real_world_script_installed_through_the_api_runs, |s| {
    let admin = api::start(&s).await;
    let source = script(
        "Tidy page",
        "// @description hides the ad, adds a button and counts visits\n// @run-at document-end\n// @grant GM_addStyle\n// @grant GM_getValue\n// @grant GM_setValue",
        "GM_addStyle('#ad { display: none !important }');\n\
         const visits = (GM_getValue('visits', 0) || 0) + 1;\n\
         GM_setValue('visits', visits);\n\
         const b = document.createElement('button'); b.id = 'us-btn'; b.textContent = 'Visits: ' + visits;\n\
         b.addEventListener('click', () => { b.textContent = 'Clicked ' + visits; });\n\
         document.body.appendChild(b);",
    );
    let (st, plan) = admin
        .post("/api/v1/userscripts/plan", json!({"source": source}))
        .await;
    assert_eq!(st, 200, "{plan}");
    assert_eq!(plan["name"], "Tidy page");
    assert!(plan["grants"]
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g == "gm_setvalue"));
    let (st, inst) = admin
        .post(
            &format!(
                "/api/v1/userscripts/plan/{}/confirm",
                plan["plan_id"].as_str().unwrap()
            ),
            json!({}),
        )
        .await;
    assert_eq!(st, 201, "{inst}");
    let id = inst["id"].as_str().unwrap().to_string();
    html(&s, "/", page("", "<div id=ad>Buy now</div><p>content</p>"));
    for visits in 1..=2 {
        s.goto(&s.url("us.test", "/")).await;
        s.wait_for("button", "!!document.getElementById('us-btn')")
            .await;
        assert_eq!(
            s.eval("document.getElementById('us-btn').textContent")
                .await,
            format!("Visits: {visits}")
        );
        assert_eq!(s.display("#ad").await, "none");
        wait_stored(&s, &id, "visits", json!(visits)).await;
    }
    s.eval("document.getElementById('us-btn').click()").await;
    assert_eq!(
        s.eval("document.getElementById('us-btn').textContent")
            .await,
        "Clicked 2"
    );
    s.assert_clean().await;
});

us_test!(
    no_token_or_channel_secret_is_observable_after_every_gm_api,
    |s| {
        s.origin.route("/data", MockResponse::ok("payload"));
        let api = s.url("api.test", "/data");
        let mut f = Fetched::default();
        f.resources.insert(
            "big".into(),
            (vec![b'a'; 300 * 1024], Some("text/plain".into())),
        );
        let id = s.proxy.install_userscript_with(
        &script(
            "everything",
            "// @run-at document-start\n// @connect api.test\n// @grant GM_getValue\n// @grant GM_setValue\n// @grant GM_deleteValue\n// @grant GM_listValues\n// @grant GM_addValueChangeListener\n// @grant GM_xmlhttpRequest\n// @grant GM_cookie\n// @grant GM.getResourceText\n// @grant GM_saveTab\n// @grant GM_getTabs\n// @grant GM_registerMenuCommand\n// @resource big https://cdn.test/big.txt",
            &format!(
                "GM_setValue('k', 'v1'); GM_registerMenuCommand('m', () => {{}}); GM_saveTab({{ a: 1 }}); GM_getTabs(() => {{}});\n\
                 GM_addValueChangeListener('k', (n, o, nv) => {{ window.__chg = nv; }});\n\
                 GM.getResourceText('big').then((t) => {{ window.__big = t.length; }});\n\
                 GM_cookie.set({{ url: location.href, name: 'c', value: '1' }}, () => {{}});\n\
                 GM_xmlhttpRequest({{ method: 'GET', url: '{api}', onload: (r) => {{ window.__x = r.status; }} }});\n\
                 window.__listed = GM_listValues().length; GM_deleteValue('zz');"
            ),
        ),
        f,
        false,
    );
        html(&s, "/", page("", "x"));
        s.goto(&s.url("us.test", "/")).await;
        s.wait_for("script done", "window.__x === 200 && window.__big > 0")
            .await;
        // Forged channel traffic from a hostile page must not change what the script sees.
        let forged = s
        .eval(&format!(
            "(async () => {{ for (const n of ['adblock-gm:{id}', 'adblock-gm-tabs:{id}']) {{ const c = new BroadcastChannel(n);\
               c.postMessage({{ t: 'set', tab: 'evil', name: 'k', new: 'FORGED', old: 'v1', has: true }}); c.close(); }}\
             await new Promise((r) => setTimeout(r, 300)); return window.__chg || null; }})()"
        ))
        .await;
        assert!(
            forged.is_null(),
            "forged value-change message was acted on: {forged}"
        );
        // Nothing a page can look at holds a token, and no channel listener hears anything.
        let leaks = s
        .eval(&format!(
            "(async () => {{ const re = /v1\\.[A-Za-z0-9_-]{{4,}}\\.\\d{{6,}}\\./; const out = [];\
             const heard = []; const chans = ['adblock-gm:{id}', 'adblock-gm-tabs:{id}'].map((n) => {{ const c = new BroadcastChannel(n); c.onmessage = (e) => heard.push(JSON.stringify(e.data)); return c; }});\
             if (re.test(document.documentElement.outerHTML)) out.push('dom');\
             for (const e of performance.getEntries()) {{ if (re.test(e.name)) out.push('perf:' + e.name); if (/[?&]t=/.test(e.name)) out.push('query-token:' + e.name); }}\
             for (const st of [localStorage, sessionStorage]) for (let i = 0; i < st.length; i++) if (re.test(st.getItem(st.key(i)) + st.key(i))) out.push('storage');\
             if (re.test(window.name)) out.push('window.name');\
             for (const k of Reflect.ownKeys(window)) {{ try {{ const v = window[k]; if (typeof v === 'string' && re.test(v)) out.push('win:' + String(k)); }} catch (_) {{}} }}\
             if (document.cookie && re.test(document.cookie)) out.push('cookie');\
             await new Promise((r) => setTimeout(r, 400));\
             if (heard.length) out.push('channel:' + heard.join(','));\
             const r = await fetch('/__adblock__/gm/v1/resource?name=big&t=v1.x.9999999999.y'); if (r.status === 200) out.push('resource-open');\
             return out; }})()"
        ))
        .await;
        assert_eq!(leaks, json!([]), "{leaks}");
        let _ = id;
    }
);

// A worker that watches what its pages send to the GM backend and reports any token it sees.
const SW_JS: &str = "self.addEventListener('fetch', (e) => { const u = new URL(e.request.url);\
   if (u.pathname.startsWith('/__adblock__/gm/v1/')) { const t = e.request.headers.get('x-gm-token');\
     self.clients.matchAll().then((cs) => cs.forEach((c) => c.postMessage({ stolen: t }))); } });";

async fn sw_register(s: &Session) -> serde_json::Value {
    s.eval(
        "(async () => { let rej = null; navigator.serviceWorker.register('/sw.js').catch((e) => { rej = e.name; });\
           for (let i = 0; i < 80; i++) { await new Promise((r) => setTimeout(r, 100)); if (rej) return 'failed:' + rej;\
             const rs = await navigator.serviceWorker.getRegistrations(); if (rs.length) return 'registered'; }\
           return 'timeout'; })()",
    )
    .await
}

us_test!(
    service_worker_cannot_register_on_a_site_with_a_privileged_script,
    |s| {
        s.origin.route(
            "/sw.js",
            MockResponse::ok(SW_JS).header("content-type", "text/javascript"),
        );
        s.proxy.install_userscript(&script(
            "priv",
            "// @grant GM_xmlhttpRequest\n// @connect api.test",
            "window.__ran = 1;",
        ));
        html(&s, "/", page("", "x"));
        s.goto(&s.url("us.test", "/")).await;
        s.wait_for("script ran", "window.__ran === 1").await;
        let r = sw_register(&s).await;
        assert!(
            r.as_str().unwrap().starts_with("failed"),
            "registration must be refused: {r}"
        );
    }
);

us_test!(
    service_workers_still_work_where_no_privileged_script_applies,
    |s| {
        s.origin.route(
            "/sw.js",
            MockResponse::ok(SW_JS).header("content-type", "text/javascript"),
        );
        s.proxy.install_userscript(&script(
            "plain",
            "// @grant GM_xmlhttpRequest\n// @connect api.test",
            "window.__ran = 1;",
        ));
        html(&s, "/", page("", "x"));
        s.proxy
            .ctx
            .set_service_worker_policy(common::config::ServiceWorkerPolicy::Allow);
        s.goto(&s.url("us.test", "/")).await;
        s.wait_for("script ran", "window.__ran === 1").await;
        assert_eq!(sw_register(&s).await, "registered");
    }
);

us_test!(tmp_sw_baseline, |s| {
    s.origin.route(
        "/sw.js",
        MockResponse::ok(SW_JS).header("content-type", "text/javascript"),
    );
    html(&s, "/", page("", "x"));
    s.goto(&s.url("us.test", "/")).await;
    assert_eq!(sw_register(&s).await, "registered");
});

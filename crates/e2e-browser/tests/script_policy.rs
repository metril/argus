//! Script control in real Chromium through the production proxy.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use e2e_browser::{run_known, MockResponse, Session};
use script_policy::{
    CapSet, Capability as C, Effect, GrantKind, Preset, Scope, DEFAULT_PROFILE as P,
};
use serde_json::Value;

macro_rules! sp_test {
    ($name:ident, |$s:ident| $body:block) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() {
            let Some($s) = Session::start(&["sp.test##.ad"]).await else {
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

fn enable(s: &Session, tweak: impl FnOnce(&mut script_policy::Settings)) {
    let (store, _) = s.proxy.script_control();
    let mut st = store.rules(P).unwrap().settings;
    st.enabled = true;
    tweak(&mut st);
    store.set_settings(P, st).unwrap();
}

fn scope(x: &str) -> Scope {
    Scope::parse(x).unwrap()
}

fn doc(cdn: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset=utf-8><title>t</title>\
         <script>window.__inline=1</script>\
         <script src=\"/own.js\"></script>\
         <script src=\"{cdn}\"></script></head>\
         <body><noscript><p id=ns>NS</p></noscript><div class=ad>ad</div><p id=p>hi</p></body></html>"
    )
}

fn routes(s: &Session) -> String {
    s.origin.route("/own.js", MockResponse::ok("window.__own=1").header("content-type", "text/javascript"));
    s.origin.route("/x.js", MockResponse::ok("window.__cdn=1").header("content-type", "text/javascript"));
    let cdn = s.url("cdn.test", "/x.js");
    s.origin.route("/", MockResponse::html(doc(&cdn)));
    cdn
}

/// Violations that our own resources could have caused: anything that is not a page script.
fn ours(v: &[Value]) -> Vec<Value> {
    v.iter()
        .filter(|v| {
            let uri = v["uri"].as_str().unwrap_or("");
            let eff = v["eff"].as_str().unwrap_or("");
            uri.contains("__adblock__")
                || eff.starts_with("style-src")
                || eff.starts_with("connect-src")
                || (eff.starts_with("script-src")
                    && !(uri == "inline" || uri == "eval" || uri.contains("/own.js") || uri.contains("/x.js")))
        })
        .cloned()
        .collect()
}

sp_test!(untrusted_blocks_page_scripts_while_ours_run, |s| {
    s.proxy.install_userscript(
        "// ==UserScript==\n// @name us1\n// @namespace sp\n// @version 1\n// @match *://sp.test/*\n// @run-at document-start\n// @grant none\n// ==/UserScript==\nwindow.__us = 1;\n",
    );
    routes(&s);
    let (store, _) = s.proxy.script_control();
    store.create_site_rule(P, scope("sp.test"), Preset::Untrusted, None).unwrap();
    enable(&s, |_| {});
    s.goto(&s.url("sp.test", "/")).await;
    assert_eq!(s.eval("typeof window.__inline").await, "undefined", "inline script blocked");
    assert_eq!(s.eval("typeof window.__own").await, "undefined", "external script blocked");
    assert_eq!(s.eval("typeof window.__cdn").await, "undefined");
    assert_eq!(s.eval("getComputedStyle(document.getElementById('ns')).display").await, "block", "<noscript> content visible");
    assert_eq!(s.display(".ad").await, "none", "our cosmetics still apply");
    assert_eq!(s.eval("window.__us").await, 1, "userscripts still run");
    let loads = s.internal_loads().await;
    assert!(loads.iter().any(|(p, st)| p.contains("/__adblock__/boot.") && *st == 200), "{loads:?}");
    let v = s.violations().await;
    assert!(v.iter().any(|v| v["eff"].as_str().unwrap_or("").starts_with("script-src")), "page scripts were refused by the browser: {v:?}");
    assert_eq!(ours(&v), Vec::<Value>::new(), "no violation attributable to our resources");
});

sp_test!(default_preset_blocks_third_party_until_allowed, |s| {
    routes(&s);
    let (store, _) = s.proxy.script_control();
    enable(&s, |_| {});
    s.goto(&s.url("sp.test", "/")).await;
    assert_eq!(s.eval("window.__own").await, 1, "first-party script runs");
    assert_eq!(s.eval("window.__inline").await, 1);
    assert_eq!(s.eval("typeof window.__cdn").await, "undefined", "third-party script blocked");
    let rep = store.report_for(P, "sp.test").expect("report");
    assert!(rep.items.iter().any(|i| i.source.as_deref() == Some("cdn.test") && i.cap == C::Script), "{rep:?}");
    assert_eq!(ours(&s.violations().await), Vec::<Value>::new());
    store
        .create_source_rule(P, scope("sp.test"), scope("cdn.test"), CapSet::of(&[C::Script]), Effect::Allow, None)
        .unwrap();
    s.goto(&s.url("sp.test", "/")).await;
    assert_eq!(s.eval("window.__cdn").await, 1, "allowed after reload");
});

sp_test!(csp_enforces_when_network_hints_are_off_and_reports_back, |s| {
    routes(&s);
    let (store, _) = s.proxy.script_control();
    enable(&s, |st| st.network_hints = false);
    s.goto(&s.url("sp.test", "/")).await;
    assert_eq!(s.eval("typeof window.__cdn").await, "undefined", "CSP blocked it");
    assert!(s.origin.requests_for("/x.js").is_empty(), "the browser never even asked: {:?}", s.origin.requests_for("/x.js").len());
    let v = s.violations().await;
    assert!(v.iter().any(|v| v["uri"].as_str().unwrap_or("").contains("cdn.test")), "{v:?}");
    // The browser's report-uri beacon reaches the proxy and is recorded as a CSP block.
    let mut ok = false;
    for _ in 0..200 {
        if store.report_for(P, "sp.test").is_some_and(|r| r.items.iter().any(|i| i.via_csp && i.source.as_deref() == Some("cdn.test"))) {
            ok = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    assert!(ok, "violation report recorded: {:?}", store.report_for(P, "sp.test"));
});

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn temporary_allow_then_expiry() {
    let Some(s) = Session::start(&["sp.test##.ad"]).await else { return };
    run_known("temporary_allow_then_expiry", async move {
        let now = Arc::new(AtomicU64::new(5_000_000));
        let n2 = now.clone();
        let (store, control) = s.proxy.script_control_with(Some(Arc::new(move || n2.load(Ordering::SeqCst))));
        routes(&s);
        enable(&s, |_| {});
        store
            .grant_temp(
                P,
                scope("sp.test"),
                GrantKind::Source { source: scope("cdn.test"), caps: CapSet::of(&[C::Script]) },
                Some(120),
                false,
                false,
            )
            .unwrap();
        s.goto(&s.url("sp.test", "/")).await;
        assert_eq!(s.eval("window.__cdn").await, 1, "temporarily allowed");
        now.store(5_000_121, Ordering::SeqCst);
        control.refresh();
        s.goto(&s.url("sp.test", "/")).await;
        assert_eq!(s.eval("typeof window.__cdn").await, "undefined", "blocked after expiry");
        s.finish().await;
    })
    .await;
}

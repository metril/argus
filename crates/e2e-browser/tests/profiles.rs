//! Per-device profiles in real Chromium: two browser contexts reach the proxy as different
//! devices (distinct source addresses) and get different userscripts on the same page.

use e2e_browser::{eval_on, MockResponse, Session, SourceRelay};

fn script(name: &str) -> String {
    format!(
        "// ==UserScript==\n// @name {name}\n// @namespace prof\n// @version 1.0\n// @match *://page.test/*\n// @run-at document-start\n// @grant none\n// ==/UserScript==\nwindow.__who = '{name}';\n"
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_profiles_on_the_same_page_get_different_userscripts() {
    let Some(s) = Session::start(&[]).await else {
        return;
    };
    let h = s.proxy.profiles();
    let (a, b) = (h.profile("alpha", ""), h.profile("beta", ""));
    h.device("da", a, &["127.0.0.81"]);
    h.device("db", b, &["127.0.0.82"]);
    h.sync().await;
    for (p, name) in [(a, "alpha"), (b, "beta")] {
        s.proxy
            .install_userscript_in(&h.namespace(p), &script(name), Default::default(), false);
    }
    s.origin.route(
        "/who",
        MockResponse::html(
            "<!doctype html><html><head><title>t</title></head><body>x</body></html>",
        ),
    );

    let url = s.url("page.test", "/who");
    let mut seen = Vec::new();
    // Keep the relays alive until both tabs are done.
    let mut relays = Vec::new();
    for ip in ["127.0.0.81", "127.0.0.82", "127.0.0.83"] {
        let relay = SourceRelay::start(s.proxy.addr, ip.parse().unwrap()).await;
        let tab = s.new_context_tab(&relay.url()).await;
        tab.goto(&url).await.expect("goto");
        let who = eval_on(&tab, "window.__who || null").await;
        seen.push(who);
        relays.push(relay);
    }
    assert_eq!(seen[0], "alpha", "{seen:?}\n{}", s.dump());
    assert_eq!(seen[1], "beta", "{seen:?}");
    assert!(
        seen[2].is_null(),
        "an unknown device gets no profile scripts: {seen:?}"
    );
    s.finish().await;
}

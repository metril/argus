//! The real extension in real Chromium against a real Argus process (no stubs): the proxy setting,
//! the real `407` answered by `onAuthRequired`, document binding, the menu calls the popup makes,
//! a browser-cookie relay, and the toggle going direct again.
//!
//! Needs an unpacked build with test host permissions (`ARGUS_E2E_HOSTS`, see `docs/TESTING.md`):
//!   cd extension && ARGUS_E2E_HOSTS='*://*.api.test/*,*://*.app.test/*,*://127.0.0.1/*' npx wxt build -b chrome
//! and a Chromium that honours `--load-extension` (Playwright's, `ARGUS_EXT_BROWSER`); branded
//! Chrome 137+ removed the switch. Without them the test skips, unless `ARGUS_EXT_E2E=1`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::cdp::browser_protocol::network::CookieParam;
use chromiumoxide::cdp::js_protocol::runtime::EvaluateParams;
use chromiumoxide::Page;
use e2e::{MockResponse, TestOrigin};
use e2e_browser::argus::Argus;
use futures_util::StreamExt;
use serde_json::{json, Value};

/// These suites need a built extension and a real Argus process, so they run only when asked
/// (`ARGUS_EXT_E2E=1`, as CI does); then a missing prerequisite is a failure, not a skip.
fn skip(why: &str) -> bool {
    if std::env::var("ARGUS_EXT_E2E").is_ok_and(|v| v == "1") {
        panic!("ARGUS_EXT_E2E=1 but {why}");
    }
    eprintln!("SKIPPED: {why} (set ARGUS_EXT_E2E=1 to run the extension suites)");
    true
}

fn chromium_with_extensions() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("ARGUS_EXT_BROWSER") {
        return Some(p.into());
    }
    let root = Path::new(&std::env::var_os("HOME")?).join(".cache/ms-playwright");
    let mut v: Vec<PathBuf> = std::fs::read_dir(root)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("chromium-"))
        .flat_map(|e| {
            std::fs::read_dir(e.path())
                .into_iter()
                .flatten()
                .filter_map(|d| d.ok())
                .map(|d| d.path().join("chrome"))
        })
        .filter(|p| p.is_file())
        .collect();
    v.sort();
    v.pop()
}

async fn eval(page: &Page, js: &str) -> Value {
    let params = EvaluateParams::builder()
        .expression(js)
        .await_promise(true)
        .return_by_value(true)
        .build()
        .unwrap();
    match page.evaluate_expression(params).await {
        Ok(r) => r.value().cloned().unwrap_or(Value::Null),
        Err(e) => panic!("eval `{js}`: {e}"),
    }
}

/// Evaluate `js` in target `target` over a second CDP connection (chromiumoxide cannot attach to
/// a popup target): attach with flattened sessions, `Runtime.evaluate`, detach.
async fn cdp_eval(ws_url: &str, target: &str, js: &str) -> Value {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;
    let (mut ws, _) = tokio_tungstenite::connect_async(ws_url)
        .await
        .expect("cdp ws");
    let mut next = 0u32;
    let mut call = |m: &str, p: Value, sid: Option<&str>| {
        next += 1;
        let mut v = json!({"id": next, "method": m, "params": p});
        if let Some(s) = sid {
            v["sessionId"] = json!(s);
        }
        (next, Message::Text(v.to_string()))
    };
    async fn answer(
        ws: &mut tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        id: u32,
    ) -> Value {
        while let Some(Ok(Message::Text(t))) = ws.next().await {
            let v: Value = serde_json::from_str(&t).unwrap();
            if v["id"] == id {
                return v;
            }
        }
        panic!("cdp closed");
    }
    let (id, m) = call(
        "Target.attachToTarget",
        json!({"targetId": target, "flatten": true}),
        None,
    );
    ws.send(m).await.unwrap();
    let sid = answer(&mut ws, id).await["result"]["sessionId"]
        .as_str()
        .expect("session")
        .to_string();
    let (id, m) = call(
        "Runtime.evaluate",
        json!({"expression": js, "awaitPromise": true, "returnByValue": true}),
        Some(&sid),
    );
    ws.send(m).await.unwrap();
    let r = answer(&mut ws, id).await;
    r["result"]["result"]["value"].clone()
}

async fn until(what: &str, mut f: impl AsyncFnMut() -> bool) {
    for _ in 0..400 {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_real_extension_binds_pages_relays_with_real_cookies_and_goes_direct_when_off() {
    if !std::env::var("ARGUS_EXT_E2E").is_ok_and(|v| v == "1") {
        skip("not asked");
        return;
    }
    let ext_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../extension/.output/chrome-mv3");
    let manifest = std::fs::read_to_string(ext_dir.join("manifest.json")).unwrap_or_default();
    if !manifest.contains("*://*.api.test/*")
        && skip("no extension build with ARGUS_E2E_HOSTS (see the test's header)")
    {
        return;
    }
    let Some(bin) = chromium_with_extensions() else {
        if skip("no Chromium that honours --load-extension (set ARGUS_EXT_BROWSER)") {
            return;
        }
        unreachable!()
    };

    let origin = TestOrigin::start().await;
    let argus = Argus::start(origin.ca_pem()).await;
    let port = origin.https_port();
    let api = format!("https://api.test:{port}");
    let script = format!(
        "// ==UserScript==\n// @name Real\n// @namespace e2e\n// @version 1.0\n// @match *://app.test/*\n// @run-at document-end\n// @grant GM_xmlhttpRequest\n// @grant GM_registerMenuCommand\n// @connect api.test\n// ==/UserScript==\nGM_registerMenuCommand('Mark', () => {{ document.documentElement.dataset.fired = '1'; }});\nGM_xmlhttpRequest({{ method: 'GET', url: '{api}/cookies', onload: r => {{ document.documentElement.dataset.resp = r.responseText; }}, onerror: e => {{ document.documentElement.dataset.err = JSON.stringify(e); }} }});\n"
    );
    argus.install_script(&script).await;
    origin.route(
        "/page",
        MockResponse::html("<!doctype html><title>t</title><body>hi</body>"),
    );
    origin.route("/cookies", MockResponse::ok("seen"));

    let profile = tempfile::tempdir().unwrap();
    let ext = ext_dir.canonicalize().unwrap();
    let args = [
        "no-first-run",
        "no-default-browser-check",
        "disable-background-networking",
        "disable-sync",
        "disable-dev-shm-usage",
        "disable-component-update",
        "password-store=basic",
        "mute-audio",
        // The CA is Argus's own, created at startup; certificate trust is not under test here.
        "ignore-certificate-errors",
    ]
    .map(String::from)
    .into_iter()
    .chain([
        format!("load-extension={}", ext.display()),
        format!("disable-extensions-except={}", ext.display()),
    ]);
    let cfg = BrowserConfig::builder()
        .chrome_executable(&bin)
        .user_data_dir(profile.path())
        .new_headless_mode()
        .no_sandbox()
        .disable_default_args()
        .launch_timeout(Duration::from_secs(60))
        .args(args)
        .build()
        .unwrap();
    let (mut browser, mut handler) = Browser::launch(cfg).await.expect("launch chromium");
    let h = tokio::spawn(async move { while handler.next().await.is_some() {} });

    // the extension's id: an unpacked extension's id is derived from its path (sha256, a-p)
    use sha2::{Digest, Sha256};
    let id: String = Sha256::digest(ext.to_string_lossy().as_bytes())[..16]
        .iter()
        .flat_map(|b| [b >> 4, b & 15])
        .map(|n| (b'a' + n) as char)
        .collect();
    until("the extension's service worker", async || {
        browser
            .fetch_targets()
            .await
            .unwrap_or_default()
            .iter()
            .any(|t| t.url.starts_with(&format!("chrome-extension://{id}/")))
    })
    .await;
    // an extension page gives us `chrome.*`
    let ext_page = browser.new_page("about:blank").await.unwrap();
    ext_page
        .goto(format!("chrome-extension://{id}/options.html"))
        .await
        .unwrap();
    until("the extension APIs on its page", async || {
        eval(
            &ext_page,
            "typeof chrome !== 'undefined' && !!chrome.storage && !!chrome.proxy",
        )
        .await
            == true
    })
    .await;
    let cfg_js = format!(
        "chrome.storage.local.set({{ argusUrl: {:?}, token: {:?}, argusProxy: {{ enabled: true, stores: {{}} }} }})",
        argus.web_url(),
        argus.token
    );
    eval(&ext_page, &cfg_js).await;

    // connected: the proxy setting points at the extension listener
    until("the browser proxy setting", async || {
        let v = eval(
            &ext_page,
            "new Promise(r => chrome.proxy.settings.get({}, d => r(d.value)))",
        )
        .await;
        v["mode"] == "fixed_servers" && v["rules"]["singleProxy"]["port"] == argus.ext
    })
    .await;
    let status = eval(
        &ext_page,
        "chrome.runtime.sendMessage({type:'bridge-status'})",
    )
    .await;
    assert_eq!(status["connected"], true);
    let sid = status["sid"].as_str().expect("sid").to_string();

    // a real cookie of the browser's profile for the relay target
    browser
        .set_cookies(vec![CookieParam::builder()
            .name("sess")
            .value("real-profile-cookie")
            .url(format!("{api}/"))
            .build()
            .unwrap()])
        .await
        .unwrap();

    // the page goes through the extension listener: the real 407 is answered, the document is bound
    let page = browser.new_page("about:blank").await.unwrap();
    page.goto(format!("https://app.test:{port}/page"))
        .await
        .expect("page through the proxy");
    let timing = eval(&page, "(performance.getEntriesByType('navigation')[0].serverTiming.find(e => e.name === 'argus') || {}).description || null").await;
    let mdoc = timing
        .as_str()
        .expect("a bound document carries its id in Server-Timing")
        .to_string();
    assert!(!mdoc.is_empty());

    // the relay used the real profile cookie (the jar of the script has none)
    until("the relayed response", async || {
        eval(&page, "!!document.documentElement.dataset.resp").await == true
    })
    .await;
    let seen = origin.requests_for("/cookies");
    assert!(
        seen.iter().any(|r| r.headers.iter().any(
            |(n, v)| n.eq_ignore_ascii_case("cookie") && v.contains("sess=real-profile-cookie")
        )),
        "the browser's cookie reached the origin: {seen:?}"
    );
    assert!(seen.iter().all(|r| r
        .headers
        .iter()
        .all(|(n, _)| !n.eq_ignore_ascii_case("x-argus-relay"))));

    // the popup's calls: list and trigger the page's menu command, from the bound session only
    let (st, menu) = argus
        .bridge(
            "GET",
            &format!("/api/v1/ext/menu?mdoc={mdoc}"),
            &sid,
            None,
            None,
        )
        .await;
    assert_eq!(st, 200, "{menu}");
    let cmd = &menu["commands"][0];
    assert_eq!(cmd["name"], "Mark");
    let (st, _) = argus
        .bridge(
            "GET",
            &format!("/api/v1/ext/menu?mdoc={mdoc}"),
            &sid,
            Some("c1x"),
            None,
        )
        .await;
    assert_eq!(st, 403, "another store's tab cannot list it");
    let (st, t) = argus
        .bridge(
            "POST",
            "/api/v1/ext/menu/trigger",
            &sid,
            None,
            Some(json!({"mdoc": mdoc, "script": cmd["script"], "cmd": cmd["cmd"]})),
        )
        .await;
    assert_eq!(st, 200, "{t}");
    until("the command to run in the page", async || {
        eval(&page, "document.documentElement.dataset.fired === '1'").await == true
    })
    .await;
    // no in-page button for a bound document
    assert_eq!(
        eval(
            &page,
            "document.querySelectorAll('[data-argus-menu], argus-menu').length"
        )
        .await,
        0
    );

    // toggle off: the setting is cleared, nothing is answered, a new page is not bound
    eval(
        &ext_page,
        "chrome.storage.local.set({ argusProxy: { enabled: false, stores: {} } })",
    )
    .await;
    until("the proxy setting to be cleared", async || {
        let v = eval(
            &ext_page,
            "new Promise(r => chrome.proxy.settings.get({}, d => r(d.value)))",
        )
        .await;
        v["mode"] != "fixed_servers"
    })
    .await;

    // the real popup, opened for the active tab: it lists the command and clicking it runs it
    let page_target = page.target_id().as_ref().to_string();
    eval(&page, "document.documentElement.dataset.fired = '0'").await;
    page.bring_to_front().await.unwrap();
    let opened = eval(
        &ext_page,
        "chrome.action.openPopup().then(() => 'ok', e => String(e))",
    )
    .await;
    assert_eq!(opened, "ok", "chrome.action.openPopup: {opened}");
    let popup_url = format!("chrome-extension://{id}/popup.html");
    let mut popup_target = String::new();
    until("the popup target", async || {
        let ts = browser.fetch_targets().await.unwrap_or_default();
        if let Some(t) = ts.iter().find(|t| t.url == popup_url) {
            popup_target = t.target_id.as_ref().to_string();
        }
        !popup_target.is_empty()
    })
    .await;
    let ws_url = browser.websocket_address().clone();
    until("the popup to list the command", async || {
        cdp_eval(
            &ws_url,
            &popup_target,
            "[...document.querySelectorAll('button.cmd')].some(b => b.textContent === 'Mark')",
        )
        .await
            == true
    })
    .await;
    cdp_eval(
        &ws_url,
        &popup_target,
        "[...document.querySelectorAll('button.cmd')].find(b => b.textContent === 'Mark').click()",
    )
    .await;
    // (the popup closes itself: from here on only a second CDP connection is used)
    until("the popup's click to run the command", async || {
        cdp_eval(
            &ws_url,
            &page_target,
            "document.documentElement.dataset.fired === '1'",
        )
        .await
            == true
    })
    .await;

    h.abort();
    drop(browser);
    argus.stop().await;
}

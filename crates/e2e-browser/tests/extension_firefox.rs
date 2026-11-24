//! The real extension in real Firefox (driven over Marionette, no geckodriver) against a real
//! Argus process: per-container routing, per-store 407 credentials, a container relay that sends
//! only that container's cookies, `Set-Cookie` landing in that container and not the default
//! store, and the private-window store.
//!
//! Needs `firefox` (or `ARGUS_FIREFOX`) and the unpacked build `extension/.output/firefox-mv3`
//! (`cd extension && npx wxt build -b firefox`). Without them the test skips, unless
//! `ARGUS_REQUIRE_BROWSER=1`.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use e2e::{MockResponse, TestOrigin};
use e2e_browser::argus::Argus;
use e2e_browser::marionette::Marionette;
use serde_json::{json, Value};

const UUID: &str = "9c1f2a3b-4d5e-4f60-8a7b-0c1d2e3f4a5b";

/// These suites need a built extension and a real Argus process, so they run only when asked
/// (`ARGUS_EXT_E2E=1`, as CI does); then a missing prerequisite is a failure, not a skip.
fn skip(why: &str) -> bool {
    if std::env::var("ARGUS_EXT_E2E").is_ok_and(|v| v == "1") {
        panic!("ARGUS_EXT_E2E=1 but {why}");
    }
    eprintln!("SKIPPED: {why} (set ARGUS_EXT_E2E=1 to run the extension suites)");
    true
}

fn firefox() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("ARGUS_FIREFOX") {
        return Some(p.into());
    }
    std::env::var_os("PATH").and_then(|p| {
        std::env::split_paths(&p)
            .map(|d| d.join("firefox"))
            .find(|c| c.is_file())
    })
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .unwrap()
        .port()
}

/// `browser.<path>(...args)` on the extension page, result as JSON.
async fn api(m: &mut Marionette, path: &str, args: Value) -> Value {
    let body = "const w = window.wrappedJSObject; const [path, argsJson] = args; \
        const parts = path.split('.'); const last = parts.pop(); let o = w.browser; for (const p of parts) o = o[p]; \
        const a = w.JSON.parse(argsJson); const r = await o[last](...a); \
        const s = w.JSON.stringify(r === undefined ? null : r); return JSON.parse(s);";
    m.run(body, json!([path, args.to_string()]))
        .await
        .unwrap_or_else(|e| panic!("browser.{path} {args}: {e}"))
}

async fn until(what: &str, mut f: impl AsyncFnMut() -> bool) {
    for _ in 0..600 {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {what}");
}

fn cookie_header(r: &e2e::RecordedRequest) -> String {
    r.headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("cookie"))
        .map(|(_, v)| v.clone())
        .collect::<Vec<_>>()
        .join("; ")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn containers_private_windows_and_per_store_relays_in_real_firefox() {
    if !std::env::var("ARGUS_EXT_E2E").is_ok_and(|v| v == "1") {
        skip("not asked");
        return;
    }
    let ext_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../extension/.output/firefox-mv3");
    if !ext_dir.join("manifest.json").is_file()
        && skip("no Firefox build (cd extension && npx wxt build -b firefox)")
    {
        return;
    }
    let Some(bin) = firefox() else {
        if skip("no firefox (set ARGUS_FIREFOX)") {
            return;
        }
        unreachable!()
    };
    let ext_dir = ext_dir.canonicalize().unwrap();

    let origin = TestOrigin::start().await;
    let argus = Argus::start(origin.ca_pem()).await;
    let port = origin.https_port();
    let api_url = format!("https://api.test:{port}");
    let script = format!(
        "// ==UserScript==\n// @name Real\n// @namespace e2e\n// @version 1.0\n// @match *://app.test/*\n// @run-at document-end\n// @grant GM_xmlhttpRequest\n// @connect api.test\n// ==/UserScript==\n\
         const tag = new URLSearchParams(location.search).get('c');\n\
         const t = (performance.getEntriesByType('navigation')[0].serverTiming || []).find(e => e.name === 'argus');\n\
         GM_xmlhttpRequest({{ method: 'GET', url: '{api_url}/cookies?c=' + tag + '&t=' + encodeURIComponent(t ? t.description : ''), onload: () => {{}} }});\n"
    );
    argus.install_script(&script).await;
    origin.route(
        "/page",
        MockResponse::html("<!doctype html><title>t</title><body>hi</body>"),
    );
    origin.route_fn("/cookies", |r| {
        let c = r
            .path_and_query
            .split("c=")
            .nth(1)
            .unwrap_or("")
            .split('&')
            .next()
            .unwrap_or("")
            .to_string();
        MockResponse::ok("seen").header(
            "set-cookie",
            &format!("from={c}; Path=/; Secure; SameSite=None"),
        )
    });

    let profile = tempfile::tempdir().unwrap();
    let mport = free_port();
    let prefs = format!(
        "user_pref('marionette.port', {mport});\n\
         user_pref('extensions.webextensions.uuids', '{{\"argus@metril.github.io\":\"{UUID}\"}}');\n\
         user_pref('xpinstall.signatures.required', false);\n\
         user_pref('extensions.autoDisableScopes', 0);\n\
         user_pref('network.dns.localDomains', 'app.test,api.test');\n\
         user_pref('app.update.enabled', false);\n\
         user_pref('browser.shell.checkDefaultBrowser', false);\n\
         user_pref('datareporting.policy.dataSubmissionEnabled', false);\n\
         user_pref('toolkit.telemetry.enabled', false);\n\
         user_pref('network.captive-portal-service.enabled', false);\n\
         user_pref('browser.privatebrowsing.autostart', false);\n\
         user_pref('privacy.userContext.enabled', true);\n\
         user_pref('network.websocket.allowInsecureFromHTTPS', true);\n\
         user_pref('security.mixed_content.block_active_content', false);\n\
         user_pref('devtools.console.stdout.chrome', true);\n\
         user_pref('devtools.console.stdout.content', true);\n"
    );
    std::fs::write(profile.path().join("user.js"), prefs).unwrap();
    let log = std::fs::File::create(profile.path().join("ff.log")).unwrap();
    let mut child = tokio::process::Command::new(&bin)
        .args(["-headless", "-marionette", "-no-remote", "-profile"])
        .arg(profile.path())
        .arg("about:blank")
        .env("MOZ_HEADLESS", "1")
        .env("MOZ_LOG", "nsWebSocket:5,WebSocket:5,nsHttp:3")
        .env("MOZ_LOG_FILE", profile.path().join("moz.log"))
        .env("MOZ_REMOTE_ALLOW_SYSTEM_ACCESS", "1")
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .kill_on_drop(true)
        .spawn()
        .expect("spawn firefox");

    let mut m = Marionette::connect(mport).await.expect("marionette");
    m.trust_ca(&String::from_utf8_lossy(&argus.ca_pem))
        .await
        .expect("trust the Argus CA");
    // (direct loads of a switched-off container reach the origin without Argus)
    m.trust_ca(origin.ca_pem())
        .await
        .expect("trust the origin CA");
    m.install_addon(ext_dir.to_str().unwrap())
        .await
        .expect("install the add-on");
    m.open_privileged(&format!("moz-extension://{UUID}/options.html"))
        .await
        .expect("open the options page");
    api(
        &mut m,
        "storage.local.set",
        json!([{
            "argusUrl": argus.web_url(), "token": argus.token,
            "argusProxy": {"enabled": true, "stores": {}},
            "granted": ["*://*.api.test/*"],
        }]),
    )
    .await;
    let a = api(
        &mut m,
        "contextualIdentities.create",
        json!([{"name": "A", "color": "blue", "icon": "fingerprint"}]),
    )
    .await["cookieStoreId"]
        .as_str()
        .unwrap()
        .to_string();
    let b = api(
        &mut m,
        "contextualIdentities.create",
        json!([{"name": "B", "color": "red", "icon": "cart"}]),
    )
    .await["cookieStoreId"]
        .as_str()
        .unwrap()
        .to_string();

    // connected: the extension has a session and the server told it where the listener is
    until("the bridge connection", async || {
        api(
            &mut m,
            "runtime.sendMessage",
            json!([{"type": "bridge-status"}]),
        )
        .await["connected"]
            == true
    })
    .await;
    let state = api(
        &mut m,
        "runtime.sendMessage",
        json!([{"type": "proxy-get"}]),
    )
    .await;
    assert_eq!(state["firefox"], true);
    until("the proxy to become active", async || {
        api(
            &mut m,
            "runtime.sendMessage",
            json!([{"type": "proxy-get"}]),
        )
        .await["active"]
            == true
    })
    .await;

    // each store has its own cookie for the relay target
    for (store, who) in [
        ("firefox-default", "D"),
        (a.as_str(), "A"),
        (b.as_str(), "B"),
        ("firefox-private", "P"),
    ] {
        api(&mut m, "cookies.set", json!([{"url": format!("{api_url}/"), "name": "who", "value": who, "storeId": store, "secure": true}])).await;
    }
    let open = |tag: &str| format!("https://app.test:{port}/page?c={tag}");
    api(
        &mut m,
        "tabs.create",
        json!([{"url": open("D"), "cookieStoreId": "firefox-default"}]),
    )
    .await;
    api(
        &mut m,
        "tabs.create",
        json!([{"url": open("A"), "cookieStoreId": a}]),
    )
    .await;
    api(
        &mut m,
        "tabs.create",
        json!([{"url": open("B"), "cookieStoreId": b}]),
    )
    .await;
    api(
        &mut m,
        "windows.create",
        json!([{"url": open("P"), "incognito": true}]),
    )
    .await;

    let seen = |tag: &str| {
        origin
            .requests()
            .into_iter()
            .filter(|r| r.path() == "/cookies" && r.path_and_query.contains(&format!("c={tag}&")))
            .collect::<Vec<_>>()
    };
    for tag in ["D", "A", "B", "P"] {
        let mut hits = vec![];
        until(&format!("the relayed request of {tag}"), async || {
            hits = seen(tag);
            !hits.is_empty()
        })
        .await;
        let ck = cookie_header(&hits[0]);
        // only that store's cookie
        assert!(ck.contains(&format!("who={tag}")), "{tag}: {ck}");
        for other in ["D", "A", "B", "P"].iter().filter(|o| **o != tag) {
            assert!(
                !ck.contains(&format!("who={other}")),
                "{tag} sent {other}'s cookie: {ck}"
            );
        }
        // the document was bound (per-store 407 credentials): its id came with the request
        assert!(!hits[0].path_and_query.ends_with("t="), "{tag}: not bound");
        assert!(hits[0]
            .headers
            .iter()
            .all(|(n, _)| !n.eq_ignore_ascii_case("x-argus-relay")
                && !n.eq_ignore_ascii_case("x-argus-job")));
    }
    let ids: std::collections::HashSet<String> = ["D", "A", "B", "P"]
        .iter()
        .map(|t| seen(t)[0].path_and_query.clone())
        .collect();
    assert_eq!(ids.len(), 4, "every store's document has its own id");

    // Set-Cookie went to the store of its job: each store holds only its own `from`, and the
    // default store is not polluted by the container and private relays
    for (store, who) in [
        ("firefox-default", "D"),
        (a.as_str(), "A"),
        (b.as_str(), "B"),
        ("firefox-private", "P"),
    ] {
        let mut vals = vec![];
        until(&format!("Set-Cookie in {store}"), async || {
            vals = api(
                &mut m,
                "cookies.getAll",
                json!([{"name": "from", "storeId": store}]),
            )
            .await
            .as_array()
            .cloned()
            .unwrap_or_default();
            !vals.is_empty()
        })
        .await;
        assert!(
            vals.iter().all(|c| c["value"] == who),
            "{store} holds {vals:?}, expected only from={who}"
        );
    }

    // a host Argus tunnels without decrypting: the browser's own request reaches the origin, and
    // nothing of the binding (session, store token, proxy credentials) is in it or in any other
    argus
        .admin(
            "POST",
            "/api/v1/bypass/entries",
            Some(json!({"pattern": "byp.test", "mode": "no_decrypt"})),
        )
        .await;
    let normal_win = api(&mut m, "tabs.query", json!([{}]))
        .await
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["incognito"] == false)
        .unwrap()["windowId"]
        .clone();
    api(
        &mut m,
        "tabs.create",
        json!([{"url": format!("https://byp.test:{port}/page?c=BYP"), "cookieStoreId": a, "windowId": normal_win}]),
    )
    .await;
    until("the passthrough page to reach the origin", async || {
        origin
            .requests()
            .iter()
            .any(|r| r.host.starts_with("byp.test"))
    })
    .await;
    let sid = api(
        &mut m,
        "runtime.sendMessage",
        json!([{"type": "bridge-status"}]),
    )
    .await["sid"]
        .as_str()
        .unwrap()
        .to_string();
    let mut secrets = vec![sid];
    for store in [a.as_str(), b.as_str(), "firefox-private"] {
        secrets.push(
            api(
                &mut m,
                "runtime.sendMessage",
                json!([{"type": "store-token", "storeId": store}]),
            )
            .await
            .as_str()
            .unwrap()
            .to_string(),
        );
    }
    for r in origin.requests() {
        for (n, v) in &r.headers {
            let (nl, vl) = (n.to_ascii_lowercase(), v.to_ascii_lowercase());
            assert!(
                !nl.starts_with("x-argus") && nl != "proxy-authorization",
                "{} {}: header {n}",
                r.host,
                r.path_and_query
            );
            for sec in &secrets {
                assert!(
                    !vl.contains(&sec.to_ascii_lowercase()),
                    "{} {}: a secret is in {n}",
                    r.host,
                    r.path_and_query
                );
            }
            assert!(
                !vl.starts_with("ext:"),
                "{} {}: {n}",
                r.host,
                r.path_and_query
            );
        }
    }
    assert!(
        origin
            .requests()
            .iter()
            .any(|r| r.host.starts_with("byp.test")),
        "the passthrough request was checked too"
    );

    // per-container routing: B switched off goes direct (not bound, no relay), A still relays
    api(
        &mut m,
        "storage.local.set",
        json!([{"argusProxy": {"enabled": true, "stores": {b.clone(): false}}}]),
    )
    .await;
    until("the new state", async || {
        api(
            &mut m,
            "runtime.sendMessage",
            json!([{"type": "proxy-get"}]),
        )
        .await["state"]["stores"][&b]
            == false
    })
    .await;
    // (the last focused window is the private one: name the normal window)
    let win = api(&mut m, "tabs.query", json!([{}]))
        .await
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["incognito"] == false)
        .unwrap()["windowId"]
        .clone();
    api(
        &mut m,
        "tabs.create",
        json!([{"url": open("B2"), "cookieStoreId": b, "windowId": win}]),
    )
    .await;
    api(
        &mut m,
        "tabs.create",
        json!([{"url": open("A2"), "cookieStoreId": a, "windowId": win}]),
    )
    .await;
    until("A's second page to relay", async || !seen("A2").is_empty()).await;
    until("B's direct page to load", async || {
        origin
            .requests()
            .iter()
            .any(|r| r.path() == "/page" && r.path_and_query.contains("c=B2"))
    })
    .await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        seen("B2").is_empty(),
        "a container switched off is not bound and does not relay"
    );

    let _ = child.kill().await;
    argus.stop().await;
}

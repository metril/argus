//! Real-browser test harness: headless Chromium driven over CDP through the production proxy.
//!
//! * Browser discovery: `ADBLOCKER_BROWSER` (path), then `chromium`/`google-chrome`/... on `PATH`,
//!   then Playwright's cache (`~/.cache/ms-playwright`). With none found, tests skip with a message,
//!   unless `ADBLOCKER_REQUIRE_BROWSER=1` (CI), which turns the skip into a failure.
//! * Every [`Session`] owns its origin, proxy (fresh CA), throwaway Chromium profile and CDP port.
//! * The proxy CA is trusted with `--ignore-certificate-errors-spki-list=<hash of the CA key>`, not
//!   a blanket error override; the baseline test additionally checks the served chain via CDP.
//! * Every session records console errors, uncaught exceptions, `securitypolicyviolation` events
//!   and Log-domain security entries; [`Session::assert_clean`] fails on any of them.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::cdp::browser_protocol::log::EventEntryAdded;
use chromiumoxide::cdp::browser_protocol::network::{
    EnableParams as NetworkEnable, EventResponseReceived,
};
use chromiumoxide::cdp::js_protocol::runtime::{
    EvaluateParams, EventConsoleApiCalled, EventExceptionThrown,
};
use chromiumoxide::Page;
use futures_util::StreamExt;
use sha2::{Digest, Sha256};

pub use e2e::{EntryMode, MockResponse, TestOrigin, TestProxy};

/// Scenarios that currently fail because of a real proxy bug. A test listed here still runs and
/// still prints its failure; it just does not fail the suite. Keep empty when everything passes.
/// Each entry: (test name, bug description).
pub const KNOWN_FAILING: &[(&str, &str)] = &[];

/// Run a scenario body; if the test is in [`KNOWN_FAILING`], report instead of failing.
pub async fn run_known<F: std::future::Future<Output = ()> + Send + 'static>(name: &str, body: F) {
    match KNOWN_FAILING.iter().find(|(n, _)| *n == name) {
        None => body.await,
        Some((_, bug)) => {
            let r = tokio::spawn(body).await;
            match r {
                Err(_) => eprintln!("KNOWN_FAILING {name}: still failing ({bug})"),
                Ok(()) => eprintln!("KNOWN_FAILING {name}: now PASSES, remove it from the list"),
            }
        }
    }
}

const BROWSER_NAMES: &[&str] = &[
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
    "chrome",
    "chrome-headless-shell",
];

fn which(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|p| {
        std::env::split_paths(&p)
            .map(|d| d.join(name))
            .find(|c| c.is_file())
    })
}

/// Newest Playwright-cache Chromium (`chrome-linux*/chrome` or `chrome-headless-shell`).
fn playwright_cache() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    let root = Path::new(&home).join(".cache/ms-playwright");
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(root)
        .ok()?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("chromium-"))
        })
        .collect();
    dirs.sort();
    dirs.reverse();
    for d in dirs {
        for sub in ["chrome-linux64/chrome", "chrome-linux/chrome"] {
            let c = d.join(sub);
            if c.is_file() {
                return Some(c);
            }
        }
    }
    None
}

/// The browser binary to use, if any.
pub fn find_browser() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("ADBLOCKER_BROWSER") {
        return Some(PathBuf::from(p));
    }
    BROWSER_NAMES
        .iter()
        .find_map(|n| which(n))
        .or_else(playwright_cache)
}

/// SHA-256 of the CA certificate's SubjectPublicKeyInfo, base64 (Chromium's SPKI-list format),
/// and its subject common name.
fn ca_spki(ca_pem: &[u8]) -> (String, String) {
    let der = rustls_pemfile::certs(&mut &*ca_pem)
        .next()
        .expect("CA pem has a certificate")
        .expect("CA pem parses");
    let (_, cert) = x509_parser::parse_x509_certificate(&der).expect("CA der parses");
    let hash = Sha256::digest(cert.public_key().raw);
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .unwrap_or("")
        .to_string();
    (base64::engine::general_purpose::STANDARD.encode(hash), cn)
}

/// Every hostname the scenarios use.
pub const HOSTS: &[&str] = &[
    "csp.test",
    "page.test",
    "blk.test",
    "top.test",
    "frame.test",
    "enc.test",
    "ws.test",
    "evil.test",
    "victim.test",
    "tok.test",
    "proc.test",
    "gen.test",
];

fn leaf_spki(der: &[u8]) -> String {
    let (_, cert) = x509_parser::parse_x509_certificate(der).expect("leaf der parses");
    base64::engine::general_purpose::STANDARD.encode(Sha256::digest(cert.public_key().raw))
}

#[derive(Default)]
struct Events {
    console_errors: Vec<String>,
    exceptions: Vec<String>,
    log_errors: Vec<String>,
    /// (url, status, protocol, issuer, sans) of every response.
    responses: Vec<ResponseInfo>,
}

#[derive(Clone, Debug)]
pub struct ResponseInfo {
    pub url: String,
    pub status: i64,
    pub protocol: String,
    pub issuer: Option<String>,
    pub sans: Vec<String>,
    /// Response headers (names as the browser reports them).
    pub headers: serde_json::Value,
}

impl ResponseInfo {
    /// First header named `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers.as_object()?.iter().find_map(|(k, v)| {
            k.eq_ignore_ascii_case(name)
                .then(|| v.as_str().unwrap_or("").to_string())
        })
    }
}

/// Init script run in every document: records CSP violations (frames forward theirs to the top
/// window, which collects them in `window.__viol`).
const INIT_JS: &str = r#"(() => {
  if (window.__abInit) return; window.__abInit = 1; window.__viol = window.__viol || [];
  const rec = (e) => {
    const v = { dir: e.violatedDirective, eff: e.effectiveDirective, uri: e.blockedURI,
                disp: e.disposition, sample: e.sample, doc: location.href };
    window.__viol.push(v);
    try { if (window.top !== window) window.top.postMessage({ __abviol: v }, '*'); } catch (_) {}
  };
  document.addEventListener('securitypolicyviolation', rec, true);
  window.addEventListener('message', (e) => {
    if (e.data && e.data.__abviol && window.top === window) window.__viol.push(e.data.__abviol);
  });
})();"#;

/// One origin + proxy + Chromium for a single test.
pub struct Session {
    pub origin: TestOrigin,
    pub proxy: TestProxy,
    pub mode: EntryMode,
    pub page: Page,
    pub ca_cn: String,
    browser: Browser,
    handler: tokio::task::JoinHandle<()>,
    events: Arc<parking_lot_lite::Mutex<Events>>,
    _profile: tempfile::TempDir,
}

/// Minimal std-mutex wrapper (avoids another dependency).
mod parking_lot_lite {
    pub struct Mutex<T>(std::sync::Mutex<T>);
    impl<T: Default> Default for Mutex<T> {
        fn default() -> Self {
            Self(Default::default())
        }
    }
    impl<T> Mutex<T> {
        pub fn lock(&self) -> std::sync::MutexGuard<'_, T> {
            self.0.lock().unwrap_or_else(|e| e.into_inner())
        }
    }
}

/// Which scriptlet/redirect resource library the proxy loads.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Resources {
    /// A tiny local `set-constant` (no dependencies), so browser behaviour can be tested
    /// independently of the converted uBO library.
    Minimal,
    /// The repo's pinned uBO snapshot, read at runtime (never compiled in: GPL data). Goes through
    /// the same validation as any library, so what the page runs is what the proxy would serve.
    Bundled,
}

fn resources_json(which: Resources) -> String {
    match which {
        Resources::Minimal => {
            let js = "function setConstant(chain, raw) { \
                const v = raw === 'undefined' ? undefined : (isNaN(+raw) ? raw : +raw); \
                Object.defineProperty(window, chain, { value: v, configurable: true, writable: false }); }";
            let b64 = base64::engine::general_purpose::STANDARD.encode(js);
            serde_json::json!([{
                "name": "set-constant.js", "aliases": ["set-constant"],
                "kind": {"mime": "application/javascript"}, "content": b64
            }])
            .to_string()
        }
        Resources::Bundled => {
            let p = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../filter-engine/resources/ubo-resources.json");
            std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
        }
    }
}

impl Session {
    /// Start in explicit-proxy mode with `rules`. `None` (after printing why) when there is no
    /// browser, unless `ADBLOCKER_REQUIRE_BROWSER=1`, which panics instead.
    pub async fn start(rules: &[&str]) -> Option<Session> {
        Self::start_mode(EntryMode::Explicit, rules).await
    }

    pub async fn start_mode(mode: EntryMode, rules: &[&str]) -> Option<Session> {
        Self::start_full(mode, rules, Resources::Minimal).await
    }

    pub async fn start_full(
        mode: EntryMode,
        rules: &[&str],
        resources: Resources,
    ) -> Option<Session> {
        let Some(bin) = find_browser() else {
            let msg = "no Chromium found (set ADBLOCKER_BROWSER=/path/to/chrome)";
            if std::env::var("ADBLOCKER_REQUIRE_BROWSER").is_ok_and(|v| v == "1") {
                panic!("ADBLOCKER_REQUIRE_BROWSER=1 but {msg}");
            }
            eprintln!("SKIPPED: {msg}");
            return None;
        };
        let origin = TestOrigin::start().await;
        let proxy = TestProxy::start(mode, &origin, rules)
            .await
            .expect("start proxy");
        proxy
            .engine
            .set_resources_from_json(&resources_json(resources))
            .expect("load scriptlet resources");
        let (ca_hash, ca_cn) = ca_spki(&proxy.ca_pem);
        // Chromium matches the SPKI list against the chain the server sends, and the proxy sends
        // only the leaf; so pin the CA plus the (cached) leaf of every hostname the tests use.
        let mut spki = vec![ca_hash];
        let mitm = proxy.mitm.as_ref().expect("MITM enabled");
        for h in HOSTS {
            let cert = mitm.get_certificate(h).await.expect("leaf cert");
            spki.push(leaf_spki(cert.cert.as_ref()));
        }
        let spki = spki.join(",");
        let profile = tempfile::tempdir().expect("profile dir");

        let mut args: Vec<String> = [
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-sync",
            "--disable-dev-shm-usage",
            "--disable-component-update",
            "--disable-features=Translate,HttpsUpgrades,OptimizationHints",
            "--password-store=basic",
            "--use-mock-keychain",
            "--mute-audio",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        args.push(format!("--ignore-certificate-errors-spki-list={spki}"));
        if let Ok(p) = std::env::var("ADBLOCKER_BROWSER_NETLOG") {
            args.push(format!("--log-net-log={p}"));
        }
        match mode {
            EntryMode::Explicit => args.push(format!("--proxy-server=http://{}", proxy.addr)),
            // No proxy: every hostname resolves to loopback and the page URL carries the
            // transparent listener's port (see `Session::url`).
            EntryMode::Transparent => {
                args.push("--no-proxy-server".into());
                args.push("--host-resolver-rules=MAP *.test 127.0.0.1".into());
            }
        }
        let mut cfg = BrowserConfig::builder()
            .chrome_executable(&bin)
            .user_data_dir(profile.path())
            .new_headless_mode()
            .no_sandbox()
            .disable_default_args()
            // The default would call Security.setIgnoreCertificateErrors: certificates are under test.
            .respect_https_errors()
            .launch_timeout(Duration::from_secs(60))
            .request_timeout(Duration::from_secs(30))
            .args(args.iter().map(|a| a.trim_start_matches("--").to_string()));
        cfg = cfg.window_size(1000, 800);
        let (browser, mut handler) = Browser::launch(cfg.build().expect("browser config"))
            .await
            .unwrap_or_else(|e| panic!("launch {}: {e}", bin.display()));
        let handler = tokio::spawn(async move { while handler.next().await.is_some() {} });
        let page = browser.new_page("about:blank").await.expect("new page");

        let events: Arc<parking_lot_lite::Mutex<Events>> = Arc::default();
        page.execute(NetworkEnable::default()).await.expect("net");
        page.enable_log().await.expect("log");
        page.enable_runtime().await.expect("runtime");
        page.evaluate_on_new_document(INIT_JS).await.expect("init");

        let mut log = page.event_listener::<EventEntryAdded>().await.unwrap();
        let mut exc = page.event_listener::<EventExceptionThrown>().await.unwrap();
        let mut con = page
            .event_listener::<EventConsoleApiCalled>()
            .await
            .unwrap();
        let mut net = page
            .event_listener::<EventResponseReceived>()
            .await
            .unwrap();
        let ev = events.clone();
        tokio::spawn(async move {
            while let Some(e) = log.next().await {
                let en = &e.entry;
                if format!("{:?}", en.level).to_lowercase().contains("error") {
                    ev.lock().log_errors.push(format!(
                        "[{:?}] {} ({})",
                        en.source,
                        en.text,
                        en.url.clone().unwrap_or_default()
                    ));
                }
            }
        });
        let ev = events.clone();
        tokio::spawn(async move {
            while let Some(e) = exc.next().await {
                let d = &e.exception_details;
                let desc = d
                    .exception
                    .as_ref()
                    .and_then(|o| o.description.clone())
                    .unwrap_or_default();
                ev.lock().exceptions.push(format!("{} {desc}", d.text));
            }
        });
        let ev = events.clone();
        tokio::spawn(async move {
            while let Some(e) = con.next().await {
                if format!("{:?}", e.r#type).to_lowercase().contains("error") {
                    let text: Vec<String> = e
                        .args
                        .iter()
                        .map(|a| {
                            a.value
                                .as_ref()
                                .map(|v| v.to_string())
                                .or_else(|| a.description.clone())
                                .unwrap_or_default()
                        })
                        .collect();
                    ev.lock().console_errors.push(text.join(" "));
                }
            }
        });
        let ev = events.clone();
        tokio::spawn(async move {
            while let Some(e) = net.next().await {
                let r = &e.response;
                let sd = r.security_details.as_ref();
                ev.lock().responses.push(ResponseInfo {
                    url: r.url.clone(),
                    status: r.status,
                    protocol: r.protocol.clone().unwrap_or_default(),
                    issuer: sd.map(|s| s.issuer.clone()),
                    sans: sd.map(|s| s.san_list.clone()).unwrap_or_default(),
                    headers: serde_json::to_value(r.headers.inner()).unwrap_or_default(),
                });
            }
        });

        Some(Session {
            origin,
            proxy,
            mode,
            page,
            ca_cn,
            browser,
            handler,
            events,
            _profile: profile,
        })
    }

    /// Port a page URL must carry for this entry mode.
    pub fn port(&self) -> u16 {
        match self.proxy.transparent_addr {
            Some(a) if self.mode == EntryMode::Transparent => a.port(),
            _ => self.origin.https_port(),
        }
    }

    /// `https://host:port` as the browser must address `host`.
    pub fn base(&self, host: &str) -> String {
        format!("https://{host}:{}", self.port())
    }

    pub fn url(&self, host: &str, path: &str) -> String {
        format!("{}{path}", self.base(host))
    }

    /// `wss://host:port<path>`
    pub fn ws_url(&self, host: &str, path: &str) -> String {
        format!("wss://{host}:{}{path}", self.port())
    }

    /// The same origin response fetched directly (no proxy: loopback is never proxied).
    pub fn direct_url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.origin.http_port())
    }

    /// Navigate (waits for the load event).
    pub async fn goto(&self, url: &str) {
        self.page
            .goto(url)
            .await
            .unwrap_or_else(|e| panic!("goto {url}: {e}\n{}", self.dump()));
    }

    /// Evaluate a JS expression (promises are awaited) and return its JSON value.
    pub async fn eval(&self, js: &str) -> serde_json::Value {
        let params = EvaluateParams::builder()
            .expression(js)
            .await_promise(true)
            .return_by_value(true)
            .build()
            .expect("eval params");
        match self.page.evaluate_expression(params).await {
            Ok(r) => r.value().cloned().unwrap_or(serde_json::Value::Null),
            Err(e) => panic!("eval `{js}`: {e}\n{}", self.dump()),
        }
    }

    /// Poll `js` until it is truthy (no fixed sleeps); panics with diagnostics on timeout.
    pub async fn wait_for(&self, what: &str, js: &str) {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let v = self.eval(js).await;
            if v.as_bool().unwrap_or(false) || v.as_i64().is_some_and(|n| n != 0) {
                return;
            }
            if Instant::now() > deadline {
                panic!(
                    "timed out waiting for {what}: `{js}` = {v}\n{}",
                    self.dump()
                );
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    pub async fn display(&self, selector: &str) -> String {
        self.eval(&format!(
            "(() => {{ const e = document.querySelector({selector:?}); \
             return e ? getComputedStyle(e).display : 'missing'; }})()"
        ))
        .await
        .as_str()
        .unwrap_or("?")
        .to_string()
    }

    /// CSP violations seen by the top document (and frames that forwarded theirs).
    pub async fn violations(&self) -> Vec<serde_json::Value> {
        self.eval("window.__viol || []")
            .await
            .as_array()
            .cloned()
            .unwrap_or_default()
    }

    pub fn responses(&self) -> Vec<ResponseInfo> {
        self.events.lock().responses.clone()
    }

    /// `/__adblock__/` resources the document fetched: (path, HTTP status).
    pub async fn internal_loads(&self) -> Vec<(String, i64)> {
        let v = self
            .eval(
                "performance.getEntriesByType('resource').filter(e => e.name.includes('/__adblock__/'))\
                 .map(e => [new URL(e.name).pathname, e.responseStatus])",
            )
            .await;
        v.as_array()
            .map(|a| {
                a.iter()
                    .map(|p| {
                        (
                            p[0].as_str().unwrap_or("").to_string(),
                            p[1].as_i64().unwrap_or(0),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Everything the browser reported that the proxy's own resources could have caused.
    pub fn problems_sync(&self, violations: &[serde_json::Value]) -> Vec<String> {
        let ev = self.events.lock();
        let violations: Vec<&serde_json::Value> = violations
            .iter()
            .filter(|v| {
                !v["uri"]
                    .as_str()
                    .is_some_and(|u| u.ends_with("/favicon.ico"))
            })
            .collect();
        let mut out: Vec<String> = violations
            .iter()
            .map(|v| format!("CSP violation: {v}"))
            .collect();
        for l in &ev.log_errors {
            let lower = l.to_lowercase();
            if lower.contains("content security policy")
                || lower.contains("trusted type")
                || lower.contains("__adblock__")
                || lower.contains("[security]")
            {
                out.push(format!("log: {l}"));
            }
        }
        for c in &ev.console_errors {
            if c.contains("__adblock__") || c.to_lowercase().contains("content security policy") {
                out.push(format!("console.error: {c}"));
            }
        }
        for x in &ev.exceptions {
            out.push(format!("uncaught exception: {x}"));
        }
        out
    }

    /// Fail on any CSP violation, security log entry, uncaught exception or console error that
    /// involves our injected resources.
    pub async fn assert_clean(&self) {
        let v = self.violations().await;
        let p = self.problems_sync(&v);
        assert!(
            p.is_empty(),
            "browser reported problems:\n{}\n{}",
            p.join("\n"),
            self.dump()
        );
    }

    /// Human-readable dump of everything recorded (for failure messages).
    pub fn dump(&self) -> String {
        let ev = self.events.lock();
        format!(
            "-- console errors: {:?}\n-- exceptions: {:?}\n-- log errors: {:?}\n-- origin saw: {:?}",
            ev.console_errors,
            ev.exceptions,
            ev.log_errors,
            self.origin
                .requests()
                .iter()
                .map(|r| format!("{} {}{}", r.method, r.host, r.path_and_query))
                .collect::<Vec<_>>()
        )
    }

    /// Close the browser (also happens on drop, less tidily).
    pub async fn finish(mut self) {
        let _ = self.browser.close().await;
        let _ = self.browser.wait().await;
        self.handler.abort();
    }
}

/// Standard HTML page with a `.ad` element and a parse-time probe of `foo` and the ad's display.
pub const TEST_GIF: &[u8] = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b";

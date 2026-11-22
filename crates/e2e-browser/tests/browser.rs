//! Real-browser scenarios. Each test owns its own origin, proxy and Chromium; see the crate docs.

use e2e::{encode, Coding};
use e2e_browser::{run_known, EntryMode, MockResponse, Resources, Session, TEST_GIF};

const SCRIPTLET: &str = "csp.test##+js(set-constant, foo, 42)";
const COSMETIC: &str = "csp.test##.ad";

/// Declare a browser test: `$body` gets `s: Session`; skipped without a browser.
macro_rules! browser_test {
    ($name:ident, $rules:expr, |$s:ident| $body:block) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() {
            let rules: &[&str] = &$rules;
            let Some($s) = Session::start(rules).await else {
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

// ---- baseline ---------------------------------------------------------------------------

browser_test!(baseline_https_h2_valid_chain, [COSMETIC], |s| {
    s.origin.route(
        "/",
        MockResponse::html("<!doctype html><title>t</title><p id=p>hello</p><div class=ad>x</div>"),
    );
    s.goto(&s.url("csp.test", "/")).await;
    assert_eq!(
        s.eval("document.getElementById('p').textContent").await,
        "hello"
    );
    assert_eq!(
        s.eval("performance.getEntriesByType('navigation')[0].nextHopProtocol")
            .await,
        "h2"
    );
    assert_eq!(s.eval("window.isSecureContext").await, true);
    let doc = s
        .responses()
        .into_iter()
        .find(|r| r.url.ends_with("/") && r.url.contains("csp.test"))
        .expect("document response");
    let issuer = doc.issuer.clone().expect("TLS security details");
    assert!(
        issuer.contains(&s.ca_cn),
        "issuer {issuer:?} is not the proxy CA {:?}",
        s.ca_cn
    );
    assert!(
        doc.sans.iter().any(|n| n == "csp.test"),
        "SANs {:?}",
        doc.sans
    );
    assert_eq!(s.display(".ad").await, "none");
    let loads = s.internal_loads().await;
    assert!(
        loads
            .iter()
            .any(|(p, st)| p.contains("/__adblock__/boot.") && *st == 200),
        "{loads:?}"
    );
    s.assert_clean().await;
});

// ---- network blocking ---------------------------------------------------------------------

browser_test!(
    network_block_and_redirect,
    [
        "/ad.png^$domain=page.test",
        "/ad.js^$script,domain=page.test",
        "/r.gif^$image,redirect=1x1.gif,domain=page.test"
    ],
    |s| {
        let b = s.base("blk.test");
        s.origin.route(
            "/ok.gif",
            MockResponse::ok(TEST_GIF).header("content-type", "image/gif"),
        );
        s.origin.route(
            "/ad.png",
            MockResponse::ok(TEST_GIF).header("content-type", "image/gif"),
        );
        s.origin.route(
            "/r.gif",
            MockResponse::ok(b"not an image".to_vec()).header("content-type", "image/gif"),
        );
        s.origin.route(
            "/ad.js",
            MockResponse::ok("window.__adjs=1").header("content-type", "application/javascript"),
        );
        s.origin.route("/", MockResponse::html(format!(
        "<!doctype html><img id=ok src='{b}/ok.gif'><img id=blocked src='{b}/ad.png'><img id=redir src='{b}/r.gif'>\
         <script src='{b}/ad.js' onload='window.__jsdone=1'></script>")));
        s.goto(&s.url("page.test", "/")).await;
        s.wait_for(
            "images settled",
            "['ok','blocked','redir'].every(i => document.getElementById(i).complete)",
        )
        .await;
        assert_eq!(
            s.eval("document.getElementById('ok').naturalWidth").await,
            1
        );
        // Blocked images are answered with a transparent pixel by design: assert on the origin instead.
        assert_eq!(
            s.eval("document.getElementById('redir').naturalWidth")
                .await,
            1,
            "redirect replacement must decode"
        );
        s.wait_for("neutered script finished", "window.__jsdone === 1")
            .await;
        assert_eq!(s.eval("typeof window.__adjs").await, "undefined");
        assert!(
            s.origin.requests_for("/ad.png").is_empty()
                && s.origin.requests_for("/ad.js").is_empty()
                && s.origin.requests_for("/r.gif").is_empty()
        );
        s.assert_clean().await;
    }
);

// ---- cosmetics ------------------------------------------------------------------------------

browser_test!(cosmetic_hidden_before_first_paint, [COSMETIC], |s| {
    s.origin.route("/", MockResponse::html(
        "<!doctype html><html><head><title>t</title></head><body><div class=ad id=a>AD</div>\
         <script>window.__atParse=getComputedStyle(document.getElementById('a')).display;\
         window.__raf=new Promise(r=>requestAnimationFrame(()=>r(getComputedStyle(document.getElementById('a')).display)))</script></body></html>"));
    s.goto(&s.url("csp.test", "/")).await;
    assert_eq!(
        s.eval("window.__atParse").await,
        "none",
        "ad visible when parser reached it"
    );
    assert_eq!(s.eval("window.__raf").await, "none");
    s.assert_clean().await;
});

browser_test!(
    generic_cosmetic_via_beacon,
    ["##.dyn-ad", "##.dyn-ad2"],
    |s| {
        s.origin.route(
            "/",
            MockResponse::html("<!doctype html><title>t</title><p class=keep id=k>k</p>"),
        );
        s.goto(&s.url("gen.test", "/")).await;
        s.eval("(() => { const d = document.createElement('div'); d.className='dyn-ad'; d.id='d1'; d.textContent='x'; document.body.appendChild(d); return 1; })()").await;
        s.wait_for(
            "dynamic ad hidden",
            "getComputedStyle(document.getElementById('d1')).display === 'none'",
        )
        .await;
        // A second element added later also gets handled (observer keeps running).
        s.eval("(() => { const d = document.createElement('div'); d.className='dyn-ad2'; d.id='d2'; document.body.appendChild(d); return 1; })()").await;
        s.wait_for(
            "second ad hidden",
            "getComputedStyle(document.getElementById('d2')).display === 'none'",
        )
        .await;
        assert_eq!(s.display("#k").await, "block");
        assert!(
            s.origin.requests_for("/__adblock__/cc").is_empty(),
            "beacon must be answered by the proxy"
        );
        let loads = s.internal_loads().await;
        assert!(
            loads
                .iter()
                .any(|(p, st)| p == "/__adblock__/cc" && *st == 200),
            "{loads:?}"
        );
        s.assert_clean().await;
    }
);

browser_test!(
    procedural_has_text_and_upward,
    [
        "proc.test##.box:has-text(Sponsored)",
        "proc.test##span.mark:upward(2)"
    ],
    |s| {
        s.origin.route("/", MockResponse::html(
        "<!doctype html><title>t</title><div class=box id=b1>Sponsored link</div><div class=box id=b2>Plain</div>\
         <section id=g><div id=mid><span class=mark>m</span></div></section><div id=other>o</div>"));
        s.goto(&s.url("proc.test", "/")).await;
        s.wait_for(
            "has-text applied",
            "getComputedStyle(document.getElementById('b1')).display === 'none'",
        )
        .await;
        assert_eq!(s.display("#b2").await, "block");
        s.wait_for(
            "upward applied",
            "getComputedStyle(document.getElementById('g')).display === 'none'",
        )
        .await;
        assert_eq!(s.display("#other").await, "block");
        s.assert_clean().await;
    }
);

// ---- scriptlet ordering -------------------------------------------------------------------------

browser_test!(
    scriptlet_runs_before_first_inline_script,
    [SCRIPTLET],
    |s| {
        s.origin.route("/", MockResponse::html(
        "<!doctype html><html><head><script>window.__early=String(typeof foo==='undefined'?'undef':foo)</script>\
         <title>t</title></head><body><script>window.__late=String(typeof foo==='undefined'?'undef':foo)</script></body></html>"));
        s.goto(&s.url("csp.test", "/")).await;
        assert_eq!(
            s.eval("window.__early").await,
            "42",
            "scriptlet must run before the page's first inline script"
        );
        assert_eq!(s.eval("window.__late").await, "42");
        s.assert_clean().await;
    }
);

// ---- CSP matrix --------------------------------------------------------------------------------

struct Case {
    headers: Vec<&'static str>,
    report_only: Vec<&'static str>,
    meta: Option<&'static str>,
    /// Page script placement: `nonce-N`, `inline`, `external`, or `none`.
    script: &'static str,
    /// Scripts (scriptlet) are expected to work.
    scriptlet: bool,
}

fn csp_page(c: &Case) -> String {
    let probe = "(window.__ran=window.__ran||[]).push('PLACE');\
                 (window.__foo=window.__foo||[]).push(String(typeof foo==='undefined'?'undef':foo));";
    let meta = c
        .meta
        .map(|m| format!("<meta http-equiv=\"Content-Security-Policy\" content=\"{m}\">"))
        .unwrap_or_default();
    let script = match c.script {
        "nonce" => format!(
            "<script nonce=\"N0\">{}</script>",
            probe.replace("PLACE", "inline")
        ),
        "inline" => format!("<script>{}</script>", probe.replace("PLACE", "inline")),
        "external" => "<script src=\"/page.js\"></script>".to_string(),
        "external-nonce" => "<script src=\"/page.js\" nonce=\"N0\"></script>".to_string(),
        _ => String::new(),
    };
    format!("<!doctype html><html><head><title>t</title>{meta}</head><body><div class=\"ad\" id=\"a1\">AD</div><p id=t>text</p>{script}</body></html>")
}

async fn csp_case(s: &Session, c: Case) {
    let mut page = MockResponse::html(csp_page(&c));
    for h in &c.headers {
        page = page.header("content-security-policy", h);
    }
    for h in &c.report_only {
        page = page.header("content-security-policy-report-only", h);
    }
    let js = "(window.__ran=window.__ran||[]).push('external');(window.__foo=window.__foo||[]).push(String(typeof foo==='undefined'?'undef':foo));";
    s.origin.route("/page", page);
    s.origin.route(
        "/page.js",
        MockResponse::ok(js).header("content-type", "application/javascript"),
    );

    // Reference: the same response, no proxy.
    s.goto(&s.direct_url("/page")).await;
    s.wait_for("direct load", "document.readyState==='complete'")
        .await;
    let direct_ran = s.eval("JSON.stringify(window.__ran||null)").await;

    s.goto(&s.url("csp.test", "/page")).await;
    let ran = s.eval("JSON.stringify(window.__ran||null)").await;
    assert_eq!(
        ran, direct_ran,
        "page's own scripts must behave as without the proxy"
    );
    assert_eq!(
        s.display("#a1").await,
        "none",
        "cosmetic rule must still apply"
    );
    if c.scriptlet && c.script != "none" {
        assert_eq!(
            s.eval("JSON.stringify(window.__foo)").await,
            "[\"42\"]",
            "scriptlet must run before page script"
        );
    }
    if c.scriptlet {
        s.wait_for("boot loaded", "performance.getEntriesByType('resource').some(e => e.name.includes('/__adblock__/boot.') && e.responseStatus === 200)").await;
    }
    s.assert_clean().await;
}

macro_rules! csp_test {
    ($name:ident, $case:expr) => {
        browser_test!($name, [COSMETIC, SCRIPTLET], |s| {
            csp_case(&s, $case).await;
        });
    };
}

csp_test!(
    csp_script_src_nonce,
    Case {
        headers: vec!["script-src 'nonce-N0'"],
        report_only: vec![],
        meta: None,
        script: "nonce",
        scriptlet: true
    }
);
csp_test!(
    csp_script_src_self,
    Case {
        headers: vec!["script-src 'self'"],
        report_only: vec![],
        meta: None,
        script: "external",
        scriptlet: true
    }
);
csp_test!(
    csp_script_src_unsafe_inline,
    Case {
        headers: vec!["script-src 'unsafe-inline'"],
        report_only: vec![],
        meta: None,
        script: "inline",
        scriptlet: true
    }
);
csp_test!(
    csp_strict_dynamic_nonce,
    Case {
        headers: vec!["script-src 'strict-dynamic' 'nonce-N0'"],
        report_only: vec![],
        meta: None,
        script: "nonce",
        scriptlet: true
    }
);
csp_test!(
    csp_default_src_none,
    Case {
        headers: vec!["default-src 'none'"],
        report_only: vec![],
        meta: None,
        script: "none",
        scriptlet: true
    }
);
csp_test!(
    csp_two_headers,
    Case {
        headers: vec![
            "script-src 'self' 'nonce-N0'",
            "script-src 'nonce-N0'; style-src 'self'"
        ],
        report_only: vec![],
        meta: None,
        script: "nonce",
        scriptlet: true
    }
);
csp_test!(
    csp_meta_policy,
    Case {
        headers: vec![],
        report_only: vec![],
        meta: Some("script-src 'nonce-N0'; style-src 'self'"),
        script: "nonce",
        scriptlet: true
    }
);
csp_test!(csp_trusted_types, Case { headers: vec!["script-src 'self' 'nonce-N0'; require-trusted-types-for 'script'; trusted-types mypolicy"], report_only: vec![], meta: None, script: "nonce", scriptlet: true });
csp_test!(
    csp_sandbox_css_only,
    Case {
        headers: vec!["sandbox allow-same-origin"],
        report_only: vec![],
        meta: None,
        script: "none",
        scriptlet: false
    }
);
csp_test!(
    csp_report_only_untouched,
    Case {
        headers: vec![],
        report_only: vec!["default-src 'none'; script-src 'nonce-N0'"],
        meta: None,
        script: "nonce",
        scriptlet: true
    }
);

browser_test!(csp_report_only_header_is_not_modified, [COSMETIC], |s| {
    let ro = "default-src 'none'; script-src 'nonce-N0'";
    s.origin.route(
        "/",
        MockResponse::html("<!doctype html><title>t</title>")
            .header("content-security-policy-report-only", ro),
    );
    s.goto(&s.url("csp.test", "/")).await;
    let h = s
        .eval(
            "fetch(location.href).then(r => r.headers.get('content-security-policy-report-only'))",
        )
        .await;
    assert_eq!(h, ro);
});

// ---- COEP ------------------------------------------------------------------------------------------

browser_test!(
    coep_require_corp_loads_our_resources,
    [COSMETIC, SCRIPTLET, "##.dyn-ad"],
    |s| {
        s.origin.route(
            "/",
            MockResponse::html("<!doctype html><title>t</title><div class=ad id=a1>x</div>")
                .header("cross-origin-embedder-policy", "require-corp")
                .header("cross-origin-opener-policy", "same-origin"),
        );
        s.goto(&s.url("csp.test", "/")).await;
        assert_eq!(s.eval("window.crossOriginIsolated").await, true);
        assert_eq!(s.display("#a1").await, "none");
        s.eval("(() => { const d = document.createElement('div'); d.className='dyn-ad'; d.id='d1'; document.body.appendChild(d); return 1; })()").await;
        s.wait_for(
            "dynamic hide under COEP",
            "getComputedStyle(document.getElementById('d1')).display === 'none'",
        )
        .await;
        s.wait_for("scriptlet under COEP", "String(window.foo) === '42'")
            .await;
        s.assert_clean().await;
    }
);

// ---- iframes ---------------------------------------------------------------------------------------

browser_test!(
    iframe_cross_origin_gets_own_cosmetics,
    ["top.test##.ad", "frame.test##.fad"],
    |s| {
        s.origin.route("/top", MockResponse::html(format!(
        "<!doctype html><title>t</title><div class=ad id=a>x</div><script>window.__msgs=[];addEventListener('message',e=>{{if(e.data&&e.data.fad)window.__msgs.push(e.data.fad)}})</script>\
         <iframe src='{}/f'></iframe>", s.base("frame.test"))));
        s.origin.route("/f", MockResponse::html(
        "<!doctype html><title>f</title><div class=fad id=f>x</div><div class=ad id=g>y</div>\
         <script>parent.postMessage({fad:[getComputedStyle(document.getElementById('f')).display,getComputedStyle(document.getElementById('g')).display]},'*')</script>"));
        s.goto(&s.url("top.test", "/top")).await;
        s.wait_for("frame reported", "window.__msgs.length > 0")
            .await;
        assert_eq!(
            s.eval("JSON.stringify(window.__msgs[0])").await,
            "[\"none\",\"block\"]",
            "frame: its own rule hides .fad, top's rule must not apply"
        );
        assert_eq!(s.display("#a").await, "none");
        s.assert_clean().await;
    }
);

browser_test!(iframe_srcdoc_and_about_blank, [COSMETIC], |s| {
    s.origin.route("/", MockResponse::html(
        "<!doctype html><title>t</title><div class=ad id=a1>x</div><iframe id=s srcdoc=\"<p id=x>hi</p>\"></iframe><iframe id=b></iframe>"));
    s.goto(&s.url("csp.test", "/")).await;
    s.wait_for(
        "srcdoc loaded",
        "!!document.getElementById('s').contentDocument.getElementById('x')",
    )
    .await;
    assert_eq!(
        s.eval("document.getElementById('s').contentDocument.getElementById('x').textContent")
            .await,
        "hi"
    );
    assert_eq!(
        s.eval("!!document.getElementById('b').contentDocument")
            .await,
        true
    );
    assert_eq!(s.display("#a1").await, "none");
    s.assert_clean().await;
});

// ---- encodings and compression ---------------------------------------------------------------------

const JP: &str = "日本語のテスト ページ";

async fn compare_with_direct(s: &Session, path: &str) -> (String, String) {
    s.goto(&s.direct_url(path)).await;
    let direct = s
        .eval("document.body.innerText")
        .await
        .as_str()
        .unwrap()
        .to_string();
    s.goto(&s.url("enc.test", path)).await;
    let proxied = s
        .eval("document.body.innerText")
        .await
        .as_str()
        .unwrap()
        .to_string();
    (direct, proxied)
}

browser_test!(encoding_shift_jis, ["enc.test##.ad"], |s| {
    let html = format!("<!doctype html><html><head><meta charset=\"shift_jis\"><title>t</title></head><body><div class=ad>AD</div><p>{JP}</p></body></html>");
    let (bytes, _, _) = encoding_rs::SHIFT_JIS.encode(&html);
    s.origin.route(
        "/sj",
        MockResponse::ok(bytes.into_owned()).header("content-type", "text/html; charset=shift_jis"),
    );
    let (direct, proxied) = compare_with_direct(&s, "/sj").await;
    assert!(direct.contains(JP), "reference load wrong: {direct:?}");
    assert!(proxied.contains(JP), "proxied text {proxied:?}");
    assert_eq!(s.display(".ad").await, "none");
    s.assert_clean().await;
});

browser_test!(encoding_utf16, ["enc.test##.ad"], |s| {
    let html = format!("<!doctype html><html><head><title>t</title></head><body><div class=ad>AD</div><p>{JP}</p></body></html>");
    let mut bytes = vec![0xff, 0xfe];
    for u in html.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    s.origin.route(
        "/u16",
        MockResponse::ok(bytes).header("content-type", "text/html; charset=utf-16"),
    );
    let (direct, proxied) = compare_with_direct(&s, "/u16").await;
    assert!(direct.contains(JP), "reference load wrong: {direct:?}");
    assert!(proxied.contains(JP), "proxied text {proxied:?}");
    assert_eq!(s.display(".ad").await, "none");
    s.assert_clean().await;
});

async fn compressed(s: &Session, coding: Coding) {
    let html = format!("<!doctype html><title>t</title><div class=ad>AD</div><p>{JP}</p>");
    let body = encode(coding, html.as_bytes()).await;
    s.origin.route(
        "/z",
        MockResponse::ok(body)
            .header("content-type", "text/html; charset=utf-8")
            .header("content-encoding", coding.token()),
    );
    s.goto(&s.url("enc.test", "/z")).await;
    assert!(s
        .eval("document.body.innerText")
        .await
        .as_str()
        .unwrap()
        .contains(JP));
    assert_eq!(s.display(".ad").await, "none", "page must be rewritten");
    s.assert_clean().await;
}

browser_test!(compression_zstd, ["enc.test##.ad"], |s| {
    compressed(&s, Coding::Zstd).await;
});
browser_test!(compression_brotli, ["enc.test##.ad"], |s| {
    compressed(&s, Coding::Br).await;
});

// ---- websocket ---------------------------------------------------------------------------------------

browser_test!(websocket_echo_over_wss, [], |s| {
    s.origin
        .route("/", MockResponse::html("<!doctype html><title>t</title>"));
    s.goto(&s.url("ws.test", "/")).await;
    let url = s.ws_url("ws.test", "/ws");
    let js = format!("new Promise((res, rej) => {{ const w = new WebSocket('{url}'); w.onopen = () => w.send('ping-1'); \
        w.onmessage = e => {{ res(e.data); w.close(); }}; w.onerror = () => rej(new Error('ws error')); }})");
    assert_eq!(s.eval(&js).await, "ping-1");
    s.assert_clean().await;
});

// ---- /__adblock__/ abuse ----------------------------------------------------------------------------------

browser_test!(internal_endpoints_not_usable_cross_origin, [], |s| {
    s.origin
        .route("/", MockResponse::html("<!doctype html><title>t</title>"));
    s.goto(&s.url("evil.test", "/")).await;
    let victim = s.base("victim.test");
    let js = format!(
        "(async () => {{ const out = {{}};
          for (const [k, init, p] of [
            ['cc_json', {{method:'POST', headers:{{'content-type':'application/json'}}, body:'{{\"url\":\"https://victim.test/\",\"classes\":[\"a\"],\"ids\":[]}}'}}, '/__adblock__/cc'],
            ['cc_plain', {{method:'POST', headers:{{'content-type':'text/plain'}}, body:'x'}}, '/__adblock__/cc'],
            ['boot_get', {{}}, '/__adblock__/boot.js'],
            ['scriptlet', {{}}, '/__adblock__/s/abc.js']]) {{
            try {{ const r = await fetch('{victim}' + p, init); out[k] = 'readable:' + r.status; }} catch (e) {{ out[k] = 'blocked'; }}
          }}
          return JSON.stringify(out); }})()");
    let v: serde_json::Value = serde_json::from_str(s.eval(&js).await.as_str().unwrap()).unwrap();
    for k in ["cc_json", "cc_plain", "boot_get", "scriptlet"] {
        assert_eq!(v[k], "blocked", "cross-origin page must not read {k}: {v}");
    }
    assert!(s.origin.requests_for("/__adblock__/cc").is_empty());
});

browser_test!(beacon_rejects_bad_token_same_origin, ["##.dyn-ad"], |s| {
    s.origin
        .route("/", MockResponse::html("<!doctype html><title>t</title>"));
    s.goto(&s.url("tok.test", "/")).await;
    let st = s.eval("fetch('/__adblock__/cc', {method:'POST', headers:{'content-type':'application/json','x-adblock-token':'bad'}, body: JSON.stringify({url: location.href, classes:['dyn-ad'], ids:[]})}).then(r => r.status)").await;
    assert!(st.as_i64().unwrap() >= 400, "forged token accepted: {st}");
});

// ---- transparent mode ------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_mode_smoke() {
    let Some(s) = Session::start_mode(EntryMode::Transparent, &[COSMETIC, SCRIPTLET]).await else {
        return;
    };
    s.origin.route("/", MockResponse::html("<!doctype html><title>t</title><div class=ad id=a1>x</div><script>window.__f=String(typeof foo==='undefined'?'undef':foo)</script>"));
    s.goto(&s.url("csp.test", "/")).await;
    assert_eq!(s.display("#a1").await, "none");
    assert_eq!(s.eval("window.__f").await, "42");
    s.assert_clean().await;
    s.finish().await;
}

// ---- the converted uBO library ---------------------------------------------------------------------

/// Uses the repo's bundled uBO snapshot unmodified. Fails today because the converter truncates
/// `validate-constant.fn` (see KNOWN_FAILING in the crate root).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bundled_ubo_set_constant_runs() {
    let Some(s) = Session::start_full(EntryMode::Explicit, &[SCRIPTLET], Resources::Bundled).await
    else {
        return;
    };
    run_known("bundled_ubo_set_constant_runs", async move {
        s.origin.route("/", MockResponse::html("<!doctype html><title>t</title><script>window.__f=String(typeof foo==='undefined'?'undef':foo)</script>"));
        s.goto(&s.url("csp.test", "/")).await;
        assert_eq!(s.eval("window.__f").await, "42");
        s.assert_clean().await;
        s.finish().await;
    })
    .await;
}

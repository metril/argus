//! Userscript delivery and the GM backend through the real proxy: bundles are served by the
//! proxy and never reach the origin, tokens are required and bound, `@connect` and the
//! destination policy are enforced server-side, and per-document state is bounded.

use std::time::Duration;

use e2e::{e2e_test, EntryMode, HttpVersion, MockResponse, TestClient, TestEnv};
use serde_json::{json, Value};
use userscript_engine::token::{self, TokenClaims};

const PAGE: &str = "<!doctype html><html><head><title>t</title></head><body>hi</body></html>";

fn script(name: &str, extra: &str) -> String {
    format!(
        "// ==UserScript==\n// @name {name}\n// @namespace e2e\n// @version 1.0\n// @match *://app.test/*\n// @run-at document-start\n{extra}\n// ==/UserScript==\nwindow.__{name} = 1;\n"
    )
}

/// `https://host:port` of the test origin, as the page's `Origin` header would spell it.
fn origin_of(env: &TestEnv, host: &str) -> String {
    let u = env.origin.https_url(host, "/");
    u.trim_end_matches('/').to_string()
}

async fn load_page(env: &TestEnv, c: &TestClient, host: &str, path: &str) -> String {
    env.origin.route(path, MockResponse::html(PAGE));
    let r = c
        .request(reqwest::Method::GET, &env.origin.https_url(host, path))
        .header("sec-fetch-dest", "document")
        .header("accept", "text/html")
        .send()
        .await
        .expect("page");
    assert_eq!(r.status(), 200);
    r.text().await.unwrap()
}

fn srcs(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(i) = rest.find("/__adblock__/us/") {
        let tail = &rest[i..];
        let end = tail.find('"').expect("quote");
        out.push(tail[..end].to_string());
        rest = &tail[end..];
    }
    out
}

async fn fetch_bundle(env: &TestEnv, c: &TestClient, host: &str, src: &str) -> reqwest::Response {
    let u = env.origin.https_url(host, src);
    c.request(reqwest::Method::GET, &u)
        .header("sec-fetch-site", "same-origin")
        .header("sec-fetch-dest", "script")
        .send()
        .await
        .expect("bundle")
}

fn token_in(js: &str) -> String {
    let i = js.find("\"token\":\"").expect("token") + 9;
    js[i..i + js[i..].find('"').unwrap()].to_string()
}

/// Load the page, fetch bundle `n`, and return its token.
async fn token_for(env: &TestEnv, c: &TestClient, host: &str, path: &str, n: usize) -> String {
    let html = load_page(env, c, host, path).await;
    let s = srcs(&html);
    let b = fetch_bundle(env, c, host, &s[n]).await;
    assert_eq!(b.status(), 200);
    token_in(&b.text().await.unwrap())
}

async fn gm(
    env: &TestEnv,
    c: &TestClient,
    host: &str,
    route: &str,
    tok: Option<&str>,
    origin: Option<&str>,
    body: Value,
) -> (u16, Value) {
    let u = env
        .origin
        .https_url(host, &format!("/__adblock__/gm/v1/{route}"));
    let mut rb = c
        .request(reqwest::Method::POST, &u)
        .header("content-type", "application/json")
        .header("sec-fetch-site", "same-origin")
        .body(body.to_string());
    if let Some(t) = tok {
        rb = rb.header("x-gm-token", t);
    }
    if let Some(o) = origin {
        rb = rb.header("origin", o);
    }
    let r = rb.send().await.expect("gm call");
    let st = r.status().as_u16();
    (st, r.json().await.unwrap_or(Value::Null))
}

/// Decode `type|len|payload` frames.
fn frames(mut b: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    while b.len() >= 5 {
        let n = u32::from_be_bytes([b[1], b[2], b[3], b[4]]) as usize;
        out.push((b[0], b[5..5 + n].to_vec()));
        b = &b[5 + n..];
    }
    out
}

async fn xhr(
    env: &TestEnv,
    c: &TestClient,
    tok: &str,
    origin: &str,
    meta: Value,
    body: &[u8],
) -> (u16, String, Vec<u8>) {
    let m = meta.to_string();
    let mut payload = (m.len() as u32).to_be_bytes().to_vec();
    payload.extend_from_slice(m.as_bytes());
    payload.extend_from_slice(body);
    let u = env.origin.https_url("app.test", "/__adblock__/gm/v1/xhr");
    let r = c
        .request(reqwest::Method::POST, &u)
        .header("content-type", "application/x-gm-frame")
        .header("sec-fetch-site", "same-origin")
        .header("origin", origin)
        .header("x-gm-token", tok)
        .body(payload)
        .send()
        .await
        .expect("xhr");
    let st = r.status().as_u16();
    let ct = r
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    (st, ct, r.bytes().await.unwrap().to_vec())
}

fn find_frame(fs: &[(u8, Vec<u8>)], t: u8) -> Option<Value> {
    fs.iter()
        .find(|(k, _)| *k == t)
        .and_then(|(_, p)| serde_json::from_slice(p).ok())
}

e2e_test!(
    bundles_are_served_by_the_proxy_once_and_never_reach_the_origin,
    rules = [],
    |env| {
        env.proxy.install_userscript(&script(
            "one",
            "// @grant GM_getValue\n// @grant GM_setValue",
        ));
        env.proxy
            .install_userscript(&script("two", "// @grant none"));
        for v in [HttpVersion::Http1, HttpVersion::Http2] {
            let c = env.client_with(v);
            let html = load_page(&env, &c, "app.test", "/p").await;
            let s = srcs(&html);
            assert_eq!(s.len(), 2, "one bundle per script: {html}");
            assert!(!html.contains("v1."), "no token in the markup");
            assert!(
                html.find("/__adblock__/us/").unwrap() < html.find("<body").unwrap(),
                "in <head>"
            );
            let b = fetch_bundle(&env, &c, "app.test", &s[0]).await;
            assert_eq!(b.status(), 200);
            let h = b.headers().clone();
            assert_eq!(h["cache-control"], "no-store");
            assert_eq!(h["x-content-type-options"], "nosniff");
            assert!(h["content-type"].to_str().unwrap().contains("javascript"));
            let js = b.text().await.unwrap();
            assert!(js.contains("window.__one = 1"), "script body present");
            assert!(js.contains("\"token\":\"v1."), "token in the body only");
            assert_eq!(
                fetch_bundle(&env, &c, "app.test", &s[0]).await.status(),
                404,
                "single use"
            );
            // The second script's bundle is independent of the first.
            assert_eq!(
                fetch_bundle(&env, &c, "app.test", &s[1]).await.status(),
                200
            );
        }
        assert!(
            env.origin
                .requests()
                .iter()
                .all(|r| !r.path_and_query.contains("__adblock__")),
            "internal endpoints never reach the origin: {:?}",
            env.origin.requests()
        );
    }
);

e2e_test!(
    non_matching_pages_and_subframes_get_nothing,
    rules = [],
    |env| {
        env.proxy
            .install_userscript(&script("nf", "// @noframes\n// @grant none"));
        let c = env.client();
        env.origin.route("/f", MockResponse::html(PAGE));
        let frame = c
            .request(
                reqwest::Method::GET,
                &env.origin.https_url("app.test", "/f"),
            )
            .header("sec-fetch-dest", "iframe")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(srcs(&frame).is_empty(), "@noframes: {frame}");
        let other = load_page(&env, &c, "other.test", "/o").await;
        assert!(srcs(&other).is_empty(), "@match: {other}");
        assert!(!other.contains("__adblock__/us"));
        assert_eq!(
            srcs(&load_page(&env, &c, "app.test", "/top").await).len(),
            1
        );
    }
);

e2e_test!(
    tokens_are_required_and_bound_to_origin_script_profile_and_time,
    rules = [],
    |env| {
        let a = env.proxy.install_userscript(&script(
            "a",
            "// @grant GM_getValue\n// @grant GM_setValue\n// @grant GM_listValues",
        ));
        let b_id = env
            .proxy
            .install_userscript(&script("b", "// @grant GM_getValue\n// @grant GM_setValue"));
        let c = env.client();
        let origin = origin_of(&env, "app.test");
        let html = load_page(&env, &c, "app.test", "/t").await;
        let s = srcs(&html);
        let ta = token_in(
            &fetch_bundle(&env, &c, "app.test", &s[0])
                .await
                .text()
                .await
                .unwrap(),
        );
        let tb = token_in(
            &fetch_bundle(&env, &c, "app.test", &s[1])
                .await
                .text()
                .await
                .unwrap(),
        );
        let get = json!({"names": null});

        let (st, v) = gm(
            &env,
            &c,
            "app.test",
            "values/get",
            Some(&ta),
            Some(&origin),
            get.clone(),
        )
        .await;
        assert_eq!((st, &v["ok"]), (200, &json!(true)), "{v}");
        // missing / garbage / tampered
        for t in [None, Some("garbage"), Some("v1.YQ.9999999999.AAAA")] {
            let (st, _) = gm(
                &env,
                &c,
                "app.test",
                "values/get",
                t,
                Some(&origin),
                get.clone(),
            )
            .await;
            assert_eq!(st, 401, "{t:?}");
        }
        let mut tampered = ta.clone();
        tampered.pop();
        tampered.push(if ta.ends_with('A') { 'B' } else { 'A' });
        assert_eq!(
            gm(
                &env,
                &c,
                "app.test",
                "values/get",
                Some(&tampered),
                Some(&origin),
                get.clone()
            )
            .await
            .0,
            401
        );
        // wrong origin header, no origin, null origin, cross-site fetch metadata
        for o in [Some("https://evil.test"), Some("null"), None] {
            let (st, _) = gm(
                &env,
                &c,
                "app.test",
                "values/get",
                Some(&ta),
                o,
                get.clone(),
            )
            .await;
            assert_eq!(st, 403, "{o:?}");
        }
        // the token is bound to the origin: replay on another host (Origin matching that host)
        let other_origin = origin_of(&env, "other.test");
        let (st, _) = gm(
            &env,
            &c,
            "other.test",
            "values/get",
            Some(&ta),
            Some(&other_origin),
            get.clone(),
        )
        .await;
        assert_eq!(st, 401, "token minted for app.test");
        // another script's token with the claimed id swapped
        {
            use base64::Engine as _;
            let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            let parts: Vec<&str> = tb.split('.').collect();
            let swapped = format!("v1.{}.{}.{}", enc.encode(&a), parts[2], parts[3]);
            assert_eq!(
                gm(
                    &env,
                    &c,
                    "app.test",
                    "values/get",
                    Some(&swapped),
                    Some(&origin),
                    get.clone()
                )
                .await
                .0,
                401
            );
            let _ = b_id;
        }
        // expired and other-profile tokens, minted with the real key
        let m = env.proxy.userscripts();
        let key = m.token_key();
        let rec = m.live_index().get(&a).unwrap().script.clone();
        let caps = token::caps_hash(&rec.metadata, rec.allow_connect_all);
        let mint = |profile: &str, exp: u64| {
            token::mint(
                key,
                &TokenClaims {
                    profile,
                    script_id: &a,
                    script_version: rec.metadata.version.as_deref().unwrap_or(""),
                    origin: &origin,
                    caps_hash: &caps,
                    exp,
                },
            )
        };
        let future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;
        assert_eq!(
            gm(
                &env,
                &c,
                "app.test",
                "values/get",
                Some(&mint("default", future)),
                Some(&origin),
                get.clone()
            )
            .await
            .0,
            200
        );
        assert_eq!(
            gm(
                &env,
                &c,
                "app.test",
                "values/get",
                Some(&mint("default", 5)),
                Some(&origin),
                get.clone()
            )
            .await
            .0,
            401,
            "expired"
        );
        assert_eq!(
            gm(
                &env,
                &c,
                "app.test",
                "values/get",
                Some(&mint("other", future)),
                Some(&origin),
                get.clone()
            )
            .await
            .0,
            401,
            "other profile"
        );
        // editing the script (new version) invalidates old tokens
        let mut edited = m.get(&a).unwrap().source.clone();
        edited = edited.replace("@version 1.0", "@version 1.1");
        m.update(&a, edited).unwrap();
        assert_eq!(
            gm(
                &env,
                &c,
                "app.test",
                "values/get",
                Some(&ta),
                Some(&origin),
                get.clone()
            )
            .await
            .0,
            401,
            "edited script"
        );
        // preflight is never answered
        let u = env
            .origin
            .https_url("app.test", "/__adblock__/gm/v1/values/get");
        let pre = c
            .request(reqwest::Method::OPTIONS, &u)
            .header("origin", "https://evil.test")
            .header("access-control-request-method", "POST")
            .header("access-control-request-headers", "x-gm-token,content-type")
            .send()
            .await
            .unwrap();
        assert!(pre.headers().get("access-control-allow-origin").is_none());
        assert_eq!(pre.status(), 403);
        assert!(env
            .origin
            .requests()
            .iter()
            .all(|r| !r.path_and_query.contains("__adblock__")));
    }
);

e2e_test!(
    values_roundtrip_grants_and_quotas_are_enforced_by_the_server,
    rules = [],
    |env| {
        env.proxy.install_userscript(&script(
            "rw",
            "// @grant GM_getValue\n// @grant GM_setValue",
        ));
        env.proxy
            .install_userscript(&script("ro", "// @grant GM_getValue"));
        let c = env.client();
        let origin = origin_of(&env, "app.test");
        let html = load_page(&env, &c, "app.test", "/v").await;
        let s = srcs(&html);
        // install order: ro installed second but both run-at start: install order = rw, ro
        let t0 = token_in(
            &fetch_bundle(&env, &c, "app.test", &s[0])
                .await
                .text()
                .await
                .unwrap(),
        );
        let t1 = token_in(
            &fetch_bundle(&env, &c, "app.test", &s[1])
                .await
                .text()
                .await
                .unwrap(),
        );
        let call = |t: &'static str, route: &'static str, body: Value| {
            let (env, c, origin) = (&env, &c, origin.clone());
            let t = t.to_string();
            async move { gm(env, c, "app.test", route, Some(&t), Some(&origin), body).await }
        };
        let _ = call;
        let (st, v) = gm(
            &env,
            &c,
            "app.test",
            "values/set",
            Some(&t0),
            Some(&origin),
            json!({"values": {"k": [1, 2]}, "src": "tab"}),
        )
        .await;
        assert_eq!(st, 200, "{v}");
        let (_, v) = gm(
            &env,
            &c,
            "app.test",
            "values/get",
            Some(&t0),
            Some(&origin),
            json!({"names": ["k"]}),
        )
        .await;
        assert_eq!(v["result"]["k"], json!([1, 2]));
        // isolated per script
        let (_, v) = gm(
            &env,
            &c,
            "app.test",
            "values/get",
            Some(&t1),
            Some(&origin),
            json!({"names": null}),
        )
        .await;
        assert_eq!(v["result"], json!({}), "{v}");
        // the read-only script cannot write, whatever the page claims
        let (st, v) = gm(
            &env,
            &c,
            "app.test",
            "values/set",
            Some(&t1),
            Some(&origin),
            json!({"values": {"k": 1}}),
        )
        .await;
        assert_eq!(
            (st, v["error"]["code"].as_str()),
            (403, Some("not_granted"))
        );
        // an ungranted API is refused even with a valid token
        let (st, _) = gm(
            &env,
            &c,
            "app.test",
            "cookie",
            Some(&t0),
            Some(&origin),
            json!({"op": "list", "url": "https://app.test/"}),
        )
        .await;
        assert_eq!(st, 403);
        // quotas: one value over the per-value cap, nothing written
        let big = "x".repeat(1 << 20);
        let (st, v) = gm(
            &env,
            &c,
            "app.test",
            "values/set",
            Some(&t0),
            Some(&origin),
            json!({"values": {"big": big}}),
        )
        .await;
        assert_eq!(
            (st, v["error"]["code"].as_str()),
            (413, Some("quota_exceeded"))
        );
        let (_, v) = gm(
            &env,
            &c,
            "app.test",
            "values/get",
            Some(&t0),
            Some(&origin),
            json!({"names": ["big"]}),
        )
        .await;
        assert_eq!(v["result"], json!({}));
        // request body cap
        let huge = "y".repeat(3 << 20);
        let (st, _) = gm(
            &env,
            &c,
            "app.test",
            "values/set",
            Some(&t0),
            Some(&origin),
            json!({"values": {"h": huge}}),
        )
        .await;
        assert_eq!(st, 413);
        // change log
        let (_, v) = gm(
            &env,
            &c,
            "app.test",
            "values/changes",
            Some(&t0),
            Some(&origin),
            json!({"since": 0}),
        )
        .await;
        assert_eq!(v["result"]["changes"][0]["name"], "k");
    }
);

e2e_test!(
    xhr_enforces_connect_redirects_and_the_destination_policy,
    rules = [],
    |env| {
        let id = env.proxy.install_userscript(&script(
            "net",
            "// @grant GM_xmlhttpRequest\n// @connect api.test",
        ));
        let _ = id;
        let c = env.client();
        let origin = origin_of(&env, "app.test");
        let tok = token_for(&env, &c, "app.test", "/x", 0).await;
        let evil = env.origin.https_url("evil.test", "/loot");
        env.origin
            .route("/data", MockResponse::ok("payload").header("x-extra", "1"));
        env.origin.route("/loot", MockResponse::ok("loot"));
        env.origin.route(
            "/hop",
            MockResponse {
                status: 302,
                ..MockResponse::ok("")
            }
            .header("location", &evil),
        );
        let ok_url = env.origin.https_url("api.test", "/data");

        // listed host: framed stream with head, data, end
        let (st, ct, body) = xhr(
            &env,
            &c,
            &tok,
            &origin,
            json!({"op": "xhr", "method": "GET", "url": ok_url, "headers": []}),
            b"",
        )
        .await;
        assert_eq!((st, ct.as_str()), (200, "application/x-gm-frames"));
        let fs = frames(&body);
        assert_eq!(find_frame(&fs, 1).unwrap()["status"], 200);
        let data: Vec<u8> = fs
            .iter()
            .filter(|(k, _)| *k == 2)
            .flat_map(|(_, p)| p.clone())
            .collect();
        assert_eq!(data, b"payload");
        assert!(find_frame(&fs, 3).is_some());
        // POST with a body and a custom header reaches the origin intact
        env.origin.route("/echo", MockResponse::ok("ok"));
        let (_, _, body) = xhr(&env, &c, &tok, &origin, json!({"op": "xhr", "method": "POST", "url": env.origin.https_url("api.test", "/echo"), "headers": [["X-Custom", "yes"], ["Content-Type", "text/plain"]]}), b"hello").await;
        assert!(find_frame(&frames(&body), 3).is_some());
        let rec = env.origin.requests_for("/echo");
        assert_eq!(rec.len(), 1);
        assert_eq!(rec[0].body, b"hello");
        assert!(rec[0]
            .headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case("x-custom") && v == "yes"));

        // not in @connect: refused before any upstream contact
        let (st, ct, body) = xhr(
            &env,
            &c,
            &tok,
            &origin,
            json!({"op": "xhr", "method": "GET", "url": evil, "headers": []}),
            b"",
        )
        .await;
        assert_eq!((st, ct.as_str()), (403, "application/json"));
        assert!(String::from_utf8_lossy(&body).contains("connect_denied"));
        // redirect from an allowed host to a non-allowed one: re-checked per hop
        let hop = env.origin.https_url("api.test", "/hop");
        let (st, _, body) = xhr(
            &env,
            &c,
            &tok,
            &origin,
            json!({"op": "xhr", "method": "GET", "url": hop, "headers": []}),
            b"",
        )
        .await;
        assert_eq!(st, 200);
        let fs = frames(&body);
        let e = find_frame(&fs, 4).expect("error frame");
        assert_eq!(e["kind"], "denied", "{e}");
        assert!(
            env.origin.requests_for("/loot").is_empty(),
            "the redirect target was never contacted"
        );
        // redirect: manual returns the 3xx itself
        let (_, _, body) = xhr(
            &env,
            &c,
            &tok,
            &origin,
            json!({"op": "xhr", "method": "GET", "url": hop, "headers": [], "redirect": "manual"}),
            b"",
        )
        .await;
        assert_eq!(find_frame(&frames(&body), 1).unwrap()["status"], 302);
        // other methods / schemes
        let (st, _, _) = xhr(
            &env,
            &c,
            &tok,
            &origin,
            json!({"op": "xhr", "method": "TRACE", "url": ok_url, "headers": []}),
            b"",
        )
        .await;
        assert_eq!(st, 400);
        let (st, _, _) = xhr(
            &env,
            &c,
            &tok,
            &origin,
            json!({"op": "xhr", "method": "GET", "url": "file:///etc/passwd", "headers": []}),
            b"",
        )
        .await;
        assert_eq!(st, 403);
    }
);

e2e_test!(
    xhr_never_reaches_loopback_even_with_connect_all_approved,
    rules = [],
    |env| {
        env.proxy.install_userscript_with(
            &script("star", "// @grant GM_xmlhttpRequest\n// @connect *"),
            Default::default(),
            true,
        );
        let c = env.client();
        let origin = origin_of(&env, "app.test");
        let tok = token_for(&env, &c, "app.test", "/l", 0).await;
        let port = env.origin.http_port();
        env.origin.route("/secret", MockResponse::ok("internal"));
        for host in [
            "127.0.0.1",
            "169.254.169.254",
            "[::1]",
            "[::ffff:127.0.0.1]",
        ] {
            let url = format!("http://{host}:{port}/secret");
            let (st, ct, body) = xhr(
                &env,
                &c,
                &tok,
                &origin,
                json!({"op": "xhr", "method": "GET", "url": url, "headers": []}),
                b"",
            )
            .await;
            assert_eq!((st, ct.as_str()), (403, "application/json"), "{host}");
            assert!(
                String::from_utf8_lossy(&body).contains("connect_denied"),
                "{host}"
            );
        }
        assert!(env.origin.requests_for("/secret").is_empty());
        // control: a public-looking address passes the policy and the (approved) @connect *
        let url = format!("http://{}:{port}/secret", e2e::PUBLIC_TEST_IP);
        let (st, _, body) = xhr(
            &env,
            &c,
            &tok,
            &origin,
            json!({"op": "xhr", "method": "GET", "url": url, "headers": []}),
            b"",
        )
        .await;
        assert_eq!(st, 200);
        assert_eq!(find_frame(&frames(&body), 1).unwrap()["status"], 200);
    }
);

e2e_test!(
    xhr_concurrency_is_capped_per_script,
    rules = [],
    explicit_only,
    |env| {
        env.proxy.install_userscript(&script(
            "slow",
            "// @grant GM_xmlhttpRequest\n// @connect api.test",
        ));
        let c = std::sync::Arc::new(env.client());
        let origin = origin_of(&env, "app.test");
        let tok = token_for(&env, &c, "app.test", "/s", 0).await;
        env.origin.route(
            "/slow",
            MockResponse::ok("z").delayed(Duration::from_millis(1500)),
        );
        let url = env.origin.https_url("api.test", "/slow");
        let env = std::sync::Arc::new(env);
        let mut hs = Vec::new();
        for _ in 0..12 {
            let (env, c, tok, origin, url) = (
                env.clone(),
                c.clone(),
                tok.clone(),
                origin.clone(),
                url.clone(),
            );
            hs.push(tokio::spawn(async move {
                xhr(
                    &env,
                    &c,
                    &tok,
                    &origin,
                    json!({"op": "xhr", "method": "GET", "url": url, "headers": []}),
                    b"",
                )
                .await
                .0
            }));
        }
        let mut codes = Vec::new();
        for h in hs {
            codes.push(h.await.unwrap());
        }
        let limited = codes.iter().filter(|c| **c == 429).count();
        assert!(
            limited >= 1 && codes.iter().filter(|c| **c == 200).count() >= 8,
            "{codes:?}"
        );
    }
);

e2e_test!(
    document_state_is_bounded_under_a_reload_storm,
    rules = [],
    explicit_only,
    |env| {
        env.proxy
            .install_userscript(&script("storm", "// @grant none"));
        let c = env.client();
        env.origin.route("/s", MockResponse::html(PAGE));
        let url = env.origin.https_url("app.test", "/s");
        for _ in 0..4300 {
            let r = c
                .request(reqwest::Method::GET, &url)
                .header("sec-fetch-dest", "document")
                .send()
                .await
                .unwrap();
            let _ = r.bytes().await;
        }
        let n = env.proxy.ctx.userscript_docs();
        assert!(n <= 4096, "{n} documents retained");
        assert!(n > 0);
    }
);

e2e_test!(
    resources_and_cookies_work_for_granted_scripts_only,
    rules = [],
    |env| {
        use userscript_engine::install::Fetched;
        let mut fetched = Fetched::default();
        fetched.resources.insert(
            "css".into(),
            (b"body{color:red}".to_vec(), Some("text/css".into())),
        );
        let src = script(
            "res",
            "// @grant GM_getResourceText\n// @grant GM_cookie\n// @connect app.test\n// @resource css https://cdn.test/a.css",
        );
        env.proxy.install_userscript_with(&src, fetched, false);
        let c = env.client();
        let origin = origin_of(&env, "app.test");
        let tok = token_for(&env, &c, "app.test", "/r", 0).await;
        let u = env
            .origin
            .https_url("app.test", "/__adblock__/gm/v1/resource?name=css");
        let r = c
            .request(reqwest::Method::GET, &u)
            .header("sec-fetch-site", "same-origin")
            .header("x-gm-token", &tok)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(r.text().await.unwrap(), "body{color:red}");
        // A token in the query string is not accepted.
        let q = env.origin.https_url(
            "app.test",
            &format!("/__adblock__/gm/v1/resource?name=css&t={tok}"),
        );
        let r = c
            .request(reqwest::Method::GET, &q)
            .header("sec-fetch-site", "same-origin")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401, "query tokens are refused");
        // cross-site GET is refused
        let r = c
            .request(reqwest::Method::GET, &u)
            .header("sec-fetch-site", "cross-site")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403);
        // cookie jar round trip, scoped to the profile's GM jar
        let cu = env.origin.https_url("app.test", "/");
        let (st, _) = gm(
            &env,
            &c,
            "app.test",
            "cookie",
            Some(&tok),
            Some(&origin),
            json!({"op": "set", "url": cu, "cookie": {"name": "k", "value": "v"}}),
        )
        .await;
        assert_eq!(st, 200);
        let (_, v) = gm(
            &env,
            &c,
            "app.test",
            "cookie",
            Some(&tok),
            Some(&origin),
            json!({"op": "list", "url": cu}),
        )
        .await;
        assert_eq!(v["result"][0]["value"], "v", "{v}");
        let _ = EntryMode::Explicit;
    }
);

/// A body that yields `n` chunks of 1 MiB (then pends forever if `stall`), counting consumption.
fn counted_body(
    consumed: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    chunks: usize,
    stall: bool,
) -> reqwest::Body {
    use std::sync::atomic::Ordering;
    let s = futures_util::stream::unfold(0usize, move |i| {
        let consumed = consumed.clone();
        async move {
            if i >= chunks {
                if stall {
                    futures_util::future::pending::<()>().await;
                }
                return None;
            }
            consumed.fetch_add(1 << 20, Ordering::SeqCst);
            Some((
                Ok::<_, std::io::Error>(bytes::Bytes::from(vec![0u8; 1 << 20])),
                i + 1,
            ))
        }
    });
    reqwest::Body::wrap_stream(s)
}

e2e_test!(
    gm_bodies_are_not_read_before_the_token_is_verified,
    rules = [],
    |env| {
        use std::sync::atomic::{AtomicUsize, Ordering};
        env.proxy.install_userscript(&script(
            "pre",
            "// @grant GM_xmlhttpRequest\n// @connect api.test",
        ));
        let c = env.client();
        let origin = origin_of(&env, "app.test");
        for (route, ct) in [
            ("xhr", "application/x-gm-frame"),
            ("values/get", "application/json"),
        ] {
            let consumed = std::sync::Arc::new(AtomicUsize::new(0));
            let u = env
                .origin
                .https_url("app.test", &format!("/__adblock__/gm/v1/{route}"));
            let r = c
                .request(reqwest::Method::POST, &u)
                .header("content-type", ct)
                .header("sec-fetch-site", "same-origin")
                .header("origin", &origin)
                .body(counted_body(consumed.clone(), 100, false))
                .send()
                .await;
            let seen = consumed.load(Ordering::SeqCst);
            if let Ok(r) = r {
                assert_eq!(r.status(), 401, "{route}");
            }
            assert!(
                seen <= 8 << 20,
                "{route}: {seen} bytes were pulled from a tokenless request"
            );
        }
    }
);

e2e_test!(
    gm_json_bodies_are_bounded_by_permits_and_a_byte_budget,
    rules = [],
    explicit_only,
    |env| {
        use std::sync::atomic::AtomicUsize;
        env.proxy
            .install_userscript(&script("bud", "// @grant GM_getValue"));
        let c = std::sync::Arc::new(env.client());
        let origin = origin_of(&env, "app.test");
        let tok = token_for(&env, &c, "app.test", "/b", 0).await;
        let u = env
            .origin
            .https_url("app.test", "/__adblock__/gm/v1/values/get");
        let mut hs = Vec::new();
        for _ in 0..40 {
            let (c, u, tok, origin) = (c.clone(), u.clone(), tok.clone(), origin.clone());
            hs.push(tokio::spawn(async move {
                let consumed = std::sync::Arc::new(AtomicUsize::new(0));
                let r = tokio::time::timeout(
                    Duration::from_secs(3),
                    c.request(reqwest::Method::POST, &u)
                        .header("content-type", "application/json")
                        .header("sec-fetch-site", "same-origin")
                        .header("origin", &origin)
                        .header("x-gm-token", &tok)
                        .body(counted_body(consumed, 1, true))
                        .send(),
                )
                .await;
                match r {
                    Ok(Ok(r)) => r.status().as_u16(),
                    _ => 0,
                }
            }));
        }
        let mut codes = Vec::new();
        for h in hs {
            codes.push(h.await.unwrap());
        }
        let limited = codes.iter().filter(|c| **c == 429).count();
        assert!(
            limited >= 8,
            "stalled bodies must hit the limits: {codes:?}"
        );
    }
);

e2e_test!(
    xhr_uploads_are_streamed_whole_and_capped,
    rules = [],
    |env| {
        env.proxy.install_userscript(&script(
            "up",
            "// @grant GM_xmlhttpRequest\n// @connect api.test",
        ));
        let c = env.client();
        let origin = origin_of(&env, "app.test");
        let tok = token_for(&env, &c, "app.test", "/u", 0).await;
        env.origin.route("/up", MockResponse::ok("ok"));
        let big = vec![7u8; 9 << 20];
        let meta = json!({"op": "xhr", "method": "POST", "url": env.origin.https_url("api.test", "/up"), "headers": [["Content-Type", "application/octet-stream"]]});
        let (_, _, body) = xhr(&env, &c, &tok, &origin, meta, &big).await;
        assert!(
            find_frame(&frames(&body), 3).is_some(),
            "{}",
            String::from_utf8_lossy(&body)
        );
        assert_eq!(env.origin.requests_for("/up")[0].body.len(), big.len());
        // Over the quota: refused before the origin sees a complete body.
        let huge = vec![1u8; (64 << 20) + 1024];
        let meta = json!({"op": "xhr", "method": "POST", "url": env.origin.https_url("api.test", "/up"), "headers": []});
        let (st, _, body) = xhr(&env, &c, &tok, &origin, meta, &huge).await;
        let txt = String::from_utf8_lossy(&body);
        assert!(
            st == 413 || st == 429 || txt.contains("quota") || txt.contains("too large"),
            "{st} {txt}"
        );
    }
);

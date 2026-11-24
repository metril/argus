//! The extension bridge through the real proxy: the session header binds a document and never
//! reaches the origin, the relay token is checked per hop and never forwarded, and credentialed
//! GM calls reach a fake extension only after every server-side check.

use std::time::Duration;

use api_types::{ExtIdent, ExtOut};
use e2e::{e2e_test, MockResponse, TestClient, TestEnv};
use proxy_core::ext_bridge::{
    job_frame, parse_job_frame, ExtHub, HubCtx, F_CANCEL, F_DATA, F_END, F_HEAD, F_JOB,
};
use serde_json::{json, Value};
use std::sync::Arc;
use userscript_engine::install::{finish_install, plan_install, Approvals, Fetched};

const PAGE: &str = "<!doctype html><html><head><title>t</title></head><body>hi</body></html>";

fn script(extra: &str, browser: bool) -> userscript_engine::Userscript {
    let src = format!(
        "// ==UserScript==\n// @name bridge\n// @namespace e2e\n// @version 1.0\n// @match *://app.test/*\n// @run-at document-start\n// @grant GM_xmlhttpRequest\n// @grant GM_cookie\n// @grant GM_registerMenuCommand\n// @connect api.test\n{extra}\n// ==/UserScript==\n1;\n"
    );
    finish_install(
        plan_install(&src, None).unwrap(),
        Fetched::default(),
        Approvals {
            allow_connect_all: false,
            browser_cookies: browser,
        },
    )
    .unwrap()
}

fn hub(env: &TestEnv) -> Arc<ExtHub> {
    let h = env.proxy.ctx.internal().gm.ext().clone();
    h.set_ctx(HubCtx {
        manager: env.proxy.userscripts(),
        profiles: None,
        bypass: env.proxy.ctx.bypass().clone(),
    });
    h
}

fn session(h: &ExtHub, token: &str) -> (u64, String, tokio::sync::mpsc::Receiver<ExtOut>) {
    h.open(ExtIdent {
        token_id: token.into(),
        user: "u".into(),
        profiles: None,
    })
}

async fn page(
    env: &TestEnv,
    c: &TestClient,
    host: &str,
    path: &str,
    sid: Option<&str>,
) -> (String, reqwest::header::HeaderMap) {
    env.origin.route(path, MockResponse::html(PAGE));
    let mut rb = c
        .request(reqwest::Method::GET, &env.origin.https_url(host, path))
        .header("sec-fetch-dest", "document")
        .header("accept", "text/html");
    if let Some(s) = sid {
        rb = rb.header("x-argus-ext", s);
    }
    let r = rb.send().await.expect("page");
    assert_eq!(r.status(), 200);
    let h = r.headers().clone();
    (r.text().await.unwrap(), h)
}

fn mdoc_of(h: &reqwest::header::HeaderMap) -> Option<String> {
    let v = h.get("server-timing")?.to_str().ok()?;
    let i = v.find("argus;desc=\"")? + 12;
    Some(v[i..i + v[i..].find('"')?].to_string())
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

fn value_in(js: &str, key: &str) -> String {
    let pat = format!("\"{key}\":\"");
    let i = js.find(&pat).expect(key) + pat.len();
    js[i..i + js[i..].find('"').unwrap()].to_string()
}

/// Load a bound page and take the script bundle's token and document id.
async fn bound_bundle(env: &TestEnv, c: &TestClient, sid: &str, path: &str) -> (String, String) {
    let (html, h) = page(env, c, "app.test", path, Some(sid)).await;
    assert!(html.contains("data-m=\"ext:"), "bound: {html}");
    let s = srcs(&html);
    let b = c
        .request(
            reqwest::Method::GET,
            &env.origin.https_url("app.test", &s[0]),
        )
        .header("sec-fetch-site", "same-origin")
        .header("sec-fetch-dest", "script")
        .send()
        .await
        .unwrap();
    let js = b.text().await.unwrap();
    let mdoc = value_in(&js, "mdoc");
    assert_eq!(Some(mdoc.clone()), mdoc_of(&h), "runtime and header agree");
    (value_in(&js, "token"), mdoc)
}

fn frames(mut b: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    while b.len() >= 5 {
        let n = u32::from_be_bytes([b[1], b[2], b[3], b[4]]) as usize;
        out.push((b[0], b[5..5 + n].to_vec()));
        b = &b[5 + n..];
    }
    out
}

async fn xhr(env: &TestEnv, c: &TestClient, tok: &str, meta: Value) -> (u16, Vec<(u8, Vec<u8>)>) {
    let m = meta.to_string();
    let mut payload = (m.len() as u32).to_be_bytes().to_vec();
    payload.extend_from_slice(m.as_bytes());
    let r = c
        .request(
            reqwest::Method::POST,
            &env.origin.https_url("app.test", "/__adblock__/gm/v1/xhr"),
        )
        .header("content-type", "application/x-gm-frame")
        .header("sec-fetch-site", "same-origin")
        .header(
            "origin",
            env.origin.https_url("app.test", "/").trim_end_matches('/'),
        )
        .header("x-gm-token", tok)
        .body(payload)
        .send()
        .await
        .expect("xhr");
    let st = r.status().as_u16();
    let framed = r
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("x-gm-frames"));
    let body = r.bytes().await.unwrap();
    // a refusal before streaming is a JSON error, not frames
    (
        st,
        if framed {
            frames(&body)
        } else {
            vec![(255, body.to_vec())]
        },
    )
}

async fn cookie(env: &TestEnv, c: &TestClient, tok: &str, body: Value) -> (u16, Value) {
    let r = c
        .request(
            reqwest::Method::POST,
            &env.origin
                .https_url("app.test", "/__adblock__/gm/v1/cookie"),
        )
        .header("content-type", "application/json")
        .header("sec-fetch-site", "same-origin")
        .header(
            "origin",
            env.origin.https_url("app.test", "/").trim_end_matches('/'),
        )
        .header("x-gm-token", tok)
        .body(body.to_string())
        .send()
        .await
        .expect("cookie");
    (r.status().as_u16(), r.json().await.unwrap_or(Value::Null))
}

async fn next_job(rx: &mut tokio::sync::mpsc::Receiver<ExtOut>) -> (u32, Value) {
    let Some(ExtOut::Binary(b)) = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("a job")
    else {
        panic!("expected a binary frame")
    };
    let (t, job, p) = parse_job_frame(&b).unwrap();
    assert_eq!(t, F_JOB);
    (job, serde_json::from_slice(p).unwrap())
}

fn no_more(rx: &mut tokio::sync::mpsc::Receiver<ExtOut>) -> bool {
    matches!(
        rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    )
}

e2e_test!(
    the_session_header_binds_the_document_and_never_reaches_the_origin,
    rules = [],
    explicit_only,
    |env| {
        env.proxy
            .userscripts()
            .install_script("default", script("", false))
            .unwrap();
        let h = hub(&env);
        let (sess, sid, _rx) = session(&h, "t1");
        let c = env.client();

        let (html, hd) = page(&env, &c, "app.test", "/p", Some(&sid)).await;
        assert!(html.contains("data-m=\"ext:"), "bound document: {html}");
        let mdoc = mdoc_of(&hd).expect("Server-Timing on a userscript document");
        assert!(
            h.menu(sess, &mdoc).is_ok(),
            "the document is bound to the session"
        );

        // an unknown or wrong sid binds nothing; the header is still stripped
        let (html2, hd2) = page(
            &env,
            &c,
            "app.test",
            "/q",
            Some("00000000000000000000000000000000"),
        )
        .await;
        assert!(!html2.contains("ext:"), "unknown sid: {html2}");
        let m2 = mdoc_of(&hd2).expect("still a userscript document");
        assert_eq!(h.menu(sess, &m2), Err(api_types::ExtError::Forbidden));
        let (html3, _) = page(&env, &c, "app.test", "/r", None).await;
        assert!(!html3.contains("ext:"));

        // no Server-Timing on a document without userscripts, or on a non-document
        let (_, other) = page(&env, &c, "other.test", "/o", Some(&sid)).await;
        assert!(other.get("server-timing").is_none());
        env.origin.route("/a.js", MockResponse::ok("1"));
        let r = c
            .request(
                reqwest::Method::GET,
                &env.origin.https_url("app.test", "/a.js"),
            )
            .header("x-argus-ext", &sid)
            .header("x-argus-relay", "whatever")
            .send()
            .await
            .unwrap();
        // an unknown relay token is refused (and never forwarded)
        assert_eq!(r.status(), 403);
        let r = c
            .request(
                reqwest::Method::GET,
                &env.origin.https_url("app.test", "/a.js"),
            )
            .header("x-argus-ext", &sid)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        assert!(r.headers().get("server-timing").is_none());

        for rq in env.origin.requests() {
            assert!(
                rq.headers.iter().all(|(n, _)| {
                    !n.eq_ignore_ascii_case("x-argus-ext")
                        && !n.eq_ignore_ascii_case("x-argus-relay")
                }),
                "bridge header reached the origin: {rq:?}"
            );
        }
    }
);

e2e_test!(
    relayed_fetches_are_rechecked_per_hop_and_the_token_is_never_forwarded,
    rules = [],
    explicit_only,
    |env| {
        let s = script("", true);
        let id = s.id.clone();
        env.proxy
            .userscripts()
            .install_script("default", s)
            .unwrap();
        let h = hub(&env);
        let (sess, _sid, mut rx) = session(&h, "t1");
        let _job = h
            .dispatch(sess, json!({"op": "xhr"}), "default", &id, "app.test", None)
            .await
            .unwrap();
        let (_, meta) = next_job(&mut rx).await;
        let relay = meta["relay"].as_str().unwrap().to_string();
        let c = env.client();
        env.origin.route("/ok", MockResponse::ok("fine"));
        env.origin.route("/bad", MockResponse::ok("never"));
        let get = |host: &'static str, path: &'static str, tok: String| {
            let rb = c
                .request(reqwest::Method::GET, &env.origin.https_url(host, path))
                .header("x-argus-relay", tok);
            async move { rb.send().await.unwrap() }
        };
        let r = get("api.test", "/ok", relay.clone()).await;
        assert_eq!(r.status(), 200);
        assert_eq!(r.text().await.unwrap(), "fine");
        // a redirect hop to a host outside @connect is refused before it is fetched
        let r = get("evil.test", "/bad", relay.clone()).await;
        assert_eq!(r.status(), 403);
        let r = get("api.test", "/ok", "unknown".into()).await;
        assert_eq!(r.status(), 403);
        assert!(env.origin.requests().iter().all(|r| r.path() != "/bad"));
        assert!(env.origin.requests().iter().all(|r| {
            r.headers
                .iter()
                .all(|(n, _)| !n.eq_ignore_ascii_case("x-argus-relay"))
        }));
    }
);

e2e_test!(
    credentialed_xhr_goes_to_the_bound_session_only_after_every_check,
    rules = [],
    explicit_only,
    |env| {
        let s = script("", true);
        env.proxy
            .userscripts()
            .install_script("default", s)
            .unwrap();
        let h = hub(&env);
        let (sess, sid, mut rx) = session(&h, "t1");
        let (other, _osid, mut orx) = session(&h, "t2");
        h.on_text(
            sess,
            &json!({"t": "perms", "origins": ["*://*.api.test/*"]}).to_string(),
        )
        .await;
        h.on_text(
            other,
            &json!({"t": "perms", "origins": ["<all_urls>"]}).to_string(),
        )
        .await;
        let c = env.client();
        let (tok, mdoc) = bound_bundle(&env, &c, &sid, "/x").await;
        env.origin.route("/jar", MockResponse::ok("from the proxy"));

        // happy path: the job reaches the bound session (not the other one) and its answer is
        // piped back
        let call = xhr(
            &env,
            &c,
            &tok,
            json!({"op": "xhr", "method": "POST", "url": "https://api.test/data", "mdoc": mdoc, "headers": [["Cookie", "x=1"], ["Accept", "a"]]}),
        );
        let extension = async {
            let (job, meta) = next_job(&mut rx).await;
            assert_eq!(meta["op"], "xhr");
            assert_eq!(meta["url"], "https://api.test/data");
            assert_eq!(meta["connect"]["list"], json!(["api.test"]));
            assert_eq!(meta["connect"]["all"], false);
            assert!(meta["relay"].as_str().unwrap().len() >= 32);
            let hdrs = meta["headers"].to_string().to_lowercase();
            assert!(
                hdrs.contains("accept") && !hdrs.contains("cookie"),
                "script cookies dropped: {hdrs}"
            );
            assert!(no_more(&mut orx), "the other session got nothing");
            h.on_binary(sess, &job_frame(F_HEAD, job, br#"{"status":201,"statusText":"Created","headers":[["x-a","b"],["set-cookie","s=1"]],"finalUrl":"https://api.test/data"}"#)).await;
            h.on_binary(sess, &job_frame(F_DATA, job, b"pong")).await;
            h.on_binary(sess, &job_frame(F_END, job, b"")).await;
        };
        let ((st, fs), ()) = tokio::join!(call, extension);
        assert_eq!(st, 200);
        let head: Value = serde_json::from_slice(&fs.iter().find(|f| f.0 == 1).unwrap().1).unwrap();
        assert_eq!(head["status"], 201);
        assert!(!head["headers"].to_string().contains("set-cookie"));
        assert_eq!(fs.iter().find(|f| f.0 == 2).unwrap().1, b"pong");
        assert!(fs.iter().any(|f| f.0 == 3));

        // (the POST's own body-end frame is still queued for the extension)
        while rx.try_recv().is_ok() {}
        // @connect is checked before anything is dispatched
        let (st, fs) = xhr(
            &env,
            &c,
            &tok,
            json!({"op": "xhr", "method": "GET", "url": "https://evil.test/", "mdoc": mdoc}),
        )
        .await;
        assert_eq!(st, 403, "{fs:?}");
        assert!(no_more(&mut rx), "denied before dispatch");
        // anonymous: the proxy's own client, no job
        let (_, fs) = xhr(&env, &c, &tok, json!({"op": "xhr", "method": "GET", "url": env.origin.https_url("api.test", "/jar"), "mdoc": mdoc, "anonymous": true})).await;
        assert_eq!(fs.iter().find(|f| f.0 == 2).unwrap().1, b"from the proxy");
        assert!(no_more(&mut rx));
        // no host permission for the target (the session only holds api.test): jar
        let (_, fs) = xhr(&env, &c, &tok, json!({"op": "xhr", "method": "GET", "url": env.origin.https_url("api.test", "/jar"), "mdoc": "bogus"})).await;
        assert_eq!(
            fs.iter().find(|f| f.0 == 2).unwrap().1,
            b"from the proxy",
            "unknown document: jar"
        );
        assert!(no_more(&mut rx));
        // the page goes away mid-request: the job is cancelled
        let slow = tokio::time::timeout(
            Duration::from_millis(300),
            xhr(
                &env,
                &c,
                &tok,
                json!({"op": "xhr", "method": "GET", "url": "https://api.test/slow", "mdoc": mdoc}),
            ),
        );
        let watcher = async {
            let (job2, _) = next_job(&mut rx).await;
            let Some(ExtOut::Binary(cb)) = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .unwrap()
            else {
                panic!("cancel")
            };
            let (t, j, _) = parse_job_frame(&cb).unwrap();
            assert_eq!((t, j), (F_CANCEL, job2), "the aborted page cancels the job");
        };
        let (r, ()) = tokio::join!(slow, watcher);
        assert!(
            r.is_err(),
            "the page gave up while the extension was silent"
        );
    }
);

e2e_test!(
    cookies_go_through_the_browser_without_httponly_ones,
    rules = [],
    explicit_only,
    |env| {
        env.proxy
            .userscripts()
            .install_script("default", script("", true))
            .unwrap();
        let h = hub(&env);
        let (sess, sid, mut rx) = session(&h, "t1");
        h.on_text(
            sess,
            &json!({"t": "perms", "origins": ["*://*.api.test/*"]}).to_string(),
        )
        .await;
        let c = env.client();
        let (tok, mdoc) = bound_bundle(&env, &c, &sid, "/c").await;
        let call = cookie(
            &env,
            &c,
            &tok,
            json!({"op": "list", "url": "https://api.test/", "mdoc": mdoc}),
        );
        let extension = async {
            let (job, meta) = next_job(&mut rx).await;
            assert_eq!(meta["op"], "cookie");
            assert_eq!(meta["cookie"]["op"], "list");
            assert!(meta["cookie"].get("mdoc").is_none());
            h.on_binary(sess, &job_frame(F_HEAD, job, br#"{"result":[{"name":"a","value":"1","http_only":false},{"name":"h","value":"secret","http_only":true}]}"#)).await;
            h.on_binary(sess, &job_frame(F_END, job, b"")).await;
        };
        let ((st, body), ()) = tokio::join!(call, extension);
        assert_eq!(st, 200, "{body}");
        let list = body["result"].as_array().unwrap();
        assert_eq!(
            list.len(),
            1,
            "the HttpOnly cookie is dropped even if the extension sent it"
        );
        assert_eq!(list[0]["name"], "a");
        // writing an HttpOnly cookie is refused without asking the browser
        let (st, _) = cookie(&env, &c, &tok, json!({"op": "set", "url": "https://api.test/", "mdoc": mdoc, "cookie": {"name": "x", "value": "1", "http_only": true}})).await;
        assert_eq!(st, 400);
        assert!(no_more(&mut rx));
        // outside @connect: refused before dispatch
        let (st, _) = cookie(
            &env,
            &c,
            &tok,
            json!({"op": "list", "url": "https://evil.test/", "mdoc": mdoc}),
        )
        .await;
        assert_eq!(st, 403);
        assert!(no_more(&mut rx));
    }
);

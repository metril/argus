//! The extension bridge through the real proxy: the extension listener binds a connection (and
//! every document in it) to a session by proxy authentication, the credentials never reach the
//! origin, the relay token is checked per hop and never forwarded, and credentialed
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
    // (the EV setting has its own cases: the fake hosts of these tests cannot be probed)
    let _ = env.proxy.ctx.bypass().update(|s| {
        s.ev_no_decrypt = false;
        Ok(())
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

/// A client whose browser authenticated to the extension listener as session `sid`.
async fn ext_client(env: &TestEnv, sid: &str, store: &str) -> TestClient {
    let addr = env.proxy.ext_addr().await;
    TestClient::via_ext(&env.proxy, addr, sid, store)
}

fn b64(b: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(b)
}

async fn page(
    env: &TestEnv,
    c: &TestClient,
    host: &str,
    path: &str,
) -> (String, reqwest::header::HeaderMap) {
    env.origin.route(path, MockResponse::html(PAGE));
    let rb = c
        .request(reqwest::Method::GET, &env.origin.https_url(host, path))
        .header("sec-fetch-dest", "document")
        .header("accept", "text/html");
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
async fn bound_bundle(env: &TestEnv, c: &TestClient, path: &str) -> (String, String) {
    let (html, h) = page(env, c, "app.test", path).await;
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
    // (text frames, such as the listener's `proxy` announcement, are not jobs)
    let b = loop {
        match tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("a job")
        {
            Some(ExtOut::Binary(b)) => break b,
            Some(ExtOut::Text(_)) => continue,
            other => panic!("expected a binary frame, got {other:?}"),
        }
    };
    let (t, job, p) = parse_job_frame(&b).unwrap();
    assert_eq!(t, F_JOB);
    (job, serde_json::from_slice(p).unwrap())
}

fn no_more(rx: &mut tokio::sync::mpsc::Receiver<ExtOut>) -> bool {
    // (a text frame is the listener's `proxy` announcement, not a job)
    loop {
        match rx.try_recv() {
            Ok(ExtOut::Text(_)) => continue,
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => return true,
            _ => return false,
        }
    }
}

e2e_test!(
    the_extension_listener_binds_connections_by_proxy_authentication,
    rules = [],
    explicit_only,
    |env| {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        env.proxy
            .userscripts()
            .install_script("default", script("", false))
            .unwrap();
        let h = hub(&env);
        let (sess, sid, _rx) = session(&h, "t1");
        let ext = ext_client(&env, &sid, "").await;

        // a bound document: ext tag, Server-Timing, and the session can list it
        let (html, hd) = page(&env, &ext, "app.test", "/p").await;
        assert!(html.contains("data-m=\"ext:"), "bound document: {html}");
        let mdoc = mdoc_of(&hd).expect("Server-Timing on a bound userscript document");
        assert!(h.menu(sess, "", &mdoc).is_ok(), "bound to the session");
        // the same connection serves further documents (bound by connection identity)
        let (html, _) = page(&env, &ext, "app.test", "/p2").await;
        assert!(html.contains("data-m=\"ext:"));

        // a normal port never 407s and binds nothing: no id, no Server-Timing, no ext tag
        let plain = env.client();
        let (html2, hd2) = page(&env, &plain, "app.test", "/q").await;
        assert!(!html2.contains("ext:"), "unbound: {html2}");
        assert!(
            hd2.get("server-timing").is_none(),
            "unbound pages carry no id"
        );
        assert_eq!(
            h.menu(sess, "", "deadbeef"),
            Err(api_types::ExtError::NotFound)
        );

        // a document served to a Firefox container's credentials belongs to that store only
        let boxed = ext_client(&env, &sid, "c1x").await;
        let (_, hd3) = page(&env, &boxed, "app.test", "/box").await;
        let m3 = mdoc_of(&hd3).expect("bound in a store");
        assert!(h.menu(sess, "c1x", &m3).is_ok());
        assert_eq!(h.menu(sess, "", &m3), Err(api_types::ExtError::Forbidden));
        assert_eq!(
            h.menu(sess, "other", &m3),
            Err(api_types::ExtError::Forbidden)
        );
        assert_eq!(
            h.menu(sess, "c1x", &mdoc),
            Err(api_types::ExtError::Forbidden)
        );

        // raw 407: no credentials, wrong credentials, a made-up sid
        let addr = env.proxy.ext_addr().await;
        for auth in [
            None,
            Some(format!(
                "Basic {}",
                b64(b"ext:00000000000000000000000000000000")
            )),
            Some(format!("Basic {}", b64(format!("user:{sid}").as_bytes()))),
            Some("Bearer x".to_string()),
        ] {
            let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
            let mut req = String::from("CONNECT app.test:443 HTTP/1.1\r\nHost: app.test:443\r\n");
            if let Some(a) = &auth {
                req += &format!("Proxy-Authorization: {a}\r\n");
            }
            req += "\r\n";
            sock.write_all(req.as_bytes()).await.unwrap();
            let mut out = Vec::new();
            let _ = tokio::time::timeout(Duration::from_secs(3), sock.read_to_end(&mut out)).await;
            let text = String::from_utf8_lossy(&out).to_string();
            assert!(text.starts_with("HTTP/1.1 407"), "{auth:?}: {text}");
            assert!(text.contains("realm=\"argus-ext\""), "{text}");
        }
        // plain (non-CONNECT) request without credentials: 407 too, nothing forwarded
        let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        let url = env.origin.http_url("app.test", "/noauth");
        env.origin.route("/noauth", MockResponse::ok("x"));
        sock.write_all(format!("GET {url} HTTP/1.1\r\nHost: app.test\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(3), sock.read_to_end(&mut out)).await;
        assert!(String::from_utf8_lossy(&out).starts_with("HTTP/1.1 407"));
        assert!(env.origin.requests_for("/noauth").is_empty());
        // the normal port: a raw CONNECT with no credentials is served, never 407
        let mut sock = tokio::net::TcpStream::connect(env.proxy.addr)
            .await
            .unwrap();
        sock.write_all(b"CONNECT app.test:443 HTTP/1.1\r\nHost: app.test:443\r\n\r\n")
            .await
            .unwrap();
        let mut head = [0u8; 12];
        sock.read_exact(&mut head).await.unwrap();
        assert_eq!(&head, b"HTTP/1.1 200");

        // Proxy-Authorization (and the relay header) never reach the origin: a plain-HTTP
        // request through the extension listener carries it in the clear
        env.origin.route("/plain", MockResponse::ok("p"));
        let r = ext
            .request(
                reqwest::Method::GET,
                &env.origin.http_url("app.test", "/plain"),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        for rq in env.origin.requests() {
            assert!(
                rq.headers.iter().all(|(n, _)| {
                    !n.eq_ignore_ascii_case("proxy-authorization")
                        && !n.eq_ignore_ascii_case("x-argus-relay")
                }),
                "a bridge header reached the origin: {rq:?}"
            );
        }

        // a relay token is refused when it does not come from the job's own session
        env.origin.route("/a.js", MockResponse::ok("1"));
        let r = ext
            .request(
                reqwest::Method::GET,
                &env.origin.https_url("app.test", "/a.js"),
            )
            .header("x-argus-relay", "whatever")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403);

        // the session ends: new connections are refused and an open tunnel is closed
        let mut tunnel = tokio::net::TcpStream::connect(addr).await.unwrap();
        tunnel
            .write_all(
                format!(
                    "CONNECT app.test:443 HTTP/1.1\r\nHost: app.test:443\r\nProxy-Authorization: Basic {}\r\n\r\n",
                    b64(format!("ext:{sid}").as_bytes())
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut head = [0u8; 12];
        tunnel.read_exact(&mut head).await.unwrap();
        assert_eq!(&head, b"HTTP/1.1 200");
        h.close(sess);
        let mut rest = Vec::new();
        let ended =
            tokio::time::timeout(Duration::from_secs(5), tunnel.read_to_end(&mut rest)).await;
        assert!(ended.is_ok(), "the tunnel died with its session");
        // a new request is refused (a refused tunnel, or a 407 on a connection that was still open)
        let after = ext
            .request(
                reqwest::Method::GET,
                &env.origin.https_url("app.test", "/p3"),
            )
            .send()
            .await;
        assert!(after.map_or(true, |r| r.status() == 407));
        assert!(
            env.origin.requests_for("/p3").is_empty(),
            "nothing reached the origin"
        );
    }
);

e2e_test!(
    revoking_a_token_drops_the_sessions_proxy_connections,
    rules = [],
    explicit_only,
    |env| {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let h = hub(&env);
        let (_s, sid, _rx) = session(&h, "tok-r");
        let addr = env.proxy.ext_addr().await;
        let mut tunnel = tokio::net::TcpStream::connect(addr).await.unwrap();
        tunnel
            .write_all(
                format!(
                    "CONNECT app.test:443 HTTP/1.1\r\nHost: app.test:443\r\nProxy-Authorization: Basic {}\r\n\r\n",
                    b64(format!("ext:{sid}").as_bytes())
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut head = [0u8; 12];
        tunnel.read_exact(&mut head).await.unwrap();
        h.close_token("tok-r");
        let mut rest = Vec::new();
        let ended =
            tokio::time::timeout(Duration::from_secs(5), tunnel.read_to_end(&mut rest)).await;
        assert!(ended.is_ok(), "revocation closes the proxy connection");
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
        let (sess, sid, mut rx) = session(&h, "t1");
        h.on_text(
            sess,
            &json!({"t": "perms", "origins": ["*://*.api.test/*"]}).to_string(),
        )
        .await;
        let _job = h
            .dispatch(sess, json!({"op": "xhr"}), "default", &id, "app.test", None)
            .await
            .unwrap();
        let (_, meta) = next_job(&mut rx).await;
        let relay = meta["relay"].as_str().unwrap().to_string();
        let c = ext_client(&env, &sid, "").await;
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
        // so is one from a connection of another session, or of a container store
        let (_o, osid, _orx) = session(&h, "t9");
        let other = ext_client(&env, &osid, "").await;
        let r = other
            .request(
                reqwest::Method::GET,
                &env.origin.https_url("api.test", "/ok"),
            )
            .header("x-argus-relay", relay.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            403,
            "another session cannot use the job's token"
        );
        let boxed = ext_client(&env, &sid, "c1x").await;
        let r = boxed
            .request(
                reqwest::Method::GET,
                &env.origin.https_url("api.test", "/ok"),
            )
            .header("x-argus-relay", relay.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            403,
            "a container store cannot use the job's token"
        );
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
        let c = ext_client(&env, &sid, "").await;
        let (tok, mdoc) = bound_bundle(&env, &c, "/x").await;
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
        let c = ext_client(&env, &sid, "").await;
        let (tok, mdoc) = bound_bundle(&env, &c, "/c").await;
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

e2e_test!(
    a_relayed_redirect_is_checked_at_the_decrypted_hop_before_the_browser_follows,
    rules = [],
    explicit_only,
    |env| {
        use common::bypass::{BypassMode, Entry};
        let s = script("", true);
        let id = s.id.clone();
        env.proxy
            .userscripts()
            .install_script("default", s)
            .unwrap();
        // the script may reach api.test and everything below it
        let h = hub(&env);
        let (sess, sid, mut rx) = session(&h, "t1");
        h.on_text(
            sess,
            &json!({"t": "perms", "origins": ["*://*.api.test/*", "*://127.0.0.1/*"]}).to_string(),
        )
        .await;
        env.proxy
            .ctx
            .bypass()
            .update(|st| {
                st.entries.push(Entry {
                    id: "b".into(),
                    pattern: "byp.api.test".into(),
                    mode: BypassMode::NoDecrypt,
                    source: "custom".into(),
                    note: None,
                    updated_at: 0,
                });
                Ok(())
            })
            .unwrap();
        let _job = h
            .dispatch(sess, json!({"op": "xhr"}), "default", &id, "app.test", None)
            .await
            .unwrap();
        let (_, meta) = next_job(&mut rx).await;
        let relay = meta["relay"].as_str().unwrap().to_string();
        let c = ext_client(&env, &sid, "").await;
        let redirect = |path: &'static str, to: &str| {
            env.origin.route(
                path,
                MockResponse::new(302, "")
                    .header("location", to)
                    .header("set-cookie", "leak=1"),
            );
        };
        let fetch = |path: &'static str| {
            let rb = c
                .request(
                    reqwest::Method::GET,
                    &env.origin.https_url("api.test", path),
                )
                .header("x-argus-relay", relay.clone());
            async move { rb.send().await.unwrap() }
        };
        env.origin.route("/end", MockResponse::ok("done"));
        // refused at the decrypted hop: outside @connect, a bypassed host, loopback, a scheme
        // that is not http(s); the answer carries no Location and no Set-Cookie
        for (path, to) in [
            ("/r-evil", "https://evil.test/x"),
            ("/r-byp", "https://byp.api.test/x"),
            ("/r-lo", "https://127.0.0.1/x"),
            ("/r-lo2", "https://localhost/x"),
            ("/r-data", "data:text/plain,x"),
        ] {
            redirect(path, to);
            let r = fetch(path).await;
            assert_eq!(r.status(), 502, "{to}");
            assert_eq!(
                r.headers().get("x-adblock-note").unwrap(),
                "relayed redirect refused"
            );
            assert!(r.headers().get("location").is_none());
            assert!(r.headers().get("set-cookie").is_none());
        }
        // a Location that cannot be checked is refused too: empty, doubled, or UTF-8 that points
        // at a bypassed host
        env.origin.route(
            "/r-empty",
            MockResponse::new(302, "").header("location", ""),
        );
        env.origin.route(
            "/r-two",
            MockResponse::new(302, "")
                .header("location", "/end")
                .header("location", "https://evil.test/x"),
        );
        env.origin.route(
            "/r-utf8",
            MockResponse::new(302, "").header("location", "https://byp.api.test/\u{e9}t\u{e9}"),
        );
        for path in ["/r-empty", "/r-two", "/r-utf8"] {
            let r = fetch(path).await;
            assert_eq!(r.status(), 502, "{path}");
            assert!(r.headers().get("location").is_none());
        }
        // a chain of allowed hops (relative and absolute) passes untouched
        redirect("/r1", "/r2");
        redirect("/r2", "https://v2.api.test/end");
        let r = fetch("/r1").await;
        assert_eq!(r.status(), 302);
        assert_eq!(r.headers().get("location").unwrap(), "/r2");
        let r = fetch("/r2").await;
        assert_eq!(r.status(), 302);
        let r = c
            .request(
                reqwest::Method::GET,
                &env.origin.https_url("v2.api.test", "/end"),
            )
            .header("x-argus-relay", relay.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(r.text().await.unwrap(), "done");
        // EV-no-decrypt on: a hop whose certificate cannot be probed (EV or unknown) is not
        // followed, because Argus would tunnel it
        env.proxy
            .ctx
            .bypass()
            .update(|st| {
                st.ev_no_decrypt = true;
                Ok(())
            })
            .unwrap();
        redirect("/r-ev", "https://api.test:9/x");
        let r = fetch("/r-ev").await;
        assert_eq!(
            r.status(),
            502,
            "an unprobeable hop is refused when EV hosts are tunnelled"
        );
        // nothing was fetched from the refused targets
        assert!(env.origin.requests().iter().all(|r| r.path() != "/x"));
    }
);

e2e_test!(
    the_extension_listener_speaks_socks5_with_per_connection_credentials,
    rules = [],
    explicit_only,
    |env| {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let h = hub(&env);
        let (sess, sid, _rx) = session(&h, "t1");
        let addr = env.proxy.ext_addr().await;
        let connect = |user: &'static str, pass: String| {
            let host = "app.test";
            async move {
                let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
                s.write_all(&[5, 2, 0, 2]).await.unwrap();
                let mut m = [0u8; 2];
                s.read_exact(&mut m).await.unwrap();
                assert_eq!(m, [5, 2], "username/password is the method");
                let mut a = vec![1, user.len() as u8];
                a.extend_from_slice(user.as_bytes());
                a.push(pass.len() as u8);
                a.extend_from_slice(pass.as_bytes());
                s.write_all(&a).await.unwrap();
                let mut r = [0u8; 2];
                s.read_exact(&mut r).await.unwrap();
                if r[1] != 0 {
                    return (r, None);
                }
                let mut q = vec![5, 1, 0, 3, host.len() as u8];
                q.extend_from_slice(host.as_bytes());
                q.extend_from_slice(&443u16.to_be_bytes());
                s.write_all(&q).await.unwrap();
                let mut rep = [0u8; 10];
                s.read_exact(&mut rep).await.unwrap();
                (r, Some((rep[1], s)))
            }
        };
        // no username/password method offered: refused
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(&[5, 1, 0]).await.unwrap();
        let mut m = [0u8; 2];
        s.read_exact(&mut m).await.unwrap();
        assert_eq!(m, [5, 0xff]);
        // wrong user, wrong secret, a malformed store: all refused before any request
        for (u, p) in [
            ("ext", "0".repeat(32)),
            ("other", sid.clone()),
            ("ext", format!("{sid}:bad token!")),
        ] {
            assert_eq!(connect(u, p).await.0, [1, 1]);
        }
        // the session's secret opens a tunnel, with or without a store token
        for p in [sid.clone(), format!("{sid}:c1x")] {
            let (r, t) = connect("ext", p).await;
            assert_eq!(r, [1, 0]);
            assert_eq!(t.as_ref().map(|t| t.0), Some(0), "request granted");
        }
        // the session ends: its tunnel is closed and its secret no longer works
        let (_, t) = connect("ext", sid.clone()).await;
        let (_, mut open) = t.unwrap();
        h.close(sess);
        let mut rest = Vec::new();
        assert!(
            tokio::time::timeout(Duration::from_secs(5), open.read_to_end(&mut rest))
                .await
                .is_ok()
        );
        assert_eq!(connect("ext", sid.clone()).await.0, [1, 1]);
        // the normal port does not speak SOCKS
        let mut s = tokio::net::TcpStream::connect(env.proxy.addr)
            .await
            .unwrap();
        s.write_all(&[5, 1, 2]).await.unwrap();
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut out)).await;
        assert!(!out.starts_with(&[5, 2]));
    }
);

async fn mitm_hub(env: &TestEnv) -> (Arc<ExtHub>, u64, String) {
    // (the listener is up once its address exists, and with it the server's shared state)
    env.proxy.ext_addr().await;
    let s = script("", true);
    let id = s.id.clone();
    env.proxy
        .userscripts()
        .install_script("default", s)
        .unwrap();
    let h = hub(env);
    let (sess, _sid, rx) = session(&h, "tm");
    std::mem::forget(rx);
    (h, sess, id)
}

fn route_of(h: &ExtHub, sess: u64, id: &str) -> proxy_core::ext_bridge::Route {
    let m = h.register_doc(
        "default",
        "https://app.test",
        vec![(id.to_string(), "n".into())],
        sess,
        "",
    );
    h.route(
        Some((sess, "")),
        Some(&m),
        "default",
        "https://app.test",
        id,
        "api.test",
        443,
    )
}

#[tokio::test]
async fn relays_follow_the_listeners_decryption_and_the_explicit_listeners_switch() {
    use proxy_core::ext_bridge::{Fallback, Route};
    // decrypting: the browser is used
    let env = TestEnv::start_tweaked(e2e::EntryMode::Explicit, &[], &|_| {}).await;
    let (h, sess, id) = mitm_hub(&env).await;
    h.on_text(
        sess,
        &json!({"t": "perms", "origins": ["*://*.api.test/*"]}).to_string(),
    )
    .await;
    assert_eq!(route_of(&h, sess, &id), Route::Ext(sess));
    drop(env);
    // MITM on globally but off for the explicit listeners ([proxy.explicit] and so the extension listener)
    let env = TestEnv::start_tweaked(e2e::EntryMode::Explicit, &[], &|c| {
        c.proxy.explicit.enable_mitm = Some(false)
    })
    .await;
    let (h, sess, id) = mitm_hub(&env).await;
    h.on_text(
        sess,
        &json!({"t": "perms", "origins": ["*://*.api.test/*"]}).to_string(),
    )
    .await;
    assert_eq!(route_of(&h, sess, &id), Route::Jar(Fallback::Bypassed));
}

#[tokio::test]
async fn socks_refuses_an_invalid_host_and_one_deadline_covers_the_whole_handshake() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let env = TestEnv::start_tweaked(e2e::EntryMode::Explicit, &[], &|c| {
        c.performance.connection_timeout_secs = 1
    })
    .await;
    let h = hub(&env);
    let (_s, sid, _rx) = session(&h, "ts");
    let addr = env.proxy.ext_addr().await;
    // an invalid host is refused ("host unreachable"), never dialled as written
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(&[5, 1, 2]).await.unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.unwrap();
    let mut a = vec![1, 3];
    a.extend_from_slice(b"ext");
    a.push(sid.len() as u8);
    a.extend_from_slice(sid.as_bytes());
    s.write_all(&a).await.unwrap();
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(r, [1, 0]);
    let bad = b"bad host/with space";
    let mut q = vec![5, 1, 0, 3, bad.len() as u8];
    q.extend_from_slice(bad);
    q.extend_from_slice(&443u16.to_be_bytes());
    s.write_all(&q).await.unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 4);
    // a client trickling a valid handshake, one byte per 400 ms, never trips a per-read timeout
    // (1 s) but is cut at the one deadline for the whole handshake
    let mut t = tokio::net::TcpStream::connect(addr).await.unwrap();
    let start = std::time::Instant::now();
    let mut hs = vec![5u8, 1, 2, 1, 3];
    hs.extend_from_slice(b"ext");
    hs.push(sid.len() as u8);
    hs.extend_from_slice(sid.as_bytes());
    let (mut rd, mut wr) = t.split();
    let writer = async {
        for b in hs {
            if wr.write_all(&[b]).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(400)).await;
        }
    };
    let reader = async {
        let mut buf = Vec::new();
        let _ = rd.read_to_end(&mut buf).await;
        start.elapsed()
    };
    let closed_at = tokio::select! {
        d = reader => d,
        _ = writer => {
            let mut buf = Vec::new();
            let _ = tokio::time::timeout(Duration::from_secs(3), rd.read_to_end(&mut buf)).await;
            start.elapsed()
        }
    };
    assert!(
        closed_at < Duration::from_millis(1600),
        "closed at the 1 s deadline, not after the last byte: {closed_at:?}"
    );
}

#[tokio::test]
async fn argus_own_hosts_follow_the_live_configuration_and_resolution() {
    use proxy_core::config::ProxyConfig;
    use proxy_core::ext_bridge::{Fallback, Route};
    let env = TestEnv::start_tweaked(e2e::EntryMode::Explicit, &[], &|_| {}).await;
    let (h, sess, id) = mitm_hub(&env).await;
    h.on_text(
        sess,
        &json!({"t": "perms", "origins": ["*://*.api.test/*"]}).to_string(),
    )
    .await;
    let m = h.register_doc(
        "default",
        "https://app.test",
        vec![(id.clone(), "n".into())],
        sess,
        "",
    );
    let go = |host: &str| {
        h.route(
            Some((sess, "")),
            Some(&m),
            "default",
            "https://app.test",
            &id,
            host,
            443,
        )
    };
    assert_eq!(go("dash.api.test"), Route::Ext(sess));
    assert_eq!(go("console.api.test"), Route::Ext(sess));
    // the dashboard URL and the web API host are read from the live configuration
    let ctl = env.proxy.control();
    let mut c = ProxyConfig::default();
    c.script_control.dashboard_url = "https://dash.api.test/".into();
    c.webui.host = "console.api.test".into();
    ctl.apply_access(&c).await.unwrap();
    assert_eq!(
        go("dash.api.test"),
        Route::Jar(Fallback::OwnHost),
        "any port, by name"
    );
    assert_eq!(go("console.api.test"), Route::Jar(Fallback::OwnHost));
    assert_eq!(go("DASH.api.test"), Route::Jar(Fallback::OwnHost));
    // changed again: the old names are free, the new one is Argus
    c.script_control.dashboard_url = "https://other.api.test/".into();
    c.webui.host = "0.0.0.0".into();
    ctl.apply_access(&c).await.unwrap();
    assert_eq!(go("dash.api.test"), Route::Ext(sess));
    assert_eq!(go("console.api.test"), Route::Ext(sess));
    assert_eq!(go("other.api.test"), Route::Jar(Fallback::OwnHost));
    // a name that resolves to the web API's bind address on its port is Argus too
    ctl.set_webui_listener("127.0.0.1", 3000).await;
    assert!(h.is_own_target("localhost", 3000).await);
    assert!(!h.is_own_target("localhost", 3001).await);
    assert!(!h.is_own_target("example.invalid", 3000).await);
}

#[tokio::test]
async fn a_revoked_session_ends_its_real_upgraded_websocket() {
    let env = TestEnv::start(e2e::EntryMode::Explicit, &[]).await;
    let h = hub(&env);
    let (sess, sid, _rx) = session(&h, "tw");
    let mut ws =
        e2e::connect_ws_via_ext(&env.proxy, &sid, "ws.test", env.origin.http_port(), "/ws").await;
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    ws.send(Message::Text("hi".into())).await.unwrap();
    let echo = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("echo");
    assert!(matches!(echo, Some(Ok(_))), "{echo:?}");
    // the token is revoked: the spliced WebSocket ends (the accept loop cannot reach this task)
    h.close_token("tw");
    let end = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match ws.next().await {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => break,
                Some(Ok(_)) => {}
            }
        }
    })
    .await;
    assert!(end.is_ok(), "the upgraded WebSocket outlived its session");
    assert!(!h.is_live(sess));
}

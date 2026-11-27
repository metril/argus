//! `proxy.block_response`: under `fail` a blocked subresource fails like a network error (an
//! HTTP/2 stream reset with CANCEL that leaves the connection's other streams alone, or a closed
//! HTTP/1 connection with no response); documents, frames and images keep their block page,
//! blank page and GIF; `synthetic` restores a well-formed answer for every block.

use bytes::Bytes;
use common::config::BlockResponse;
use e2e::{e2e_test, tls_via_proxy, HttpVersion, MockResponse, TestEnv};
use filter_engine::{EventAction, EventOutcome};
use http_body_util::{BodyExt, Empty};
use hyper::{Request, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Blocks `/ads/...` on `a.test`; everything else on it is allowed.
const RULES: [&str; 1] = ["||a.test^*/ads/"];

type H2 = hyper::client::conn::http2::SendRequest<Empty<Bytes>>;

async fn h2_over_tls(env: &TestEnv, sni: &str) -> H2 {
    let tls = tls_via_proxy(&env.proxy, sni, env.origin.https_port(), &[b"h2"]).await;
    let (sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
    tokio::spawn(conn);
    sender
}

fn req(env: &TestEnv, path: &str, dest: &str) -> Request<Empty<Bytes>> {
    Request::get(format!("https://a.test:{}{path}", env.origin.https_port()))
        .header("sec-fetch-dest", dest)
        .header("sec-fetch-mode", "cors")
        .header("sec-fetch-site", "cross-site")
        .header("referer", "https://page.test/")
        .body(Empty::<Bytes>::new())
        .unwrap()
}

/// The HTTP/2 reset reason carried by a client error, if the stream was reset.
fn reset_reason(e: &hyper::Error) -> Option<h2::Reason> {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(c) = cur {
        if let Some(h) = c.downcast_ref::<h2::Error>() {
            return h.reason();
        }
        cur = c.source();
    }
    None
}

async fn read_body(r: hyper::Response<hyper::body::Incoming>) -> Bytes {
    r.into_body().collect().await.unwrap().to_bytes()
}

fn log_of(env: &TestEnv, needle: &str) -> Vec<filter_engine::RequestEvent> {
    env.proxy
        .engine
        .recent_requests(1000)
        .into_iter()
        .filter(|e| e.url.contains(needle))
        .collect()
}

e2e_test!(
    h2_block_resets_only_that_stream_with_cancel,
    rules = RULES,
    |env| {
        env.origin.route("/ok", MockResponse::ok("fine"));
        env.origin.route("/ads/x.js", MockResponse::ok("ad"));
        env.origin.route("/ads/z.json", MockResponse::ok("ad"));
        let s = h2_over_tls(&env, "a.test").await;

        // Two blocked streams and an allowed one, concurrently on one connection.
        let (blocked_script, ok, blocked_xhr) = tokio::join!(
            s.clone().send_request(req(&env, "/ads/x.js", "script")),
            s.clone().send_request(req(&env, "/ok", "empty")),
            s.clone().send_request(req(&env, "/ads/z.json", "empty")),
        );
        for (what, r) in [("script", blocked_script), ("xhr", blocked_xhr)] {
            let e = r.expect_err(what);
            assert_eq!(reset_reason(&e), Some(h2::Reason::CANCEL), "{what}: {e:?}");
        }
        let ok = ok.expect("allowed stream is untouched");
        assert_eq!(ok.status(), 200);
        assert_eq!(read_body(ok).await, "fine");

        // The connection survives: more streams of both kinds, then a frame and an image that
        // keep their synthetic answers on the very same connection.
        let mut s2 = s.clone();
        s2.ready().await.expect("connection still open");
        let again = s2.send_request(req(&env, "/ok", "empty")).await.unwrap();
        assert_eq!(read_body(again).await, "fine");
        let again = s
            .clone()
            .send_request(req(&env, "/ads/y.js", "script"))
            .await;
        assert_eq!(reset_reason(&again.unwrap_err()), Some(h2::Reason::CANCEL));
        let img = s
            .clone()
            .send_request(req(&env, "/ads/p.gif", "image"))
            .await;
        let img = img.expect("images are answered");
        assert_eq!(img.status(), 200);
        assert_eq!(img.headers()["content-type"], "image/gif");
        assert!(read_body(img).await.starts_with(b"GIF8"));

        assert!(env.origin.requests_for("/ads/x.js").is_empty());
        assert!(env.origin.requests_for("/ads/z.json").is_empty());

        // The request log records the outcome, and an abort has no status.
        let ev = log_of(&env, "/ads/x.js");
        assert_eq!(ev.len(), 1, "{ev:?}");
        assert_eq!(ev[0].action, EventAction::Blocked);
        assert_eq!(ev[0].outcome, Some(EventOutcome::Aborted));
        assert_eq!(ev[0].status, None);
        let ev = log_of(&env, "/ads/p.gif");
        assert_eq!(ev[0].outcome, Some(EventOutcome::Synthetic));
    }
);

e2e_test!(
    h2_client_sees_a_failed_fetch_not_a_response,
    rules = RULES,
    |env| {
        env.origin.route("/ok", MockResponse::ok("fine"));
        let c = env.client_with(HttpVersion::Http2);
        let blocked = c
            .request(
                reqwest::Method::GET,
                &env.origin.https_url("a.test", "/ads/x.js"),
            )
            .header("sec-fetch-dest", "script")
            .send()
            .await;
        let e = blocked.expect_err("a blocked script must fail");
        assert!(!e.is_timeout(), "{e:?}");
        // The same client (and its pooled connection) keeps working.
        let ok = c.get(&env.origin.https_url("a.test", "/ok")).await;
        assert_eq!(ok.status(), 200);
        assert_eq!(ok.version(), reqwest::Version::HTTP_2);
    }
);

e2e_test!(
    h1_block_closes_the_connection_without_a_response,
    rules = RULES,
    |env| {
        env.origin.route("/ok", MockResponse::ok("fine"));
        let port = env.origin.https_port();

        // Raw: the connection ends without a single response byte.
        let mut tls = tls_via_proxy(&env.proxy, "a.test", port, &[b"http/1.1"]).await;
        tls.write_all(
            format!(
                "GET /ads/x.js HTTP/1.1\r\nHost: a.test:{port}\r\nSec-Fetch-Dest: script\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut out = Vec::new();
        let _ = tls.read_to_end(&mut out).await;
        assert!(out.is_empty(), "{}", String::from_utf8_lossy(&out));

        // Through a client: a failed request, and the next one on a fresh connection works.
        let c = env.client_with(HttpVersion::Http1);
        let e = c
            .request(
                reqwest::Method::GET,
                &env.origin.https_url("a.test", "/ads/x.js"),
            )
            .header("sec-fetch-dest", "empty")
            .send()
            .await
            .expect_err("a blocked fetch must fail");
        assert!(!e.is_timeout(), "{e:?}");
        let ok = c.get(&env.origin.https_url("a.test", "/ok")).await;
        assert_eq!(ok.status(), 200);
        assert_eq!(ok.version(), reqwest::Version::HTTP_11);

        // Frames and images are still answered on HTTP/1.
        let tls = tls_via_proxy(&env.proxy, "a.test", port, &[b"http/1.1"]).await;
        let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .unwrap();
        let conn = tokio::spawn(conn);
        let r = send.send_request(req(&env, "/ads/p.gif", "image")).await;
        assert_eq!(r.unwrap().status(), StatusCode::OK);
        drop(send);
        let _ = conn.await;

        assert!(env.origin.requests_for("/ads/x.js").is_empty());
        let ev = log_of(&env, "/ads/x.js");
        assert!(!ev.is_empty());
        assert!(ev.iter().all(|e| e.outcome == Some(EventOutcome::Aborted)));
    }
);

e2e_test!(
    block_response_shape_per_type_and_mode,
    rules = ["||blk.test^"],
    |env| {
        // (Sec-Fetch-Dest, aborted under `fail`, status when answered, content-type)
        type Case = (&'static str, bool, u16, Option<&'static str>);
        let cases: [Case; 8] = [
            ("document", false, 403, Some("text/html; charset=utf-8")),
            ("iframe", false, 200, Some("text/html; charset=utf-8")),
            ("image", false, 200, Some("image/gif")),
            ("script", true, 200, Some("application/javascript")),
            ("style", true, 200, Some("text/css")),
            ("empty", true, 204, None),
            ("font", true, 204, None),
            ("video", true, 204, None),
        ];
        let url = env.origin.https_url("blk.test", "/r");
        for mode in [BlockResponse::Fail, BlockResponse::Synthetic] {
            env.proxy.ctx.set_block_response(mode);
            for (dest, aborts, status, ctype) in cases {
                let sent = env
                    .client()
                    .request(reqwest::Method::GET, &url)
                    .header("sec-fetch-dest", dest)
                    .header("sec-fetch-site", "cross-site")
                    .header("referer", "https://page.test/")
                    .send()
                    .await;
                let what = format!("{mode:?} dest={dest}");
                if aborts && mode == BlockResponse::Fail {
                    let e = sent.expect_err(&what);
                    assert!(!e.is_timeout(), "{what}: {e:?}");
                    continue;
                }
                let resp = sent.unwrap_or_else(|e| panic!("{what}: {e:?}"));
                assert_eq!(resp.status(), status, "{what}");
                assert_eq!(resp.headers()["x-adblock"], "blocked", "{what}");
                match ctype {
                    Some(c) => assert_eq!(resp.headers()["content-type"], c, "{what}"),
                    None => assert!(resp.headers().get("content-type").is_none(), "{what}"),
                }
                let b = resp.bytes().await.unwrap();
                match dest {
                    "document" => assert!(String::from_utf8_lossy(&b).contains("||blk.test^")),
                    "iframe" => assert!(b.starts_with(b"<!DOCTYPE html>"), "blank frame"),
                    "image" => assert!(b.starts_with(b"GIF8")),
                    _ => assert!(b.is_empty(), "{what}"),
                }
            }
        }
        assert!(env.origin.requests().is_empty());
        // Both modes were logged, with their outcome.
        let outcomes: Vec<_> = log_of(&env, "blk.test")
            .into_iter()
            .filter(|e| e.request_type == "script")
            .map(|e| e.outcome)
            .collect();
        assert!(
            outcomes.contains(&Some(EventOutcome::Aborted)),
            "{outcomes:?}"
        );
        assert!(
            outcomes.contains(&Some(EventOutcome::Synthetic)),
            "{outcomes:?}"
        );
    }
);

// uBO serves a `$redirect` resource to whatever request type the rule matches (its redirect
// engine has no resource/type compatibility check: `src/js/redirect-engine.js`), and the rule's
// own type options decide the match. The live lists carry
// `||pagead2.googlesyndication.com^$xhr,redirect=noop.js`, so an XHR / `fetch(HEAD, no-cors)`
// probe of that host is redirected, while a script-only rule leaves an XHR alone.
e2e_test!(
    redirect_follows_the_rule_types,
    rules = [
        "||pagead2.test^$xhr,redirect=noop.js",
        "||scr.test^$script,redirect=noopjs",
        "||txt.test^$xhr,redirect=nooptext",
        "||plain.test^",
    ],
    |env| {
        env.origin
            .route("/fakepage.html", MockResponse::ok("origin"));
        let fetch_mode = |host: &'static str,
                          method: reqwest::Method,
                          dest: &'static str,
                          mode: &'static str| {
            let c = env.client();
            let url = env.origin.https_url(host, "/fakepage.html");
            async move {
                c.request(method, &url)
                    .header("sec-fetch-dest", dest)
                    .header("sec-fetch-mode", mode)
                    .header("sec-fetch-site", "cross-site")
                    .header("referer", "https://adblock.turtlecute.org/")
                    .send()
                    .await
            }
        };
        let fetch = |host: &'static str, method: reqwest::Method, dest: &'static str| {
            fetch_mode(host, method, dest, "cors")
        };
        // A no-cors fetch/xhr/beacon is opaque to the page: aborted (logged as an abort), as
        // uBO's redirect ends up failing on Firefox, not answered with the stub.
        for (host, m) in [
            ("pagead2.test", reqwest::Method::HEAD),
            ("txt.test", reqwest::Method::GET),
        ] {
            assert!(
                fetch_mode(host, m, "empty", "no-cors").await.is_err(),
                "{host}"
            );
        }
        let ev = env.proxy.engine.recent_requests(100);
        let ev = ev.iter().find(|e| e.url.contains("pagead2.test")).unwrap();
        assert_eq!(ev.outcome, Some(EventOutcome::Aborted));
        // Element loads keep the stub even in no-cors mode.
        let r = fetch_mode("scr.test", reqwest::Method::GET, "script", "no-cors")
            .await
            .unwrap();
        assert_eq!(r.headers()["x-adblock"], "redirected");
        // The cors-mode probe: HEAD, `Sec-Fetch-Dest: empty` (xhr), explicit `$xhr` rule.
        let r = fetch("pagead2.test", reqwest::Method::HEAD, "empty")
            .await
            .unwrap();
        assert_eq!(r.headers()["x-adblock"], "redirected");
        assert_eq!(r.headers()["content-type"], "application/javascript");
        // `noopjs` on a script.
        let r = fetch("scr.test", reqwest::Method::GET, "script")
            .await
            .unwrap();
        assert_eq!(r.headers()["x-adblock"], "redirected");
        assert_eq!(r.headers()["content-type"], "application/javascript");
        // `noop.txt` on an XHR.
        let r = fetch("txt.test", reqwest::Method::GET, "empty")
            .await
            .unwrap();
        assert_eq!(r.headers()["x-adblock"], "redirected");
        assert_eq!(r.headers()["content-type"], "text/plain");
        // A `$script` rule does not match an XHR: it reaches the origin.
        let r = fetch("scr.test", reqwest::Method::GET, "empty")
            .await
            .unwrap();
        assert_eq!(r.text().await.unwrap(), "origin");
        // An `$xhr` rule does not match a script.
        let r = fetch("pagead2.test", reqwest::Method::GET, "script")
            .await
            .unwrap();
        assert!(r.headers().get("x-adblock").is_none());
        // A plain block of an XHR is an abort.
        assert!(fetch("plain.test", reqwest::Method::GET, "empty")
            .await
            .is_err());
    }
);

e2e_test!(
    h2_upstream_timeout_resets_only_that_fetch_stream,
    rules = RULES,
    |env| {
        env.origin.route("/ok", MockResponse::ok("fine"));
        env.origin.route(
            "/slow",
            MockResponse::ok("late").delayed(std::time::Duration::from_secs(30)),
        );
        env.proxy
            .ctx
            .set_request_timeout(std::time::Duration::from_millis(300));
        let s = h2_over_tls(&env, "a.test").await;
        let (slow_fetch, ok, slow_doc) = tokio::join!(
            s.clone().send_request(req(&env, "/slow", "empty")),
            s.clone().send_request(req(&env, "/ok", "empty")),
            s.clone().send_request(req(&env, "/slow", "document")),
        );
        // A fetch to an unresponsive upstream fails like a network error, not a 504 ...
        let e = slow_fetch.expect_err("fetch");
        assert_eq!(reset_reason(&e), Some(h2::Reason::CONNECT_ERROR), "{e:?}");
        // ... the other stream on the connection is untouched ...
        let ok = ok.expect("other stream");
        assert_eq!(ok.status(), 200);
        assert_eq!(read_body(ok).await, "fine");
        // ... and a document keeps the 504.
        assert_eq!(slow_doc.expect("document").status(), 504);
        // Logged as an upstream timeout, never as a block.
        let ev = log_of(&env, "/slow");
        assert!(
            ev.iter()
                .all(|e| e.action == EventAction::Error && e.outcome.is_none()),
            "{ev:?}"
        );
        assert!(ev
            .iter()
            .any(|e| e.error_kind == Some(filter_engine::ErrorKind::UpstreamTimeout)));
    }
);

//! Destination policy, client access control, host binding of intercepted connections and the
//! smaller request/response correctness rules, in both entry modes where they apply.

use std::time::Duration;

use bytes::Bytes;
use e2e::{e2e_test, tls_via_proxy, EntryMode, HttpVersion, MockResponse, TestEnv};
use http_body_util::{BodyExt, Empty};
use hyper::{Request, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

const DOC_HEADERS: [(&str, &str); 2] = [("sec-fetch-dest", "document"), ("accept", "text/html")];

/// One raw HTTP/1.1 exchange with the proxy for `host_port`, shaped for the entry mode (absolute
/// form through the explicit proxy, origin form with a Host header on the transparent listener).
async fn raw_get(env: &TestEnv, host_port: &str, path: &str) -> String {
    let req = match env.mode {
        EntryMode::Explicit => format!(
            "GET http://{host_port}{path} HTTP/1.1\r\nHost: {host_port}\r\nConnection: close\r\n\r\n"
        ),
        EntryMode::Transparent => {
            format!("GET {path} HTTP/1.1\r\nHost: {host_port}\r\nConnection: close\r\n\r\n")
        }
    };
    let mut tcp = tokio::net::TcpStream::connect(env.proxy.entry_addr())
        .await
        .unwrap();
    tcp.write_all(req.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut out))
        .await
        .expect("response")
        .unwrap();
    String::from_utf8_lossy(&out).into_owned()
}

// ---- Destination policy -------------------------------------------------------------------

e2e_test!(
    refuses_loopback_and_link_local_requests,
    rules = [],
    |env| {
        env.origin.route("/secret", MockResponse::ok("internal"));
        let port = env.origin.http_port();
        for host in [
            format!("127.0.0.1:{port}"),
            format!("169.254.169.254:{port}"),
            format!("[::1]:{port}"),
            format!("[::ffff:169.254.169.254]:{port}"),
            format!("[fe80::1]:{port}"),
        ] {
            let out = raw_get(&env, &host, "/secret").await;
            assert!(out.starts_with("HTTP/1.1 403"), "{host}: {out}");
            assert!(
                out.to_ascii_lowercase()
                    .contains("x-adblock: destination-refused"),
                "{host}: {out}"
            );
            assert!(!out.contains("internal"), "{host}: {out}");
        }
        assert!(
            env.origin.requests().is_empty(),
            "nothing reached the origin"
        );
        // Sanity: a public-looking destination on the same origin is let through.
        let out = raw_get(&env, &format!("{}:{port}", e2e::PUBLIC_TEST_IP), "/secret").await;
        assert!(
            out.starts_with("HTTP/1.1 200") && out.contains("internal"),
            "{out}"
        );
    }
);

e2e_test!(
    refuses_connect_to_loopback_and_link_local,
    rules = [],
    explicit_only,
    |env| {
        for target in [
            format!("127.0.0.1:{}", env.origin.https_port()),
            "169.254.169.254:443".to_string(),
            "[::1]:443".to_string(),
        ] {
            let mut tcp = tokio::net::TcpStream::connect(env.proxy.entry_addr())
                .await
                .unwrap();
            tcp.write_all(
                format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
            let mut out = Vec::new();
            tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut out))
                .await
                .expect("closed")
                .unwrap();
            let text = String::from_utf8_lossy(&out);
            assert!(text.starts_with("HTTP/1.1 403"), "{target}: {text}");
            assert!(text.contains("x-adblock: destination-refused"), "{target}");
        }
        assert!(env.origin.requests().is_empty());
    }
);

// Transparent mode: an opaque tunnel to a forced loopback / link-local original destination is
// closed without dialling.
e2e_test!(
    transparent_tunnel_refuses_reserved_destination,
    rules = [],
    transparent_only,
    |env| {
        for dst in [
            format!("127.0.0.1:{}", env.origin.http_port()),
            "169.254.169.254:9999".to_string(),
        ] {
            env.proxy.dst.force(dst.parse().unwrap());
            let mut tcp = tokio::net::TcpStream::connect(env.proxy.entry_addr())
                .await
                .unwrap();
            // Neither TLS nor HTTP: would be tunnelled verbatim to the destination.
            tcp.write_all(b"PING there\r\n\r\n").await.unwrap();
            let mut out = Vec::new();
            tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut out))
                .await
                .expect("closed")
                .unwrap();
            assert!(out.is_empty(), "{dst}: {:?}", String::from_utf8_lossy(&out));
        }
        assert!(env.origin.requests().is_empty());
    }
);

e2e_test!(
    refuses_websocket_to_reserved_destinations,
    rules = [],
    |env| {
        for host in [
            format!("127.0.0.1:{}", env.origin.http_port()),
            "169.254.169.254:80".to_string(),
        ] {
            let tcp = tokio::net::TcpStream::connect(env.proxy.entry_addr())
                .await
                .unwrap();
            let err = tokio_tungstenite::client_async(format!("ws://{host}/ws"), tcp)
                .await
                .expect_err("handshake must be refused");
            assert!(
                matches!(&err, tokio_tungstenite::tungstenite::Error::Http(r) if r.status() == 403),
                "{host}: {err:?}"
            );
        }
        assert!(env.origin.requests().is_empty());
    }
);

// ---- Client access control ----------------------------------------------------------------

e2e_test!(disallowed_client_is_closed_at_accept, rules = [], |env| {
    // Same proxy shape, but only 203.0.113.0/24 may connect: loopback is not in it.
    let strict = TestEnv::start_tweaked(env.mode, &[], &|c| {
        c.proxy.allowed_clients = vec!["203.0.113.0/24".into()];
    })
    .await;
    let mut tcp = tokio::net::TcpStream::connect(strict.proxy.entry_addr())
        .await
        .unwrap();
    let _ = tcp
        .write_all(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n")
        .await;
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut out))
        .await
        .expect("closed promptly");
    assert!(out.is_empty(), "no bytes for a disallowed client: {out:?}");
    assert!(strict.origin.requests().is_empty());
    // The default ACL (loopback included) serves the same request.
    env.origin.route("/", MockResponse::ok("hi"));
    let ok = raw_get(&env, &format!("a.test:{}", env.origin.http_port()), "/").await;
    assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
});

// ---- Host binding of intercepted connections ----------------------------------------------

async fn h1_over_tls(
    env: &TestEnv,
    sni: &str,
) -> hyper::client::conn::http1::SendRequest<Empty<Bytes>> {
    let tls = tls_via_proxy(&env.proxy, sni, env.origin.https_port(), &[b"http/1.1"]).await;
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(conn);
    sender
}

async fn h2_over_tls(
    env: &TestEnv,
    sni: &str,
) -> hyper::client::conn::http2::SendRequest<Empty<Bytes>> {
    let tls = tls_via_proxy(&env.proxy, sni, env.origin.https_port(), &[b"h2"]).await;
    let (sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
    tokio::spawn(conn);
    sender
}

e2e_test!(host_mismatch_gets_421_h1, rules = [], |env| {
    env.origin.route("/x", MockResponse::ok("x"));
    let mut s = h1_over_tls(&env, "a.test").await;
    let req = |host: &str| {
        Request::get("/x")
            .header("host", host)
            .body(Empty::<Bytes>::new())
            .unwrap()
    };
    let resp = s.send_request(req("b.test")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::MISDIRECTED_REQUEST);
    assert!(env.origin.requests().is_empty(), "never dialled");
    // The connection itself is fine for its own host and for a covered subdomain.
    for host in ["a.test", "www.a.test"] {
        let resp = s.send_request(req(host)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{host}");
    }
    // A name the certificate does not cover, even one that merely ends with the host.
    let resp = s.send_request(req("evil-a.test")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::MISDIRECTED_REQUEST);
    assert_eq!(env.origin.requests().len(), 2);
});

e2e_test!(h2_coalescing_follows_certificate_sans, rules = [], |env| {
    env.origin.route("/y", MockResponse::ok("y"));
    let mut s = h2_over_tls(&env, "a.test").await;
    let port = env.origin.https_port();
    let get = |authority: String| {
        Request::get(format!("https://{authority}/y"))
            .body(Empty::<Bytes>::new())
            .unwrap()
    };
    // SAN-covered subdomain on the same connection: served.
    let resp = s
        .send_request(get(format!("sub.a.test:{port}")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"y");
    // Another site: 421, and it never reaches the origin.
    let resp = s
        .send_request(get(format!("other.test:{port}")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::MISDIRECTED_REQUEST);
    let got = env.origin.requests_for("/y");
    assert_eq!(got.len(), 1);
    assert!(got[0].host.starts_with("sub.a.test"), "{}", got[0].host);
});

e2e_test!(websocket_host_mismatch_gets_421, rules = [], |env| {
    let tls = tls_via_proxy(
        &env.proxy,
        "wss.test",
        env.origin.https_port(),
        &[b"http/1.1"],
    )
    .await;
    let mut req = format!("wss://wss.test:{}/ws", env.origin.https_port())
        .into_client_request()
        .unwrap();
    req.headers_mut()
        .insert("host", "elsewhere.test".parse().unwrap());
    let err = tokio_tungstenite::client_async(req, tls)
        .await
        .expect_err("mismatching host must not upgrade");
    assert!(
        matches!(&err, tokio_tungstenite::tungstenite::Error::Http(r) if r.status() == 421),
        "{err:?}"
    );
    assert!(env.origin.requests().is_empty());
});

// The accepted target fixes the WebSocket port: a hostile port in `Host` is ignored.
e2e_test!(websocket_ignores_hostile_host_port, rules = [], |env| {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    let tls = tls_via_proxy(
        &env.proxy,
        "wss.test",
        env.origin.https_port(),
        &[b"http/1.1"],
    )
    .await;
    let mut req = format!("wss://wss.test:{}/ws", env.origin.https_port())
        .into_client_request()
        .unwrap();
    req.headers_mut()
        .insert("host", "wss.test:1".parse().unwrap());
    let (mut ws, resp) = tokio_tungstenite::client_async(req, tls).await.unwrap();
    assert_eq!(resp.status(), 101);
    ws.send(Message::Text("ping".into())).await.unwrap();
    assert_eq!(ws.next().await.unwrap().unwrap().to_text().unwrap(), "ping");
    let got = env.origin.requests_for("/ws");
    assert_eq!(got[0].host, format!("wss.test:{}", env.origin.https_port()));
});

// A client's framing headers are not forwarded with the body-less upgrade request.
e2e_test!(
    websocket_upgrade_drops_client_framing_headers,
    rules = [],
    |env| {
        let mut req = format!("ws://ws.test:{}/ws", env.origin.http_port())
            .into_client_request()
            .unwrap();
        req.headers_mut()
            .insert("content-length", "0".parse().unwrap());
        let tcp = tokio::net::TcpStream::connect(env.proxy.entry_addr())
            .await
            .unwrap();
        let (_ws, resp) = tokio_tungstenite::client_async(req, tcp).await.unwrap();
        assert_eq!(resp.status(), 101);
        let got = env.origin.requests_for("/ws");
        assert!(
            !got[0].headers.iter().any(|(k, _)| k == "content-length"),
            "{:?}",
            got[0].headers
        );
    }
);

// Shutting the proxy down ends spliced WebSocket connections.
e2e_test!(proxy_shutdown_ends_websocket_splice, rules = [], |env| {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    let mut ws = e2e::connect_wss(&env.proxy, "wss.test", env.origin.https_port(), "/ws").await;
    ws.send(Message::Text("hello".into())).await.unwrap();
    assert!(ws.next().await.unwrap().unwrap().is_text());
    let _dir = env.proxy.stop();
    let end = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("splice must end on shutdown");
    assert!(matches!(
        end,
        None | Some(Err(_)) | Some(Ok(Message::Close(_)))
    ));
});

// ---- Internal endpoint --------------------------------------------------------------------

e2e_test!(oversized_cc_body_gets_413, rules = [], |env| {
    let client = env.client();
    let url = env.origin.https_url("cc.test", "/__adblock__/cc");
    let big = client
        .request(reqwest::Method::POST, &url)
        .body(vec![b'a'; 100 * 1024])
        .send()
        .await
        .unwrap();
    assert_eq!(big.status(), 413);
    let small = client
        .request(reqwest::Method::POST, &url)
        .body(r#"{"url":"https://cc.test/","classes":["x"],"ids":[]}"#)
        .send()
        .await
        .unwrap();
    // Well-formed but without a page token: refused (the full flow is in rewrite_e2e).
    assert_eq!(small.status(), 415);
    assert!(env.origin.requests().is_empty());
});

// ---- Response / request correctness -------------------------------------------------------

const AD_RULES: [&str; 1] = ["z.test##.ad"];

e2e_test!(
    zstd_and_stacked_encodings_pass_through_untouched,
    rules = AD_RULES,
    |env| {
        let body = b"\x28\xb5\x2f\xfd not really zstd <html><head></head></html>".to_vec();
        env.origin.route(
            "/z",
            MockResponse::html(body.clone()).header("content-encoding", "zstd"),
        );
        env.origin.route(
            "/stack",
            MockResponse::html(body.clone()).header("content-encoding", "gzip, br"),
        );
        for (path, enc) in [("/z", "zstd"), ("/stack", "gzip, br")] {
            let mut rb = env
                .client_with(HttpVersion::Http1)
                .request(reqwest::Method::GET, &env.origin.https_url("z.test", path));
            for (k, v) in DOC_HEADERS {
                rb = rb.header(k, v);
            }
            let resp = rb.send().await.unwrap();
            assert_eq!(resp.status(), 200);
            assert_eq!(resp.headers()["content-encoding"], enc);
            assert_eq!(resp.headers()["content-length"], body.len().to_string());
            assert_eq!(resp.bytes().await.unwrap().to_vec(), body, "{path}");
        }
    }
);

e2e_test!(
    document_requests_keep_the_clients_accept_encoding,
    rules = AD_RULES,
    |env| {
        env.origin
            .route("/d", MockResponse::html("<html><head></head></html>"));
        env.origin.route("/asset", MockResponse::ok("a"));
        let client = env.client_with(HttpVersion::Http1);
        let mut rb = client
            .request(reqwest::Method::GET, &env.origin.https_url("z.test", "/d"))
            .header("accept-encoding", "gzip, zstd;q=0.9, br");
        for (k, v) in DOC_HEADERS {
            rb = rb.header(k, v);
        }
        assert_eq!(rb.send().await.unwrap().status(), 200);
        let only_zstd = client
            .request(reqwest::Method::GET, &env.origin.https_url("z.test", "/d"))
            .header("accept-encoding", "zstd")
            .header("sec-fetch-dest", "document");
        assert_eq!(only_zstd.send().await.unwrap().status(), 200);
        // Non-document requests are left alone.
        let asset = client
            .request(
                reqwest::Method::GET,
                &env.origin.https_url("z.test", "/asset"),
            )
            .header("accept-encoding", "zstd")
            .header("sec-fetch-dest", "image");
        assert_eq!(asset.send().await.unwrap().status(), 200);
        let enc = |p: &str| {
            let r = env.origin.requests_for(p);
            r.iter()
                .map(|r| {
                    r.headers
                        .iter()
                        .find(|(k, _)| k == "accept-encoding")
                        .map(|(_, v)| v.clone())
                        .unwrap_or_default()
                })
                .collect::<Vec<_>>()
        };
        // Accept-Encoding is forwarded as the client sent it (zstd is decodable now).
        assert_eq!(enc("/d"), vec!["gzip, zstd;q=0.9, br", "zstd"]);
        assert_eq!(enc("/asset"), vec!["zstd"]);
    }
);

e2e_test!(
    head_keeps_content_length_and_gets_no_injection,
    rules = AD_RULES,
    |env| {
        let page = "<html><head></head><body>x</body></html>";
        env.origin.route("/h", MockResponse::html(page));
        let mut rb = env
            .client_with(HttpVersion::Http1)
            .request(reqwest::Method::HEAD, &env.origin.https_url("z.test", "/h"));
        for (k, v) in DOC_HEADERS {
            rb = rb.header(k, v);
        }
        let resp = rb.send().await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers()["content-length"], page.len().to_string());
        assert!(resp.bytes().await.unwrap().is_empty());
    }
);

e2e_test!(
    connection_listed_headers_are_not_forwarded,
    rules = [],
    |env| {
        env.origin.route(
            "/c",
            MockResponse::ok("c")
                .header("connection", "x-resp-hop")
                .header("x-resp-hop", "1")
                .header("x-resp-keep", "1"),
        );
        let resp = env
            .client_with(HttpVersion::Http1)
            .request(reqwest::Method::GET, &env.origin.https_url("c.test", "/c"))
            .header("connection", "x-req-hop")
            .header("x-req-hop", "1")
            .header("x-req-keep", "1")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert!(resp.headers().get("x-resp-hop").is_none());
        assert!(resp.headers().get("x-resp-keep").is_some());
        let sent = &env.origin.requests_for("/c")[0].headers;
        assert!(!sent.iter().any(|(k, _)| k == "x-req-hop"), "{sent:?}");
        assert!(sent.iter().any(|(k, _)| k == "x-req-keep"));
    }
);

e2e_test!(bracketed_ipv6_host_is_parsed, rules = [], |env| {
    env.origin.route("/v6", MockResponse::ok("v6"));
    let port = env.origin.http_port();
    let out = raw_get(&env, &format!("[2001:db8::1]:{port}"), "/v6").await;
    assert!(
        out.starts_with("HTTP/1.1 200") && out.contains("v6"),
        "{out}"
    );
    let got = env.origin.requests_for("/v6");
    assert_eq!(got[0].host, format!("[2001:db8::1]:{port}"));
});

fn bypass_entry(env: &e2e::TestEnv, pattern: &str) {
    env.proxy
        .ctx
        .bypass()
        .update(|s| {
            s.entries.push(common::bypass::Entry {
                id: common::bypass::new_id(),
                pattern: pattern.into(),
                mode: common::bypass::BypassMode::NoDecrypt,
                source: "custom".into(),
                note: None,
                updated_at: 0,
            });
            Ok(())
        })
        .unwrap();
}

// A bypassed host can never ride a decrypted connection, even where the connection's certificate
// covers it (the certificate for a.test covers www.a.test): 421, so the client opens its own.
e2e_test!(
    bypassed_hosts_get_421_on_a_decrypted_connection_h1,
    rules = [],
    |env| {
        env.origin.route("/x", MockResponse::ok("x"));
        let mut s = h1_over_tls(&env, "a.test").await;
        let req = |host: &str| {
            Request::get("/x")
                .header("host", host)
                .body(Empty::<Bytes>::new())
                .unwrap()
        };
        let resp = s.send_request(req("www.a.test")).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "covered subdomain is normally served"
        );
        bypass_entry(&env, "www.a.test");
        let resp = s.send_request(req("www.a.test")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::MISDIRECTED_REQUEST);
        // The connection's own host and other covered names are unaffected.
        for host in ["a.test", "sub.a.test"] {
            let resp = s.send_request(req(host)).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "{host}");
        }
    }
);

e2e_test!(
    bypassed_hosts_get_421_on_a_coalesced_h2_connection,
    rules = [],
    |env| {
        env.origin.route("/y", MockResponse::ok("y"));
        let mut s = h2_over_tls(&env, "a.test").await;
        let port = env.origin.https_port();
        let get = |authority: String| {
            Request::get(format!("https://{authority}/y"))
                .body(Empty::<Bytes>::new())
                .unwrap()
        };
        let ok = s
            .send_request(get(format!("sub.a.test:{port}")))
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);
        bypass_entry(&env, "*.a.test");
        let resp = s
            .send_request(get(format!("sub.a.test:{port}")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::MISDIRECTED_REQUEST);
        assert_eq!(
            env.origin.requests_for("/y").len(),
            1,
            "never reached the origin"
        );
    }
);

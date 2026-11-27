use e2e::{e2e_test, HttpVersion, MockResponse, TestClient};

const BLOCKED_RULES: [&str; 1] = ["||blocked.test^"];

e2e_test!(allowed_https_h1, rules = BLOCKED_RULES, |env| {
    env.origin.route("/hello", MockResponse::ok("origin-hello"));
    let resp = env
        .client_with(HttpVersion::Http1)
        .get(&env.origin.https_url("allowed.test", "/hello"))
        .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.version(), reqwest::Version::HTTP_11);
    assert_eq!(resp.text().await.unwrap(), "origin-hello");
    let got = env.origin.requests_for("/hello");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].scheme, "https");
    assert!(got[0].host.starts_with("allowed.test"));
});

e2e_test!(allowed_https_h2, rules = BLOCKED_RULES, |env| {
    env.origin.route("/hello", MockResponse::ok("origin-hello"));
    let resp = env
        .client_with(HttpVersion::Http2)
        .get(&env.origin.https_url("allowed.test", "/hello"))
        .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.version(), reqwest::Version::HTTP_2);
    assert_eq!(resp.text().await.unwrap(), "origin-hello");
    assert_eq!(env.origin.requests_for("/hello").len(), 1);
});

e2e_test!(blocked_never_reaches_origin, rules = BLOCKED_RULES, |env| {
    env.origin.route("/ad.js", MockResponse::ok("ad"));
    let client = env.client();
    let url = env.origin.https_url("blocked.test", "/ad.js");
    // `proxy.block_response = fail` (the default): the script request fails like a network error.
    let e = client.try_get(&url).await.expect_err("aborted");
    assert!(!e.is_timeout(), "{e:?}");
    // `synthetic`: an empty JS body.
    env.proxy
        .ctx
        .set_block_response(proxy_core::config::BlockResponse::Synthetic);
    let resp = client.get(&url).await;
    assert_eq!(resp.status(), 200); // script block: empty JS body
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/javascript"
    );
    assert_eq!(resp.headers().get("x-adblock").unwrap(), "blocked");
    // Sanity: an allowed request on the same origin does arrive, so "no request" is meaningful.
    env.origin.route("/ok", MockResponse::ok("ok"));
    assert_eq!(
        client
            .get(&env.origin.https_url("allowed.test", "/ok"))
            .await
            .status(),
        200
    );
    assert!(env.origin.requests_for("/ad.js").is_empty());
    assert_eq!(env.origin.requests().len(), 1);
});

e2e_test!(plain_http_through_proxy, rules = BLOCKED_RULES, |env| {
    env.origin.route("/plain", MockResponse::ok("plain-body"));
    let resp = env
        .client()
        .get(&env.origin.http_url("allowed.test", "/plain"))
        .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "plain-body");
    assert_eq!(env.origin.requests_for("/plain")[0].scheme, "http");
});

e2e_test!(
    cosmetic_injection_on_html,
    rules = ["example.test##.ad"],
    |env| {
        env.origin.route(
            "/page",
            MockResponse::html("<html><head></head><body><div class=\"ad\">x</div></body></html>"),
        );
        let resp = env
            .client()
            .request(
                reqwest::Method::GET,
                &env.origin.https_url("example.test", "/page"),
            )
            .header("sec-fetch-dest", "document")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let html = resp.text().await.unwrap();
        assert!(
            html.contains("class=\"ad\""),
            "original content kept: {html}"
        );
        assert!(
            html.contains(".ad{display:none!important}"),
            "no cosmetic rule injected: {html}"
        );
    }
);

e2e_test!(alt_svc_is_stripped, rules = [], |env| {
    env.origin.route(
        "/alt",
        MockResponse::ok("x").header("alt-svc", "h3=\":443\"; ma=86400"),
    );
    for url in [
        env.origin.https_url("alt.test", "/alt"),
        env.origin.http_url("alt.test", "/alt"),
    ] {
        let resp = env.client().get(&url).await;
        assert_eq!(resp.status(), 200, "{url}");
        assert!(resp.headers().get("alt-svc").is_none(), "{url}");
    }
    assert_eq!(env.origin.requests_for("/alt").len(), 2);
});

// The origin must see the SNI hostname with the original destination's port.
e2e_test!(sni_host_and_origin_port_reach_origin, rules = [], |env| {
    env.origin.route("/sni", MockResponse::ok("ok"));
    let resp = env
        .client_with(HttpVersion::Http1)
        .get(&env.origin.https_url("sni.test", "/sni"))
        .await;
    assert_eq!(resp.status(), 200);
    let got = env.origin.requests_for("/sni");
    assert_eq!(got[0].host, format!("sni.test:{}", env.origin.https_port()));
    assert_eq!(env.proxy.mitm.as_ref().unwrap().generation_count(), 1);
});

// Exact and `*.suffix` entries are tunnelled in both entry modes: a client that trusts ONLY the
// origin CA succeeds (so it saw the origin's certificate) and no certificate is minted, while a
// client trusting only the proxy CA fails the handshake. Unlisted hosts are still intercepted.
e2e_test!(
    passthrough_hosts_are_not_intercepted,
    // No blocking rules for these hosts: passthrough hosts migrate to `no_decrypt` bypass, which
    // keeps host-level blocking (see bypass_e2e for that).
    rules = Vec::<&str>::new(),
    passthrough = ["pinned.test", "*.wild.test"],
    |env| {
        env.origin.route("/p", MockResponse::ok("origin-direct"));
        let origin_ca = env.origin.ca_pem().as_bytes();
        let direct = TestClient::trusting(&env.proxy, HttpVersion::Http1, &[origin_ca]);
        for host in ["pinned.test", "a.wild.test"] {
            let resp = direct.get(&env.origin.https_url(host, "/p")).await;
            assert_eq!(resp.status(), 200, "{host}");
            assert_eq!(resp.text().await.unwrap(), "origin-direct");
        }
        assert_eq!(env.origin.requests_for("/p").len(), 2);
        assert_eq!(env.proxy.mitm.as_ref().unwrap().generation_count(), 0);

        let mitm_only = env.client_with(HttpVersion::Http1);
        let err = mitm_only
            .request(
                reqwest::Method::GET,
                &env.origin.https_url("pinned.test", "/p"),
            )
            .send()
            .await;
        assert!(
            err.is_err(),
            "proxy CA must not be presented for passthrough hosts"
        );

        // `*.wild.test` does not cover the apex, and other hosts are intercepted as usual.
        let resp = mitm_only
            .request(
                reqwest::Method::GET,
                &env.origin.https_url("wild.test", "/p"),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(env.proxy.mitm.as_ref().unwrap().generation_count(), 1);
    }
);

// Port-80 style: the target comes from the Host header; without one, from the original
// destination address.
e2e_test!(
    plain_http_host_header_routing,
    rules = [],
    transparent_only,
    |env| {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        env.origin.route("/h", MockResponse::ok("routed"));
        for (req, want_host) in [
            (
                "GET /h HTTP/1.1\r\nHost: route.test\r\nConnection: close\r\n\r\n".to_string(),
                "route.test",
            ),
            ("GET /h HTTP/1.0\r\n\r\n".to_string(), "203.0.113.7"),
        ] {
            let mut tcp = tokio::net::TcpStream::connect(env.proxy.entry_addr())
                .await
                .unwrap();
            tcp.write_all(req.as_bytes()).await.unwrap();
            let mut out = Vec::new();
            tcp.read_to_end(&mut out).await.unwrap();
            let text = String::from_utf8_lossy(&out);
            assert!(text.contains(" 200 OK"), "{text}");
            assert!(text.contains("routed"), "{text}");
            let got = env.origin.requests_for("/h");
            let last = got.last().unwrap();
            assert_eq!(last.host, format!("{want_host}:{}", env.origin.http_port()));
        }
    }
);

// An original destination that is the proxy itself is refused, never dialled.
e2e_test!(
    loop_guard_refuses_own_address,
    rules = [],
    transparent_only,
    |env| {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        env.proxy.dst.force(env.proxy.transparent_addr.unwrap());
        let mut tcp = tokio::net::TcpStream::connect(env.proxy.entry_addr())
            .await
            .unwrap();
        let _ = tcp
            .write_all(b"GET /loop HTTP/1.1\r\nHost: loop.test\r\n\r\n")
            .await;
        let mut out = Vec::new();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), tcp.read_to_end(&mut out))
            .await
            .expect("connection closed promptly");
        assert!(
            out.is_empty(),
            "no response expected: {:?}",
            String::from_utf8_lossy(&out)
        );
        assert!(env.origin.requests().is_empty());
    }
);

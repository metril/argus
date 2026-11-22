//! Match-result behaviour end to end: redirects, removeparam, `$csp`, rule precedence, block
//! response shapes and streamed uploads.

use e2e::{e2e_test, MockResponse, TestEnv};

async fn get_as(env: &TestEnv, url: &str, dest: &str) -> reqwest::Response {
    env.client()
        .request(reqwest::Method::GET, url)
        .header("sec-fetch-dest", dest)
        .header("sec-fetch-site", "cross-site")
        .header("referer", "https://page.test/")
        .send()
        .await
        .unwrap_or_else(|e| panic!("GET {url} failed: {e:?}"))
}

e2e_test!(
    redirect_resource_served_by_proxy,
    rules = ["||ads.test^$redirect=1x1.gif"],
    |env| {
        env.origin.route("/pixel.gif", MockResponse::ok("real"));
        let resp = get_as(
            &env,
            &env.origin.https_url("ads.test", "/pixel.gif"),
            "image",
        )
        .await;
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers()["content-type"], "image/gif");
        assert_eq!(resp.headers()["x-adblock"], "redirected");
        assert!(resp.bytes().await.unwrap().starts_with(b"GIF8"));
        assert!(
            env.origin.requests().is_empty(),
            "redirect must not hit origin"
        );
    }
);

e2e_test!(
    redirect_rule_serves_noop_js,
    rules = ["||ads.test^$script", "||ads.test^$redirect-rule=noop.js"],
    |env| {
        let resp = get_as(&env, &env.origin.https_url("ads.test", "/a.js"), "script").await;
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers()["content-type"], "application/javascript");
        assert!(!resp.text().await.unwrap().is_empty());
        assert!(env.origin.requests().is_empty());
    }
);

e2e_test!(
    removeparam_subresource_fetches_cleaned_url,
    rules = ["||rm.test^$removeparam=utm"],
    |env| {
        env.origin.route("/p", MockResponse::ok("body"));
        let resp = get_as(
            &env,
            &env.origin.https_url("rm.test", "/p?a=1&utm=2"),
            "empty",
        )
        .await;
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.text().await.unwrap(), "body");
        let got = env.origin.requests_for("/p");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].path_and_query, "/p?a=1");
    }
);

e2e_test!(
    removeparam_document_gets_307,
    rules = ["||rm.test^$removeparam=utm"],
    |env| {
        env.origin.route("/p", MockResponse::ok("body"));
        let resp = get_as(
            &env,
            &env.origin.https_url("rm.test", "/p?a=1&utm=2"),
            "document",
        )
        .await;
        assert_eq!(resp.status(), 307);
        let loc = resp.headers()["location"].to_str().unwrap().to_string();
        assert!(loc.starts_with("https://rm.test:"), "{loc}");
        assert!(loc.ends_with("/p?a=1"), "{loc}");
        assert!(env.origin.requests().is_empty());
    }
);

e2e_test!(
    csp_header_added_on_documents_only,
    rules = ["||csp.test^$csp=script-src 'none'"],
    |env| {
        env.origin.route(
            "/page",
            MockResponse::html("<html><head></head><body>x</body></html>")
                .header("content-security-policy", "img-src *"),
        );
        let url = env.origin.https_url("csp.test", "/page");
        let resp = get_as(&env, &url, "document").await;
        assert_eq!(resp.status(), 200);
        let all: Vec<_> = resp
            .headers()
            .get_all("content-security-policy")
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        assert!(
            all.contains(&"img-src *".to_string()),
            "origin CSP kept: {all:?}"
        );
        assert!(all.contains(&"script-src 'none'".to_string()), "{all:?}");

        // Not added to subresources.
        let resp = get_as(&env, &url, "image").await;
        assert!(resp
            .headers()
            .get("content-security-policy")
            .is_some_and(|v| v == "img-src *"));
        assert_eq!(
            resp.headers()
                .get_all("content-security-policy")
                .iter()
                .count(),
            1
        );
    }
);

e2e_test!(
    exception_beats_block,
    rules = ["||ex.test^", "@@||ex.test^*ok"],
    |env| {
        env.origin.route("/ok", MockResponse::ok("fine"));
        env.origin.route("/bad", MockResponse::ok("never"));
        let ok = get_as(&env, &env.origin.https_url("ex.test", "/ok"), "image").await;
        assert_eq!(ok.status(), 200);
        assert_eq!(ok.text().await.unwrap(), "fine");
        let bad = get_as(&env, &env.origin.https_url("ex.test", "/bad"), "image").await;
        assert_eq!(bad.headers()["x-adblock"], "blocked");
        assert_eq!(env.origin.requests().len(), 1);
    }
);

e2e_test!(
    important_beats_exception,
    rules = [
        "||imp.test^$important",
        "@@||imp.test^",
        "||plain.test^",
        "@@||plain.test^"
    ],
    |env| {
        env.origin.route("/x", MockResponse::ok("origin"));
        let imp = get_as(&env, &env.origin.https_url("imp.test", "/x"), "image").await;
        assert_eq!(imp.headers()["x-adblock"], "blocked");
        let plain = get_as(&env, &env.origin.https_url("plain.test", "/x"), "image").await;
        assert_eq!(plain.status(), 200);
        assert_eq!(plain.text().await.unwrap(), "origin");
        assert_eq!(env.origin.requests().len(), 1);
    }
);

e2e_test!(
    block_response_shape_per_type,
    rules = ["||blk.test^"],
    |env| {
        // (Sec-Fetch-Dest, status, content-type, body check)
        let cases: [(&str, u16, Option<&str>); 8] = [
            ("document", 403, Some("text/html; charset=utf-8")),
            ("iframe", 200, Some("text/html; charset=utf-8")),
            ("image", 200, Some("image/gif")),
            ("script", 200, Some("application/javascript")),
            ("style", 200, Some("text/css")),
            ("empty", 204, None),
            ("font", 204, None),
            ("video", 204, None),
        ];
        for (dest, status, ctype) in cases {
            let resp = get_as(&env, &env.origin.https_url("blk.test", "/r"), dest).await;
            assert_eq!(resp.status(), status, "dest={dest}");
            assert_eq!(resp.headers()["x-adblock"], "blocked", "dest={dest}");
            assert_eq!(resp.headers()["cache-control"], "no-store", "dest={dest}");
            match ctype {
                Some(c) => assert_eq!(resp.headers()["content-type"], c, "dest={dest}"),
                None => assert!(resp.headers().get("content-type").is_none(), "dest={dest}"),
            }
            let body = resp.bytes().await.unwrap();
            match dest {
                "document" => {
                    let s = String::from_utf8_lossy(&body);
                    assert!(s.contains("||blk.test^"), "block page names the rule: {s}");
                }
                "image" => assert!(body.starts_with(b"GIF8")),
                "script" | "style" | "empty" | "font" | "video" => assert!(body.is_empty()),
                _ => {}
            }
        }
        assert!(env.origin.requests().is_empty());
    }
);

e2e_test!(
    third_party_with_origin_only_referer,
    rules = ["||tp.test^$third-party"],
    |env| {
        env.origin.route("/x", MockResponse::ok("o"));
        let url = env.origin.https_url("tp.test", "/x");
        let send = |referer: &'static str| {
            let c = env.client();
            let url = url.clone();
            async move {
                c.request(reqwest::Method::GET, &url)
                    .header("sec-fetch-dest", "script")
                    .header("referer", referer)
                    .send()
                    .await
                    .unwrap()
            }
        };
        // Referer reduced to an origin: foreign page -> third-party -> blocked.
        assert_eq!(
            send("https://other.test/").await.headers()["x-adblock"],
            "blocked"
        );
        // Same registrable domain page -> first-party -> allowed.
        assert_eq!(send("https://www.tp.test/").await.status(), 200);
    }
);

e2e_test!(
    large_upload_streams_round_trip,
    rules = ["||blocked.test^"],
    |env| {
        env.origin
            .route_fn("/echo", |r| MockResponse::ok(r.body.clone()));
        let payload: Vec<u8> = (0..8 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
        let resp = env
            .client()
            .request(
                reqwest::Method::POST,
                &env.origin.https_url("up.test", "/echo"),
            )
            .body(payload.clone())
            .send()
            .await
            .expect("upload");
        assert_eq!(resp.status(), 200);
        let echoed = resp.bytes().await.unwrap();
        assert_eq!(echoed.len(), payload.len());
        assert!(echoed.as_ref() == payload.as_slice(), "echoed body differs");
        let rec = env.origin.requests_for("/echo");
        assert_eq!(rec.len(), 1);
        assert_eq!(rec[0].method, "POST");
        assert_eq!(rec[0].body.len(), payload.len());
    }
);

e2e_test!(live_enabled_toggle, rules = ["||tg.test^"], |env| {
    env.origin.route("/x", MockResponse::ok("o"));
    let url = env.origin.https_url("tg.test", "/x");
    assert_eq!(
        get_as(&env, &url, "image").await.headers()["x-adblock"],
        "blocked"
    );
    env.proxy.engine.set_enabled(false);
    assert_eq!(get_as(&env, &url, "image").await.text().await.unwrap(), "o");
    env.proxy.engine.set_enabled(true);
    assert_eq!(
        get_as(&env, &url, "image").await.headers()["x-adblock"],
        "blocked"
    );
});

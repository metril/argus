use e2e::{e2e_test, HttpVersion, MockResponse};

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
    let resp = client
        .get(&env.origin.https_url("blocked.test", "/ad.js"))
        .await;
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
            .get(&env.origin.https_url("example.test", "/page"))
            .await;
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

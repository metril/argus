//! Extended (uBO / AdGuard) rules on the wire: one scenario per kind, both entry modes, over
//! HTTP/1.1 and HTTP/2 where the transport matters.

use e2e::{
    decode, e2e_test, encode, Coding, EntryMode, HttpVersion, MockResponse, StreamSpec, TestEnv,
};
use std::sync::Arc;

const VERSIONS: [HttpVersion; 2] = [HttpVersion::Http1, HttpVersion::Http2];
const H: &str = "ext.test";

/// GET `path` as a browser would for `dest` (`document`, `script`, `empty`, ...).
async fn get(
    env: &TestEnv,
    v: HttpVersion,
    path: &str,
    dest: &str,
    extra: &[(&str, &str)],
) -> reqwest::Response {
    let mut rb = env
        .client_with(v)
        .request(reqwest::Method::GET, &env.origin.https_url(H, path))
        .header("sec-fetch-dest", dest);
    if dest == "document" {
        rb = rb
            .header("sec-fetch-mode", "navigate")
            .header("accept", "text/html");
    }
    for (k, val) in extra {
        rb = rb.header(*k, *val);
    }
    rb.send().await.expect("request")
}

async fn text(r: impl std::future::Future<Output = reqwest::Response>) -> String {
    String::from_utf8(r.await.bytes().await.unwrap().to_vec()).unwrap()
}

fn js(body: &str) -> MockResponse {
    MockResponse::ok(body).header("content-type", "application/javascript")
}

// ---- body transforms -------------------------------------------------------------------------

e2e_test!(
    replace_changes_js_html_and_gzipped_bodies,
    rules = ["||ext.test^$replace=/adsbygoogle/noads/"],
    |env| {
        env.origin.route("/a.js", js("var x='adsbygoogle';"));
        env.origin.route(
            "/p",
            MockResponse::html(
                "<!DOCTYPE html><html><head></head><body><p>adsbygoogle</p></body></html>",
            ),
        );
        let gz = encode(Coding::Gzip, b"var y='adsbygoogle';").await;
        env.origin.route(
            "/z.js",
            MockResponse::ok(gz)
                .header("content-type", "application/javascript")
                .header("content-encoding", "gzip"),
        );
        for v in VERSIONS {
            assert_eq!(
                text(get(&env, v, "/a.js", "script", &[])).await,
                "var x='noads';"
            );
            let html = text(get(&env, v, "/p", "document", &[])).await;
            assert!(
                html.contains("<p>noads</p>") && !html.contains("adsbygoogle"),
                "{html}"
            );
            let r = get(&env, v, "/z.js", "script", &[("accept-encoding", "gzip")]).await;
            assert_eq!(r.headers()["content-encoding"], "gzip");
            let raw = r.bytes().await.unwrap();
            assert_eq!(decode(&[Coding::Gzip], &raw).await, b"var y='noads';");
        }
    }
);

e2e_test!(
    jsonprune_removes_a_key_from_an_api_response,
    rules = ["/api^$jsonprune=\\$.ads"],
    |env| {
        env.origin.route(
            "/api",
            MockResponse::ok(r#"{"ads":[1,2],"keep":{"a":1}}"#)
                .header("content-type", "application/json"),
        );
        for v in VERSIONS {
            let j: serde_json::Value =
                serde_json::from_str(&text(get(&env, v, "/api", "empty", &[])).await).unwrap();
            assert_eq!(j, serde_json::json!({"keep": {"a": 1}}));
        }
    }
);

e2e_test!(
    hls_drops_ad_segments,
    rules = [".m3u8$hls=/ads\\.ext\\.test/"],
    |env| {
        let pl = "#EXTM3U\n#EXT-X-TARGETDURATION:4\n#EXTINF:4,\nhttps://cdn.ext.test/c1.ts\n#EXTINF:4,\nhttps://ads.ext.test/ad1.ts\n#EXTINF:4,\nhttps://cdn.ext.test/c2.ts\n#EXT-X-ENDLIST\n";
        env.origin.route(
            "/v.m3u8",
            MockResponse::ok(pl).header("content-type", "application/vnd.apple.mpegurl"),
        );
        for v in VERSIONS {
            let out = text(get(&env, v, "/v.m3u8", "empty", &[])).await;
            assert!(
                !out.contains("ad1.ts") && out.contains("c1.ts") && out.contains("c2.ts"),
                "{out}"
            );
            assert!(out.contains("#EXT-X-ENDLIST"));
        }
    }
);

e2e_test!(
    oversized_body_passes_through_untouched_and_is_counted,
    rules = ["||ext.test^$replace=/adsbygoogle/noads/"],
    |env| {
        // Streamed (no Content-Length), 3.5 MiB: over the 3 MiB `$replace` cap.
        let total = 3 * 1024 * 1024 + 512 * 1024;
        env.origin.route(
            "/big.js",
            MockResponse::streaming(
                200,
                StreamSpec::new("adsbygoogle", vec![b'a'; 64 * 1024], total),
            )
            .header("content-type", "application/javascript"),
        );
        let before = proxy_core::rewrite::pipeline::over_cap_total();
        let body = get(&env, HttpVersion::Http1, "/big.js", "script", &[])
            .await
            .bytes()
            .await
            .unwrap();
        assert!(body.starts_with(b"adsbygoogle"), "must be untouched");
        assert!(body.len() >= total);
        assert!(proxy_core::rewrite::pipeline::over_cap_total() > before);
    }
);

// ---- headers and cookies ---------------------------------------------------------------------

e2e_test!(
    removeheader_removes_and_refuses_forbidden_headers,
    rules = [
        "||ext.test^$removeheader=x-secret",
        "||ext.test^$removeheader=access-control-allow-origin",
    ],
    |env| {
        env.origin.route(
            "/h",
            MockResponse::ok("x")
                .header("x-secret", "1")
                .header("access-control-allow-origin", "*"),
        );
        for v in VERSIONS {
            let r = get(&env, v, "/h", "empty", &[]).await;
            assert!(r.headers().get("x-secret").is_none());
            assert_eq!(r.headers()["access-control-allow-origin"], "*");
        }
    }
);

e2e_test!(
    cookie_rule_strips_set_cookie_and_request_cookie,
    rules = ["||ext.test^$cookie=track"],
    |env| {
        env.origin.route(
            "/c",
            MockResponse::ok("x")
                .header("set-cookie", "track=1; Path=/")
                .header("set-cookie", "keep=2; Path=/"),
        );
        for v in VERSIONS {
            let r = get(&env, v, "/c", "empty", &[("cookie", "track=9; keep=8")]).await;
            let set: Vec<_> = r.headers().get_all("set-cookie").iter().collect();
            assert_eq!(set.len(), 1, "{set:?}");
            assert!(set[0].to_str().unwrap().starts_with("keep=2"));
        }
        let seen = env.origin.requests_for("/c");
        assert!(!seen.is_empty());
        for r in seen {
            let cookie = r
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("cookie"))
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            assert_eq!(cookie, "keep=8");
        }
    }
);

e2e_test!(
    permissions_rule_adds_the_header_on_documents,
    rules = ["||ext.test^$permissions=geolocation=()"],
    |env| {
        env.origin
            .route("/p", MockResponse::html("<html><body>x</body></html>"));
        for v in VERSIONS {
            let r = get(&env, v, "/p", "document", &[]).await;
            assert_eq!(r.headers()["permissions-policy"], "geolocation=()");
        }
    }
);

e2e_test!(
    header_rule_blocks_a_response_with_a_matching_header,
    rules = ["/hdr.js^$header=x-ad:yes"],
    |env| {
        env.origin
            .route("/hdr.js", js("real();").header("x-ad", "yes"));
        for v in VERSIONS {
            let r = get(&env, v, "/hdr.js", "script", &[]).await;
            assert_eq!(r.headers()["x-adblock"], "blocked");
            assert_eq!(r.text().await.unwrap(), "");
        }
    }
);

// ---- request side ----------------------------------------------------------------------------

e2e_test!(
    denyallow_method_and_to_block_requests,
    rules = [
        "/dblk$denyallow=good.test",
        "/mblk^$method=post",
        "/tblk$to=ext.test,xhr",
    ],
    |env| {
        for p in ["/dblk", "/mblk", "/tblk", "/ok"] {
            env.origin.route(p, MockResponse::ok("real"));
        }
        for v in VERSIONS {
            let blocked = |r: &reqwest::Response| r.headers().contains_key("x-adblock");
            assert!(
                blocked(&get(&env, v, "/dblk", "script", &[]).await),
                "denyallow"
            );
            assert!(blocked(&get(&env, v, "/tblk", "empty", &[]).await), "to");
            assert!(!blocked(&get(&env, v, "/ok", "script", &[]).await));
            // $method=post blocks POST only.
            assert!(
                !blocked(&get(&env, v, "/mblk", "empty", &[]).await),
                "GET passes"
            );
            let r = env
                .client_with(v)
                .request(reqwest::Method::POST, &env.origin.https_url(H, "/mblk"))
                .header("sec-fetch-dest", "empty")
                .send()
                .await
                .unwrap();
            assert!(blocked(&r), "POST blocked");
        }
        assert!(env.origin.requests_for("/dblk").is_empty());
        assert!(env.origin.requests_for("/tblk").is_empty());
    }
);

e2e_test!(
    urltransform_rewrites_the_upstream_url,
    rules = ["x1^$urltransform=/x1/x2/"],
    |env| {
        env.origin.route("/x2", MockResponse::ok("rewritten"));
        for v in VERSIONS {
            assert_eq!(text(get(&env, v, "/x1", "empty", &[])).await, "rewritten");
        }
        assert!(env.origin.requests_for("/x1").is_empty());
    }
);

// ---- HTML filters and injections -------------------------------------------------------------

const SCRIPTS: &str = "<!DOCTYPE html><html><head><script>detect_adblock()</script><script>keep_me()</script></head><body>b</body></html>";

e2e_test!(
    html_filters_remove_one_inline_script_and_keep_the_rest,
    rules = [
        "ext.test##^script:has-text(detect_adblock)",
        "ext.test$$script[tag-content=\"other_ad\"]",
    ],
    |env| {
        env.origin.route("/p", MockResponse::html(SCRIPTS));
        env.origin.route(
            "/q",
            MockResponse::html("<html><head><script>other_ad()</script><script>keep_me()</script></head><body></body></html>"),
        );
        for v in VERSIONS {
            let a = text(get(&env, v, "/p", "document", &[])).await;
            assert!(
                !a.contains("detect_adblock") && a.contains("keep_me()"),
                "{a}"
            );
            let b = text(get(&env, v, "/q", "document", &[])).await;
            assert!(!b.contains("other_ad") && b.contains("keep_me()"), "{b}");
        }
    }
);

/// The inline-bundle URLs (`/__adblock__/s/..js`) a page references, fetched through the proxy.
async fn bundles(env: &TestEnv, html: &str) -> String {
    let mut all = String::new();
    let mut rest = html;
    while let Some(i) = rest.find("src=\"/__adblock__/s/") {
        let r = &rest[i + 5..];
        let path = &r[..r.find('"').unwrap()];
        all.push_str(&text(env.client().get(&env.origin.https_url(H, path))).await);
        rest = &r[1..];
    }
    all
}

e2e_test!(
    js_injection_comes_only_from_trusted_lists,
    rules = ["ext.test#%#window.__trusted_marker=1;"],
    |env| {
        env.origin.route(
            "/p",
            MockResponse::html("<html><head></head><body>x</body></html>"),
        );
        let html = text(get(&env, HttpVersion::Http1, "/p", "document", &[])).await;
        assert!(
            html.contains("/__adblock__/boot."),
            "runtime must load first: {html}"
        );
        assert!(bundles(&env, &html)
            .await
            .contains("window.__trusted_marker=1;"));
    }
);

e2e_test!(
    js_injection_is_dropped_and_counted_for_untrusted_lists,
    rules = ["!untrusted", "ext.test#%#window.__untrusted_marker=1;"],
    |env| {
        env.origin.route(
            "/p",
            MockResponse::html("<html><head></head><body>x</body></html>"),
        );
        let html = text(get(&env, HttpVersion::Http1, "/p", "document", &[])).await;
        assert!(!html.contains("/__adblock__/s/"), "{html}");
        let g = env.proxy.engine.generation();
        let st = g.aux::<ext_rules::ExtIndex>().unwrap().stats().clone();
        assert_eq!(st.per_kind["js-inject"].dropped_untrusted, 1);
        assert_eq!(st.dropped_untrusted_by_list["test"], 1);
    }
);

// ---- exceptions ------------------------------------------------------------------------------

e2e_test!(
    exception_rules_disable_each_kind,
    rules = [
        "||ext.test^$replace=/adsbygoogle/noads/",
        "@@/n1.js^$replace",
        "/n2^$jsonprune=\\$.ads",
        "@@/n2^$jsonprune",
        "||ext.test^$removeheader=x-secret",
        "@@/n3^$removeheader",
        "/n4$denyallow=good.test",
        "@@/n4$denyallow=good.test",
        "/n5^$cookie=track",
        "@@/n5^$cookie",
        "x7^$urltransform=/x7/x8/",
        "@@x7^$urltransform",
        ".n8m3u8$hls=/ads/",
        "@@.n8m3u8$hls",
        "/n9.js^$header=x-ad:yes",
        "@@/n9.js^$header",
        "/n10^$method=get",
        "@@/n10^$method=get",
        "/n11$to=ext.test,xhr",
        "@@/n11$to=ext.test",
    ],
    |env| {
        env.origin.route("/n1.js", js("var x='adsbygoogle';"));
        env.origin.route(
            "/n2",
            MockResponse::ok(r#"{"ads":1}"#).header("content-type", "application/json"),
        );
        env.origin
            .route("/n3", MockResponse::ok("x").header("x-secret", "1"));
        env.origin.route("/n4", MockResponse::ok("real"));
        env.origin
            .route("/n5", MockResponse::ok("x").header("set-cookie", "track=1"));
        env.origin.route("/x7", MockResponse::ok("not transformed"));
        env.origin.route(
            "/v.n8m3u8",
            MockResponse::ok("#EXTM3U\n#EXTINF:4,\nhttps://ads.ext.test/a.ts\n#EXT-X-ENDLIST\n")
                .header("content-type", "application/vnd.apple.mpegurl"),
        );
        env.origin
            .route("/n9.js", js("real();").header("x-ad", "yes"));
        env.origin.route("/n10", MockResponse::ok("real"));
        env.origin.route("/n11", MockResponse::ok("real"));
        for v in VERSIONS {
            assert_eq!(
                text(get(&env, v, "/x7", "empty", &[])).await,
                "not transformed"
            );
            assert!(text(get(&env, v, "/v.n8m3u8", "empty", &[]))
                .await
                .contains("a.ts"));
            assert_eq!(text(get(&env, v, "/n9.js", "script", &[])).await, "real();");
            assert_eq!(text(get(&env, v, "/n10", "empty", &[])).await, "real");
            assert_eq!(text(get(&env, v, "/n11", "empty", &[])).await, "real");
            assert_eq!(
                text(get(&env, v, "/n1.js", "script", &[])).await,
                "var x='adsbygoogle';"
            );
            assert_eq!(
                text(get(&env, v, "/n2", "empty", &[])).await,
                r#"{"ads":1}"#
            );
            assert!(get(&env, v, "/n3", "empty", &[])
                .await
                .headers()
                .contains_key("x-secret"));
            assert_eq!(text(get(&env, v, "/n4", "script", &[])).await, "real");
            assert!(get(&env, v, "/n5", "empty", &[])
                .await
                .headers()
                .contains_key("set-cookie"));
        }
    }
);

e2e_test!(
    exception_rules_disable_html_filters_and_injections,
    rules = [
        "ext.test##^script:has-text(detect_adblock)",
        "ext.test#@#^script:has-text(detect_adblock)",
        "ext.test#%#window.__m=1;",
        "ext.test#@%#",
        "||ext.test^$permissions=geolocation=()",
        "@@||ext.test^$permissions",
    ],
    |env| {
        env.origin.route("/p", MockResponse::html(SCRIPTS));
        let r = get(&env, HttpVersion::Http1, "/p", "document", &[]).await;
        assert!(r.headers().get("permissions-policy").is_none());
        let html = text(async { r }).await;
        assert!(html.contains("detect_adblock()"), "{html}");
        assert!(!html.contains("/__adblock__/s/"), "{html}");
    }
);

// ---- no-transform and clients without Fetch Metadata ----------------------------------------------

const NT_RULES: [&str; 2] = [
    "||ext.test^$replace=/adsbygoogle/noads/",
    "||ext.test^$removeheader=x-secret",
];

fn nt_page() -> MockResponse {
    MockResponse::html("<html><head></head><body>adsbygoogle</body></html>")
        .header("cache-control", "public, No-Transform")
        .header("x-secret", "1")
}

#[tokio::test]
async fn no_transform_keeps_the_body_but_header_edits_still_apply() {
    for mode in [EntryMode::Explicit, EntryMode::Transparent] {
        let env = TestEnv::start(mode, &NT_RULES).await;
        env.origin.route("/nt", nt_page());
        let r = get(&env, HttpVersion::Http1, "/nt", "document", &[]).await;
        assert!(r.headers().get("x-secret").is_none(), "header edit applies");
        let body = r.text().await.unwrap();
        assert!(
            body.contains("adsbygoogle") && !body.contains("__adblock"),
            "{body}"
        );
    }
}

#[tokio::test]
async fn no_transform_can_be_overridden_by_config() {
    let env = TestEnv::start_tweaked(EntryMode::Explicit, &NT_RULES, &|c| {
        c.adblock.respect_no_transform = false
    })
    .await;
    env.origin.route("/nt", nt_page());
    let body = text(get(&env, HttpVersion::Http1, "/nt", "document", &[])).await;
    assert!(
        body.contains("noads") && !body.contains("adsbygoogle"),
        "{body}"
    );
}

e2e_test!(
    clients_without_fetch_metadata_still_get_documents_rewritten,
    rules = ["ext.test##^script:has-text(detect_adblock)"],
    |env| {
        env.origin.route("/p", MockResponse::html(SCRIPTS));
        // No Sec-Fetch-* at all: an old browser's navigation (Accept + Upgrade-Insecure-Requests)
        // and a bare `Accept: text/html` client.
        for extra in [
            &[
                ("accept", "text/html,application/xhtml+xml"),
                ("upgrade-insecure-requests", "1"),
            ][..],
            &[("accept", "text/html")][..],
        ] {
            let mut rb = env
                .client_with(HttpVersion::Http1)
                .request(reqwest::Method::GET, &env.origin.https_url(H, "/p"));
            for (k, v) in extra {
                rb = rb.header(*k, *v);
            }
            let html = rb.send().await.unwrap().text().await.unwrap();
            assert!(
                !html.contains("detect_adblock") && html.contains("keep_me()"),
                "{html}"
            );
        }
    }
);

// ---- atomic swap -----------------------------------------------------------------------------

/// The engine's `$removeparam` and the ext index's `$urltransform` come from one build: a
/// request must never see the engine of one build with the ext rules of the other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn engine_and_ext_rules_swap_together_under_concurrent_requests() {
    let env = Arc::new(TestEnv::start(EntryMode::Explicit, &[]).await);
    let a = [
        "||ext.test^$removeparam=a",
        "probe$urltransform=/probe/probeA/",
    ];
    let b = [
        "||ext.test^$removeparam=b",
        "probe$urltransform=/probe/probeB/",
    ];
    env.proxy.install_rules(&a);
    env.origin.route("/probeA", MockResponse::ok("A"));
    env.origin.route("/probeB", MockResponse::ok("B"));
    let swapper = {
        let env = env.clone();
        tokio::task::spawn_blocking(move || {
            for i in 0..60 {
                env.proxy.install_rules(if i % 2 == 0 { &b } else { &a });
            }
        })
    };
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let env = env.clone();
        tasks.push(tokio::spawn(async move {
            for _ in 0..40 {
                let r = env
                    .client_with(HttpVersion::Http1)
                    .request(
                        reqwest::Method::GET,
                        &env.origin.https_url(H, "/probe?a=1&b=1"),
                    )
                    .header("sec-fetch-dest", "empty")
                    .send()
                    .await
                    .unwrap();
                assert_eq!(r.status(), 200);
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    swapper.await.unwrap();
    let seen = env.origin.requests();
    assert!(seen.len() >= 160);
    for r in seen {
        match r.path_and_query.as_str() {
            "/probeA?b=1" | "/probeB?a=1" => {}
            other => panic!("torn generation: {other}"),
        }
    }
}

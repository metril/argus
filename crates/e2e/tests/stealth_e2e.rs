//! Stealth Mode through the real proxy: each option, live settings changes, `$stealth`
//! exceptions, full bypass and per-site blocking-off.

use common::bypass::{new_id, BypassMode, Entry};
use common::config::StealthSettings;
use e2e::{EntryMode, MockResponse, TestEnv};

const PAGE: &str = "https://page.test/article?q=1";

/// Events in the request log whose URL contains `needle` and whose rule is `rule`.
fn logged_with(env: &TestEnv, needle: &str, rule: &str) -> Vec<filter_engine::RequestEvent> {
    env.proxy
        .engine
        .recent_requests(1000)
        .into_iter()
        .filter(|e| e.url.contains(needle) && e.rule.as_deref().unwrap_or("") == rule)
        .collect()
}

async fn env_with(rules: &[&str], f: impl Fn(&mut StealthSettings)) -> TestEnv {
    let env = TestEnv::start_tweaked(EntryMode::Explicit, rules, &|c| {
        c.stealth.enabled = true;
        // Off by default; on here so each test starts from the full set.
        c.stealth.block_webrtc = true;
        c.stealth.block_push = true;
        c.stealth.block_location = true;
        c.stealth.strip_tracking_params = true;
        f(&mut c.stealth);
    })
    .await;
    env.origin.route("/a.js", MockResponse::ok("x"));
    env
}

/// A cross-site subresource fetch from `PAGE`.
async fn third_party(
    env: &TestEnv,
    host: &str,
    path: &str,
    extra: &[(&str, &str)],
) -> reqwest::Response {
    let mut r = env
        .client()
        .request(reqwest::Method::GET, &env.origin.https_url(host, path))
        .header("sec-fetch-dest", "script")
        .header("sec-fetch-site", "cross-site");
    if !extra.iter().any(|(k, _)| *k == "referer") {
        r = r.header("referer", PAGE);
    }
    for (k, v) in extra {
        r = r.header(*k, *v);
    }
    r.send().await.expect("request")
}

fn header(env: &TestEnv, path: &str, name: &str) -> Option<String> {
    let got = env.origin.requests_for(path);
    assert_eq!(got.len(), 1, "origin saw {} requests for {path}", got.len());
    got[0]
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

#[tokio::test]
async fn off_by_default_changes_nothing() {
    let env = TestEnv::start(EntryMode::Explicit, &[]).await;
    env.origin.route("/a.js", MockResponse::ok("x"));
    env.origin.route(
        "/c",
        MockResponse::ok("x")
            .header("set-cookie", "t=1; Max-Age=999999")
            .header("etag", "\"v1\""),
    );
}

#[tokio::test]
async fn request_headers_follow_the_options_and_live_changes() {
    let env = env_with(&[], |_| {}).await;
    let extra = [
        ("x-client-data", "abc"),
        ("authorization", "Bearer t"),
        ("if-none-match", "\"e\""),
    ];
    third_party(&env, "cdn.test", "/a.js", &extra).await;
    assert_eq!(header(&env, "/a.js", "dnt").as_deref(), Some("1"));
    assert_eq!(header(&env, "/a.js", "sec-gpc").as_deref(), Some("1"));
    assert_eq!(header(&env, "/a.js", "x-client-data"), None);
    assert_eq!(header(&env, "/a.js", "if-none-match"), None);
    // Third-party Referer: the target's own origin.
    assert_eq!(
        header(&env, "/a.js", "referer").as_deref(),
        Some(env.origin.https_url("cdn.test", "/").as_str())
    );
    // Authorization is off by default.
    assert_eq!(
        header(&env, "/a.js", "authorization").as_deref(),
        Some("Bearer t")
    );

    // Live: no restart, the next request sees the new settings.
    env.proxy.ctx.set_stealth(StealthSettings {
        enabled: true,
        block_third_party_auth: true,
        hide_referer: false,
        send_dnt: false,
        ..Default::default()
    });
    env.origin.clear_requests();
    third_party(&env, "cdn.test", "/a.js", &extra).await;
    assert_eq!(header(&env, "/a.js", "authorization"), None);
    assert_eq!(header(&env, "/a.js", "dnt"), None);
    assert_eq!(header(&env, "/a.js", "referer").as_deref(), Some(PAGE));
    // Master switch off: nothing applies.
    env.proxy.ctx.set_stealth(StealthSettings::default());
    env.origin.clear_requests();
    third_party(&env, "cdn.test", "/a.js", &extra).await;
    assert_eq!(
        header(&env, "/a.js", "x-client-data").as_deref(),
        Some("abc")
    );
}

#[tokio::test]
async fn first_party_requests_keep_referer_authorization_and_validators() {
    let env = env_with(&[], |s| s.block_third_party_auth = true).await;
    env.client()
        .request(
            reqwest::Method::GET,
            &env.origin.https_url("page.test", "/a.js"),
        )
        .header("sec-fetch-dest", "script")
        .header("sec-fetch-site", "same-origin")
        .header("referer", PAGE)
        .header("authorization", "Bearer t")
        .header("if-none-match", "\"e\"")
        .send()
        .await
        .unwrap();
    assert_eq!(header(&env, "/a.js", "referer").as_deref(), Some(PAGE));
    assert_eq!(
        header(&env, "/a.js", "authorization").as_deref(),
        Some("Bearer t")
    );
    assert_eq!(
        header(&env, "/a.js", "if-none-match").as_deref(),
        Some("\"e\"")
    );
}

#[tokio::test]
async fn search_queries_are_hidden_from_the_result_site() {
    let env = env_with(&[], |s| s.hide_referer = false).await;
    env.origin.route(
        "/p",
        MockResponse::html("<html><head></head><body>x</body></html>"),
    );
    env.client()
        .request(
            reqwest::Method::GET,
            &env.origin.https_url("shop.test", "/p"),
        )
        .header("sec-fetch-dest", "document")
        .header("sec-fetch-site", "cross-site")
        .header("referer", "https://www.google.com/search?q=my+secret")
        .send()
        .await
        .unwrap();
    assert_eq!(
        header(&env, "/p", "referer").as_deref(),
        Some(env.origin.https_url("shop.test", "/").as_str())
    );
}

#[tokio::test]
async fn tracking_params_are_removed_and_documents_redirect() {
    let env = env_with(&[], |_| {}).await;
    env.origin.route("/p", MockResponse::ok("body"));
    third_party(&env, "cdn.test", "/p?a=1&utm_source=s&fbclid=9", &[]).await;
    assert_eq!(env.origin.requests_for("/p")[0].path_and_query, "/p?a=1");
    env.origin.clear_requests();
    let r = env
        .client()
        .request(
            reqwest::Method::GET,
            &env.origin.https_url("shop.test", "/p?gclid=1&k=v"),
        )
        .header("sec-fetch-dest", "document")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 307);
    assert!(r.headers()["location"]
        .to_str()
        .unwrap()
        .ends_with("/p?k=v"));
    assert!(env.origin.requests_for("/p").is_empty());
    let stub = logged_with(&env, "shop.test", "tracking parameters stripped");
    assert_eq!(stub.len(), 1, "{stub:?}");
    assert_eq!(stub[0].status, Some(307));
}

#[tokio::test]
async fn user_agent_is_reduced_or_replaced() {
    let ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.7339.12 Safari/537.36";
    let env = env_with(&[], |s| s.hide_user_agent = true).await;
    third_party(
        &env,
        "cdn.test",
        "/a.js",
        &[
            ("user-agent", ua),
            ("sec-ch-ua-platform-version", "\"6\""),
            ("accept-language", "de-DE,de;q=0.9,en;q=0.8"),
        ],
    )
    .await;
    let seen = header(&env, "/a.js", "user-agent").unwrap();
    assert!(
        seen.contains("X11; Linux x86_64") && seen.contains("Chrome/149.0.0.0"),
        "{seen}"
    );
    assert_eq!(header(&env, "/a.js", "sec-ch-ua-platform-version"), None);
    assert_eq!(
        header(&env, "/a.js", "accept-language").as_deref(),
        Some("de-DE")
    );

    let env = env_with(&[], |s| {
        s.hide_user_agent = true;
        s.user_agent_custom = "Custom/1.0".into();
    })
    .await;
    third_party(&env, "cdn.test", "/a.js", &[("user-agent", ua)]).await;
    assert_eq!(
        header(&env, "/a.js", "user-agent").as_deref(),
        Some("Custom/1.0")
    );
}

#[tokio::test]
async fn mask_ip_sends_x_forwarded_for() {
    let env = env_with(&[], |s| {
        s.mask_ip = true;
        s.mask_ip_address = "198.51.100.7".into();
    })
    .await;
    third_party(&env, "cdn.test", "/a.js", &[]).await;
    assert_eq!(
        header(&env, "/a.js", "x-forwarded-for").as_deref(),
        Some("198.51.100.7")
    );
}

#[tokio::test]
async fn third_party_cookies_expire_and_etags_go() {
    let env = env_with(&[], |_| {}).await;
    env.origin.route(
        "/c",
        MockResponse::ok("x")
            .header("set-cookie", "t=1; Path=/; Max-Age=999999")
            .header("set-cookie", "sess=1")
            .header("set-cookie", "gone=; Expires=Thu, 01-Jan-1970 00:00:00 GMT")
            .header("etag", "\"v1\""),
    );
    let r = third_party(&env, "cdn.test", "/c", &[]).await;
    let cookies: Vec<_> = r
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    assert_eq!(
        cookies,
        [
            "t=1; Path=/; Max-Age=172800",
            "sess=1",
            "gone=; Expires=Thu, 01-Jan-1970 00:00:00 GMT"
        ]
    );
    assert!(r.headers().get("etag").is_none());
    // First-party responses are untouched by default.
    let r = env
        .client()
        .request(
            reqwest::Method::GET,
            &env.origin.https_url("page.test", "/c"),
        )
        .header("sec-fetch-dest", "script")
        .header("sec-fetch-site", "same-origin")
        .header("referer", PAGE)
        .send()
        .await
        .unwrap();
    assert_eq!(r.headers()["set-cookie"], "t=1; Path=/; Max-Age=999999");
    assert!(r.headers().get("etag").is_some());
}

#[tokio::test]
async fn first_party_cookies_can_be_blocked_with_zero_minutes() {
    let env = env_with(&[], |s| {
        s.first_party_cookies = true;
        s.first_party_cookie_minutes = 0;
    })
    .await;
    env.origin
        .route("/c", MockResponse::ok("x").header("set-cookie", "t=1"));
    let r = env
        .client()
        .request(
            reqwest::Method::GET,
            &env.origin.https_url("page.test", "/c"),
        )
        .header("sec-fetch-dest", "script")
        .header("sec-fetch-site", "same-origin")
        .header("referer", PAGE)
        .send()
        .await
        .unwrap();
    assert!(r.headers().get("set-cookie").is_none());
}

async fn page_body(env: &TestEnv, host: &str) -> String {
    env.origin.route(
        "/doc",
        MockResponse::html("<html><head></head><body>hi</body></html>"),
    );
    let r = env
        .client()
        .request(reqwest::Method::GET, &env.origin.https_url(host, "/doc"))
        .header("sec-fetch-dest", "document")
        .send()
        .await
        .unwrap();
    r.text().await.unwrap()
}

/// The shim served for a document, if one was injected.
async fn shim_of(env: &TestEnv, body: &str) -> Option<String> {
    let i = body.find("/__adblock__/s/")?;
    let path: String = body[i..].chars().take_while(|c| *c != '"').collect();
    let r = env
        .client()
        .request(
            reqwest::Method::GET,
            &env.origin.https_url("page.test", &path),
        )
        .send()
        .await
        .unwrap();
    Some(r.text().await.unwrap())
}

#[tokio::test]
async fn pages_get_the_api_shim_even_with_ad_blocking_rules_absent() {
    let env = env_with(&[], |_| {}).await;
    let body = page_body(&env, "page.test").await;
    let js = shim_of(&env, &body).await.expect("shim injected");
    for k in [
        "RTCPeerConnection",
        "PushManager",
        "Geolocation",
        "globalPrivacyControl",
    ] {
        assert!(js.contains(k), "{k}");
    }
    // Each option off removes its part.
    let env = env_with(&[], |s| {
        s.block_webrtc = false;
        s.block_push = false;
        s.block_location = false;
        s.send_dnt = false;
        s.block_java = false;
        s.hide_referer = false;
        s.hide_search_queries = false;
    })
    .await;
    assert!(shim_of(&env, &page_body(&env, "page.test").await)
        .await
        .is_none());
}

#[tokio::test]
async fn stealth_exceptions_turn_listed_or_all_options_off() {
    // Listed options only.
    let env = env_with(&["@@||page.test^$stealth=webrtc|donottrack"], |_| {}).await;
    let body = page_body(&env, "page.test").await;
    let js = shim_of(&env, &body).await.unwrap();
    assert!(!js.contains("RTCPeerConnection") && !js.contains("globalPrivacyControl"));
    assert!(js.contains("Geolocation"));
    // Another site is unaffected.
    let js = shim_of(&env, &page_body(&env, "other.test").await)
        .await
        .unwrap();
    assert!(js.contains("RTCPeerConnection"));
    // Bare `$stealth`: everything off for the page.
    let env = env_with(&["@@||page.test^$stealth"], |_| {}).await;
    assert!(shim_of(&env, &page_body(&env, "page.test").await)
        .await
        .is_none());
}

#[tokio::test]
async fn full_bypass_and_blocking_off_sites_are_left_alone() {
    let env = env_with(&[], |_| {}).await;
    env.proxy
        .ctx
        .bypass()
        .update(|s| {
            s.entries.push(Entry {
                id: new_id(),
                pattern: "cdn.test".into(),
                mode: BypassMode::Full,
                source: "custom".into(),
                note: None,
                updated_at: 0,
            });
            Ok(())
        })
        .unwrap();
    // Full bypass is tunnelled, never decrypted: Stealth Mode cannot touch it.
    let direct = e2e::TestClient::trusting(
        &env.proxy,
        e2e::HttpVersion::Http1,
        &[env.origin.ca_pem().as_bytes()],
    );
    direct
        .request(
            reqwest::Method::GET,
            &env.origin.https_url("cdn.test", "/a.js"),
        )
        .header("x-client-data", "abc")
        .header("referer", PAGE)
        .send()
        .await
        .unwrap();
    assert_eq!(
        header(&env, "/a.js", "x-client-data").as_deref(),
        Some("abc")
    );
    assert_eq!(header(&env, "/a.js", "referer").as_deref(), Some(PAGE));
    assert_eq!(header(&env, "/a.js", "dnt"), None);

    // A site the user switched blocking off for.
    let env = env_with(&["||adblock.invalid^", "@@$domain=page.test"], |_| {}).await;
    assert!(shim_of(&env, &page_body(&env, "page.test").await)
        .await
        .is_none());
    third_party(&env, "cdn.test", "/a.js", &[]).await;
    assert_eq!(header(&env, "/a.js", "dnt"), None);
}

#[tokio::test]
async fn stealth_exceptions_match_requests_by_url_type_and_initiator() {
    // Requests to the excepted host, from any page.
    let env = env_with(
        &["@@||cdn.test^$stealth=donottrack|referrer|xclientdata"],
        |_| {},
    )
    .await;
    third_party(&env, "cdn.test", "/a.js", &[("x-client-data", "abc")]).await;
    assert_eq!(header(&env, "/a.js", "dnt"), None);
    assert_eq!(
        header(&env, "/a.js", "x-client-data").as_deref(),
        Some("abc")
    );
    assert_eq!(header(&env, "/a.js", "referer").as_deref(), Some(PAGE));
    // Other hosts stay covered.
    env.origin.route("/b.js", MockResponse::ok("x"));
    third_party(&env, "other.test", "/b.js", &[]).await;
    assert_eq!(header(&env, "/b.js", "dnt").as_deref(), Some("1"));

    // `$script,stealth,domain=`: the type and the initiating page both count.
    let env = env_with(&["@@||cdn.test^$script,stealth,domain=page.test"], |_| {}).await;
    third_party(&env, "cdn.test", "/a.js", &[]).await;
    assert_eq!(header(&env, "/a.js", "dnt"), None, "script from page.test");
    env.origin.clear_requests();
    third_party(
        &env,
        "cdn.test",
        "/a.js",
        &[("referer", "https://elsewhere.test/")],
    )
    .await;
    assert_eq!(
        header(&env, "/a.js", "dnt").as_deref(),
        Some("1"),
        "script from another page"
    );
    env.origin.clear_requests();
    env.client()
        .request(
            reqwest::Method::GET,
            &env.origin.https_url("cdn.test", "/a.js"),
        )
        .header("sec-fetch-dest", "image")
        .header("sec-fetch-site", "cross-site")
        .header("referer", PAGE)
        .send()
        .await
        .unwrap();
    assert_eq!(
        header(&env, "/a.js", "dnt").as_deref(),
        Some("1"),
        "an image is not a script"
    );
}

#[tokio::test]
async fn unsafe_methods_keep_their_referer() {
    let env = env_with(&[], |_| {}).await;
    env.origin.route("/post", MockResponse::ok("x"));
    env.client()
        .request(
            reqwest::Method::POST,
            &env.origin.https_url("cdn.test", "/post"),
        )
        .header("sec-fetch-dest", "empty")
        .header("sec-fetch-site", "cross-site")
        .header("referer", PAGE)
        .body("a=1")
        .send()
        .await
        .unwrap();
    assert_eq!(header(&env, "/post", "referer").as_deref(), Some(PAGE));
    assert_eq!(
        header(&env, "/post", "dnt").as_deref(),
        Some("1"),
        "other options still apply"
    );
}

#[tokio::test]
async fn the_shim_is_nonced_and_covers_frames_and_the_referrer() {
    let env = env_with(&[], |_| {}).await;
    env.origin.route(
        "/doc",
        MockResponse::html("<html><head></head><body>hi</body></html>")
            .header("content-security-policy", "script-src 'nonce-theirs'"),
    );
    let r = env
        .client()
        .request(
            reqwest::Method::GET,
            &env.origin.https_url("page.test", "/doc"),
        )
        .header("sec-fetch-dest", "document")
        .send()
        .await
        .unwrap();
    let csp = r.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .to_string();
    let body = r.text().await.unwrap();
    let tag = &body[body
        .find("<script src=\"/__adblock__/s/")
        .expect("shim tag")..];
    let n = tag.find("nonce=\"").unwrap() + 7;
    let nonce = &tag[n..n + tag[n..].find('"').unwrap()];
    assert!(
        !nonce.is_empty() && csp.contains(&format!("'nonce-{nonce}'")),
        "{csp} / {nonce}"
    );
    let js = shim_of(&env, &body).await.unwrap();
    assert!(js.contains("contentWindow") && js.contains("'referrer'"));
}

#[tokio::test]
async fn blocking_off_with_stealth_on_injects_only_the_shim() {
    let env = env_with(&["##.ad"], |_| {}).await;
    env.proxy.ctx.set_guard_service_workers(true);
    let on = page_body(&env, "page.test").await;
    assert!(on.contains("__ab_cfg"), "{on}");
    env.proxy.ctx.set_adblock_enabled(false);
    let body = page_body(&env, "page.test").await;
    assert!(shim_of(&env, &body).await.is_some(), "{body}");
    assert!(!body.contains("__ab_cfg") && !body.contains("sw:1") && !body.contains("\"sw\""));
    assert!(!body.contains("__adblock_cosmetic"), "{body}");
}

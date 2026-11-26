//! Script control through the real proxy: the generated policy header, network hints, HTML
//! actions, temporary grants, reports and the violation beacon.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use e2e::{e2e_test, MockResponse, TestClient, TestEnv};
use script_policy::{
    CapSet, Capability as C, Effect, GrantKind, Preset, Scope, Settings, DEFAULT_PROFILE as P,
};

const PAGE: &str = "<!doctype html><html><head><title>t</title></head><body>hi</body></html>";

fn enable(env: &TestEnv, tweak: impl FnOnce(&mut Settings)) {
    let (store, _) = env.proxy.script_control();
    let mut s = store.rules(P).unwrap().settings;
    s.enabled = true;
    tweak(&mut s);
    store.set_settings(P, s).unwrap();
}

async fn page(env: &TestEnv, c: &TestClient, host: &str, path: &str) -> reqwest::Response {
    c.request(reqwest::Method::GET, &env.origin.https_url(host, path))
        .header("sec-fetch-dest", "document")
        .header("sec-fetch-site", "none")
        .header("accept", "text/html")
        .send()
        .await
        .expect("page")
}

fn origin_str(env: &TestEnv, host: &str) -> String {
    env.origin.https_url(host, "/")
}

/// Events in the request log whose URL contains `needle` and whose rule is `rule`.
fn logged_with(env: &TestEnv, needle: &str, rule: &str) -> Vec<filter_engine::RequestEvent> {
    env.proxy
        .engine
        .recent_requests(1000)
        .into_iter()
        .filter(|e| e.url.contains(needle) && e.rule.as_deref().unwrap_or("") == rule)
        .collect()
}

/// A subresource request as a browser would send it from `page_host`.
async fn sub(
    env: &TestEnv,
    c: &TestClient,
    page_host: &str,
    host: &str,
    path: &str,
    dest: &str,
) -> reqwest::Response {
    c.request(reqwest::Method::GET, &env.origin.https_url(host, path))
        .header("referer", origin_str(env, page_host))
        .header("sec-fetch-dest", dest)
        .header(
            "sec-fetch-site",
            if host == page_host {
                "same-origin"
            } else {
                "cross-site"
            },
        )
        .send()
        .await
        .expect("sub")
}

fn csp_values(r: &reqwest::Response) -> Vec<String> {
    r.headers()
        .get_all("content-security-policy")
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect()
}

e2e_test!(disabled_policy_is_a_zero_cost_path, rules = [], |env| {
    let (_, control) = env.proxy.script_control();
    env.origin.route("/p", MockResponse::html(PAGE));
    env.origin.route("/a.js", MockResponse::ok("1"));
    let c = env.client();
    let r = page(&env, &c, "app.test", "/p").await;
    assert_eq!(r.status(), 200);
    assert!(csp_values(&r).is_empty());
    assert!(r.headers().get("permissions-policy").is_none());
    let r = sub(&env, &c, "app.test", "cdn.test", "/a.js", "script").await;
    assert!(r.headers().get("x-adblock").is_none());
    assert_eq!(
        control.decide_calls(),
        0,
        "decide must not run when disabled"
    );
    // Switching it on makes the same calls consult the policy.
    enable(&env, |_| {});
    let r = sub(&env, &c, "app.test", "cdn.test", "/a.js", "script").await;
    assert_eq!(r.headers()["x-adblock"], "policy");
    assert!(control.decide_calls() > 0);
});

e2e_test!(
    generated_csp_is_added_beside_the_sites_own,
    rules = [],
    |env| {
        let site = "default-src 'self'; img-src *";
        env.origin.route(
            "/p",
            MockResponse::html(PAGE).header("content-security-policy", site),
        );
        let (store, _) = env.proxy.script_control();
        store
            .create_site_rule(
                P,
                Scope::parse("app.test").unwrap(),
                Preset::Untrusted,
                None,
            )
            .unwrap();
        enable(&env, |_| {});
        let r = page(&env, &c_of(&env), "app.test", "/p").await;
        let v = csp_values(&r);
        assert_eq!(v.len(), 2, "{v:?}");
        assert_eq!(v[0], site, "the site's header is never edited");
        assert!(v[1].contains("script-src"), "{}", v[1]);
        assert!(v[1].contains("'nonce-"), "{}", v[1]);
        assert!(v[1].contains("report-uri /__adblock__/pv?d="), "{}", v[1]);
        assert!(
            !v[1].contains("ABPOLICY"),
            "markers must be replaced: {}",
            v[1]
        );
        // Trusted pages get no header at all.
        store
            .create_site_rule(P, Scope::parse("ok.test").unwrap(), Preset::Trusted, None)
            .unwrap();
        env.origin.route("/q", MockResponse::html(PAGE));
        let r = page(&env, &c_of(&env), "ok.test", "/q").await;
        assert!(csp_values(&r).is_empty());
    }
);

fn c_of(env: &TestEnv) -> TestClient {
    env.client()
}

e2e_test!(
    third_party_script_is_blocked_at_the_proxy_and_reported,
    rules = [],
    |env| {
        enable(&env, |_| {});
        let (store, _) = env.proxy.script_control();
        env.origin.route("/own.js", MockResponse::ok("1"));
        env.origin.route("/cdn.js", MockResponse::ok("2"));
        let c = env.client();
        let ok = sub(&env, &c, "app.test", "app.test", "/own.js", "script").await;
        assert_eq!(ok.status(), 200);
        assert!(ok.headers().get("x-adblock").is_none());
        let blocked = sub(&env, &c, "app.test", "cdn.test", "/cdn.js", "script").await;
        assert_eq!(blocked.headers()["x-adblock"], "policy");
        assert_eq!(
            env.origin.requests_for("/cdn.js").len(),
            0,
            "never reached the origin"
        );
        let ev = logged_with(&env, "/cdn.js", "script policy");
        assert_eq!(ev.len(), 1, "{ev:?}");
        assert_eq!(ev[0].action, filter_engine::EventAction::Blocked);
        let rep = store.report_for(P, "app.test").expect("report");
        let item = rep.items.iter().find(|i| i.cap == C::Script).expect("item");
        assert_eq!(item.source.as_deref(), Some("cdn.test"));
        assert!(item.via_network);
        // A different profile (none here) sees nothing.
        assert!(store.report_for("other", "app.test").is_none());
    }
);

e2e_test!(
    requests_of_unknown_context_are_not_blocked,
    rules = [],
    |env| {
        enable(&env, |_| {});
        env.origin.route("/cdn.js", MockResponse::ok("2"));
        let c = env.client();
        let u = env.origin.https_url("cdn.test", "/cdn.js");
        for hdrs in [
            vec![
                ("sec-fetch-dest", "script"),
                ("sec-fetch-site", "cross-site"),
            ],
            vec![
                ("sec-fetch-dest", "script"),
                ("origin", "null"),
                ("sec-fetch-site", "cross-site"),
            ],
            vec![("sec-fetch-dest", "script"), ("referer", "not a url")],
            // Not a subresource at all.
            vec![
                ("sec-fetch-dest", "document"),
                ("referer", "https://app.test/"),
            ],
        ] {
            let mut rb = c.request(reqwest::Method::GET, &u);
            for (k, v) in &hdrs {
                rb = rb.header(*k, *v);
            }
            let r = rb.send().await.unwrap();
            assert!(r.headers().get("x-adblock").is_none(), "{hdrs:?}");
            assert_eq!(r.status(), 200, "{hdrs:?}");
        }
    }
);

e2e_test!(
    noscript_is_unwrapped_when_scripts_are_blocked,
    rules = [],
    |env| {
        let (store, _) = env.proxy.script_control();
        store
            .create_site_rule(
                P,
                Scope::parse("app.test").unwrap(),
                Preset::Untrusted,
                None,
            )
            .unwrap();
        enable(&env, |_| {});
        env.origin.route(
        "/p",
        MockResponse::html(
            "<!doctype html><html><head><title>t</title></head><body><noscript><p id=ns>fallback</p></noscript><script>x()</script></body></html>",
        ),
    );
        let body = page(&env, &env.client(), "app.test", "/p")
            .await
            .text()
            .await
            .unwrap();
        assert!(!body.contains("<noscript"), "{body}");
        assert!(body.contains("<p id=ns>fallback</p>"), "{body}");
        // Default preset keeps first-party inline scripts, so <noscript> stays.
        env.origin.route(
            "/q",
            MockResponse::html("<html><head></head><body><noscript>n</noscript></body></html>"),
        );
        let body = page(&env, &env.client(), "other.test", "/q")
            .await
            .text()
            .await
            .unwrap();
        assert!(body.contains("<noscript>"), "{body}");
    }
);

e2e_test!(
    strip_mode_removes_blocked_scripts_and_preloads,
    rules = [],
    |env| {
        enable(&env, |s| s.strip_blocked_scripts = true);
        env.origin.route(
        "/p",
        MockResponse::html(
            "<!doctype html><html><head><link rel=\"preload\" as=\"script\" href=\"https://cdn.test/a.js\"><link rel=modulepreload href=\"/own.js\"><script src=\"https://cdn.test/a.js\"></script><script src=\"/own.js\"></script></head><body><a href=\"/x\" ping=\"https://cdn.test/ping\">l</a></body></html>",
        ),
    );
        let body = page(&env, &env.client(), "app.test", "/p")
            .await
            .text()
            .await
            .unwrap();
        assert!(
            !body.contains("cdn.test/a.js"),
            "blocked script and its preload are gone: {body}"
        );
        assert!(body.contains("<script src=\"/own.js\">"), "{body}");
        assert!(
            body.contains("modulepreload"),
            "first-party preload stays: {body}"
        );
        assert!(
            !body.contains("ping="),
            "denied ping attribute removed: {body}"
        );
    }
);

#[tokio::test]
async fn temporary_grant_expiry_flips_behaviour_without_restart() {
    let origin = e2e::TestOrigin::start().await;
    let proxy = e2e::TestProxy::start(e2e::EntryMode::Explicit, &origin, &[])
        .await
        .unwrap();
    let now = Arc::new(AtomicU64::new(1_000_000));
    let n2 = now.clone();
    let (store, control) =
        proxy.script_control_with(Some(Arc::new(move || n2.load(Ordering::SeqCst))));
    let env = TestEnv {
        origin,
        proxy,
        mode: e2e::EntryMode::Explicit,
    };
    enable(&env, |_| {});
    env.origin.route("/cdn.js", MockResponse::ok("2"));
    let c = env.client();
    let blocked =
        |r: &reqwest::Response| r.headers().get("x-adblock").is_some_and(|v| v == "policy");
    assert!(blocked(
        &sub(&env, &c, "app.test", "cdn.test", "/cdn.js", "script").await
    ));
    store
        .grant_temp(
            P,
            Scope::parse("app.test").unwrap(),
            GrantKind::Source {
                source: Scope::parse("cdn.test").unwrap(),
                caps: CapSet::of(&[C::Script]),
            },
            Some(60),
            false,
            false,
        )
        .unwrap();
    assert!(!blocked(
        &sub(&env, &c, "app.test", "cdn.test", "/cdn.js", "script").await
    ));
    now.store(1_000_061, Ordering::SeqCst);
    control.refresh();
    assert!(blocked(
        &sub(&env, &c, "app.test", "cdn.test", "/cdn.js", "script").await
    ));
    let _ = Effect::Allow;
}

/// The report-uri token and the full generated header of a document.
async fn doc_csp(env: &TestEnv, host: &str) -> (String, String) {
    env.origin.route("/d", MockResponse::html(PAGE));
    let r = page(env, &env.client(), host, "/d").await;
    let ours = csp_values(&r).pop().expect("our header");
    let i = ours.find("pv?d=").unwrap() + 5;
    (
        ours[i..].split([';', ' ']).next().unwrap().to_string(),
        ours,
    )
}

async fn pv(
    env: &TestEnv,
    host: &str,
    token: &str,
    ctype: &str,
    body: String,
    extra: &[(&str, &str)],
) -> u16 {
    let c = env.client();
    let mut rb = c
        .request(
            reqwest::Method::POST,
            &env.origin
                .https_url(host, &format!("/__adblock__/pv?d={token}")),
        )
        .header("content-type", ctype)
        .body(body);
    if !extra.iter().any(|(k, _)| *k == "sec-fetch-site") {
        rb = rb.header("sec-fetch-site", "same-origin");
    }
    for (k, v) in extra {
        rb = rb.header(*k, *v);
    }
    rb.send().await.unwrap().status().as_u16()
}

fn report(env: &TestEnv, host: &str, blocked: &str, policy: &str) -> String {
    serde_json::json!({"csp-report": {
        "document-uri": env.origin.https_url(host, "/d"),
        "blocked-uri": blocked,
        "effective-directive": "script-src-elem",
        "violated-directive": "script-src-elem",
        "original-policy": policy,
        "disposition": "enforce",
    }})
    .to_string()
}

e2e_test!(
    violation_beacon_accepts_only_our_policy_and_is_bounded,
    rules = [],
    |env| {
        let (store, _) = env.proxy.script_control();
        store
            .create_site_rule(
                P,
                Scope::parse("app.test").unwrap(),
                Preset::Untrusted,
                None,
            )
            .unwrap();
        enable(&env, |_| {});
        let (token, ours) = doc_csp(&env, "app.test").await;
        let ct = "application/csp-report";
        // Ours (even with another nonce): accepted and recorded.
        let other_nonce = {
            let i = ours.find("'nonce-").unwrap() + 7;
            let j = ours[i..].find('\'').unwrap() + i;
            format!("{}AAAAAAAAAAAAAAAAAAAAAA=={}", &ours[..i], &ours[j..])
        };
        let blocked = "https://cdn.test/x.js";
        assert_eq!(
            pv(
                &env,
                "app.test",
                &token,
                ct,
                report(&env, "app.test", blocked, &other_nonce),
                &[]
            )
            .await,
            204
        );
        let rep = store.report_for(P, "app.test").expect("recorded");
        let it = rep
            .items
            .iter()
            .find(|i| i.source.as_deref() == Some("cdn.test"))
            .expect("item");
        assert!(it.via_csp);
        let events = rep.events;
        // The site's own policy: acknowledged, never forwarded.
        assert_eq!(
            pv(
                &env,
                "app.test",
                &token,
                ct,
                report(
                    &env,
                    "app.test",
                    "https://evil.test/y.js",
                    "default-src 'self'"
                ),
                &[]
            )
            .await,
            204
        );
        assert_eq!(store.report_for(P, "app.test").unwrap().events, events);
        // Token-bound: wrong token, token of another host, missing.
        assert_eq!(
            pv(
                &env,
                "app.test",
                "1.2.3",
                ct,
                report(&env, "app.test", blocked, &ours),
                &[]
            )
            .await,
            403
        );
        assert_eq!(
            pv(
                &env,
                "app.test",
                "",
                ct,
                report(&env, "app.test", blocked, &ours),
                &[]
            )
            .await,
            403
        );
        let (other_token, _) = doc_csp(&env, "other.test").await;
        assert_eq!(
            pv(
                &env,
                "app.test",
                &other_token,
                ct,
                report(&env, "app.test", blocked, &ours),
                &[]
            )
            .await,
            403
        );
        // The report must name the token's host.
        assert_eq!(
            pv(
                &env,
                "app.test",
                &token,
                ct,
                report(&env, "other.test", blocked, &ours),
                &[]
            )
            .await,
            403
        );
        // Content type, origin, size.
        assert_eq!(
            pv(&env, "app.test", &token, "text/plain", "{}".into(), &[]).await,
            415
        );
        assert_eq!(
            pv(
                &env,
                "app.test",
                &token,
                ct,
                report(&env, "app.test", blocked, &ours),
                &[("sec-fetch-site", "cross-site")]
            )
            .await,
            403
        );
        assert_eq!(
            pv(&env, "app.test", &token, ct, "x".repeat(9 * 1024), &[]).await,
            413
        );
        assert_eq!(
            pv(&env, "app.test", &token, ct, "not json".into(), &[]).await,
            400
        );
        // Per-document rate limit.
        let mut last = 0;
        for _ in 0..80 {
            last = pv(
                &env,
                "app.test",
                &token,
                ct,
                report(&env, "app.test", blocked, &ours),
                &[],
            )
            .await;
        }
        assert_eq!(last, 429);
        // Another document is not affected.
        let (t2, o2) = doc_csp(&env, "app.test").await;
        assert_eq!(
            pv(
                &env,
                "app.test",
                &t2,
                ct,
                report(&env, "app.test", blocked, &o2),
                &[]
            )
            .await,
            204
        );
    }
);

e2e_test!(
    site_exception_line_switches_ad_blocking_off_for_that_site,
    rules = ["||ads.test^", "app.test##.ad"],
    |env| {
        env.origin.route("/x.js", MockResponse::ok("1"));
        env.origin.route(
            "/p",
            MockResponse::html(
                "<!doctype html><html><head></head><body><div class=ad>x</div></body></html>",
            ),
        );
        let c = env.client();
        let blocked =
            |r: &reqwest::Response| r.headers().get("x-adblock").is_some_and(|v| v == "blocked");
        assert!(blocked(
            &sub(&env, &c, "app.test", "ads.test", "/x.js", "script").await
        ));
        assert!(page(&env, &c, "app.test", "/p")
            .await
            .text()
            .await
            .unwrap()
            .contains("display:none"));
        // The very line the panel and the API write.
        let rules =
            list_service::site_exceptions::set("||ads.test^\napp.test##.ad\n", "app.test", true)
                .unwrap();
        assert!(rules.contains("@@$domain=app.test") && rules.contains("||adblock.invalid^"));
        let lines: Vec<&str> = rules.lines().collect();
        env.proxy.install_rules(&lines);
        assert!(
            !blocked(&sub(&env, &c, "app.test", "ads.test", "/x.js", "script").await),
            "requests from the site are not blocked"
        );
        assert!(
            !page(&env, &c, "app.test", "/p")
                .await
                .text()
                .await
                .unwrap()
                .contains("display:none"),
            "no cosmetic hiding either"
        );
        // Other sites are unaffected.
        assert!(blocked(
            &sub(&env, &c, "other.test", "ads.test", "/x.js", "script").await
        ));
    }
);

e2e_test!(
    meta_refresh_is_removed_only_when_opted_in_and_scripts_are_blocked,
    rules = [],
    |env| {
        let (store, _) = env.proxy.script_control();
        store
            .create_site_rule(
                P,
                Scope::parse("app.test").unwrap(),
                Preset::Untrusted,
                None,
            )
            .unwrap();
        env.origin.route(
        "/p",
        MockResponse::html("<!doctype html><html><head><meta http-equiv=\"Refresh\" content=\"5;url=/next\"><meta charset=utf-8></head><body>x</body></html>"),
    );
        enable(&env, |_| {});
        let body = page(&env, &env.client(), "app.test", "/p")
            .await
            .text()
            .await
            .unwrap();
        assert!(
            body.to_ascii_lowercase().contains("refresh"),
            "off by default: {body}"
        );
        enable(&env, |s| s.strip_meta_refresh = true);
        let body = page(&env, &env.client(), "app.test", "/p")
            .await
            .text()
            .await
            .unwrap();
        assert!(!body.to_ascii_lowercase().contains("refresh"), "{body}");
        assert!(body.contains("charset"), "other metas stay");
        // Scripts allowed on the page: the refresh stays.
        let body = page(&env, &env.client(), "free.test", "/p")
            .await
            .text()
            .await
            .unwrap();
        assert!(body.to_ascii_lowercase().contains("refresh"), "{body}");
    }
);

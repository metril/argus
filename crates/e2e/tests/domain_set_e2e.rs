//! Pure domain rules held in the domain set, through the real proxy: blocks, exceptions and the
//! recent-blocked feed behave as if every rule were in the engine.

use e2e::{e2e_test, MockResponse, TestEnv};
use filter_engine::{build_set, ListFormat, ListInput};

fn input(id: &str, content: &str, format: ListFormat) -> ListInput {
    ListInput {
        id: id.into(),
        content: content.into(),
        format,
        ..Default::default()
    }
}

async fn is_blocked(env: &TestEnv, host: &str, path: &str) -> bool {
    env.origin.route(path, MockResponse::ok("origin-body"));
    let resp = env.client().get(&env.origin.https_url(host, path)).await;
    resp.headers()
        .get("x-adblock")
        .is_some_and(|v| v == "blocked")
}

e2e_test!(
    domain_set_blocks_honours_exceptions_and_feeds_recent_blocked,
    rules = Vec::<&str>::new(),
    |env| {
        let built = build_set(&[
            input(
                "hosts",
                "0.0.0.0 set-ad.test set-ok.test\n0.0.0.0 imp.test\n",
                ListFormat::Hosts,
            ),
            input(
                "abp",
                "@@||set-ok.test^\n||imp.test^$important\n@@||imp.test^\n||engine-ad.test^\n",
                ListFormat::Abp,
            ),
        ]);
        assert_eq!(
            built.domains.len(),
            4,
            "every pure `||host^` rule, in either list"
        );
        built.install_into(&env.proxy.engine);

        assert!(is_blocked(&env, "set-ad.test", "/a.js").await);
        assert!(
            is_blocked(&env, "x.set-ad.test", "/a.js").await,
            "subdomain"
        );
        assert!(is_blocked(&env, "engine-ad.test", "/a.js").await);
        assert!(
            !is_blocked(&env, "set-ok.test", "/a.js").await,
            "@@ exception beats a domain-set block"
        );
        assert!(
            is_blocked(&env, "imp.test", "/a.js").await,
            "$important beats the exception"
        );
        assert!(!is_blocked(&env, "clean.test", "/a.js").await);

        let events = env.proxy.engine.recent_blocked(10);
        let rules: Vec<(&str, Option<&str>)> = events
            .iter()
            .map(|e| (e.rule.as_str(), e.list_id.as_deref()))
            .collect();
        // Newest first: imp.test (the engine's $important rule), engine-ad.test, subdomain, host.
        assert_eq!(events.len(), 4, "{rules:?}");
        assert_eq!(events[0].rule, "||imp.test^$important");
        assert_eq!(
            (events[1].rule.as_str(), events[1].list_id.as_deref()),
            ("||engine-ad.test^", Some("abp"))
        );
        assert_eq!(
            (events[2].rule.as_str(), events[2].list_id.as_deref()),
            ("||set-ad.test^", Some("hosts"))
        );
        assert!(events[3].url.contains("set-ad.test") && !events[3].request_type.is_empty());
        assert_eq!(env.proxy.engine.recent_blocked(2).len(), 2);
    }
);

//! Non-ABP list formats end to end: each format's entries block real requests through the proxy
//! (both entry modes), and allowlist / `rpz-passthru` entries unblock them.

use e2e::{e2e_test, MockResponse, TestEnv};
use filter_engine::{convert, ConvertOptions, ListFormat};

/// Convert each `(content, format, allowlist)` list and return its rule lines.
fn rules_for(lists: &[(&str, ListFormat, bool)]) -> Vec<&'static str> {
    let mut out = Vec::new();
    for (content, format, allowlist) in lists {
        let c = convert(
            content,
            &ConvertOptions {
                format: *format,
                allowlist: *allowlist,
                ..Default::default()
            },
        );
        assert_eq!(c.stats.error_count, 0, "{:?}", c.stats.errors);
        for line in c.rules.lines() {
            out.push(&*Box::leak(line.to_string().into_boxed_str()));
        }
    }
    out
}

/// Request `https://<host>/ad.js`; true if the proxy blocked it (and never contacted the origin).
async fn is_blocked(env: &TestEnv, host: &str) -> bool {
    env.origin.route("/ad.js", MockResponse::ok("origin-body"));
    let before = env.origin.requests_for("/ad.js").len();
    let sent = env
        .client()
        .try_get(&env.origin.https_url(host, "/ad.js"))
        .await;
    let blocked = e2e::was_blocked(&sent);
    let reached = env.origin.requests_for("/ad.js").len() - before;
    if blocked {
        assert_eq!(reached, 0, "{host}: blocked request reached the origin");
    } else {
        assert_eq!(reached, 1, "{host}: allowed request must reach the origin");
        assert_eq!(sent.unwrap().text().await.unwrap(), "origin-body");
    }
    blocked
}

e2e_test!(
    hosts_entry_blocks,
    rules = rules_for(&[(
        "# hosts\n127.0.0.1 localhost\n0.0.0.0 hosts-ad.test other-ad.test\n",
        ListFormat::Auto,
        false
    )]),
    |env| {
        assert!(is_blocked(&env, "hosts-ad.test").await);
        assert!(is_blocked(&env, "other-ad.test").await);
        assert!(
            is_blocked(&env, "sub.hosts-ad.test").await,
            "subdomains too"
        );
        assert!(!is_blocked(&env, "clean.test").await);
    }
);

e2e_test!(
    dnsmasq_entry_blocks,
    rules = rules_for(&[(
        "address=/dnsmasq-ad.test/0.0.0.0\nserver=/nx-ad.test/\naddress=/real.test/192.0.2.9\n",
        ListFormat::Auto,
        false
    )]),
    |env| {
        assert!(is_blocked(&env, "dnsmasq-ad.test").await);
        assert!(is_blocked(&env, "nx-ad.test").await);
        assert!(
            !is_blocked(&env, "real.test").await,
            "custom answer is not a block entry"
        );
    }
);

e2e_test!(
    rpz_entry_blocks_and_passthru_unblocks,
    rules = rules_for(&[(
        "$TTL 300\n@ IN SOA localhost. root.localhost. (1 3h 1h 1w 1h)\n  IN NS localhost.\n\
         rpz-ad.test CNAME .\n*.rpz-ad.test CNAME .\n\
         ok.rpz-ad.test CNAME rpz-passthru.\n",
        ListFormat::Auto,
        false
    )]),
    |env| {
        assert!(is_blocked(&env, "rpz-ad.test").await);
        assert!(is_blocked(&env, "x.rpz-ad.test").await);
        assert!(
            !is_blocked(&env, "ok.rpz-ad.test").await,
            "rpz-passthru is an exception"
        );
    }
);

e2e_test!(
    clash_entry_blocks,
    rules = rules_for(&[(
        "payload:\n  - '+.clash-ad.test'\n  - DOMAIN,exact-ad.test\n  - DOMAIN-KEYWORD,kwad\n",
        ListFormat::Auto,
        false
    )]),
    |env| {
        assert!(is_blocked(&env, "clash-ad.test").await);
        assert!(is_blocked(&env, "deep.clash-ad.test").await);
        assert!(is_blocked(&env, "exact-ad.test").await);
        assert!(
            !is_blocked(&env, "sub.exact-ad.test").await,
            "DOMAIN is exact"
        );
        assert!(is_blocked(&env, "my-kwad-host.test").await);
        assert!(!is_blocked(&env, "clean.test").await);
    }
);

e2e_test!(
    allowlist_list_unblocks_what_a_blocklist_blocks,
    rules = rules_for(&[
        (
            "0.0.0.0 shared-ad.test\n0.0.0.0 keep-ad.test\n",
            ListFormat::Hosts,
            false
        ),
        ("shared-ad.test\n", ListFormat::Domains, true),
    ]),
    |env| {
        assert!(is_blocked(&env, "keep-ad.test").await);
        assert!(!is_blocked(&env, "shared-ad.test").await);
    }
);

e2e_test!(
    pihole_regex_and_surge_and_snitch_block,
    rules = rules_for(&[
        ("^pihole-ad[0-9]+\\.test$\n", ListFormat::Pihole, false),
        (
            "DOMAIN-SUFFIX,surge-ad.test,REJECT\n",
            ListFormat::Surge,
            false
        ),
        (
            "{\"denied-remote-domains\": [\"snitch-ad.test\"]}",
            ListFormat::LittleSnitch,
            false
        ),
    ]),
    |env| {
        assert!(is_blocked(&env, "pihole-ad7.test").await);
        assert!(!is_blocked(&env, "xpihole-ad7.test").await);
        assert!(is_blocked(&env, "surge-ad.test").await);
        assert!(is_blocked(&env, "snitch-ad.test").await);
    }
);

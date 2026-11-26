mod common;
use common::*;
use script_policy::Capability as C;
use script_policy::*;

fn allows(c: &CompiledPolicy, page: (&str, &str), cap: C, src: &str) -> bool {
    c.decide(page.0, page.1, None).allows_host(cap, src)
}

#[test]
fn precedence_table() {
    const P: (&str, &str) = ("https", "www.example.com");
    // (name, rules to install, cap, source, expected)
    type Setup = fn(&mut RuleSet);
    let cases: Vec<(&str, Setup, C, &str, bool)> = vec![
        (
            "baseline default blocks third-party script",
            |_| {},
            C::Script,
            "cdn.net",
            false,
        ),
        (
            "baseline default allows first-party script",
            |_| {},
            C::Script,
            "static.example.com",
            true,
        ),
        (
            "page-specific deny beats global allow",
            |r| {
                src_rule(r, "a", "*", "host:cdn.net", &[C::Script], Effect::Allow);
                src_rule(
                    r,
                    "b",
                    "example.com",
                    "host:cdn.net",
                    &[C::Script],
                    Effect::Deny,
                );
            },
            C::Script,
            "cdn.net",
            false,
        ),
        (
            "page-specific allow beats global deny",
            |r| {
                src_rule(r, "a", "*", "host:cdn.net", &[C::Script], Effect::Deny);
                src_rule(
                    r,
                    "b",
                    "example.com",
                    "host:cdn.net",
                    &[C::Script],
                    Effect::Allow,
                );
            },
            C::Script,
            "cdn.net",
            true,
        ),
        (
            "host page scope beats site page scope",
            |r| {
                src_rule(
                    r,
                    "a",
                    "example.com",
                    "host:cdn.net",
                    &[C::Script],
                    Effect::Deny,
                );
                src_rule(
                    r,
                    "b",
                    "host:www.example.com",
                    "host:cdn.net",
                    &[C::Script],
                    Effect::Allow,
                );
            },
            C::Script,
            "cdn.net",
            true,
        ),
        (
            "host+scheme page scope beats host",
            |r| {
                src_rule(
                    r,
                    "a",
                    "host:www.example.com",
                    "host:cdn.net",
                    &[C::Script],
                    Effect::Allow,
                );
                src_rule(
                    r,
                    "b",
                    "https://www.example.com",
                    "host:cdn.net",
                    &[C::Script],
                    Effect::Deny,
                );
            },
            C::Script,
            "cdn.net",
            false,
        ),
        (
            "host+scheme for the other scheme does not apply",
            |r| {
                src_rule(
                    r,
                    "b",
                    "http://www.example.com",
                    "host:cdn.net",
                    &[C::Script],
                    Effect::Allow,
                )
            },
            C::Script,
            "cdn.net",
            false,
        ),
        (
            "source host beats source site at the same page scope",
            |r| {
                src_rule(
                    r,
                    "a",
                    "example.com",
                    "site:cdn.net",
                    &[C::Script],
                    Effect::Deny,
                );
                src_rule(
                    r,
                    "b",
                    "example.com",
                    "host:js.cdn.net",
                    &[C::Script],
                    Effect::Allow,
                );
            },
            C::Script,
            "js.cdn.net",
            true,
        ),
        (
            "deny wins ties",
            |r| {
                src_rule(
                    r,
                    "a",
                    "example.com",
                    "host:cdn.net",
                    &[C::Script],
                    Effect::Allow,
                );
                src_rule(
                    r,
                    "b",
                    "example.com",
                    "host:cdn.net",
                    &[C::Script],
                    Effect::Deny,
                );
            },
            C::Script,
            "cdn.net",
            false,
        ),
        (
            "page scope outranks source scope",
            |r| {
                src_rule(r, "a", "*", "host:cdn.net", &[C::Script], Effect::Allow);
                src_rule(r, "b", "example.com", "*", &[C::Script], Effect::Deny);
            },
            C::Script,
            "cdn.net",
            false,
        ),
        (
            "source rule can deny first party",
            |r| {
                src_rule(
                    r,
                    "a",
                    "example.com",
                    "site:example.com",
                    &[C::Script],
                    Effect::Deny,
                )
            },
            C::Script,
            "www.example.com",
            false,
        ),
        (
            "rule for another capability is ignored",
            |r| {
                src_rule(
                    r,
                    "a",
                    "example.com",
                    "host:cdn.net",
                    &[C::Font],
                    Effect::Deny,
                )
            },
            C::Script,
            "cdn.net",
            false,
        ),
        (
            "trusted site rule allows third-party script",
            |r| site_rule(r, "t", "example.com", Preset::Trusted),
            C::Script,
            "cdn.net",
            true,
        ),
        (
            "host site rule beats site site rule",
            |r| {
                site_rule(r, "t", "example.com", Preset::Trusted);
                site_rule(r, "u", "host:www.example.com", Preset::Untrusted);
            },
            C::Script,
            "www.example.com",
            false,
        ),
        (
            "source allow beats untrusted preset",
            |r| {
                site_rule(r, "u", "example.com", Preset::Untrusted);
                src_rule(
                    r,
                    "a",
                    "example.com",
                    "host:cdn.net",
                    &[C::Script],
                    Effect::Allow,
                );
            },
            C::Script,
            "cdn.net",
            true,
        ),
        (
            "global default untrusted blocks first-party script too",
            |r| r.settings.global = Preset::Untrusted,
            C::Script,
            "www.example.com",
            false,
        ),
    ];
    for (name, setup, cap, src, want) in cases {
        let mut r = rs();
        setup(&mut r);
        let c = compile(&r);
        assert_eq!(allows(&c, P, cap, src), want, "{name}");
    }
}

#[test]
fn page_scheme_and_unknown_scheme_sources() {
    let mut r = rs();
    src_rule(
        &mut r,
        "a",
        "example.com",
        "https://cdn.net",
        &[C::Script],
        Effect::Allow,
    );
    let c = compile(&r);
    let p = c.decide("https", "example.com", None);
    assert!(p.allows(
        C::Script,
        Source {
            scheme: Some(Scheme::Https),
            host: "cdn.net"
        }
    ));
    assert!(!p.allows(
        C::Script,
        Source {
            scheme: Some(Scheme::Http),
            host: "cdn.net"
        }
    ));
    assert!(!p.allows(
        C::Script,
        Source {
            scheme: None,
            host: "cdn.net"
        }
    ));
}

#[test]
fn site_scoping_uses_the_public_suffix_list() {
    let mut r = rs();
    site_rule(&mut r, "1", "example.co.uk", Preset::Trusted);
    site_rule(&mut r, "2", "xn--bcher-kva.de", Preset::Trusted);
    site_rule(&mut r, "3", "localhost", Preset::Trusted);
    site_rule(&mut r, "4", "192.168.1.10", Preset::Trusted);
    site_rule(&mut r, "5", "intranet", Preset::Trusted);
    site_rule(&mut r, "6", "alice.github.io", Preset::Trusted);
    let c = compile(&r);
    let trusted = |h: &str| c.decide("https", h, None).profile() == Profile::TRUSTED;
    assert!(trusted("example.co.uk"));
    assert!(trusted("a.b.example.co.uk"));
    assert!(
        !trusted("other.co.uk"),
        "co.uk is a public suffix, not a site"
    );
    assert!(trusted("shop.xn--bcher-kva.de"));
    assert!(trusted("localhost"));
    assert!(trusted("192.168.1.10"));
    assert!(!trusted("192.168.1.11"));
    assert!(!trusted("168.1.10"), "IPv4 must not be split into labels");
    assert!(trusted("intranet"));
    assert!(trusted("x.alice.github.io"));
    assert!(
        !trusted("bob.github.io"),
        "private suffixes separate tenants"
    );
    // Registrable domain, not the page host, decides first-party.
    let p = c.decide("https", "www.example.co.uk", None);
    assert!(p.is_first_party("img.example.co.uk"));
    assert!(!p.is_first_party("img.other.co.uk"));
    // IPv6 host literal.
    let mut r = rs();
    site_rule(&mut r, "1", "host:[::1]", Preset::Untrusted);
    let c = compile(&r);
    assert_eq!(
        c.decide("http", "[::1]", Some(8080)).profile(),
        Profile::UNTRUSTED
    );
}

#[test]
fn temp_grants_expire_by_injected_clock() {
    let mut r = rs();
    site_rule(&mut r, "u", "example.com", Preset::Untrusted);
    r.temps.insert(
        "t1".into(),
        TempGrant {
            id: "t1".into(),
            page: scope("example.com"),
            kind: GrantKind::Site {
                preset: Preset::Trusted,
            },
            expires_at: Some(2000),
            until_restart: false,
            persist: false,
            created_at: 1000,
        },
    );
    r.temps.insert(
        "t2".into(),
        TempGrant {
            id: "t2".into(),
            page: scope("example.com"),
            kind: GrantKind::Source {
                source: scope("host:cdn.net"),
                caps: CapSet::of(&[C::Script]),
            },
            expires_at: None,
            until_restart: true,
            persist: false,
            created_at: 1000,
        },
    );
    let at = |now| CompiledPolicy::compile(&r, 1, now);
    let before = at(1500);
    assert_eq!(before.valid_until(), Some(2000));
    assert_eq!(
        before.decide("https", "example.com", None).profile(),
        Profile::TRUSTED
    );
    let after = at(2000);
    assert_eq!(after.valid_until(), None);
    assert_eq!(
        after.decide("https", "example.com", None).profile(),
        Profile::UNTRUSTED
    );
    // The until-restart source grant outlives the timed one and beats the untrusted preset.
    assert!(after
        .decide("https", "example.com", None)
        .allows_host(C::Script, "cdn.net"));
    let mut pruned = r.clone();
    pruned.prune_temps(2000);
    assert!(pruned.temps.contains_key("t2") && !pruned.temps.contains_key("t1"));
}

#[test]
fn temp_beats_permanent_at_equal_specificity_but_not_more_specific() {
    let mut r = rs();
    src_rule(
        &mut r,
        "d",
        "example.com",
        "host:cdn.net",
        &[C::Script],
        Effect::Deny,
    );
    r.temps.insert(
        "t".into(),
        TempGrant {
            id: "t".into(),
            page: scope("example.com"),
            kind: GrantKind::Source {
                source: scope("host:cdn.net"),
                caps: CapSet::of(&[C::Script]),
            },
            expires_at: Some(10),
            until_restart: false,
            persist: false,
            created_at: 0,
        },
    );
    let c = CompiledPolicy::compile(&r, 1, 5);
    assert!(c
        .decide("https", "example.com", None)
        .allows_host(C::Script, "cdn.net"));
    // A permanent deny with a more specific page scope still wins.
    src_rule(
        &mut r,
        "d2",
        "host:example.com",
        "host:cdn.net",
        &[C::Script],
        Effect::Deny,
    );
    let c = CompiledPolicy::compile(&r, 1, 5);
    assert!(!c
        .decide("https", "example.com", None)
        .allows_host(C::Script, "cdn.net"));
}

#[test]
fn validation() {
    let mut r = rs();
    r.site_rules.insert(
        "x".into(),
        SiteRule {
            id: "x".into(),
            scope: Scope::Global,
            preset: Preset::Trusted,
            note: None,
            updated_at: 0,
        },
    );
    assert!(r.site_rules["x"].validate().is_err());
    let bad = SourceRule {
        id: "y".into(),
        page: Scope::Global,
        source: Scope::Global,
        caps: CapSet::of(&[C::Eval]),
        effect: Effect::Allow,
        note: None,
    };
    assert!(bad.validate().is_err());
    let g = TempGrant {
        id: "g".into(),
        page: Scope::Global,
        kind: GrantKind::Site {
            preset: Preset::Trusted,
        },
        expires_at: None,
        until_restart: false,
        persist: false,
        created_at: 0,
    };
    assert!(g.validate().is_err());
}

#[test]
fn export_import_round_trip() {
    let mut r = rs();
    r.settings.global = Preset::Untrusted;
    r.settings.strip_blocked_scripts = true;
    site_rule(&mut r, "1", "example.com", Preset::Trusted);
    site_rule(
        &mut r,
        "2",
        "host:www.b.org",
        custom(&[C::Eval], &[C::Script], &[C::Image]),
    );
    src_rule(
        &mut r,
        "3",
        "example.com",
        "host:cdn.net",
        &[C::Script, C::Font],
        Effect::Allow,
    );
    src_rule(
        &mut r,
        "4",
        "*",
        "site:ads.example",
        &[C::Ping],
        Effect::Deny,
    );
    let json = serde_json::to_string_pretty(&r.export()).unwrap();
    let back: PolicyExport = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r.export());
    let mut n = 0;
    let mut fresh = RuleSet::default();
    fresh
        .import(back.clone(), true, || {
            n += 1;
            format!("id{n}")
        })
        .unwrap();
    assert_eq!(fresh.export(), r.export());
    assert_eq!(fresh.settings, r.settings);
    // Merge keeps ids of existing keys and settings.
    let before: Vec<_> = fresh.site_rules.keys().cloned().collect();
    fresh.settings.enabled = false;
    fresh.import(back, false, || "never".into()).unwrap();
    assert_eq!(fresh.site_rules.keys().cloned().collect::<Vec<_>>(), before);
    assert!(!fresh.settings.enabled);
    // Bad documents are rejected without changes.
    let mut bad = r.export();
    bad.version = 99;
    assert!(fresh.import(bad, true, || "x".into()).is_err());
    let mut bad = r.export();
    bad.source_rules[0].caps = CapSet::of(&[C::Eval]);
    let snapshot = fresh.export();
    assert!(fresh.import(bad, true, || "x".into()).is_err());
    assert_eq!(fresh.export(), snapshot);
}

#[test]
fn explain_matching_lists_rules() {
    let mut r = rs();
    site_rule(&mut r, "1", "example.com", Preset::Trusted);
    site_rule(&mut r, "2", "other.com", Preset::Trusted);
    src_rule(
        &mut r,
        "3",
        "example.com",
        "host:cdn.net",
        &[C::Script],
        Effect::Allow,
    );
    let m = r.matching(Some(Scheme::Https), "www.example.com", 0);
    assert_eq!(
        (m.site_rules.len(), m.source_rules.len(), m.temps.len()),
        (1, 1, 0)
    );
}

// ---- HTML actions ----

#[test]
fn html_actions_unwrap_noscript_only_when_all_own_scripts_are_blocked() {
    let mut r = rs();
    site_rule(&mut r, "u", "untrusted.com", Preset::Untrusted);
    let c = compile(&r);
    let a = c.decide("https", "untrusted.com", None).html_actions();
    assert!(a.unwrap_noscript);
    assert!(a
        .rules
        .iter()
        .any(|x| x.selector == "noscript" && x.op == HtmlOp::UnwrapKeepContent));
    // Default (first-party scripts allowed): leave <noscript> alone.
    let a = c.decide("https", "other.org", None).html_actions();
    assert!(!a.unwrap_noscript);
    // Strip mode + meta refresh are opt-in.
    assert!(
        !c.decide("https", "untrusted.com", None)
            .html_actions()
            .strip_scripts
    );
    assert!(!a.rules.iter().any(|x| x.selector.starts_with("meta[")));
    r.settings.strip_blocked_scripts = true;
    r.settings.strip_meta_refresh = true;
    let c = compile(&r);
    let a = c.decide("https", "untrusted.com", None).html_actions();
    assert!(a.strip_scripts);
    assert!(a
        .rules
        .iter()
        .any(|x| x.selector.starts_with("meta[http-equiv")));
    assert!(a.rules.iter().any(|x| x.selector == "script[src]"));
    assert!(a
        .rules
        .iter()
        .any(|x| x.selector == html::INLINE_EXECUTABLE_SCRIPT));
    // Default preset strips only third-party external scripts (inline allowed).
    let a = c.decide("https", "other.org", None).html_actions();
    assert!(a.rules.iter().any(|x| x.selector == "script[src]"));
    assert!(!a
        .rules
        .iter()
        .any(|x| x.selector == html::INLINE_EXECUTABLE_SCRIPT));
    // No strip rule at all for a trusted site.
    site_rule(&mut r, "t", "trusted.com", Preset::Trusted);
    let c = compile(&r);
    assert!(c
        .decide("https", "trusted.com", None)
        .html_actions()
        .rules
        .is_empty());
}

#[test]
fn allows_url_judges_script_src_values() {
    let c = compile(&rs());
    let p = c.decide("https", "www.example.com", None);
    assert!(p.allows_url(C::Script, "/app.js"));
    assert!(p.allows_url(C::Script, "app.js?x=1"));
    assert!(p.allows_url(C::Script, "https://static.example.com/a.js"));
    assert!(p.allows_url(C::Script, "//EXAMPLE.com/a.js"));
    assert!(!p.allows_url(C::Script, "https://cdn.other.net/a.js"));
    assert!(!p.allows_url(C::Script, "//cdn.other.net:8443/a.js?q=1"));
    assert!(!p.allows_url(C::Script, "https://user:pw@cdn.other.net/a.js"));
    // Not judged here (CSP governs them).
    assert!(p.allows_url(C::Script, "data:text/javascript,1"));
    assert!(p.allows_url(C::Script, "blob:https://x/uuid"));
    // Pings: whitespace-separated lists are the caller's job; each URL is judged alone.
    assert!(!p.allows_url(C::Ping, "https://tracker.net/p"));
    assert!(p.allows_url(C::Ping, "/p"));
}

// ---- network hints ----

#[test]
fn page_context_from_headers() {
    let t = (Scheme::Https, "cdn.net", None);
    let k = |r, o, s| PageContext::from_headers(r, o, s, t);
    assert_eq!(
        k(
            Some("https://www.example.com/a/b?c"),
            None,
            Some("cross-site")
        ),
        PageContext::Known {
            scheme: Scheme::Https,
            host: "www.example.com",
            port: None
        }
    );
    assert_eq!(
        k(Some("http://localhost:3000/"), None, None),
        PageContext::Known {
            scheme: Scheme::Http,
            host: "localhost",
            port: Some(3000)
        }
    );
    assert_eq!(
        k(Some("https://example.com"), None, None),
        PageContext::Known {
            scheme: Scheme::Https,
            host: "example.com",
            port: None
        }
    );
    assert_eq!(
        k(None, Some("https://app.example.com"), None),
        PageContext::Known {
            scheme: Scheme::Https,
            host: "app.example.com",
            port: None
        }
    );
    assert_eq!(
        k(None, Some("null"), None),
        PageContext::Unknown(UnknownReason::OpaqueOrigin)
    );
    assert_eq!(
        k(None, None, Some("cross-site")),
        PageContext::Unknown(UnknownReason::NoInitiator)
    );
    assert_eq!(
        k(None, None, Some("none")),
        PageContext::Unknown(UnknownReason::UserNavigation)
    );
    assert_eq!(
        k(Some("about:blank"), None, None),
        PageContext::Unknown(UnknownReason::Unparsable)
    );
    // Same-origin without a referrer: the page is the target's own origin.
    assert_eq!(
        k(None, None, Some("same-origin")),
        PageContext::Known {
            scheme: Scheme::Https,
            host: "cdn.net",
            port: None
        }
    );
    assert_eq!(
        k(Some("https://[::1]:8443/x"), None, None),
        PageContext::Known {
            scheme: Scheme::Https,
            host: "[::1]",
            port: Some(8443)
        }
    );
}

#[test]
fn enabled_default_policy_keeps_the_iubenda_badge_script_from_loading() {
    // canyoublockit.com's footer loads cdn.iubenda.com/iubenda.js, which turns the privacy-policy
    // link into a 115x22 `iubenda-ibadge` iframe. With the script policy on (shipped default:
    // third-party scripts denied) that request is refused, so the link stays a plain anchor and
    // no badge renders. This is a script-policy effect, not a cosmetic or list rule.
    let c = compile(&rs());
    let p = c.decide("https", "canyoublockit.com", None);
    let hints = p.network_hints();
    let req = |dest: &str, host: &'static str| SubRequest {
        dest: FetchDest::from_header(dest),
        ping: false,
        target: Source {
            scheme: Some(Scheme::Https),
            host,
        },
    };
    assert_eq!(
        p.check_request(&hints, &req("script", "cdn.iubenda.com")),
        HintVerdict::Block { cap: C::Script }
    );
    assert_eq!(
        p.check_request(&hints, &req("script", "canyoublockit.com")),
        HintVerdict::Allow
    );
    // With the policy off (the default) nothing is judged and the badge renders.
    let mut off = rs();
    off.settings.enabled = false;
    let c = compile(&off);
    let p = c.decide("https", "canyoublockit.com", None);
    assert!(p.network_hints().is_empty());
}

#[test]
fn network_hints_block_denied_third_party_subresources() {
    let c = compile(&rs());
    let p = c.decide("https", "www.example.com", None);
    let hints = p.network_hints();
    assert!(hints.enforce.contains(C::Script) && hints.enforce.contains(C::Ping));
    assert!(!hints.enforce.contains(C::Image));
    let req = |dest: &str, host: &'static str, ping| SubRequest {
        dest: FetchDest::from_header(dest),
        ping,
        target: Source {
            scheme: Some(Scheme::Https),
            host,
        },
    };
    use HintVerdict::*;
    assert_eq!(
        p.check_request(&hints, &req("script", "cdn.net", false)),
        Block { cap: C::Script }
    );
    assert_eq!(
        p.check_request(&hints, &req("script", "static.example.com", false)),
        Allow
    );
    assert_eq!(
        p.check_request(&hints, &req("image", "cdn.net", false)),
        Allow
    );
    assert_eq!(
        p.check_request(&hints, &req("empty", "t.net", true)),
        Block { cap: C::Ping }
    );
    assert_eq!(
        p.check_request(&hints, &req("empty", "api.net", false)),
        Allow
    );
    assert_eq!(
        p.check_request(&hints, &req("document", "cdn.net", false)),
        Allow
    );
    assert_eq!(
        p.check_request(&hints, &req("object", "cdn.net", false)),
        Block { cap: C::Object }
    );
    assert_eq!(
        p.check_request(&hints, &req("sharedworker", "cdn.net", false)),
        Block { cap: C::Worker }
    );
    // Trusted pages need no checks at all.
    let mut r = rs();
    site_rule(&mut r, "t", "example.com", Preset::Trusted);
    assert!(compile(&r)
        .decide("https", "example.com", None)
        .network_hints()
        .is_empty());
    // Opt-in connect enforcement.
    let mut r = rs();
    site_rule(&mut r, "u", "example.com", Preset::Untrusted);
    let c = compile(&r);
    let p = c.decide("https", "example.com", None);
    assert!(!p.network_hints().enforce.contains(C::Connect));
    let h = p.network_hints_with(DEFAULT_ENFORCEABLE.with(C::Connect));
    assert_eq!(
        p.check_request(&h, &req("empty", "api.net", false)),
        Block { cap: C::Connect }
    );
    // Setting off.
    let mut r = rs();
    r.settings.network_hints = false;
    assert!(compile(&r)
        .decide("https", "x.com", None)
        .network_hints()
        .is_empty());
}

// ---- reports ----

#[test]
fn report_aggregation_is_bounded_and_classifies_violations() {
    let mut agg = ReportAggregator::new(ReportLimits {
        max_pages: 2,
        max_items_per_page: 2,
        max_sample_len: 20,
    });
    let ev = |cap, src: &str| BlockEvent {
        cap,
        source: Some(src.into()),
        sample: Some(format!("https://{src}/some/very/long/path/x.js?token=1")),
        via: Via::Network,
    };
    for _ in 0..3 {
        agg.record("a.com", ev(C::Script, "cdn.net"), 10);
    }
    agg.record("a.com", ev(C::Font, "f.net"), 11);
    agg.record("a.com", ev(C::Image, "i.net"), 12); // evicts the least hit item (font)
    let p = agg.page("a.com").unwrap();
    assert_eq!(p.items.len(), 2);
    assert_eq!(p.dropped, 1);
    assert_eq!(p.events, 5);
    assert_eq!((p.items[0].cap, p.items[0].count), (C::Script, 3));
    assert_eq!(p.items[0].sample.as_deref(), Some("https://cdn.net/some"));
    assert!(!p.items[0].sample.as_ref().unwrap().contains('?'));
    // Page bound: oldest page is evicted.
    agg.record("b.com", ev(C::Script, "x.net"), 20);
    agg.record("c.com", ev(C::Script, "x.net"), 30);
    assert!(agg.page("a.com").is_none());
    assert_eq!(
        agg.pages()
            .iter()
            .map(|p| p.page.as_str())
            .collect::<Vec<_>>(),
        ["c.com", "b.com"]
    );

    let mut agg = ReportAggregator::default();
    let v = |d: &str, b: &str| CspViolation {
        document_uri: "https://www.a.com/p".into(),
        effective_directive: d.into(),
        blocked_uri: b.into(),
        disposition: "enforce".into(),
    };
    assert!(agg.record_violation(&v("script-src-elem", "https://cdn.net/x.js"), 1));
    assert!(agg.record_violation(&v("script-src-elem", "inline"), 1));
    assert!(agg.record_violation(&v("script-src", "eval"), 1));
    assert!(agg.record_violation(&v("img-src", "data"), 1));
    assert!(!agg.record_violation(&v("base-uri", "https://x"), 1));
    assert!(!agg.record_violation(
        &CspViolation {
            disposition: "report".into(),
            ..v("script-src", "inline")
        },
        1
    ));
    let p = agg.page("www.a.com").unwrap();
    let caps: Vec<_> = p.items.iter().map(|i| i.cap).collect();
    for want in [C::Script, C::InlineScript, C::Eval, C::Image] {
        assert!(caps.contains(&want), "{want:?}");
    }
    let script = p.items.iter().find(|i| i.cap == C::Script).unwrap();
    assert!(script.via_csp && !script.via_network);
    let (src, caps) = script.suggested_allow().unwrap();
    assert_eq!(src, Scope::Host("cdn.net".into()));
    assert_eq!(caps, CapSet::of(&[C::Script]));
    assert!(p
        .items
        .iter()
        .find(|i| i.cap == C::Eval)
        .unwrap()
        .suggested_allow()
        .is_none());
}

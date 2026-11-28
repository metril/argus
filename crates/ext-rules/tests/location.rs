//! AdGuard page-location cosmetics (`[$path=…]`, `[$domain=…]`, regex hostnames), exceptions,
//! state truthfulness, and the new request-side matchers. Rules are the real production ones.

use std::net::IpAddr;

use ext_rules::*;
use filter_engine::formats::classify_rejected;

fn rule(raw: &str, trusted: bool) -> ExtRule {
    // Classify like the pipeline does for rejected rules, fall back to `other`.
    let mut r = classify_rejected(raw).unwrap_or_else(|| ExtRule::new(ExtKind::Other, raw));
    r.trusted = trusted;
    r.list = "L".into();
    r
}

fn build(raws: &[&str]) -> ExtIndex {
    ExtIndex::build(&raws.iter().map(|r| rule(r, true)).collect::<Vec<_>>())
}

/// Rules injected / removed for the HTML document at `url`.
fn on(i: &ExtIndex, url: &str) -> (usize, usize) {
    let req = RequestInfo::new(url, "GET", ResourceType::Document);
    let h = [("Content-Type", "text/html")];
    let p = i.response_plan(
        &req,
        &ResponseInfo {
            status: 200,
            headers: &h,
        },
    );
    (p.injections.len(), p.html_removals.len())
}

fn hits(i: &ExtIndex, url: &str) -> usize {
    let (a, b) = on(i, url);
    a + b
}

const PATH_FORM: &str =
    "[$path=/rinku/land/]#$#form[id][method=\"post\"] { display: block !important; }";
const DOM_PATH: &str =
    "[$domain=facebook.com,path=/adsmanager]#$#body { display: block !important; }";
const RE_DOM_SCRIPTLET: &str =
    r"[$domain=/7tv\d+\.com$/]#%#//scriptlet('trusted-click-element', '.x')";
const BARE_PATH: &str = "[$path]f95zone.to##.node:not(.node--forum):has(a[data-xf-init])";
const ROOT_RE: &str = r"[$path=/^\/$/]cinejosh.com##.container-fluid + br + .container-fluid";
const RE_DOM_HIDE: &str = r"[$domain=/7tv\d+\.com$/]##.a-d-block";
const RE_HOST1: &str = r"/yavasgir\d+\.(com|live)/##.telegram-follow-button";
const RE_HOST2: &str = r"/^www\.selcuksportshd[a-z0-9-]+\.xyz$/##.banner";
const RE_HOST3: &str = r"/apl.*\.me/##[onclick=&quot;adr();&quot;]:upward(3)";
const RE_HOST_HTML: &str =
    r"/(\d{0,1})?tamilprint(\d{1,2})?\.[a-z]{3,7}/##^script:has-text('{delete window[')";
const NEG_RE: &str = r"b.com,~/^m\.b\.com$/##x";

#[test]
fn path_prefix_only_on_matching_path() {
    let i = build(&[PATH_FORM]);
    assert_eq!(hits(&i, "https://any.example/rinku/land/page"), 1);
    assert_eq!(
        hits(&i, "https://other.example/x?a=/rinku/land/"),
        1,
        "query counts"
    );
    assert_eq!(hits(&i, "https://any.example/"), 0);
    assert_eq!(hits(&i, "https://any.example/rinku/"), 0);
}

#[test]
fn domain_and_path_prefix() {
    let i = build(&[DOM_PATH]);
    assert_eq!(hits(&i, "https://facebook.com/adsmanager/x"), 1);
    assert_eq!(hits(&i, "https://www.facebook.com/adsmanager"), 1);
    assert_eq!(hits(&i, "https://facebook.com/other"), 0);
    assert_eq!(hits(&i, "https://example.com/adsmanager"), 0);
}

#[test]
fn regex_domain_prefix_scriptlet_and_hide() {
    let i = build(&[RE_DOM_SCRIPTLET, RE_DOM_HIDE]);
    assert_eq!(hits(&i, "https://7tv123.com/a"), 2);
    assert_eq!(hits(&i, "https://www.7tv9.com/"), 2);
    assert_eq!(hits(&i, "https://7tv.com/a"), 0);
    assert_eq!(hits(&i, "https://7tv123.com.evil.example/"), 0);
    assert_eq!(hits(&i, "https://example.com/"), 0);
}

#[test]
fn bare_path_means_main_page_of_host() {
    let i = build(&[BARE_PATH]);
    assert_eq!(hits(&i, "https://f95zone.to/"), 1);
    assert_eq!(hits(&i, "https://f95zone.to/?x=1"), 1);
    assert_eq!(hits(&i, "https://f95zone.to/threads/1"), 0);
    assert_eq!(hits(&i, "https://other.example/"), 0);
}

#[test]
fn regex_path_with_host_list() {
    let i = build(&[ROOT_RE]);
    assert_eq!(hits(&i, "https://cinejosh.com/"), 1);
    assert_eq!(hits(&i, "https://cinejosh.com/news"), 0);
    assert_eq!(hits(&i, "https://other.example/"), 0);
}

#[test]
fn regex_hostnames_in_the_domain_list() {
    let i = build(&[RE_HOST1, RE_HOST2, RE_HOST_HTML]);
    assert_eq!(
        hits(&i, "https://yavasgir12.live/x"),
        1,
        "only the telegram rule"
    );
    assert_eq!(hits(&i, "https://www.selcuksportshd1a.xyz/"), 1);
    assert_eq!(
        hits(&i, "https://selcuksportshd1a.xyz/"),
        0,
        "anchored: no www"
    );
    assert_eq!(hits(&i, "https://tamilprint12.com/"), 1);
    assert_eq!(hits(&i, "https://x.tamilprint.net/"), 1);
    assert_eq!(hits(&i, "https://example.com/"), 0);
    // The has-text rule is an HTML filter, the others injections.
    assert_eq!(on(&i, "https://tamilprint12.com/"), (0, 1));
}

#[test]
fn negated_regex_host() {
    let i = build(&[NEG_RE]);
    assert_eq!(hits(&i, "https://b.com/"), 1);
    assert_eq!(hits(&i, "https://www.b.com/"), 1);
    assert_eq!(hits(&i, "https://m.b.com/"), 0);
    assert_eq!(hits(&i, "https://c.com/"), 0);
}

#[test]
fn exceptions_are_scoped_like_their_rules() {
    // A global rule, a path-scoped exception, a regex-host exception.
    let i = build(&[
        "##.ad",
        r"[$path=/keep/]#@#.ad",
        r"/^safe\d+\.example$/#@#.ad",
        r"[$domain=/^q\d\.example$/,path=/z]#@#.ad",
    ]);
    // `##.ad` is an ordinary cosmetic for the engine; here it is a procedural-css injection.
    let n = |u: &str| hits(&i, u);
    assert_eq!(n("https://a.example/page"), 1);
    assert_eq!(n("https://a.example/keep/x"), 0, "exception on that path");
    assert_eq!(
        n("https://safe7.example/page"),
        0,
        "exception on the regex host"
    );
    assert_eq!(n("https://safe.example/page"), 1);
    assert_eq!(n("https://q1.example/z"), 0);
    assert_eq!(
        n("https://q1.example/other"),
        1,
        "exception does not leak off its path"
    );
    assert_eq!(n("https://q99.example/z"), 1);
}

#[test]
fn exception_with_prefix_is_never_global() {
    let i = build(&["x.com##.ad", r"[$path=/only/]#@#.ad"]);
    assert_eq!(hits(&i, "https://x.com/"), 1);
    assert_eq!(hits(&i, "https://x.com/only/a"), 0);
}

#[test]
fn other_modifiers_are_unsupported_never_ignored() {
    for raw in [
        "[$app=firefox.exe]##.ad",
        "[$url=/x/]example.com##.ad",
        "[$path=/x,app=a]##.ad",
        "[$weird=1]##.ad",
    ] {
        let i = build(&[raw]);
        assert!(
            matches!(i.state_of(0), Some(RuleState::Unsupported(r)) if r.contains("modifier")),
            "{raw}: {:?}",
            i.state_of(0)
        );
        assert!(i.is_empty(), "{raw}");
    }
}

#[test]
fn bad_regexes_are_unsupported_with_a_reason() {
    for raw in [
        r"[$domain=/(?=x)/]##.ad",
        r"/^(a)\1$/##.ad",
        r"[$path=/(?!x)/]a.com##.ad",
        r"/(/##.ad",
        r"[$domain=/a{1000}{1000}{1000}/]##.ad",
    ] {
        let i = build(&[raw]);
        let st = i.state_of(0).unwrap();
        assert!(
            matches!(st, RuleState::Unsupported(r) if r.contains("regex") || r.contains("path pattern")),
            "{raw}: {st:?}"
        );
        assert!(i.is_empty(), "{raw}");
    }
}

#[test]
fn no_production_location_rule_is_global() {
    let raws = [
        PATH_FORM,
        DOM_PATH,
        RE_DOM_SCRIPTLET,
        BARE_PATH,
        ROOT_RE,
        RE_DOM_HIDE,
        RE_HOST1,
        RE_HOST2,
        RE_HOST3,
        RE_HOST_HTML,
        NEG_RE,
    ];
    let probes = [
        "https://zzz-unrelated.example/",
        "https://zzz-unrelated.example/some/path?q=1",
        "https://a.test/",
    ];
    for raw in raws {
        let i = build(&[raw]);
        for u in probes {
            assert_eq!(hits(&i, u), 0, "{raw} fired on {u}");
        }
    }
    // And together, on the same probes.
    let i = build(&raws);
    for u in probes {
        assert_eq!(hits(&i, u), 0, "{u}");
    }
}

#[test]
fn indexed_matches_linear_scan() {
    let i = build(&[
        PATH_FORM,
        DOM_PATH,
        RE_DOM_HIDE,
        BARE_PATH,
        NEG_RE,
        "a.com##.x",
    ]);
    for (h, p) in [
        ("facebook.com", "/adsmanager"),
        ("f95zone.to", "/"),
        ("7tv1.com", "/q"),
        ("m.b.com", "/"),
        ("b.com", "/rinku/land/"),
        ("a.com", "/"),
    ] {
        assert_eq!(
            i.debug_dom_matches_at(h, p, true),
            i.debug_dom_matches_at(h, p, false),
            "{h}{p}"
        );
    }
}

// ---- cheap wins ----------------------------------------------------------------------------------

fn state(raw: &str) -> RuleState {
    let i = build(&[raw]);
    i.state_of(0).unwrap().clone()
}

fn req_with<'a>(url: &'a str, ty: ResourceType, src: Option<&'a str>) -> RequestInfo<'a> {
    RequestInfo {
        source_url: src,
        ..RequestInfo::new(url, "GET", ty)
    }
}

#[test]
fn strict_party_uses_exact_hostnames() {
    let i = build(&["/ads/*$script,strict3p", "/trk/*$script,1p,strict1p"]);
    let blocked = |u, src| {
        i.request_decision(&req_with(u, ResourceType::Script, Some(src)))
            .block
            .is_some()
    };
    // Same registrable domain, different hostname: 1st-party but strict-3rd-party.
    assert!(blocked(
        "https://cdn.site.example/ads/a.js",
        "https://www.site.example/"
    ));
    assert!(!blocked(
        "https://www.site.example/ads/a.js",
        "https://www.site.example/"
    ));
    assert!(blocked(
        "https://www.site.example/trk/a.js",
        "https://www.site.example/"
    ));
    assert!(!blocked(
        "https://cdn.site.example/trk/a.js",
        "https://www.site.example/"
    ));
    assert_eq!(state("/ads/*$script,strict3p"), RuleState::Active);
}

#[test]
fn redirect_with_denyallow_to_method() {
    let i = build(&[
        "*$script,third-party,redirect=noopjs,denyallow=google.com,domain=tvtropes.org",
        "*$script,redirect-rule=noopjs:5,from=dutchycorp.*,to=~sentry-cdn.com",
        "||p.example^$3p,xhr,method=head,redirect-rule=noop.js,domain=photopea.com",
    ]);
    let d = i.request_decision(&req_with(
        "https://ads.example/a.js",
        ResourceType::Script,
        Some("https://tvtropes.org/"),
    ));
    assert_eq!(d.redirect.as_ref().map(|r| r.0.as_str()), Some("noopjs"));
    assert!(d.redirect_rule.is_none() && d.block.is_none());
    let d = i.request_decision(&req_with(
        "https://google.com/a.js",
        ResourceType::Script,
        Some("https://tvtropes.org/"),
    ));
    assert!(d.redirect.is_none(), "denyallow");
    let d = i.request_decision(&req_with(
        "https://ads.example/a.js",
        ResourceType::Script,
        Some("https://dutchycorp.com/"),
    ));
    assert_eq!(d.redirect_rule.map(|r| r.0), Some("noopjs".into()));
    let mut r = RequestInfo::new("https://p.example/x", "HEAD", ResourceType::Xhr);
    r.source_url = Some("https://photopea.com/");
    assert!(i.request_decision(&r).redirect_rule.is_some());
    r.method = "GET";
    assert!(i.request_decision(&r).redirect_rule.is_none(), "method");
    // Exception by resource name.
    let i = build(&[
        "||a.example^$redirect=noopjs",
        "@@||a.example^$redirect=noopjs",
    ]);
    let d = i.request_decision(&req_with(
        "https://a.example/x.js",
        ResourceType::Script,
        None,
    ));
    assert!(d.redirect.is_none());
    for r in [
        "*$script,redirect=noopjs,to=a.com",
        "||x^$redirect-rule=noopjs,method=get",
    ] {
        assert!(matches!(state(r), RuleState::NotEnforced(_)), "{r}");
    }
}

#[test]
fn generichide_exception_disables_generic_ext_cosmetics_only() {
    let i = build(&[
        "##.generic",
        "site.example##.specific",
        "@@||site.example^$generichide,genericblock",
    ]);
    assert_eq!(hits(&i, "https://other.example/"), 1);
    assert_eq!(
        hits(&i, "https://site.example/"),
        1,
        "specific rule survives"
    );
    assert!(matches!(i.state_of(2), Some(RuleState::NotEnforced(_))));
    let req = RequestInfo::new("https://site.example/", "GET", ResourceType::Document);
    let h = [("Content-Type", "text/html")];
    let p = i.response_plan(
        &req,
        &ResponseInfo {
            status: 200,
            headers: &h,
        },
    );
    assert!(p.disabled & target::GENERICHIDE != 0 && p.disabled & target::GENERICBLOCK != 0);
}

#[test]
fn popunder_is_not_applicable_and_reason_is_ignored() {
    assert!(
        matches!(state("||a.example^$popunder"), RuleState::NotApplicable(r) if r.contains("proxy"))
    );
    let i = build(&["||a.example^$popunder"]);
    assert_eq!(i.stats().per_kind["unsupported-option"].not_applicable, 1);
    assert_eq!(i.stats().issues.len(), 0, "not an issue");
    let i = build(&["||a.example/x.js$script,reason=ad network"]);
    assert_eq!(i.state_of(0), Some(&RuleState::Active));
    assert!(i
        .request_decision(&req_with(
            "https://a.example/x.js",
            ResourceType::Script,
            None
        ))
        .block
        .is_some());
}

// ---- features --------------------------------------------------------------------------------------

#[test]
fn urlskip_target() {
    let i = build(&[
        "||shortnest.com/st?$doc,urlskip=?url",
        "||anylinks.in/full*^url=aHR0c$doc,urlskip=?url -base64",
        "@@||anylinks.in^$urlskip",
    ]);
    let doc = |u| req_with(u, ResourceType::Document, None);
    let r = doc("https://shortnest.com/st?url=https%3A%2F%2Fdest.example%2F");
    let t = i.urlskip_target(&r, false).unwrap();
    assert_eq!(t.0, "https://dest.example/");
    assert!(i
        .urlskip_target(&doc("https://shortnest.com/st?x=1"), false)
        .is_none());
    assert!(
        i.urlskip_target(
            &doc("https://anylinks.in/full?x&url=aHR0cHM6Ly9kLmV4YW1wbGUv"),
            false
        )
        .is_none(),
        "exception"
    );
    assert!(
        i.urlskip_target(&r, true).is_none(),
        "blocked requests need -blocked"
    );
    assert!(matches!(i.state_of(0), Some(RuleState::NotEnforced(_))));
}

#[test]
fn ipaddress_matching() {
    let i = build(&[
        "||top^$doc,ipaddress=13.143.164.28",
        "||com/go/$doc,to=com,ipaddress=2406:da18:3af:9302:6ead:4c78:949:685a",
        "*$doc,ipaddress=/^206\\.119\\./,to=top",
        "||lan.example^$doc,ipaddress=lan",
        "||lo.example^$doc,ipaddress=loopback",
        "||pre.example^$doc,ipaddress=10.1.*",
        "@@||ok.top^$doc,ipaddress=13.143.164.28",
    ]);
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    let doc = |u| req_with(u, ResourceType::Document, None);
    assert!(i
        .ip_decision(&doc("https://x.top/"), ip("13.143.164.28"))
        .is_some());
    assert!(i
        .ip_decision(&doc("https://x.top/"), ip("13.143.164.29"))
        .is_none());
    assert!(
        i.ip_decision(&doc("https://ok.top/"), ip("13.143.164.28"))
            .is_none(),
        "exception"
    );
    assert!(i
        .ip_decision(
            &doc("https://a.com/go/x"),
            ip("2406:da18:3af:9302:6ead:4c78:949:685a")
        )
        .is_some());
    assert!(i
        .ip_decision(&doc("https://y.top/"), ip("206.119.1.1"))
        .is_some());
    assert!(i
        .ip_decision(&doc("https://lan.example/"), ip("192.168.1.9"))
        .is_some());
    assert!(i
        .ip_decision(&doc("https://lan.example/"), ip("8.8.8.8"))
        .is_none());
    assert!(i
        .ip_decision(&doc("https://lo.example/"), ip("127.0.0.1"))
        .is_some());
    assert!(i
        .ip_decision(&doc("https://pre.example/"), ip("10.1.2.3"))
        .is_some());
    assert!(i
        .ip_decision(&doc("https://pre.example/"), ip("10.2.2.3"))
        .is_none());
    // Without an address the pre-request path never fires them.
    assert!(i.request_decision(&doc("https://x.top/")).block.is_none());
    assert!(matches!(i.state_of(0), Some(RuleState::NotEnforced(_))));
}

#[test]
fn cname_exceptions() {
    let i = build(&[
        "@@||crackle.com^$cname",
        "||tracker.example^$cname",
        "@@||google.*^$cname",
    ]);
    let r = req_with(
        "https://metrics.site.example/p.js",
        ResourceType::Script,
        Some("https://site.example/"),
    );
    let d = i.cname_decision(&r, "tracker.example");
    assert!(d.block.is_some() && d.exempt.is_none());
    let d = i.cname_decision(&r, "crackle.com");
    assert!(d.block.is_none() && d.exempt.is_some());
    assert!(i.cname_decision(&r, "x.google.com").exempt.is_some());
    assert!(i.cname_decision(&r, "other.example").exempt.is_none());
    // $cname rules never match the request's own host.
    assert!(i
        .request_decision(&req_with(
            "https://tracker.example/p.js",
            ResourceType::Script,
            None
        ))
        .block
        .is_none());
    assert!(matches!(i.state_of(0), Some(RuleState::NotEnforced(_))));
}

#[test]
fn network_regex_domain_option() {
    let i = build(&[r"||a.example^$script,domain=/^m\d\.site\.example$/"]);
    assert!(i
        .request_decision(&req_with(
            "https://a.example/x.js",
            ResourceType::Script,
            Some("https://m1.site.example/")
        ))
        .block
        .is_some());
    assert!(i
        .request_decision(&req_with(
            "https://a.example/x.js",
            ResourceType::Script,
            Some("https://x.site.example/")
        ))
        .block
        .is_none());
}

// ---- review follow-ups ---------------------------------------------------------------------------

fn frame_hits(i: &ExtIndex, url: &str, parent: &str) -> usize {
    let req = RequestInfo {
        source_url: Some(parent),
        ..RequestInfo::new(url, "GET", ResourceType::Subdocument)
    };
    let h = [("Content-Type", "text/html")];
    let p = i.response_plan(
        &req,
        &ResponseInfo {
            status: 200,
            headers: &h,
        },
    );
    p.injections.len() + p.html_removals.len()
}

#[test]
fn location_rules_use_the_frames_own_url() {
    let i = build(&[PATH_FORM, r"/^ads\d\.example$/##.f"]);
    assert_eq!(
        frame_hits(&i, "https://x.example/rinku/land/a", "https://top.example/"),
        1
    );
    assert_eq!(
        frame_hits(
            &i,
            "https://x.example/other",
            "https://top.example/rinku/land/"
        ),
        0
    );
    assert_eq!(
        frame_hits(&i, "https://ads1.example/f", "https://top.example/"),
        1
    );
    assert_eq!(
        frame_hits(&i, "https://top.example/f", "https://ads1.example/"),
        0
    );
}

#[test]
fn fragment_and_encoding_at_the_index_level() {
    let i = build(&[PATH_FORM, "[$path=/a%20b]##.e", "[$path]f95zone.to##.m"]);
    // The fragment is not part of the path the browser requests.
    assert_eq!(hits(&i, "https://x.example/p#/rinku/land/"), 0);
    assert_eq!(hits(&i, "https://x.example/rinku/land/#frag"), 1);
    // The raw (undecoded) path is matched.
    assert_eq!(hits(&i, "https://x.example/a%20b"), 1);
    assert_eq!(hits(&i, "https://x.example/a b"), 0);
    assert_eq!(hits(&i, "https://x.example/a%2520b"), 0);
    // Main page: fragment and query do not make it another page.
    assert_eq!(hits(&i, "https://f95zone.to/#top"), 1);
    assert_eq!(hits(&i, "https://f95zone.to/?page=2"), 1);
    assert_eq!(hits(&i, "https://f95zone.to"), 1);
}

#[test]
fn mixed_plain_and_regex_domain_list_stays_scoped() {
    let i = build(&[r"a.com,/^re\d\.example$/,~x.a.com##.m", "##.generic"]);
    let n = |u: &str| hits(&i, u);
    assert_eq!(n("https://a.com/"), 2);
    assert_eq!(n("https://www.a.com/"), 2);
    assert_eq!(
        n("https://x.a.com/"),
        1,
        "exclusion applies to the plain part"
    );
    assert_eq!(n("https://re1.example/"), 2);
    assert_eq!(n("https://re.example/"), 1);
    assert_eq!(n("https://b.com/"), 1);
    for (h, p) in [
        ("a.com", "/"),
        ("re1.example", "/"),
        ("x.a.com", "/"),
        ("b.com", "/"),
    ] {
        assert_eq!(
            i.debug_dom_matches_at(h, p, true),
            i.debug_dom_matches_at(h, p, false)
        );
    }
    // Exclusion of a regex entry applies to the plain part too.
    let i = build(&[r"a.com,~/^m\.a\.com$/##.m"]);
    assert_eq!(hits(&i, "https://a.com/"), 1);
    assert_eq!(hits(&i, "https://m.a.com/"), 0);
}

#[test]
fn domain_prefix_with_a_domain_list_is_invalid() {
    for raw in [
        "[$domain=a.com]b.com##.x",
        "[$domain=a.com,path=/p]b.com##.x",
        "[$domain=a.com]~b.com#@#.x",
    ] {
        let i = build(&[raw]);
        assert!(
            matches!(i.state_of(0), Some(RuleState::Invalid(r)) if r.contains("cannot be combined with a domain list")),
            "{raw}: {:?}",
            i.state_of(0)
        );
        assert!(i.is_empty());
    }
    // path + a domain list is fine.
    assert_eq!(
        build(&["[$path=/p]b.com##.x"]).state_of(0),
        Some(&RuleState::Active)
    );
}

#[test]
fn generichide_with_location_scoped_generic_rules() {
    let i = build(&[
        "[$path=/p]##.g",
        "[$path=/p]site.example##.s",
        "@@||site.example^$generichide",
    ]);
    // On the excepted site the path-scoped generic rule is switched off, the host-scoped one stays.
    assert_eq!(hits(&i, "https://site.example/p"), 1);
    assert_eq!(hits(&i, "https://other.example/p"), 1);
    assert_eq!(hits(&i, "https://other.example/q"), 0);
    match i.state_of(2) {
        Some(RuleState::NotEnforced(r)) => assert!(
            r.contains("only extended generic cosmetics are suppressed")
                && r.contains("main engine's generic hiding is not affected yet"),
            "{r}"
        ),
        s => panic!("{s:?}"),
    }
    let g = build(&["@@||site.example^$genericblock"]);
    assert!(matches!(g.state_of(0), Some(RuleState::NotEnforced(r)) if r.contains("genericblock")));
}

#[test]
fn ipv4_mapped_addresses_match_ipv4_conditions() {
    let i = build(&[
        "||lan.example^$doc,ipaddress=lan",
        "||lo.example^$doc,ipaddress=loopback",
        "||p.example^$doc,ipaddress=10.1.*",
        "||e.example^$doc,ipaddress=192.168.1.1",
        "||m.example^$doc,ipaddress=::ffff:10.9.9.9",
        r"||r.example^$doc,ipaddress=/^10\.2\./",
    ]);
    for (h, ip) in [
        ("lan.example", "::ffff:192.168.1.1"),
        ("lo.example", "::ffff:127.0.0.1"),
        ("p.example", "::ffff:10.1.2.3"),
        ("e.example", "::ffff:192.168.1.1"),
        ("m.example", "10.9.9.9"),
        ("m.example", "::ffff:10.9.9.9"),
        ("r.example", "::ffff:10.2.0.1"),
    ] {
        let u = format!("https://{h}/");
        assert!(
            i.ip_decision(
                &req_with(&u, ResourceType::Document, None),
                ip.parse().unwrap()
            )
            .is_some(),
            "{h} {ip}"
        );
    }
    assert!(i
        .ip_decision(
            &req_with("https://lan.example/", ResourceType::Document, None),
            "::ffff:8.8.8.8".parse().unwrap()
        )
        .is_none());
}

#[test]
fn quoted_replace_and_urlskip_regex_with_steps_parse() {
    let q = ExtRule {
        trusted: true,
        ..rule(
            r"$frame,3p,domain=a.example,replace='/^/<script>(()=>{window.open=new Proxy(window.open,{apply:(e,t,r)=>{}});})()<\/script>/'",
            true,
        )
    };
    let i = ExtIndex::build(&[q]);
    assert_eq!(
        i.state_of(0),
        Some(&RuleState::Active),
        "{:?}",
        i.state_of(0)
    );
    let i = build(&[
        r"||pstmrk.it/*/$doc,to=click.pstmrk.it|track.pstmrk.it,urlskip=/\.pstmrk\.it\/[23][mst]{0,2}\/([^\/?#]+)/ -uricomponent +https",
    ]);
    assert!(
        matches!(i.state_of(0), Some(RuleState::NotEnforced(_))),
        "{:?}",
        i.state_of(0)
    );
    let r = req_with(
        "https://click.pstmrk.it/2s/dest.example%2Fx/abc",
        ResourceType::Document,
        None,
    );
    assert_eq!(
        i.urlskip_target(&r, false).map(|t| t.0),
        Some("https://dest.example/x".into())
    );
}

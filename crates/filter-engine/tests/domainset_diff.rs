//! Differential test: decisions with pure domain rules routed into the `DomainSet` (the
//! `build_set` path) must equal the decisions of an engine compiled with every rule in
//! adblock-rust. Deterministic seed, thousands of generated (rules, URL) cases.

use std::collections::HashSet;

use filter_engine::{
    build_set, compile_lists, convert, ConvertOptions, ListFormat, ListInput, MatchResult,
    SharedEngine,
};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn pick<'a, T>(&mut self, v: &'a [T]) -> &'a T {
        &v[self.below(v.len())]
    }
    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }
}

const LABELS: &[&str] = &[
    "ads", "cdn", "track", "x", "www", "a1", "b2", "api", "static", "img", "px", "t-1", "u_2",
];
const TLDS: &[&str] = &["com", "net", "org", "co.uk", "io", "test"];

fn host(r: &mut Rng) -> String {
    let n = 1 + r.below(3);
    let mut parts: Vec<&str> = (0..n).map(|_| *r.pick(LABELS)).collect();
    parts.push(*r.pick(TLDS));
    parts.join(".")
}

struct Corpus {
    lists: Vec<String>,
    /// Every host that appears in some pure `||h^` rule.
    members: Vec<String>,
    all_rules: HashSet<String>,
}

fn corpus(r: &mut Rng, with_engine: bool) -> Corpus {
    let members: Vec<String> = (0..180).map(|_| host(r)).collect();
    let (mut l0, mut l1, mut l2) = (String::new(), String::new(), String::new());
    let mut all = HashSet::new();
    let mut add = |list: &mut String, rule: String| {
        list.push_str(&rule);
        list.push('\n');
        all.insert(rule);
    };
    for (i, h) in members.iter().enumerate() {
        // Pure domain rules, with duplicates across lists.
        match i % 3 {
            0 => add(&mut l0, format!("||{h}^")),
            1 => add(&mut l1, format!("||{h}^")),
            _ => {
                add(&mut l0, format!("||{h}^"));
                add(&mut l1, format!("||{h}^"));
            }
        }
        // Exact-host rules.
        if r.chance(15) {
            for s in ["http", "https", "ws", "wss"] {
                if r.chance(60) {
                    add(&mut l1, format!("|{s}://{h}^"));
                }
            }
        }
        // Engine-side interactions with a domain rule.
        let sub = format!("{}.{h}", r.pick(LABELS));
        match if with_engine { r.below(20) } else { 99 } {
            0 => add(&mut l2, format!("@@||{h}^")),
            1 => add(&mut l2, format!("@@||{sub}^")),
            2 => add(&mut l2, format!("||{h}^$important")),
            3 => add(&mut l2, format!("||{h}^$badfilter")),
            4 => add(&mut l2, format!("@@||{h}/ok^")),
            5 => add(&mut l2, format!("@@||{h}^$domain=site.test")),
            6 => add(&mut l2, format!("||{h}/p.gif$redirect=1x1.gif")),
            7 => add(&mut l2, format!("||{h}^$script,third-party")),
            8 => add(&mut l2, format!("||{h}/ads/*")),
            9 => add(&mut l2, format!("@@||{h}^$image")),
            10 => add(&mut l2, format!("||{h}^$important,domain=site.test")),
            11 => add(&mut l2, format!("|https://{h}^$badfilter")),
            12 => add(&mut l2, format!("@@||{sub}^$document")),
            13 => add(&mut l2, format!("||{h}^$redirect-rule=noop.js")),
            _ => {}
        }
    }
    // Rules that must stay in the engine.
    for h in ["Upper.example.com", "1.2.3.4", "single"] {
        if with_engine {
            add(&mut l2, format!("||{h}^"));
        }
    }
    Corpus {
        lists: vec![l0, l1, l2],
        members,
        all_rules: all,
    }
}

fn urls(r: &mut Rng, c: &Corpus, n: usize) -> Vec<(String, String, &'static str)> {
    const TYPES: &[&str] = &[
        "script",
        "image",
        "stylesheet",
        "document",
        "subdocument",
        "xhr",
        "websocket",
        "other",
        "font",
        "media",
        "ping",
        "main_frame",
        "weird",
    ];
    const SCHEMES: &[&str] = &["http", "https", "https", "ws", "wss", "ftp"];
    let sources = [
        "https://site.test/",
        "https://other.test/p",
        "",
        "http://a.b.c/",
    ];
    let mut out = Vec::new();
    for _ in 0..n {
        let base = match r.below(10) {
            0..=3 => c.members[r.below(c.members.len())].clone(),
            4 | 5 => format!("{}.{}", r.pick(LABELS), r.pick(&c.members)),
            6 => host(r),
            7 => format!("{}.evil.net", r.pick(&c.members)),
            8 => format!("x{}", r.pick(&c.members)),
            _ => r.pick(&c.members).to_uppercase(),
        };
        let authority = match r.below(14) {
            0 => format!("{base}:8443"),
            1 => format!("user:pw@{base}"),
            2 => format!("{base}:80"),
            3 => "1.2.3.4".to_string(),
            4 => format!("[::1]:{}", 80 + r.below(9)),
            _ => base.clone(),
        };
        let path = match r.below(8) {
            0 => "".to_string(),
            1 => "/".to_string(),
            2 => "/ok".to_string(),
            3 => "/ads/banner.js".to_string(),
            4 => "/p.gif".to_string(),
            5 => format!("/path/{}", r.pick(&c.members)),
            6 => format!("?u={}", r.pick(&c.members)),
            _ => "/a/b.js?x=1#frag".to_string(),
        };
        let scheme = r.pick(SCHEMES);
        out.push((
            format!("{scheme}://{authority}{path}"),
            r.pick(&sources).to_string(),
            *r.pick(TYPES),
        ));
    }
    out
}

fn is_pure_rule(rule: &str) -> bool {
    let body = rule
        .strip_prefix("||")
        .or_else(|| rule.split_once("://").map(|x| x.1))
        .and_then(|b| b.strip_suffix('^'));
    body.is_some_and(|b| !b.contains(['$', '/', '@']))
}

#[test]
fn domain_set_path_equals_full_engine() {
    let mut r = Rng(0x5eed_1234_abcd_ef01);
    let mut stats = [0usize; 6]; // blocked, allowed, exception, important, redirect, via-set
    let mut cases = 0;
    let rounds: usize = std::env::var("DIFF_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(6);
    for round in 0..rounds {
        // Every third round has no engine rules at all (the hosts-only fast path).
        let c = corpus(&mut r, round % 3 != 2);
        let cases_here = urls(&mut r, &c, 1200);

        // Reference: every converted rule in the engine, no domain set.
        let converted: Vec<String> = c
            .lists
            .iter()
            .map(|l| {
                convert(
                    l,
                    &ConvertOptions {
                        format: ListFormat::Abp,
                        ..Default::default()
                    },
                )
                .rules
            })
            .collect();
        let refs: Vec<&str> = converted.iter().map(String::as_str).collect();
        let reference = SharedEngine::new();
        reference.install(compile_lists(&refs).blob);
        assert!(reference.domains().is_empty());

        // Subject: the build pipeline with domain routing.
        let inputs: Vec<ListInput> = c
            .lists
            .iter()
            .enumerate()
            .map(|(i, l)| ListInput {
                id: format!("list{i}"),
                content: l.clone(),
                format: ListFormat::Abp,
                ..Default::default()
            })
            .collect();
        let subject = SharedEngine::new();
        let built = build_set(&inputs);
        assert!(built.domains.len() > 100, "domain rules were routed");
        built.install_into(&subject);

        for (url, source, ty) in &cases_here {
            let want: MatchResult = reference.check(url, source, ty);
            let got: MatchResult = subject.check(url, source, ty);
            let ctx = format!(
                "round {round}: {url} src={source:?} type={ty}\nwant {want:?}\ngot  {got:?}"
            );
            assert_eq!(want.blocked, got.blocked, "blocked: {ctx}");
            assert_eq!(want.important, got.important, "important: {ctx}");
            assert_eq!(want.exception_rule, got.exception_rule, "exception: {ctx}");
            assert_eq!(want.redirect, got.redirect, "redirect: {ctx}");
            if got.blocked {
                let rule = got.matched_rule.as_deref().expect("rule named");
                assert!(c.all_rules.contains(rule), "unknown rule {rule}: {ctx}");
                if got.important {
                    assert_eq!(want.matched_rule, got.matched_rule, "important rule: {ctx}");
                }
                if got.list_id.is_some() {
                    assert!(is_pure_rule(rule), "list id only on set rules: {ctx}");
                    stats[5] += 1;
                }
            }
            stats[if want.blocked { 0 } else { 1 }] += 1;
            stats[2] += want.exception_rule.is_some() as usize;
            stats[3] += want.important as usize;
            stats[4] += want.redirect.is_some() as usize;
            cases += 1;
        }
    }
    eprintln!(
        "cases={cases} blocked={} allowed={} exception={} important={} redirect={} via_set={}",
        stats[0], stats[1], stats[2], stats[3], stats[4], stats[5]
    );
    assert!(cases >= 1200 * rounds);
    // The corpus must actually exercise every decision kind.
    assert!(stats[0] > 800 && stats[1] > 800, "{stats:?}");
    assert!(
        stats[2] > 50 && stats[3] > 20 && stats[4] > 10 && stats[5] > 300,
        "{stats:?}"
    );
}

#[test]
fn trailing_dot_hosts_follow_dns_semantics() {
    // adblock-rust matches `||host^` against `sub.host.` only for some labels; the set treats a
    // fully-qualified trailing dot as the same host, consistently.
    let e = SharedEngine::new();
    build_set(&[ListInput {
        id: "l".into(),
        content: "0.0.0.0 ads.example.com\n".into(),
        ..Default::default()
    }])
    .install_into(&e);
    for u in ["https://ads.example.com./x", "https://x1.ads.example.com./"] {
        assert!(e.check(u, "https://p.test/", "script").blocked, "{u}");
    }
    // ...and, like the engine, never matches a mixed-case host.
    assert!(
        !e.check("https://ADS.example.com/", "https://p.test/", "script")
            .blocked
    );
}

#[test]
fn matched_rule_and_list_for_set_hits() {
    let inputs = vec![
        ListInput {
            id: "hosts-a".into(),
            content: "0.0.0.0 ads.example.com\n".into(),
            ..Default::default()
        },
        ListInput {
            id: "surge-b".into(),
            content: "DOMAIN,exact.example.net\n".into(),
            format: ListFormat::Surge,
            ..Default::default()
        },
    ];
    let e = SharedEngine::new();
    build_set(&inputs).install_into(&e);
    let r = e.check(
        "https://x.ads.example.com/t.js",
        "https://p.test/",
        "script",
    );
    assert!(r.blocked);
    assert_eq!(r.matched_rule.as_deref(), Some("||ads.example.com^"));
    assert_eq!(r.list_id.as_deref(), Some("hosts-a"));
    let r = e.check("https://exact.example.net/", "https://p.test/", "script");
    assert_eq!(
        r.matched_rule.as_deref(),
        Some("|https://exact.example.net^")
    );
    assert_eq!(r.list_id.as_deref(), Some("surge-b"));
    assert!(
        !e.check(
            "https://sub.exact.example.net/",
            "https://p.test/",
            "script"
        )
        .blocked
    );
}

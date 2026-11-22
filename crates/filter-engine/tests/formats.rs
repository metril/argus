//! Per-format fixture table: exact converted output and stats, detection, and robustness.
//!
//! Expected output lives in `tests/fixtures/expected/<fixture>.{rules,stats}`; regenerate with
//! `UPDATE_EXPECTED=1 cargo test -p filter-engine --test formats` and review the diff.

use std::collections::HashMap;
use std::path::PathBuf;

use filter_engine::formats::{preprocess_and_meta, scriptlet_alias_table};
use filter_engine::{
    compile_lists, convert, detect, ConvertOptions, Converted, ExtKind, ListFormat, SharedEngine,
};

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn fixture(name: &str) -> String {
    let bytes = std::fs::read(dir().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
    String::from_utf8(bytes).unwrap()
}

fn includes() -> HashMap<String, String> {
    HashMap::from([("extra.txt".to_string(), fixture("extra.txt"))])
}

fn stats_text(c: &Converted) -> String {
    let s = &c.stats;
    let mut t = format!(
        "format={}\ntotal_lines={}\nconverted={}\nskipped={}\nerror_count={}\ntranslated={}\next={}\nip_block={}\nip_allow={}\next_counts={:?}\nskipped_reasons={:?}\nmeta={:?}\n",
        c.format,
        s.total_lines,
        s.converted,
        s.skipped,
        s.error_count,
        s.translated,
        c.ext.len(),
        c.ip_block.len(),
        c.ip_allow.len(),
        s.ext_counts,
        s.skipped_reasons,
        c.meta,
    );
    for (n, e) in &s.errors {
        t.push_str(&format!("error line {n}: {e}\n"));
    }
    for e in &c.ext {
        t.push_str(&format!("ext {:?} {} {:?}\n", e.kind, e.raw, e.domains));
    }
    for r in c.ip_block.iter().chain(&c.ip_allow) {
        t.push_str(&format!("ip {}-{}\n", r.start, r.end));
    }
    t
}

fn check_expected(name: &str, c: &Converted) {
    let exp = dir().join("expected");
    let (rules_p, stats_p) = (
        exp.join(format!("{name}.rules")),
        exp.join(format!("{name}.stats")),
    );
    let (rules, stats) = (c.rules.clone(), stats_text(c));
    if std::env::var_os("UPDATE_EXPECTED").is_some() {
        std::fs::create_dir_all(&exp).unwrap();
        std::fs::write(&rules_p, &rules).unwrap();
        std::fs::write(&stats_p, &stats).unwrap();
        return;
    }
    let want_rules =
        std::fs::read_to_string(&rules_p).unwrap_or_else(|_| panic!("missing {rules_p:?}"));
    let want_stats =
        std::fs::read_to_string(&stats_p).unwrap_or_else(|_| panic!("missing {stats_p:?}"));
    assert_eq!(rules, want_rules, "rules for {name}");
    assert_eq!(stats, want_stats, "stats for {name}");
}

/// (fixture file, expected detected format, allowlist)
const TABLE: &[(&str, ListFormat, bool)] = &[
    ("hosts.txt", ListFormat::Hosts, false),
    ("domains.txt", ListFormat::Domains, false),
    ("dnsmasq.conf", ListFormat::Dnsmasq, false),
    ("unbound.conf", ListFormat::Unbound, false),
    ("rpz.zone", ListFormat::Rpz, false),
    ("pihole.txt", ListFormat::Pihole, false),
    ("adguard-home.txt", ListFormat::AdguardHome, false),
    ("little-snitch.lsrules", ListFormat::LittleSnitch, false),
    ("surge.list", ListFormat::Surge, false),
    ("clash.yaml", ListFormat::Clash, false),
    ("ip-list.txt", ListFormat::IpList, false),
    ("abp.txt", ListFormat::Abp, false),
    ("ubo.txt", ListFormat::Ubo, false),
    ("adguard.txt", ListFormat::Adguard, false),
    ("hosts.txt", ListFormat::Hosts, true),
    ("abp.txt", ListFormat::Abp, true),
];

#[test]
fn fixture_table_exact_output_and_stats() {
    for (file, want_format, allow) in TABLE {
        let content = fixture(file);
        assert_eq!(detect(&content), *want_format, "detect {file}");
        let c = convert(
            &content,
            &ConvertOptions {
                allowlist: *allow,
                includes: includes(),
                ..Default::default()
            },
        );
        assert_eq!(c.format, *want_format, "converted format {file}");
        let name = format!("{file}{}", if *allow { ".allow" } else { "" });
        check_expected(&name, &c);
    }
}

#[test]
fn every_fixture_output_compiles_without_panics() {
    for (file, _, _) in TABLE {
        let c = convert(
            &fixture(file),
            &ConvertOptions {
                includes: includes(),
                ..Default::default()
            },
        );
        let out = compile_lists(&[&c.rules]);
        let s = &out.per_list[0];
        // Everything we emit must be accepted by the engine except hand-offs we could not know of.
        assert_eq!(s.rejected, 0, "{file}: rejected {:?}", s.errors);
    }
}

#[test]
fn explicit_format_overrides_detection() {
    // A domain list forced to `hosts` still yields bare domains; forced to `ip-list` it errors.
    let content = fixture("domains.txt");
    let c = convert(
        &content,
        &ConvertOptions {
            format: ListFormat::Hosts,
            ..Default::default()
        },
    );
    assert_eq!(c.format, ListFormat::Hosts);
    assert!(c.rules.contains("||ads.example.com^"));
    let c = convert(
        &content,
        &ConvertOptions {
            format: ListFormat::IpList,
            ..Default::default()
        },
    );
    assert!(c.rules.is_empty() && c.stats.error_count > 0);
}

#[test]
fn adblock_version_constant_matches_lockfile() {
    let lock = std::fs::read_to_string(dir().join("../../../../Cargo.lock")).unwrap();
    let want = format!(
        "name = \"adblock\"\nversion = \"{}\"",
        filter_engine::ADBLOCK_CRATE_VERSION
    );
    assert!(lock.contains(&want), "update ADBLOCK_CRATE_VERSION");
}

#[test]
fn format_names_round_trip() {
    for f in ListFormat::ALL {
        assert_eq!(f.as_str().parse::<ListFormat>().unwrap(), f);
        let j = serde_json::to_string(&f).unwrap();
        assert_eq!(serde_json::from_str::<ListFormat>(&j).unwrap(), f);
    }
    assert!("nope".parse::<ListFormat>().is_err());
}

// ---- detection ---------------------------------------------------------------------------------

#[test]
fn detect_survives_bom_crlf_and_comment_noise() {
    let hosts = "\u{feff}# c\r\n\r\n# more\r\n0.0.0.0 a.example.com\r\n0.0.0.0 b.example.com\r\n";
    assert_eq!(detect(hosts), ListFormat::Hosts);
    assert_eq!(detect(&hosts.replace("\r\n", "\n")), ListFormat::Hosts);
    assert_eq!(detect("! Title: x\r\n||a.example^\r\n"), ListFormat::Abp);
    assert_eq!(
        detect("\u{feff}[Adblock Plus 2.0]\n||a.example^\n"),
        ListFormat::Abp
    );
}

#[test]
fn detect_adversarial_mixes() {
    // Mostly hosts with a few ABP-looking lines: hosts wins.
    let mut mixed = String::new();
    for i in 0..30 {
        mixed.push_str(&format!("0.0.0.0 h{i}.example.com\n"));
    }
    mixed.push_str("||stray.example^\n@@||other.example^\nrandom junk line here\n");
    assert_eq!(detect(&mixed), ListFormat::Hosts);

    // Mostly ABP with stray domains.
    let mut abp = String::new();
    for i in 0..30 {
        abp.push_str(&format!("||ad{i}.example^$third-party\n"));
    }
    abp.push_str("stray.example.com\n0.0.0.0 x.example.com\n");
    assert_eq!(detect(&abp), ListFormat::Abp);

    // Domain list vs domain + regex (Pi-hole).
    assert_eq!(
        detect("a.example.com\nb.example.com\nc.example.org\n"),
        ListFormat::Domains
    );
    assert_eq!(
        detect("a.example.com\n^ads[0-9]+\\.example\\.com$\nb.example.com\n"),
        ListFormat::Pihole
    );

    // Empty / pure comments / binary-ish junk fall back to ABP and never panic.
    for junk in [
        "",
        "\n\n\n",
        "# only comments\n# here\n",
        "\0\0\0\u{1}\u{2}",
        "{not json",
        "{\"a\":1}",
    ] {
        assert_eq!(detect(junk), ListFormat::Abp, "{junk:?}");
    }
    // JSON that is not Little Snitch is not mistaken for it.
    assert_ne!(detect("{\"name\": \"x\"}"), ListFormat::LittleSnitch);

    // dnsmasq with an interleaved hosts line.
    let d =
        "address=/a.example.com/0.0.0.0\naddress=/b.example.com/0.0.0.0\n0.0.0.0 c.example.com\n";
    assert_eq!(detect(d), ListFormat::Dnsmasq);
    // IP list is not mistaken for hosts, and a hosts line is not mistaken for an IP list.
    assert_eq!(detect("1.2.3.0/24\n5.6.7.8\n"), ListFormat::IpList);
    assert_eq!(detect("1.2.3.4 host.example.com\n"), ListFormat::Hosts);
    // AdGuard-only syntax inside an ABP list flips it to adguard; uBO directives to ubo.
    assert_eq!(
        detect("||a.example^\nexample.com#%#//scriptlet('x')\n"),
        ListFormat::Adguard
    );
    assert_eq!(
        detect("||a.example^\n!#if ext_ublock\n||b.example^\n!#endif\n"),
        ListFormat::Ubo
    );
}

// ---- semantics ---------------------------------------------------------------------------------

fn conv(content: &str, format: ListFormat) -> Converted {
    convert(
        content,
        &ConvertOptions {
            format,
            ..Default::default()
        },
    )
}

fn lines(c: &Converted) -> Vec<&str> {
    c.rules.lines().collect()
}

#[test]
fn hosts_semantics() {
    let c = conv(
        "0.0.0.0 A.Example.COM b.example.com # x\n127.0.0.1 localhost\n",
        ListFormat::Hosts,
    );
    assert_eq!(lines(&c), ["||a.example.com^", "||b.example.com^"]);
    assert_eq!(c.stats.skipped, 1);
    // IDN is normalised to punycode, invalid hosts are errors.
    let c = conv(
        "0.0.0.0 bücher.example\n0.0.0.0 -bad-.com\n",
        ListFormat::Hosts,
    );
    assert_eq!(lines(&c), ["||xn--bcher-kva.example^"]);
    assert_eq!(c.stats.error_count, 1);
}

#[test]
fn rpz_passthru_becomes_exception_and_nsdname_is_counted() {
    let c = convert(&fixture("rpz.zone"), &ConvertOptions::default());
    assert!(lines(&c).contains(&"@@||safe.example.com^"));
    assert!(lines(&c).contains(&"||ads.example.com^"));
    assert_eq!(c.stats.skipped_reasons.get("rpz-nsdname"), Some(&1));
    assert_eq!(c.stats.skipped_reasons.get("rpz-ip"), Some(&1));
}

#[test]
fn pihole_regex_matches_host_not_path() {
    let c = conv(
        "^ads[0-9]+\\.example\\.com$\n(\\.|^)tracker\\.example\\.net$\n",
        ListFormat::Pihole,
    );
    let engine = SharedEngine::new();
    engine.install(compile_lists(&[&c.rules]).blob);
    let blocked = |u: &str| engine.check(u, "https://page.test/", "script").blocked;
    assert!(blocked("https://ads12.example.com/x.js"));
    assert!(blocked("https://ads12.example.com:8443/x.js"));
    assert!(
        !blocked("https://xads12.example.com/x.js"),
        "anchored at host start"
    );
    assert!(
        !blocked("https://other.test/ads12.example.com"),
        "must not match the path"
    );
    assert!(blocked("https://tracker.example.net/"));
    assert!(blocked("https://sub.tracker.example.net/"));
    assert!(
        !blocked("https://notracker.example.net/"),
        "(\\.|^) requires a label boundary"
    );
}

#[test]
fn surge_domain_is_exact_and_keyword_is_host_only() {
    let c = conv(
        "DOMAIN,exact.example.com,REJECT\nDOMAIN-KEYWORD,adtrack,REJECT\n",
        ListFormat::Surge,
    );
    let engine = SharedEngine::new();
    engine.install(compile_lists(&[&c.rules]).blob);
    let blocked = |u: &str| engine.check(u, "https://page.test/", "script").blocked;
    assert!(blocked("https://exact.example.com/a"));
    assert!(blocked("wss://exact.example.com/a") || blocked("https://exact.example.com/"));
    assert!(!blocked("https://sub.exact.example.com/a"));
    assert!(blocked("https://my-adtrack-host.example.net/"));
    assert!(
        !blocked("https://example.net/adtrack/x.js"),
        "keyword must not match the path"
    );
}

#[test]
fn ip_ranges_collected_not_hostname_rules() {
    let c = convert(&fixture("ip-list.txt"), &ConvertOptions::default());
    assert!(c.rules.is_empty());
    let set = filter_engine::IpSet::from_ranges(&c.ip_block);
    for ip in [
        "192.0.2.77",
        "198.51.100.7",
        "203.0.113.7",
        "2001:db8::1",
        "1.2.3.200",
    ] {
        assert!(set.contains(ip.parse().unwrap()), "{ip}");
    }
    for ip in ["192.0.3.1", "198.51.100.8", "203.0.113.10", "2001:db9::1"] {
        assert!(!set.contains(ip.parse().unwrap()), "{ip}");
    }
}

#[test]
fn preprocessor_environment() {
    let (text, meta) = preprocess_and_meta(&fixture("ubo.txt"), &includes());
    assert!(text.contains("||not-chromium.example^"));
    assert!(text.contains("||ublock.example^"));
    assert!(text.contains("||included.example^"));
    assert!(!text.contains("chromium-only") && !text.contains("adguard-or-mobile"));
    assert_eq!(meta.title.as_deref(), Some("uBO list"));
    // `!#include` loops are bounded.
    let looped = HashMap::from([(
        "a.txt".to_string(),
        "!#include a.txt\n||loop.example^\n".to_string(),
    )]);
    let (t, _) = preprocess_and_meta("!#include a.txt\n", &looped);
    assert!(t.matches("||loop.example^").count() <= 4);
}

#[test]
fn metadata_headers() {
    let c = convert(&fixture("abp.txt"), &ConvertOptions::default());
    assert_eq!(c.meta.title.as_deref(), Some("Test ABP"));
    assert_eq!(c.meta.homepage.as_deref(), Some("https://example.org"));
    assert_eq!(c.meta.version.as_deref(), Some("202401010000"));
    assert_eq!(c.meta.expires_secs, Some(4 * 86_400));
    assert_eq!(
        c.meta.redirect.as_deref(),
        Some("https://example.org/new.txt")
    );
    let c = convert(&fixture("hosts.txt"), &ConvertOptions::default());
    assert_eq!(c.meta.expires_secs, Some(2 * 86_400));
    for (v, want) in [
        ("12 hours", 12 * 3600),
        ("1 hour", 3600),
        ("30 days", 14 * 86_400),
        ("1 day", 86_400),
    ] {
        let c = convert(
            &format!("! Expires: {v}\n||a.example^\n"),
            &ConvertOptions::default(),
        );
        assert_eq!(c.meta.expires_secs, Some(want), "{v}");
    }
}

#[test]
fn allowlist_marks_everything_as_exception() {
    let c = convert(
        "||a.example^\nexample.com##.x\n||b.example^$script\n@@||c.example^\n",
        &ConvertOptions {
            allowlist: true,
            ..Default::default()
        },
    );
    assert_eq!(
        lines(&c),
        [
            "@@||a.example^",
            "example.com#@#.x",
            "@@||b.example^$script",
            "@@||c.example^"
        ]
    );
}

// ---- AdGuard / uBO extended syntax -------------------------------------------------------------

fn one(rule: &str) -> Converted {
    convert(
        &format!("{rule}\n"),
        &ConvertOptions {
            format: ListFormat::Adguard,
            ..Default::default()
        },
    )
}

#[test]
fn scriptlet_translation() {
    let c = one("example.com#%#//scriptlet('abort-on-property-read', 'foo.bar')");
    assert_eq!(
        lines(&c),
        ["example.com##+js(abort-on-property-read, foo.bar)"]
    );
    let c = one("example.com#%#//scriptlet(\"prevent-setTimeout\", \"ads\", \"500\")");
    assert_eq!(lines(&c), ["example.com##+js(no-setTimeout-if, ads, 500)"]);
    let c = one("example.com#%#//scriptlet('prevent-xhr', 'a,b')");
    assert_eq!(lines(&c), ["example.com##+js(no-xhr-if, a\\,b)"]);
    let c = one("example.com#@%#//scriptlet('abort-on-property-read', 'x')");
    assert_eq!(lines(&c), ["example.com#@#+js(abort-on-property-read, x)"]);
    let c = one("example.com#%#//scriptlet('unknown-thing')");
    assert!(c.rules.is_empty());
    assert_eq!(c.ext[0].kind, ExtKind::Scriptlet);
    assert_eq!(c.ext[0].domains, ["example.com"]);
    // Every alias in the table is syntactically well-formed.
    for (ag, ubo) in scriptlet_alias_table() {
        let c = one(&format!("a.example#%#//scriptlet('{ag}', 'x')"));
        assert_eq!(lines(&c), [format!("a.example##+js({ubo}, x)")], "{ag}");
    }
}

#[test]
fn translated_scriptlet_actually_injects() {
    let c = one("example.com#%#//scriptlet('abort-on-property-read', 'foo.bar')");
    let engine = SharedEngine::new();
    engine.install(compile_lists(&[&c.rules]).blob);
    let json = serde_json::json!([{
        "name": "abort-on-property-read.js", "aliases": ["aopr"],
        "kind": {"mime": "application/javascript"},
        "content": "ZnVuY3Rpb24gYWJvcnRPblByb3BlcnR5UmVhZCgpIHt9",
    }]);
    engine.set_resources_from_json(&json.to_string()).unwrap();
    assert!(!engine
        .cosmetic_for("https://example.com/")
        .injected_script
        .is_empty());
}

#[test]
fn css_injection_translation() {
    let c = one("example.com#$#.sel { display: none !important; }");
    assert_eq!(
        lines(&c),
        ["example.com##.sel:style(display: none !important)"]
    );
    let c = one("example.com#@$#.sel { margin: 0 }");
    assert_eq!(lines(&c), ["example.com#@#.sel:style(margin: 0)"]);
    let c = one("example.com#$#hide-if-contains 'x'");
    assert_eq!(c.ext[0].kind, ExtKind::Snippet);
}

#[test]
fn ext_classification_per_kind() {
    let cases = [
        ("||a.example^$replace=/foo/bar/", ExtKind::Replace),
        ("||a.example^$jsonprune=\\$..ads", ExtKind::JsonPrune),
        ("||a.example^$xmlprune=//ad", ExtKind::XmlPrune),
        ("||a.example^$cookie=sid", ExtKind::Cookie),
        ("||a.example^$removeheader=refresh", ExtKind::RemoveHeader),
        ("||a.example^$hls=ad", ExtKind::Hls),
        (
            "||a.example^$permissions=geolocation=()",
            ExtKind::Permissions,
        ),
        ("||a.example^$urltransform=/a/b/", ExtKind::UrlTransform),
        ("||a.example^$method=post", ExtKind::Method),
        ("||a.example^$popup", ExtKind::Popup),
        ("||a.example^$popup,domain=x.example", ExtKind::Popup),
        ("example.com##^script:has-text(ad)", ExtKind::HtmlFilter),
        (
            "example.com$$script[tag-content=\"ad\"]",
            ExtKind::HtmlFilter,
        ),
        ("example.com#%#window.x = 1;", ExtKind::JsInject),
    ];
    for (rule, kind) in &cases {
        let c = one(rule);
        assert!(c.rules.is_empty(), "{rule}");
        assert_eq!(c.ext.len(), 1, "{rule}");
        assert_eq!(c.ext[0].kind, *kind, "{rule}");
        assert_eq!(c.ext[0].raw, *rule);
        assert_eq!(c.stats.ext_counts.get(kind.as_str()), Some(&1), "{rule}");
    }
    let c = one("||a.example^$replace=/x/y/,domain=p.example|q.example");
    assert_eq!(c.ext[0].domains, ["p.example", "q.example"]);
}

#[test]
fn network_modifier_translations() {
    // $popup alongside $document is redundant.
    assert_eq!(
        lines(&one("||h.example^$document,popup")),
        ["||h.example^$document"]
    );
    // $all / $document / $from are native.
    assert_eq!(lines(&one("||h.example^$all")), ["||h.example^$all"]);
    assert_eq!(
        lines(&one("||h.example^$from=x.example")),
        ["||h.example^$from=x.example"]
    );
    // $denyallow becomes the rule plus scoped exceptions.
    let c = one("*$denyallow=x.example|y.example,script,domain=z.example");
    assert_eq!(
        lines(&c),
        [
            "*$script,domain=z.example",
            "@@||x.example^$script,domain=z.example",
            "@@||y.example^$script,domain=z.example"
        ]
    );
    // $to with a match-all pattern becomes host rules; with a pattern it is handed off.
    let c = one("*$to=t1.example|t2.example,image");
    assert_eq!(lines(&c), ["||t1.example^$image", "||t2.example^$image"]);
    let c = one("/ads/*$to=t1.example");
    assert_eq!(c.ext[0].kind, ExtKind::To);
    // $empty maps to a redirect resource.
    assert_eq!(
        lines(&one("||k.example^$empty")),
        ["||k.example^$redirect=nooptext"]
    );
    // $header is skipped and counted.
    let c = one("||hh.example^$header=x-ad");
    assert!(c.rules.is_empty() && c.ext.is_empty());
    assert_eq!(c.stats.skipped_reasons.get("header"), Some(&1));
}

#[test]
fn denyallow_translation_semantics() {
    let c = one("*$denyallow=cdn.test,script,domain=site.test");
    let engine = SharedEngine::new();
    engine.install(compile_lists(&[&c.rules]).blob);
    let blocked = |u: &str, src: &str| engine.check(u, src, "script").blocked;
    assert!(blocked("https://ads.test/a.js", "https://site.test/"));
    assert!(!blocked("https://cdn.test/a.js", "https://site.test/"));
    assert!(!blocked("https://ads.test/a.js", "https://other.test/"));
}

#[test]
fn unsupported_options_rejected_by_engine_are_handed_off_at_compile() {
    let c = one("||s.example^$stealth\n||ok.example^");
    let out = compile_lists(&[&c.rules]);
    assert_eq!(out.per_list[0].network, 1);
    assert_eq!(out.per_list[0].ext, 1);
    assert_eq!(
        out.per_list[0].ext_rules[0].kind,
        ExtKind::UnsupportedOption
    );
    assert_eq!(out.per_list[0].rejected, 0);
}

#[test]
fn compile_reports_rejects_with_reasons() {
    let out = compile_lists(&["||ok.example^\n|\n"]);
    assert_eq!(out.per_list[0].network, 1);
    assert_eq!(out.per_list[0].rejected, 1);
    assert_eq!(out.per_list[0].errors[0].0, 2);
}

// ---- robustness --------------------------------------------------------------------------------

/// Tiny xorshift so the fuzz loop is deterministic and dependency-free.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

#[test]
fn conversion_never_panics_on_arbitrary_input() {
    let seeds: Vec<String> = TABLE.iter().map(|(f, _, _)| fixture(f)).collect();
    let mut rng = Rng(0x9E3779B97F4A7C15);
    let alphabet: Vec<char> = "$#@!|^*/\\()[]{}.,:;=~-_ \t\r\n0aAzZ9é\u{feff}\0%\"'`+?"
        .chars()
        .collect();
    for round in 0..600 {
        let seed = &seeds[round % seeds.len()];
        let mut chars: Vec<char> = seed.chars().collect();
        // Mutate: replace, insert, delete, truncate.
        for _ in 0..(1 + rng.next() % 12) {
            if chars.is_empty() {
                break;
            }
            let i = (rng.next() as usize) % chars.len();
            match rng.next() % 4 {
                0 => chars[i] = alphabet[(rng.next() as usize) % alphabet.len()],
                1 => chars.insert(i, alphabet[(rng.next() as usize) % alphabet.len()]),
                2 => {
                    chars.remove(i);
                }
                _ => chars.truncate(i),
            }
        }
        let mutated: String = chars.into_iter().collect();
        let format = ListFormat::ALL[(rng.next() as usize) % ListFormat::ALL.len()];
        let allow = rng.next() % 2 == 0;
        let c = convert(
            &mutated,
            &ConvertOptions {
                format,
                allowlist: allow,
                ..Default::default()
            },
        );
        // Whatever comes out must also survive the engine.
        let _ = compile_lists(&[&c.rules]);
        let _ = detect(&mutated);
    }
    // Pure noise, including invalid-UTF-8-derived text.
    for len in [0usize, 1, 7, 100, 4000] {
        let bytes: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        for f in ListFormat::ALL {
            let _ = convert(
                &text,
                &ConvertOptions {
                    format: f,
                    ..Default::default()
                },
            );
        }
    }
}

#[test]
fn error_list_is_capped() {
    let junk: String = (0..500)
        .map(|i| format!("0.0.0.0 bad_{i}!.com\n"))
        .collect();
    let c = conv(&junk, ListFormat::Hosts);
    assert_eq!(c.stats.error_count, 500);
    assert_eq!(c.stats.errors.len(), filter_engine::formats::MAX_ERRORS);
}

#[test]
fn dedupe_drops_repeats_within_and_across_lists() {
    use filter_engine::formats::dedupe;
    let mut seen = std::collections::HashSet::new();
    let (a, d1) = dedupe("||a^\n||b^\n||a^\n", &mut seen);
    assert_eq!((a.as_str(), d1), ("||a^\n||b^\n", 1));
    let (b, d2) = dedupe("||b^\n||c^\n", &mut seen);
    assert_eq!((b.as_str(), d2), ("||c^\n", 1));
}

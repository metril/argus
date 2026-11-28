//! The per-line classifier must agree with what a real build reports for the same lists.

use std::collections::HashMap;
use std::time::Instant;

use filter_engine::inspect::{classify_list, Classified, ExtVerdict, Live};
use filter_engine::{build_set, ExtRule, ListFormat, ListInput, ListReport};

fn input(id: &str, content: &str, format: ListFormat) -> ListInput {
    ListInput {
        id: id.into(),
        content: content.into(),
        format,
        ..Default::default()
    }
}

fn enforce(r: &[ExtRule]) -> Vec<ExtVerdict> {
    r.iter().map(|_| ExtVerdict::enforced()).collect()
}

fn fixtures() -> Vec<ListInput> {
    let abp = "[Adblock Plus 2.0]\n! Title: Fixture\n||ads.test^\n||ads.test^\n||sub.ads.test^\n\
               ||t.test/banner^$script\n||t.test/banner^$script\n@@||ok.test^$document\n\
               example.com##.sponsor\nexample.com##.sponsor\n##.ad-box\n\
               ||x.test^$replace=/a/b/\nexample.com##^script:has-text(x)\n\
               ||y.test^$bogus-option\n||$$\n\
               example.com#$#body { margin: 0 }\n\
               ##+js(set-constant, a, 1)\n!#if ext_ublock\n||only-ubo.test^\n!#else\n||else.test^\n!#endif\n\
               !#if cap_html_filtering\n||html.test^\n!#endif\n!#include inc.txt\n||last.test^\n";
    let mut a = input("abp", abp, ListFormat::Auto);
    a.includes.insert(
        "inc.txt".into(),
        "||inc1.test^\n!#if false\n||never.test^\n!#endif\ninc.test##.i\n".into(),
    );
    let mut trusted = input("trusted-ubo", abp, ListFormat::Ubo);
    trusted.trusted = true;
    trusted.includes = a.includes.clone();
    let hosts = input(
        "hosts",
        "# hosts\n127.0.0.1 localhost\n0.0.0.0 ads.test dup.test dup.test\n0.0.0.0 sub.ads.test\n\
         192.168.1.5 nas\nfoo bar baz\n0.0.0.0\nnot a host line\nlast-host.test\n",
        ListFormat::Hosts,
    );
    let adguard = input(
        "adguard-fixture",
        "||m.test/a.js$script,redirect=noop.js\n||m.test^$redirect-rule=noop.js\n@@://h.test^|\n\
         @@||keep.test^\nexample.org#%#//scriptlet('abort-on-property-read', 'x')\n\
         example.org$$script[data-x]\n||d.test^$denyallow=a.com\n[$domain=a.com]##.x\n[$path=/p]##.y\n",
        ListFormat::Adguard,
    );
    let surge = input(
        "surge",
        "[Rule]\nDOMAIN,exact.test,REJECT\nDOMAIN-SUFFIX,suffix.test,REJECT\nDOMAIN-KEYWORD,kw,REJECT\n\
         IP-CIDR,10.0.0.0/8,REJECT\nGEOIP,CN,DIRECT\nDOMAIN,proxy.test,PROXY\nbogus line\n\
         [Proxy]\nDOMAIN,x.test,REJECT\n",
        ListFormat::Surge,
    );
    let dnsmasq = input(
        "dnsmasq",
        "# dnsmasq\naddress=/dnsm.test/0.0.0.0\nserver=/other.test/\naddress=/ans.test/1.2.3.4\ncache-size=100\naddress=nothing\n",
        ListFormat::Dnsmasq,
    );
    let rpz = input(
        "rpz",
        "$TTL 300\n$ORIGIN rpz.example.\n@ SOA localhost. root.localhost. ( 1 2 3 4 5 )\n\
         rpz.test CNAME .\nok.test CNAME rpz-passthru.\nbad record\nrpz-nsdname.foo CNAME .\n*.wild.test CNAME .\n",
        ListFormat::Rpz,
    );
    let ips = input(
        "ips",
        "# ips\n192.0.2.0/24\n198.51.100.1\nnot-an-ip\n10.0.0.1 10.0.0.9\n",
        ListFormat::IpList,
    );
    let pihole = input(
        "pihole",
        "pi.test\n/ad[0-9]+\\.test/\n(bad(regex\nhosts.test extra\n",
        ListFormat::Pihole,
    );
    let mut allow = input("allow", "allowed.test\nads.test\n", ListFormat::Domains);
    allow.allowlist = true;
    // `$badfilter` across lists, a rule that is covered AND disabled, and one exact host held
    // by two lists under different schemes.
    let bf_a = input(
        "bf-a",
        "||x.test^\n||cov.test^\n||sub.cov.test^\n||x.test^\n|https://ex.test^\n|https://ex.test^\n",
        ListFormat::Abp,
    );
    let bf_b = input(
        "bf-b",
        "||x.test^$badfilter\n||sub.cov.test^$badfilter\n||x.test^\n|http://ex.test^\n|https://ex.test^\n",
        ListFormat::Abp,
    );
    let mut v = vec![
        a, trusted, hosts, adguard, surge, dnsmasq, rpz, ips, pihole, allow,
    ];
    v.extend([bf_a, bf_b]);
    v
}

fn assert_parity(inputs: &[ListInput]) {
    let built = build_set(inputs);
    let live = Live {
        origins: &built.origins,
        domains: &built.domains,
    };
    for (i, rep) in inputs.iter().zip(&built.reports) {
        let c = classify_list(i, Some(live), &enforce);
        assert!(c.in_build, "{}", i.id);
        assert_matches(&i.id, &c, rep);
    }
}

fn assert_matches(id: &str, c: &Classified, rep: &ListReport) {
    let n = &c.counts;
    let got = [
        n.lines,
        n.network,
        n.cosmetic,
        n.ext(),
        n.duplicate,
        n.covered,
        n.disabled,
        n.unsupported,
        n.invalid_conversion,
        n.invalid_compile,
        n.ip_ranges,
        n.translated,
    ];
    let want = [
        rep.total_lines,
        rep.network,
        rep.cosmetic,
        rep.ext,
        rep.duplicates,
        rep.compressed,
        rep.disabled,
        rep.skipped,
        rep.error_count,
        rep.rejected,
        rep.ip_ranges,
        rep.translated,
    ];
    assert_eq!(c.format, rep.format, "{id}");
    assert_eq!(got, want, "{id}: classifier vs build report");
}

#[test]
fn classifier_totals_equal_the_build_report_in_both_orders() {
    let inputs = fixtures();
    assert_parity(&inputs);
    let mut rev = inputs.clone();
    rev.reverse();
    assert_parity(&rev);
    // And every pair swapped around the middle.
    let mut rot = inputs.clone();
    rot.rotate_left(3);
    assert_parity(&rot);
}

#[test]
fn a_single_list_standalone_equals_its_own_build() {
    for i in fixtures() {
        let built = build_set(std::slice::from_ref(&i));
        let alone = classify_list(&i, None, &enforce);
        assert!(!alone.in_build);
        assert_matches(&i.id, &alone, &built.reports[0]);
    }
}

#[test]
fn every_status_appears_and_lines_are_ordered_and_in_range() {
    let inputs = fixtures();
    let built = build_set(&inputs);
    let live = Live {
        origins: &built.origins,
        domains: &built.domains,
    };
    let mut seen: HashMap<String, usize> = HashMap::new();
    for i in &inputs {
        let c = classify_list(i, Some(live), &enforce);
        let mut prev = 0;
        for r in &c.records {
            assert!(
                r.line >= 1 && r.line as usize <= c.counts.lines,
                "{}: {}",
                i.id,
                r.line
            );
            assert!(r.line >= prev, "{}: records out of order", i.id);
            prev = r.line;
            *seen.entry(format!("{:?}", r.kind)).or_default() += 1;
        }
    }
    for k in [
        "Comment",
        "Inactive",
        "Network",
        "Cosmetic",
        "Extended",
        "Duplicate",
        "Covered",
        "Unsupported",
        "Invalid",
    ] {
        assert!(
            seen.contains_key(k),
            "no {k} line in the fixtures: {seen:?}"
        );
    }
}

/// Production lists (a directory of cached list files named by hash), from `ARGUS_LISTS_DIR`:
/// every list must classify to the totals the build reports. Prints lines, counts and time.
/// `cargo test -p filter-engine --release --test inspect_parity -- --ignored --nocapture`
#[test]
#[ignore = "needs ARGUS_LISTS_DIR"]
fn production_lists_match_their_build_report() {
    let dir = std::env::var("ARGUS_LISTS_DIR").expect("ARGUS_LISTS_DIR");
    let mut inputs: Vec<ListInput> = Vec::new();
    let mut names: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .map(|e| e.path())
        .collect();
    names.sort();
    for p in names {
        let Ok(content) = std::fs::read_to_string(&p) else {
            continue;
        };
        let id = p.file_name().unwrap().to_string_lossy().to_string();
        let mut i = input(&id[..id.len().min(12)], &content, ListFormat::Auto);
        i.trusted = false;
        inputs.push(i);
    }
    let t = Instant::now();
    let built = build_set(&inputs);
    eprintln!("build of {} lists: {:?}", inputs.len(), t.elapsed());
    let live = Live {
        origins: &built.origins,
        domains: &built.domains,
    };
    let mut bad = Vec::new();
    for (i, rep) in inputs.iter().zip(&built.reports) {
        let t = Instant::now();
        let c = classify_list(i, Some(live), &enforce);
        let took = t.elapsed();
        let n = &c.counts;
        eprintln!(
            "{:>12} {:?} lines={} comment={} inactive={} network={} ip={} cosmetic={} ext={} dup={} covered={} unsupported={} invalid_conv={} invalid_compile={} in {:?}",
            i.id, c.format, n.lines, n.comment, n.inactive, n.network, n.ip_ranges, n.cosmetic,
            n.ext(), n.duplicate, n.covered, n.unsupported, n.invalid_conversion,
            n.invalid_compile, took
        );
        let r = std::panic::catch_unwind(|| assert_matches(&i.id, &c, rep));
        if r.is_err() {
            bad.push(i.id.clone());
        }
    }
    assert!(
        bad.is_empty(),
        "classifier differs from the build for {bad:?}"
    );
}

#[test]
fn trust_dependent_branches_and_location_cosmetics_match_the_build() {
    use filter_engine::inspect::Kind;
    let text = "!#if cap_html_filtering\n||trusted-branch.test^\n!#else\n||untrusted-branch.test^\n!#endif\n\
        [$path=/search]a.test##.ad\n/^h[0-9]+\\.x\\.test$/##.ad\n||r.test^$replace=/a,b/c/,script\n";
    for trusted in [false, true] {
        let mut i = input("t", text, ListFormat::Abp);
        i.trusted = trusted;
        assert_parity(&[i.clone()]);
        let c = classify_list(&i, None, &enforce);
        let kinds = |line: u32| -> Vec<Kind> {
            c.records
                .iter()
                .filter(|r| r.line == line)
                .map(|r| r.kind)
                .collect()
        };
        // Exactly one branch of the `!#if` is active for the list's trust.
        assert_eq!(
            kinds(2),
            [if trusted {
                Kind::Network
            } else {
                Kind::Inactive
            }]
        );
        assert_eq!(
            kinds(4),
            [if trusted {
                Kind::Inactive
            } else {
                Kind::Network
            }]
        );
        // Location-scoped cosmetics always go to the extended-rule index.
        for line in [6, 7] {
            let r = c.records.iter().find(|r| r.line == line).unwrap();
            assert_eq!(r.kind, Kind::Extended, "line {line}");
            assert_eq!(r.ext_kind.map(|k| k.as_str()), Some("cosmetic-location"));
        }
    }
}

#[test]
fn badfilter_covered_and_exact_scheme_cases_are_attributed() {
    use filter_engine::inspect::Kind;
    let all = fixtures();
    let pair: Vec<ListInput> = all
        .iter()
        .filter(|i| i.id.starts_with("bf-"))
        .cloned()
        .collect();
    assert_eq!(pair.len(), 2);
    let built = build_set(&pair);
    let live = Live {
        origins: &built.origins,
        domains: &built.domains,
    };
    let a = classify_list(&pair[0], Some(live), &enforce);
    let b = classify_list(&pair[1], Some(live), &enforce);
    let kind = |c: &Classified, line: u32| {
        c.records
            .iter()
            .filter(|r| r.line == line)
            .map(|r| r.kind)
            .collect::<Vec<_>>()
    };
    // `||x.test^` is disabled by bf-b's `$badfilter`, in both lists, every occurrence.
    assert_eq!(kind(&a, 1), [Kind::Disabled]);
    assert_eq!(kind(&a, 4), [Kind::Disabled]);
    assert_eq!(kind(&b, 3), [Kind::Disabled]);
    assert_eq!(kind(&b, 1), [Kind::Network], "the $badfilter rule itself");
    // `||sub.cov.test^` is covered by `||cov.test^` and also disabled: covered comes first, and
    // the report agrees.
    assert_eq!(kind(&a, 3), [Kind::Covered]);
    // The same exact host under another scheme in the later list is a duplicate of the lowest.
    assert_eq!(kind(&a, 5), [Kind::Network]);
    assert_eq!(kind(&a, 6), [Kind::Duplicate]);
    assert_eq!(kind(&b, 4), [Kind::Duplicate]);
    assert_eq!(kind(&b, 5), [Kind::Duplicate]);
    assert_eq!(a.counts.disabled, built.reports[0].disabled);
    assert_eq!(b.counts.disabled, built.reports[1].disabled);
    assert_eq!(built.reports[0].disabled, 2);
}

fn vm_kb(field: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix(field))
        .and_then(|v| v.trim().trim_end_matches(" kB").trim().parse().ok())
        .unwrap_or(0)
}

/// Memory of the biggest list in `ARGUS_LISTS_DIR`: bytes held per record, and the peak resident
/// size while classifying it alone, standalone (run this test by itself so the peak is its own):
/// `-- --ignored --nocapture largest_production_list_memory`
#[test]
#[ignore = "needs ARGUS_LISTS_DIR"]
fn largest_production_list_memory() {
    let dir = std::env::var("ARGUS_LISTS_DIR").expect("ARGUS_LISTS_DIR");
    let biggest = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .max_by_key(|p| std::fs::metadata(p).map_or(0, |m| m.len()))
        .unwrap();
    let content = std::fs::read_to_string(&biggest).unwrap();
    let i = input("big", &content, ListFormat::Auto);
    let (before, hwm0) = (vm_kb("VmRSS:"), vm_kb("VmHWM:"));
    let t = Instant::now();
    let c = classify_list(&i, None, &enforce);
    let took = t.elapsed();
    let (after, hwm) = (vm_kb("VmRSS:"), vm_kb("VmHWM:"));
    eprintln!(
        "list of {} bytes, {} lines, {} records, format {:?}: classified in {took:?}\n\
         held: {} bytes = {:.1} bytes/record (record struct {} bytes), text {} bytes\n\
         resident before {before} kB, after {after} kB; peak {hwm} kB (peak before {hwm0} kB): \
         transient peak over the input ~{} MB",
        content.len(),
        c.counts.lines,
        c.records.len(),
        c.format,
        c.approx_bytes(),
        c.approx_bytes() as f64 / c.records.len() as f64,
        std::mem::size_of::<filter_engine::inspect::Record>(),
        content.len(),
        (hwm.saturating_sub(before)) / 1024
    );
}

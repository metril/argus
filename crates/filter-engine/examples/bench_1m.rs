//! One timed convert + dedupe + compile of a synthetic 1M-line hosts list, with peak RSS, load
//! time and per-check latency (hit in the domain set, miss everywhere, hit via an engine rule).

use std::hint::black_box;
use std::time::Instant;

use filter_engine::{build_set, convert, ConvertOptions, ListFormat, ListInput, SharedEngine};

fn peak_rss_mb() -> f64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmHWM:"))
                .and_then(|l| l.split_whitespace().nth(1)?.parse::<f64>().ok())
        })
        .map_or(0.0, |kb| kb / 1024.0)
}

fn ns_per_check(engine: &SharedEngine, url: &str, ty: &str, expect_blocked: bool) -> f64 {
    let n = 200_000;
    assert_eq!(
        engine.check(url, "https://page.example/", ty).blocked,
        expect_blocked,
        "{url}"
    );
    // Best of 7 rounds: robust against noisy neighbours.
    (0..7)
        .map(|_| {
            let t = Instant::now();
            for _ in 0..n / 4 {
                black_box(engine.check(black_box(url), "https://page.example/", ty));
            }
            t.elapsed().as_nanos() as f64 / (n / 4) as f64
        })
        .fold(f64::MAX, f64::min)
}

fn main() {
    let n = 1_000_000;
    let mut hosts = String::with_capacity(n * 32);
    hosts.push_str("# Title: synthetic\n127.0.0.1 localhost\n");
    for i in 0..n {
        hosts.push_str(&format!(
            "0.0.0.0 ad{i}.tracker{}.example{}.com\n",
            i % 997,
            i % 13
        ));
    }
    println!("input: {} lines, {:.1} MB", n + 2, hosts.len() as f64 / 1e6);

    let t = Instant::now();
    let c = convert(&hosts, &ConvertOptions::default());
    println!(
        "convert:                    {:>8.0?}  ({} rules)",
        t.elapsed(),
        c.stats.converted
    );
    drop(c);

    for (label, engine_rules) in [
        ("hosts only (engine empty)", ""),
        (
            "engine has NO exceptions",
            "||ads.engine-rule.net^$script,third-party\n",
        ),
        (
            "engine has exceptions",
            "||ads.engine-rule.net^$script,third-party\n@@||ok.engine-rule.net^\n",
        ),
    ] {
        println!("--- {label}");
        scenario(&hosts, engine_rules);
    }
}

fn scenario(hosts: &str, engine_rules: &str) {
    let t = Instant::now();
    let built = build_set(&[
        ListInput {
            id: "hosts".into(),
            content: hosts.to_string(),
            format: ListFormat::Auto,
            ..Default::default()
        },
        ListInput {
            id: "abp".into(),
            content: engine_rules.into(),
            ..Default::default()
        },
    ]);
    let build = t.elapsed();
    let blob = built.blob.len();
    println!(
        "convert+dedupe+compile:     {build:>8.0?}  (network={}, engine blob {:.1} MB, domain set {:.1} MB)",
        built.reports[0].network,
        blob as f64 / 1e6,
        built.domains.size_bytes() as f64 / 1e6
    );
    let rss_build = peak_rss_mb();

    let t = Instant::now();
    let bytes = built.domains.to_bytes();
    let back = filter_engine::DomainSet::from_bytes(&bytes).unwrap();
    println!(
        "domain set serialize+load:  {:>8.0?}  ({} entries, {:.1} MB)",
        t.elapsed(),
        back.len(),
        bytes.len() as f64 / 1e6
    );
    drop((bytes, back));
    let t = Instant::now();
    let engine = SharedEngine::new();
    built.install_into(&engine);
    println!("install (startup path):     {:>8.0?}", t.elapsed());
    println!(
        "peak RSS after build: {rss_build:.0} MB; at end: {:.0} MB",
        peak_rss_mb()
    );

    let i = 500_000;
    let hit = format!(
        "https://ad{i}.tracker{}.example{}.com/x.js",
        i % 997,
        i % 13
    );
    let sub = format!(
        "https://cdn.eu.ad{i}.tracker{}.example{}.com/x.js",
        i % 997,
        i % 13
    );
    println!(
        "check, domain-set hit:      {:>8.0} ns",
        ns_per_check(&engine, &hit, "script", true)
    );
    println!(
        "check, domain-set subdomain:{:>8.0} ns",
        ns_per_check(&engine, &sub, "script", true)
    );
    println!(
        "check, miss everywhere:     {:>8.0} ns",
        ns_per_check(
            &engine,
            "https://www.wikipedia.org/wiki/Rust?x=1",
            "script",
            false
        )
    );
    if !engine_rules.is_empty() {
        println!(
            "check, hit via engine rule: {:>8.0} ns",
            ns_per_check(&engine, "https://ads.engine-rule.net/a.js", "script", true)
        );
    }
}

//! `SharedEngine::check` against a synthetic ~50k-rule network list.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use filter_engine::{
    build_set, compile_engine, try_build_engine, ListFormat, ListInput, SharedEngine,
};
use std::sync::Arc;
use std::time::Instant;

fn rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|s| s.split_whitespace().nth(1)?.parse::<u64>().ok())
        .map_or(0, |p| p * 4)
}

fn synthetic_list(n: usize) -> String {
    let mut s = String::with_capacity(n * 40);
    for i in 0..n {
        match i % 5 {
            0 => s.push_str(&format!("||ads{i}.example{}.com^\n", i % 97)),
            1 => s.push_str(&format!(
                "||cdn{i}.tracker.net/pixel{i}.gif$image,third-party\n"
            )),
            2 => s.push_str(&format!("/banner{i}/*$script\n")),
            3 => s.push_str(&format!("&adunit{i}=\n")),
            _ => s.push_str(&format!("@@||safe{i}.example.org^$document\n")),
        }
    }
    s
}

fn bench_check(c: &mut Criterion) {
    let engine = SharedEngine::new();
    engine.install(compile_engine(&[synthetic_list(50_000)]));

    let cases = [
        ("blocked_host", "https://ads10.example10.com/x.js", "script"),
        ("blocked_path", "https://site.test/banner12/a.js", "script"),
        (
            "allowed_miss",
            "https://static.cdn.test/app/main.bundle.js?v=3",
            "script",
        ),
        (
            "allowed_long",
            "https://www.example.com/assets/img/photo/large/2024/05/hero.jpg",
            "image",
        ),
    ];
    let mut g = c.benchmark_group("check_50k_rules");
    for (name, url, ty) in cases {
        g.bench_function(name, |b| {
            b.iter(|| black_box(engine.check(black_box(url), "https://page.example.com/", ty)))
        });
    }
    g.finish();
}

/// Real lists from `ADBLOCK_BENCH_LISTS` (colon-separated paths); skipped when unset.
fn bench_real(c: &mut Criterion) {
    let Ok(paths) = std::env::var("ADBLOCK_BENCH_LISTS") else {
        return;
    };
    let inputs: Vec<ListInput> = paths
        .split(':')
        .filter(|p| !p.is_empty())
        .enumerate()
        .map(|(i, p)| ListInput {
            id: format!("l{i}"),
            content: std::fs::read_to_string(p).expect("read list"),
            format: ListFormat::Auto,
            allowlist: false,
            trusted: false,
            includes: Default::default(),
        })
        .collect();
    let rss0 = rss_kib();
    let t = Instant::now();
    let built = build_set(&inputs);
    let t_build = t.elapsed();
    let t = Instant::now();
    let engine = try_build_engine(&built.blob, &[]).expect("engine");
    let t_load = t.elapsed();
    let rules: usize = built
        .reports
        .iter()
        .map(|r| r.network + r.cosmetic + r.ext)
        .sum();
    eprintln!(
        "real lists: {rules} rules, build_set {t_build:?}, engine load {t_load:?}, blob {} KiB, \
         domain set {} entries, rss delta {} KiB",
        built.blob.len() / 1024,
        built.domains.len(),
        rss_kib().saturating_sub(rss0)
    );
    let shared = SharedEngine::new();
    shared.install_set(
        Arc::new(built.blob),
        engine,
        Arc::default(),
        Arc::new(built.ip),
        Arc::new(built.domains),
    );
    let cases = [
        ("blocked_host", "https://doubleclick.net/ads/show.js", "script"),
        ("blocked_path", "https://www.example.com/js/adframe.js", "script"),
        (
            "allowed_miss",
            "https://static.cdn.test/app/main.bundle.js?v=3",
            "script",
        ),
        (
            "allowed_long",
            "https://www.example.com/assets/img/photo/large/2024/05/hero-image-1600x900.jpg?w=1600&q=80",
            "image",
        ),
        (
            "third_party_script",
            "https://cdn.thirdparty.test/lib/widget/v2/loader.min.js",
            "script",
        ),
    ];
    let mut g = c.benchmark_group("check_real_lists");
    for (name, url, ty) in cases {
        g.bench_function(name, |b| {
            b.iter(|| black_box(shared.check(black_box(url), "https://page.example.com/", ty)))
        });
    }
    g.finish();
}

criterion_group!(benches, bench_check, bench_real);
criterion_main!(benches);

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
    let stage_engine = try_build_engine(&built.blob, &[]).expect("engine");
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

    // Where the time of one check goes: URL parse, request construction (what the check path
    // builds per call) and the adblock-rust match on a prebuilt request.
    let source = "https://page.example.com/";
    let mut g = c.benchmark_group("check_real_stages");
    for (name, url, ty) in cases {
        g.bench_function(format!("{name}/url_parse"), |b| {
            b.iter(|| black_box(adblock::url_parser::parse_url(black_box(url))))
        });
        g.bench_function(format!("{name}/request_new"), |b| {
            b.iter(|| black_box(adblock::request::Request::new(black_box(url), source, ty)))
        });
        let req = adblock::request::Request::new(url, source, ty).expect("request");
        g.bench_function(format!("{name}/engine_match"), |b| {
            b.iter(|| black_box(stage_engine.check_network_request(black_box(&req))))
        });
        g.bench_function(format!("{name}/check_deferred"), |b| {
            b.iter(|| black_box(shared.check_deferred(black_box(url), source, ty)))
        });
    }
    g.finish();
}

/// Loadgen's generated list (same mix), `n` rules.
fn loadgen_list(n: u64) -> String {
    fn splitmix(mut z: u64) -> u64 {
        z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    let mut s = String::from("||ads0.test^\nwww0.test##.ad-banner\n");
    for i in 0..n {
        let h = splitmix(1_000_003u64.wrapping_add(i));
        let k = h % 100;
        let id = (h >> 8) % 10_000_000;
        match k {
            0..=54 => s += &format!("||ad{id}.tracker{}.example^\n", k % 7),
            55..=74 => s += &format!("/ads{}/banner{id}*.js$script,third-party\n", k % 13),
            75..=84 => s += &format!("@@||ok{id}.example^$image\n"),
            85..=94 => s += &format!("site{}.example##.ad-{id}\n", id % 5000),
            _ => s += &format!("##.sponsored-{id}\n"),
        }
    }
    s
}

/// The engine work one rewritten HTML response does, against lists of growing size.
fn bench_html_path(c: &mut Criterion) {
    let mut g = c.benchmark_group("html_response_path");
    g.sample_size(30);
    for n in [100u64, 50_000, 500_000] {
        let engine = SharedEngine::new();
        engine.install(compile_engine(&[loadgen_list(n)]));
        let url = "https://www0.test/page.html";
        g.bench_function(format!("{n}/check_document"), |b| {
            b.iter(|| black_box(engine.check_deferred(black_box(url), url, "document")))
        });
        g.bench_function(format!("{n}/site_off"), |b| {
            b.iter(|| black_box(engine.site_off(black_box(url))))
        });
        g.bench_function(format!("{n}/csp_for"), |b| {
            b.iter(|| black_box(engine.csp_for(black_box(url), url, "document")))
        });
        g.bench_function(format!("{n}/cosmetic_for"), |b| {
            b.iter(|| black_box(engine.cosmetic_for(black_box(url))))
        });
    }
    g.finish();
}

/// A profile with an overlay: what `apply_overlay` plus the document `site_off` probes cost when
/// each layer builds its own adblock request (`separate`) versus sharing one (`shared`).
fn bench_overlay_path(c: &mut Criterion) {
    let base = SharedEngine::new();
    base.install(compile_engine(&[loadgen_list(50_000)]));
    let ov =
        filter_engine::overlay_from_rules("||overlay-ads.test^\n@@||ads0.test^$domain=ok.test\n")
            .unwrap()
            .unwrap();
    let source = "https://page.example.com/";
    let cases = [
        (
            "allowed_script",
            "https://cdn.thirdparty.test/app.js",
            "script",
        ),
        ("base_blocked_image", "https://ads0.test/pixel.gif", "image"),
        ("document", "https://www0.test/page.html", "document"),
    ];
    let mut g = c.benchmark_group("overlay_path");
    for (name, url, ty) in cases {
        let doc = ty == "document";
        g.bench_function(format!("{name}/separate"), |b| {
            b.iter(|| {
                let url = black_box(url);
                let b0 = base.check_deferred(url, source, ty);
                let o = ov.check_deferred(url, source, ty);
                let mut out = o.blocked || o.exception_rule.is_some();
                if !out && b0.blocked {
                    if let Ok(req) = adblock::request::Request::new(url, source, ty) {
                        out = ov
                            .engine()
                            .check_network_request_subset(&req, false, true)
                            .exception
                            .is_some();
                    }
                }
                let off = doc && (base.site_off(url) || ov.site_off(url));
                black_box((b0.blocked, out, off))
            })
        });
        g.bench_function(format!("{name}/shared"), |b| {
            b.iter(|| {
                let url = black_box(url);
                let q = filter_engine::Query::new(url, source, ty);
                let b0 = base.check_deferred_q(&q);
                let o = ov.check_deferred_q(&q);
                let mut out = o.blocked || o.exception_rule.is_some();
                if !out && b0.blocked {
                    if let Some(req) = q.request() {
                        out = ov
                            .engine()
                            .check_network_request_subset(req, false, true)
                            .exception
                            .is_some();
                    }
                }
                let off = doc && {
                    let probe = SharedEngine::site_probe(url);
                    base.site_off_with(&probe) || ov.site_off_with(&probe)
                };
                black_box((b0.blocked, out, off))
            })
        });
    }
    g.finish();
}

criterion_group!(
    benches,
    bench_check,
    bench_real,
    bench_html_path,
    bench_overlay_path
);
criterion_main!(benches);

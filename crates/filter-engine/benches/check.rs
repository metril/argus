//! `SharedEngine::check` against a synthetic ~50k-rule network list.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use filter_engine::{compile_engine, SharedEngine};

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

criterion_group!(benches, bench_check);
criterion_main!(benches);

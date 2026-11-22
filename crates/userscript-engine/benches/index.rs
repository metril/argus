//! `ScriptIndex::candidates` latency with 500 scripts: a host no script targets (miss, the
//! common case), a host with a few matching scripts (hit), and a wildcard-heavy worst case.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use userscript_engine::{index::ScriptIndex, matcher::Options, Userscript};

fn script(i: usize) -> Userscript {
    let hdr = match i % 5 {
        0 => format!("// @match https://site{i}.example.com/*"),
        1 => format!("// @match *://*.domain{i}.org/path/*"),
        2 => format!("// @include https://shop{i}.net/*"),
        3 => format!("// @include /^https:\\/\\/re{i}\\.test\\//"),
        _ => format!(
            "// @match https://www.site{i}.com/a/*\n// @exclude https://www.site{i}.com/a/private*"
        ),
    };
    Userscript::new(format!(
        "// ==UserScript==\n// @name s{i}\n{hdr}\n// ==/UserScript==\n"
    ))
    .unwrap()
}

fn bench(c: &mut Criterion) {
    let mut scripts: Vec<Userscript> = (0..500).map(script).collect();
    // A handful of any-host scripts, as real installs have (regex/`*` includes).
    for i in 500..505 {
        scripts.push(Userscript::new(format!("// ==UserScript==\n// @name any{i}\n// @include /youtube\\.com\\/watch/\n// ==/UserScript==\n")).unwrap());
    }
    let idx = ScriptIndex::build("default", &scripts, Options::default()).index;

    c.bench_function("candidates/miss (500 scripts)", |b| {
        b.iter(|| {
            black_box(idx.candidates(
                black_box("news.unrelated-site.org"),
                black_box("https://news.unrelated-site.org/2024/article?id=5"),
                true,
            ))
        })
    });
    c.bench_function("candidates/hit exact host", |b| {
        b.iter(|| {
            black_box(idx.candidates(
                black_box("site100.example.com"),
                black_box("https://site100.example.com/a/b?c=d"),
                true,
            ))
        })
    });
    c.bench_function("candidates/hit domain suffix", |b| {
        b.iter(|| {
            black_box(idx.candidates(
                black_box("deep.sub.domain101.org"),
                black_box("https://deep.sub.domain101.org/path/x"),
                true,
            ))
        })
    });
    c.bench_function("candidates/any-host regex hit", |b| {
        b.iter(|| {
            black_box(idx.candidates(
                black_box("www.youtube.com"),
                black_box("https://www.youtube.com/watch?v=abc"),
                true,
            ))
        })
    });
    let empty = ScriptIndex::default();
    c.bench_function("candidates/empty index", |b| {
        b.iter(|| {
            black_box(empty.candidates(black_box("a.com"), black_box("https://a.com/"), true))
        })
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);

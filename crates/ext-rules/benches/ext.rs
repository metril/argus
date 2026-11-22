//! `cargo bench -p ext-rules`: lookup on a miss / hit with 20k rules, body transform throughput.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use ext_rules::*;

fn rules(n: usize) -> Vec<ExtRule> {
    let mut v = Vec::with_capacity(n + 4);
    for i in 0..n {
        let raw = match i % 5 {
            0 => format!("||ads{i}.tracker{}.example^$method=post", i % 997),
            1 => format!("||cdn{i}.example^$removeheader=refresh"),
            2 => format!("/adserver{i}/banner$denyallow=ok{}.example,script", i % 13),
            3 => format!("||h{i}.example^$cookie=sid{i}"),
            _ => format!("site{i}.example##^script:has-text(banner{i})"),
        };
        let mut e = ExtRule::new(ExtKind::Other, &raw);
        e.trusted = true;
        v.push(e);
    }
    let mut e = ExtRule::new(ExtKind::Replace, "||hit.example^$replace=/adsbygoogle/x/i");
    e.trusted = true;
    v.push(e);
    v
}

fn bench(c: &mut Criterion) {
    let idx = ExtIndex::build(&rules(20_000));
    let miss = RequestInfo {
        source_url: Some("https://www.news.example/"),
        third_party: Some(true),
        ..RequestInfo::new(
            "https://static.cdn.unrelated.example/assets/app.min.js?v=123456",
            "GET",
            ResourceType::Script,
        )
    };
    let hit = RequestInfo {
        source_url: Some("https://www.news.example/"),
        third_party: Some(true),
        ..RequestInfo::new("https://ads0.tracker0.example/x", "POST", ResourceType::Xhr)
    };
    let hdrs = [("Content-Type", "text/html")];
    let resp = ResponseInfo {
        status: 200,
        headers: &hdrs,
    };
    let hit_doc = RequestInfo::new("https://hit.example/", "GET", ResourceType::Document);
    let mut g = c.benchmark_group("lookup_20k");
    g.bench_function("request_miss", |b| {
        b.iter(|| black_box(idx.request_decision(black_box(&miss))))
    });
    g.bench_function("request_hit", |b| {
        b.iter(|| black_box(idx.request_decision(black_box(&hit))))
    });
    g.bench_function("response_miss", |b| {
        b.iter(|| black_box(idx.response_plan(black_box(&miss), &resp)))
    });
    g.bench_function("response_hit", |b| {
        b.iter(|| black_box(idx.response_plan(black_box(&hit_doc), &resp)))
    });
    g.finish();

    let body: Vec<u8> = "<script>var adsbygoogle = [];</script><p>hello world</p>\n"
        .repeat(20_000)
        .into_bytes();
    let spec = ReplaceSpec::parse("/adsbygoogle/noads/gi").unwrap();
    let mut g = c.benchmark_group("body");
    g.throughput(Throughput::Bytes(body.len() as u64));
    g.bench_function("apply_replace", |b| {
        b.iter(|| black_box(apply_replace(black_box(&body), &spec)))
    });
    let mut json = String::from("{\"items\":[");
    for i in 0..8000 {
        json.push_str(&format!(
            "{{\"id\":{i},\"title\":\"item {i}\",\"adPlacements\":[1,2,3],\"meta\":{{\"k\":\"v\"}}}},"
        ));
    }
    json.push_str("{}]}");
    let jb = json.into_bytes();
    let jp = JsonPrune::parse("$..adPlacements").unwrap();
    g.throughput(Throughput::Bytes(jb.len() as u64));
    g.bench_function("apply_jsonprune", |b| {
        b.iter(|| black_box(apply_jsonprune(black_box(&jb), &[&jp])))
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);

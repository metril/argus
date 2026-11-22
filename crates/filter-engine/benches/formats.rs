//! Convert + dedupe + compile of a synthetic 1M-line hosts list.
//!
//! `cargo bench -p filter-engine --bench formats`; for a single timed run with peak RSS use
//! `cargo run --release -p filter-engine --example bench_1m`.

use criterion::{criterion_group, criterion_main, Criterion};
use filter_engine::{build_set, convert, ConvertOptions, ListFormat, ListInput};

pub fn synthetic_hosts(n: usize) -> String {
    let mut s = String::with_capacity(n * 32);
    s.push_str("# Title: synthetic\n127.0.0.1 localhost\n");
    for i in 0..n {
        s.push_str(&format!(
            "0.0.0.0 ad{i}.tracker{}.example{}.com\n",
            i % 997,
            i % 13
        ));
    }
    s
}

fn bench(c: &mut Criterion) {
    let hosts = synthetic_hosts(1_000_000);
    let mut g = c.benchmark_group("hosts_1m");
    g.sample_size(10);
    g.bench_function("convert", |b| {
        b.iter(|| convert(&hosts, &ConvertOptions::default()).stats.converted)
    });
    g.bench_function("convert+dedupe+compile", |b| {
        b.iter(|| {
            build_set(&[ListInput {
                id: "hosts".into(),
                content: hosts.clone(),
                format: ListFormat::Auto,
                ..Default::default()
            }])
            .blob
            .len()
        })
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);

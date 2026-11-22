//! One timed convert + dedupe + compile of a synthetic 1M-line hosts list, with peak RSS.

use std::time::Instant;

use filter_engine::{build_engine, build_set, convert, ConvertOptions, ListFormat, ListInput};

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

    let t = Instant::now();
    let built = build_set(&[ListInput {
        id: "hosts".into(),
        content: hosts,
        format: ListFormat::Auto,
        ..Default::default()
    }]);
    println!(
        "convert+dedupe+compile:     {:>8.0?}  (network={}, blob {:.1} MB)",
        t.elapsed(),
        built.reports[0].network,
        built.blob.len() as f64 / 1e6
    );

    let t = Instant::now();
    let _engine = build_engine(&built.blob, &[]);
    println!("deserialize (startup path): {:>8.0?}", t.elapsed());
    println!("peak RSS: {:.0} MB", peak_rss_mb());
}

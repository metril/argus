//! Cost of script control on the proxy path with 10,000 per-site rules.
//!
//! * `document/*`: what each HTML response pays: a cached lookup (the usual case), and a cold
//!   `decide` plus header rendering.
//! * `hint/*`: the per-request check of a third-party subresource: allow (first party), deny
//!   (blocked at the proxy, includes recording the block), unknown page, and the disabled path.
//! * `inject/*`: building the page head with and without the panel hotkey.
//! * Prints the boot script size.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hyper::header::{HeaderMap, HeaderValue};
use proxy_core::scriptctl::ScriptControl;
use script_policy::model::{ExportedSiteRule, PolicyExport};
use script_policy::store::PolicyStore;
use script_policy::{Preset, RuleSet, Scope, DEFAULT_PROFILE as P, EXPORT_VERSION};
use std::sync::Arc;

fn control(enabled: bool) -> (tempfile::TempDir, Arc<ScriptControl>) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(PolicyStore::new(common::db::Db::open(dir.path()).unwrap()));
    let mut settings = RuleSet::default().settings;
    settings.enabled = enabled;
    let doc = PolicyExport {
        version: EXPORT_VERSION,
        settings,
        site_rules: (0..10_000)
            .map(|i| ExportedSiteRule {
                scope: Scope::parse(&format!("site{i}.test")).unwrap(),
                preset: if i % 2 == 0 {
                    Preset::Untrusted
                } else {
                    Preset::Trusted
                },
                note: None,
            })
            .collect(),
        source_rules: vec![],
    };
    store.import(P, doc, true).unwrap();
    let c = ScriptControl::new(store, P);
    (dir, c)
}

fn hdr(page: &str, dest: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("sec-fetch-dest", HeaderValue::from_str(dest).unwrap());
    h.insert("sec-fetch-site", HeaderValue::from_static("cross-site"));
    h.insert(
        "referer",
        HeaderValue::from_str(&format!("https://{page}/x")).unwrap(),
    );
    h
}

fn bench(c: &mut Criterion) {
    let (_d, on) = control(true);
    let (_d2, off) = control(false);
    println!("boot.js: {} bytes", include_str!("../assets/boot.js").len());
    println!(
        "panel.js (lazy): {} bytes",
        include_str!("../assets/panel.js").len()
    );

    let mut g = c.benchmark_group("document");
    g.bench_function("cached", |b| {
        on.document("https", "site4242.test", 443);
        b.iter(|| black_box(on.document("https", black_box("site4242.test"), 443)))
    });
    let mut i = 0u32;
    g.bench_function("cold_decide_and_render", |b| {
        b.iter(|| {
            i = i.wrapping_add(1);
            // A host with no rule, never seen before: full decide + CSP render.
            black_box(on.document("https", &format!("fresh{i}.example.org"), 443))
        })
    });
    g.bench_function("disabled", |b| {
        b.iter(|| black_box(off.document("https", black_box("site4242.test"), 443)))
    });
    g.finish();

    let mut g = c.benchmark_group("hint");
    let allow = hdr("site4242.test", "script");
    let deny = hdr("fresh.example.org", "script");
    let mut unknown = hdr("fresh.example.org", "script");
    unknown.remove("referer");
    g.bench_function("allow_first_party", |b| {
        b.iter(|| black_box(on.check_request(&allow, "https", black_box("site4242.test"), 443)))
    });
    g.bench_function("allow_trusted_page", |b| {
        let h = hdr("site4243.test", "script");
        b.iter(|| black_box(on.check_request(&h, "https", black_box("cdn.example.net"), 443)))
    });
    g.bench_function("deny_third_party", |b| {
        b.iter(|| black_box(on.check_request(&deny, "https", black_box("cdn.example.net"), 443)))
    });
    g.bench_function("unknown_page", |b| {
        b.iter(|| black_box(on.check_request(&unknown, "https", black_box("cdn.example.net"), 443)))
    });
    g.bench_function("disabled", |b| {
        b.iter(|| black_box(off.check_request(&deny, "https", black_box("cdn.example.net"), 443)))
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use script_policy::*;

fn rules(n: usize) -> RuleSet {
    let mut rs = RuleSet::default();
    rs.settings.enabled = true;
    for i in 0..n {
        let id = format!("s{i}");
        let scope = if i % 4 == 0 {
            Scope::Host(format!("www.site{i}.com"))
        } else {
            Scope::Site(format!("site{i}.co.uk"))
        };
        rs.site_rules.insert(
            id.clone(),
            SiteRule {
                id,
                scope,
                preset: if i % 3 == 0 {
                    Preset::Trusted
                } else {
                    Preset::Untrusted
                },
                note: None,
            },
        );
    }
    for i in 0..(n / 10) {
        let id = format!("r{i}");
        rs.source_rules.insert(
            id.clone(),
            SourceRule {
                id,
                page: Scope::Site(format!("site{}.co.uk", i * 4 + 1)),
                source: Scope::Host(format!("cdn{i}.example.net")),
                caps: CapSet::of(&[Capability::Script]),
                effect: Effect::Allow,
                note: None,
            },
        );
    }
    rs
}

fn bench(c: &mut Criterion) {
    let p = CompiledPolicy::compile(&rules(10_000), 1, 0);
    c.bench_function("decide/default path (no rule)", |b| {
        b.iter(|| black_box(p.decide("https", black_box("news.unlisted-example.org"), None)))
    });
    c.bench_function("decide/site rule hit", |b| {
        b.iter(|| black_box(p.decide("https", black_box("a.b.site4999.co.uk"), None)))
    });
    c.bench_function("decide/host rule hit", |b| {
        b.iter(|| black_box(p.decide("https", black_box("www.site400.com"), None)))
    });
    let page = p.decide("https", "www.site5.co.uk", None);
    c.bench_function("allows/third-party script", |b| {
        b.iter(|| black_box(page.allows_host(Capability::Script, black_box("cdn1.example.net"))))
    });
    c.bench_function("csp/site with source rule", |b| {
        b.iter(|| black_box(page.csp_header(None)))
    });
    c.bench_function("compile/10k rules", |b| {
        let rs = rules(10_000);
        b.iter(|| black_box(CompiledPolicy::compile(&rs, 1, 0)))
    });
}
criterion_group!(benches, bench);
criterion_main!(benches);

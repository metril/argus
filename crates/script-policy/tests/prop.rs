//! Property: the compiled `decide` + `allows` equals a brute-force evaluation over all rules.

use proptest::prelude::*;
use script_policy::Capability as C;
use script_policy::*;

const HOSTS: [&str; 9] = [
    "a.com",
    "www.a.com",
    "b.a.com",
    "c.co.uk",
    "www.c.co.uk",
    "x.c.co.uk",
    "d.net",
    "localhost",
    "10.0.0.1",
];
const SITES: [&str; 5] = ["a.com", "c.co.uk", "d.net", "localhost", "10.0.0.1"];

fn scope_of(kind: u8, i: usize) -> Scope {
    match kind % 4 {
        0 => Scope::Global,
        1 => Scope::Site(SITES[i % SITES.len()].into()),
        2 => Scope::Host(HOSTS[i % HOSTS.len()].into()),
        _ => Scope::HostScheme(
            if i.is_multiple_of(2) {
                Scheme::Http
            } else {
                Scheme::Https
            },
            HOSTS[i % HOSTS.len()].into(),
        ),
    }
}

fn preset_of(k: u8) -> Preset {
    match k % 4 {
        0 => Preset::Default,
        1 => Preset::Trusted,
        2 => Preset::Untrusted,
        _ => Preset::Custom {
            profile: Profile {
                page: CapSet::of(&[C::InlineScript]),
                first_party: CapSet::of(&[C::Script, C::Image]),
                third_party: CapSet::of(&[C::Image, C::Font]),
            },
        },
    }
}

const CAPS: [C; 4] = [C::Script, C::Image, C::Font, C::InlineScript];

#[derive(Debug, Clone)]
struct Spec {
    site: Vec<(u8, usize, u8)>,
    src: Vec<(u8, usize, u8, usize, u8, bool)>,
    temp: Vec<(u8, usize, u8, usize, u8, bool, u64)>,
    global: u8,
}

fn build(sp: &Spec) -> RuleSet {
    let mut rs = RuleSet::default();
    rs.settings.enabled = true;
    rs.settings.global = preset_of(sp.global);
    for (n, (k, i, p)) in sp.site.iter().enumerate() {
        let scope = scope_of(*k, *i);
        if scope == Scope::Global {
            continue;
        }
        let id = format!("s{n}");
        rs.site_rules.insert(
            id.clone(),
            SiteRule {
                id,
                scope,
                preset: preset_of(*p),
                note: None,
                updated_at: 0,
            },
        );
    }
    for (n, (pk, pi, sk, si, cap, deny)) in sp.src.iter().enumerate() {
        let id = format!("r{n}");
        rs.source_rules.insert(
            id.clone(),
            SourceRule {
                id,
                page: scope_of(*pk, *pi),
                source: scope_of(*sk, *si),
                caps: CapSet::of(&[CAPS[*cap as usize % 3]]),
                effect: if *deny { Effect::Deny } else { Effect::Allow },
                note: None,
            },
        );
    }
    for (n, (pk, pi, sk, si, p, is_site, exp)) in sp.temp.iter().enumerate() {
        let id = format!("t{n}");
        rs.temps.insert(
            id.clone(),
            TempGrant {
                id,
                page: scope_of(*pk, *pi),
                kind: if *is_site {
                    GrantKind::Site {
                        preset: preset_of(*p),
                    }
                } else {
                    GrantKind::Source {
                        source: scope_of(*sk, *si),
                        caps: CapSet::of(&[CAPS[*p as usize % 3]]),
                    }
                },
                expires_at: Some(*exp),
                until_restart: false,
                persist: false,
                created_at: n as u64,
            },
        );
    }
    rs
}

fn host_site(h: &str) -> &str {
    SITES
        .iter()
        .find(|s| h == **s || h.ends_with(&format!(".{s}")))
        .copied()
        .unwrap()
}

fn matches(sc: &Scope, scheme: Option<Scheme>, host: &str) -> bool {
    match sc {
        Scope::Global => true,
        Scope::Site(s) => host_site(host) == s,
        Scope::Host(h) => h == host,
        Scope::HostScheme(x, h) => Some(*x) == scheme && h == host,
    }
}

fn ref_profile(rs: &RuleSet, now: u64, scheme: Scheme, host: &str) -> Profile {
    // (specificity, is_temp, created_at) -> profile
    let mut best: (i32, bool, u64, Profile) =
        (0, false, 0, rs.settings.global.resolve(&rs.settings));
    let mut consider = |spec: i32, temp: bool, at: u64, p: Profile| {
        if (spec, temp, at) >= (best.0, best.1, best.2) {
            best = (spec, temp, at, p);
        }
    };
    for r in rs.site_rules.values() {
        if matches(&r.scope, Some(scheme), host) {
            consider(
                r.scope.specificity() as i32,
                false,
                0,
                r.preset.resolve(&rs.settings),
            );
        }
    }
    for t in rs.temps.values() {
        if let GrantKind::Site { preset } = &t.kind {
            if t.active_at(now) && matches(&t.page, Some(scheme), host) {
                consider(
                    t.page.specificity() as i32,
                    true,
                    t.created_at + 1,
                    preset.resolve(&rs.settings),
                );
            }
        }
    }
    best.3
}

fn ref_allows(
    rs: &RuleSet,
    now: u64,
    scheme: Scheme,
    host: &str,
    cap: Capability,
    src_scheme: Option<Scheme>,
    src: &str,
) -> bool {
    let prof = ref_profile(rs, now, scheme, host);
    if !cap.is_source_keyed() {
        return prof.page.contains(cap);
    }
    let mut best: Option<((u8, u8, u8, u8), bool)> = None;
    let mut consider = |page: &Scope, source: &Scope, caps: CapSet, deny: bool, temp: bool| {
        if caps.contains(cap)
            && matches(page, Some(scheme), host)
            && matches(source, src_scheme, src)
        {
            let key = (
                page.specificity(),
                source.specificity(),
                temp as u8,
                deny as u8,
            );
            if best.is_none_or(|b| key > b.0) {
                best = Some((key, deny));
            }
        }
    };
    for r in rs.source_rules.values() {
        consider(&r.page, &r.source, r.caps, r.effect == Effect::Deny, false);
    }
    for t in rs.temps.values() {
        if let GrantKind::Source { source, caps } = &t.kind {
            if t.active_at(now) {
                consider(&t.page, source, *caps, false, true);
            }
        }
    }
    match best {
        Some((_, deny)) => !deny,
        None => prof.allows_source(cap, host_site(host) == host_site(src)),
    }
}

fn spec_strategy() -> impl Strategy<Value = Spec> {
    (
        prop::collection::vec((0u8..4, 0usize..9, 0u8..4), 0..12),
        prop::collection::vec(
            (0u8..4, 0usize..9, 0u8..4, 0usize..9, 0u8..3, any::<bool>()),
            0..16,
        ),
        prop::collection::vec(
            (
                0u8..4,
                0usize..9,
                0u8..4,
                0usize..9,
                0u8..4,
                any::<bool>(),
                0u64..40,
            ),
            0..6,
        ),
        0u8..4,
    )
        .prop_map(|(site, src, temp, global)| Spec {
            site,
            src,
            temp,
            global,
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]
    #[test]
    fn decide_matches_brute_force(sp in spec_strategy(), now in 0u64..40) {
        let rs = build(&sp);
        let c = CompiledPolicy::compile(&rs, 1, now);
        for host in HOSTS {
            for scheme in [Scheme::Http, Scheme::Https] {
                let page = c.decide(scheme.as_str(), host, None);
                prop_assert_eq!(
                    page.profile(),
                    ref_profile(&rs, now, scheme, host),
                    "profile for {}://{}", scheme.as_str(), host
                );
                for src in HOSTS {
                    for src_scheme in [None, Some(Scheme::Https)] {
                        for cap in CAPS {
                            let got = page.allows(cap, Source { scheme: src_scheme, host: src });
                            let want = ref_allows(&rs, now, scheme, host, cap, src_scheme, src);
                            prop_assert_eq!(got, want,
                                "{}://{} {:?} from {:?}://{}", scheme.as_str(), host, cap, src_scheme, src);
                        }
                    }
                }
            }
        }
    }
}

#![allow(dead_code)]
use script_policy::*;

pub fn rs() -> RuleSet {
    let mut r = RuleSet::default();
    r.settings.enabled = true;
    r
}

pub fn scope(s: &str) -> Scope {
    Scope::parse(s).unwrap()
}

pub fn site_rule(r: &mut RuleSet, id: &str, sc: &str, preset: Preset) {
    r.site_rules.insert(
        id.into(),
        SiteRule {
            id: id.into(),
            scope: scope(sc),
            preset,
            note: None,
            updated_at: 0,
        },
    );
}

pub fn src_rule(
    r: &mut RuleSet,
    id: &str,
    page: &str,
    source: &str,
    caps: &[Capability],
    e: Effect,
) {
    r.source_rules.insert(
        id.into(),
        SourceRule {
            id: id.into(),
            page: scope(page),
            source: scope(source),
            caps: CapSet::of(caps),
            effect: e,
            note: None,
        },
    );
}

pub fn compile(r: &RuleSet) -> CompiledPolicy {
    CompiledPolicy::compile(r, 1, 1000)
}

pub fn custom(page: &[Capability], first: &[Capability], third: &[Capability]) -> Preset {
    Preset::Custom {
        profile: Profile {
            page: CapSet::of(page),
            first_party: CapSet::of(first),
            third_party: CapSet::of(third),
        },
    }
}

pub const PX: ProxyInject<'static> = ProxyInject {
    nonce: Some("N0nce"),
    path: Some("/__adblock__/"),
};

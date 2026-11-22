//! `CompiledPolicy`: the immutable, shareable lookup structure, and `decide`.

use crate::caps::{Capability, Profile};
use crate::model::{Effect, GrantKind, RuleSet, Settings};
use crate::scope::{site_of, Scheme, Scope};
use rustc_hash::FxHashMap;

/// A source rule, reduced to what evaluation needs.
#[derive(Clone, Debug)]
pub(crate) struct CRule {
    pub source: Scope,
    pub scheme: Option<Scheme>,
    pub caps: crate::caps::CapSet,
    pub deny: bool,
    /// `source specificity * 4 + temp * 2 + deny`; combined with the page level in [`rank`].
    pub low: u8,
}

/// Rank of a rule found at page level `level` (0 global .. 3 host+scheme): page specificity,
/// then source specificity, then temporary over permanent, then deny over allow.
pub(crate) fn rank(level: usize, r: &CRule) -> u8 {
    ((level as u8) << 4) | r.low
}

#[derive(Default, Debug)]
pub(crate) struct RuleIndex {
    /// Source scope `*`.
    pub any: Vec<CRule>,
    /// Keyed by the source site.
    pub site: FxHashMap<Box<str>, Vec<CRule>>,
    /// Keyed by the source host (host and host+scheme scopes).
    pub host: FxHashMap<Box<str>, Vec<CRule>>,
}

impl RuleIndex {
    fn insert(&mut self, r: CRule) {
        match &r.source {
            Scope::Global => self.any.push(r),
            Scope::Site(s) => self.site.entry(s.as_str().into()).or_default().push(r),
            Scope::Host(h) | Scope::HostScheme(_, h) => {
                self.host.entry(h.as_str().into()).or_default().push(r)
            }
        }
    }

    pub fn matching<'a>(
        &'a self,
        src: Source<'a>,
        src_site: &'a str,
    ) -> impl Iterator<Item = &'a CRule> + 'a {
        self.any
            .iter()
            .chain(self.site.get(src_site).into_iter().flatten())
            .chain(
                self.host
                    .get(src.host)
                    .into_iter()
                    .flatten()
                    .filter(move |r| r.scheme.is_none() || r.scheme == src.scheme),
            )
    }

    pub fn all(&self) -> impl Iterator<Item = &CRule> {
        self.any
            .iter()
            .chain(self.site.values().flatten())
            .chain(self.host.values().flatten())
    }
}

#[derive(Default, Debug)]
pub(crate) struct PageEntry {
    pub profile: Option<Profile>,
    pub rules: RuleIndex,
}

#[derive(Default, Debug)]
struct HostEntry {
    any: PageEntry,
    http: Option<PageEntry>,
    https: Option<PageEntry>,
}

/// A request/resource source: scheme (when known) and normalised host.
#[derive(Clone, Copy, Debug)]
pub struct Source<'a> {
    pub scheme: Option<Scheme>,
    pub host: &'a str,
}

/// Immutable compiled policy of one profile. `Send + Sync`; share in an `Arc`.
#[derive(Debug)]
pub struct CompiledPolicy {
    generation: u64,
    valid_until: Option<u64>,
    settings: Settings,
    global: PageEntry,
    sites: FxHashMap<Box<str>, PageEntry>,
    hosts: FxHashMap<Box<str>, HostEntry>,
}

impl CompiledPolicy {
    /// A policy that applies nothing.
    pub fn disabled() -> Self {
        Self::compile(&RuleSet::default(), 0, 0)
    }

    /// Compile `rules` as of `now` (unix seconds). Temporary grants that are inactive at `now`
    /// are ignored; rebuild at [`CompiledPolicy::valid_until`]. `generation` is the caller's
    /// change counter, exposed through [`CompiledPolicy::generation`] for cache keys.
    pub fn compile(rules: &RuleSet, generation: u64, now: u64) -> Self {
        let mut p = CompiledPolicy {
            generation,
            valid_until: None,
            settings: rules.settings.clone(),
            global: PageEntry {
                profile: Some(rules.settings.global.resolve(&rules.settings)),
                rules: RuleIndex::default(),
            },
            sites: FxHashMap::default(),
            hosts: FxHashMap::default(),
        };
        for r in rules.site_rules.values() {
            let prof = r.preset.resolve(&rules.settings);
            p.entry_mut(&r.scope).profile = Some(prof);
        }
        let mut temps: Vec<_> = rules.temps.values().filter(|t| t.active_at(now)).collect();
        temps.sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
        for t in temps {
            if let Some(e) = t.expires_at {
                p.valid_until = Some(p.valid_until.map_or(e, |v| v.min(e)));
            }
            match &t.kind {
                GrantKind::Site { preset } => {
                    p.entry_mut(&t.page).profile = Some(preset.resolve(&rules.settings));
                }
                GrantKind::Source { source, caps } => {
                    p.entry_mut(&t.page)
                        .rules
                        .insert(crule(source, *caps, Effect::Allow, true));
                }
            }
        }
        for r in rules.source_rules.values() {
            p.entry_mut(&r.page)
                .rules
                .insert(crule(&r.source, r.caps, r.effect, false));
        }
        p
    }

    fn entry_mut(&mut self, scope: &Scope) -> &mut PageEntry {
        match scope {
            Scope::Global => &mut self.global,
            Scope::Site(s) => self.sites.entry(s.as_str().into()).or_default(),
            Scope::Host(h) => &mut self.hosts.entry(h.as_str().into()).or_default().any,
            Scope::HostScheme(sc, h) => {
                let he = self.hosts.entry(h.as_str().into()).or_default();
                match sc {
                    Scheme::Http => he.http.get_or_insert_with(Default::default),
                    Scheme::Https => he.https.get_or_insert_with(Default::default),
                }
            }
        }
    }

    /// The caller's generation counter value this was compiled for.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Unix second at which a temporary grant expires and the policy must be recompiled.
    pub fn valid_until(&self) -> Option<u64> {
        self.valid_until
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    pub fn is_enabled(&self) -> bool {
        self.settings.enabled
    }

    /// Resolve the policy for a document. `host` must be normalised (lowercase, punycode, no
    /// trailing dot; IPv6 bracketed). No allocation: a few hash probes and a public-suffix walk.
    pub fn decide<'a>(&'a self, scheme: &str, host: &'a str, port: Option<u16>) -> PagePolicy<'a> {
        let scheme = Scheme::parse(scheme);
        let site = site_of(host);
        let he = self.hosts.get(host);
        let levels = [
            Some(&self.global),
            self.sites.get(site),
            he.map(|h| &h.any),
            he.and_then(|h| match scheme {
                Some(Scheme::Http) => h.http.as_ref(),
                Some(Scheme::Https) => h.https.as_ref(),
                None => None,
            }),
        ];
        let profile = levels
            .iter()
            .rev()
            .flatten()
            .find_map(|e| e.profile)
            .unwrap_or(Profile::SHIPPED_DEFAULT);
        PagePolicy {
            c: self,
            scheme,
            host,
            site,
            port,
            levels,
            profile,
            active: self.settings.enabled,
        }
    }
}

fn crule(source: &Scope, caps: crate::caps::CapSet, effect: Effect, temp: bool) -> CRule {
    let deny = effect == Effect::Deny;
    CRule {
        source: source.clone(),
        scheme: match source {
            Scope::HostScheme(s, _) => Some(*s),
            _ => None,
        },
        caps,
        deny,
        low: source.specificity() * 4 + (temp as u8) * 2 + deny as u8,
    }
}

/// The policy for one document. Borrows the compiled policy and the caller's host string.
#[derive(Clone, Copy, Debug)]
pub struct PagePolicy<'a> {
    pub(crate) c: &'a CompiledPolicy,
    pub(crate) scheme: Option<Scheme>,
    pub(crate) host: &'a str,
    pub(crate) site: &'a str,
    pub(crate) port: Option<u16>,
    pub(crate) levels: [Option<&'a PageEntry>; 4],
    pub(crate) profile: Profile,
    pub(crate) active: bool,
}

impl<'a> PagePolicy<'a> {
    /// False when the master switch is off: nothing is enforced.
    pub fn is_active(&self) -> bool {
        self.active
    }
    /// The effective base profile (site rule or global default), before source rules.
    pub fn profile(&self) -> Profile {
        self.profile
    }
    pub fn host(&self) -> &'a str {
        self.host
    }
    pub fn site(&self) -> &'a str {
        self.site
    }
    pub fn scheme(&self) -> Option<Scheme> {
        self.scheme
    }
    pub fn settings(&self) -> &'a Settings {
        &self.c.settings
    }

    /// Cheap cache key for per-document results: `(generation, scheme, host)`.
    pub fn cache_key(&self) -> (u64, Option<Scheme>, &'a str) {
        (self.c.generation, self.scheme, self.host)
    }

    /// Is `host` first party for this page (same registrable domain; same host for IPs and
    /// names with no registrable domain)?
    pub fn is_first_party(&self, host: &str) -> bool {
        site_of(host) == self.site
    }

    /// Page-level capability (inline script, eval, wasm, inline style, noscript, features).
    pub fn allows_page(&self, cap: Capability) -> bool {
        !self.active || self.profile.page.contains(cap)
    }

    /// May the page use `cap` with the source `src`? Page-level capabilities ignore `src`.
    pub fn allows(&self, cap: Capability, src: Source<'_>) -> bool {
        if !self.active {
            return true;
        }
        if !cap.is_source_keyed() {
            return self.profile.page.contains(cap);
        }
        let ssite = site_of(src.host);
        let mut best: Option<(u8, bool)> = None;
        for (lvl, e) in self.levels.iter().enumerate() {
            let Some(e) = e else { continue };
            for r in e.rules.matching(src, ssite) {
                if r.caps.contains(cap) {
                    let rk = rank(lvl, r);
                    if best.is_none_or(|b| rk > b.0) {
                        best = Some((rk, r.deny));
                    }
                }
            }
        }
        match best {
            Some((_, deny)) => !deny,
            None => self.profile.allows_source(cap, ssite == self.site),
        }
    }

    /// [`PagePolicy::allows`] with an unknown source scheme.
    pub fn allows_host(&self, cap: Capability, host: &str) -> bool {
        self.allows(cap, Source { scheme: None, host })
    }

    /// Every source rule that applies to this page and mentions `cap`, with its rank.
    pub(crate) fn rules_for(&self, cap: Capability) -> Vec<(u8, &'a CRule)> {
        let mut out = Vec::new();
        for (lvl, e) in self.levels.iter().enumerate() {
            if let Some(e) = e {
                for r in e.rules.all().filter(|r| r.caps.contains(cap)) {
                    out.push((rank(lvl, r), r));
                }
            }
        }
        out
    }
}

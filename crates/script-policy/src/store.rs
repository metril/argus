//! redb persistence for per-profile policy rules (feature `store`).
//!
//! Reads (`snapshot`) never wait for a write: compiled policies are published through a
//! read-mostly map and only rebuilt on a change or when a temporary grant expires. Every change
//! bumps the profile's generation counter, persisted with the rules in the same transaction.

use crate::caps::CapSet;
use crate::compile::CompiledPolicy;
use crate::model::{
    Effect, GrantKind, PolicyExport, Preset, RuleError, RuleSet, Settings, SiteRule, SourceRule,
    TempGrant,
};
use crate::panel::PanelSettings;
use crate::report::{BlockEvent, CspViolation, PageReport, ReportAggregator};
use crate::scope::Scope;
use common::db::redb::Durability;
use common::db::{tables, Db, DbError};
use parking_lot::{Mutex, RwLock};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

/// Seconds since the unix epoch; injectable for tests.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Callback run after a committed change, with the profile name.
type Listener = Arc<dyn Fn(&str) + Send + Sync>;

pub fn system_clock() -> Clock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    })
}

#[derive(Debug)]
pub enum StoreError {
    Db(DbError),
    Rule(RuleError),
    Conflict(String),
    NotFound(String),
    Corrupt(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Db(e) => write!(f, "{e}"),
            StoreError::Rule(e) => write!(f, "{e}"),
            StoreError::Conflict(m) | StoreError::NotFound(m) | StoreError::Corrupt(m) => {
                f.write_str(m)
            }
        }
    }
}
impl std::error::Error for StoreError {}
impl From<DbError> for StoreError {
    fn from(e: DbError) -> Self {
        StoreError::Db(e)
    }
}
impl From<RuleError> for StoreError {
    fn from(e: RuleError) -> Self {
        StoreError::Rule(e)
    }
}
macro_rules! from_redb {
    ($($t:ty),*) => {$(impl From<$t> for StoreError {
        fn from(e: $t) -> Self { StoreError::Db(DbError::from(e)) }
    })*};
}
from_redb!(common::db::redb::TableError, common::db::redb::StorageError);

const PINLOCK_PREFIX: &str = "pinlock\0";
/// Failures are forgotten after this long without a new one.
const PIN_LOCK_DECAY: u64 = 24 * 3600;
const PIN_LOCK_MAX_ENTRIES: usize = 4096;

/// Failed-PIN counter and the time it is locked until (unix seconds).
#[derive(Clone, Copy, Default, serde::Serialize, serde::Deserialize)]
struct PinLock {
    fails: u32,
    last: u64,
    until: u64,
}

fn key(profile: &str, id: &str) -> String {
    format!("{profile}\0{id}")
}

struct ProfileState {
    rules: RuleSet,
    generation: u64,
}

/// Per-profile rule storage + compiled snapshots + the blocked-sources report.
pub struct PolicyStore {
    db: Arc<Db>,
    clock: Clock,
    /// Serialises writers and slow-path rebuilds; never held by `snapshot`'s fast path.
    state: Mutex<HashMap<String, ProfileState>>,
    published: RwLock<HashMap<String, Arc<CompiledPolicy>>>,
    /// Blocked-source reports, one aggregator per profile.
    reports: Mutex<HashMap<String, ReportAggregator>>,
    /// Called with the profile name after every committed change (rules, panel settings).
    listeners: RwLock<Vec<Listener>>,
}

impl PolicyStore {
    pub fn new(db: Arc<Db>) -> Self {
        Self::with_clock(db, system_clock())
    }

    pub fn with_clock(db: Arc<Db>, clock: Clock) -> Self {
        PolicyStore {
            db,
            clock,
            state: Mutex::new(HashMap::new()),
            published: RwLock::new(HashMap::new()),
            reports: Mutex::new(HashMap::new()),
            listeners: RwLock::new(Vec::new()),
        }
    }

    pub fn now(&self) -> u64 {
        (self.clock)()
    }

    /// The compiled policy of `profile`, rebuilt when a temporary grant has expired.
    pub fn snapshot(&self, profile: &str) -> Result<Arc<CompiledPolicy>, StoreError> {
        let now = self.now();
        if let Some(c) = self.published.read().get(profile) {
            if c.valid_until().is_none_or(|v| now < v) {
                return Ok(c.clone());
            }
        }
        let mut st = self.state.lock();
        self.ensure_loaded(&mut st, profile, now)?;
        let ps = st.get_mut(profile).expect("loaded");
        // Another thread may have refreshed it while we waited.
        if let Some(c) = self.published.read().get(profile) {
            if c.valid_until().is_none_or(|v| now < v) {
                return Ok(c.clone());
            }
        }
        ps.generation += 1;
        let c = Arc::new(CompiledPolicy::compile(&ps.rules, ps.generation, now));
        self.published.write().insert(profile.into(), c.clone());
        Ok(c)
    }

    /// Current generation counter (changes on every edit and on grant expiry).
    pub fn generation(&self, profile: &str) -> Result<u64, StoreError> {
        Ok(self.snapshot(profile)?.generation())
    }

    /// A copy of the editable rules (expired temporary grants removed).
    pub fn rules(&self, profile: &str) -> Result<RuleSet, StoreError> {
        let now = self.now();
        let mut st = self.state.lock();
        self.ensure_loaded(&mut st, profile, now)?;
        let mut r = st[profile].rules.clone();
        r.prune_temps(now);
        Ok(r)
    }

    fn ensure_loaded(
        &self,
        st: &mut HashMap<String, ProfileState>,
        profile: &str,
        now: u64,
    ) -> Result<(), StoreError> {
        if st.contains_key(profile) {
            return Ok(());
        }
        let loaded = self.load(profile, now)?;
        st.insert(profile.to_string(), loaded);
        Ok(())
    }

    fn load(&self, profile: &str, now: u64) -> Result<ProfileState, StoreError> {
        let prefix = format!("{profile}\0");
        let end = format!("{profile}\u{1}");
        self.db.read(|txn| {
            let mut rules = RuleSet::default();
            let meta = txn.open_table(tables::POLICY_META)?;
            if let Some(v) = meta.get(key(profile, "settings").as_str())? {
                rules.settings = serde_json::from_slice::<Settings>(v.value())
                    .map_err(|e| StoreError::Corrupt(format!("policy settings: {e}")))?;
            }
            let generation = meta
                .get(key(profile, "generation").as_str())?
                .and_then(|v| <[u8; 8]>::try_from(v.value()).ok())
                .map_or(0, u64::from_be_bytes);
            fn scan<T: serde::de::DeserializeOwned>(
                txn: &common::db::redb::ReadTransaction,
                def: common::db::redb::TableDefinition<&str, &[u8]>,
                prefix: &str,
                end: &str,
            ) -> Result<Vec<T>, StoreError> {
                let t = txn.open_table(def)?;
                let mut out = Vec::new();
                for row in t.range(prefix..end)? {
                    let (_, v) = row?;
                    out.push(
                        serde_json::from_slice(v.value())
                            .map_err(|e| StoreError::Corrupt(format!("policy row: {e}")))?,
                    );
                }
                Ok(out)
            }
            for r in scan::<SiteRule>(txn, tables::POLICY_SITE_RULES, &prefix, &end)? {
                rules.site_rules.insert(r.id.clone(), r);
            }
            for r in scan::<SourceRule>(txn, tables::POLICY_SOURCE_RULES, &prefix, &end)? {
                rules.source_rules.insert(r.id.clone(), r);
            }
            for t in scan::<TempGrant>(txn, tables::POLICY_TEMP, &prefix, &end)? {
                if t.active_at(now) {
                    rules.temps.insert(t.id.clone(), t);
                }
            }
            Ok(ProfileState { rules, generation })
        })
    }

    /// Apply `f` to a copy of the rules; on success persist the difference (one immediate
    /// transaction), bump the generation and publish a fresh snapshot. Blocks for the fsync:
    /// call from `spawn_blocking` on async threads.
    pub fn mutate<R>(
        &self,
        profile: &str,
        f: impl FnOnce(&mut RuleSet, u64) -> Result<R, StoreError>,
    ) -> Result<R, StoreError> {
        let now = self.now();
        let mut st = self.state.lock();
        self.ensure_loaded(&mut st, profile, now)?;
        let ps = st.get_mut(profile).expect("loaded");
        let old = ps.rules.clone();
        let mut new = ps.rules.clone();
        new.prune_temps(now);
        let out = f(&mut new, now)?;
        let generation = ps.generation + 1;
        self.db.write(Durability::Immediate, |txn| {
            persist_diff(txn, profile, &old, &new, generation)
        })?;
        ps.rules = new;
        ps.generation = generation;
        let compiled = Arc::new(CompiledPolicy::compile(&ps.rules, generation, now));
        self.published.write().insert(profile.into(), compiled);
        drop(st);
        self.notify(profile);
        Ok(out)
    }

    /// Remove everything stored for a deleted profile: site and source rules, temporary grants,
    /// settings, panel settings and PIN, PIN lockout state, and the in-memory snapshot and
    /// blocked-source report. A profile created later under the same name starts empty. The
    /// default profile is refused. Blocks for the fsync: call from `spawn_blocking`.
    pub fn delete_profile(&self, profile: &str) -> Result<(), StoreError> {
        if profile == crate::DEFAULT_PROFILE {
            return Err(StoreError::Conflict(
                "the default profile's policy cannot be deleted".into(),
            ));
        }
        use common::db::redb::ReadableTable as _;
        let mut st = self.state.lock();
        let (lo, hi) = (format!("{profile}\0"), format!("{profile}\u{1}"));
        let (plo, phi) = (
            format!("{PINLOCK_PREFIX}{profile}\0"),
            format!("{PINLOCK_PREFIX}{profile}\u{1}"),
        );
        self.db.write(Durability::Immediate, |txn| {
            for (def, meta) in [
                (tables::POLICY_SITE_RULES, false),
                (tables::POLICY_SOURCE_RULES, false),
                (tables::POLICY_TEMP, false),
                (tables::POLICY_META, true),
            ] {
                let mut t = txn.open_table(def)?;
                let mut keys: Vec<String> = Vec::new();
                let ranges: &[(&str, &str)] = if meta {
                    &[(&lo, &hi), (&plo, &phi)]
                } else {
                    &[(&lo, &hi)]
                };
                for (a, b) in ranges {
                    for row in t.range(*a..*b)? {
                        keys.push(row?.0.value().to_string());
                    }
                }
                for k in keys {
                    t.remove(k.as_str())?;
                }
            }
            Ok::<_, StoreError>(())
        })?;
        st.remove(profile);
        self.published.write().remove(profile);
        self.reports.lock().remove(profile);
        drop(st);
        self.notify(profile);
        Ok(())
    }

    /// Register a callback run (on the writer's thread) after every committed change.
    pub fn on_change(&self, f: impl Fn(&str) + Send + Sync + 'static) {
        self.listeners.write().push(Arc::new(f));
    }

    fn notify(&self, profile: &str) {
        let ls: Vec<_> = self.listeners.read().clone();
        for l in ls {
            l(profile);
        }
    }

    /// Panel settings of `profile` (defaults when never set).
    pub fn panel_settings(&self, profile: &str) -> Result<PanelSettings, StoreError> {
        self.db.read(|txn| {
            let meta = txn.open_table(tables::POLICY_META)?;
            Ok(match meta.get(key(profile, "panel").as_str())? {
                Some(v) => serde_json::from_slice(v.value())
                    .map_err(|e| StoreError::Corrupt(format!("panel settings: {e}")))?,
                None => PanelSettings::default(),
            })
        })
    }

    pub fn set_panel_settings(&self, profile: &str, p: &PanelSettings) -> Result<(), StoreError> {
        let bytes = serde_json::to_vec(p).map_err(|e| StoreError::Corrupt(e.to_string()))?;
        self.db.write(Durability::Immediate, |txn| {
            let mut meta = txn.open_table(tables::POLICY_META)?;
            meta.insert(key(profile, "panel").as_str(), bytes.as_slice())?;
            Ok::<_, StoreError>(())
        })?;
        self.notify(profile);
        Ok(())
    }

    // ---- PIN lockout (persisted so a restart does not reset it) ----

    fn lock_key(profile: &str, who: &str) -> String {
        format!("{PINLOCK_PREFIX}{profile}\0{who}")
    }

    fn lock_get(
        meta: &impl common::db::redb::ReadableTable<&'static str, &'static [u8]>,
        k: &str,
        now: u64,
    ) -> Result<PinLock, StoreError> {
        let l: PinLock = match meta.get(k)? {
            Some(v) => serde_json::from_slice(v.value()).unwrap_or_default(),
            None => PinLock::default(),
        };
        // Old failures are forgotten.
        Ok(if now.saturating_sub(l.last) > PIN_LOCK_DECAY {
            PinLock::default()
        } else {
            l
        })
    }

    /// Seconds a PIN attempt from `ip` on `profile` must still wait (0 = may try), from both the
    /// per-client and the per-profile backoff.
    pub fn pin_wait(&self, profile: &str, ip: &str) -> Result<u64, StoreError> {
        let now = self.now();
        self.db.read(|txn| {
            let meta = txn.open_table(tables::POLICY_META)?;
            let mut wait = 0;
            for who in [format!("ip:{ip}"), "*".to_string()] {
                let l = Self::lock_get(&meta, &Self::lock_key(profile, &who), now)?;
                wait = wait.max(l.until.saturating_sub(now));
            }
            Ok(wait)
        })
    }

    /// Record a wrong PIN from `ip`: bumps the per-client and the per-profile counters.
    pub fn pin_failed(&self, profile: &str, ip: &str) -> Result<(), StoreError> {
        use crate::panel::backoff_secs;
        use common::db::redb::ReadableTable as _;
        let now = self.now();
        self.db.write(Durability::Immediate, |txn| {
            let mut meta = txn.open_table(tables::POLICY_META)?;
            // Bounded: forget stale per-client entries; past the cap only the profile counter grows.
            let lo = format!("{PINLOCK_PREFIX}{profile}\0");
            let hi = format!("{PINLOCK_PREFIX}{profile}\u{1}");
            let mut stale = Vec::new();
            let mut n = 0usize;
            for e in meta.range(lo.as_str()..hi.as_str())? {
                let (k, v) = e?;
                n += 1;
                let l: PinLock = serde_json::from_slice(v.value()).unwrap_or_default();
                if now.saturating_sub(l.last) > PIN_LOCK_DECAY {
                    stale.push(k.value().to_string());
                }
            }
            for k in &stale {
                meta.remove(k.as_str())?;
            }
            n -= stale.len();
            for (who, free, max) in [(format!("ip:{ip}"), 5, 3600), ("*".to_string(), 15, 3600)] {
                let k = Self::lock_key(profile, &who);
                if who != "*" && n >= PIN_LOCK_MAX_ENTRIES && meta.get(k.as_str())?.is_none() {
                    continue;
                }
                let mut l = Self::lock_get(&meta, &k, now)?;
                l.fails += 1;
                l.last = now;
                l.until = now + backoff_secs(l.fails, free, 30, max);
                let bytes =
                    serde_json::to_vec(&l).map_err(|e| StoreError::Corrupt(e.to_string()))?;
                meta.insert(k.as_str(), bytes.as_slice())?;
            }
            Ok::<_, StoreError>(())
        })
    }

    /// A correct PIN clears the client's counter (and the profile's).
    pub fn pin_ok(&self, profile: &str, ip: &str) -> Result<(), StoreError> {
        self.db.write(Durability::Immediate, |txn| {
            let mut meta = txn.open_table(tables::POLICY_META)?;
            for who in [format!("ip:{ip}"), "*".to_string()] {
                meta.remove(Self::lock_key(profile, &who).as_str())?;
            }
            Ok::<_, StoreError>(())
        })
    }

    // ---- convenience edits (each is one `mutate`) ----

    pub fn set_settings(&self, profile: &str, s: Settings) -> Result<(), StoreError> {
        self.mutate(profile, |r, _| {
            r.settings = s;
            Ok(())
        })
    }

    pub fn create_site_rule(
        &self,
        profile: &str,
        scope: Scope,
        preset: Preset,
        note: Option<String>,
    ) -> Result<SiteRule, StoreError> {
        self.mutate(profile, |r, _| {
            let rule = SiteRule {
                id: new_id(),
                scope,
                preset,
                note,
            };
            rule.validate()?;
            if r.site_rule_for_scope(&rule.scope).is_some() {
                return Err(StoreError::Conflict(format!(
                    "a site rule for {} already exists",
                    rule.scope
                )));
            }
            r.site_rules.insert(rule.id.clone(), rule.clone());
            Ok(rule)
        })
    }

    pub fn update_site_rule(
        &self,
        profile: &str,
        id: &str,
        preset: Preset,
        note: Option<String>,
    ) -> Result<SiteRule, StoreError> {
        self.mutate(profile, |r, _| {
            let rule = r
                .site_rules
                .get_mut(id)
                .ok_or_else(|| StoreError::NotFound(format!("site rule {id} not found")))?;
            rule.preset = preset;
            rule.note = note;
            Ok(rule.clone())
        })
    }

    pub fn delete_site_rule(&self, profile: &str, id: &str) -> Result<(), StoreError> {
        self.mutate(profile, |r, _| {
            r.site_rules
                .remove(id)
                .map(|_| ())
                .ok_or_else(|| StoreError::NotFound(format!("site rule {id} not found")))
        })
    }

    pub fn create_source_rule(
        &self,
        profile: &str,
        page: Scope,
        source: Scope,
        caps: CapSet,
        effect: Effect,
        note: Option<String>,
    ) -> Result<SourceRule, StoreError> {
        self.mutate(profile, |r, _| {
            let rule = SourceRule {
                id: new_id(),
                page,
                source,
                caps,
                effect,
                note,
            };
            rule.validate()?;
            if r.source_rule_for(&rule.page, &rule.source, rule.effect)
                .is_some()
            {
                return Err(StoreError::Conflict(format!(
                    "a {:?} rule for {} on {} already exists",
                    rule.effect, rule.source, rule.page
                )));
            }
            r.source_rules.insert(rule.id.clone(), rule.clone());
            Ok(rule)
        })
    }

    pub fn update_source_rule(
        &self,
        profile: &str,
        id: &str,
        caps: CapSet,
        note: Option<String>,
    ) -> Result<SourceRule, StoreError> {
        self.mutate(profile, |r, _| {
            let rule = r
                .source_rules
                .get_mut(id)
                .ok_or_else(|| StoreError::NotFound(format!("source rule {id} not found")))?;
            rule.caps = caps;
            rule.note = note;
            rule.validate()?;
            Ok(rule.clone())
        })
    }

    pub fn delete_source_rule(&self, profile: &str, id: &str) -> Result<(), StoreError> {
        self.mutate(profile, |r, _| {
            r.source_rules
                .remove(id)
                .map(|_| ())
                .ok_or_else(|| StoreError::NotFound(format!("source rule {id} not found")))
        })
    }

    /// Grant a temporary permission. `ttl_secs` sets the expiry; `until_restart` keeps it in
    /// memory only; `persist` stores a timed grant so it survives a restart.
    pub fn grant_temp(
        &self,
        profile: &str,
        page: Scope,
        kind: GrantKind,
        ttl_secs: Option<u64>,
        until_restart: bool,
        persist: bool,
    ) -> Result<TempGrant, StoreError> {
        self.mutate(profile, |r, now| {
            let g = TempGrant {
                id: new_id(),
                page,
                kind,
                expires_at: ttl_secs.map(|t| now.saturating_add(t)),
                until_restart,
                persist,
                created_at: now,
            };
            g.validate()?;
            r.temps.insert(g.id.clone(), g.clone());
            Ok(g)
        })
    }

    pub fn revoke_temp(&self, profile: &str, id: &str) -> Result<(), StoreError> {
        self.mutate(profile, |r, _| {
            r.temps
                .remove(id)
                .map(|_| ())
                .ok_or_else(|| StoreError::NotFound(format!("temporary grant {id} not found")))
        })
    }

    /// Remove every temporary grant; returns how many there were.
    pub fn revoke_all_temps(&self, profile: &str) -> Result<usize, StoreError> {
        self.mutate(profile, |r, _| {
            let n = r.temps.len();
            r.temps.clear();
            Ok(n)
        })
    }

    pub fn import(
        &self,
        profile: &str,
        doc: PolicyExport,
        replace: bool,
    ) -> Result<(), StoreError> {
        self.mutate(profile, |r, _| {
            r.import(doc, replace, new_id)?;
            Ok(())
        })
    }

    // ---- reports ----

    pub fn record_block(&self, profile: &str, page_host: &str, ev: BlockEvent) {
        let now = self.now();
        self.reports
            .lock()
            .entry(profile.to_string())
            .or_default()
            .record(page_host, ev, now);
    }

    /// Returns false when the violation was ignored.
    pub fn record_violation(&self, profile: &str, v: &CspViolation) -> bool {
        let now = self.now();
        self.reports
            .lock()
            .entry(profile.to_string())
            .or_default()
            .record_violation(v, now)
    }

    pub fn report_for(&self, profile: &str, page_host: &str) -> Option<PageReport> {
        self.reports.lock().get(profile)?.page(page_host)
    }

    pub fn report_pages(&self, profile: &str) -> Vec<PageReport> {
        self.reports
            .lock()
            .get(profile)
            .map(|a| a.pages())
            .unwrap_or_default()
    }
}

fn new_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

fn persisted_temps(r: &RuleSet) -> BTreeMap<&String, &TempGrant> {
    r.temps
        .iter()
        .filter(|(_, t)| t.persist && !t.until_restart && t.expires_at.is_some())
        .collect()
}

fn diff_table<T: serde::Serialize + PartialEq>(
    txn: &common::db::redb::WriteTransaction,
    def: common::db::redb::TableDefinition<&str, &[u8]>,
    profile: &str,
    old: &BTreeMap<&String, &T>,
    new: &BTreeMap<&String, &T>,
) -> Result<(), StoreError> {
    let mut t = txn.open_table(def)?;
    for (id, v) in new {
        if old.get(id) != Some(v) {
            let json = serde_json::to_vec(v).map_err(|e| StoreError::Corrupt(e.to_string()))?;
            t.insert(key(profile, id).as_str(), json.as_slice())?;
        }
    }
    for id in old.keys() {
        if !new.contains_key(id) {
            t.remove(key(profile, id).as_str())?;
        }
    }
    Ok(())
}

fn persist_diff(
    txn: &common::db::redb::WriteTransaction,
    profile: &str,
    old: &RuleSet,
    new: &RuleSet,
    generation: u64,
) -> Result<(), StoreError> {
    diff_table(
        txn,
        tables::POLICY_SITE_RULES,
        profile,
        &refs(&old.site_rules),
        &refs(&new.site_rules),
    )?;
    diff_table(
        txn,
        tables::POLICY_SOURCE_RULES,
        profile,
        &refs(&old.source_rules),
        &refs(&new.source_rules),
    )?;
    diff_table(
        txn,
        tables::POLICY_TEMP,
        profile,
        &persisted_temps(old),
        &persisted_temps(new),
    )?;
    let mut meta = txn.open_table(tables::POLICY_META)?;
    if old.settings != new.settings {
        let json =
            serde_json::to_vec(&new.settings).map_err(|e| StoreError::Corrupt(e.to_string()))?;
        meta.insert(key(profile, "settings").as_str(), json.as_slice())?;
    }
    meta.insert(
        key(profile, "generation").as_str(),
        generation.to_be_bytes().as_slice(),
    )?;
    Ok(())
}

fn refs<T>(m: &BTreeMap<String, T>) -> BTreeMap<&String, &T> {
    m.iter().collect()
}

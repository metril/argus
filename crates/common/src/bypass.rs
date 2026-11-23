//! Bypass: hosts the proxy does not intercept (and, in `full` mode, does not filter or log).
//!
//! An entry is a pattern (an exact host or `*.suffix`, which matches subdomains only), a
//! [`BypassMode`] and a source: `builtin:<category>` (curated data shipped in the binary),
//! `custom` / `migrated` (the user's own entries) or `sub:<id>` (a subscribed exclusion list).
//! [`BypassSet`] is the immutable lookup structure (two hash maps, one probe per label of the
//! host); [`BypassEngine`] owns the persisted state and swaps a rebuilt set in live.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

/// What the proxy does for a bypassed host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BypassMode {
    /// Tunnel without MITM. Host-level blocking still applies and a `passthrough` event is
    /// logged (host only).
    NoDecrypt,
    /// No MITM, no filtering, no log event: only an aggregate counter.
    Full,
}

impl BypassMode {
    /// The stricter of two modes: `no_decrypt` (it keeps host-level blocking).
    pub fn stricter(a: Self, b: Self) -> Self {
        if a == Self::NoDecrypt || b == Self::NoDecrypt {
            Self::NoDecrypt
        } else {
            Self::Full
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoDecrypt => "no_decrypt",
            Self::Full => "full",
        }
    }
}

// ---------------------------------------------------------------------------------------------
// First-party lists (argus-lists)
// ---------------------------------------------------------------------------------------------

/// Public key (minisign format) the first-party lists are verified against.
///
/// Key id B554ACC4E424DB3C. The secret half exists only in the `ARGUS_LISTS_SIGNING_KEY`
/// secret of metril/argus-lists; rotating it means a new key here and a new Argus release.
pub const ARGUS_LISTS_PUBLIC_KEY: &str = "RWQ82yTkxKxUtT326jYenbUppmz9i6VowuDCf3IA28w+cOwBWkpNtVGA";

/// Where the first-party lists are published.
pub const ARGUS_LISTS_BASE_URL: &str =
    "https://github.com/metril/argus-lists/releases/latest/download";

/// The first-party categories: `(id, title)`. The hosts live in the argus-lists repository, not
/// here; this only names what to subscribe to.
pub const FIRST_PARTY: [(&str, &str); 7] = [
    ("banking_finance", "Banking and finance"),
    ("payments", "Payments"),
    ("health", "Health"),
    ("government", "Government"),
    ("password_managers", "Password managers"),
    ("os_updates", "OS and software updates"),
    ("pinned_apps", "Certificate-pinned apps"),
];

/// Subscription id of a first-party category.
pub fn argus_id(category: &str) -> String {
    format!("argus:{category}")
}

/// Whether a subscription id is a first-party one.
pub fn is_first_party(id: &str) -> bool {
    id.starts_with("argus:")
}

// ---------------------------------------------------------------------------------------------
// Patterns
// ---------------------------------------------------------------------------------------------

fn valid_host(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// Government namespaces whose whole TLD or public suffix is deliberately bypassed (the fallback
/// for argus-lists' signed `allowed_wildcards`, which is `scripts/allowed-wildcards.txt` there).
const ALLOWED_WILDCARDS: &[&str] = &[
    "*.nhs.uk",
    "*.gov.scot",
    "*.gov.wales",
    "*.gov",
    "*.mil",
    "*.gov.uk",
    "*.gov.au",
    "*.gc.ca",
    "*.gov.ie",
    "*.gov.nz",
    "*.gov.in",
    "*.gov.za",
    "*.gov.sg",
    "*.gouv.fr",
    "*.gv.at",
    "*.gob.es",
    "*.gob.mx",
    "*.gov.br",
    "*.gov.it",
    "*.gob.cl",
    "*.gov.pl",
    "*.gov.se",
    "*.gov.no",
    "*.gov.dk",
    "*.gov.fi",
    "*.europa.eu",
    "*.admin.ch",
    "*.overheid.nl",
    "*.bund.de",
    "*.gouv.qc.ca",
];

/// Whether `host` is itself a public suffix (`com`, `co.uk`, `github.io`, ...), per the Public
/// Suffix List.
fn is_public_suffix(host: &str) -> bool {
    psl::suffix(host.as_bytes()).is_some_and(|s| s.is_known() && s.as_bytes() == host.as_bytes())
}

/// Single-label TLDs an allow-list entry may name.
const ALLOWED_TLDS: &[&str] = &["gov", "mil"];

/// Keep the entries of a (signed) `allowed_wildcards` list that are sane: `*.` followed by a
/// public suffix of two or more labels, or one of the TLDs `gov` / `mil`. Anything else (`*.com`,
/// `*.net`, `*.example.com`) is dropped even if it was signed.
pub fn sanitize_allowed_wildcards(list: &[String]) -> Vec<String> {
    list.iter()
        .map(|e| e.trim().to_ascii_lowercase())
        .filter(|e| {
            e.strip_prefix("*.").is_some_and(|rest| {
                valid_host(rest)
                    && ((rest.contains('.') && is_public_suffix(rest))
                        || ALLOWED_TLDS.contains(&rest))
            })
        })
        .collect()
}

/// Normalise and validate a pattern: an exact host (or IP) or `*.suffix`. Single-label names and
/// patterns that cover a whole public suffix (`com`, `*.com`, `co.uk`, `*.co.uk`) are refused,
/// except the government namespaces in [`ALLOWED_WILDCARDS`] (`*.gov`, `*.gov.uk`, ...).
pub fn normalize_pattern(raw: &str) -> Result<String, String> {
    normalize_pattern_with(raw, &[])
}

/// [`normalize_pattern`] that also honours `extra_allowed` wildcards. Only pass a list that
/// came from a verified first-party `meta.json` (and went through
/// [`sanitize_allowed_wildcards`]); subscriptions and custom entries use [`normalize_pattern`].
pub fn normalize_pattern_with(raw: &str, extra_allowed: &[String]) -> Result<String, String> {
    let p = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(rest) = p.strip_prefix("*.") {
        if !valid_host(rest) {
            return Err(format!("{raw:?} is not a valid *.suffix pattern"));
        }
        if (!rest.contains('.') || is_public_suffix(rest))
            && !ALLOWED_WILDCARDS.contains(&p.as_str())
            && !extra_allowed.contains(&p)
        {
            return Err(format!(
                "{raw:?} is too broad: it covers a whole public suffix"
            ));
        }
        return Ok(p);
    }
    if p.parse::<std::net::IpAddr>().is_ok() {
        return Ok(p);
    }
    if !valid_host(&p) {
        return Err(format!("{raw:?} is not a host name or *.suffix pattern"));
    }
    if !p.contains('.') {
        return Err(format!("{raw:?} is a single-label name, not a site"));
    }
    if is_public_suffix(&p) {
        return Err(format!("{raw:?} is a public suffix, not a site"));
    }
    Ok(p)
}

// ---------------------------------------------------------------------------------------------
// Persisted state
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CategorySetting {
    pub enabled: bool,
    pub mode: BypassMode,
}

/// A user-managed entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub pattern: String,
    pub mode: BypassMode,
    /// `custom` or `migrated`.
    pub source: String,
    #[serde(default)]
    pub note: Option<String>,
    /// Unix seconds.
    pub updated_at: i64,
}

/// A subscribed exclusion list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub name: String,
    pub url: String,
    pub mode: BypassMode,
    pub enabled: bool,
    #[serde(default)]
    pub last_fetched: Option<i64>,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub host_count: usize,
    /// Lines of the last fetch that were skipped (invalid or too broad). Not an error.
    #[serde(default)]
    pub skipped_lines: u32,
    #[serde(default)]
    pub skipped_sample: Vec<String>,
}

fn yes() -> bool {
    true
}

/// Categories that shipped with `full` as their default before `no_decrypt` became the default.
const OLD_FULL_DEFAULTS: [&str; 5] = [
    "banking_finance",
    "payments",
    "health",
    "government",
    "password_managers",
];

/// What the last check of the first-party lists found.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArgusInfo {
    /// Release the installed lists come from (`vYYYY.MM.DD[.N]`).
    #[serde(default)]
    pub version: Option<String>,
    /// The newest release ever installed: a monotonic floor that nothing clears, so an older
    /// release is refused even after the cache was lost.
    #[serde(default)]
    pub min_version: Option<String>,
    /// Unix seconds of the last successful install.
    #[serde(default)]
    pub updated_at: Option<i64>,
    /// Unix seconds of the last check (successful or not).
    #[serde(default)]
    pub last_checked: Option<i64>,
    #[serde(default)]
    pub last_error: Option<String>,
    /// Lines skipped across the installed lists (invalid or too broad). Not an error.
    #[serde(default)]
    pub skipped_lines: u32,
    #[serde(default)]
    pub skipped_sample: Vec<String>,
    /// Category descriptions from the signed `meta.json`.
    #[serde(default)]
    pub categories: BTreeMap<String, ArgusCategory>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArgusCategory {
    pub name: String,
    pub description: String,
    pub default_mode: BypassMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassState {
    /// Settings of the former built-in categories; only read to migrate them into the
    /// first-party subscriptions.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub categories: BTreeMap<String, CategorySetting>,
    #[serde(default)]
    pub entries: Vec<Entry>,
    /// Third-party subscriptions and the first-party `argus:<category>` ones.
    #[serde(default)]
    pub subscriptions: Vec<Subscription>,
    /// Fetched patterns per subscription id. Kept in files of their own (see the engine), not in
    /// the settings file, and shared cheaply between state snapshots.
    #[serde(skip)]
    pub sub_hosts: BTreeMap<String, Arc<Vec<String>>>,
    /// `sub_hosts` as an older version stored them inside the settings file (read once).
    #[serde(default, rename = "sub_hosts", skip_serializing)]
    legacy_sub_hosts: BTreeMap<String, Vec<String>>,
    /// `tls_passthrough_hosts` from the config file were turned into entries.
    #[serde(default)]
    pub migrated: bool,
    /// Tunnel sites whose certificate is an Extended Validation one instead of decrypting them.
    #[serde(default = "yes")]
    pub ev_no_decrypt: bool,
    /// Decrypt even though an enabled first-party list has not loaded yet (admin override of
    /// the fail-safe).
    #[serde(default)]
    pub decrypt_without_lists: bool,
    #[serde(default)]
    pub argus: ArgusInfo,
    /// Version of the defaults the stored state was written against.
    #[serde(default)]
    pub defaults_version: u32,
}

const CURRENT_DEFAULTS_VERSION: u32 = 2;

impl Default for BypassState {
    fn default() -> Self {
        Self {
            categories: BTreeMap::new(),
            entries: Vec::new(),
            subscriptions: Vec::new(),
            sub_hosts: BTreeMap::new(),
            legacy_sub_hosts: BTreeMap::new(),
            migrated: false,
            ev_no_decrypt: true,
            decrypt_without_lists: false,
            argus: ArgusInfo::default(),
            defaults_version: CURRENT_DEFAULTS_VERSION,
        }
    }
}

/// Whether the fail-safe is holding decryption back, and why.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Failsafe {
    pub active: bool,
    pub reason: Option<String>,
}

impl BypassState {
    /// Replace a subscription's fetched patterns.
    pub fn set_hosts(&mut self, id: &str, hosts: Vec<String>) {
        self.sub_hosts.insert(id.to_string(), Arc::new(hosts));
    }

    /// Make sure every first-party category has its subscription (subscribed by default on a
    /// first run) and carry the settings of the former embedded categories over: their switch
    /// and mode become the subscription's. A mode still at the old default (`full`) moves to the
    /// new one (`no_decrypt`); a deliberate choice is kept. Returns whether anything changed.
    pub fn ensure_first_party(&mut self) -> bool {
        let mut changed = false;
        for (cat, title) in FIRST_PARTY {
            let id = argus_id(cat);
            if self.subscriptions.iter().any(|x| x.id == id) {
                continue;
            }
            let legacy = self.categories.get(cat).copied();
            let mut mode = legacy.map_or(BypassMode::NoDecrypt, |c| c.mode);
            if self.defaults_version < 1
                && OLD_FULL_DEFAULTS.contains(&cat)
                && mode == BypassMode::Full
            {
                mode = BypassMode::NoDecrypt;
            }
            self.subscriptions.push(Subscription {
                id,
                name: title.to_string(),
                url: format!("{ARGUS_LISTS_BASE_URL}/{cat}.txt"),
                mode,
                enabled: legacy.is_none_or(|c| c.enabled),
                last_fetched: None,
                last_error: None,
                host_count: 0,
                skipped_lines: 0,
                skipped_sample: Vec::new(),
            });
            changed = true;
        }
        if !self.categories.is_empty() {
            self.categories.clear();
            changed = true;
        }
        if self.defaults_version < CURRENT_DEFAULTS_VERSION {
            self.defaults_version = CURRENT_DEFAULTS_VERSION;
            changed = true;
        }
        changed
    }

    /// The first-party subscription of `category`.
    pub fn first_party(&self, category: &str) -> Option<&Subscription> {
        let id = argus_id(category);
        self.subscriptions.iter().find(|x| x.id == id)
    }

    /// Fail-safe state: while an enabled first-party list has never loaded (from the network or
    /// the verified cache) nothing may be decrypted, because the exclusions it carries (banks,
    /// health, ...) are not known yet.
    pub fn failsafe(&self) -> Failsafe {
        if self.decrypt_without_lists {
            return Failsafe::default();
        }
        let waiting: Vec<&str> = self
            .subscriptions
            .iter()
            .filter(|x| is_first_party(&x.id) && x.enabled && x.last_fetched.is_none())
            .map(|x| x.id.trim_start_matches("argus:"))
            .collect();
        if waiting.is_empty() {
            return Failsafe::default();
        }
        let mut reason = format!(
            "waiting for the Argus lists to load ({}); HTTPS is tunnelled, not decrypted",
            waiting.join(", ")
        );
        if let Some(e) = &self.argus.last_error {
            reason.push_str(&format!(": {e}"));
        }
        Failsafe {
            active: true,
            reason: Some(reason),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Lookup structure
// ---------------------------------------------------------------------------------------------

const RANK_CUSTOM: u8 = 0;
const RANK_SUB: u8 = 1;
const RANK_BUILTIN: u8 = 2;

#[derive(Debug, Clone)]
struct Slot {
    mode: BypassMode,
    rank: u8,
    source: Arc<str>,
    pattern: Arc<str>,
}

impl Slot {
    /// Custom beats subscription beats built-in; on equal rank the stricter mode wins.
    fn better_than(&self, o: &Slot) -> bool {
        (self.rank, self.mode == BypassMode::Full) < (o.rank, o.mode == BypassMode::Full)
    }
}

/// What matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub mode: BypassMode,
    /// `argus:<category>`, `custom`, `migrated` or `sub:<id>`.
    pub source: String,
    pub pattern: String,
}

/// Immutable lookup tables.
#[derive(Debug, Default)]
pub struct BypassSet {
    exact: HashMap<Box<str>, Slot>,
    /// `*.example.com` is stored as `example.com`.
    suffix: HashMap<Box<str>, Slot>,
}

impl BypassSet {
    fn insert(&mut self, pattern: &str, mode: BypassMode, rank: u8, source: &Arc<str>) {
        let (map, key) = match pattern.strip_prefix("*.") {
            Some(rest) => (&mut self.suffix, rest),
            None => (&mut self.exact, pattern),
        };
        let slot = Slot {
            mode,
            rank,
            source: source.clone(),
            pattern: pattern.into(),
        };
        match map.get_mut(key) {
            Some(old) if !slot.better_than(old) => {}
            Some(old) => *old = slot,
            None => {
                map.insert(key.into(), slot);
            }
        }
    }

    pub fn build(state: &BypassState) -> Self {
        let mut s = Self::default();
        for sub in state.subscriptions.iter().filter(|x| x.enabled) {
            // First-party lists are the built-in tier; others rank above them.
            let (source, rank): (Arc<str>, u8) = if is_first_party(&sub.id) {
                (sub.id.as_str().into(), RANK_BUILTIN)
            } else {
                (format!("sub:{}", sub.id).into(), RANK_SUB)
            };
            for p in state
                .sub_hosts
                .get(&sub.id)
                .map(|h| h.as_slice())
                .unwrap_or_default()
            {
                s.insert(p, sub.mode, rank, &source);
                // Exclusion lists name a domain to cover its subdomains too.
                if !p.starts_with("*.") && p.parse::<std::net::IpAddr>().is_err() {
                    s.insert(&format!("*.{p}"), sub.mode, rank, &source);
                }
            }
        }
        for e in &state.entries {
            let source: Arc<str> = e.source.as_str().into();
            s.insert(&e.pattern, e.mode, RANK_CUSTOM, &source);
        }
        s
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.suffix.is_empty()
    }

    /// The best match for `host`: the exact entry and every enclosing `*.suffix` entry compete
    /// on source precedence, then strictness.
    pub fn lookup(&self, host: &str) -> Option<Hit> {
        if self.is_empty() {
            return None;
        }
        let host: Cow<str> = if host.bytes().any(|b| b.is_ascii_uppercase()) {
            Cow::Owned(host.to_ascii_lowercase())
        } else {
            Cow::Borrowed(host)
        };
        let host = host.trim_end_matches('.');
        let mut best: Option<&Slot> = self.exact.get(host);
        for (i, _) in host.match_indices('.') {
            if let Some(s) = self.suffix.get(&host[i + 1..]) {
                if best.is_none_or(|b| s.better_than(b)) {
                    best = Some(s);
                }
            }
        }
        best.map(|s| Hit {
            mode: s.mode,
            source: s.source.to_string(),
            pattern: s.pattern.to_string(),
        })
    }

    /// Just the mode (the per-connection hot path: no allocation).
    pub fn mode_of(&self, host: &str) -> Option<BypassMode> {
        if self.is_empty() {
            return None;
        }
        let lower;
        let host = if host.bytes().any(|b| b.is_ascii_uppercase()) {
            lower = host.to_ascii_lowercase();
            lower.as_str()
        } else {
            host
        };
        let host = host.trim_end_matches('.');
        let mut best: Option<&Slot> = self.exact.get(host);
        for (i, _) in host.match_indices('.') {
            if let Some(s) = self.suffix.get(&host[i + 1..]) {
                if best.is_none_or(|b| s.better_than(b)) {
                    best = Some(s);
                }
            }
        }
        best.map(|s| s.mode)
    }
}

// ---------------------------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------------------------

/// The live bypass state: persisted settings, the current lookup set and counters.
pub struct BypassEngine {
    state: Mutex<BypassState>,
    set: ArcSwap<BypassSet>,
    path: Option<PathBuf>,
    /// Serialises writers and remembers what is on disk, so only what changed is written.
    persist: Mutex<Persisted>,
    bypassed: AtomicU64,
    ev: std::sync::atomic::AtomicBool,
    failsafe: std::sync::atomic::AtomicBool,
}

/// What was last written, to skip unchanged files.
#[derive(Default)]
struct Persisted {
    /// The settings file's bytes.
    small: Vec<u8>,
    /// Hash of each subscription's hosts file.
    hosts: HashMap<String, u64>,
    small_writes: u64,
    host_writes: u64,
}

fn hash_hosts(h: &[String]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut s = std::collections::hash_map::DefaultHasher::new();
    h.hash(&mut s);
    s.finish()
}

fn hosts_file(dir: &std::path::Path, id: &str) -> PathBuf {
    dir.join("bypass-hosts")
        .join(format!("{}.json", id.replace([':', '/', '\\'], "_")))
}

impl Default for BypassEngine {
    fn default() -> Self {
        Self::in_memory()
    }
}

/// A fresh id.
pub fn new_id() -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    format!("{nanos:x}{:x}", SEQ.fetch_add(1, Ordering::Relaxed))
}

impl BypassEngine {
    fn with(state: BypassState, path: Option<PathBuf>) -> Self {
        Self {
            set: ArcSwap::from_pointee(BypassSet::build(&state)),
            state: Mutex::new(state),
            path,
            persist: Mutex::new(Persisted::default()),
            bypassed: AtomicU64::new(0),
            ev: std::sync::atomic::AtomicBool::new(true),
            failsafe: std::sync::atomic::AtomicBool::new(false),
        }
        .sync_flags()
    }

    fn sync_flags(self) -> Self {
        {
            let g = self.state.lock();
            self.ev.store(g.ev_no_decrypt, Ordering::Relaxed);
            self.failsafe.store(g.failsafe().active, Ordering::Relaxed);
        }
        self
    }

    /// Directory the state is kept in (`None` for an in-memory engine).
    pub fn data_dir(&self) -> Option<PathBuf> {
        self.path
            .as_ref()
            .and_then(|p| p.parent())
            .map(PathBuf::from)
    }

    /// Whether decryption is held back until the first-party lists have loaded. Cheap: read per
    /// connection.
    #[inline]
    pub fn failsafe_active(&self) -> bool {
        self.failsafe.load(Ordering::Relaxed)
    }

    /// The fail-safe state with its reason.
    pub fn failsafe(&self) -> Failsafe {
        self.state.lock().failsafe()
    }

    /// Whether EV-certificate sites are tunnelled instead of decrypted.
    #[inline]
    pub fn ev_no_decrypt(&self) -> bool {
        self.ev.load(Ordering::Relaxed)
    }

    /// No first-party lists and nothing persisted (tests and embedded use): never fail-safe.
    pub fn in_memory() -> Self {
        Self::with(BypassState::default(), None)
    }

    /// Load `path` (missing = defaults); every change is written back atomically. The small
    /// settings and status live in `path`; each subscription's fetched hosts in
    /// `bypass-hosts/<id>.json` next to it, written only when they change.
    pub fn load(path: PathBuf) -> Self {
        let mut state: BypassState = std::fs::read_to_string(&path)
            .ok()
            .and_then(|t| match serde_json::from_str(&t) {
                Ok(s) => Some(s),
                Err(e) => {
                    tracing::warn!("ignoring unreadable bypass state {}: {e}", path.display());
                    None
                }
            })
            .unwrap_or_default();
        let dir = path.parent().map(PathBuf::from).unwrap_or_default();
        let mut persisted = Persisted::default();
        // An older version kept the hosts inside the settings file: adopt them (rewritten into
        // their own files by the first save below).
        let legacy = std::mem::take(&mut state.legacy_sub_hosts);
        let had_legacy = !legacy.is_empty();
        for (id, h) in legacy {
            state.set_hosts(&id, h);
        }
        for sub in &state.subscriptions {
            if state.sub_hosts.contains_key(&sub.id) {
                continue;
            }
            if let Some(h) = std::fs::read(hosts_file(&dir, &sub.id))
                .ok()
                .and_then(|b| serde_json::from_slice::<Vec<String>>(&b).ok())
            {
                persisted.hosts.insert(sub.id.clone(), hash_hosts(&h));
                state.sub_hosts.insert(sub.id.clone(), Arc::new(h));
            }
        }
        // First-party subscriptions (default on a first run) and the migration of the former
        // embedded categories' settings into them.
        let changed = state.ensure_first_party() || had_legacy;
        persisted.small = std::fs::read(&path).unwrap_or_default();
        let engine = Self::with(state, Some(path));
        *engine.persist.lock() = persisted;
        if changed {
            let st = engine.state.lock().clone();
            let mut pg = engine.persist.lock();
            if let Err(e) = engine.persist_state(&mut pg, &st) {
                tracing::warn!("could not save the bypass state: {e}");
            }
        }
        engine
    }

    /// Write what differs from what is on disk: the settings file if its content changed, and
    /// only the hosts files whose hosts changed (removing those of deleted subscriptions).
    fn persist_state(&self, pg: &mut Persisted, next: &BypassState) -> Result<(), String> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let dir = path.parent().map(PathBuf::from).unwrap_or_default();
        // Hosts first, settings last: a crash between them leaves settings that still point at
        // hosts that exist.
        for (id, hosts) in &next.sub_hosts {
            let h = hash_hosts(hosts);
            if pg.hosts.get(id) == Some(&h) {
                continue;
            }
            let json = serde_json::to_vec(hosts.as_ref()).map_err(|e| e.to_string())?;
            crate::config::write_atomic(&hosts_file(&dir, id), &json).map_err(|e| e.to_string())?;
            pg.hosts.insert(id.clone(), h);
            pg.host_writes += 1;
        }
        let gone: Vec<String> = pg
            .hosts
            .keys()
            .filter(|id| !next.sub_hosts.contains_key(*id))
            .cloned()
            .collect();
        for id in gone {
            let _ = std::fs::remove_file(hosts_file(&dir, &id));
            pg.hosts.remove(&id);
        }
        let small = serde_json::to_vec_pretty(next).map_err(|e| e.to_string())?;
        if small != pg.small {
            crate::config::write_atomic(path, &small).map_err(|e| e.to_string())?;
            pg.small = small;
            pg.small_writes += 1;
        }
        Ok(())
    }

    /// How many times the settings file and hosts files were written (tests).
    pub fn write_counts(&self) -> (u64, u64) {
        let pg = self.persist.lock();
        (pg.small_writes, pg.host_writes)
    }

    /// The bypass mode of `host`, if any (cheap: used per connection).
    #[inline]
    pub fn mode_of(&self, host: &str) -> Option<BypassMode> {
        self.set.load().mode_of(host)
    }

    /// The full match (mode, source, pattern).
    pub fn lookup(&self, host: &str) -> Option<Hit> {
        self.set.load().lookup(host)
    }

    /// Count a request or tunnel handled in `full` mode.
    #[inline]
    pub fn note_bypassed(&self) {
        self.bypassed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn bypassed_total(&self) -> u64 {
        self.bypassed.load(Ordering::Relaxed)
    }

    /// Read the state.
    pub fn read<R>(&self, f: impl FnOnce(&BypassState) -> R) -> R {
        f(&self.state.lock())
    }

    /// Change the state: on success it is saved and a rebuilt set is swapped in; an error from
    /// `f` or from saving leaves everything as it was. Only changed files are written. This does
    /// file I/O: from async code use [`Self::update_async`].
    pub fn update<R>(
        &self,
        f: impl FnOnce(&mut BypassState) -> Result<R, String>,
    ) -> Result<R, String> {
        // Writers are serialised by `persist`; readers only ever wait for the cheap state lock.
        let mut pg = self.persist.lock();
        let mut next = self.state.lock().clone();
        let out = f(&mut next)?;
        self.persist_state(&mut pg, &next)?;
        let set = BypassSet::build(&next);
        self.ev.store(next.ev_no_decrypt, Ordering::Relaxed);
        self.failsafe
            .store(next.failsafe().active, Ordering::Relaxed);
        *self.state.lock() = next;
        self.set.store(Arc::new(set));
        Ok(out)
    }

    /// [`Self::update`] on the blocking pool, so a large state's writes never run on an async
    /// worker thread.
    pub async fn update_async<R: Send + 'static>(
        self: &Arc<Self>,
        f: impl FnOnce(&mut BypassState) -> Result<R, String> + Send + 'static,
    ) -> Result<R, String> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.update(f))
            .await
            .map_err(|e| e.to_string())?
    }

    /// Change status-only fields (nothing that affects matching): kept in memory and saved with
    /// the next real change, so frequent status ticks cost no disk writes.
    pub fn update_volatile(&self, f: impl FnOnce(&mut BypassState)) {
        f(&mut self.state.lock());
    }

    /// Replace the entries sourced `migrated` with `hosts` (mode `no_decrypt`): the old
    /// `tls_passthrough_hosts` setting, kept working through the new model.
    pub fn sync_legacy(&self, hosts: &[String]) -> Result<(), String> {
        self.update(|s| {
            s.entries.retain(|e| e.source != "migrated");
            for h in hosts {
                let Ok(p) = normalize_pattern(h) else {
                    continue;
                };
                if s.entries.iter().any(|e| e.pattern == p) {
                    continue;
                }
                s.entries.push(Entry {
                    id: new_id(),
                    pattern: p,
                    mode: BypassMode::NoDecrypt,
                    source: "migrated".into(),
                    note: None,
                    updated_at: now(),
                });
            }
            s.migrated = true;
            Ok(())
        })
    }

    /// Startup migration: turn the config's `tls_passthrough_hosts` into entries once.
    pub fn migrate_legacy_once(&self, hosts: &[String]) -> Result<bool, String> {
        if self.read(|s| s.migrated) {
            return Ok(false);
        }
        self.sync_legacy(hosts)?;
        Ok(true)
    }
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// Parse an exclusion list: one host or `*.suffix` per line; `#`, `!` and `;` comments and
/// blank lines are skipped, as is anything that is not a valid pattern. `cap` bounds the count.
pub fn parse_exclusion_list(text: &str, cap: usize) -> Vec<String> {
    parse_exclusion_list_counted(text, cap).0
}

/// Lines a list parse skipped (not valid patterns, or too broad); comments and blank lines are
/// not counted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Skipped {
    pub count: usize,
    /// The first few skipped lines, for display.
    pub sample: Vec<String>,
}

/// Most skipped lines kept as a sample.
pub const SKIPPED_SAMPLE: usize = 5;

impl Skipped {
    fn note(&mut self, line: &str) {
        self.count += 1;
        if self.sample.len() < SKIPPED_SAMPLE {
            self.sample.push(line.chars().take(120).collect());
        }
    }

    /// Fold another list's skips in.
    pub fn merge(&mut self, other: Skipped) {
        self.count += other.count;
        for l in other.sample {
            if self.sample.len() < SKIPPED_SAMPLE {
                self.sample.push(l);
            }
        }
    }
}

/// [`parse_exclusion_list`] that also reports the lines it skipped.
pub fn parse_exclusion_list_counted(text: &str, cap: usize) -> (Vec<String>, Skipped) {
    parse_exclusion_list_counted_with(text, cap, &[])
}

/// [`parse_exclusion_list_counted`] honouring a verified first-party `allowed_wildcards` list
/// (see [`normalize_pattern_with`]).
pub fn parse_exclusion_list_counted_with(
    text: &str,
    cap: usize,
    extra_allowed: &[String],
) -> (Vec<String>, Skipped) {
    let mut skipped = Skipped::default();
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for line in text.lines() {
        let l = line.split(['#', '!', ';']).next().unwrap_or("");
        let l = l.split("//").next().unwrap_or("").trim();
        if l.is_empty() {
            continue;
        }
        // One token, or a hosts-file style "0.0.0.0 host".
        let toks: Vec<&str> = l.split_whitespace().collect();
        let tok = match toks.as_slice() {
            [t] => *t,
            [ip, t] if ip.parse::<std::net::IpAddr>().is_ok() => *t,
            _ => {
                skipped.note(l);
                continue;
            }
        };
        match normalize_pattern_with(tok, extra_allowed) {
            Ok(p) => {
                if seen.insert(p.clone()) {
                    out.push(p);
                    if out.len() >= cap {
                        break;
                    }
                }
            }
            Err(_) => skipped.note(tok),
        }
    }
    (out, skipped)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(list: &[(&str, BypassMode)]) -> Vec<Entry> {
        list.iter()
            .map(|(p, m)| Entry {
                id: new_id(),
                pattern: p.to_string(),
                mode: *m,
                source: "custom".into(),
                note: None,
                updated_at: 0,
            })
            .collect()
    }

    fn state_with(list: &[(&str, BypassMode)]) -> BypassState {
        BypassState {
            entries: entries(list),
            ..Default::default()
        }
    }

    /// A first-party category that has loaded `hosts`.
    fn load_argus(s: &mut BypassState, cat: &str, mode: BypassMode, hosts: &[&str]) {
        let id = argus_id(cat);
        s.subscriptions.retain(|x| x.id != id);
        s.subscriptions.push(Subscription {
            id: id.clone(),
            name: cat.into(),
            url: String::new(),
            mode,
            enabled: true,
            last_fetched: Some(1),
            last_error: None,
            host_count: hosts.len(),
            skipped_lines: 0,
            skipped_sample: Vec::new(),
        });
        s.set_hosts(&id, hosts.iter().map(|h| h.to_string()).collect());
    }

    fn third_party(s: &mut BypassState, id: &str, mode: BypassMode, hosts: &[&str]) {
        s.subscriptions.push(Subscription {
            id: id.into(),
            name: id.into(),
            url: format!("https://x.test/{id}"),
            mode,
            enabled: true,
            last_fetched: Some(1),
            last_error: None,
            host_count: hosts.len(),
            skipped_lines: 0,
            skipped_sample: Vec::new(),
        });
        s.set_hosts(id, hosts.iter().map(|h| h.to_string()).collect());
    }

    #[test]
    fn nothing_is_embedded_in_the_binary() {
        // A fresh state knows no hosts at all; the lists come from the first-party release.
        let set = BypassSet::build(&BypassState::default());
        assert!(set.is_empty());
        assert!(set.lookup("login.chase.com").is_none());
        assert_eq!(FIRST_PARTY.len(), 7);
    }

    #[test]
    fn wildcards_cover_subdomains_only_and_bare_domains_cover_both() {
        let set = BypassSet::build(&state_with(&[
            ("*.pinned.test", BypassMode::Full),
            ("bank.test", BypassMode::NoDecrypt),
        ]));
        assert!(set.lookup("a.pinned.test").is_some());
        assert!(set.lookup("A.B.Pinned.test.").is_some());
        assert!(
            set.lookup("pinned.test").is_none(),
            "wildcard excludes the apex"
        );
        assert!(set.lookup("bank.test").is_some());
        assert!(
            set.lookup("www.bank.test").is_none(),
            "an exact custom entry covers only itself"
        );
        assert!(set.lookup("notpinned.test").is_none());
    }

    #[test]
    fn first_party_lists_apply_with_their_mode_and_source_and_a_bare_domain_covers_subdomains() {
        let mut s = BypassState::default();
        load_argus(
            &mut s,
            "banking_finance",
            BypassMode::NoDecrypt,
            &["chase.com", "*.gov"],
        );
        let set = BypassSet::build(&s);
        let h = set.lookup("secure.chase.com").unwrap();
        assert_eq!(
            (h.mode, h.source.as_str()),
            (BypassMode::NoDecrypt, "argus:banking_finance")
        );
        assert!(set.lookup("chase.com").is_some());
        assert!(set.lookup("www.irs.gov").is_some());
        // Switching the category off or changing its mode takes effect on rebuild.
        s.subscriptions[0].mode = BypassMode::Full;
        assert_eq!(
            BypassSet::build(&s).lookup("chase.com").unwrap().mode,
            BypassMode::Full
        );
        s.subscriptions[0].enabled = false;
        assert!(BypassSet::build(&s).lookup("chase.com").is_none());
    }

    #[test]
    fn precedence_is_custom_then_subscription_then_first_party_and_the_stricter_mode_breaks_ties() {
        let mut s = BypassState::default();
        load_argus(&mut s, "banking_finance", BypassMode::Full, &["chase.com"]);
        third_party(
            &mut s,
            "s1",
            BypassMode::NoDecrypt,
            &["chase.com", "only-sub.test"],
        );
        let h = BypassSet::build(&s).lookup("chase.com").unwrap();
        assert_eq!(
            (h.source.as_str(), h.mode),
            ("sub:s1", BypassMode::NoDecrypt),
            "subscription beats first-party"
        );
        s.entries = entries(&[("chase.com", BypassMode::Full)]);
        let h = BypassSet::build(&s).lookup("chase.com").unwrap();
        assert_eq!(
            (h.source.as_str(), h.mode),
            ("custom", BypassMode::Full),
            "custom beats subscription"
        );
        // A more specific first-party entry does not beat a broader custom one: source wins.
        s.entries = entries(&[("*.chase.com", BypassMode::NoDecrypt)]);
        assert_eq!(
            BypassSet::build(&s).lookup("www.chase.com").unwrap().source,
            "custom"
        );
        // Same rank, same pattern, two modes: the stricter (no_decrypt) wins.
        s.entries = entries(&[
            ("tie.test", BypassMode::Full),
            ("tie.test", BypassMode::NoDecrypt),
        ]);
        assert_eq!(
            BypassSet::build(&s).lookup("tie.test").unwrap().mode,
            BypassMode::NoDecrypt
        );
        s.entries = entries(&[
            ("a.tie.test", BypassMode::Full),
            ("*.tie.test", BypassMode::NoDecrypt),
        ]);
        assert_eq!(
            BypassSet::build(&s).lookup("a.tie.test").unwrap().mode,
            BypassMode::NoDecrypt
        );
    }

    #[test]
    fn subscription_domains_cover_their_subdomains_but_ips_stay_exact() {
        let mut s = BypassState::default();
        third_party(
            &mut s,
            "a",
            BypassMode::NoDecrypt,
            &["bank.test", "192.0.2.1"],
        );
        let set = BypassSet::build(&s);
        assert!(set.lookup("bank.test").is_some() && set.lookup("www.bank.test").is_some());
        assert!(set.lookup("192.0.2.1").is_some());
    }

    #[test]
    fn pattern_validation() {
        for ok in [
            "Example.COM",
            "*.gov",
            "a-b.c_d.test",
            "10.0.0.1",
            "bank.test.",
        ] {
            assert!(normalize_pattern(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "*",
            "*.",
            "a b.test",
            "https://x.test",
            "x.test:443",
            "a..b",
            "*.*.x",
        ] {
            assert!(normalize_pattern(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn exclusion_lists_skip_comments_and_garbage() {
        let l = "# comment\n! another\n// slash comment\n\nbank.test\n*.wild.test ; trailing\nnot a host line\n0.0.0.0 hosts.test\nbank.test\n/path/x\napi.github.com$app=Discord.exe\n";
        assert_eq!(
            parse_exclusion_list(l, 100),
            ["bank.test", "*.wild.test", "hosts.test"]
        );
        assert_eq!(parse_exclusion_list(l, 1).len(), 1);
    }

    #[test]
    fn a_fresh_install_subscribes_to_every_first_party_list_enabled_and_waits_for_them() {
        let d = tempfile::tempdir().unwrap();
        let e = BypassEngine::load(d.path().join("bypass.json"));
        let subs = e.read(|s| s.subscriptions.clone());
        assert_eq!(subs.len(), 7);
        for (cat, _) in FIRST_PARTY {
            let x = subs.iter().find(|x| x.id == argus_id(cat)).unwrap();
            assert!(x.enabled && x.mode == BypassMode::NoDecrypt && x.last_fetched.is_none());
            assert_eq!(x.url, format!("{ARGUS_LISTS_BASE_URL}/{cat}.txt"));
        }
        assert!(e.failsafe_active(), "nothing has loaded yet");
        let f = e.failsafe();
        assert!(f.active && f.reason.unwrap().contains("banking_finance"));
    }

    #[test]
    fn failsafe_ends_when_every_enabled_list_loaded_and_the_override_and_switches_apply() {
        let d = tempfile::tempdir().unwrap();
        let e = BypassEngine::load(d.path().join("bypass.json"));
        assert!(e.failsafe_active());
        // Loading all but one keeps it on.
        e.update(|s| {
            for (cat, _) in FIRST_PARTY.iter().take(6) {
                let sub = s
                    .subscriptions
                    .iter_mut()
                    .find(|x| x.id == argus_id(cat))
                    .unwrap();
                sub.last_fetched = Some(1);
            }
            Ok(())
        })
        .unwrap();
        assert!(e.failsafe_active());
        // Disabling the one that is missing ends it (nothing enabled is waiting).
        e.update(|s| {
            s.subscriptions
                .iter_mut()
                .find(|x| x.id == "argus:pinned_apps")
                .unwrap()
                .enabled = false;
            Ok(())
        })
        .unwrap();
        assert!(!e.failsafe_active());
        // Re-enabling it brings the fail-safe back, and the admin override turns it off live.
        e.update(|s| {
            s.subscriptions
                .iter_mut()
                .find(|x| x.id == "argus:pinned_apps")
                .unwrap()
                .enabled = true;
            Ok(())
        })
        .unwrap();
        assert!(e.failsafe_active());
        e.update(|s| {
            s.decrypt_without_lists = true;
            Ok(())
        })
        .unwrap();
        assert!(!e.failsafe_active() && !e.failsafe().active);
        // An in-memory engine (no first-party subscriptions) is never fail-safe.
        assert!(!BypassEngine::in_memory().failsafe_active());
    }

    #[test]
    fn the_former_embedded_categories_migrate_into_subscriptions_keeping_their_settings() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("bypass.json");
        // Written by an older version: banking still at the old default (full), payments chosen
        // as no_decrypt by the user, government switched off, os_updates explicitly full.
        std::fs::write(
            &path,
            r#"{"categories":{
                "banking_finance":{"enabled":true,"mode":"full"},
                "payments":{"enabled":true,"mode":"no_decrypt"},
                "government":{"enabled":false,"mode":"full"},
                "os_updates":{"enabled":true,"mode":"full"}},
               "entries":[],"subscriptions":[],"sub_hosts":{},"migrated":true}"#,
        )
        .unwrap();
        let e = BypassEngine::load(path.clone());
        let sub = |id: &str| e.read(|s| s.first_party(id).cloned()).unwrap();
        assert_eq!(
            sub("banking_finance").mode,
            BypassMode::NoDecrypt,
            "old default moves"
        );
        assert_eq!(sub("payments").mode, BypassMode::NoDecrypt);
        assert!(!sub("government").enabled, "the switch carries over");
        assert_eq!(
            sub("os_updates").mode,
            BypassMode::Full,
            "a deliberate choice is kept"
        );
        assert!(sub("health").enabled, "unset categories default to on");
        assert!(e.read(|s| s.categories.is_empty()), "legacy map consumed");
        // Persisted in the new shape: a restart keeps everything and does not re-migrate.
        let again = BypassEngine::load(path);
        assert_eq!(
            again.read(|s| s.first_party("os_updates").unwrap().mode),
            BypassMode::Full
        );
        assert!(!again.read(|s| s.first_party("government").unwrap().enabled));
        assert_eq!(again.read(|s| s.subscriptions.len()), 7);
    }

    #[test]
    fn ev_setting_is_live_and_persisted() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("bypass.json");
        let e = BypassEngine::load(path.clone());
        assert!(e.ev_no_decrypt());
        e.update(|s| {
            s.ev_no_decrypt = false;
            Ok(())
        })
        .unwrap();
        assert!(!e.ev_no_decrypt());
        assert!(!BypassEngine::load(path).ev_no_decrypt());
    }

    #[test]
    fn engine_persists_swaps_live_and_migrates_legacy_hosts_once() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("bypass.json");
        let e = BypassEngine::load(path.clone());
        assert!(e.mode_of("pinned.test").is_none());
        assert!(e
            .migrate_legacy_once(&[
                "pinned.test".into(),
                "*.wild.test".into(),
                "bad host".into()
            ])
            .unwrap());
        assert_eq!(e.mode_of("pinned.test"), Some(BypassMode::NoDecrypt));
        assert_eq!(e.lookup("x.wild.test").unwrap().source, "migrated");
        assert!(
            !e.migrate_legacy_once(&["other.test".into()]).unwrap(),
            "only once"
        );
        assert!(e.mode_of("other.test").is_none());
        let e2 = BypassEngine::load(path);
        assert_eq!(e2.mode_of("pinned.test"), Some(BypassMode::NoDecrypt));
        assert!(e2.read(|s| s.migrated));
        let before = e2.read(|s| s.entries.len());
        assert!(e2
            .update::<()>(|s| {
                s.entries.clear();
                Err("nope".into())
            })
            .is_err());
        assert_eq!(e2.read(|s| s.entries.len()), before);
        e2.note_bypassed();
        assert_eq!(e2.bypassed_total(), 1);
    }

    #[test]
    fn single_label_names_and_public_suffixes_are_refused_but_government_namespaces_stay() {
        for bad in [
            "com",
            "net",
            "localhost",
            "*.com",
            "*.net",
            "co.uk",
            "*.co.uk",
            "com.au",
            "*.com.au",
            "github.io",
            "*.github.io",
            "*.test",
            "*.org",
        ] {
            let e = normalize_pattern(bad).unwrap_err();
            assert!(
                e.contains("too broad")
                    || e.contains("single-label")
                    || e.contains("public suffix"),
                "{bad}: {e}"
            );
        }
        // Real sites under those suffixes are fine, as are the intentional government wildcards.
        for ok in [
            "example.com",
            "bbc.co.uk",
            "chase.com",
            "*.example.co.uk",
            "*.gov",
            "*.mil",
            "*.gov.uk",
            "*.gc.ca",
            "*.europa.eu",
            "irs.gov",
            "10.0.0.1",
        ] {
            assert!(normalize_pattern(ok).is_ok(), "{ok}");
        }
        // Lists skip such lines and count them.
        let (hosts, skipped) = parse_exclusion_list_counted(
            "good.test\n*.com\nco.uk\n*.gov\nnot valid here\n# comment\n\n",
            100,
        );
        assert_eq!(hosts, ["good.test", "*.gov"]);
        assert_eq!(skipped.count, 3);
        assert_eq!(skipped.sample, ["*.com", "co.uk", "not valid here"]);
        // The sample is bounded.
        let many: String = (0..20).map(|i| format!("tld{i}\n")).collect();
        let (_, s) = parse_exclusion_list_counted(&many, 100);
        assert_eq!((s.count, s.sample.len()), (20, SKIPPED_SAMPLE));
    }

    #[test]
    fn fetched_hosts_live_in_their_own_files_and_only_changed_files_are_written() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("bypass.json");
        let e = BypassEngine::load(path.clone());
        let base = e.write_counts();
        // A status/settings change writes the small file only.
        e.update(|s| {
            s.ev_no_decrypt = false;
            Ok(())
        })
        .unwrap();
        let after_setting = e.write_counts();
        assert_eq!(
            after_setting.1, base.1,
            "no hosts file written for a settings change"
        );
        assert_eq!(after_setting.0, base.0 + 1);
        // Loading hosts writes that subscription's file; the settings file records status only.
        e.update(|s| {
            s.set_hosts("argus:payments", vec!["pay.test".into()]);
            s.subscriptions
                .iter_mut()
                .find(|x| x.id == "argus:payments")
                .unwrap()
                .last_fetched = Some(1);
            Ok(())
        })
        .unwrap();
        assert_eq!(e.write_counts().1, base.1 + 1);
        let small = std::fs::read_to_string(&path).unwrap();
        assert!(
            !small.contains("pay.test"),
            "hosts are not in the settings file"
        );
        assert!(d.path().join("bypass-hosts/argus_payments.json").exists());
        // The same hosts again, or an unrelated change, rewrites neither hosts file.
        let before = e.write_counts();
        e.update(|s| {
            s.set_hosts("argus:payments", vec!["pay.test".into()]);
            Ok(())
        })
        .unwrap();
        assert_eq!(e.write_counts().1, before.1);
        // A status tick is kept in memory and costs no write at all.
        e.update_volatile(|s| s.argus.last_checked = Some(42));
        assert_eq!(e.write_counts(), before);
        assert_eq!(e.read(|s| s.argus.last_checked), Some(42));
        // Restart: hosts come back from their file; a removed subscription's file goes away.
        let again = BypassEngine::load(path.clone());
        assert!(again.lookup("pay.test").is_some());
        assert_eq!(
            again.write_counts(),
            (0, 0),
            "an unchanged load writes nothing"
        );
        again
            .update(|s| {
                s.subscriptions.retain(|x| x.id != "argus:payments");
                s.sub_hosts.remove("argus:payments");
                Ok(())
            })
            .unwrap();
        assert!(!d.path().join("bypass-hosts/argus_payments.json").exists());
    }

    #[test]
    fn hosts_stored_inside_the_settings_file_by_an_older_version_are_adopted() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("bypass.json");
        std::fs::write(
            &path,
            r#"{"entries":[],"subscriptions":[
                {"id":"s1","name":"x","url":"https://x.test/l","mode":"no_decrypt","enabled":true,
                 "last_fetched":1,"host_count":1}],
               "sub_hosts":{"s1":["old.test"]},"migrated":true,"defaults_version":2}"#,
        )
        .unwrap();
        let e = BypassEngine::load(path.clone());
        assert!(e.lookup("old.test").is_some());
        // Moved into its own file and out of the settings file on the first save.
        assert!(d.path().join("bypass-hosts/s1.json").exists());
        assert!(!std::fs::read_to_string(&path).unwrap().contains("old.test"));
        assert!(BypassEngine::load(path).lookup("old.test").is_some());
    }

    #[tokio::test]
    async fn update_async_runs_off_the_async_threads_and_applies_the_change() {
        let d = tempfile::tempdir().unwrap();
        let e = Arc::new(BypassEngine::load(d.path().join("bypass.json")));
        e.update_async(|s| {
            s.entries.push(Entry {
                id: "1".into(),
                pattern: "later.test".into(),
                mode: BypassMode::Full,
                source: "custom".into(),
                note: None,
                updated_at: 0,
            });
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(e.mode_of("later.test"), Some(BypassMode::Full));
        assert!(e.update_async::<()>(|_| Err("no".into())).await.is_err());
    }

    #[test]
    fn signed_allow_lists_are_sanity_checked_and_only_extend_what_a_caller_passes() {
        let sane = sanitize_allowed_wildcards(&[
            "*.gov".into(),
            "*.MIL".into(),
            "*.gov.uk".into(),
            "*.nhs.uk".into(),
            "*.ltd.uk".into(),
        ]);
        assert_eq!(sane, ["*.gov", "*.mil", "*.gov.uk", "*.nhs.uk", "*.ltd.uk"]);
        // Even signed, these are refused: a single-label TLD other than gov/mil, a non-suffix,
        // a bare name, an exact entry.
        let bad = sanitize_allowed_wildcards(&[
            "*.com".into(),
            "*.net".into(),
            "*.uk".into(),
            "*.example.com".into(),
            "gov.uk".into(),
            "*.".into(),
            "*".into(),
        ]);
        assert!(bad.is_empty(), "{bad:?}");
        // The extension only takes effect where a caller passes it (first-party lists).
        assert!(normalize_pattern("*.ltd.uk").is_err());
        assert_eq!(
            normalize_pattern_with("*.ltd.uk", &sane).unwrap(),
            "*.ltd.uk"
        );
        assert!(
            normalize_pattern_with("*.com", &sane).is_err(),
            "still too broad"
        );
        let text = "*.ltd.uk\n*.com\ngood.test\n";
        let (plain, s1) = parse_exclusion_list_counted(text, 100);
        assert_eq!((plain, s1.count), (vec!["good.test".to_string()], 2));
        let (with, s2) = parse_exclusion_list_counted_with(text, 100, &sane);
        assert_eq!(
            (with, s2.count),
            (vec!["*.ltd.uk".to_string(), "good.test".to_string()], 1)
        );
    }

    #[test]
    fn the_compiled_in_default_allowlist_covers_government_namespaces() {
        for ok in [
            "*.gov",
            "*.mil",
            "*.gov.uk",
            "*.nhs.uk",
            "*.gov.scot",
            "*.gov.wales",
            "*.gc.ca",
        ] {
            assert!(normalize_pattern(ok).is_ok(), "{ok}");
        }
        let sane = sanitize_allowed_wildcards(
            &ALLOWED_WILDCARDS
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
        );
        // Entries naming a public suffix (or gov/mil) also pass the signed-list rule; the others
        // (gov.scot, gov.wales) are simply not "too broad" in the first place.
        for e in ["*.gov", "*.mil", "*.gov.uk", "*.nhs.uk"] {
            assert!(sane.contains(&e.to_string()), "{e}");
        }
    }
}

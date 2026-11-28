//! Signed catalogue documents (`filters.json`, `userscripts.json`) from argus-lists: fetched from
//! the release, verified against the compiled-in minisign key, checked against the signed
//! `meta.json` digest, cached on the data volume and never replaced by an older release.

use std::cmp::Ordering;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::argus::{sha256_hex, verify_trusted, version_cmp, version_key, ArgusConfig};
use crate::ListService;

/// Between successful checks (as the first-party lists).
const CHECK_EVERY: Duration = Duration::from_secs(6 * 3600);
/// Most entries accepted from one document.
const MAX_ENTRIES: usize = 5000;

/// An entry that can be checked after parsing; invalid ones are skipped, not fatal.
pub trait CatalogueEntry: DeserializeOwned {
    /// The entry's id (collections refer to it).
    fn id(&self) -> &str;

    fn validate(&self) -> Result<(), String>;

    /// The list to install, enabled, on a first run (`default_enabled` filter entries).
    fn seed_list(&self) -> Option<filter_engine::FilterList> {
        None
    }

    /// The signed snapshot shipped in the binary, used until a cached or fetched copy verifies.
    fn snapshot() -> Option<Snapshot> {
        None
    }
}

/// A signed catalogue release compiled into the binary: the document, the signed `meta.json`
/// and both signatures. It is verified exactly like fetched data.
#[derive(Debug, Clone, Copy)]
pub struct Snapshot {
    pub text: &'static str,
    pub sig: &'static str,
    pub meta: &'static str,
    pub meta_sig: &'static str,
}

/// The embedded `filters.json` release (refresh with `scripts/update-catalogue-snapshot.sh`).
const FILTERS_SNAPSHOT: Snapshot = Snapshot {
    text: include_str!("../assets/catalogue/filters.json"),
    sig: include_str!("../assets/catalogue/filters.json.minisig"),
    meta: include_str!("../assets/catalogue/meta.json"),
    meta_sig: include_str!("../assets/catalogue/meta.json.minisig"),
};

fn https(url: &str) -> bool {
    url.len() > 8 && url[..8].eq_ignore_ascii_case("https://")
}

/// Plain http to a loopback host, for local test servers only; never accepted in production.
#[cfg(any(test, feature = "testkit"))]
fn test_loopback_http(u: &str) -> bool {
    url::Url::parse(u).is_ok_and(|u| {
        u.scheme() == "http"
            && matches!(
                u.host(),
                Some(url::Host::Domain("localhost"))
                    | Some(url::Host::Ipv4(std::net::Ipv4Addr::LOCALHOST))
                    | Some(url::Host::Ipv6(std::net::Ipv6Addr::LOCALHOST))
            )
    })
}

#[cfg(not(any(test, feature = "testkit")))]
fn test_loopback_http(_: &str) -> bool {
    false
}

fn named(id: &str, name: &str, category: &str) -> Result<(), String> {
    if id.trim().is_empty() || name.trim().is_empty() {
        return Err("empty id or name".into());
    }
    if category.trim().is_empty() {
        return Err("empty category".into());
    }
    Ok(())
}

/// The envelope of a catalogue file.
#[derive(Debug, Deserialize)]
pub struct CatalogueDoc<E> {
    pub schema: u32,
    pub kind: String,
    pub entries: Vec<E>,
    /// Optional named groups of entries; absent in older documents.
    #[serde(default, deserialize_with = "null_default")]
    pub collections: Vec<serde_json::Value>,
}

/// A named group of catalogue lists (`collections` of `filters.json`), e.g. "Recommended".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Collection {
    pub id: String,
    pub name: String,
    #[serde(default, deserialize_with = "null_default")]
    pub description: String,
    /// What turning the collection on may break.
    #[serde(default)]
    pub warning: Option<String>,
    /// Catalogue entry ids.
    pub lists: Vec<String>,
}

/// One entry of `filters.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FilterCatalogueEntry {
    pub id: String,
    pub name: String,
    #[serde(default, deserialize_with = "null_default")]
    pub description: String,
    pub url: String,
    /// `abp`, `ubo`, `adguard`, `hosts`, `domains` or `ips`.
    pub format: String,
    pub category: String,
    #[serde(default, deserialize_with = "null_default")]
    pub licence: String,
    #[serde(default)]
    pub licence_note: Option<String>,
    #[serde(default, deserialize_with = "null_default")]
    pub homepage: String,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default, deserialize_with = "null_default")]
    pub noncommercial: bool,
    /// The list's extended rules (scriptlets, `$replace`, ...) may run; set by the catalogue for
    /// uBlock Origin's lists and AdGuard Base.
    #[serde(default, deserialize_with = "null_default")]
    pub trusted: bool,
    /// Installed and enabled once on a first run, before the user has any lists.
    #[serde(default, deserialize_with = "null_default")]
    pub default_enabled: bool,
}

impl CatalogueEntry for FilterCatalogueEntry {
    fn id(&self) -> &str {
        &self.id
    }

    fn validate(&self) -> Result<(), String> {
        named(&self.id, &self.name, &self.category)?;
        if !https(&self.url) {
            return Err("url is not https".into());
        }
        if self.list_format().is_none() {
            return Err(format!("unknown format {:?}", self.format));
        }
        Ok(())
    }

    fn snapshot() -> Option<Snapshot> {
        Some(FILTERS_SNAPSHOT)
    }

    fn seed_list(&self) -> Option<filter_engine::FilterList> {
        if !self.default_enabled {
            return None;
        }
        let mut l =
            filter_engine::FilterList::new(self.id.clone(), self.name.clone(), self.url.clone());
        l.format = self.list_format()?;
        l.trusted = self.trusted;
        l.enabled = true;
        Some(l)
    }
}

impl FilterCatalogueEntry {
    /// The list format this entry maps to (`None`: not one we can add).
    pub fn list_format(&self) -> Option<filter_engine::ListFormat> {
        use filter_engine::ListFormat as F;
        Some(match self.format.as_str() {
            "abp" => F::Abp,
            "ubo" => F::Ubo,
            "adguard" => F::Adguard,
            "hosts" => F::Hosts,
            "domains" => F::Domains,
            "ips" => F::IpList,
            _ => return None,
        })
    }
}

/// Treats an explicit JSON `null` like a missing field (the published catalogue uses `null` for
/// "unknown"), so one sloppy entry cannot make the whole document unparseable.
fn null_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

impl CatalogueEntry for UserscriptCatalogueEntry {
    fn id(&self) -> &str {
        &self.id
    }

    fn validate(&self) -> Result<(), String> {
        named(&self.id, &self.name, &self.category)?;
        if !https(&self.install_url) && !test_loopback_http(&self.install_url) {
            return Err("install_url is not https".into());
        }
        Ok(())
    }
}

/// One entry of `userscripts.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserscriptCatalogueEntry {
    pub id: String,
    pub name: String,
    #[serde(default, deserialize_with = "null_default")]
    pub description: String,
    pub install_url: String,
    #[serde(default, deserialize_with = "null_default")]
    pub homepage: String,
    #[serde(default, deserialize_with = "null_default")]
    pub sites: Vec<String>,
    #[serde(default, deserialize_with = "null_default")]
    pub category: String,
    #[serde(default, deserialize_with = "null_default")]
    pub licence: String,
    #[serde(default, deserialize_with = "null_default")]
    pub licence_note: Option<String>,
    /// `none`, `basic` or `xhr`.
    #[serde(default, deserialize_with = "null_default")]
    pub needs_gm: String,
    #[serde(default, deserialize_with = "null_default")]
    pub connect: Vec<String>,
    #[serde(default, deserialize_with = "null_default")]
    pub requires: Vec<String>,
}

/// Where the copy in force came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// The signed copy built into the binary.
    Snapshot,
    /// The copy cached on the data volume (verified again at start).
    Cache,
    /// Fetched from the release in this run.
    Fetched,
}

/// A verified document in force.
#[derive(Debug)]
pub struct Loaded<E> {
    pub entries: Vec<E>,
    /// Validated collections: every list id exists in `entries`, none is empty.
    pub collections: Vec<Collection>,
    pub origin: Origin,
    /// Release the document came from (`vYYYY.MM.DD[.N]`).
    pub version: String,
    /// When it was fetched and verified (RFC 3339; the cache file's time after a restart);
    /// `None` for the copy embedded in the binary.
    pub fetched_at: Option<String>,
    /// The copy embedded in the binary, not one fetched or cached.
    pub embedded: bool,
}

/// What the subscription is doing: shown in the UI.
#[derive(Debug, Clone, Default)]
struct Checks {
    last_checked: Option<String>,
    next_check: Option<String>,
    last_ok: Option<String>,
    last_error: Option<String>,
}

/// Snapshot of a subscription for the API.
#[derive(Debug, Clone)]
pub struct SignedStatus {
    /// Where the file is fetched from.
    pub url: String,
    /// Release in force, if any copy has loaded.
    pub version: Option<String>,
    pub origin: Option<Origin>,
    pub fetched_at: Option<String>,
    pub last_checked: Option<String>,
    pub next_check: Option<String>,
    pub last_ok: Option<String>,
    pub last_error: Option<String>,
}

/// What a verified copy holds.
struct Checked<E> {
    entries: Vec<E>,
    collections: Vec<Collection>,
    version: String,
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Keep the collections that are well formed, drop unknown list ids (warning) and empty ones.
fn validate_collections(file: &str, raw: Vec<serde_json::Value>, ids: &[&str]) -> Vec<Collection> {
    let known: std::collections::HashSet<&str> = ids.iter().copied().collect();
    let mut out: Vec<Collection> = Vec::new();
    for v in raw {
        let c: Collection = match serde_json::from_value(v.clone()) {
            Ok(c) => c,
            Err(e) => {
                let id = v.get("id").and_then(|i| i.as_str()).unwrap_or("?");
                tracing::warn!("{file}: skipping collection {id:?}: {e}");
                continue;
            }
        };
        if c.id.trim().is_empty() || c.name.trim().is_empty() {
            tracing::warn!("{file}: skipping a collection with an empty id or name");
            continue;
        }
        if out.iter().any(|o| o.id == c.id) {
            tracing::warn!("{file}: skipping duplicate collection {:?}", c.id);
            continue;
        }
        let mut lists: Vec<String> = Vec::new();
        for l in &c.lists {
            if !known.contains(l.as_str()) {
                tracing::warn!(
                    "{file}: collection {:?} names unknown list {l:?}, dropped",
                    c.id
                );
            } else if !lists.contains(l) {
                lists.push(l.clone());
            }
        }
        if lists.is_empty() {
            tracing::warn!("{file}: collection {:?} has no known lists, dropped", c.id);
            continue;
        }
        out.push(Collection { lists, ..c });
    }
    out
}

#[derive(Deserialize)]
struct Meta {
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    catalogues: Vec<MetaCatalogue>,
}

#[derive(Deserialize)]
struct MetaCatalogue {
    kind: String,
    sha256: String,
}

/// One signed catalogue kind: fetch, verify, cache, refresh.
pub struct SignedDoc<E> {
    kind: &'static str,
    svc: Option<Arc<ListService>>,
    cfg: parking_lot::RwLock<Arc<dyn Fn() -> ArgusConfig + Send + Sync>>,
    current: parking_lot::RwLock<Option<Arc<Loaded<E>>>>,
    /// Text and signature of the copy in force, and the key it was verified with: a key change
    /// verifies it again.
    installed: parking_lot::Mutex<Option<(String, String)>>,
    applied_key: parking_lot::Mutex<String>,
    wake: tokio::sync::Notify,
    /// Newest release ever accepted (outlives the cache file).
    min_version: parking_lot::Mutex<Option<String>>,
    busy: tokio::sync::Mutex<()>,
    checks: parking_lot::Mutex<Checks>,
}

impl<E: CatalogueEntry + Send + Sync + 'static> SignedDoc<E> {
    pub fn new(kind: &'static str, svc: Option<Arc<ListService>>, cfg: ArgusConfig) -> Arc<Self> {
        Arc::new(Self {
            kind,
            svc,
            applied_key: parking_lot::Mutex::new(cfg.public_key.clone()),
            cfg: parking_lot::RwLock::new(Arc::new(move || cfg.clone())),
            current: Default::default(),
            installed: Default::default(),
            wake: Default::default(),
            min_version: Default::default(),
            busy: tokio::sync::Mutex::new(()),
            checks: Default::default(),
        })
    }

    /// Read the base URL, key and cache directory from `f` on every use (the live config), so a
    /// change in the UI applies without a restart.
    pub fn set_config_source(&self, f: impl Fn() -> ArgusConfig + Send + Sync + 'static) {
        *self.cfg.write() = Arc::new(f);
    }

    fn cfg(&self) -> ArgusConfig {
        let f = self.cfg.read().clone();
        f()
    }

    /// The verified document, if one has loaded.
    pub fn get(&self) -> Option<Arc<Loaded<E>>> {
        self.current.read().clone()
    }

    /// The subscription's state: source, release in force, and the outcome of the checks.
    pub fn status(&self) -> SignedStatus {
        let url = Self::url(&self.cfg(), &self.file());
        let cur = self.get();
        let c = self.checks.lock().clone();
        SignedStatus {
            url,
            version: cur.as_ref().map(|d| d.version.clone()),
            origin: cur.as_ref().map(|d| d.origin),
            fetched_at: cur.as_ref().and_then(|d| d.fetched_at.clone()),
            last_checked: c.last_checked,
            next_check: c.next_check,
            last_ok: c.last_ok,
            last_error: c.last_error,
        }
    }

    fn file(&self) -> String {
        format!("{}.json", self.kind)
    }

    fn url(cfg: &ArgusConfig, file: &str) -> String {
        format!("{}/{file}", cfg.base_url.trim_end_matches('/'))
    }

    fn path(cfg: &ArgusConfig, name: &str) -> Option<PathBuf> {
        cfg.cache_dir.as_ref().map(|d| d.join(name))
    }

    /// Check again soon (the lists location or key changed).
    pub fn nudge(&self) {
        self.wake.notify_one();
    }

    /// On a key change, verify the copy in force again with the new key, as a restart would;
    /// if it fails, drop it. The downgrade floor is kept.
    fn sync_key(&self, cfg: &ArgusConfig) {
        {
            let mut k = self.applied_key.lock();
            if *k == cfg.public_key {
                return;
            }
            k.clone_from(&cfg.public_key);
        }
        let Some((text, sig)) = self.installed.lock().clone() else {
            return;
        };
        if let Err(e) = self.check(cfg, &text, &sig, None) {
            tracing::warn!("{}: dropping the installed copy: {e}", self.kind);
            *self.current.write() = None;
            *self.installed.lock() = None;
        }
    }

    /// Verify the signature, the kind, the release and the digest of a copy; returns its entries
    /// and release. `meta` is the signed `meta.json` and its signature, when available.
    fn check(
        &self,
        cfg: &ArgusConfig,
        text: &str,
        sig: &str,
        meta: Option<(&str, &str)>,
    ) -> Result<Checked<E>, String> {
        let file = self.file();
        let key = &cfg.public_key;
        let comment =
            verify_trusted(key, text.as_bytes(), sig).map_err(|e| format!("{file}: {e}"))?;
        let doc: CatalogueDoc<serde_json::Value> =
            serde_json::from_str(text).map_err(|e| format!("{file}: {e}"))?;
        if doc.kind != self.kind {
            return Err(format!(
                "{file}: kind is {:?}, expected {:?}",
                doc.kind, self.kind
            ));
        }
        if doc.schema != 1 {
            return Err(format!("{file}: unsupported schema {}", doc.schema));
        }
        if doc.entries.len() > MAX_ENTRIES {
            return Err(format!("{file}: too many entries"));
        }
        // The signed comment names the release and the file ("argus-lists v2026.11.23 filters.json").
        if comment.split_whitespace().last() != Some(file.as_str()) {
            return Err(format!("{file}: the signature is for another file"));
        }
        let version = comment
            .split_whitespace()
            .find(|w| version_key(w).is_some())
            .map(str::to_string)
            .ok_or_else(|| format!("{file}: signature names no release"))?;
        if let Some((mtext, msig)) = meta {
            verify_trusted(key, mtext.as_bytes(), msig).map_err(|e| format!("meta.json: {e}"))?;
            let m: Meta = serde_json::from_str(mtext).map_err(|e| format!("meta.json: {e}"))?;
            let c = m
                .catalogues
                .iter()
                .find(|c| c.kind == self.kind)
                .ok_or_else(|| format!("meta.json does not list {file}"))?;
            if !c.sha256.eq_ignore_ascii_case(&sha256_hex(text.as_bytes())) {
                return Err(format!("{file} does not match the digest in meta.json"));
            }
            if m.version.as_deref() != Some(version.as_str()) {
                return Err(format!("{file}: release differs from meta.json's"));
            }
        }
        let entries: Vec<E> = doc
            .entries
            .into_iter()
            .filter_map(|v| {
                let r = serde_json::from_value::<E>(v.clone())
                    .map_err(|e| e.to_string())
                    .and_then(|e| e.validate().map(|()| e));
                match r {
                    Ok(e) => Some(e),
                    Err(e) => {
                        let id = v.get("id").and_then(|i| i.as_str()).unwrap_or("?");
                        tracing::warn!("{file}: skipping entry {id:?}: {e}");
                        None
                    }
                }
            })
            .collect();
        let ids: Vec<&str> = entries.iter().map(|e| e.id()).collect();
        let collections = validate_collections(&file, doc.collections, &ids);
        Ok(Checked {
            entries,
            collections,
            version,
        })
    }

    fn floor(&self) -> Option<String> {
        self.min_version.lock().clone()
    }

    fn raise_floor(&self, v: &str) {
        let mut g = self.min_version.lock();
        if g.as_deref()
            .is_none_or(|c| version_cmp(v, c) == Some(Ordering::Greater))
        {
            *g = Some(v.to_string());
        }
    }

    /// Seed the store once from the verified catalogue's `default_enabled` lists (see
    /// [`crate::ListStore::seed_catalogue`]) and rebuild when any was added.
    fn seed(&self, entries: &[E]) {
        let Some(svc) = &self.svc else { return };
        let lists: Vec<_> = entries.iter().filter_map(|e| e.seed_list()).collect();
        match svc.store().seed_catalogue(lists) {
            Ok(added) if !added.is_empty() => {
                tracing::info!("{}: enabled default lists {added:?}", self.kind);
                if tokio::runtime::Handle::try_current().is_ok() {
                    svc.trigger();
                }
            }
            Ok(_) => {}
            Err(e) => tracing::warn!("{}: could not seed lists: {e}", self.kind),
        }
    }

    /// Install the embedded snapshot, verified like fetched data, unless a copy is already in
    /// force. Never replaces a cached or fetched release and respects the downgrade floor.
    pub(crate) fn load_snapshot(&self, snap: &Snapshot) -> Result<(), String> {
        if self.get().is_some() {
            return Ok(());
        }
        // A fetch in progress will install something newer; never race it.
        let Ok(_g) = self.busy.try_lock() else {
            return Ok(());
        };
        if self.get().is_some() {
            return Ok(());
        }
        let cfg = self.cfg();
        let Checked {
            entries,
            collections,
            version,
        } = self.check(&cfg, snap.text, snap.sig, Some((snap.meta, snap.meta_sig)))?;
        if let Some(f) = self.floor() {
            if version_cmp(&version, &f) == Some(Ordering::Less) {
                return Err(format!("snapshot {version} is older than {f}"));
            }
        }
        self.raise_floor(&version);
        self.seed(&entries);
        *self.current.write() = Some(Arc::new(Loaded {
            entries,
            collections,
            origin: Origin::Snapshot,
            version,
            fetched_at: None,
            embedded: true,
        }));
        *self.installed.lock() = Some((snap.text.to_string(), snap.sig.to_string()));
        Ok(())
    }

    /// Load the last good copy from the cache (verified again); when there is none, the embedded
    /// snapshot.
    pub fn init_cache(&self) {
        self.load_cache();
        if self.get().is_none() {
            if let Some(snap) = E::snapshot() {
                if let Err(e) = self.load_snapshot(&snap) {
                    tracing::warn!("{}: ignoring the embedded snapshot: {e}", self.kind);
                }
            }
        }
    }

    fn load_cache(&self) {
        let cfg = self.cfg();
        self.applied_key.lock().clone_from(&cfg.public_key);
        if let Some(v) = Self::path(&cfg, &format!("{}.version", self.kind))
            .and_then(|p| std::fs::read_to_string(p).ok())
        {
            let v = v.trim();
            if version_key(v).is_some() {
                self.raise_floor(v);
            }
        }
        let (Some(tp), Some(sp)) = (
            Self::path(&cfg, &self.file()),
            Self::path(&cfg, &format!("{}.minisig", self.file())),
        ) else {
            return;
        };
        let (Ok(text), Ok(sig)) = (std::fs::read_to_string(&tp), std::fs::read_to_string(sp))
        else {
            return;
        };
        match self.check(&cfg, &text, &sig, None) {
            Ok(Checked {
                entries,
                collections,
                version,
            }) => {
                if let Some(f) = self.floor() {
                    if version_cmp(&version, &f) == Some(Ordering::Less) {
                        tracing::warn!(
                            "{}: ignoring the cached copy ({version} is older than {f})",
                            self.kind
                        );
                        return;
                    }
                }
                self.raise_floor(&version);
                self.seed(&entries);
                // The real fetch time survives a restart: the file was written when it was fetched.
                let fetched_at = std::fs::metadata(&tp)
                    .and_then(|m| m.modified())
                    .map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339())
                    .unwrap_or_else(|_| now_rfc3339());
                *self.current.write() = Some(Arc::new(Loaded {
                    entries,
                    collections,
                    origin: Origin::Cache,
                    version,
                    fetched_at: Some(fetched_at),
                    embedded: false,
                }));
                *self.installed.lock() = Some((text, sig));
            }
            Err(e) => tracing::warn!("{}: ignoring the cached copy: {e}", self.kind),
        }
    }

    /// Fetch, verify and install the newest copy. Returns the release in force. The outcome is
    /// recorded in [`Self::status`]; a failure is logged at warn once per distinct message.
    pub async fn refresh(&self) -> Result<String, String> {
        let r = self.refresh_inner().await;
        let now = now_rfc3339();
        let mut c = self.checks.lock();
        c.last_checked = Some(now.clone());
        match &r {
            Ok(_) => {
                c.last_ok = Some(now);
                c.last_error = None;
            }
            Err(e) => {
                if c.last_error.as_deref() != Some(e.as_str()) {
                    tracing::warn!("{} catalogue: {e}", self.kind);
                }
                c.last_error = Some(e.clone());
            }
        }
        r
    }

    async fn refresh_inner(&self) -> Result<String, String> {
        let svc = self.svc.as_ref().ok_or("no fetcher")?;
        // One check at a time, and the config is read under the lock so a refresh that waited
        // never installs with a key that has since been replaced.
        let _g = self.busy.lock().await;
        let cfg = self.cfg();
        // A key change drops what the old key vouched for even if the new source is down.
        self.sync_key(&cfg);
        let file = self.file();
        let text = svc.fetch_exclusion_list(&Self::url(&cfg, &file)).await?;
        let sig = svc
            .fetch_exclusion_list(&Self::url(&cfg, &format!("{file}.minisig")))
            .await?;
        // The signed meta.json is a cross-check; the file's own signature still protects us.
        let cache = svc.meta_cache();
        let fetch_meta = || async {
            let t = svc
                .fetch_exclusion_list(&Self::url(&cfg, "meta.json"))
                .await?;
            let s = svc
                .fetch_exclusion_list(&Self::url(&cfg, "meta.json.minisig"))
                .await?;
            Ok::<_, String>((t, s))
        };
        let (meta, shared) = match cache.get_or_fetch(&cfg, fetch_meta).await {
            Ok((m, hit)) => (Some(m), hit),
            Err(_) => (None, false),
        };
        let r = self
            .apply_locked(&cfg, text.clone(), sig.clone(), meta)
            .await;
        if r.is_err() {
            cache.invalidate(&cfg).await;
            if shared {
                // The shared meta may predate a release published since: retry once with a fresh one.
                let meta = cache.get_or_fetch(&cfg, fetch_meta).await.ok().map(|x| x.0);
                return self.apply_locked(&cfg, text, sig, meta).await;
            }
        }
        r
    }

    /// Verify and install a copy already in hand (also what tests drive).
    pub async fn apply(
        &self,
        text: String,
        sig: String,
        meta: Option<(String, String)>,
    ) -> Result<String, String> {
        let _g = self.busy.lock().await;
        let cfg = self.cfg();
        self.apply_locked(&cfg, text, sig, meta).await
    }

    /// [`Self::apply`] with `busy` already held and the configuration read under it.
    async fn apply_locked(
        &self,
        cfg: &ArgusConfig,
        text: String,
        sig: String,
        meta: Option<(String, String)>,
    ) -> Result<String, String> {
        self.sync_key(cfg);
        let Checked {
            entries,
            collections,
            version,
        } = self.check(
            cfg,
            &text,
            &sig,
            meta.as_ref().map(|(a, b)| (a.as_str(), b.as_str())),
        )?;
        if let Some(f) = self.floor() {
            if version_cmp(&version, &f) == Some(Ordering::Less) {
                return Err(format!(
                    "{}: release {version} is older than {f}, the newest ever accepted",
                    self.file()
                ));
            }
        }
        self.raise_floor(&version);
        self.seed(&entries);
        *self.current.write() = Some(Arc::new(Loaded {
            entries,
            collections,
            origin: Origin::Fetched,
            version: version.clone(),
            fetched_at: Some(now_rfc3339()),
            embedded: false,
        }));
        *self.installed.lock() = Some((text.clone(), sig.clone()));
        if let (Some(vp), Some(tp), Some(sp)) = (
            Self::path(cfg, &format!("{}.version", self.kind)),
            Self::path(cfg, &self.file()),
            Self::path(cfg, &format!("{}.minisig", self.file())),
        ) {
            let w = |p: PathBuf, b: &[u8]| common::config::write_atomic(&p, b);
            // Version first, signature last: a half-written cache fails verification.
            let r = w(vp, version.as_bytes())
                .and_then(|_| w(tp, text.as_bytes()))
                .and_then(|_| w(sp, sig.as_bytes()));
            if let Err(e) = r {
                tracing::warn!("{}: could not cache {version}: {e}", self.kind);
            }
        }
        Ok(version)
    }

    /// Load the cache, then keep the document current (backoff until the first success).
    pub fn start(self: &Arc<Self>) {
        self.init_cache();
        let this = self.clone();
        tokio::spawn(async move {
            let mut backoff = Duration::from_secs(10);
            loop {
                let wait = match this.refresh().await {
                    Ok(v) => {
                        backoff = Duration::from_secs(10);
                        tracing::info!("{} catalogue: {v}", this.kind);
                        CHECK_EVERY
                    }
                    // A verified copy is in force: retry on the normal schedule.
                    Err(_) if this.get().is_some() => CHECK_EVERY,
                    Err(_) => {
                        let w = backoff;
                        backoff = (backoff * 2).min(Duration::from_secs(900));
                        w
                    }
                };
                this.checks.lock().next_check = chrono::Duration::from_std(wait)
                    .ok()
                    .map(|d| (chrono::Utc::now() + d).to_rfc3339());
                tokio::select! {
                    _ = tokio::time::sleep(wait) => {}
                    _ = this.wake.notified() => {}
                }
            }
        });
    }
}

/// Test support: a signing key and signed fixtures (no network).
#[cfg(any(test, feature = "testkit"))]
pub mod testkit {
    use std::io::Cursor;

    pub struct Signer {
        pk: minisign::PublicKeyBox,
        sk: minisign::SecretKey,
    }

    impl Signer {
        pub fn new() -> Self {
            let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
            Self {
                pk: kp.pk.to_box().unwrap(),
                sk: kp.sk,
            }
        }

        /// The base64 public key line.
        pub fn public_key(&self) -> String {
            self.pk.to_string().lines().nth(1).unwrap().to_string()
        }

        /// A `.minisig` over `data` whose trusted comment names `release` and `file`.
        pub fn sign(&self, data: &str, release: &str, file: &str) -> String {
            self.sign_comment(data, &format!("argus-lists {release} {file}"))
        }

        /// A `.minisig` over `data` with exactly this trusted comment.
        pub fn sign_comment(&self, data: &str, comment: &str) -> String {
            let pk = self.pk.clone().into_public_key().unwrap();
            minisign::sign(
                Some(&pk),
                &self.sk,
                Cursor::new(data.as_bytes()),
                Some(comment),
                None,
            )
            .unwrap()
            .to_string()
        }

        /// Signed `meta.json` (and signature) listing `kind` with the digest of `doc`.
        pub fn meta(&self, release: &str, kind: &str, doc: &str) -> (String, String) {
            let sha = super::sha256_hex(doc.as_bytes());
            let m = format!(
                r#"{{"version":"{release}","categories":[],"catalogues":[{{"kind":"{kind}","file":"{kind}.json","sha256":"{sha}","entries":1}}]}}"#
            );
            let s = self.sign(&m, release, "meta.json");
            (m, s)
        }
    }

    impl Default for Signer {
        fn default() -> Self {
            Self::new()
        }
    }

    /// A one-entry `filters.json`.
    pub fn filters_json(format: &str) -> String {
        format!(
            r#"{{"schema":1,"kind":"filters","entries":[{{"id":"fx","name":"Fx","description":"d","url":"https://example.test/fx.txt","format":"{format}","category":"ads","licence":"MIT","homepage":"https://example.test","region":"de","noncommercial":true}}]}}"#
        )
    }

    /// A `filters.json` of lists `a` (trusted), `b` and `c` (not) with this raw `collections` array.
    pub fn filters_with_collections(collections: &str) -> String {
        let e = |id: &str, trusted: bool| {
            format!(
                r#"{{"id":"{id}","name":"List {id}","url":"https://127.0.0.1:1/{id}.txt","format":"abp","category":"ads","trusted":{trusted}}}"#
            )
        };
        format!(
            r#"{{"schema":1,"kind":"filters","entries":[{},{},{}],"collections":{collections}}}"#,
            e("a", true),
            e("b", false),
            e("c", false)
        )
    }

    /// A one-entry `userscripts.json`.
    pub fn userscripts_json(install_url: &str) -> String {
        format!(
            r#"{{"schema":1,"kind":"userscripts","entries":[{{"id":"us1","name":"Us","description":"d","install_url":"{install_url}","homepage":"https://example.test","sites":["*"],"category":"ads","licence":"MIT","needs_gm":"none","connect":[],"requires":[]}}]}}"#
        )
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;

    fn doc(
        signer: &Signer,
        kind: &'static str,
        dir: Option<&std::path::Path>,
    ) -> Arc<SignedDoc<FilterCatalogueEntry>> {
        SignedDoc::new(
            kind,
            None,
            ArgusConfig {
                base_url: "http://unused.test".into(),
                public_key: signer.public_key(),
                cache_dir: dir.map(|d| d.to_path_buf()),
            },
        )
    }

    #[tokio::test]
    async fn a_signed_document_loads_with_its_release_and_maps_formats() {
        let s = Signer::new();
        let d = doc(&s, "filters", None);
        let text = filters_json("ubo");
        let sig = s.sign(&text, "v2026.11.23", "filters.json");
        let meta = s.meta("v2026.11.23", "filters", &text);
        assert_eq!(d.apply(text, sig, Some(meta)).await.unwrap(), "v2026.11.23");
        let l = d.get().unwrap();
        assert_eq!(
            l.entries[0].list_format(),
            Some(filter_engine::ListFormat::Ubo)
        );
        for (f, want) in [
            ("abp", filter_engine::ListFormat::Abp),
            ("adguard", filter_engine::ListFormat::Adguard),
            ("hosts", filter_engine::ListFormat::Hosts),
            ("domains", filter_engine::ListFormat::Domains),
            ("ips", filter_engine::ListFormat::IpList),
        ] {
            let mut e = l.entries[0].clone();
            e.format = f.into();
            assert_eq!(e.list_format(), Some(want));
        }
        let mut e = l.entries[0].clone();
        e.format = "clash".into();
        assert_eq!(e.list_format(), None);
    }

    #[tokio::test]
    async fn a_bad_signature_or_wrong_key_is_refused_and_nothing_loads() {
        let (s, other) = (Signer::new(), Signer::new());
        let d = doc(&s, "filters", None);
        let text = filters_json("abp");
        let sig = other.sign(&text, "v2026.11.23", "filters.json");
        assert!(d.apply(text.clone(), sig, None).await.is_err());
        let sig = s.sign(&text, "v2026.11.23", "filters.json");
        assert!(d.apply(format!("{text} "), sig, None).await.is_err());
        assert!(d.get().is_none());
    }

    fn seeded_json() -> String {
        let e = |id: &str, extra: &str| {
            format!(
                r#"{{"id":"{id}","name":"{id}","url":"https://example.test/{id}.txt","format":"abp","category":"ads"{extra}}}"#
            )
        };
        format!(
            r#"{{"schema":1,"kind":"filters","entries":[{},{},{},{}]}}"#,
            e("d1", r#","default_enabled":true,"trusted":true"#),
            e("d2", r#","default_enabled":true,"profile":"strict""#),
            e("x1", r#","default_enabled":null"#),
            e("p1", "")
        )
    }

    fn test_cfg(s: &Signer) -> ArgusConfig {
        ArgusConfig {
            base_url: String::new(),
            public_key: s.public_key(),
            cache_dir: None,
        }
    }

    #[tokio::test]
    async fn default_enabled_entries_seed_once_and_a_removed_list_stays_removed() {
        let s = Signer::new();
        let (_d, svc) = svc();
        let d = SignedDoc::<FilterCatalogueEntry>::new("filters", Some(svc.clone()), test_cfg(&s));
        let store = svc.store();
        assert!(store.get("d1").unwrap().is_none(), "fail-safe before load");
        let text = seeded_json();
        let sig = s.sign(&text, "v2026.11.23", "filters.json");
        d.apply(text.clone(), sig, None).await.unwrap();
        let ids: Vec<_> = store.get_all().unwrap().into_iter().map(|l| l.id).collect();
        assert_eq!(ids, ["d1", "d2"], "exactly the default_enabled set");
        let d1 = store.get("d1").unwrap().unwrap();
        assert!(d1.enabled && d1.trusted);
        assert!(!store.get("d2").unwrap().unwrap().trusted);
        // The user removes one; a newer release does not bring it back.
        store.remove("d1").unwrap();
        let sig = s.sign(&text, "v2026.11.24", "filters.json");
        d.apply(text, sig, None).await.unwrap();
        assert!(store.get("d1").unwrap().is_none());
    }

    #[tokio::test]
    async fn a_populated_store_is_not_seeded() {
        let s = Signer::new();
        let (_d, svc) = svc();
        let mine =
            filter_engine::FilterList::new("mine".into(), "Mine".into(), "https://e/m".into());
        svc.store().upsert(&mine).unwrap();
        let d = SignedDoc::<FilterCatalogueEntry>::new("filters", Some(svc.clone()), test_cfg(&s));
        let text = seeded_json();
        let sig = s.sign(&text, "v2026.11.23", "filters.json");
        d.apply(text, sig, None).await.unwrap();
        let ids: Vec<_> = svc
            .store()
            .get_all()
            .unwrap()
            .into_iter()
            .map(|l| l.id)
            .collect();
        assert_eq!(ids, ["mine"]);
    }

    fn real_cfg() -> ArgusConfig {
        ArgusConfig {
            base_url: String::new(),
            public_key: common::bypass::ARGUS_LISTS_PUBLIC_KEY.to_string(),
            cache_dir: None,
        }
    }

    #[test]
    fn the_embedded_snapshot_verifies_with_the_compiled_in_key() {
        let d = SignedDoc::<FilterCatalogueEntry>::new("filters", None, real_cfg());
        d.load_snapshot(&FILTERS_SNAPSHOT).unwrap();
        let l = d.get().unwrap();
        assert!(l.embedded && l.fetched_at.is_none());
        assert!(l.version.starts_with('v'));
        assert!(l.entries.iter().any(|e| e.default_enabled));
        assert!(l.entries.iter().any(|e| !e.default_enabled));
    }

    #[test]
    fn the_embedded_snapshot_exposes_its_two_collections() {
        let d = SignedDoc::<FilterCatalogueEntry>::new("filters", None, real_cfg());
        d.load_snapshot(&FILTERS_SNAPSHOT).unwrap();
        let l = d.get().unwrap();
        let ids: Vec<_> = l.collections.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, ["recommended", "annoyances-social"]);
        let entry_ids: std::collections::HashSet<_> =
            l.entries.iter().map(|e| e.id.as_str()).collect();
        // Nothing was dropped on load: the signed document lists only known ids.
        let raw: serde_json::Value = serde_json::from_str(FILTERS_SNAPSHOT.text).unwrap();
        for c in &l.collections {
            assert!(c.lists.iter().all(|i| entry_ids.contains(i.as_str())));
            let n = raw["collections"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["id"] == c.id.as_str())
                .unwrap()["lists"]
                .as_array()
                .unwrap()
                .len();
            assert_eq!(c.lists.len(), n, "{}", c.id);
        }
        let mut rec = l.collections[0].lists.clone();
        let mut def: Vec<_> = l
            .entries
            .iter()
            .filter(|e| e.default_enabled)
            .map(|e| e.id.clone())
            .collect();
        rec.sort();
        def.sort();
        assert_eq!(rec, def, "recommended is the default-enabled set");
        for id in ["adguard-annoyances", "adguard-social"] {
            assert!(l.entries.iter().find(|e| e.id == id).unwrap().trusted);
        }
    }

    #[test]
    fn a_tampered_snapshot_is_rejected() {
        let leak = |s: String| -> &'static str { Box::leak(s.into_boxed_str()) };
        for tamper in 0..3 {
            let mut snap = FILTERS_SNAPSHOT;
            match tamper {
                0 => snap.text = leak(format!("{} ", snap.text)),
                1 => snap.meta = leak(snap.meta.replacen("filters", "filterz", 1)),
                _ => snap.sig = leak(snap.sig.replacen('A', "B", 1)),
            }
            let d = SignedDoc::<FilterCatalogueEntry>::new("filters", None, real_cfg());
            assert!(d.load_snapshot(&snap).is_err(), "tamper {tamper}");
            assert!(d.get().is_none());
        }
    }

    #[test]
    fn a_snapshot_signed_by_another_key_is_rejected() {
        let d = SignedDoc::<FilterCatalogueEntry>::new("filters", None, test_cfg(&Signer::new()));
        assert!(d.load_snapshot(&FILTERS_SNAPSHOT).is_err());
    }

    #[tokio::test]
    async fn first_boot_without_network_seeds_the_snapshots_default_set() {
        let (_d, svc) = svc();
        let d = SignedDoc::<FilterCatalogueEntry>::new("filters", Some(svc.clone()), real_cfg());
        d.init_cache();
        let loaded = d.get().expect("snapshot in force");
        let want: std::collections::BTreeSet<_> = loaded
            .entries
            .iter()
            .filter(|e| e.default_enabled)
            .map(|e| e.id.clone())
            .collect();
        assert!(!want.is_empty());
        let all = svc.store().get_all().unwrap();
        let got: std::collections::BTreeSet<_> = all.iter().map(|l| l.id.clone()).collect();
        assert_eq!(got, want);
        assert!(all.iter().all(|l| l.enabled));
        // A second start (restart) changes nothing, even after a removal.
        let victim = want.iter().next().unwrap().clone();
        svc.store().remove(&victim).unwrap();
        let d2 = SignedDoc::<FilterCatalogueEntry>::new("filters", Some(svc.clone()), real_cfg());
        d2.init_cache();
        assert!(svc.store().get(&victim).unwrap().is_none());
    }

    #[tokio::test]
    async fn a_newer_cache_beats_the_snapshot() {
        let s = Signer::new();
        let dir = tempfile::tempdir().unwrap();
        let text = filters_json("abp");
        let sig = s.sign(&text, "v2099.01.01", "filters.json");
        let d = doc(&s, "filters", Some(dir.path()));
        d.apply(text, sig, None).await.unwrap();
        // Restart: the cache loads, and the snapshot (signed by the same test key) is not used.
        let again = doc(&s, "filters", Some(dir.path()));
        again.load_cache();
        assert_eq!(again.get().unwrap().version, "v2099.01.01");
        again.load_snapshot(&FILTERS_SNAPSHOT).unwrap();
        assert_eq!(again.get().unwrap().version, "v2099.01.01");
        // Nor can an older fetched release replace it.
        let text = filters_json("abp");
        let sig = s.sign(&text, "v2026.11.27.4", "filters.json");
        assert!(again.apply(text, sig, None).await.is_err());
    }

    #[tokio::test]
    async fn a_kind_mismatch_is_refused() {
        let s = Signer::new();
        let d = doc(&s, "userscripts", None);
        let text = filters_json("abp");
        let sig = s.sign(&text, "v2026.11.23", "userscripts.json");
        let e = d.apply(text, sig, None).await.unwrap_err();
        assert!(e.contains("kind"), "{e}");
    }

    #[tokio::test]
    async fn a_digest_that_disagrees_with_the_signed_meta_is_refused() {
        let s = Signer::new();
        let d = doc(&s, "filters", None);
        let text = filters_json("abp");
        let sig = s.sign(&text, "v2026.11.23", "filters.json");
        let meta = s.meta("v2026.11.23", "filters", "something else");
        let e = d.apply(text, sig, Some(meta)).await.unwrap_err();
        assert!(e.contains("digest"), "{e}");
    }

    #[tokio::test]
    async fn an_older_release_is_refused_and_survives_a_lost_cache() {
        let s = Signer::new();
        let dir = tempfile::tempdir().unwrap();
        let d = doc(&s, "filters", Some(dir.path()));
        let text = filters_json("abp");
        let new = s.sign(&text, "v2026.11.23", "filters.json");
        let old = s.sign(&text, "v2026.11.22", "filters.json");
        d.apply(text.clone(), new, None).await.unwrap();
        let e = d.apply(text.clone(), old.clone(), None).await.unwrap_err();
        assert!(e.contains("older"), "{e}");
        // A restart reloads the verified cache and still refuses the older release, even with the
        // cached document gone.
        std::fs::remove_file(dir.path().join("filters.json")).unwrap();
        let d2 = doc(&s, "filters", Some(dir.path()));
        d2.init_cache();
        assert!(d2.get().is_none());
        assert!(d2.apply(text, old, None).await.is_err());
    }

    #[tokio::test]
    async fn the_verified_cache_reloads_and_a_tampered_one_does_not() {
        let s = Signer::new();
        let dir = tempfile::tempdir().unwrap();
        let text = filters_json("abp");
        let sig = s.sign(&text, "v2026.11.23", "filters.json");
        doc(&s, "filters", Some(dir.path()))
            .apply(text, sig, None)
            .await
            .unwrap();
        let d = doc(&s, "filters", Some(dir.path()));
        d.init_cache();
        assert_eq!(d.get().unwrap().version, "v2026.11.23");
        std::fs::write(dir.path().join("filters.json"), filters_json("hosts")).unwrap();
        let d = doc(&s, "filters", Some(dir.path()));
        d.init_cache();
        assert!(d.get().is_none());
    }

    async fn load_collections(raw: &str) -> Vec<Collection> {
        let s = Signer::new();
        let d = doc(&s, "filters", None);
        let text = filters_with_collections(raw);
        let sig = s.sign(&text, "v2026.11.23", "filters.json");
        d.apply(text, sig, None).await.unwrap();
        d.get().unwrap().collections.clone()
    }

    #[tokio::test]
    async fn collections_load_and_unknown_ids_and_empty_collections_are_dropped() {
        let cs = load_collections(
            r#"[{"id":"rec","name":"Recommended","description":"d","warning":"may break","lists":["a","b"]},
                {"id":"mix","name":"Mixed","lists":["c","nope","c"]},
                {"id":"ghost","name":"Ghost","lists":["nope"]},
                {"id":"rec","name":"Dup","lists":["a"]},
                {"id":"bad","lists":["a"]}]"#,
        )
        .await;
        let ids: Vec<_> = cs.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, ["rec", "mix"]);
        assert_eq!(cs[0].warning.as_deref(), Some("may break"));
        assert_eq!(cs[0].lists, ["a", "b"]);
        assert_eq!(cs[1].lists, ["c"], "unknown and repeated ids dropped");
        assert_eq!(cs[1].description, "");
    }

    #[tokio::test]
    async fn an_old_document_without_collections_still_loads() {
        let s = Signer::new();
        let d = doc(&s, "filters", None);
        let text = filters_json("abp");
        assert!(!text.contains("collections"));
        let sig = s.sign(&text, "v2026.11.23", "filters.json");
        d.apply(text, sig, None).await.unwrap();
        let l = d.get().unwrap();
        assert_eq!(l.entries.len(), 1);
        assert!(l.collections.is_empty());
        assert_eq!(
            load_collections("null").await.len(),
            0,
            "a null array is tolerated"
        );
    }

    #[tokio::test]
    async fn fetched_at_is_the_real_fetch_time_and_survives_a_restart() {
        let s = Signer::new();
        let dir = tempfile::tempdir().unwrap();
        let text = filters_json("abp");
        let sig = s.sign(&text, "v2026.11.23", "filters.json");
        let d = doc(&s, "filters", Some(dir.path()));
        d.apply(text, sig, None).await.unwrap();
        assert_eq!(d.get().unwrap().origin, Origin::Fetched);
        // The file was written two days ago: a restart reports that, not "now".
        let when = std::time::SystemTime::now() - Duration::from_secs(2 * 86400);
        let f = std::fs::File::options()
            .write(true)
            .open(dir.path().join("filters.json"))
            .unwrap();
        f.set_modified(when).unwrap();
        drop(f);
        let d = doc(&s, "filters", Some(dir.path()));
        d.init_cache();
        let l = d.get().unwrap();
        assert_eq!(l.origin, Origin::Cache);
        let got = chrono::DateTime::parse_from_rfc3339(l.fetched_at.as_ref().unwrap()).unwrap();
        let want = chrono::DateTime::<chrono::Utc>::from(when);
        assert_eq!(got.timestamp(), want.timestamp());
        assert_eq!(d.status().origin, Some(Origin::Cache));
    }

    #[tokio::test]
    async fn status_shows_a_failed_check_once_and_clears_it_on_success() {
        let s = Signer::new();
        let (_d, svc) = svc();
        let mut cfg = test_cfg(&s);
        cfg.base_url = "http://127.0.0.1:1/".into();
        let d = SignedDoc::<FilterCatalogueEntry>::new("filters", Some(svc.clone()), cfg);
        let st = d.status();
        assert_eq!(st.url, "http://127.0.0.1:1/filters.json");
        assert!(st.last_checked.is_none() && st.last_error.is_none() && st.version.is_none());
        // A verified copy is in force; the check then fails: still served, error visible.
        let text = filters_json("abp");
        let sig = s.sign(&text, "v2026.11.23", "filters.json");
        d.apply(text, sig, None).await.unwrap();
        let err = d.refresh().await.unwrap_err();
        let st = d.status();
        assert_eq!(st.last_error.as_deref(), Some(err.as_str()));
        assert!(st.last_checked.is_some() && st.last_ok.is_none());
        assert_eq!(st.version.as_deref(), Some("v2026.11.23"));
        assert_eq!(st.origin, Some(Origin::Fetched));
        // A working source clears it.
        let (base, _) = serve(release_files(&s, "v2026.11.24")).await;
        let mut cfg = test_cfg(&s);
        cfg.base_url = base;
        d.set_config_source(move || cfg.clone());
        d.refresh().await.unwrap();
        let st = d.status();
        assert!(st.last_error.is_none() && st.last_ok.is_some());
        assert_eq!(st.version.as_deref(), Some("v2026.11.24"));
    }

    #[test]
    fn abp_and_ubo_lists_parse_with_the_mapped_format() {
        use filter_engine::formats::{convert, ConvertOptions};
        let abp = "[Adblock Plus 2.0]\n! Title: t\n||ads.example^\n@@||ok.example^\n";
        let ubo = "! Title: u\n||trk.example^$third-party\nexample.org##+js(set, a, b)\n";
        for (text, fmt) in [
            (abp, filter_engine::ListFormat::Abp),
            (ubo, filter_engine::ListFormat::Ubo),
        ] {
            let c = convert(
                text,
                &ConvertOptions {
                    format: fmt,
                    ..Default::default()
                },
            );
            assert_eq!(c.format, fmt);
            assert!(c.rules.contains("example"), "{:?}", c.rules);
        }
    }

    #[tokio::test]
    async fn meta_that_misses_the_kind_or_names_another_release_is_refused() {
        let s = Signer::new();
        let d = doc(&s, "filters", None);
        let text = filters_json("abp");
        let sig = s.sign(&text, "v2026.11.23", "filters.json");
        // Lists only another kind.
        let other = s.meta("v2026.11.23", "userscripts", &text);
        let e = d
            .apply(text.clone(), sig.clone(), Some(other))
            .await
            .unwrap_err();
        assert!(e.contains("does not list"), "{e}");
        // Right digest, different release.
        let stale = s.meta("v2026.11.22", "filters", &text);
        let e = d.apply(text.clone(), sig, Some(stale)).await.unwrap_err();
        assert!(e.contains("release differs"), "{e}");
        assert!(d.get().is_none());
    }

    #[tokio::test]
    async fn a_comment_without_a_release_or_for_another_file_is_refused() {
        let s = Signer::new();
        let d = doc(&s, "filters", None);
        let text = filters_json("abp");
        let none = s.sign_comment(&text, "argus-lists filters.json");
        let e = d.apply(text.clone(), none, None).await.unwrap_err();
        assert!(e.contains("no release"), "{e}");
        let other = s.sign(&text, "v2026.11.23", "userscripts.json");
        let e = d.apply(text, other, None).await.unwrap_err();
        assert!(e.contains("another file"), "{e}");
    }

    #[tokio::test]
    async fn the_userscripts_document_caches_and_refuses_rollback() {
        let s = Signer::new();
        let dir = tempfile::tempdir().unwrap();
        let mk = || {
            SignedDoc::<UserscriptCatalogueEntry>::new(
                "userscripts",
                None,
                ArgusConfig {
                    base_url: "http://unused.test".into(),
                    public_key: s.public_key(),
                    cache_dir: Some(dir.path().to_path_buf()),
                },
            )
        };
        let text = userscripts_json("https://example.test/a.user.js");
        let new = s.sign(&text, "v2026.11.23", "userscripts.json");
        let old = s.sign(&text, "v2026.11.22", "userscripts.json");
        let d = mk();
        d.apply(text.clone(), new, None).await.unwrap();
        assert!(d.apply(text, old, None).await.is_err());
        let d2 = mk();
        d2.init_cache();
        let l = d2.get().unwrap();
        assert_eq!(
            (l.version.as_str(), l.entries[0].id.as_str()),
            ("v2026.11.23", "us1")
        );
    }

    async fn load_filters(entries: &str) -> Vec<String> {
        let s = Signer::new();
        let d = doc(&s, "filters", None);
        let text = format!(r#"{{"schema":1,"kind":"filters","entries":[{entries}]}}"#);
        let sig = s.sign(&text, "v2026.11.23", "filters.json");
        d.apply(text, sig, None).await.unwrap();
        d.get()
            .unwrap()
            .entries
            .iter()
            .map(|e| e.id.clone())
            .collect()
    }

    #[tokio::test]
    async fn one_bad_entry_never_drops_the_document() {
        let ok = r#"{"id":"ok","name":"Ok","url":"https://x.test/a.txt","format":"abp","category":"ads","licence":null,"homepage":null,"description":null,"region":null,"licence_note":null}"#;
        let bad = [
            r#"{"id":"nourl","name":"N","format":"abp","category":"ads"}"#,
            r#"{"id":"nullurl","name":"N","url":null,"format":"abp","category":"ads"}"#,
            r#"{"name":"noid","url":"https://x.test/a","format":"abp","category":"ads"}"#,
            r#"{"id":"nocat","name":"N","url":"https://x.test/a","format":"abp","category":""}"#,
            r#"{"id":"http","name":"N","url":"http://x.test/a","format":"abp","category":"ads"}"#,
            r#"{"id":"fmt","name":"N","url":"https://x.test/a","format":"zip","category":"ads"}"#,
            r#"{"id":"","name":"N","url":"https://x.test/a","format":"abp","category":"ads"}"#,
        ];
        let all = format!("{},{ok}", bad.join(","));
        assert_eq!(load_filters(&all).await, vec!["ok"]);
    }

    #[tokio::test]
    async fn a_userscript_entry_without_an_https_install_url_is_skipped() {
        let s = Signer::new();
        let d = SignedDoc::<UserscriptCatalogueEntry>::new(
            "userscripts",
            None,
            ArgusConfig {
                base_url: "http://unused.test".into(),
                public_key: s.public_key(),
                cache_dir: None,
            },
        );
        let text = r#"{"schema":1,"kind":"userscripts","entries":[{"id":"a","name":"A","install_url":null,"category":"ads"},{"id":"b","name":"B","install_url":"http://x.test/b.user.js","category":"ads"},{"id":"c","name":"C","install_url":"https://x.test/c.user.js","category":"ads","licence":null}]}"#.to_string();
        let sig = s.sign(&text, "v2026.11.23", "userscripts.json");
        d.apply(text, sig, None).await.unwrap();
        let ids: Vec<_> = d
            .get()
            .unwrap()
            .entries
            .iter()
            .map(|e| e.id.clone())
            .collect();
        assert_eq!(ids, vec!["c"]);
    }

    #[test]
    fn a_null_field_in_an_entry_reads_as_empty() {
        let e: UserscriptCatalogueEntry = serde_json::from_str(
            r#"{"id":"a","name":"A","install_url":"https://x.test/a.user.js","category":"ads","licence":null,"homepage":null,"sites":null}"#,
        )
        .unwrap();
        assert_eq!((e.licence.as_str(), e.sites.len()), ("", 0));
    }

    #[tokio::test]
    async fn a_key_change_reverifies_the_installed_copy_and_drops_it_on_failure() {
        let (a, b) = (Signer::new(), Signer::new());
        let d = doc(&a, "filters", None);
        let text = filters_json("abp");
        d.apply(
            text.clone(),
            a.sign(&text, "v2026.11.23", "filters.json"),
            None,
        )
        .await
        .unwrap();
        assert!(d.get().is_some());
        // Same key again (a URL-only change): the copy stays.
        let key_a = a.public_key();
        d.set_config_source(move || ArgusConfig {
            base_url: "http://mirror.test".into(),
            public_key: key_a.clone(),
            cache_dir: None,
        });
        let older = a.sign(&text, "v2026.11.01", "filters.json");
        assert!(d.apply(text.clone(), older, None).await.is_err());
        assert!(d.get().is_some());
        // Another key: the installed copy no longer verifies and is dropped; the floor stays.
        let key_b = b.public_key();
        d.set_config_source(move || ArgusConfig {
            base_url: "http://mirror.test".into(),
            public_key: key_b.clone(),
            cache_dir: None,
        });
        let older = b.sign(&text, "v2026.11.01", "filters.json");
        assert!(d.apply(text.clone(), older, None).await.is_err());
        assert!(d.get().is_none());
        assert!(d
            .apply(
                text.clone(),
                b.sign(&text, "v2026.11.24", "filters.json"),
                None
            )
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn racing_applies_with_different_keys_resolve_to_the_new_key() {
        let (a, b) = (Signer::new(), Signer::new());
        let d = doc(&a, "filters", None);
        let text = filters_json("abp");
        let key_b = b.public_key();
        // The key was replaced; a straggler still carrying the old key's document must lose.
        d.set_config_source(move || ArgusConfig {
            base_url: "http://unused.test".into(),
            public_key: key_b.clone(),
            cache_dir: None,
        });
        let old = d.apply(
            text.clone(),
            a.sign(&text, "v2026.11.23", "filters.json"),
            None,
        );
        let new = d.apply(
            text.clone(),
            b.sign(&text, "v2026.11.24", "filters.json"),
            None,
        );
        let (old, new) = tokio::join!(old, new);
        assert!(old.is_err());
        assert_eq!(new.unwrap(), "v2026.11.24");
        assert_eq!(d.get().unwrap().version, "v2026.11.24");
    }

    #[tokio::test]
    async fn the_live_config_source_changes_the_key_without_a_restart() {
        let (a, b) = (Signer::new(), Signer::new());
        let d = doc(&a, "filters", None);
        let text = filters_json("abp");
        let sig = b.sign(&text, "v2026.11.23", "filters.json");
        assert!(d.apply(text.clone(), sig.clone(), None).await.is_err());
        let key = b.public_key();
        d.set_config_source(move || ArgusConfig {
            base_url: "http://unused.test".into(),
            public_key: key.clone(),
            cache_dir: None,
        });
        assert!(d.apply(text, sig, None).await.is_ok());
    }

    /// Serve `files` over loopback http; returns the base URL and the `meta.json` request count.
    async fn serve(
        files: std::collections::HashMap<String, String>,
    ) -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let metas = Arc::new(AtomicUsize::new(0));
        let m2 = metas.clone();
        let files = Arc::new(files);
        let app = axum::Router::new().fallback(move |uri: axum::http::Uri| {
            let (files, m2) = (files.clone(), m2.clone());
            async move {
                let name = uri.path().trim_start_matches('/').to_string();
                if name == "meta.json" {
                    m2.fetch_add(1, Ordering::SeqCst);
                }
                match files.get(&name) {
                    Some(b) => (axum::http::StatusCode::OK, b.clone()),
                    None => (axum::http::StatusCode::NOT_FOUND, String::new()),
                }
            }
        });
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(l, app).await;
        });
        (format!("http://{addr}"), metas)
    }

    fn svc() -> (tempfile::TempDir, Arc<ListService>) {
        let d = tempfile::tempdir().unwrap();
        let store = crate::ListStore::open(&d.path().join("store")).unwrap();
        let svc = ListService::new(
            crate::ListServiceConfig::default(),
            store,
            Arc::new(filter_engine::SharedEngine::new()),
            reqwest::Client::new(),
        );
        (d, svc)
    }

    fn release_files(s: &Signer, release: &str) -> std::collections::HashMap<String, String> {
        let text = filters_json("ubo");
        let (meta, meta_sig) = s.meta(release, "filters", &text);
        [
            (
                "filters.json.minisig",
                s.sign(&text, release, "filters.json"),
            ),
            ("filters.json", text),
            ("meta.json", meta),
            ("meta.json.minisig", meta_sig),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect()
    }

    #[tokio::test]
    async fn a_stale_shared_meta_is_refetched_once_and_the_refresh_succeeds() {
        let s = Signer::new();
        let (_d, svc) = svc();
        let (base, metas) = serve(release_files(&s, "v2026.11.24")).await;
        let cfg = ArgusConfig {
            base_url: base,
            public_key: s.public_key(),
            cache_dir: None,
        };
        // A validly signed meta for the previous release is still in the shared cache.
        let (old_meta, old_sig) = s.meta("v2026.11.23", "filters", &filters_json("abp"));
        svc.meta_cache().put(&cfg, (old_meta, old_sig)).await;
        let d = SignedDoc::<FilterCatalogueEntry>::new("filters", Some(svc.clone()), cfg);
        assert_eq!(d.refresh().await.unwrap(), "v2026.11.24");
        assert_eq!(
            metas.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "one fresh meta fetch after the stale copy failed"
        );
    }

    #[tokio::test]
    async fn two_catalogues_share_one_meta_fetch() {
        let s = Signer::new();
        let (_d, svc) = svc();
        let (base, metas) = serve(release_files(&s, "v2026.11.24")).await;
        let cfg = ArgusConfig {
            base_url: base,
            public_key: s.public_key(),
            cache_dir: None,
        };
        let a = SignedDoc::<FilterCatalogueEntry>::new("filters", Some(svc.clone()), cfg.clone());
        a.refresh().await.unwrap();
        let b = SignedDoc::<FilterCatalogueEntry>::new("filters", Some(svc), cfg);
        b.refresh().await.unwrap();
        assert_eq!(metas.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}

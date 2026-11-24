//! First-party bypass lists (argus-lists): fetched from a release, verified against a compiled-in
//! minisign public key, cached on the data volume and never replaced by an older version.
//!
//! Until every enabled `argus:*` list has loaded once (from the network or the verified cache) the
//! bypass engine's fail-safe keeps HTTPS undecrypted, so a failed first download can never expose
//! banking or health traffic to interception.

use std::cmp::Ordering;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use common::bypass::{self, BypassEngine, BypassMode, FIRST_PARTY};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::ListService;

/// Most hosts accepted from one list.
const MAX_HOSTS: usize = 500_000;
/// Between successful checks.
const CHECK_EVERY: Duration = Duration::from_secs(6 * 3600);

/// Where to fetch from and what to trust.
#[derive(Debug, Clone)]
pub struct ArgusConfig {
    /// Directory holding `<id>.txt`, `<id>.txt.minisig`, `meta.json`, `meta.json.minisig`.
    pub base_url: String,
    /// Minisign public key (the base64 line).
    pub public_key: String,
    /// Where the last good verified copy is kept (`None`: not cached).
    pub cache_dir: Option<PathBuf>,
}

impl ArgusConfig {
    /// The built-in location and key, with the config's overrides applied.
    pub fn from_config(c: &common::config::BypassConfig, cache_dir: Option<PathBuf>) -> Self {
        let pick = |v: &str, d: &str| {
            if v.trim().is_empty() {
                d.to_string()
            } else {
                v.trim().to_string()
            }
        };
        Self {
            base_url: pick(&c.lists_base_url, bypass::ARGUS_LISTS_BASE_URL),
            public_key: pick(&c.lists_public_key, bypass::ARGUS_LISTS_PUBLIC_KEY),
            cache_dir,
        }
    }
}

/// Verify `sig_text` (a `.minisig` file) over `data` with `public_key` (base64). Only prehashed
/// (`ED`) minisign signatures made with that key's id are accepted.
pub fn verify(public_key: &str, data: &[u8], sig_text: &str) -> Result<(), String> {
    let pk = minisign_verify::PublicKey::from_base64(public_key.trim())
        .map_err(|e| format!("invalid public key: {e}"))?;
    let sig = minisign_verify::Signature::decode(sig_text)
        .map_err(|e| format!("invalid signature file: {e}"))?;
    // Releases are signed by the minisign CLI, which prehashes ("ED"); the legacy un-hashed
    // kind is refused. The verifier also rejects a signature whose key id is not the key's.
    pk.verify(data, &sig, false)
        .map_err(|e| format!("signature does not verify: {e}"))
}

/// Like [`verify`], and returns the signed (trusted) comment.
pub fn verify_trusted(public_key: &str, data: &[u8], sig_text: &str) -> Result<String, String> {
    verify(public_key, data, sig_text)?;
    let sig = minisign_verify::Signature::decode(sig_text)
        .map_err(|e| format!("invalid signature file: {e}"))?;
    Ok(sig.trusted_comment().to_string())
}

/// `vYYYY.MM.DD[.N]` as comparable numbers.
pub(crate) fn version_key(v: &str) -> Option<Vec<u64>> {
    let rest = v.strip_prefix('v')?;
    let parts: Option<Vec<u64>> = rest.split('.').map(|p| p.parse().ok()).collect();
    parts.filter(|p| p.len() >= 3)
}

/// The newer of two release versions (an unparsable one loses).
fn max_version(a: Option<String>, b: Option<String>) -> Option<String> {
    match (a, b) {
        (Some(x), Some(y)) => match version_cmp(&x, &y) {
            Some(Ordering::Less) => Some(y),
            _ => Some(x),
        },
        (x, None) => x,
        (None, y) => y,
    }
}

/// Compare two release versions (a missing `.N` is `.0`).
pub(crate) fn version_cmp(a: &str, b: &str) -> Option<Ordering> {
    let (mut a, mut b) = (version_key(a)?, version_key(b)?);
    let n = a.len().max(b.len());
    a.resize(n, 0);
    b.resize(n, 0);
    Some(a.cmp(&b))
}

#[derive(Debug, Deserialize)]
struct Meta {
    version: String,
    /// Wildcards the first-party lists may use despite covering a whole public suffix (signed
    /// together with the rest of `meta.json`); sanitised before use.
    #[serde(default)]
    allowed_wildcards: Vec<String>,
    categories: Vec<MetaCategory>,
}

#[derive(Debug, Deserialize)]
struct MetaCategory {
    id: String,
    name: String,
    description: String,
    default_mode: BypassMode,
    sha256: String,
}

/// What a refresh did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// New lists were installed.
    Installed { version: String },
    /// The release is the one already installed and everything is loaded.
    Current { version: String },
}

pub struct ArgusLists {
    engine: Arc<BypassEngine>,
    svc: Arc<ListService>,
    cfg: parking_lot::RwLock<Arc<dyn Fn() -> ArgusConfig + Send + Sync>>,
    /// One check at a time.
    busy: tokio::sync::Mutex<()>,
    wake: tokio::sync::Notify,
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    common::config::write_atomic(path, bytes).map_err(|e| e.to_string())
}

impl ArgusLists {
    pub fn new(engine: Arc<BypassEngine>, svc: Arc<ListService>, cfg: ArgusConfig) -> Arc<Self> {
        Arc::new(Self {
            engine,
            svc,
            cfg: parking_lot::RwLock::new(Arc::new(move || cfg.clone())),
            busy: tokio::sync::Mutex::new(()),
            wake: tokio::sync::Notify::new(),
        })
    }

    /// Read the base URL, key and cache directory from `f` on every use (the live config), so a
    /// change in the UI applies on the next refresh without a restart.
    pub fn set_config_source(&self, f: impl Fn() -> ArgusConfig + Send + Sync + 'static) {
        *self.cfg.write() = Arc::new(f);
    }

    fn cfg(&self) -> ArgusConfig {
        let f = self.cfg.read().clone();
        f()
    }

    fn url(&self, file: &str) -> String {
        format!("{}/{file}", self.cfg().base_url.trim_end_matches('/'))
    }

    /// Check again soon (a category was enabled, or the user asked).
    pub fn nudge(&self) {
        self.wake.notify_one();
    }

    /// Load the last good copy from the cache: every file is verified again against the key (and
    /// the signed `meta.json` digests), so a tampered or stale-keyed cache loads nothing.
    pub fn init_cache(&self) {
        let Some(dir) = self.cfg().cache_dir else {
            return;
        };
        let loaded = self.read_cache(&dir);
        let now = bypass::now();
        let res = self.engine.update(|s| {
            match &loaded {
                Some((meta, lists)) => {
                    for (cat, _) in FIRST_PARTY {
                        let id = bypass::argus_id(cat);
                        let Some(sub) = s.subscriptions.iter_mut().find(|x| x.id == id) else {
                            continue;
                        };
                        match lists.get(cat) {
                            Some(hosts) => {
                                sub.host_count = hosts.len();
                                sub.last_fetched = Some(now);
                                sub.last_error = None;
                                s.set_hosts(&id, hosts.clone());
                            }
                            None => {
                                sub.last_fetched = None;
                                s.sub_hosts.remove(&id);
                            }
                        }
                    }
                    s.argus.version = Some(meta.version.clone());
                    s.argus.min_version =
                        max_version(s.argus.min_version.take(), Some(meta.version.clone()));
                    s.argus.categories = meta_info(meta);
                }
                None => {
                    // Nothing trustworthy on disk: forget whatever the state file claimed.
                    for (cat, _) in FIRST_PARTY {
                        let id = bypass::argus_id(cat);
                        if let Some(sub) = s.subscriptions.iter_mut().find(|x| x.id == id) {
                            sub.last_fetched = None;
                        }
                        s.sub_hosts.remove(&id);
                    }
                    // The installed version is unknown now, but `min_version` stays: an older
                    // release must still be refused.
                    s.argus.version = None;
                }
            }
            Ok(())
        });
        if let Err(e) = res {
            tracing::warn!("could not record the cached Argus lists: {e}");
        }
    }

    #[allow(clippy::type_complexity)]
    fn read_cache(
        &self,
        dir: &Path,
    ) -> Option<(Meta, std::collections::BTreeMap<String, Vec<String>>)> {
        let read = |name: &str| std::fs::read(dir.join(name)).ok();
        let meta_bytes = read("meta.json")?;
        let sig = String::from_utf8(read("meta.json.minisig")?).ok()?;
        verify(&self.cfg().public_key, &meta_bytes, &sig).ok()?;
        let meta: Meta = serde_json::from_slice(&meta_bytes).ok()?;
        version_key(&meta.version)?;
        let key = self.cfg().public_key;
        let mut lists = std::collections::BTreeMap::new();
        for c in &meta.categories {
            let Some(bytes) = read(&format!("{}.txt", c.id)) else {
                continue;
            };
            let Some(sig) =
                read(&format!("{}.txt.minisig", c.id)).and_then(|b| String::from_utf8(b).ok())
            else {
                continue;
            };
            if verify(&key, &bytes, &sig).is_err() || sha256_hex(&bytes) != c.sha256 {
                continue;
            }
            let (hosts, _) = bypass::parse_exclusion_list_counted_with(
                &String::from_utf8_lossy(&bytes),
                MAX_HOSTS,
                &bypass::sanitize_allowed_wildcards(&meta.allowed_wildcards),
            );
            if !hosts.is_empty() {
                lists.insert(c.id.clone(), hosts);
            }
        }
        Some((meta, lists))
    }

    /// Look for a newer release and install it. A bad signature, a digest mismatch or a version
    /// older than the installed one is refused and leaves everything as it was.
    pub async fn refresh(&self) -> Result<RefreshOutcome, String> {
        let _g = self.busy.lock().await;
        let result = self.refresh_inner().await;
        let now = bypass::now();
        let err = result.as_ref().err().cloned();
        // Status only: kept in memory, saved with the next real change (no write per check).
        self.engine.update_volatile(|s| {
            s.argus.last_checked = Some(now);
            if let Some(e) = &err {
                s.argus.last_error = Some(e.clone());
            }
        });
        result
    }

    async fn fetch(&self, file: &str) -> Result<String, String> {
        self.svc.fetch_exclusion_list(&self.url(file)).await
    }

    async fn refresh_inner(&self) -> Result<RefreshOutcome, String> {
        let meta_text = self.fetch("meta.json").await?;
        let meta_sig = self.fetch("meta.json.minisig").await?;
        verify(&self.cfg().public_key, meta_text.as_bytes(), &meta_sig)
            .map_err(|e| format!("meta.json: {e}"))?;
        let meta: Meta = serde_json::from_str(&meta_text).map_err(|e| format!("meta.json: {e}"))?;
        if version_key(&meta.version).is_none() {
            return Err(format!("meta.json: bad version {:?}", meta.version));
        }
        let (installed, all_loaded) = self.engine.read(|s| {
            (
                // The floor: the newest release ever installed, even if its cache is gone.
                max_version(s.argus.min_version.clone(), s.argus.version.clone()),
                s.subscriptions
                    .iter()
                    .filter(|x| bypass::is_first_party(&x.id) && x.enabled)
                    .all(|x| x.last_fetched.is_some()),
            )
        });
        if let Some(cur) = &installed {
            match version_cmp(&meta.version, cur) {
                Some(Ordering::Less) => {
                    return Err(format!(
                        "release {} is older than {cur}, the newest release ever installed; not installing it",
                        meta.version
                    ))
                }
                Some(Ordering::Equal) if all_loaded => {
                    return Ok(RefreshOutcome::Current {
                        version: meta.version,
                    })
                }
                _ => {}
            }
        }
        // Every list, verified, before anything is installed.
        let allowed = bypass::sanitize_allowed_wildcards(&meta.allowed_wildcards);
        let mut lists: Vec<(String, String, Vec<u8>, Vec<String>)> = Vec::new();
        let mut skipped_total = bypass::Skipped::default();
        for (cat, _) in FIRST_PARTY {
            let Some(c) = meta.categories.iter().find(|c| c.id == cat) else {
                return Err(format!("meta.json lacks the {cat} list"));
            };
            let text = self.fetch(&format!("{cat}.txt")).await?;
            let sig = self.fetch(&format!("{cat}.txt.minisig")).await?;
            // Verifying and parsing a big list is CPU work: off the async threads.
            let allowed = allowed.clone();
            let (key, want_sha, name) = (
                self.cfg().public_key.clone(),
                c.sha256.clone(),
                cat.to_string(),
            );
            let (text, sig, hosts, skipped) = tokio::task::spawn_blocking(move || {
                verify(&key, text.as_bytes(), &sig).map_err(|e| format!("{name}.txt: {e}"))?;
                if sha256_hex(text.as_bytes()) != want_sha {
                    return Err(format!("{name}.txt does not match the digest in meta.json"));
                }
                let (hosts, skipped) =
                    bypass::parse_exclusion_list_counted_with(&text, MAX_HOSTS, &allowed);
                if hosts.is_empty() {
                    return Err(format!("{name}.txt has no hosts"));
                }
                Ok((text, sig, hosts, skipped))
            })
            .await
            .map_err(|e| e.to_string())??;
            skipped_total.merge(skipped);
            lists.push((cat.to_string(), sig, text.into_bytes(), hosts));
        }
        // Cache (lists first, meta last: a half-written cache fails verification, never lies).
        if let Some(dir) = self.cfg().cache_dir {
            let files: Vec<(String, Vec<u8>)> = lists
                .iter()
                .flat_map(|(cat, sig, text, _)| {
                    [
                        (format!("{cat}.txt"), text.clone()),
                        (format!("{cat}.txt.minisig"), sig.clone().into_bytes()),
                    ]
                })
                .chain([
                    (
                        "meta.json.minisig".to_string(),
                        meta_sig.clone().into_bytes(),
                    ),
                    ("meta.json".to_string(), meta_text.clone().into_bytes()),
                ])
                .collect();
            tokio::task::spawn_blocking(move || {
                for (name, bytes) in files {
                    atomic_write(&dir.join(name), &bytes)?;
                }
                Ok::<(), String>(())
            })
            .await
            .map_err(|e| e.to_string())??;
        }
        let now = bypass::now();
        let version = meta.version.clone();
        let skipped = skipped_total;
        self.engine
            .update_async(move |s| {
                for (cat, _, _, hosts) in lists {
                    let id = bypass::argus_id(&cat);
                    if let Some(sub) = s.subscriptions.iter_mut().find(|x| x.id == id) {
                        sub.host_count = hosts.len();
                        sub.last_fetched = Some(now);
                        sub.last_error = None;
                    }
                    s.set_hosts(&id, hosts);
                }
                s.argus.version = Some(meta.version.clone());
                s.argus.min_version =
                    max_version(s.argus.min_version.take(), Some(meta.version.clone()));
                s.argus.updated_at = Some(now);
                // Lines skipped as invalid or too broad are reported apart from errors.
                s.argus.last_error = None;
                s.argus.skipped_lines = skipped.count as u32;
                s.argus.skipped_sample = skipped.sample;
                s.argus.categories = meta_info(&meta);
                Ok(())
            })
            .await?;
        Ok(RefreshOutcome::Installed { version })
    }

    /// Load the cache now, then keep the lists current in the background: retry quickly (with
    /// backoff) until the first success, afterwards every few hours. Fetching starts at once.
    pub fn start(self: &Arc<Self>) {
        self.init_cache();
        let this = self.clone();
        tokio::spawn(async move {
            let mut backoff = Duration::from_secs(10);
            loop {
                let wait = match this.refresh().await {
                    Ok(o) => {
                        backoff = Duration::from_secs(10);
                        tracing::info!("Argus lists: {o:?}");
                        CHECK_EVERY
                    }
                    Err(e) => {
                        tracing::warn!("Argus lists: {e}");
                        let w = backoff;
                        backoff = (backoff * 2).min(Duration::from_secs(900));
                        w
                    }
                };
                tokio::select! {
                    _ = tokio::time::sleep(wait) => {}
                    _ = this.wake.notified() => {}
                }
            }
        });
    }
}

fn meta_info(m: &Meta) -> std::collections::BTreeMap<String, bypass::ArgusCategory> {
    m.categories
        .iter()
        .map(|c| {
            (
                c.id.clone(),
                bypass::ArgusCategory {
                    name: c.name.clone(),
                    description: c.description.clone(),
                    default_mode: c.default_mode,
                },
            )
        })
        .collect()
}

pub(crate) fn sha256_hex(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::Cursor;
    use std::sync::Mutex;

    fn keypair() -> (minisign::PublicKeyBox, minisign::SecretKey) {
        let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        (kp.pk.to_box().unwrap(), kp.sk)
    }

    fn pk_b64(pk: &minisign::PublicKeyBox) -> String {
        // The second line of the public key file is the base64 key.
        pk.to_string().lines().nth(1).unwrap().to_string()
    }

    fn sign(sk: &minisign::SecretKey, pk: &minisign::PublicKeyBox, data: &[u8]) -> String {
        let pk = pk.clone().into_public_key().unwrap();
        minisign::sign(Some(&pk), sk, Cursor::new(data), Some("t"), Some("c"))
            .unwrap()
            .to_string()
    }

    #[test]
    fn signatures_verify_and_tampering_or_a_wrong_key_is_rejected() {
        let (pk, sk) = keypair();
        let (other_pk, _) = keypair();
        let data = b"bank.test\n*.wild.test\n";
        let sig = sign(&sk, &pk, data);
        assert!(verify(&pk_b64(&pk), data, &sig).is_ok());
        // Tampered content.
        let e = verify(&pk_b64(&pk), b"bank.test\n*.evil.test\n", &sig).unwrap_err();
        assert!(e.contains("does not verify"), "{e}");
        // Wrong key (and the placeholder constant never verifies anything).
        assert!(verify(&pk_b64(&other_pk), data, &sig).is_err());
        assert!(verify(bypass::ARGUS_LISTS_PUBLIC_KEY, data, &sig).is_err());
        // Garbage signature files and keys are errors, not panics.
        assert!(verify(&pk_b64(&pk), data, "not a signature").is_err());
        assert!(verify("not a key", data, &sig).is_err());
    }

    #[test]
    fn versions_compare_by_date_then_release_number() {
        use Ordering::*;
        assert_eq!(version_cmp("v2025.11.23", "v2025.11.22"), Some(Greater));
        assert_eq!(version_cmp("v2025.11.23.2", "v2025.11.23"), Some(Greater));
        assert_eq!(
            version_cmp("v2025.11.23.10", "v2025.11.23.9"),
            Some(Greater)
        );
        assert_eq!(version_cmp("v2025.11.23", "v2025.11.23.0"), Some(Equal));
        assert_eq!(version_cmp("v2024.12.31", "v2025.01.01"), Some(Less));
        assert_eq!(version_cmp("2025.11.23", "v2025.11.23"), None);
    }

    /// A release: files by name.
    struct Release {
        files: HashMap<String, Vec<u8>>,
    }

    fn release(
        sk: &minisign::SecretKey,
        pk: &minisign::PublicKeyBox,
        version: &str,
        hosts: &[(&str, &str)],
    ) -> Release {
        release_ex(sk, pk, version, hosts, &[])
    }

    fn release_ex(
        sk: &minisign::SecretKey,
        pk: &minisign::PublicKeyBox,
        version: &str,
        hosts: &[(&str, &str)],
        allowed: &[&str],
    ) -> Release {
        let mut files = HashMap::new();
        let mut cats = Vec::new();
        for (cat, _) in FIRST_PARTY {
            let body = hosts
                .iter()
                .find(|(c, _)| *c == cat)
                .map_or("fallback.test\n".to_string(), |(_, h)| format!("{h}\n"));
            files.insert(format!("{cat}.txt"), body.clone().into_bytes());
            files.insert(
                format!("{cat}.txt.minisig"),
                sign(sk, pk, body.as_bytes()).into_bytes(),
            );
            cats.push(serde_json::json!({
                "id": cat, "name": cat, "description": "d", "default_mode": "no_decrypt",
                "sha256": sha256_hex(body.as_bytes()),
            }));
        }
        let meta = serde_json::json!({"version": version, "categories": cats, "allowed_wildcards": allowed}).to_string();
        files.insert(
            "meta.json.minisig".into(),
            sign(sk, pk, meta.as_bytes()).into_bytes(),
        );
        files.insert("meta.json".into(), meta.into_bytes());
        Release { files }
    }

    /// Serve the current release's files over HTTP; `swap` replaces them.
    async fn serve(rel: Release) -> (std::net::SocketAddr, Arc<Mutex<Release>>) {
        let shared = Arc::new(Mutex::new(rel));
        let s2 = shared.clone();
        let app = axum::Router::new().fallback(move |uri: axum::http::Uri| {
            let s = s2.clone();
            async move {
                let name = uri.path().trim_start_matches('/').to_string();
                match s.lock().unwrap().files.get(&name) {
                    Some(b) => (axum::http::StatusCode::OK, b.clone()),
                    None => (axum::http::StatusCode::NOT_FOUND, Vec::new()),
                }
            }
        });
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(l, app).await;
        });
        (addr, shared)
    }

    fn service() -> (tempfile::TempDir, Arc<ListService>) {
        let d = tempfile::tempdir().unwrap();
        let store = crate::ListStore::open(&d.path().join("store")).unwrap();
        let engine = Arc::new(filter_engine::SharedEngine::new());
        let svc = ListService::new(
            crate::ListServiceConfig::default(),
            store,
            engine,
            reqwest::Client::new(),
        );
        (d, svc)
    }

    struct Rig {
        _d: tempfile::TempDir,
        engine: Arc<BypassEngine>,
        lists: Arc<ArgusLists>,
        cache: PathBuf,
        state_path: PathBuf,
    }

    fn rig(addr: std::net::SocketAddr, pk: &minisign::PublicKeyBox, dir: Option<&Path>) -> Rig {
        let (d, svc) = service();
        let root = dir
            .map(Path::to_path_buf)
            .unwrap_or_else(|| d.path().to_path_buf());
        let state_path = root.join("bypass.json");
        let engine = Arc::new(BypassEngine::load(state_path.clone()));
        let cache = root.join("argus-lists");
        let lists = ArgusLists::new(
            engine.clone(),
            svc,
            ArgusConfig {
                base_url: format!("http://{addr}"),
                public_key: pk_b64(pk),
                cache_dir: Some(cache.clone()),
            },
        );
        Rig {
            _d: d,
            engine,
            lists,
            cache,
            state_path,
        }
    }

    #[tokio::test]
    async fn a_verified_release_installs_ends_the_failsafe_and_is_cached() {
        let (pk, sk) = keypair();
        let (addr, _rel) = serve(release(
            &sk,
            &pk,
            "v2025.11.23",
            &[("banking_finance", "chase.test\n*.bank-wild.test")],
        ))
        .await;
        let r = rig(addr, &pk, None);
        assert!(r.engine.failsafe_active(), "waiting for the lists");
        assert_eq!(
            r.lists.refresh().await.unwrap(),
            RefreshOutcome::Installed {
                version: "v2025.11.23".into()
            }
        );
        assert!(!r.engine.failsafe_active());
        let h = r.engine.lookup("www.chase.test").unwrap();
        assert_eq!(
            (h.source.as_str(), h.mode),
            ("argus:banking_finance", BypassMode::NoDecrypt)
        );
        assert!(r.engine.lookup("x.bank-wild.test").is_some());
        assert_eq!(
            r.engine.read(|s| s.argus.version.clone()),
            Some("v2025.11.23".into())
        );
        assert!(
            r.cache.join("meta.json").exists()
                && r.cache.join("banking_finance.txt.minisig").exists()
        );
        // Same release again: nothing to do.
        assert_eq!(
            r.lists.refresh().await.unwrap(),
            RefreshOutcome::Current {
                version: "v2025.11.23".into()
            }
        );
    }

    #[tokio::test]
    async fn a_live_config_change_applies_on_the_next_refresh_and_a_key_change_rejects_old_signatures(
    ) {
        let (pk_a, sk_a) = keypair();
        let (pk_b, sk_b) = keypair();
        let (addr_a, _a) = serve(release(&sk_a, &pk_a, "v2025.11.23", &[])).await;
        let (addr_b, _b) = serve(release(&sk_b, &pk_b, "v2025.11.24", &[])).await;
        let r = rig(addr_a, &pk_a, None);
        assert!(r.lists.refresh().await.is_ok());
        // The key changes: the same, previously valid release no longer verifies.
        let cache = Some(r.cache.clone());
        let src = |addr: std::net::SocketAddr, pk: &minisign::PublicKeyBox| {
            let c = ArgusConfig {
                base_url: format!("http://{addr}"),
                public_key: pk_b64(pk),
                cache_dir: cache.clone(),
            };
            move || c.clone()
        };
        r.lists.set_config_source(src(addr_a, &pk_b));
        assert!(r.lists.refresh().await.is_err());
        // The location and key change together: the other release installs.
        r.lists.set_config_source(src(addr_b, &pk_b));
        assert_eq!(
            r.lists.refresh().await.unwrap(),
            RefreshOutcome::Installed {
                version: "v2025.11.24".into()
            }
        );
    }

    #[tokio::test]
    async fn a_tampered_list_a_wrong_key_and_a_digest_mismatch_install_nothing() {
        let (pk, sk) = keypair();
        let rel = release(&sk, &pk, "v2025.11.23", &[]);
        let (addr, shared) = serve(rel).await;
        let r = rig(addr, &pk, None);
        // Tamper with one list after it was signed.
        shared
            .lock()
            .unwrap()
            .files
            .insert("payments.txt".into(), b"evil.test\n".to_vec());
        let e = r.lists.refresh().await.unwrap_err();
        assert!(e.contains("payments.txt"), "{e}");
        assert!(
            r.engine.failsafe_active(),
            "nothing installed, fail-safe stays on"
        );
        assert!(r.engine.lookup("evil.test").is_none());
        assert!(r.engine.read(|s| s.argus.last_error.clone()).is_some());
        assert!(!r.cache.join("meta.json").exists(), "nothing cached either");
        // A release signed by a different key is refused as a whole.
        let (other_pk, other_sk) = keypair();
        let (addr2, _s2) = serve(release(&other_sk, &other_pk, "v2025.11.24", &[])).await;
        let r2 = rig(addr2, &pk, None);
        assert!(r2.lists.refresh().await.unwrap_err().contains("meta.json"));
        assert!(r2.engine.failsafe_active());
        // The placeholder key (the shipped default) verifies nothing.
        let (d, svc) = service();
        let l = ArgusLists::new(
            Arc::new(BypassEngine::load(d.path().join("b.json"))),
            svc,
            ArgusConfig {
                base_url: format!("http://{addr}"),
                public_key: bypass::ARGUS_LISTS_PUBLIC_KEY.into(),
                cache_dir: None,
            },
        );
        assert!(l.refresh().await.is_err());
    }

    #[tokio::test]
    async fn the_cache_is_reverified_at_start_and_a_restart_without_network_still_decrypts() {
        let (pk, sk) = keypair();
        let (addr, _s) = serve(release(
            &sk,
            &pk,
            "v2025.11.23",
            &[("health", "hospital.test")],
        ))
        .await;
        let d = tempfile::tempdir().unwrap();
        let r = rig(addr, &pk, Some(d.path()));
        r.lists.refresh().await.unwrap();
        // "Restart": a fresh engine over the same files, and no server at all.
        let (_, svc) = service();
        let engine = Arc::new(BypassEngine::load(r.state_path.clone()));
        let lists = ArgusLists::new(
            engine.clone(),
            svc,
            ArgusConfig {
                base_url: "http://127.0.0.1:1".into(),
                public_key: pk_b64(&pk),
                cache_dir: Some(r.cache.clone()),
            },
        );
        lists.init_cache();
        assert!(
            !engine.failsafe_active(),
            "the verified cache counts as loaded"
        );
        assert!(engine.lookup("hospital.test").is_some());
        assert_eq!(
            engine.read(|s| s.argus.version.clone()),
            Some("v2025.11.23".into())
        );

        // A tampered cache file is not trusted: that list is treated as not loaded.
        std::fs::write(r.cache.join("health.txt"), b"attacker.test\n").unwrap();
        let engine = Arc::new(BypassEngine::load(r.state_path.clone()));
        let (_, svc) = service();
        let lists = ArgusLists::new(
            engine.clone(),
            svc,
            ArgusConfig {
                base_url: "http://127.0.0.1:1".into(),
                public_key: pk_b64(&pk),
                cache_dir: Some(r.cache.clone()),
            },
        );
        lists.init_cache();
        assert!(engine.lookup("attacker.test").is_none());
        assert!(engine.lookup("hospital.test").is_none());
        assert!(engine.failsafe_active(), "health is missing again");
        // A cache verified against another key loads nothing either.
        let (other_pk, _) = keypair();
        let (_, svc) = service();
        let engine = Arc::new(BypassEngine::load(r.state_path.clone()));
        let lists = ArgusLists::new(
            engine.clone(),
            svc,
            ArgusConfig {
                base_url: "http://127.0.0.1:1".into(),
                public_key: pk_b64(&other_pk),
                cache_dir: Some(r.cache.clone()),
            },
        );
        lists.init_cache();
        assert!(engine.failsafe_active());
    }

    #[tokio::test]
    async fn an_older_release_is_never_installed_over_a_newer_one() {
        let (pk, sk) = keypair();
        let (addr, shared) = serve(release(
            &sk,
            &pk,
            "v2025.11.23.1",
            &[("payments", "pay-new.test")],
        ))
        .await;
        let r = rig(addr, &pk, None);
        r.lists.refresh().await.unwrap();
        // The server now offers an older (validly signed) release, e.g. a replayed asset.
        *shared.lock().unwrap() = release(&sk, &pk, "v2025.11.22", &[("payments", "pay-old.test")]);
        let e = r.lists.refresh().await.unwrap_err();
        assert!(e.contains("older"), "{e}");
        assert!(r.engine.lookup("pay-new.test").is_some());
        assert!(r.engine.lookup("pay-old.test").is_none());
        assert_eq!(
            r.engine.read(|s| s.argus.version.clone()),
            Some("v2025.11.23.1".into())
        );
        // The same day, a later release number, is accepted.
        *shared.lock().unwrap() =
            release(&sk, &pk, "v2025.11.23.2", &[("payments", "pay-newer.test")]);
        assert!(matches!(
            r.lists.refresh().await.unwrap(),
            RefreshOutcome::Installed { .. }
        ));
        assert!(r.engine.lookup("pay-newer.test").is_some());
        // A signed meta from an older release cannot be mixed with newer list files either:
        // the digests in meta.json must match the files.
        let stale = release(&sk, &pk, "v2025.12.01", &[]);
        let mut mixed = release(&sk, &pk, "v2025.12.01", &[("payments", "x.test")]);
        mixed
            .files
            .insert("meta.json".into(), stale.files["meta.json"].clone());
        mixed.files.insert(
            "meta.json.minisig".into(),
            stale.files["meta.json.minisig"].clone(),
        );
        *shared.lock().unwrap() = mixed;
        assert!(r.lists.refresh().await.unwrap_err().contains("digest"));
    }

    #[test]
    fn a_signature_made_for_another_key_id_is_refused_even_with_valid_bytes() {
        use base64::Engine as _;
        let (pk, sk) = keypair();
        let data = b"bank.test\n";
        let sig = sign(&sk, &pk, data);
        assert!(verify(&pk_b64(&pk), data, &sig).is_ok());
        // Flip the key id inside the signature line (bytes 2..10 of the decoded blob).
        let mut lines: Vec<String> = sig.lines().map(String::from).collect();
        let mut raw = base64::engine::general_purpose::STANDARD
            .decode(&lines[1])
            .unwrap();
        raw[2] ^= 0xff;
        lines[1] = base64::engine::general_purpose::STANDARD.encode(raw);
        let forged = lines.join("\n") + "\n";
        let e = verify(&pk_b64(&pk), data, &forged).unwrap_err();
        assert!(e.contains("different key"), "{e}");
    }

    #[tokio::test]
    async fn the_downgrade_floor_survives_a_lost_cache_and_a_restart() {
        let (pk, sk) = keypair();
        let (addr, shared) = serve(release(
            &sk,
            &pk,
            "v2025.12.01",
            &[("payments", "pay-new.test")],
        ))
        .await;
        let d = tempfile::tempdir().unwrap();
        let r = rig(addr, &pk, Some(d.path()));
        r.lists.refresh().await.unwrap();
        assert_eq!(
            r.engine.read(|s| s.argus.min_version.clone()),
            Some("v2025.12.01".into())
        );
        // The cache is lost (disk wiped / tampered) and the process restarts.
        std::fs::remove_dir_all(&r.cache).unwrap();
        let (_, svc) = service();
        let engine = Arc::new(BypassEngine::load(r.state_path.clone()));
        let lists = ArgusLists::new(
            engine.clone(),
            svc,
            ArgusConfig {
                base_url: format!("http://{addr}"),
                public_key: pk_b64(&pk),
                cache_dir: Some(r.cache.clone()),
            },
        );
        lists.init_cache();
        assert!(
            engine.failsafe_active(),
            "nothing verified is loaded any more"
        );
        assert_eq!(engine.read(|s| s.argus.version.clone()), None);
        assert_eq!(
            engine.read(|s| s.argus.min_version.clone()),
            Some("v2025.12.01".into()),
            "init_cache never clears the floor"
        );
        // A validly signed older release (a replay) is refused ...
        *shared.lock().unwrap() = release(&sk, &pk, "v2025.11.01", &[("payments", "pay-old.test")]);
        let e = lists.refresh().await.unwrap_err();
        assert!(e.contains("older"), "{e}");
        assert!(engine.lookup("pay-old.test").is_none() && engine.failsafe_active());
        // ... the floor itself, and newer ones, are accepted.
        *shared.lock().unwrap() =
            release(&sk, &pk, "v2025.12.01", &[("payments", "pay-same.test")]);
        assert!(matches!(
            lists.refresh().await.unwrap(),
            RefreshOutcome::Installed { .. }
        ));
        assert!(!engine.failsafe_active());
    }

    #[tokio::test]
    async fn too_broad_lines_are_skipped_and_reported_apart_from_errors() {
        let (pk, sk) = keypair();
        let (addr, _s) = serve(release(
            &sk,
            &pk,
            "v2025.11.23",
            &[(
                "banking_finance",
                "chase.test\n*.com\nco.uk\n*.gov\nlocalhost",
            )],
        ))
        .await;
        let r = rig(addr, &pk, None);
        r.lists.refresh().await.unwrap();
        assert!(r.engine.lookup("chase.test").is_some());
        assert!(
            r.engine.lookup("anything.com").is_none(),
            "*.com was not installed"
        );
        assert!(
            r.engine.lookup("www.irs.gov").is_some(),
            "the allow-listed *.gov was"
        );
        // Reported apart from errors: a healthy list is not an error.
        assert_eq!(r.engine.read(|s| s.argus.last_error.clone()), None);
        let (n, sample) = r
            .engine
            .read(|s| (s.argus.skipped_lines, s.argus.skipped_sample.clone()));
        assert_eq!(n, 3);
        assert_eq!(sample, ["*.com", "co.uk", "localhost"]);
        assert!(!r.engine.failsafe_active());
    }

    #[tokio::test]
    async fn status_checks_do_not_write_to_disk() {
        let (pk, sk) = keypair();
        let (addr, _s) = serve(release(&sk, &pk, "v2025.11.23", &[])).await;
        let r = rig(addr, &pk, None);
        r.lists.refresh().await.unwrap();
        let after_install = r.engine.write_counts();
        for _ in 0..3 {
            assert!(matches!(
                r.lists.refresh().await.unwrap(),
                RefreshOutcome::Current { .. }
            ));
        }
        assert_eq!(r.engine.write_counts(), after_install, "no write per check");
        assert!(r.engine.read(|s| s.argus.last_checked).is_some());
    }

    #[tokio::test]
    async fn a_signed_allowed_wildcards_list_extends_first_party_lists_only_and_is_sanity_checked()
    {
        let (pk, sk) = keypair();
        let lists = [("banking_finance", "*.ltd.uk\n*.com\nok.test")];
        // Signed allow-list naming one sane suffix and `*.com` (which must stay refused).
        let (addr, shared) = serve(release_ex(
            &sk,
            &pk,
            "v2025.11.23",
            &lists,
            &["*.ltd.uk", "*.com"],
        ))
        .await;
        let d = tempfile::tempdir().unwrap();
        let r = rig(addr, &pk, Some(d.path()));
        r.lists.refresh().await.unwrap();
        assert!(
            r.engine.lookup("x.ltd.uk").is_some(),
            "honoured for the first-party list"
        );
        assert!(
            r.engine.lookup("anything.com").is_none(),
            "*.com is refused even though signed"
        );
        assert!(r.engine.lookup("ok.test").is_some());
        assert_eq!(r.engine.read(|s| s.argus.skipped_lines), 1);
        assert_eq!(r.engine.read(|s| s.argus.skipped_sample.clone()), ["*.com"]);
        assert_eq!(r.engine.read(|s| s.argus.last_error.clone()), None);
        // The cached copy is parsed with the cached (signed) meta the same way after a restart.
        let (_, svc) = service();
        let engine = Arc::new(BypassEngine::load(r.state_path.clone()));
        let again = ArgusLists::new(
            engine.clone(),
            svc,
            ArgusConfig {
                base_url: "http://127.0.0.1:1".into(),
                public_key: pk_b64(&pk),
                cache_dir: Some(r.cache.clone()),
            },
        );
        again.init_cache();
        assert!(engine.lookup("x.ltd.uk").is_some() && engine.lookup("anything.com").is_none());
        // Without the field the same line is skipped (the compiled-in default does not name it).
        *shared.lock().unwrap() = release_ex(&sk, &pk, "v2025.11.24", &lists, &[]);
        r.lists.refresh().await.unwrap();
        assert!(r.engine.lookup("x.ltd.uk").is_none());
        assert_eq!(r.engine.read(|s| s.argus.skipped_lines), 2);
        // A third-party list never gets the first-party allow-list.
        let (hosts, skipped) = bypass::parse_exclusion_list_counted("*.ltd.uk\nfine.test\n", 10);
        assert_eq!((hosts, skipped.count), (vec!["fine.test".to_string()], 1));
    }
}

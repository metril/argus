//! The list service: fetch, compile and install, single-flight.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use filter_engine::{compile_engine, FilterList, SharedEngine};
use futures_util::StreamExt;
use parking_lot::Mutex;
use reqwest::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::store::{ListStatus, ListStore};
use crate::{Error, Result};

/// Runtime settings of the list service.
#[derive(Debug, Clone)]
pub struct ListServiceConfig {
    /// Master switch: when false, [`ListService::start`] does nothing.
    pub enabled: bool,
    /// Directory for the list store and the scriptlet resource cache.
    pub data_dir: PathBuf,
    pub auto_update: bool,
    pub update_interval: Duration,
    /// Scriptlet resource source; empty disables loading.
    pub scriptlet_resources_url: String,
    /// Max simultaneous list downloads.
    pub fetch_concurrency: usize,
    /// Per-list request timeout (whole request including body).
    pub fetch_timeout: Duration,
    /// Max accepted size of a downloaded list / resource, in bytes.
    pub max_list_bytes: usize,
    pub scriptlet_retry_initial: Duration,
    pub scriptlet_retry_max: Duration,
}

impl Default for ListServiceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            data_dir: PathBuf::from("data/filters"),
            auto_update: true,
            update_interval: Duration::from_secs(24 * 3600),
            scriptlet_resources_url: String::new(),
            fetch_concurrency: 4,
            fetch_timeout: Duration::from_secs(30),
            max_list_bytes: 50 * 1024 * 1024,
            scriptlet_retry_initial: Duration::from_secs(5),
            scriptlet_retry_max: Duration::from_secs(15 * 60),
        }
    }
}

impl ListServiceConfig {
    /// Derive from the `[adblock]` config section.
    pub fn from_adblock(a: &common::config::AdblockSettings) -> Self {
        Self {
            enabled: a.enabled,
            data_dir: a.data_dir.clone(),
            auto_update: a.auto_update,
            update_interval: Duration::from_secs(a.update_interval_hours.max(1) * 3600),
            scriptlet_resources_url: a.scriptlet_resources_url.clone(),
            fetch_concurrency: a.list_fetch_concurrency.max(1),
            fetch_timeout: Duration::from_secs(a.list_fetch_timeout_secs.max(1)),
            max_list_bytes: a.max_list_bytes,
            ..Self::default()
        }
    }
}

#[derive(Default)]
struct Flight {
    running: bool,
    pending: bool,
}

/// Owns lists, content, compile and install for one [`SharedEngine`].
pub struct ListService {
    pub(crate) cfg: ListServiceConfig,
    store: Arc<ListStore>,
    pub(crate) engine: Arc<SharedEngine>,
    pub(crate) client: reqwest::Client,
    flight: Mutex<Flight>,
    busy: watch::Sender<bool>,
    builds: AtomicU64,
    installed_once: AtomicBool,
    pub(crate) scriptlets_tx: watch::Sender<bool>,
}

/// Read a response body, failing once it exceeds `cap` bytes.
pub(crate) async fn read_capped(
    mut resp: reqwest::Response,
    cap: usize,
) -> std::result::Result<Vec<u8>, String> {
    if resp.content_length().is_some_and(|n| n > cap as u64) {
        return Err(format!("response exceeds size cap of {cap} bytes"));
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
        if body.len() + chunk.len() > cap {
            return Err(format!("response exceeds size cap of {cap} bytes"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Approximate rule count: non-empty, non-comment lines.
fn count_rules(content: &str) -> usize {
    content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('!'))
        .count()
}

impl ListService {
    /// Build a service over an existing store (no seeding).
    pub fn new(
        cfg: ListServiceConfig,
        store: Arc<ListStore>,
        engine: Arc<SharedEngine>,
        client: reqwest::Client,
    ) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            store,
            engine,
            client,
            flight: Mutex::new(Flight::default()),
            busy: watch::channel(false).0,
            builds: AtomicU64::new(0),
            installed_once: AtomicBool::new(false),
            scriptlets_tx: watch::channel(false).0,
        })
    }

    /// Open the store under `cfg.data_dir`, seed default lists on a fresh install and build the
    /// list-download HTTP client.
    pub fn open(cfg: ListServiceConfig, engine: Arc<SharedEngine>) -> Result<Arc<Self>> {
        let store = ListStore::open(&cfg.data_dir)?;
        store.seed_defaults_if_empty()?;
        let client = reqwest::Client::builder()
            .user_agent(concat!("AdBlocker/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| Error::Other(format!("build list-download client: {e}")))?;
        Ok(Self::new(cfg, store, engine, client))
    }

    pub fn store(&self) -> &Arc<ListStore> {
        &self.store
    }

    /// Number of build cycles started so far.
    pub fn build_count(&self) -> u64 {
        self.builds.load(Ordering::Acquire)
    }

    /// Receiver that turns `true` once scriptlet resources are loaded.
    pub fn scriptlets_ready(&self) -> watch::Receiver<bool> {
        self.scriptlets_tx.subscribe()
    }

    /// Start background work and return immediately: an initial load (cached content is
    /// installed first, then lists are refreshed), scriptlet resource loading and the
    /// auto-update ticker. No-op when disabled.
    pub fn start(self: &Arc<Self>) {
        if !self.cfg.enabled {
            return;
        }
        self.trigger();
        let this = self.clone();
        tokio::spawn(async move { this.ensure_scriptlet_resources().await });
        if self.cfg.auto_update {
            let this = self.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(this.cfg.update_interval);
                ticker.tick().await; // initial load is separate
                loop {
                    ticker.tick().await;
                    info!("Auto-update: refreshing filter lists");
                    this.trigger();
                }
            });
        }
    }

    /// Request a rebuild without waiting. Overlapping triggers coalesce: at most one build runs,
    /// and triggers arriving while it runs cause exactly one follow-up build.
    pub fn trigger(self: &Arc<Self>) {
        {
            let mut f = self.flight.lock();
            if f.running {
                f.pending = true;
                return;
            }
            f.running = true;
            self.busy.send_replace(true);
        }
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                if let Err(e) = this.build_once().await {
                    warn!("Filter reload failed: {e}");
                }
                let mut f = this.flight.lock();
                if f.pending {
                    f.pending = false;
                } else {
                    f.running = false;
                    this.busy.send_replace(false);
                    break;
                }
            }
        });
    }

    /// Trigger a rebuild and wait until the service is idle again.
    pub async fn reload_now(self: &Arc<Self>) {
        self.trigger();
        self.wait_idle().await;
    }

    /// Wait until no build is running or queued.
    pub async fn wait_idle(&self) {
        let mut rx = self.busy.subscribe();
        let _ = rx.wait_for(|busy| !*busy).await;
    }

    async fn compile_install(&self, contents: Vec<String>) -> Result<()> {
        let bytes = tokio::task::spawn_blocking(move || compile_engine(&contents))
            .await
            .map_err(|e| Error::Other(format!("compile task failed: {e}")))?;
        self.engine.install(bytes);
        self.installed_once.store(true, Ordering::Release);
        Ok(())
    }

    fn custom_rules(&self) -> Option<String> {
        self.store
            .get_custom_rules()
            .ok()
            .filter(|r| !r.trim().is_empty())
    }

    async fn build_once(&self) -> Result<()> {
        self.builds.fetch_add(1, Ordering::AcqRel);
        let enabled: Vec<FilterList> = self
            .store
            .get_all()?
            .into_iter()
            .filter(|l| l.enabled)
            .collect();
        info!(
            "Reloading filter engine from {} enabled list(s)",
            enabled.len()
        );

        // First build of the process: serve cached rules immediately, before touching the network.
        if !self.installed_once.load(Ordering::Acquire) {
            let mut cached: Vec<String> = enabled
                .iter()
                .filter_map(|l| self.store.get_content(&l.id).ok().flatten())
                .collect();
            if !cached.is_empty() {
                cached.extend(self.custom_rules());
                self.compile_install(cached).await?;
            }
        }

        let mut contents: Vec<String> = futures_util::stream::iter(enabled)
            .map(|l| self.fetch_one(l))
            .buffered(self.cfg.fetch_concurrency.max(1))
            .filter_map(|c| async move { c })
            .collect()
            .await;
        // Custom rules compile last so their `@@` exceptions apply to every list.
        contents.extend(self.custom_rules());
        self.compile_install(contents).await
    }

    fn record(&self, list: &FilterList, status: &ListStatus) {
        if let Err(e) = self.store.set_status(&list.id, status) {
            warn!("Failed to persist status for {}: {e}", list.name);
        }
    }

    /// Fetch one list conditionally; fall back to the cached copy on any failure.
    async fn fetch_one(&self, mut list: FilterList) -> Option<String> {
        let cached = self.store.get_content(&list.id).ok().flatten();
        let mut status = self.store.get_status(&list.id).unwrap_or_default();
        status.last_checked = Some(Utc::now());

        match self.download(&list, &status, cached.is_some()).await {
            Ok(Fetched::NotModified) => match cached {
                Some(c) => {
                    status.last_success = status.last_checked;
                    status.last_error = None;
                    self.record(&list, &status);
                    Some(c)
                }
                None => {
                    status.last_error = Some("304 without cached content".into());
                    self.record(&list, &status);
                    None
                }
            },
            Ok(Fetched::Body {
                text,
                etag,
                last_modified,
            }) => {
                list.etag = etag;
                list.rule_count = count_rules(&text);
                list.last_updated = status.last_checked;
                status.last_modified = last_modified;
                status.last_success = status.last_checked;
                status.last_error = None;
                if let Err(e) = self.store.put_content(&list.id, &text) {
                    warn!("Failed to cache content for {}: {e}", list.name);
                }
                if let Err(e) = self.store.upsert(&list) {
                    warn!("Failed to persist metadata for {}: {e}", list.name);
                }
                self.record(&list, &status);
                info!("Downloaded {} ({} rules)", list.name, list.rule_count);
                Some(text)
            }
            Err(e) => {
                warn!("List {}: {e}; falling back to cache", list.name);
                status.last_error = Some(e);
                self.record(&list, &status);
                cached
            }
        }
    }

    async fn download(
        &self,
        list: &FilterList,
        status: &ListStatus,
        have_cache: bool,
    ) -> std::result::Result<Fetched, String> {
        let mut req = self.client.get(&list.url).timeout(self.cfg.fetch_timeout);
        // Validators are only useful when there is cached content to reuse on a 304.
        if have_cache {
            if let Some(etag) = &list.etag {
                req = req.header(IF_NONE_MATCH, etag);
            }
            if let Some(lm) = &status.last_modified {
                req = req.header(IF_MODIFIED_SINCE, lm);
            }
        }
        let resp = req.send().await.map_err(|e| e.to_string())?;
        let code = resp.status();
        if code == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(Fetched::NotModified);
        }
        if !code.is_success() {
            return Err(format!("HTTP {code}"));
        }
        let hdr = |name| {
            resp.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        let (etag, last_modified) = (hdr(ETAG), hdr(LAST_MODIFIED));
        let body = read_capped(resp, self.cfg.max_list_bytes).await?;
        Ok(Fetched::Body {
            text: String::from_utf8_lossy(&body).into_owned(),
            etag,
            last_modified,
        })
    }
}

enum Fetched {
    NotModified,
    Body {
        text: String,
        etag: Option<String>,
        last_modified: Option<String>,
    },
}

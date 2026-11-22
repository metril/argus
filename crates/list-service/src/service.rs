//! The list service: fetch, convert, compile and install, single-flight.
//!
//! Per list: `fetch -> detect/convert -> dedupe -> compile`. Conversion and parsing run on the
//! rayon pool inside `spawn_blocking` (never on async workers). After a successful build the
//! compiled engine is persisted; at startup it is loaded if its cache key still matches.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use common::net_policy::{control_plane_client, is_refusal, NetPolicy};
use filter_engine::{
    build_set, formats::find_includes, try_build_engine, FilterList, ListFormat, ListInput,
    ListReport, SharedEngine,
};
use futures_util::StreamExt;
use parking_lot::Mutex;
use reqwest::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::persist::{self, KeyEntry};
use crate::report::{BuildState, BuildSummary};
use crate::store::{ListStatus, ListStore, CUSTOM_REPORT_ID};
use crate::{Error, Result};

/// Runtime settings of the list service.
#[derive(Debug, Clone)]
pub struct ListServiceConfig {
    /// Master switch: when false, [`ListService::start`] does nothing.
    pub enabled: bool,
    /// Directory for the list store, the persisted engine and the scriptlet resource cache.
    pub data_dir: PathBuf,
    pub auto_update: bool,
    pub update_interval: Duration,
    /// Scriptlet resource source (a directory of uBO resource files, a single `.js`, or a ready
    /// `.json` array); empty disables loading (and the bundled fallback).
    pub scriptlet_resources_url: String,
    /// Max simultaneous list downloads.
    pub fetch_concurrency: usize,
    /// Per-list request timeout (whole request including body).
    pub fetch_timeout: Duration,
    /// Max accepted size of a downloaded list / resource, in bytes.
    pub max_list_bytes: usize,
    pub scriptlet_retry_initial: Duration,
    pub scriptlet_retry_max: Duration,
    /// Persist the compiled engine to `<data_dir>/engine.bin` and load it at startup. Off by
    /// default so ad-hoc services (tests) never write to a relative default directory;
    /// [`Self::from_adblock`] turns it on.
    pub persist_engine: bool,
    /// Extra control-plane fetch destinations (CIDRs, IPs, host names) allowed although they are
    /// private; loopback, link-local and other reserved addresses stay refused unless listed as
    /// a CIDR/IP.
    pub allowed_fetch_destinations: Vec<String>,
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
            persist_engine: false,
            allowed_fetch_destinations: Vec::new(),
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
            persist_engine: true,
            allowed_fetch_destinations: a.allowed_fetch_destinations.clone(),
            ..Self::default()
        }
    }
}

#[derive(Default)]
struct Flight {
    running: bool,
    pending: bool,
    /// A pending or starting build must ignore per-list `Expires` and revalidate every list.
    force: bool,
}

/// A list ready to build: fetched (or cached) text plus resolved includes.
pub(crate) struct BuildInput {
    pub(crate) id: String,
    pub(crate) format: ListFormat,
    pub(crate) allowlist: bool,
    /// Extended rules of this list may run code / rewrite content (custom rules always do).
    pub(crate) trusted: bool,
    pub(crate) content: String,
    pub(crate) includes: HashMap<String, String>,
    pub(crate) digest: String,
}

/// Stamp [`ExtRule::trusted`] on every rule of a trusted list.
pub(crate) fn mark_trusted(
    ext: &mut [filter_engine::ExtRule],
    trusted: &std::collections::HashSet<String>,
) {
    for e in ext {
        if trusted.contains(&e.list) {
            e.trusted = true;
        }
    }
}

/// Build the shared extended-rule index (trust comes from [`ExtRule::trusted`] and `trusted`).
pub(crate) fn build_ext_index(
    ext: &[filter_engine::ExtRule],
    trusted: &std::collections::HashSet<String>,
) -> Arc<ext_rules::ExtIndex> {
    Arc::new(ext_rules::ExtIndex::build_with(
        ext,
        &ext_rules::BuildOptions {
            trusted_lists: trusted.clone(),
            ..Default::default()
        },
    ))
}

/// Owns lists, content, compile and install for one [`SharedEngine`].
pub struct ListService {
    pub(crate) cfg: ListServiceConfig,
    store: Arc<ListStore>,
    pub(crate) engine: Arc<SharedEngine>,
    pub(crate) client: reqwest::Client,
    /// Control-plane destination policy; `None` only for ad-hoc services built with
    /// [`ListService::new`] (tests), which fetch from anywhere.
    guard: Option<Arc<NetPolicy>>,
    flight: Mutex<Flight>,
    busy: watch::Sender<bool>,
    builds: AtomicU64,
    installed_once: AtomicBool,
    /// Cache key of the installed engine, to skip recompiling identical inputs.
    installed_key: Mutex<Option<persist::Key>>,
    summary: Mutex<BuildSummary>,
    /// Live build state, progress and last cycle (see [`ListService::summary`]).
    state: Mutex<BuildState>,
    fetch_done: AtomicUsize,
    last_cycle: Mutex<(Option<chrono::DateTime<Utc>>, u64)>,
    pub(crate) scriptlets_tx: watch::Sender<bool>,
    /// `true` once a fetched/cached resource library was applied (it then outranks the bundled one).
    fetched_resources: Arc<Mutex<bool>>,
    pub(crate) bundled_tried: AtomicBool,
    /// Live auto-update schedule: `(auto_update, interval)`.
    schedule: watch::Sender<(bool, Duration)>,
    /// Per-list-set engines (see [`ListService::engine_for`]).
    pub(crate) sets: crate::sets::SetRegistry,
    /// Test hook: make the next build panic.
    #[cfg(test)]
    panic_next: AtomicBool,
    /// Test hook: make the next engine load fail (as an over-limit rule count does).
    #[cfg(test)]
    fail_compile: AtomicBool,
}

/// Clears the single-flight state on drop, so a build that panics (or a cancelled build task)
/// cannot leave `running`/`busy` stuck and hang [`ListService::wait_idle`].
struct FlightGuard(Arc<ListService>);

impl Drop for FlightGuard {
    fn drop(&mut self) {
        let mut f = self.0.flight.lock();
        *f = Flight::default();
        self.0.busy.send_replace(false);
    }
}

fn same_origin(a: &reqwest::Url, b: &reqwest::Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

/// Render a request error, naming a policy refusal plainly.
fn send_error(e: &reqwest::Error) -> String {
    if is_refusal(e) {
        "destination refused by the fetch policy (see adblock.allowed_fetch_destinations)".into()
    } else {
        // Include the cause (for example why a redirect was refused).
        let mut out = e.to_string();
        let mut cur = std::error::Error::source(e);
        while let Some(c) = cur {
            out.push_str(": ");
            out.push_str(&c.to_string());
            cur = c.source();
        }
        out
    }
}

/// Compressed-to-decoded ratio beyond which a download is treated as a decompression bomb.
const MAX_RATIO: usize = 100;
/// The ratio cap only applies once this many decoded bytes were produced.
const RATIO_FLOOR: usize = 1024 * 1024;

/// Read a response body, failing once its DECODED size exceeds `cap` bytes. gzip, deflate, br
/// and zstd are decoded as a stream; the decoded-to-encoded ratio is capped too.
pub(crate) async fn read_capped(
    resp: reqwest::Response,
    cap: usize,
) -> std::result::Result<Vec<u8>, String> {
    use async_compression::tokio::bufread::{BrotliDecoder, GzipDecoder, ZlibDecoder, ZstdDecoder};
    use tokio::io::AsyncReadExt;

    let coding = match resp.headers().get(reqwest::header::CONTENT_ENCODING) {
        None => String::new(),
        Some(v) => v
            .to_str()
            .map_err(|_| "unreadable Content-Encoding".to_string())?
            .trim()
            .to_ascii_lowercase(),
    };
    if matches!(coding.as_str(), "" | "identity") {
        let mut resp = resp;
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
        return Ok(body);
    }
    if !matches!(
        coding.as_str(),
        "gzip" | "x-gzip" | "deflate" | "br" | "zstd"
    ) {
        return Err(format!("unsupported Content-Encoding \"{coding}\""));
    }
    let read = Arc::new(AtomicUsize::new(0));
    let counter = read.clone();
    let stream = resp.bytes_stream().map(move |r| {
        r.inspect(|b| {
            counter.fetch_add(b.len(), Ordering::Relaxed);
        })
        .map_err(std::io::Error::other)
    });
    let input = tokio_util::io::StreamReader::new(stream);
    let mut dec: std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>> = match coding.as_str() {
        "gzip" | "x-gzip" => Box::pin(GzipDecoder::new(input)),
        "deflate" => Box::pin(ZlibDecoder::new(input)),
        "br" => Box::pin(BrotliDecoder::new(input)),
        _ => Box::pin(ZstdDecoder::new(input)),
    };
    let mut body: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = dec
            .read(&mut buf)
            .await
            .map_err(|e| format!("decoding {coding} body: {e}"))?;
        if n == 0 {
            break;
        }
        if body.len() + n > cap {
            return Err(format!("response exceeds size cap of {cap} bytes"));
        }
        body.extend_from_slice(&buf[..n]);
        let enc = read.load(Ordering::Relaxed).max(1);
        if body.len() >= RATIO_FLOOR && body.len() / enc > MAX_RATIO {
            return Err(format!(
                "compression ratio exceeds {MAX_RATIO}:1 (decompression bomb?)"
            ));
        }
    }
    Ok(body)
}

/// Approximate rule count: non-empty, non-comment lines (replaced by the build report once the
/// list is compiled).
fn count_rules(content: &str) -> usize {
    content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with(['!', '#']))
        .count()
}

fn sorted_includes(m: &HashMap<String, String>) -> Vec<(&String, &String)> {
    let mut v: Vec<_> = m.iter().collect();
    v.sort();
    v
}

impl ListService {
    /// Build a service over an existing store (no seeding).
    pub fn new(
        cfg: ListServiceConfig,
        store: Arc<ListStore>,
        engine: Arc<SharedEngine>,
        client: reqwest::Client,
    ) -> Arc<Self> {
        Self::new_guarded(cfg, store, engine, client, None)
    }

    /// Like [`Self::new`] with a control-plane fetch policy applied to every URL (the client
    /// should be built with [`common::net_policy::control_plane_client`] on the same policy).
    pub fn new_guarded(
        cfg: ListServiceConfig,
        store: Arc<ListStore>,
        engine: Arc<SharedEngine>,
        client: reqwest::Client,
        guard: Option<Arc<NetPolicy>>,
    ) -> Arc<Self> {
        let schedule = watch::channel((cfg.auto_update, cfg.update_interval)).0;
        let summary = store.get_summary().unwrap_or_default();
        Arc::new(Self {
            schedule,
            sets: Default::default(),
            cfg,
            store,
            engine,
            client,
            guard,
            flight: Mutex::new(Flight::default()),
            busy: watch::channel(false).0,
            builds: AtomicU64::new(0),
            installed_once: AtomicBool::new(false),
            installed_key: Mutex::new(None),
            summary: Mutex::new(summary),
            state: Mutex::new(BuildState::Idle),
            fetch_done: AtomicUsize::new(0),
            last_cycle: Mutex::new((None, 0)),
            scriptlets_tx: watch::channel(false).0,
            fetched_resources: Arc::new(Mutex::new(false)),
            bundled_tried: AtomicBool::new(false),
            #[cfg(test)]
            panic_next: AtomicBool::new(false),
            #[cfg(test)]
            fail_compile: AtomicBool::new(false),
        })
    }

    /// Open the store under `cfg.data_dir`, seed default lists on a fresh install and build the
    /// list-download HTTP client.
    pub fn open(cfg: ListServiceConfig, engine: Arc<SharedEngine>) -> Result<Arc<Self>> {
        let store = ListStore::open(&cfg.data_dir)?;
        store.seed_defaults_if_empty()?;
        let guard = Arc::new(
            NetPolicy::control_plane(&cfg.allowed_fetch_destinations)
                .map_err(|e| Error::Other(e.to_string()))?,
        );
        let client = control_plane_client(guard.clone())
            .user_agent(concat!("AdBlocker/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| Error::Other(format!("build list-download client: {e}")))?;
        Ok(Self::new_guarded(cfg, store, engine, client, Some(guard)))
    }

    /// The control-plane fetch policy (every list, include and resource URL is held to it).
    pub fn fetch_policy(&self) -> Option<&Arc<NetPolicy>> {
        self.guard.as_ref()
    }

    pub fn store(&self) -> &Arc<ListStore> {
        &self.store
    }

    /// The engine this service installs into (also carries the extended-rule list and IP filter).
    pub fn engine(&self) -> &Arc<SharedEngine> {
        &self.engine
    }

    pub(crate) fn fetched_resources_handle(&self) -> Arc<Mutex<bool>> {
        self.fetched_resources.clone()
    }

    /// Number of build cycles started so far.
    pub fn build_count(&self) -> u64 {
        self.builds.load(Ordering::Acquire)
    }

    /// Totals of the last build (also available right after a restart), with the live build
    /// state and the duration and finish time of the last whole build cycle.
    pub fn summary(&self) -> BuildSummary {
        let mut s = self.summary.lock().clone();
        s.state = self.state.lock().clone();
        let (at, ms) = *self.last_cycle.lock();
        if at.is_some() {
            s.last_build_at = at;
            s.last_build_ms = ms;
        }
        s
    }

    /// Whether a build is running or queued (the same signal [`Self::wait_idle`] waits on).
    pub fn is_building(&self) -> bool {
        *self.busy.borrow()
    }

    fn set_state(&self, s: BuildState) {
        *self.state.lock() = s;
    }

    /// What the last build made of list `id`: detected format, rule counts, first errors,
    /// header metadata.
    pub fn report(&self, id: &str) -> Option<ListReport> {
        self.store.get_report(id).ok().flatten()
    }

    /// The report of the custom rules.
    pub fn custom_rules_report(&self) -> Option<ListReport> {
        self.report(CUSTOM_REPORT_ID)
    }

    /// Receiver that turns `true` once scriptlet resources are loaded from the network or cache
    /// (the bundled snapshot is applied earlier and does not count).
    pub fn scriptlets_ready(&self) -> watch::Receiver<bool> {
        self.scriptlets_tx.subscribe()
    }

    /// Start background work and return immediately: an initial load (the persisted engine or
    /// cached content is installed first, then lists are refreshed), scriptlet resource loading
    /// and the auto-update ticker. No-op when disabled.
    pub fn start(self: &Arc<Self>) {
        if !self.cfg.enabled {
            return;
        }
        self.trigger();
        let this = self.clone();
        tokio::spawn(async move { this.ensure_scriptlet_resources().await });
        let this = self.clone();
        tokio::spawn(async move {
            let mut rx = this.schedule.subscribe();
            loop {
                let (auto, interval) = *rx.borrow_and_update();
                if !auto {
                    if rx.changed().await.is_err() {
                        break;
                    }
                    continue;
                }
                tokio::select! {
                    _ = tokio::time::sleep(this.next_wake(interval)) => {
                        info!("Auto-update: checking filter lists");
                        this.trigger_due();
                    }
                    r = rx.changed() => {
                        if r.is_err() {
                            break;
                        }
                    }
                }
            }
        });
    }

    /// Shortest of the global interval and the `! Expires:` of any enabled list.
    fn next_wake(&self, interval: Duration) -> Duration {
        let shortest = self
            .store
            .get_all()
            .unwrap_or_default()
            .into_iter()
            .filter(|l| l.enabled)
            .filter_map(|l| self.report(&l.id)?.meta.expires_secs)
            .min()
            .map(Duration::from_secs);
        shortest.map_or(interval, |s| s.min(interval))
    }

    /// Change the auto-update schedule while running; takes effect immediately.
    pub fn set_schedule(&self, auto_update: bool, interval: Duration) {
        self.schedule.send_replace((auto_update, interval));
    }

    /// The current `(auto_update, interval)` schedule.
    pub fn schedule(&self) -> (bool, Duration) {
        *self.schedule.borrow()
    }

    /// Request a rebuild without waiting; every list is revalidated. Overlapping triggers
    /// coalesce: at most one build runs, and triggers arriving while it runs cause exactly one
    /// follow-up build.
    pub fn trigger(self: &Arc<Self>) {
        self.trigger_with(true);
    }

    /// Like [`Self::trigger`], but lists whose `! Expires:` interval has not elapsed since their
    /// last successful fetch are not re-downloaded (used by the auto-update ticker).
    pub fn trigger_due(self: &Arc<Self>) {
        self.trigger_with(false);
    }

    fn trigger_with(self: &Arc<Self>, force: bool) {
        {
            let mut f = self.flight.lock();
            if f.running {
                f.pending = true;
                f.force |= force;
                return;
            }
            f.running = true;
            f.force = force;
            self.busy.send_replace(true);
        }
        let this = self.clone();
        tokio::spawn(async move {
            let _guard = FlightGuard(this.clone());
            loop {
                let force = std::mem::take(&mut this.flight.lock().force);
                // Run the build as its own task so a panic surfaces as a `JoinError` here.
                let build = this.clone();
                let started = Instant::now();
                match tokio::spawn(async move { build.build_once(force).await }).await {
                    Ok(Ok(())) => {
                        this.set_state(BuildState::Idle);
                        this.refresh_sets().await;
                    }
                    Ok(Err(e)) => {
                        warn!("Filter reload failed; the previous engine stays installed: {e}");
                        this.set_state(BuildState::Failed {
                            error: e.to_string(),
                        });
                    }
                    Err(e) => {
                        warn!("Filter reload panicked: {e}");
                        this.record_build_failure("filter reload panicked");
                        this.set_state(BuildState::Failed {
                            error: "filter reload panicked".into(),
                        });
                    }
                }
                *this.last_cycle.lock() = (Some(Utc::now()), started.elapsed().as_millis() as u64);
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

    /// Record a whole-build failure on every enabled list's status.
    fn record_build_failure(&self, msg: &str) {
        for list in self.store.get_all().unwrap_or_default() {
            if list.enabled {
                let mut status = self.store.get_status(&list.id).unwrap_or_default();
                status.last_checked = Some(Utc::now());
                status.last_error = Some(msg.to_string());
                self.record(&list, &status);
            }
        }
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

    // ---- build -----------------------------------------------------------------------------

    fn custom_rules(&self) -> Option<String> {
        self.store
            .get_custom_rules()
            .ok()
            .filter(|r| !r.trim().is_empty())
    }

    fn custom_digest(custom: Option<&str>) -> String {
        persist::content_digest(custom.unwrap_or(""), std::iter::empty())
    }

    fn key_of(inputs: &[BuildInput]) -> persist::Key {
        let mut entries: Vec<KeyEntry<'_>> = inputs
            .iter()
            .filter(|i| i.id != CUSTOM_REPORT_ID)
            .map(|i| KeyEntry {
                id: &i.id,
                format: i.format,
                allowlist: i.allowlist,
                trusted: i.trusted,
                digest: &i.digest,
            })
            .collect();
        let custom = inputs
            .iter()
            .find(|i| i.id == CUSTOM_REPORT_ID)
            .map(|i| i.content.as_str());
        persist::engine_key(&mut entries, &Self::custom_digest(custom))
    }

    /// The cache key of the current store state, from stored content digests (no list text is
    /// read). `None` if any enabled list has no digest yet.
    fn key_from_store(&self, enabled: &[FilterList]) -> Option<persist::Key> {
        let digests: Vec<String> = enabled
            .iter()
            .map(|l| self.store.get_status(&l.id).ok()?.content_sha)
            .collect::<Option<_>>()?;
        let mut entries: Vec<KeyEntry<'_>> = enabled
            .iter()
            .zip(&digests)
            .map(|(l, d)| KeyEntry {
                id: &l.id,
                format: l.format,
                allowlist: l.allowlist,
                trusted: l.trusted,
                digest: d,
            })
            .collect();
        let custom = self.custom_rules();
        Some(persist::engine_key(
            &mut entries,
            &Self::custom_digest(custom.as_deref()),
        ))
    }

    /// Cached (offline) inputs: list text from the store, includes from the include cache.
    async fn cached_inputs(&self, enabled: &[FilterList]) -> Vec<BuildInput> {
        let mut out = Vec::new();
        for l in enabled {
            if let Some(content) = self.store.get_content(&l.id).ok().flatten() {
                let includes = self.resolve_includes(l, &content, false).await;
                out.push(self.make_input(l, content, includes));
            }
        }
        out.extend(self.custom_input());
        out
    }

    fn custom_input(&self) -> Option<BuildInput> {
        self.custom_rules().map(|c| BuildInput {
            id: CUSTOM_REPORT_ID.to_string(),
            format: ListFormat::Abp,
            allowlist: false,
            trusted: true,
            digest: Self::custom_digest(Some(&c)),
            content: c,
            includes: HashMap::new(),
        })
    }

    pub(crate) fn make_input(
        &self,
        list: &FilterList,
        content: String,
        includes: HashMap<String, String>,
    ) -> BuildInput {
        let digest = persist::content_digest(&content, sorted_includes(&includes));
        let mut status = self.store.get_status(&list.id).unwrap_or_default();
        if status.content_sha.as_deref() != Some(&digest) {
            status.content_sha = Some(digest.clone());
            if let Err(e) = self.store.set_status(&list.id, &status) {
                warn!("Failed to persist content digest for {}: {e}", list.name);
            }
        }
        BuildInput {
            id: list.id.clone(),
            format: list.format,
            allowlist: list.allowlist,
            trusted: list.trusted,
            content,
            includes,
            digest,
        }
    }

    /// Convert and compile `inputs` off the async threads, install the result and persist it.
    async fn compile_install(&self, inputs: Vec<BuildInput>) -> Result<()> {
        self.set_state(BuildState::Compiling);
        let key = Self::key_of(&inputs);
        let ids: Vec<String> = inputs.iter().map(|i| i.id.clone()).collect();
        let trusted_lists: std::collections::HashSet<String> = inputs
            .iter()
            .filter(|i| i.trusted)
            .map(|i| i.id.clone())
            .collect();
        let resources = self.engine.resources();
        let started = Instant::now();
        #[cfg(test)]
        let fail = self.fail_compile.swap(false, Ordering::AcqRel);
        let (built, engine, index) = tokio::task::spawn_blocking(move || {
            let list_inputs: Vec<ListInput> = inputs
                .into_iter()
                .map(|i| ListInput {
                    id: i.id,
                    content: i.content,
                    format: i.format,
                    allowlist: i.allowlist,
                    trusted: i.trusted,
                    includes: i.includes,
                })
                .collect();
            let mut built = build_set(&list_inputs);
            mark_trusted(&mut built.ext, &trusted_lists);
            // A blob the engine cannot load back (for example more rules than its flatbuffer
            // verifier allows) must fail the build, not silently install an empty engine.
            #[cfg(test)]
            if fail {
                return Err(Error::Other("injected engine load failure".into()));
            }
            let engine = try_build_engine(&built.blob, &resources).map_err(Error::Other)?;
            let index = build_ext_index(&built.ext, &trusted_lists);
            Ok::<_, Error>((built, engine, index))
        })
        .await
        .map_err(|e| Error::Other(format!("compile task failed: {e}")))??;

        let now = Utc::now();
        let mut summary = BuildSummary {
            built_at: Some(now),
            duration_ms: started.elapsed().as_millis() as u64,
            lists: ids.len(),
            engine_key: persist::hex(&key),
            ..Default::default()
        };
        for (id, report) in ids.iter().zip(&built.reports) {
            summary.network += report.network;
            summary.cosmetic += report.cosmetic;
            summary.ext += report.ext;
            summary.rejected += report.rejected;
            summary.ip_ranges += report.ip_ranges;
            summary.duplicates += report.duplicates;
            let mut report = report.clone();
            crate::report::sanitize_report(&mut report);
            let report = &report;
            if let Err(e) = self.store.set_report(id, report) {
                warn!("Failed to persist report for {id}: {e}");
            }
            if id != CUSTOM_REPORT_ID {
                if let Ok(Some(mut list)) = self.store.get(id) {
                    list.rule_count = report.network + report.cosmetic + report.ext;
                    let _ = self.store.upsert(&list);
                }
            }
        }
        if built.reports.len() < ids.len() {
            warn!("build produced fewer reports than lists");
        }
        summary.domain_set = built.domains.len();
        summary.ext_stats = Some(index.stats().clone());
        let (ext, ip, blob, domains) = (
            Arc::new(built.ext),
            Arc::new(built.ip),
            Arc::new(built.blob),
            Arc::new(built.domains),
        );
        info!(
            "Compiled {} list(s): {} network, {} cosmetic, {} extended, {} rejected, {} duplicate rules dropped in {} ms",
            summary.lists, summary.network, summary.cosmetic, summary.ext, summary.rejected,
            summary.duplicates, summary.duration_ms
        );
        // Engine and extended-rule index are one generation: swapped together.
        self.engine.install_set_with(
            blob.clone(),
            engine,
            Some(index),
            ext.clone(),
            ip.clone(),
            domains.clone(),
        );
        self.installed_once.store(true, Ordering::Release);
        *self.installed_key.lock() = Some(key);
        if let Err(e) = self.store.set_summary(&summary) {
            warn!("Failed to persist build summary: {e}");
        }
        *self.summary.lock() = summary.clone();

        if self.cfg.persist_engine {
            let path = self.cfg.data_dir.join(persist::FILE_NAME);
            let res = tokio::task::spawn_blocking(move || {
                persist::save(&path, &key, &blob, &domains, &ext, &ip, &summary)
            })
            .await;
            match res {
                Ok(Ok(())) => {}
                Ok(Err(e)) => warn!("Failed to persist compiled engine: {e}"),
                Err(e) => warn!("Persist task failed: {e}"),
            }
        }
        Ok(())
    }

    /// Install the persisted engine if its key matches the store's current state.
    async fn try_load_persisted(&self, key: persist::Key) -> bool {
        let path = self.cfg.data_dir.join(persist::FILE_NAME);
        let resources = self.engine.resources();
        let res = tokio::task::spawn_blocking(move || {
            let existed = path.exists();
            let p = persist::load(&path, &key).map_err(|e| (e, existed))?;
            let engine = try_build_engine(&p.blob, &resources).map_err(|e| (e, true))?;
            // The index is derived data: rebuilt from the persisted rules (their trust flags
            // are part of the cache key, so they are exactly what the build used).
            let index = build_ext_index(&p.ext, &std::collections::HashSet::new());
            Ok::<_, (String, bool)>((p, engine, index))
        })
        .await;
        match res {
            Ok(Ok((p, engine, index))) => {
                let mut summary = p.summary;
                summary.from_persisted = true;
                summary.domain_set = p.domains.len();
                info!(
                    "Loaded persisted filter engine ({} network, {} cosmetic rules)",
                    summary.network, summary.cosmetic
                );
                summary.ext_stats = Some(index.stats().clone());
                self.engine.install_set_with(
                    Arc::new(p.blob),
                    engine,
                    Some(index),
                    Arc::new(p.ext),
                    Arc::new(p.ip),
                    Arc::new(p.domains),
                );
                self.installed_once.store(true, Ordering::Release);
                *self.installed_key.lock() = Some(key);
                *self.summary.lock() = summary;
                true
            }
            Ok(Err((e, existed))) => {
                if existed {
                    warn!("Ignoring persisted filter engine: {e}");
                }
                false
            }
            Err(e) => {
                warn!("Persisted-engine load task failed: {e}");
                false
            }
        }
    }

    async fn build_once(&self, force: bool) -> Result<()> {
        #[cfg(test)]
        if self.panic_next.swap(false, Ordering::AcqRel) {
            panic!("injected build panic");
        }
        self.builds.fetch_add(1, Ordering::AcqRel);
        self.load_bundled_resources().await;
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

        // First build of the process: serve the persisted engine (or cached rules) immediately,
        // before touching the network.
        if !self.installed_once.load(Ordering::Acquire) {
            let loaded = match self
                .cfg
                .persist_engine
                .then(|| self.key_from_store(&enabled))
            {
                Some(Some(key)) => self.try_load_persisted(key).await,
                _ => false,
            };
            if !loaded {
                let cached = self.cached_inputs(&enabled).await;
                if !cached.is_empty() {
                    self.compile_install(cached).await?;
                }
            }
        }

        let total = enabled.len();
        self.fetch_done.store(0, Ordering::Relaxed);
        self.set_state(BuildState::Fetching { done: 0, total });
        let mut inputs: Vec<BuildInput> = futures_util::stream::iter(enabled)
            .map(|l| async move {
                let r = self.fetch_one(l, force).await;
                let done = self.fetch_done.fetch_add(1, Ordering::Relaxed) + 1;
                self.set_state(BuildState::Fetching { done, total });
                r
            })
            .buffered(self.cfg.fetch_concurrency.max(1))
            .filter_map(|c| async move { c })
            .collect()
            .await;
        // Custom rules compile last so their `@@` exceptions apply to every list.
        inputs.extend(self.custom_input());
        if *self.installed_key.lock() == Some(Self::key_of(&inputs)) {
            info!("Filter lists unchanged; keeping the installed engine");
            return Ok(());
        }
        self.compile_install(inputs).await
    }

    fn record(&self, list: &FilterList, status: &ListStatus) {
        if let Err(e) = self.store.set_status(&list.id, status) {
            warn!("Failed to persist status for {}: {e}", list.name);
        }
    }

    /// Is the cached copy of `list` still within its own `! Expires:` interval?
    fn fresh_per_expires(&self, list: &FilterList, status: &ListStatus) -> bool {
        let Some(expires) = self.report(&list.id).and_then(|r| r.meta.expires_secs) else {
            return false;
        };
        status
            .last_success
            .is_some_and(|t| (Utc::now() - t).num_seconds() < expires as i64)
    }

    /// Fetch one list conditionally; fall back to the cached copy on any failure.
    pub(crate) async fn fetch_one(&self, mut list: FilterList, force: bool) -> Option<BuildInput> {
        let cached = self.store.get_content(&list.id).ok().flatten();
        let mut status = self.store.get_status(&list.id).unwrap_or_default();

        if !force && cached.is_some() && self.fresh_per_expires(&list, &status) {
            let content = cached?;
            let includes = self.resolve_includes(&list, &content, false).await;
            return Some(self.make_input(&list, content, includes));
        }
        status.last_checked = Some(Utc::now());

        let text = match self.download(&list, &status, cached.is_some()).await {
            Ok(Fetched::NotModified) => match cached {
                Some(c) => {
                    status.last_success = status.last_checked;
                    status.last_error = None;
                    self.record(&list, &status);
                    c
                }
                None => {
                    status.last_error = Some("304 without cached content".into());
                    self.record(&list, &status);
                    return None;
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
                // Store writes (content file, metadata, status) are blocking IO: off the async
                // threads.
                let store = self.store.clone();
                let (l, st, t) = (list.clone(), status.clone(), text.clone());
                let res = tokio::task::spawn_blocking(move || {
                    if let Err(e) = store.put_content(&l.id, &t) {
                        warn!("Failed to cache content for {}: {e}", l.name);
                    }
                    if let Err(e) = store.upsert(&l) {
                        warn!("Failed to persist metadata for {}: {e}", l.name);
                    }
                    if let Err(e) = store.set_status(&l.id, &st) {
                        warn!("Failed to persist status for {}: {e}", l.name);
                    }
                })
                .await;
                if let Err(e) = res {
                    warn!("Store write task for {} failed: {e}", list.name);
                }
                info!("Downloaded {} ({} rules)", list.name, list.rule_count);
                text
            }
            Err(e) => {
                warn!("List {}: {e}; falling back to cache", list.name);
                status.last_error = Some(e);
                self.record(&list, &status);
                cached?
            }
        };
        let includes = self.resolve_includes(&list, &text, true).await;
        Some(self.make_input(&list, text, includes))
    }

    /// Resolve `!#include` targets of `content` (same origin as the list URL, at most 16, cached
    /// in the store). With `fetch` false only the cache is consulted.
    pub(crate) async fn resolve_includes(
        &self,
        list: &FilterList,
        content: &str,
        fetch: bool,
    ) -> HashMap<String, String> {
        const MAX_INCLUDES: usize = 16;
        let mut map = HashMap::new();
        if !content.contains("!#include") {
            return map;
        }
        let base = reqwest::Url::parse(&list.url).ok();
        let mut pending = find_includes(content);
        // All includes of one list together may not exceed the per-list size cap.
        let mut budget = self.cfg.max_list_bytes;
        while let Some(path) = pending.pop() {
            if map.len() >= MAX_INCLUDES || map.contains_key(&path) {
                continue;
            }
            let fetched = if fetch {
                match self.fetch_include(base.as_ref(), &path, budget).await {
                    Ok(t) => {
                        budget = budget.saturating_sub(t.len());
                        let _ = self.store.put_include(&list.id, &path, &t);
                        Some(t)
                    }
                    Err(e) => {
                        warn!("List {}: include `{path}`: {e}", list.name);
                        None
                    }
                }
            } else {
                None
            };
            let text = match fetched {
                Some(t) => Some(t),
                None => self.store.get_include(&list.id, &path).ok().flatten(),
            };
            if let Some(t) = text {
                pending.extend(find_includes(&t));
                map.insert(path, t);
            }
        }
        map
    }

    async fn fetch_include(
        &self,
        base: Option<&reqwest::Url>,
        path: &str,
        budget: usize,
    ) -> std::result::Result<String, String> {
        let base = base.ok_or("list URL is not absolute")?;
        let url = base.join(path).map_err(|e| e.to_string())?;
        // Includes may only come from the list's own origin.
        if !same_origin(&url, base) {
            return Err("include is on a different origin".into());
        }
        self.fetch_text(url.as_str(), Some(base), budget).await
    }

    pub(crate) async fn get_text(
        &self,
        url: impl AsRef<str>,
    ) -> std::result::Result<String, String> {
        self.fetch_text(url.as_ref(), None, self.cfg.max_list_bytes)
            .await
    }

    /// Check a URL before connecting: http(s) only and, under a guard, the control-plane policy.
    fn precheck(&self, url: &str) -> std::result::Result<(), String> {
        let u = reqwest::Url::parse(url).map_err(|_| "invalid URL".to_string())?;
        match &self.guard {
            Some(g) => g.check_url_literal(&u).map_err(|e| e.to_string()),
            None if matches!(u.scheme(), "http" | "https") => Ok(()),
            None => Err("only http and https URLs are allowed".into()),
        }
    }

    /// Check where a response actually came from (after redirects) before reading its body: the
    /// final URL must pass the policy and, for includes, stay on the list's origin.
    fn vet_response(
        &self,
        resp: &reqwest::Response,
        origin: Option<&reqwest::Url>,
    ) -> std::result::Result<(), String> {
        self.precheck(resp.url().as_str())?;
        if let Some(o) = origin {
            if !same_origin(resp.url(), o) {
                return Err("include redirected to a different origin".into());
            }
        }
        Ok(())
    }

    async fn fetch_text(
        &self,
        url: &str,
        origin: Option<&reqwest::Url>,
        cap: usize,
    ) -> std::result::Result<String, String> {
        self.precheck(url).map_err(|e| format!("{url}: {e}"))?;
        let resp = self
            .client
            .get(url)
            .header(reqwest::header::ACCEPT_ENCODING, "gzip, br, zstd")
            .timeout(self.cfg.fetch_timeout)
            .send()
            .await
            .map_err(|e| format!("{url}: {}", send_error(&e)))?;
        self.vet_response(&resp, origin)
            .map_err(|e| format!("{url}: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("{url}: HTTP {}", resp.status()));
        }
        let body = read_capped(resp, cap).await?;
        Ok(String::from_utf8_lossy(&body).into_owned())
    }

    async fn download(
        &self,
        list: &FilterList,
        status: &ListStatus,
        have_cache: bool,
    ) -> std::result::Result<Fetched, String> {
        self.precheck(&list.url)?;
        let mut req = self
            .client
            .get(&list.url)
            .header(reqwest::header::ACCEPT_ENCODING, "gzip, br, zstd")
            .timeout(self.cfg.fetch_timeout);
        // Validators are only useful when there is cached content to reuse on a 304.
        if have_cache {
            if let Some(etag) = &list.etag {
                req = req.header(IF_NONE_MATCH, etag);
            }
            if let Some(lm) = &status.last_modified {
                req = req.header(IF_MODIFIED_SINCE, lm);
            }
        }
        let resp = req.send().await.map_err(|e| send_error(&e))?;
        self.vet_response(&resp, None)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn panicking_build_does_not_hang_and_records_status() {
        let dir = tempfile::tempdir().unwrap();
        let store = ListStore::open(dir.path()).unwrap();
        store.seed_defaults_if_empty().unwrap();
        let list = store
            .get_all()
            .unwrap()
            .into_iter()
            .find(|l| l.enabled)
            .unwrap();
        let cfg = ListServiceConfig {
            data_dir: dir.path().to_path_buf(),
            ..Default::default()
        };
        let svc = ListService::new(
            cfg,
            store,
            Arc::new(SharedEngine::new()),
            reqwest::Client::new(),
        );
        svc.panic_next.store(true, Ordering::Release);
        tokio::time::timeout(Duration::from_secs(5), svc.reload_now())
            .await
            .expect("reload_now must not hang after a panic");
        let status = svc.store().get_status(&list.id).unwrap();
        assert!(status.last_error.unwrap().contains("panicked"));
        assert!(!svc.is_building());
        assert!(matches!(svc.summary().state, BuildState::Failed { .. }));
        // The flight state is clean: a later trigger can run.
        assert!(!svc.flight.lock().running);
    }

    #[tokio::test]
    async fn failed_build_keeps_serving_the_old_rules_and_reports_failure() {
        let dir = tempfile::tempdir().unwrap();
        let store = ListStore::open(dir.path()).unwrap();
        let mut l = FilterList::new(
            "one".into(),
            "One".into(),
            "https://127.0.0.1:1/one.txt".into(),
        );
        l.enabled = true;
        store.upsert(&l).unwrap();
        store.put_content("one", "||old-ad.test^\n").unwrap();
        let cfg = ListServiceConfig {
            data_dir: dir.path().to_path_buf(),
            persist_engine: false,
            ..Default::default()
        };
        let engine = Arc::new(SharedEngine::new());
        let svc = ListService::new(cfg, store, engine.clone(), reqwest::Client::new());
        svc.reload_now().await;
        assert_eq!(svc.summary().state, BuildState::Idle);
        let blocked = |u: &str| engine.check(u, "https://page.test/", "script").blocked;
        assert!(blocked("https://old-ad.test/a.js"));

        // New rules, but the engine cannot be built from them.
        svc.store().set_custom_rules("||new-ad.test^\n").unwrap();
        svc.fail_compile.store(true, Ordering::Release);
        svc.reload_now().await;
        match svc.summary().state {
            BuildState::Failed { error } => assert!(error.contains("injected"), "{error}"),
            s => panic!("expected Failed, got {s:?}"),
        }
        assert!(blocked("https://old-ad.test/a.js"), "old rules still block");
        assert!(
            !blocked("https://new-ad.test/a.js"),
            "failed build not installed"
        );

        // The next good build recovers.
        svc.reload_now().await;
        assert_eq!(svc.summary().state, BuildState::Idle);
        assert!(blocked("https://new-ad.test/a.js"));
    }
}

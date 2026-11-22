//! Shared adblock engine: one `Arc<Engine>` behind an `ArcSwap`.
//!
//! `adblock::Engine` is `Send + Sync` (the workspace builds it without the `single-thread`
//! feature), and every query method takes `&self`. The request path therefore does one atomic
//! load and calls the engine directly; there is no per-thread copy and no deserialization after a
//! reload. Reloads build the new engine off the request path and swap the pointer; in-flight
//! requests keep the old engine alive until they finish.
//!
//! The compiled blob is kept next to the live engine so it can be persisted
//! ([`SharedEngine::serialized`]) and so the resource library can be re-applied.

use adblock::request::Request as AdblockRequest;
use adblock::resources::Resource;
use adblock::Engine as AdblockEngine;
use arc_swap::ArcSwap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn};

use crate::compile::compile_lists;
use crate::domainset::{DomainHit, DomainSet, Scheme};
use crate::events::{BlockEvent, BlockLog, DEFAULT_CAPACITY};
use crate::formats::{ExtRule, IpRange, IpSet};
use crate::matcher::{MatchResult, RequestMatcher};
use crate::precheck;
use crate::redirect_resources::builtin_redirect_resources;
use crate::stats::FilterStats;

/// Cosmetic resources for a page: element-hiding selectors + scriptlet JS to inject.
#[derive(Debug, Clone, Default)]
pub struct Cosmetics {
    /// CSS selectors to hide with `{ display: none !important; }`.
    pub hide_selectors: Vec<String>,
    /// JavaScript scriptlet code to inject (empty unless the scriptlet resource library is loaded).
    pub injected_script: String,
    /// JSON-encoded procedural cosmetic filters (`:has-text`, `:matches-css`, `:upward`, actions,
    /// etc.) to be evaluated client-side.
    pub procedural_actions: Vec<String>,
    /// True if this page is excepted from generic (class/id) hiding.
    pub generichide: bool,
}

/// IP-literal host matcher (CIDR lists cannot be hostname rules); `allow` wins over `block`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpFilter {
    pub block: IpSet,
    pub allow: IpSet,
}

impl IpFilter {
    pub fn from_ranges(block: &[IpRange], allow: &[IpRange]) -> Self {
        Self {
            block: IpSet::from_ranges(block),
            allow: IpSet::from_ranges(allow),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.block.is_empty()
    }
}

/// Outcome of loading a resource library: how many resources are served and which were dropped
/// by validation (see [`crate::validate_resources`]), with the reason.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResourceReport {
    pub loaded: usize,
    pub dropped: Vec<crate::scriptlet_resources::DroppedResource>,
}

/// Handle to the live compiled engine, shared by all workers via `Arc<SharedEngine>`.
pub struct SharedEngine {
    /// The live engine generation (engine + opaque companion data). Readers do one `load()`;
    /// writers swap in a fully built generation.
    engine: ArcSwap<Generation>,
    /// Source of [`Generation::id`].
    next_gen: std::sync::atomic::AtomicU64,
    /// Serialized form of the installed rules (empty = empty engine).
    blob: ArcSwap<Vec<u8>>,
    /// Extended rules the engine cannot express (hand-off for later phases).
    ext_rules: ArcSwap<Vec<ExtRule>>,
    /// Blocked / allowed IP ranges, checked for requests to IP-literal hosts.
    ip_filter: ArcSwap<IpFilter>,
    /// Pure domain / exact-host block rules kept out of the engine (see [`crate::domainset`]).
    domains: ArcSwap<DomainSet>,
    /// Ring of recent block events.
    block_log: BlockLog,
    /// Master on/off switch, shared (see [`Self::enabled_flag`]) so the web UI toggle is live.
    enabled: Arc<AtomicBool>,
    /// User-loaded scriptlet/redirect resource library (overrides built-ins by name).
    resources: ArcSwap<Vec<Resource>>,
    /// What the last [`Self::set_resources_from_json`] kept and dropped.
    resource_report: ArcSwap<ResourceReport>,
    /// Serializes writers (install / resource load); never taken on the request path.
    write_lock: Mutex<()>,
    /// Shared, thread-safe blocking statistics.
    stats: FilterStats,
}

/// One installed engine together with data built from the same rules (the extended-rule index),
/// swapped as a unit: a reader holding a `Generation` never sees a mix of builds.
pub struct Generation {
    pub engine: Arc<AdblockEngine>,
    /// Companion built from the same build, opaque here (downcast by the owner of the type).
    pub aux: Option<Arc<dyn std::any::Any + Send + Sync>>,
    /// Strictly increasing per install; equal ids mean the same build.
    pub id: u64,
}

impl Generation {
    /// The companion data as `T`, if present and of that type.
    pub fn aux<T: std::any::Any + Send + Sync>(&self) -> Option<&T> {
        self.aux.as_deref().and_then(|a| a.downcast_ref::<T>())
    }
}

impl Default for SharedEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Deserialize `blob` (if non-empty) and apply built-in plus user resources. CPU-bound: call it
/// from `spawn_blocking` for large lists.
pub fn build_engine(blob: &[u8], user_resources: &[Resource]) -> Arc<AdblockEngine> {
    match try_build_engine(blob, user_resources) {
        Ok(e) => e,
        Err(e) => {
            warn!("{e}; using empty engine");
            apply_resources(AdblockEngine::default(), user_resources)
        }
    }
}

/// Like [`build_engine`] but reports a blob that fails to deserialize instead of falling back to
/// an empty engine.
pub fn try_build_engine(
    blob: &[u8],
    user_resources: &[Resource],
) -> Result<Arc<AdblockEngine>, String> {
    let mut engine = AdblockEngine::default();
    if !blob.is_empty() {
        engine
            .deserialize(blob)
            .map_err(|e| format!("failed to deserialize filter engine: {e:?}"))?;
    }
    Ok(apply_resources(engine, user_resources))
}

fn apply_resources(mut engine: AdblockEngine, user_resources: &[Resource]) -> Arc<AdblockEngine> {
    let mut all: Vec<Resource> = user_resources.to_vec();
    for b in builtin_redirect_resources() {
        let taken = all
            .iter()
            .any(|r| r.name == b.name || r.aliases.contains(&b.name));
        if !taken {
            all.push(b);
        }
    }
    engine.use_resources(all);
    Arc::new(engine)
}

/// URL probed by [`SharedEngine::site_off`]; the sentinel rule `||adblock.invalid^` blocks it.
pub const SITE_OFF_PROBE: &str = "https://adblock.invalid/__site_off__";

impl SharedEngine {
    /// Create an empty shared engine (allows everything until rules are installed).
    pub fn new() -> Self {
        Self::with_event_capacity(DEFAULT_CAPACITY)
    }

    /// Like [`Self::new`] with a recent-blocked ring of `capacity` events (0 disables it).
    pub fn with_event_capacity(capacity: usize) -> Self {
        Self {
            engine: ArcSwap::new(Arc::new(Generation {
                engine: build_engine(&[], &[]),
                aux: None,
                id: 0,
            })),
            next_gen: std::sync::atomic::AtomicU64::new(1),
            blob: ArcSwap::new(Arc::new(Vec::new())),
            ext_rules: ArcSwap::new(Arc::new(Vec::new())),
            ip_filter: ArcSwap::new(Arc::new(IpFilter::default())),
            domains: ArcSwap::new(Arc::new(DomainSet::empty())),
            block_log: BlockLog::new(capacity),
            enabled: Arc::new(AtomicBool::new(true)),
            resources: ArcSwap::new(Arc::new(Vec::new())),
            resource_report: ArcSwap::new(Arc::new(ResourceReport::default())),
            write_lock: Mutex::new(()),
            stats: FilterStats::new(),
        }
    }

    /// Load the scriptlet/redirect resource library from a JSON array of uBO-compatible resources
    /// (e.g. Brave's `resources.json`) and rebuild the engine. Returns the number served.
    ///
    /// Every JavaScript resource is validated first (see [`crate::validate_resources`]): one that
    /// does not parse, or whose dependencies do not resolve, is dropped and listed in
    /// [`Self::resource_report`] instead of being served.
    pub fn set_resources_from_json(&self, json: &str) -> Result<usize, serde_json::Error> {
        let parsed: Vec<Resource> = serde_json::from_str(json)?;
        let v = crate::scriptlet_resources::validate_resources(parsed);
        let resources = v.resources;
        let n = resources.len();
        for d in v.dropped.iter().take(20) {
            warn!("Dropped scriptlet resource `{}`: {}", d.name, d.reason);
        }
        if v.dropped.len() > 20 {
            warn!("... and {} more dropped resources", v.dropped.len() - 20);
        }
        let _g = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        self.resource_report.store(Arc::new(ResourceReport {
            loaded: n,
            dropped: v.dropped,
        }));
        self.resources.store(Arc::new(resources));
        let cur = self.engine.load_full();
        self.engine.store(Arc::new(Generation {
            engine: build_engine(&self.blob.load(), &self.resources.load()),
            aux: cur.aux.clone(),
            id: self.next_gen.fetch_add(1, Ordering::Relaxed),
        }));
        info!("Loaded {n} scriptlet/redirect resources");
        Ok(n)
    }

    /// What the last resource-library load kept and dropped.
    pub fn resource_report(&self) -> Arc<ResourceReport> {
        self.resource_report.load_full()
    }

    /// The scriptlet/redirect resources currently loaded (pass to [`build_engine`] off-thread).
    pub fn resources(&self) -> Arc<Vec<Resource>> {
        self.resources.load_full()
    }

    /// Install a freshly compiled, serialized engine (from [`compile_engine`]) and swap it in.
    ///
    /// Deserializes on the calling thread; from async code use `spawn_blocking`, or build with
    /// [`build_engine`] there and call [`Self::install_built`].
    pub fn install(&self, serialized: Vec<u8>) {
        let engine = build_engine(&serialized, &self.resources.load());
        self.install_built(Arc::new(serialized), engine);
    }

    /// Swap in an engine already built from `blob` by [`build_engine`] (no work on this thread).
    pub fn install_built(&self, blob: Arc<Vec<u8>>, engine: Arc<AdblockEngine>) {
        self.install_full(blob, engine, Arc::default(), Arc::default());
    }

    /// Like [`Self::install_built`], also replacing the extended-rule list and IP filter. The
    /// domain set is emptied (all rules are expected to be in the engine).
    pub fn install_full(
        &self,
        blob: Arc<Vec<u8>>,
        engine: Arc<AdblockEngine>,
        ext: Arc<Vec<ExtRule>>,
        ip: Arc<IpFilter>,
    ) {
        self.install_set(blob, engine, ext, ip, Arc::default());
    }

    /// Install everything a build produced: engine, extended rules, IP filter and domain set,
    /// swapped in one writer critical section.
    pub fn install_set(
        &self,
        blob: Arc<Vec<u8>>,
        engine: Arc<AdblockEngine>,
        ext: Arc<Vec<ExtRule>>,
        ip: Arc<IpFilter>,
        domains: Arc<DomainSet>,
    ) {
        self.install_set_with(blob, engine, None, ext, ip, domains);
    }

    /// [`Self::install_set`] plus companion data (`aux`) swapped atomically with the engine.
    pub fn install_set_with(
        &self,
        blob: Arc<Vec<u8>>,
        engine: Arc<AdblockEngine>,
        aux: Option<Arc<dyn std::any::Any + Send + Sync>>,
        ext: Arc<Vec<ExtRule>>,
        ip: Arc<IpFilter>,
        domains: Arc<DomainSet>,
    ) {
        let _g = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let bytes = blob.len();
        self.blob.store(blob);
        self.engine.store(Arc::new(Generation {
            engine,
            aux,
            id: self.next_gen.fetch_add(1, Ordering::Relaxed),
        }));
        self.ext_rules.store(ext);
        self.ip_filter.store(ip);
        let n = domains.len();
        self.domains.store(domains);
        info!("Installed compiled filter engine ({bytes} bytes, {n} domain-set entries)");
    }

    /// The installed domain set.
    pub fn domains(&self) -> Arc<DomainSet> {
        self.domains.load_full()
    }

    /// The most recent blocked requests, newest first (at most `limit`, at most the ring
    /// capacity).
    pub fn recent_blocked(&self, limit: usize) -> Vec<BlockEvent> {
        self.block_log.recent(limit)
    }

    /// Keep query strings in the recent-blocked ring (default off: they may hold secrets).
    pub fn set_recent_keep_query(&self, keep: bool) {
        self.block_log.set_keep_query(keep);
    }

    /// Capacity of the recent-blocked ring.
    pub fn recent_blocked_capacity(&self) -> usize {
        self.block_log.capacity()
    }

    /// Record a block that happened outside [`Self::check`] (for example a request the proxy
    /// refused for another reason) in the recent-blocked ring.
    pub fn record_block(&self, event: &BlockEvent) {
        self.block_log.record(
            &event.url,
            &event.source_host,
            &event.request_type,
            &event.rule,
            event.list_id.as_deref(),
            event.client.as_deref(),
        );
    }

    /// Extended rules (`$replace`, HTML filters, ...) found in the installed lists.
    pub fn ext_rules(&self) -> Arc<Vec<ExtRule>> {
        self.ext_rules.load_full()
    }

    /// The installed IP block / allow ranges.
    pub fn ip_filter(&self) -> Arc<IpFilter> {
        self.ip_filter.load_full()
    }

    /// The serialized rules currently installed (for persisting to disk).
    pub fn serialized(&self) -> Arc<Vec<u8>> {
        self.blob.load_full()
    }

    /// The live engine (one atomic load + refcount bump).
    pub fn engine(&self) -> Arc<AdblockEngine> {
        self.engine.load().engine.clone()
    }

    /// The live generation (engine + companion), one atomic load.
    pub fn generation(&self) -> Arc<Generation> {
        self.engine.load_full()
    }

    /// Id of the live generation (cheap; no refcount traffic). A check that reads this before
    /// and after its work and sees the same value ran against one build throughout.
    pub fn generation_id(&self) -> u64 {
        self.engine.load().id
    }

    /// Enable or disable blocking globally.
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    /// Whether blocking is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// The shared on/off flag, for components that want to flip or read it directly.
    pub fn enabled_flag(&self) -> Arc<AtomicBool> {
        self.enabled.clone()
    }

    /// Get a cloneable handle to the shared statistics tracker.
    pub fn stats_handle(&self) -> FilterStats {
        self.stats.clone()
    }

    /// Run `f` with the live engine: a single atomic load, no clone, no lock.
    #[inline]
    fn with_engine<R>(&self, f: impl FnOnce(&AdblockEngine) -> R) -> R {
        let guard = self.engine.load();
        f(&guard.engine)
    }

    /// Extra `Content-Security-Policy` directives (`$csp`) for a document/subdocument response.
    pub fn csp_for(&self, url: &str, source_url: &str, resource_type: &str) -> Option<String> {
        if !self.enabled.load(Ordering::Relaxed) {
            return None;
        }
        self.with_engine(|e| RequestMatcher::csp_directives(e, url, source_url, resource_type))
    }

    /// Cosmetic resources (element-hiding CSS + scriptlet JS) for a page URL.
    ///
    /// Same engine as [`Self::check`]. `generichide` is true when the page
    /// is excepted from generic (class/id) hiding — callers can use it to skip the dynamic helper.
    pub fn cosmetic_for(&self, url: &str) -> Cosmetics {
        if !self.enabled.load(Ordering::Relaxed) {
            return Cosmetics::default();
        }
        self.with_engine(|engine| {
            let res = engine.url_cosmetic_resources(url);
            Cosmetics {
                hide_selectors: res.hide_selectors.into_iter().collect(),
                injected_script: res.injected_script,
                procedural_actions: res.procedural_actions.into_iter().collect(),
                generichide: res.generichide,
            }
        })
    }

    /// Generic element-hiding selectors triggered by the given class/id tokens on a page.
    ///
    /// Used by the dynamic (MutationObserver) hiding path: the page reports the classes/ids it
    /// contains and gets back any generic hide selectors that apply. Recomputes the page's
    /// cosmetic exceptions/`generichide` so it stays stateless.
    pub fn dynamic_hide_selectors(
        &self,
        page_url: &str,
        classes: &[String],
        ids: &[String],
    ) -> Vec<String> {
        if !self.enabled.load(Ordering::Relaxed) {
            return Vec::new();
        }
        self.with_engine(|engine| {
            let res = engine.url_cosmetic_resources(page_url);
            if res.generichide {
                return Vec::new();
            }
            engine.hidden_class_id_selectors(classes, ids, &res.exceptions)
        })
    }

    /// Has the user switched ad blocking off for the page at `page_url`? Probes a sentinel rule
    /// (`||adblock.invalid^`, kept in the custom rules next to the per-site `@@$domain=` lines)
    /// as if the page requested it: an exception matching means the page is excepted. Records
    /// nothing. One engine lookup; call it for documents only.
    pub fn site_off(&self, page_url: &str) -> bool {
        self.enabled.load(Ordering::Relaxed)
            && self
                .decide(SITE_OFF_PROBE, page_url, "other")
                .exception_rule
                .is_some()
    }

    /// Check whether a network request should be blocked, recording statistics and (on a block)
    /// the recent-blocked event.
    ///
    /// `resource_type` is the adblock resource type (e.g. `script`, `image`, `document`,
    /// `websocket`, `other`). Atomic loads only; no lock. Order: IP ranges, then the domain
    /// set, then the engine (see [`Self::check_for`] to attach a client label).
    pub fn check(&self, url: &str, source_url: &str, resource_type: &str) -> MatchResult {
        self.check_inner(url, source_url, resource_type, None)
    }

    /// [`Self::check`] with an opaque client / profile label stored in the block event.
    pub fn check_for(
        &self,
        url: &str,
        source_url: &str,
        resource_type: &str,
        client: &str,
    ) -> MatchResult {
        self.check_inner(url, source_url, resource_type, Some(client))
    }

    /// [`Self::check_for`] that also returns the [`Generation`] the verdict was computed
    /// against: the caller can read the companion data (extended-rule index) of the very build
    /// that produced the verdict, never one from before or after a concurrent swap.
    pub fn check_gen(
        &self,
        url: &str,
        source_url: &str,
        resource_type: &str,
        client: &str,
    ) -> (MatchResult, Arc<Generation>) {
        loop {
            let generation = self.engine.load_full();
            let r = if self.enabled.load(Ordering::Relaxed) {
                self.decide(url, source_url, resource_type)
            } else {
                MatchResult::allowed()
            };
            // `decide` reads the live engine itself: if a swap slipped in meanwhile the verdict
            // may be from the newer build, so redo it (ids only ever grow: no ABA).
            if self.engine.load().id == generation.id {
                return (
                    self.record(r, url, source_url, resource_type, Some(client)),
                    generation,
                );
            }
        }
    }

    fn check_inner(
        &self,
        url: &str,
        source_url: &str,
        resource_type: &str,
        client: Option<&str>,
    ) -> MatchResult {
        let r = if self.enabled.load(Ordering::Relaxed) {
            self.decide(url, source_url, resource_type)
        } else {
            MatchResult::allowed()
        };
        self.record(r, url, source_url, resource_type, client)
    }

    /// Statistics and block-log bookkeeping for a finished verdict.
    fn record(
        &self,
        r: MatchResult,
        url: &str,
        source_url: &str,
        resource_type: &str,
        client: Option<&str>,
    ) -> MatchResult {
        if r.blocked {
            self.stats
                .record_blocked(resource_type, RequestMatcher::host_of(url));
            self.block_log.record(
                url,
                RequestMatcher::host_of(source_url),
                resource_type,
                r.matched_rule.as_deref().unwrap_or(""),
                r.list_id.as_deref(),
                client,
            );
        } else {
            self.stats.record_allowed();
        }
        r
    }

    /// The decision, without side effects.
    fn decide(&self, url: &str, source_url: &str, resource_type: &str) -> MatchResult {
        // Pre-check layer: IP literals, then the domain set.
        let ipf = self.ip_filter.load();
        let ds = self.domains.load();
        let host = RequestMatcher::host_of(url);
        if !ipf.is_empty()
            && (host.contains(':') || host.bytes().last().is_some_and(|b| b.is_ascii_digit()))
        {
            if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                if !ipf.allow.contains(ip) && ipf.block.contains(ip) {
                    return MatchResult::blocked(format!("ip-list:{ip}"));
                }
            }
        }
        let fast = if ds.is_empty() {
            None
        } else {
            precheck::fast(url, resource_type)
        };
        if let Some(f) = &fast {
            // adblock-rust matches `||host^` against the case-preserved hostname (so never a
            // mixed-case one) but exact rules against the lowercased URL.
            let found = if f.lower {
                ds.lookup(f.host, f.scheme)
            } else {
                ds.lookup_exact(f.host, f.scheme)
            };
            if let Some(hit) = found {
                let ok = match hit.exact {
                    // An exact rule needs the scheme to lead the URL: not with `user@`.
                    Some(_) => !f.userinfo && precheck::applies(true, f.scheme, f.rt),
                    None => precheck::applies(false, f.scheme, f.rt),
                };
                if ok {
                    return self.domain_block(&ds, hit, f.host, url, source_url, resource_type);
                }
            }
        }

        if !ds.is_empty() && !ds.engine_has_network_rules() && fast.is_some() {
            // The set missed and the engine has no network rules: nothing can block this.
            return MatchResult::allowed();
        }

        let request = match AdblockRequest::new(url, source_url, resource_type) {
            Ok(r) => r,
            Err(e) => {
                debug!("Filter check error for {url}: {e}; allowing");
                return MatchResult::allowed();
            }
        };
        if fast.is_none()
            && !ds.is_empty()
            && request.is_supported
            && !request.hostname.bytes().any(|c| c.is_ascii_uppercase())
        {
            // Unusual URL: probe with the parsed hostname (suffix rules only).
            let scheme = if request.is_http {
                Scheme::Http
            } else if request.is_https {
                Scheme::Https
            } else if request.url.as_bytes().get(2) == Some(&b's') {
                Scheme::Wss
            } else {
                Scheme::Ws
            };
            // A fully-qualified trailing dot names the same host (adblock-rust's own handling of
            // it is inconsistent, so rules in the set follow DNS semantics instead).
            let name = request
                .hostname
                .strip_suffix('.')
                .unwrap_or(&request.hostname);
            if let Some(hit) = ds.lookup(name, scheme) {
                if hit.exact.is_none()
                    && precheck::applies(false, scheme, precheck::idx(&request.request_type))
                {
                    let host = name.to_string();
                    return self.domain_block(&ds, hit, &host, url, source_url, resource_type);
                }
            }
        }
        let result = self.with_engine(|e| e.check_network_request(&request));
        RequestMatcher::to_match_result(result)
    }

    /// A domain-set hit: the block, unless the engine's exceptions / `$important` rules say
    /// otherwise (`check_network_request_subset` with "something already matched" evaluates exactly
    /// those, as the full engine would after a normal block match).
    fn domain_block(
        &self,
        ds: &DomainSet,
        hit: DomainHit,
        host: &str,
        url: &str,
        source_url: &str,
        resource_type: &str,
    ) -> MatchResult {
        let mut rule = String::with_capacity(host.len() + 12);
        match hit.exact {
            Some(s) => {
                rule.push('|');
                rule.push_str(s.as_str());
                rule.push_str("://");
                rule.push_str(host);
            }
            None => {
                rule.push_str("||");
                rule.push_str(&host[hit.start..]);
            }
        }
        rule.push('^');
        // The prefix is already lowercase; only an exact rule's host may be mixed case.
        rule.make_ascii_lowercase();
        let list = ds.list_id(hit.list).map(str::to_string);
        let plain = |rule: String, list: Option<String>| MatchResult {
            blocked: true,
            matched_rule: Some(rule),
            list_id: list,
            ..MatchResult::default()
        };
        if !ds.engine_overrides() {
            return plain(rule, list);
        }
        let Ok(request) = AdblockRequest::new(url, source_url, resource_type) else {
            return plain(rule, list);
        };
        let res = self.with_engine(|e| e.check_network_request_subset(&request, true, true));
        let mut r = RequestMatcher::to_match_result(res);
        if r.blocked && !r.important {
            r.matched_rule = Some(rule);
            r.list_id = list;
        }
        r
    }
}

/// Compile ABP/uBO rule text (one string per list) into a serialized adblock engine.
///
/// Thin wrapper over [`compile_lists`] that discards the per-list accounting. Pure-CPU and
/// `Send`-safe: call it from `spawn_blocking`.
pub fn compile_engine(list_contents: &[String]) -> Vec<u8> {
    let refs: Vec<&str> = list_contents.iter().map(String::as_str).collect();
    compile_lists(&refs).blob
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_engine_allows_everything() {
        let shared = SharedEngine::new();
        let r = shared.check(
            "https://ads.example.com/banner.jpg",
            "https://example.com",
            "image",
        );
        assert!(!r.blocked);
    }

    #[test]
    fn compiled_rule_blocks_then_allows() {
        let shared = SharedEngine::new();
        // Block any request to ad.example.com; a classic adblock network rule.
        let list = "||ad.example.com^\n".to_string();
        let bytes = compile_engine(&[list]);
        assert!(!bytes.is_empty());
        shared.install(bytes);

        let blocked = shared.check(
            "https://ad.example.com/track.gif",
            "https://news.example/page",
            "image",
        );
        assert!(blocked.blocked, "ad host should be blocked");

        let allowed = shared.check(
            "https://cdn.example/app.js",
            "https://news.example/page",
            "script",
        );
        assert!(!allowed.blocked, "unrelated host should be allowed");
    }

    #[test]
    fn cosmetic_hide_selectors_for_domain() {
        let shared = SharedEngine::new();
        // A generic + a domain-specific element-hiding rule.
        let list = "##.generic-ad\nexample.com##.sponsored\n".to_string();
        shared.install(compile_engine(&[list]));

        let cos = shared.cosmetic_for("https://example.com/page");
        assert!(
            cos.hide_selectors.iter().any(|s| s.contains(".sponsored")),
            "expected domain-specific selector, got {:?}",
            cos.hide_selectors
        );

        // Dynamic: reporting the generic class yields its hide selector.
        let dyn_sel = shared.dynamic_hide_selectors(
            "https://example.com/page",
            &["generic-ad".to_string()],
            &[],
        );
        assert!(
            dyn_sel.iter().any(|s| s.contains(".generic-ad")),
            "expected generic selector from dynamic lookup, got {dyn_sel:?}"
        );
    }

    #[test]
    fn procedural_filters_exposed() {
        let shared = SharedEngine::new();
        shared.install(compile_engine(&[
            // A procedural *selector* (no action) → comes back in hide_selectors as a raw string.
            "example.com##.box:has-text(Sponsored)\n\
             // An *action* filter → comes back in procedural_actions as JSON.\n\
             example.com##.ad:remove()\n"
                .to_string(),
        ]));

        let cos = shared.cosmetic_for("https://example.com/");
        assert!(
            cos.hide_selectors.iter().any(|s| s.contains(":has-text(")),
            "procedural selector should appear in hide_selectors, got {:?}",
            cos.hide_selectors
        );
        assert!(
            !cos.procedural_actions.is_empty(),
            "action filter should populate procedural_actions"
        );
        let v: serde_json::Value =
            serde_json::from_str(&cos.procedural_actions[0]).expect("procedural action is JSON");
        assert_eq!(v["action"]["type"], "remove");
    }

    #[test]
    fn scriptlet_injects_only_after_resources_loaded() {
        use base64::Engine as _;
        let shared = SharedEngine::new();
        shared.install(compile_engine(&["example.com##+js(noopjs)\n".to_string()]));

        // Without the resource library, scriptlets resolve to nothing (graceful degradation).
        assert!(shared
            .cosmetic_for("https://example.com/")
            .injected_script
            .is_empty());

        // Load a uBO-style resource named `noopjs.js` (lookup applies a `.js` extension).
        let content = base64::engine::general_purpose::STANDARD.encode("(function(){})();");
        let json = serde_json::json!([{
            "name": "noopjs.js",
            "aliases": [],
            "kind": {"mime": "application/javascript"},
            "content": content,
        }])
        .to_string();
        assert_eq!(shared.set_resources_from_json(&json).unwrap(), 1);

        let cos = shared.cosmetic_for("https://example.com/");
        assert!(
            !cos.injected_script.is_empty(),
            "scriptlet should inject once the resource library is loaded"
        );
    }

    #[test]
    fn allow_exception_overrides_block() {
        // A custom `@@` exception (a separate source, like user custom rules) wins over a block.
        let shared = SharedEngine::new();
        shared.install(compile_engine(&[
            "||ads.example^\n".to_string(),
            "@@||ads.example/ok^\n".to_string(),
        ]));
        assert!(
            shared
                .check("https://ads.example/track", "https://site/", "image")
                .blocked
        );
        assert!(
            !shared
                .check("https://ads.example/ok", "https://site/", "image")
                .blocked,
            "@@ exception should allow this URL"
        );
    }

    fn engine_with(rules: &[&str]) -> SharedEngine {
        let shared = SharedEngine::new();
        let lines: Vec<String> = rules.iter().map(|r| format!("{r}\n")).collect();
        shared.install(compile_engine(&lines));
        shared
    }

    #[test]
    fn engine_is_send_sync() {
        fn assert_ss<T: Send + Sync>() {}
        assert_ss::<AdblockEngine>();
        assert_ss::<SharedEngine>();
    }

    #[test]
    fn blocked_result_carries_rule_text() {
        let s = engine_with(&["||ads.test^"]);
        let r = s.check("https://ads.test/x.js", "https://site.test/", "script");
        assert!(r.blocked && !r.important);
        assert_eq!(r.matched_rule.as_deref(), Some("||ads.test^"));
    }

    #[test]
    fn exception_beats_block() {
        let s = engine_with(&["||ads.test^", "@@||ads.test/ok^"]);
        let r = s.check("https://ads.test/ok", "https://site.test/", "image");
        assert!(!r.blocked);
        assert_eq!(r.exception_rule.as_deref(), Some("@@||ads.test/ok^"));
    }

    #[test]
    fn important_beats_exception() {
        let s = engine_with(&["||ads.test^$important", "@@||ads.test^"]);
        let r = s.check("https://ads.test/x", "https://site.test/", "image");
        assert!(r.blocked && r.important, "{r:?}");
        // Without $important the exception wins.
        let s = engine_with(&["||ads.test^", "@@||ads.test^"]);
        assert!(
            !s.check("https://ads.test/x", "https://site.test/", "image")
                .blocked
        );
    }

    #[test]
    fn redirect_result_is_served_from_builtin_resource() {
        let s = engine_with(&["||ads.test/p.gif$redirect=1x1.gif"]);
        let r = s.check("https://ads.test/p.gif", "https://site.test/", "image");
        assert!(r.blocked);
        let res = r.redirect_resource().expect("redirect resource");
        assert_eq!(res.mime, "image/gif");
        assert!(res.body.starts_with(b"GIF8"));
    }

    #[test]
    fn redirect_rule_applies_only_with_a_block() {
        let s = engine_with(&["||ads.test^$script", "||ads.test^$redirect-rule=noop.js"]);
        let r = s.check("https://ads.test/a.js", "https://site.test/", "script");
        assert_eq!(
            r.redirect_resource().unwrap().mime,
            "application/javascript"
        );
        let r = s.check("https://ads.test/a.png", "https://site.test/", "image");
        assert!(!r.blocked && r.redirect.is_none());
    }

    #[test]
    fn removeparam_rewrites_url() {
        let s = engine_with(&["||site.test^$removeparam=utm_source"]);
        let r = s.check(
            "https://site.test/p?a=1&utm_source=x",
            "https://site.test/",
            "document",
        );
        assert!(!r.blocked);
        assert_eq!(r.rewritten_url.as_deref(), Some("https://site.test/p?a=1"));
    }

    #[test]
    fn csp_directives_returned_for_documents() {
        let s = engine_with(&["||site.test^$csp=script-src 'none'"]);
        let csp = s.csp_for("https://site.test/", "https://site.test/", "document");
        assert_eq!(csp.as_deref(), Some("script-src 'none'"));
        assert!(s
            .csp_for("https://other.test/", "https://other.test/", "document")
            .is_none());
    }

    #[test]
    fn reload_swaps_engine_without_stale_readers() {
        let s = engine_with(&["||a.test^"]);
        assert!(
            s.check("https://a.test/", "https://x.test/", "image")
                .blocked
        );
        s.install(compile_engine(&["||b.test^\n".to_string()]));
        assert!(
            !s.check("https://a.test/", "https://x.test/", "image")
                .blocked
        );
        assert!(
            s.check("https://b.test/", "https://x.test/", "image")
                .blocked
        );
        assert!(!s.serialized().is_empty());
    }

    #[test]
    fn enabled_flag_is_shared() {
        let s = engine_with(&["||a.test^"]);
        s.enabled_flag().store(false, Ordering::Relaxed);
        assert!(!s.is_enabled());
        assert!(
            !s.check("https://a.test/", "https://x.test/", "image")
                .blocked
        );
    }

    #[test]
    fn disabled_allows_everything() {
        let shared = SharedEngine::new();
        shared.install(compile_engine(&["||ad.example.com^\n".to_string()]));
        shared.set_enabled(false);
        let r = shared.check("https://ad.example.com/x", "https://example.com", "image");
        assert!(!r.blocked);
    }
}

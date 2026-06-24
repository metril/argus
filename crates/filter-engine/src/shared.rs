//! Thread-local, lock-free shared adblock engine.
//!
//! `adblock::Engine` is `!Send`/`!Sync` (it holds an `Rc` + `RefCell`), so it cannot be stored in
//! shared state or called across the proxy's worker threads directly. Instead we share the
//! *compiled engine as serialized bytes* (`Send + Sync`) plus a generation counter, and let each
//! worker thread lazily deserialize its **own** `Engine` into a `thread_local!`.
//!
//! The hot path (`check`, `cosmetic_for`, ...) is lock-free: it loads the generation with a single
//! relaxed/acquire atomic and compares it to the thread-local cached generation. On a match (the
//! common case) it uses the cached engine directly — no `ArcSwap` load, no `Arc` clone, no mutex.
//! Only when the generation changed (once per worker per reload) does it `load_full()` the blob and
//! deserialize. This scales linearly across worker threads to hundreds of concurrent clients.

use adblock::lists::{FilterSet, ParseOptions};
use adblock::Engine as AdblockEngine;
use arc_swap::ArcSwap;
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::matcher::{MatchResult, RequestMatcher};
use crate::stats::FilterStats;

thread_local! {
    /// Per-worker-thread engine, tagged with the generation it was built from.
    static LOCAL_ENGINE: RefCell<Option<(u64, AdblockEngine)>> = const { RefCell::new(None) };
}

/// A `Send + Sync` handle to a compiled adblock engine, shared as serialized bytes.
///
/// Clone-free sharing is done via `Arc<SharedEngine>`; the type itself is intentionally not
/// `Clone` (it owns the atomics/blob).
pub struct SharedEngine {
    /// Serialized engine bytes produced by [`compile_engine`]. Empty means "empty engine".
    blob: ArcSwap<Vec<u8>>,
    /// Bumped on every [`SharedEngine::install`]; worker threads rebuild when it changes.
    generation: AtomicU64,
    /// Master on/off switch (independent of the compiled ruleset).
    enabled: AtomicBool,
    /// Shared, thread-safe blocking statistics.
    stats: FilterStats,
}

impl Default for SharedEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedEngine {
    /// Create an empty shared engine (allows everything until rules are installed).
    pub fn new() -> Self {
        Self {
            blob: ArcSwap::new(Arc::new(Vec::new())),
            generation: AtomicU64::new(0),
            enabled: AtomicBool::new(true),
            stats: FilterStats::new(),
        }
    }

    /// Install a freshly compiled, serialized engine and make every worker rebuild on next use.
    pub fn install(&self, serialized: Vec<u8>) {
        let bytes = serialized.len();
        self.blob.store(Arc::new(serialized));
        let gen = self.generation.fetch_add(1, Ordering::Release) + 1;
        info!("Installed compiled filter engine (generation {gen}, {bytes} bytes)");
    }

    /// Enable or disable blocking globally.
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    /// Whether blocking is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Get a cloneable handle to the shared statistics tracker.
    pub fn stats_handle(&self) -> FilterStats {
        self.stats.clone()
    }

    /// Run `f` with this thread's engine, rebuilding it first if the shared generation changed.
    ///
    /// Lock-free fast path: a single atomic load + thread-local borrow when up to date.
    fn with_engine<R>(&self, f: impl FnOnce(&AdblockEngine) -> R) -> R {
        let current_gen = self.generation.load(Ordering::Acquire);
        LOCAL_ENGINE.with(|cell| {
            {
                let stale = match &*cell.borrow() {
                    Some((gen, _)) => *gen != current_gen,
                    None => true,
                };
                if stale {
                    let blob = self.blob.load_full();
                    let mut engine = AdblockEngine::default();
                    if !blob.is_empty() {
                        if let Err(e) = engine.deserialize(&blob) {
                            warn!("Failed to deserialize filter engine (generation {current_gen}): {e:?}; using empty engine");
                        }
                    }
                    *cell.borrow_mut() = Some((current_gen, engine));
                }
            }
            let guard = cell.borrow();
            let (_, engine) = guard.as_ref().expect("engine just ensured present");
            f(engine)
        })
    }

    /// Check whether a network request should be blocked, recording statistics.
    ///
    /// `resource_type` is the adblock resource type (e.g. `script`, `image`, `document`,
    /// `websocket`, `other`). Sync and lock-free; never held across an `.await`.
    pub fn check(&self, url: &str, source_url: &str, resource_type: &str) -> MatchResult {
        if !self.enabled.load(Ordering::Relaxed) {
            self.stats.record_allowed();
            return MatchResult::allowed();
        }

        let result = self.with_engine(|engine| {
            RequestMatcher::check_request(engine, url, source_url, resource_type)
        });

        match result {
            Ok(r) => {
                if r.blocked {
                    let domain = RequestMatcher::extract_domain(url)
                        .unwrap_or_else(|_| "unknown".to_string());
                    self.stats.record_blocked(resource_type, &domain);
                } else {
                    self.stats.record_allowed();
                }
                r
            }
            Err(e) => {
                debug!("Filter check error for {url}: {e}; allowing");
                self.stats.record_allowed();
                MatchResult::allowed()
            }
        }
    }
}

/// Compile a set of raw filter-list contents into a serialized adblock engine.
///
/// Every list's full text is handed to `FilterSet::add_filter_list`, which parses comments,
/// metadata, network rules and cosmetic rules natively. The resulting engine is optimized and
/// returned as serialized bytes suitable for [`SharedEngine::install`]. Pure-CPU and `Send`-safe —
/// call it from `spawn_blocking`.
pub fn compile_engine(list_contents: &[String]) -> Vec<u8> {
    let mut filter_set = FilterSet::new(false);
    for content in list_contents {
        // `add_filter_list` handles comment/metadata stripping and rule classification itself.
        let _ = filter_set.add_filter_list(content, ParseOptions::default());
    }
    let engine = AdblockEngine::from_filter_set(filter_set, true);
    engine.serialize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_engine_allows_everything() {
        let shared = SharedEngine::new();
        let r = shared.check("https://ads.example.com/banner.jpg", "https://example.com", "image");
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
    fn disabled_allows_everything() {
        let shared = SharedEngine::new();
        shared.install(compile_engine(&["||ad.example.com^\n".to_string()]));
        shared.set_enabled(false);
        let r = shared.check("https://ad.example.com/x", "https://example.com", "image");
        assert!(!r.blocked);
    }
}

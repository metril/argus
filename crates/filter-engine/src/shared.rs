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
use adblock::resources::Resource;
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
    /// Scriptlet/redirect resource library (uBO-compatible). Empty until loaded; applied to each
    /// worker's engine after deserialize so `##+js(...)` scriptlets resolve.
    resources: ArcSwap<Vec<Resource>>,
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
            resources: ArcSwap::new(Arc::new(Vec::new())),
            stats: FilterStats::new(),
        }
    }

    /// Load the scriptlet/redirect resource library from a JSON array of uBO-compatible resources
    /// (e.g. Brave's `resources.json`). Bumps the generation so every worker re-applies them.
    /// Returns the number of resources loaded.
    pub fn set_resources_from_json(&self, json: &str) -> Result<usize, serde_json::Error> {
        let resources: Vec<Resource> = serde_json::from_str(json)?;
        let n = resources.len();
        self.resources.store(Arc::new(resources));
        self.generation.fetch_add(1, Ordering::Release);
        info!("Loaded {n} scriptlet/redirect resources");
        Ok(n)
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
                    // Re-apply the scriptlet resource library so `##+js(...)` rules resolve. Not
                    // part of the serialized blob, so it must be set on each worker's engine.
                    let resources = self.resources.load();
                    if !resources.is_empty() {
                        engine.use_resources(resources.iter().cloned());
                    }
                    *cell.borrow_mut() = Some((current_gen, engine));
                }
            }
            let guard = cell.borrow();
            let (_, engine) = guard.as_ref().expect("engine just ensured present");
            f(engine)
        })
    }

    /// Cosmetic resources (element-hiding CSS + scriptlet JS) for a page URL.
    ///
    /// Lock-free thread-local, same engine as [`Self::check`]. `generichide` is true when the page
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

    #[test]
    fn disabled_allows_everything() {
        let shared = SharedEngine::new();
        shared.install(compile_engine(&["||ad.example.com^\n".to_string()]));
        shared.set_enabled(false);
        let r = shared.check("https://ad.example.com/x", "https://example.com", "image");
        assert!(!r.blocked);
    }
}

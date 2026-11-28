//! One base engine per distinct enabled-list set (for per-device profiles).
//!
//! [`ListService::engine_for`] returns an engine compiled from exactly the given lists (no custom
//! rules), shared by every caller that asks for the same set in any order. Engines are held
//! weakly: when the last user drops one it is freed and rebuilt on the next request.
//!
//! Statistics, the block log and the master enable switch are the default engine's, so they stay
//! global. A profile's custom rules are a separate overlay
//! ([`filter_engine::overlay_from_rules`]).
//!
//! Updates: after every global build cycle the service re-checks each live set; one whose member
//! lists changed (content, format, trust flags) is rebuilt and installed **into the same
//! `Arc<SharedEngine>`** (callers keep their handle; `generation_id()` increases). Every pass that
//! rebuilt something bumps the counter of [`ListService::subscribe_sets`]. Content is read from
//! the store; a list with no cached content is fetched once. Lists that are not globally enabled
//! are not refreshed by the update ticker (only by the global cycle's enabled set).

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};

use filter_engine::{build_set_checked, try_build_engine, ListInput, SharedEngine};
use parking_lot::Mutex;
use tokio::sync::watch;
use tracing::warn;

use crate::service::{build_ext_index, mark_trusted, BuildInput, ListService};
use crate::{Error, Result};

/// A set of list ids, order-insensitive (sorted, deduplicated).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SetKey(Vec<String>);

impl SetKey {
    pub fn new(lists: &[String]) -> Self {
        let mut v = lists.to_vec();
        v.sort();
        v.dedup();
        Self(v)
    }

    pub fn ids(&self) -> &[String] {
        &self.0
    }
}

struct Entry {
    engine: Weak<SharedEngine>,
    /// What the engine was built from (see [`ListService::current_sig`]).
    sig: Vec<String>,
}

pub(crate) struct SetRegistry {
    engines: Mutex<HashMap<SetKey, Entry>>,
    /// Serializes builds of one set (single flight).
    locks: Mutex<HashMap<SetKey, Arc<tokio::sync::Mutex<()>>>>,
    builds: std::sync::atomic::AtomicU64,
    generation: watch::Sender<u64>,
}

impl Default for SetRegistry {
    fn default() -> Self {
        Self {
            engines: Mutex::default(),
            locks: Mutex::default(),
            builds: Default::default(),
            generation: watch::channel(0).0,
        }
    }
}

impl SetRegistry {
    fn live(&self, key: &SetKey) -> Option<Arc<SharedEngine>> {
        self.engines.lock().get(key)?.engine.upgrade()
    }

    fn lock_for(&self, key: &SetKey) -> Arc<tokio::sync::Mutex<()>> {
        self.locks.lock().entry(key.clone()).or_default().clone()
    }

    fn insert(&self, key: SetKey, engine: &Arc<SharedEngine>, sig: Vec<String>) {
        let mut m = self.engines.lock();
        m.retain(|_, e| e.engine.strong_count() > 0);
        m.insert(
            key,
            Entry {
                engine: Arc::downgrade(engine),
                sig,
            },
        );
        // Forget build locks of sets that are gone (a lock in use stays: its Arc is held).
        self.locks
            .lock()
            .retain(|k, l| m.contains_key(k) || Arc::strong_count(l) > 1);
    }
}

impl ListService {
    /// The base engine for exactly the lists in `lists` (order-insensitive; unknown ids are
    /// skipped), with no custom rules. Concurrent callers of the same set share one build.
    /// Built off the async threads. See the module docs for update behaviour.
    pub async fn engine_for(&self, lists: &[String]) -> Result<Arc<SharedEngine>> {
        let key = SetKey::new(lists);
        if let Some(e) = self.sets.live(&key) {
            return Ok(e);
        }
        let lock = self.sets.lock_for(&key);
        let _held = lock.lock().await;
        if let Some(e) = self.sets.live(&key) {
            return Ok(e);
        }
        let engine = Arc::new(SharedEngine::with_shared(
            self.engine.stats_handle(),
            self.engine.block_log_handle(),
            self.engine.enabled_flag(),
        ));
        let sig = self.build_set_into(&key, &engine).await?;
        self.sets.insert(key, &engine, sig);
        Ok(engine)
    }

    /// A counter that increases after every refresh pass that rebuilt at least one live set
    /// engine (their `Arc`s stay valid; only the contents were swapped).
    pub fn subscribe_sets(&self) -> watch::Receiver<u64> {
        self.sets.generation.subscribe()
    }

    /// How many set engines were compiled so far (initial builds and rebuilds).
    pub fn set_build_count(&self) -> u64 {
        self.sets.builds.load(Ordering::Acquire)
    }

    /// Whether the live engine of `key` was built from the stored state of its lists as it is now.
    pub(crate) fn set_is_current(&self, key: &SetKey) -> bool {
        let built = self.sets.engines.lock().get(key).map(|e| e.sig.clone());
        built.is_some_and(|s| s == self.current_sig(key))
    }

    /// Signature of the stored state of each member list.
    fn current_sig(&self, key: &SetKey) -> Vec<String> {
        key.ids()
            .iter()
            .map(|id| match self.store().get(id) {
                Ok(Some(l)) => {
                    let sha = self
                        .store()
                        .get_status(id)
                        .ok()
                        .and_then(|s| s.content_sha)
                        .unwrap_or_default();
                    format!("{id}|{:?}|{}|{}|{sha}", l.format, l.allowlist, l.trusted)
                }
                _ => format!("{id}|missing"),
            })
            .collect()
    }

    /// Compile the set and install it into `target`; returns the signature it was built from.
    async fn build_set_into(&self, key: &SetKey, target: &SharedEngine) -> Result<Vec<String>> {
        let mut inputs: Vec<BuildInput> = Vec::new();
        for id in key.ids() {
            let Some(list) = self.store().get(id)? else {
                warn!("profile list {id} does not exist; skipped");
                continue;
            };
            if let Some(content) = self.store().get_content(id).ok().flatten() {
                let includes = self.resolve_includes(&list, &content, false).await;
                inputs.push(self.make_input(&list, content, includes));
            } else if let Some(i) = self.fetch_one(list, false).await {
                inputs.push(i);
            }
        }
        let sig = self.current_sig(key);
        let trusted: std::collections::HashSet<String> = inputs
            .iter()
            .filter(|i| i.trusted)
            .map(|i| i.id.clone())
            .collect();
        let resources = target.resources();
        let pool = self.build_pool();
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
            let known = filter_engine::known_redirect_names(&resources);
            let mut built = pool.install(|| build_set_checked(&list_inputs, Some(&known)));
            drop(list_inputs);
            mark_trusted(&mut built.ext, &trusted);
            let engine = try_build_engine(&built.blob, &resources).map_err(Error::Other)?;
            let index = build_ext_index(&built.ext, &trusted);
            Ok::<_, Error>((built, engine, index))
        })
        .await
        .map_err(|e| Error::Other(format!("compile task failed: {e}")))??;
        target.install_set_with(
            Arc::new(built.blob),
            engine,
            Some(index),
            Arc::new(built.ext),
            Arc::new(built.ip),
            Arc::new(built.domains),
            Arc::new(built.origins),
        );
        self.sets.builds.fetch_add(1, Ordering::AcqRel);
        Ok(sig)
    }

    /// Rebuild, in place, every live set engine whose member lists changed.
    pub(crate) async fn refresh_sets(&self) {
        let live: Vec<(SetKey, Arc<SharedEngine>, Vec<String>)> = {
            let mut m = self.sets.engines.lock();
            m.retain(|_, e| e.engine.strong_count() > 0);
            m.iter()
                .filter_map(|(k, e)| Some((k.clone(), e.engine.upgrade()?, e.sig.clone())))
                .collect()
        };
        let mut rebuilt = false;
        for (key, engine, old) in live {
            if self.current_sig(&key) == old {
                continue;
            }
            let lock = self.sets.lock_for(&key);
            let _held = lock.lock().await;
            match self.build_set_into(&key, &engine).await {
                Ok(sig) => {
                    if let Some(e) = self.sets.engines.lock().get_mut(&key) {
                        e.sig = sig;
                    }
                    rebuilt = true;
                }
                Err(e) => warn!("rebuilding a list-set engine failed; keeping the old one: {e}"),
            }
        }
        if rebuilt {
            self.sets.generation.send_modify(|g| *g += 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ListServiceConfig, ListStore};
    use filter_engine::FilterList;

    fn svc(lists: &[(&str, &str)]) -> (tempfile::TempDir, Arc<ListService>) {
        let dir = tempfile::tempdir().unwrap();
        let store = ListStore::open(dir.path()).unwrap();
        for (id, rules) in lists {
            let mut l = FilterList::new(
                id.to_string(),
                id.to_string(),
                format!("https://127.0.0.1:1/{id}.txt"),
            );
            l.enabled = true;
            store.upsert(&l).unwrap();
            store.put_content(id, rules).unwrap();
        }
        let cfg = ListServiceConfig {
            data_dir: dir.path().to_path_buf(),
            ..Default::default()
        };
        let s = ListService::new(
            cfg,
            store,
            Arc::new(SharedEngine::new()),
            reqwest::Client::new(),
        );
        (dir, s)
    }

    fn ids(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn blocked(e: &SharedEngine, host: &str) -> bool {
        e.check(
            &format!("https://{host}/x.js"),
            "https://page.test/",
            "script",
        )
        .blocked
    }

    #[tokio::test]
    async fn concurrent_same_set_builds_once_and_different_sets_differ() {
        let (_d, s) = svc(&[("a", "||a.test^\n"), ("b", "||b.test^\n")]);
        let (k1, k2) = (ids(&["a", "b"]), ids(&["b", "a", "a"]));
        let (x, y) = tokio::join!(s.engine_for(&k1), s.engine_for(&k2));
        let (x, y) = (x.unwrap(), y.unwrap());
        assert!(Arc::ptr_eq(&x, &y));
        assert_eq!(s.set_build_count(), 1);
        assert!(blocked(&x, "a.test") && blocked(&x, "b.test"));

        let only_a = s.engine_for(&ids(&["a"])).await.unwrap();
        assert!(!Arc::ptr_eq(&x, &only_a));
        assert!(blocked(&only_a, "a.test") && !blocked(&only_a, "b.test"));
        let none = s.engine_for(&[]).await.unwrap();
        assert!(!blocked(&none, "a.test"));
        // The default engine is untouched.
        assert!(!blocked(s.engine(), "a.test"));
    }

    #[tokio::test]
    async fn dropped_engines_are_freed_and_rebuilt() {
        let (_d, s) = svc(&[("a", "||a.test^\n")]);
        let e = s.engine_for(&ids(&["a"])).await.unwrap();
        let weak = Arc::downgrade(&e);
        drop(e);
        assert!(weak.upgrade().is_none(), "service must hold engines weakly");
        let again = s.engine_for(&ids(&["a"])).await.unwrap();
        assert_eq!(s.set_build_count(), 2);
        assert!(blocked(&again, "a.test"));
    }

    #[tokio::test]
    async fn stats_and_switch_are_global() {
        let (_d, s) = svc(&[("a", "||a.test^\n"), ("b", "||b.test^\n")]);
        let ea = s.engine_for(&ids(&["a"])).await.unwrap();
        let eb = s.engine_for(&ids(&["b"])).await.unwrap();
        assert!(blocked(&ea, "a.test") && blocked(&eb, "b.test"));
        assert_eq!(s.engine().stats_handle().snapshot().blocked_requests, 2);
        s.engine().set_enabled(false);
        assert!(!blocked(&ea, "a.test"));
    }

    #[tokio::test]
    async fn member_list_update_rebuilds_in_place_and_notifies() {
        let (_d, s) = svc(&[("a", "||a.test^\n")]);
        let e = s.engine_for(&ids(&["a"])).await.unwrap();
        let rx = s.subscribe_sets();
        let gen = e.generation_id();
        assert!(!blocked(&e, "new.test"));
        s.store()
            .put_content("a", "||a.test^\n||new.test^\n")
            .unwrap();
        s.reload_now().await;
        assert!(blocked(&e, "new.test"), "same Arc sees the new rules");
        assert!(e.generation_id() > gen);
        assert!(rx.has_changed().unwrap());
        assert_eq!(s.set_build_count(), 2);
        // No change -> no rebuild.
        s.reload_now().await;
        assert_eq!(s.set_build_count(), 2);
    }
}

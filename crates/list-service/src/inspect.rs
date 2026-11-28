//! Per-line inspection of lists for the API: the extended-rule judge, the cache of classified
//! lists and the service entry points (see [`filter_engine::inspect`]).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use filter_engine::inspect::{classify_list, Classified, ExtState, ExtVerdict, Live};
use filter_engine::{ExtRule, ListFormat, ListInput};
use parking_lot::Mutex;

use crate::persist;
use crate::service::ListService;
use crate::store::CUSTOM_REPORT_ID;
use crate::Result;

/// Upper bound of the classified-list cache (the newest entry is always kept, even when larger).
pub const CACHE_BYTES: usize = 64 * 1024 * 1024;
/// A cached classification unused for this long is dropped.
pub const CACHE_IDLE: Duration = Duration::from_secs(15 * 60);

/// The verdict the extended-rule index gives a rule, in the API's vocabulary: its state name
/// (see [`filter_engine::inspect::EXT_STATES`]). A rule switched off by a `$badfilter` rule or a
/// `$badfilter` rule itself count as enforced: the index has handled them as the list author
/// meant. Any other state is carried under its own name.
pub(crate) fn verdict_of(state: Option<&ext_rules::RuleState>) -> ExtVerdict {
    let Some(s) = state else {
        return ExtVerdict::enforced();
    };
    let reason = |why: Option<&str>| why.map(str::to_string);
    let (state, why) = match s.as_str() {
        "active" => (ExtState::ENFORCED, None),
        "badfiltered" => (
            ExtState::ENFORCED,
            Some("switched off by a $badfilter rule"),
        ),
        "badfilter" => (ExtState::ENFORCED, Some("a $badfilter rule")),
        "dropped_untrusted" => (ExtState::NEEDS_TRUST, Some("the list is not trusted")),
        other => (ExtState::named(other), s.reason()),
    };
    ExtVerdict {
        state,
        reason: reason(why),
    }
}

/// Judge `rules` of one list with a fresh extended-rule index (the rules carry the list's id and
/// trust, see [`filter_engine::inspect::classify_list`]).
pub fn judge_ext(rules: &[ExtRule]) -> Vec<ExtVerdict> {
    let trusted: HashSet<String> = rules
        .iter()
        .filter(|r| r.trusted)
        .map(|r| r.list.clone())
        .collect();
    let index = ext_rules::ExtIndex::build_with(
        rules,
        &ext_rules::BuildOptions {
            trusted_lists: trusted,
            max_issues: 0,
        },
    );
    (0..rules.len())
        .map(|i| verdict_of(index.state_of(i)))
        .collect()
}

/// Classify `text` as a list of its own that is not part of any build.
pub fn classify_text(text: &str, format: ListFormat, allowlist: bool, trusted: bool) -> Classified {
    classify_list(
        &ListInput {
            id: "text".into(),
            content: text.to_string(),
            format,
            allowlist,
            trusted,
            includes: HashMap::new(),
        },
        None,
        &judge_ext,
    )
}

/// What a classification depends on: the list's text and settings, and, for a list inside the
/// live build, that build (`generation`; 0 for a list judged standalone, which no build changes).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub id: String,
    pub digest: String,
    pub generation: u64,
    /// 0 for the global engine, else the profile's list set.
    pub scope: u64,
    pub format: ListFormat,
    pub allowlist: bool,
    pub trusted: bool,
}

struct Slot {
    value: Arc<Classified>,
    bytes: usize,
    used: Instant,
    tick: u64,
}

/// Classified lists, least recently used out first once over the byte cap, idle ones dropped.
pub struct ClassCache {
    cap: usize,
    idle: Duration,
    inner: Mutex<CacheInner>,
}

#[derive(Default)]
struct CacheInner {
    map: HashMap<CacheKey, Slot>,
    bytes: usize,
    tick: u64,
}

impl ClassCache {
    pub fn new(cap: usize, idle: Duration) -> Self {
        Self {
            cap,
            idle,
            inner: Mutex::new(CacheInner::default()),
        }
    }

    pub fn get(&self, key: &CacheKey) -> Option<Arc<Classified>> {
        let mut g = self.inner.lock();
        g.expire(self.idle);
        g.tick += 1;
        let tick = g.tick;
        let s = g.map.get_mut(key)?;
        s.used = Instant::now();
        s.tick = tick;
        Some(s.value.clone())
    }

    pub fn insert(&self, key: CacheKey, value: Arc<Classified>) {
        let mut g = self.inner.lock();
        g.expire(self.idle);
        g.tick += 1;
        let (bytes, tick) = (value.approx_bytes(), g.tick);
        // Another build of the same list (older text or generation) is of no use any more.
        let stale: Vec<CacheKey> = g
            .map
            .keys()
            .filter(|k| k.id == key.id && k.scope == key.scope && **k != key)
            .cloned()
            .collect();
        for k in stale {
            g.remove(&k);
        }
        g.remove(&key);
        g.bytes += bytes;
        g.map.insert(
            key,
            Slot {
                value,
                bytes,
                used: Instant::now(),
                tick,
            },
        );
        while g.bytes > self.cap && g.map.len() > 1 {
            let Some(oldest) = g
                .map
                .iter()
                .min_by_key(|(_, s)| s.tick)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            g.remove(&oldest);
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn bytes(&self) -> usize {
        self.inner.lock().bytes
    }
}

impl CacheInner {
    fn remove(&mut self, k: &CacheKey) {
        if let Some(s) = self.map.remove(k) {
            self.bytes = self.bytes.saturating_sub(s.bytes);
        }
    }

    fn expire(&mut self, idle: Duration) {
        let now = Instant::now();
        let dead: Vec<CacheKey> = self
            .map
            .iter()
            .filter(|(_, s)| now.duration_since(s.used) > idle)
            .map(|(k, _)| k.clone())
            .collect();
        for k in dead {
            self.remove(&k);
        }
    }
}

/// A list as the last successful build used it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Installed {
    pub digest: String,
    pub format: ListFormat,
    pub allowlist: bool,
    pub trusted: bool,
}

/// Where a list is judged: the global engine, or the engine of a profile's list set.
#[derive(Debug, Clone, Default)]
pub enum Scope {
    #[default]
    Global,
    /// The profile's enabled list ids.
    Profile(Vec<String>),
}

impl ListService {
    /// The classified source lines of list `id` (`CUSTOM_REPORT_ID` for the custom rules), with
    /// the generation they were judged under (0 when judged standalone). Served from the cache
    /// when the text, settings and live build are unchanged; the cache is checked before any
    /// lock and without reading the list text (the stored content digest keys it). A list the
    /// scope's engine holds as it is now is judged inside that build; any other (disabled, or
    /// changed since) is judged standalone. `None` when the list has no text.
    pub async fn classified(
        self: &Arc<Self>,
        id: &str,
        scope: &Scope,
    ) -> Result<Option<(Arc<Classified>, u64)>> {
        let (engine, scope_id, set_key) = match scope {
            Scope::Global => (self.engine.clone(), 0u64, None),
            Scope::Profile(lists) => {
                let engine = self.engine_for(lists).await?;
                let key = crate::sets::SetKey::new(lists);
                (engine, scope_hash(&key), Some(key))
            }
        };
        let Some((format, allowlist, trusted, digest)) = self.inspect_meta(id)? else {
            return Ok(None);
        };
        for _ in 0..3 {
            let generation = engine.generation();
            let installed_ok = match &set_key {
                None => self.installed.lock().get(id).is_some_and(|i| {
                    i.digest == digest
                        && i.format == format
                        && i.allowlist == allowlist
                        && i.trusted == trusted
                }),
                Some(k) => k.ids().iter().any(|l| l == id) && self.set_is_current(k),
            };
            let in_build = installed_ok && generation.origins.ids().iter().any(|l| l == id);
            let key = CacheKey {
                id: id.to_string(),
                digest: digest.clone(),
                generation: if in_build { generation.id } else { 0 },
                scope: scope_id,
                format,
                allowlist,
                trusted,
            };
            if let Some(hit) = self.class_cache.get(&key) {
                return Ok(Some((hit, key.generation)));
            }
            // One classification at a time: concurrent pages of the same list wait for the
            // first, then find it cached.
            let _one = self.class_lock.lock().await;
            if let Some(hit) = self.class_cache.get(&key) {
                return Ok(Some((hit, key.generation)));
            }
            // A classification and a build each peak at hundreds of MB on the largest lists:
            // never at once. Wait for the build, then judge against what it installed.
            if self.is_building() {
                self.wait_idle().await;
                continue;
            }
            let Some(input) = self.inspect_input(id).await? else {
                return Ok(None);
            };
            let pool = self.build_pool();
            let gen2 = generation.clone();
            let done = tokio::task::spawn_blocking(move || {
                let live = in_build.then(|| Live {
                    origins: &gen2.origins,
                    domains: &gen2.domains,
                });
                pool.install(|| classify_list(&input, live, &judge_ext))
            })
            .await
            .map_err(|e| crate::Error::Other(format!("classify task failed: {e}")))?;
            if in_build && engine.generation_id() != generation.id {
                continue; // a build landed meanwhile; judge again against it
            }
            let mut done = done;
            done.digest = digest.clone();
            let done = Arc::new(done);
            self.class_cache.insert(key.clone(), done.clone());
            return Ok(Some((done, key.generation)));
        }
        Err(crate::Error::Other(
            "the filter engine kept changing; try again".into(),
        ))
    }

    /// Classify rules text that belongs to no list (a profile's own rules), standalone and
    /// trusted, cached by its digest.
    pub async fn classified_rules(
        self: &Arc<Self>,
        rules: String,
    ) -> Result<(Arc<Classified>, u64)> {
        let digest = persist::content_digest(&rules, std::iter::empty());
        let key = CacheKey {
            id: format!("\0rules:{}", &digest[..16]),
            digest: digest.clone(),
            generation: 0,
            scope: 1,
            format: ListFormat::Abp,
            allowlist: false,
            trusted: true,
        };
        if let Some(hit) = self.class_cache.get(&key) {
            return Ok((hit, 0));
        }
        let _one = self.class_lock.lock().await;
        self.wait_idle().await;
        let input = ListInput {
            id: key.id.clone(),
            content: rules,
            format: ListFormat::Abp,
            allowlist: false,
            trusted: true,
            includes: HashMap::new(),
        };
        let pool = self.build_pool();
        let mut done = tokio::task::spawn_blocking(move || {
            pool.install(|| classify_list(&input, None, &judge_ext))
        })
        .await
        .map_err(|e| crate::Error::Other(format!("classify task failed: {e}")))?;
        done.digest = digest;
        let done = Arc::new(done);
        self.class_cache.insert(key, done.clone());
        Ok((done, 0))
    }

    /// Settings and content digest of list `id` without reading its text: the digest the build
    /// recorded (list text and includes), hashed here only when none is stored.
    fn inspect_meta(&self, id: &str) -> Result<Option<(ListFormat, bool, bool, String)>> {
        if id == CUSTOM_REPORT_ID {
            let Some(rules) = self.custom_rules_text() else {
                return Ok(None);
            };
            let digest = persist::content_digest(&rules, std::iter::empty());
            return Ok(Some((ListFormat::Abp, false, true, digest)));
        }
        let Some(list) = self.store().get(id)? else {
            return Ok(None);
        };
        let stored = self.store().get_status(id)?.content_sha;
        let digest = match stored {
            Some(d) => d,
            None => {
                let Some(content) = self.store().get_content(id)? else {
                    return Ok(None);
                };
                persist::content_digest(&content, std::iter::empty())
            }
        };
        Ok(Some((list.format, list.allowlist, list.trusted, digest)))
    }

    /// The text and settings of list `id` as a build would take them.
    async fn inspect_input(&self, id: &str) -> Result<Option<ListInput>> {
        if id == CUSTOM_REPORT_ID {
            return Ok(self.custom_rules_text().map(|rules| ListInput {
                id: id.to_string(),
                content: rules,
                format: ListFormat::Abp,
                allowlist: false,
                trusted: true,
                includes: HashMap::new(),
            }));
        }
        let Some(list) = self.store().get(id)? else {
            return Ok(None);
        };
        let Some(content) = self.store().get_content(id)? else {
            return Ok(None);
        };
        let includes = self.resolve_includes(&list, &content, false).await;
        Ok(Some(ListInput {
            id: id.to_string(),
            content,
            format: list.format,
            allowlist: list.allowlist,
            trusted: list.trusted,
            includes,
        }))
    }
}

fn scope_hash(k: &crate::sets::SetKey) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    k.ids().hash(&mut h);
    h.finish() | 2
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::ListServiceConfig;
    use crate::store::ListStore;
    use filter_engine::inspect::{Filter, Kind};
    use filter_engine::{FilterList, SharedEngine};

    fn service(lists: &[(&str, &str, bool, bool)]) -> (Arc<ListService>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = ListStore::open(dir.path()).unwrap();
        for (id, text, enabled, trusted) in lists {
            let mut l = FilterList::new(
                id.to_string(),
                id.to_string(),
                format!("https://127.0.0.1:1/{id}.txt"),
            );
            l.enabled = *enabled;
            l.trusted = *trusted;
            store.upsert(&l).unwrap();
            store.put_content(id, text).unwrap();
        }
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
        (svc, dir)
    }

    async fn cl(svc: &Arc<ListService>, id: &str) -> Arc<Classified> {
        svc.classified(id, &Scope::Global)
            .await
            .unwrap()
            .expect("classified")
            .0
    }

    const MIXED: &str = "! Title: mixed\n||ads.test^\n||ads.test^\n||sub.ads.test^\n\
        example.com##.sponsor\n||x.test^$replace=/a/b/\n\
        example.com#%#//scriptlet('abort-on-property-read', 'x')\n\
        ||u.test^$popunder\n||bad$$\n/ads/*$bogus\n##+js(trusted-set-cookie, a, b)\n";

    #[tokio::test]
    async fn counts_equal_the_stored_report_including_extended_states() {
        let (svc, _d) = service(&[("first", MIXED, true, false), ("second", MIXED, true, true)]);
        svc.store()
            .set_custom_rules("||custom.test^\n||ads.test^\n##.c\n")
            .unwrap();
        svc.reload_now().await;
        for id in ["first", "second", CUSTOM_REPORT_ID] {
            let rep = svc.report(id).expect("report");
            let c = cl(&svc, id).await;
            assert!(c.in_build, "{id}");
            let n = &c.counts;
            assert_eq!(
                (
                    n.network,
                    n.cosmetic,
                    n.ext_enforced,
                    n.ext_unsupported,
                    n.ext_invalid,
                    n.ext_needs_trust,
                    n.duplicate,
                    n.covered,
                    n.unsupported,
                    n.invalid_conversion,
                    n.invalid_compile,
                ),
                (
                    rep.network,
                    rep.cosmetic,
                    rep.ext_enforced,
                    rep.ext_unsupported,
                    rep.ext_invalid,
                    rep.ext_needs_trust,
                    rep.duplicates,
                    rep.compressed,
                    rep.skipped,
                    rep.error_count,
                    rep.rejected,
                ),
                "{id}"
            );
            assert_eq!(n.ext(), rep.ext, "{id}");
        }
        let first = svc.report("first").unwrap();
        let second = svc.report("second").unwrap();
        assert!(first.ext_needs_trust >= 1, "{first:?}");
        assert_eq!(
            second.ext_needs_trust, 0,
            "the trusted list is not asked for trust"
        );
        // The second list repeats the first: everything it holds is already provided.
        assert!(second.duplicates > 0);
        // Problems are listed with their source line, rule text and stage.
        let issue = first
            .errors
            .iter()
            .find(|e| e.rule.contains("bad$$"))
            .expect("a conversion error for ||bad$$");
        assert_eq!(issue.line, 9);
        // The engine's compiler rejects it: traced back to its source line, not its place in the
        // converted text.
        assert_eq!(issue.stage, filter_engine::IssueStage::Compile);
        let rej = first.errors.iter().find(|e| e.rule.contains("bogus"));
        if let Some(r) = rej {
            assert_eq!(r.line, 10);
            assert_eq!(r.stage, filter_engine::IssueStage::Compile);
        }
    }

    #[tokio::test]
    async fn classification_is_cached_and_survives_unrelated_builds() {
        let (svc, _d) = service(&[
            ("on", "||on.test^\n##.x\n", true, false),
            ("off", "||off.test^\n||off.test^\n", false, false),
        ]);
        svc.reload_now().await;
        let on1 = cl(&svc, "on").await;
        let off1 = cl(&svc, "off").await;
        assert!(on1.in_build);
        assert!(!off1.in_build, "a disabled list is judged on its own");
        assert_eq!(off1.counts.duplicate, 1);
        assert!(Arc::ptr_eq(&on1, &cl(&svc, "on").await));
        assert_eq!(svc.class_cache.len(), 2);

        // A build that changes another list moves the engine on: the enabled list is judged
        // again, the standalone one (same text, no build involved) is kept.
        svc.store().set_custom_rules("||custom.test^\n").unwrap();
        svc.reload_now().await;
        let on2 = cl(&svc, "on").await;
        assert!(!Arc::ptr_eq(&on1, &on2));
        assert!(on2.in_build);
        assert!(Arc::ptr_eq(&off1, &cl(&svc, "off").await));

        // A rebuild that changes nothing keeps everything.
        svc.reload_now().await;
        assert!(Arc::ptr_eq(&on2, &cl(&svc, "on").await));
    }

    #[tokio::test]
    async fn a_cache_hit_neither_reads_the_text_nor_waits_for_a_classification() {
        let (svc, _d) = service(&[("a", "||a.test^\n", true, false)]);
        svc.reload_now().await;
        let (c, gen) = svc.classified("a", &Scope::Global).await.unwrap().unwrap();
        assert!(gen > 0 && c.in_build);
        // A running classification holds the lock; a hit does not wait for it.
        let _held = svc.class_lock.lock().await;
        let hit = tokio::time::timeout(Duration::from_secs(2), svc.classified("a", &Scope::Global))
            .await
            .expect("a cache hit must not wait for class_lock")
            .unwrap()
            .unwrap();
        assert!(Arc::ptr_eq(&c, &hit.0));
        assert_eq!(hit.1, gen);
    }

    #[tokio::test]
    async fn text_changed_since_the_build_is_judged_standalone() {
        let (svc, _d) = service(&[("a", "||a.test^\n", true, false)]);
        svc.reload_now().await;
        assert!(cl(&svc, "a").await.in_build);
        // A fetch stores the text and its digest; the cache is keyed on that digest.
        let list = svc.store().get("a").unwrap().unwrap();
        svc.store()
            .put_content("a", "||a.test^\n||b.test^\n")
            .unwrap();
        svc.make_input(&list, "||a.test^\n||b.test^\n".into(), HashMap::new());
        let c = cl(&svc, "a").await;
        assert!(!c.in_build);
        assert_eq!(c.counts.network, 2);
        assert!(svc
            .classified("missing", &Scope::Global)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn a_fetch_re_keys_the_cache_before_any_rebuild() {
        use axum::{routing::get, Router};
        let body = Arc::new(parking_lot::Mutex::new("||old.test^\n".to_string()));
        let gate = Arc::new(tokio::sync::Notify::new());
        let app = Router::new()
            .route(
                "/a.txt",
                get({
                    let b = body.clone();
                    move || async move { b.lock().clone() }
                }),
            )
            .route(
                "/inc.txt",
                get({
                    let g = gate.clone();
                    move || async move {
                        g.notified().await;
                        "||inc.test^\n"
                    }
                }),
            );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });

        let (svc, _d) = service(&[("a", "||old.test^\n", true, false)]);
        let mut list = svc.store().get("a").unwrap().unwrap();
        list.url = format!("http://{addr}/a.txt");
        svc.store().upsert(&list).unwrap();
        svc.reload_now().await;
        assert!(cl(&svc, "a").await.in_build);

        // The new text pulls an include that is held back, so the fetch is between storing the
        // text and building its input while the viewer is asked.
        *body.lock() = "||new.test^\n||new2.test^\n!#include inc.txt\n".into();
        let fetch = tokio::spawn({
            let svc = svc.clone();
            async move { svc.fetch_one(list, true).await }
        });
        tokio::time::timeout(Duration::from_secs(10), async {
            while svc.store().get_content("a").unwrap().as_deref() == Some("||old.test^\n") {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("fetch stored the new text");
        let c = cl(&svc, "a").await;
        assert!(!c.in_build, "new text is not what the build has");
        assert_eq!(c.counts.network, 2, "the new text is served");
        gate.notify_one();
        fetch.await.unwrap();
    }

    #[tokio::test]
    async fn an_identical_refetch_keeps_the_digest_and_does_not_rebuild_a_set() {
        use axum::{routing::get, Router};
        let app = Router::new().route("/a.txt", get(|| async { "||a.test^\n" }));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        let (svc, _d) = service(&[("a", "||a.test^\n", true, false)]);
        let mut list = svc.store().get("a").unwrap().unwrap();
        list.url = format!("http://{addr}/a.txt");
        svc.store().upsert(&list).unwrap();
        svc.reload_now().await;
        let key = crate::sets::SetKey::new(&["a".to_string()]);
        svc.engine_for(&["a".to_string()]).await.unwrap();
        let (digest, builds) = (
            svc.store().get_status("a").unwrap().content_sha,
            svc.set_build_count(),
        );
        assert!(digest.is_some());
        svc.fetch_one(list, true).await.expect("fetched");
        assert_eq!(svc.store().get_status("a").unwrap().content_sha, digest);
        assert!(svc.set_is_current(&key));
        svc.reload_now().await;
        assert_eq!(svc.set_build_count(), builds, "no rebuild for equal text");
    }

    #[tokio::test]
    async fn a_classification_waits_for_a_running_build() {
        let (svc, _d) = service(&[("off", "||a.test^\n", false, false)]);
        svc.busy.send_replace(true);
        let task = tokio::spawn({
            let svc = svc.clone();
            async move { svc.classified("off", &Scope::Global).await }
        });
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(!task.is_finished(), "must not classify while a build runs");
        svc.busy.send_replace(false);
        let (c, _) = tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("classified after the build")
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(c.counts.network, 1);
    }

    #[tokio::test]
    async fn profile_scope_judges_against_the_profiles_engine() {
        let (svc, _d) = service(&[
            ("a", "||dup.test^\n||a.test^\n", true, false),
            ("b", "||dup.test^\n||b.test^\n", true, false),
        ]);
        svc.reload_now().await;
        // Globally `b` comes second: its copy is a duplicate. In a profile that has only `b`
        // it is the first and only holder.
        assert_eq!(cl(&svc, "b").await.counts.duplicate, 1);
        let only_b = Scope::Profile(vec!["b".into()]);
        let (c, gen) = svc.classified("b", &only_b).await.unwrap().unwrap();
        assert!(c.in_build && gen > 0);
        assert_eq!((c.counts.duplicate, c.counts.network), (0, 2));
        // A list the profile does not have is judged on its own.
        let (c, gen) = svc.classified("a", &only_b).await.unwrap().unwrap();
        assert!(!c.in_build);
        assert_eq!(gen, 0);
        // Both scopes are cached apart.
        assert_eq!(cl(&svc, "b").await.counts.duplicate, 1);
    }

    #[tokio::test]
    async fn custom_rules_are_trusted_and_listed() {
        let (svc, _d) = service(&[("a", "||a.test^\n", true, false)]);
        svc.store()
            .set_custom_rules("||x.test^$replace=/a/b/\n||a.test^\n")
            .unwrap();
        svc.reload_now().await;
        let c = cl(&svc, CUSTOM_REPORT_ID).await;
        assert!(c.in_build);
        assert_eq!(
            c.counts.ext_needs_trust, 0,
            "custom rules are built trusted"
        );
        assert_eq!(c.counts.duplicate, 1, "||a.test^ is also in list a");
        let d = c
            .records
            .iter()
            .find(|r| r.kind == Kind::Duplicate)
            .unwrap();
        assert_eq!(c.list_name(d.other), Some("a"));
        assert!(Filter::Duplicate.matches(d));
    }

    fn cached(bytes_of: &str) -> Arc<Classified> {
        Arc::new(classify_text(bytes_of, ListFormat::Auto, false, false))
    }

    fn key(id: &str) -> CacheKey {
        CacheKey {
            id: id.into(),
            digest: "d".into(),
            generation: 1,
            scope: 0,
            format: ListFormat::Auto,
            allowlist: false,
            trusted: false,
        }
    }

    #[test]
    fn cache_evicts_least_recently_used_over_the_cap_and_expires_idle() {
        let text = "||a.test^\n".repeat(200);
        let one = cached(&text);
        let cache = ClassCache::new(one.approx_bytes() * 2 + 10, Duration::from_secs(60));
        cache.insert(key("a"), one.clone());
        cache.insert(key("b"), cached(&text));
        assert!(cache.get(&key("a")).is_some());
        cache.insert(key("c"), cached(&text));
        assert!(
            cache.get(&key("b")).is_none(),
            "b was the least recently used"
        );
        assert!(cache.get(&key("a")).is_some() && cache.get(&key("c")).is_some());
        assert!(cache.bytes() <= one.approx_bytes() * 2 + 10);

        // The newest entry stays even when it alone is over the cap.
        let tiny = ClassCache::new(1, Duration::from_secs(60));
        tiny.insert(key("big"), one);
        assert!(tiny.get(&key("big")).is_some());

        let idle = ClassCache::new(usize::MAX, Duration::from_millis(1));
        idle.insert(key("x"), cached("||x.test^\n"));
        std::thread::sleep(Duration::from_millis(20));
        assert!(idle.get(&key("x")).is_none());
        assert!(idle.is_empty());
    }

    #[test]
    fn a_newer_text_of_a_list_replaces_the_older_one() {
        let cache = ClassCache::new(usize::MAX, Duration::from_secs(60));
        cache.insert(key("a"), cached("||a.test^\n"));
        let mut k2 = key("a");
        k2.digest = "e".into();
        cache.insert(k2.clone(), cached("||b.test^\n"));
        assert_eq!(cache.len(), 1);
        assert!(cache.get(&k2).is_some());
    }
}

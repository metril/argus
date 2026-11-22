//! Builds stored profiles and devices into the live lookup table.
//!
//! [`ProfileBuilder`] watches the profile store and the list service and keeps
//! [`crate::profiles::Profiles`] in step with them, entirely off the request path:
//!
//! * each stored profile becomes an `Arc<Profile>`: base engine from
//!   `ListService::engine_for(lists)` (profiles with the same lists share it), an overlay engine
//!   from its rules, the shared userscript manager and a script control keyed by its stable namespace (`p<id>`, so renames keep the data);
//! * a change to a profile's contents swaps the `Arc<Profile>` inside its existing slot
//!   (`Profiles::edit`, no epoch bump); a change to the set of profiles or to the device mapping
//!   publishes a new table (`Profiles::publish`) that reuses every unchanged slot;
//! * a profile whose build fails keeps its previous compiled state (or the default profile's
//!   engine if it was never built) and the error is recorded, see [`ProfileBuilder::status`];
//! * a profile that disappears from the store has its data removed, see
//!   [`delete_profile_data`].
//!
//! Bursts of changes are debounced and builds are single-flight.

use crate::filtering::ProxyContext;
use crate::profiles::{ProfileTable, Profiles};
use crate::request_ctx::{Profile, ProfileSlot, DEFAULT_PROFILE_ID};
use crate::scriptctl::ScriptControl;
use chrono::{DateTime, Utc};
use common::profile_store::{namespace, DeviceRecord, ProfileRecord, ProfileStore};
use filter_engine::{overlay_from_rules_shared, ArcSwap, SharedEngine};
use ipnet::IpNet;
use list_service::ListService;
use parking_lot::Mutex;
use script_policy::store::PolicyStore;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::sync::{watch, Notify};
use tracing::{info, warn};
use userscript_engine::UserscriptManager;

/// Quiet time after the last change before a rebuild starts.
pub const DEFAULT_DEBOUNCE: Duration = Duration::from_millis(100);
/// How long to wait before retrying a failed removal of a deleted profile's data.
const CLEANUP_RETRY: Duration = Duration::from_secs(30);

/// What the builder last did for one profile.
#[derive(Debug, Clone, Default)]
pub struct ProfileStatus {
    /// Why the last build failed; `None` when it succeeded.
    pub last_error: Option<String>,
    /// When the profile was last built successfully.
    pub last_built: Option<DateTime<Utc>>,
    /// Generation of the live profile (bumped on every successful rebuild).
    pub generation: u64,
}

/// What [`ProfileBuilder::start`] works over.
pub struct BuilderDeps {
    pub ctx: Arc<ProxyContext>,
    pub store: Arc<ProfileStore>,
    pub lists: Arc<ListService>,
    /// The shared userscript manager (all profiles' scripts live in it, keyed by profile namespace).
    pub manager: Option<Arc<UserscriptManager>>,
    /// Script-policy storage; `None` leaves profiles without script control.
    pub policy: Option<Arc<PolicyStore>>,
    pub debounce: Duration,
}

/// Handle to the background builder. Dropping it stops the background task.
pub struct ProfileBuilder {
    inner: Arc<Inner>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

struct Inner {
    ctx: Weak<ProxyContext>,
    store: Arc<ProfileStore>,
    lists: Arc<ListService>,
    manager: Option<Arc<UserscriptManager>>,
    policy: Option<Arc<PolicyStore>>,
    state: tokio::sync::Mutex<State>,
    status: Mutex<HashMap<u64, ProfileStatus>>,
    /// Set-engine contents changed in place: bump every profile's generation at the next pass.
    sets_changed: AtomicBool,
    /// A removal of a deleted profile's data failed: retry on a timer.
    cleanup_failed: AtomicBool,
    wake: Notify,
    reloads: watch::Sender<u64>,
}

#[derive(Default)]
struct State {
    profiles: HashMap<u64, Tracked>,
    map: MapSig,
}

struct Tracked {
    name: String,
    /// Sorted, deduplicated list ids and the overlay rules the profile was built from.
    sig: (Vec<String>, String),
    profile: Arc<Profile>,
    slot: ProfileSlot,
    control: Option<Arc<ScriptControl>>,
    /// Never built successfully: serving the default profile's engine.
    fell_back: bool,
}

/// `(device id, profile id, addresses, token digest)`.
type DeviceSig = (u64, u64, Vec<IpNet>, Option<[u8; 32]>);

/// The part of the stored state that decides the table: which profiles exist and what each
/// device resolves to.
#[derive(Default, PartialEq)]
struct MapSig {
    ids: Vec<u64>,
    devices: Vec<DeviceSig>,
}

impl ProfileBuilder {
    /// Build once in the background, then follow `store.subscribe()` and
    /// `lists.subscribe_sets()`.
    pub fn start(deps: BuilderDeps) -> Arc<Self> {
        let inner = Arc::new(Inner {
            ctx: Arc::downgrade(&deps.ctx),
            store: deps.store,
            lists: deps.lists,
            manager: deps.manager,
            policy: deps.policy,
            state: tokio::sync::Mutex::new(State::default()),
            status: Mutex::new(HashMap::new()),
            sets_changed: AtomicBool::new(false),
            cleanup_failed: AtomicBool::new(false),
            wake: Notify::new(),
            reloads: watch::channel(0).0,
        });
        let task = tokio::spawn(run(inner.clone(), deps.debounce));
        Arc::new(Self {
            inner,
            task: Mutex::new(Some(task)),
        })
    }

    /// Rebuild from the current stored state now and wait for it (single-flight with the
    /// background task: whoever runs second sees the latest state).
    pub async fn sync(&self) {
        self.inner.reload().await;
    }

    /// Ask the background task for a rebuild (debounced).
    pub fn trigger(&self) {
        self.inner.wake.notify_one();
    }

    /// Per-profile result of the last build (profile id to last error / last built time).
    pub fn status(&self) -> HashMap<u64, ProfileStatus> {
        self.inner.status.lock().clone()
    }

    /// Number of completed build passes.
    pub fn passes(&self) -> u64 {
        *self.inner.reloads.borrow()
    }

    /// Wait until at least `n` build passes have completed.
    pub async fn wait_passes(&self, n: u64) {
        let mut rx = self.inner.reloads.subscribe();
        let _ = rx.wait_for(|p| *p >= n).await;
    }
}

impl Drop for ProfileBuilder {
    fn drop(&mut self) {
        if let Some(t) = self.task.lock().take() {
            t.abort();
        }
    }
}

async fn run(inner: Arc<Inner>, debounce: Duration) {
    let mut store_rx = inner.store.subscribe();
    let mut sets_rx = inner.lists.subscribe_sets();
    inner.reload().await;
    loop {
        tokio::select! {
            r = store_rx.changed() => if r.is_err() { return },
            r = sets_rx.changed() => {
                if r.is_err() { return }
                inner.sets_changed.store(true, Ordering::Release);
            }
            _ = inner.wake.notified() => {}
            _ = tokio::time::sleep(CLEANUP_RETRY), if inner.cleanup_failed.load(Ordering::Relaxed) => {}
        }
        // Absorb a burst: rebuild once the changes stop arriving.
        loop {
            tokio::select! {
                _ = tokio::time::sleep(debounce) => break,
                r = store_rx.changed() => if r.is_err() { return },
                r = sets_rx.changed() => {
                    if r.is_err() { return }
                    inner.sets_changed.store(true, Ordering::Release);
                }
            }
        }
        inner.reload().await;
    }
}

fn lists_sig(lists: &[String]) -> Vec<String> {
    let mut v = lists.to_vec();
    v.sort();
    v.dedup();
    v
}

/// What a finished build produced.
struct Compiled {
    engine: Arc<SharedEngine>,
    overlay: Option<Arc<SharedEngine>>,
}

impl Inner {
    async fn reload(&self) {
        let mut st = self.state.lock().await;
        let Some(ctx) = self.ctx.upgrade() else {
            return;
        };
        let store = self.store.clone();
        let read = tokio::task::spawn_blocking(move || {
            // The id bound first: a profile created after it has an id at or above it, so its
            // data is never mistaken for a deleted profile's.
            let bound = store.profile_id_bound()?;
            Ok::<_, common::profile_store::ProfileError>((bound, store.list()?, store.devices()?))
        })
        .await;
        let (bound, records, devices) = match read {
            Ok(Ok(x)) => x,
            Ok(Err(e)) => {
                warn!("profile builder: reading the profile store failed: {e}");
                return;
            }
            Err(e) => {
                warn!("profile builder: store read task failed: {e}");
                return;
            }
        };
        let records: Vec<ProfileRecord> = records
            .into_iter()
            .filter(|r| r.id != DEFAULT_PROFILE_ID)
            .collect();
        self.build_all(&ctx, &mut st, records, devices, bound).await;
        self.reloads.send_modify(|n| *n += 1);
    }

    async fn build_all(
        &self,
        ctx: &Arc<ProxyContext>,
        st: &mut State,
        records: Vec<ProfileRecord>,
        devices: Vec<DeviceRecord>,
        bound: u64,
    ) {
        let profiles: &Profiles = ctx.profiles();
        let sets_changed = self.sets_changed.swap(false, Ordering::AcqRel);
        let default_slot = ctx.default_profile().clone();
        let default = default_slot.load_full();

        // Lists any profile uses are downloaded and refreshed like the globally enabled ones.
        let union: BTreeSet<String> = records.iter().flat_map(|r| r.lists.clone()).collect();
        self.lists.set_profile_lists(union);

        // Data of profiles that are gone is removed after the new table is live. Ids are never
        // reused, so a namespace is purged at most once and a rename never touches data.
        let mut cleanup: Vec<(String, Option<Arc<ScriptControl>>)> = Vec::new();
        let live: HashSet<u64> = records.iter().map(|r| r.id).collect();
        let gone: Vec<u64> = st
            .profiles
            .keys()
            .copied()
            .filter(|id| !live.contains(id))
            .collect();
        for id in gone {
            if let Some(t) = st.profiles.remove(&id) {
                cleanup.push((namespace(id), t.control));
            }
            self.status.lock().remove(&id);
        }

        for rec in &records {
            let sig = (lists_sig(&rec.lists), rec.rules.clone());
            let prev = st.profiles.get(&rec.id);
            let renamed = prev.is_some_and(|t| t.name != rec.name);
            let unchanged = prev.is_some_and(|t| !renamed && t.sig == sig && !t.fell_back);
            if unchanged && !sets_changed {
                continue;
            }
            if unchanged {
                // Same inputs, but a list set was rebuilt in place: new generation, same slot.
                let t = st.profiles.get_mut(&rec.id).expect("tracked");
                let p = Arc::new(t.profile.with(|p| p.generation += 1));
                t.profile = p.clone();
                if !profiles.edit(rec.id, p.clone()) {
                    t.slot.store(p.clone());
                }
                if let Some(s) = self.status.lock().get_mut(&rec.id) {
                    s.generation = p.generation;
                }
                continue;
            }
            let result = self.compile(&sig, &default.engine).await;
            let prev = st.profiles.get_mut(&rec.id);
            match (result, prev) {
                // Failed again: keep what is serving (unless the name changed, below).
                (Err(e), Some(t)) => {
                    warn!(
                        "profile {} ({}): build failed, keeping previous state: {e}",
                        rec.id, rec.name
                    );
                    self.record_error(rec.id, e, t.profile.generation);
                }
                (result, prev) => {
                    let (compiled, fell_back, error) = match result {
                        Ok(c) => (c, false, None),
                        Err(e) => {
                            warn!("profile {} ({}): first build failed, using the default engine: {e}", rec.id, rec.name);
                            (
                                Compiled {
                                    engine: default.engine.clone(),
                                    overlay: None,
                                },
                                true,
                                Some(e),
                            )
                        }
                    };
                    let (generation, slot) = match &prev {
                        Some(t) => (t.profile.generation + 1, Some(t.slot.clone())),
                        None => (1, None),
                    };
                    let control = match prev.as_ref().and_then(|t| t.control.clone()) {
                        Some(c) => Some(c),
                        None => self.new_control(&namespace(rec.id)).await,
                    };
                    let profile = Arc::new(
                        Profile::new(rec.id, generation, compiled.engine)
                            .with(|p| p.display_name = Arc::from(rec.name.as_str()))
                            .with_overlay(compiled.overlay)
                            .with_userscripts(default.userscripts.clone())
                            .with_script_control(control.clone()),
                    );
                    let slot = match slot {
                        Some(s) => {
                            if !profiles.edit(rec.id, profile.clone()) {
                                s.store(profile.clone());
                            }
                            s
                        }
                        None => Arc::new(ArcSwap::from(profile.clone())),
                    };
                    self.status.lock().insert(
                        rec.id,
                        ProfileStatus {
                            last_error: error,
                            last_built: (!fell_back).then(Utc::now),
                            generation,
                        },
                    );
                    st.profiles.insert(
                        rec.id,
                        Tracked {
                            name: rec.name.clone(),
                            sig,
                            profile,
                            slot,
                            control,
                            fell_back,
                        },
                    );
                    info!(
                        "profile {} ({}) built, generation {generation}",
                        rec.id, rec.name
                    );
                }
            }
        }

        // Table: only when the profile set or a device mapping changed.
        let mut ids: Vec<u64> = st.profiles.keys().copied().collect();
        ids.sort_unstable();
        let mut devs: Vec<_> = devices
            .iter()
            .map(|d| (d.id, d.profile_id, d.ips.clone(), d.token_digest))
            .collect();
        devs.sort_by_key(|d| d.0);
        let map = MapSig { ids, devices: devs };
        if map != st.map {
            let mut b = ProfileTable::builder(default_slot);
            for (id, t) in &st.profiles {
                b = b.profile(*id, t.slot.clone());
            }
            for d in &devices {
                let seen = Some(profiles.seen_cell(d.id));
                for net in &d.ips {
                    b = if net.prefix_len() == net.max_prefix_len() {
                        b.ip_for(net.addr(), d.profile_id, seen.clone())
                    } else {
                        b.prefix_for(*net, d.profile_id, seen.clone())
                    };
                }
                if let Some(digest) = d.token_digest {
                    b = b.token_for(digest, d.profile_id, seen.clone());
                }
            }
            profiles.retain_seen(&devices.iter().map(|d| d.id).collect());
            profiles.publish(b.build());
            st.map = map;
        }

        for (name, control) in cleanup {
            let (manager, policy) = (self.manager.clone(), self.policy.clone());
            let res = tokio::task::spawn_blocking(move || {
                delete_profile_data(
                    &name,
                    manager.as_deref(),
                    policy.as_deref(),
                    control.as_deref(),
                )
                .map_err(|e| format!("{name}: {e}"))
            })
            .await;
            match res {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    warn!("profile cleanup failed (will retry): {e}");
                    self.cleanup_failed.store(true, Ordering::Relaxed);
                }
                Err(e) => {
                    warn!("profile cleanup task failed (will retry): {e}");
                    self.cleanup_failed.store(true, Ordering::Relaxed);
                }
            }
        }
        self.sweep(&live, bound).await;
    }

    /// Remove the data of every `p<id>` namespace in the policy and userscript stores whose
    /// profile no longer exists: one created and deleted inside a debounce window, one deleted
    /// while the proxy was down, or one whose cleanup failed. Runs at startup and after every
    /// pass; ids below `bound` that are not `live` were handed out and are gone for good.
    async fn sweep(&self, live: &HashSet<u64>, bound: u64) {
        let (manager, policy) = (self.manager.clone(), self.policy.clone());
        if manager.is_none() && policy.is_none() {
            return;
        }
        let live = live.clone();
        let res = tokio::task::spawn_blocking(move || -> Result<bool, String> {
            let mut names = BTreeSet::new();
            if let Some(m) = &manager {
                names.extend(
                    m.stored_profiles()
                        .map_err(|e| format!("userscripts: {e}"))?,
                );
            }
            if let Some(p) = &policy {
                names.extend(
                    p.stored_profiles()
                        .map_err(|e| format!("script policy: {e}"))?,
                );
            }
            let mut failed = false;
            for name in names {
                let Some(id) = name.strip_prefix('p').and_then(|d| d.parse::<u64>().ok()) else {
                    continue;
                };
                if id == DEFAULT_PROFILE_ID
                    || id >= bound
                    || live.contains(&id)
                    || name != namespace(id)
                {
                    continue;
                }
                match delete_profile_data(&name, manager.as_deref(), policy.as_deref(), None) {
                    Ok(()) => info!("removed leftover data of deleted profile {id}"),
                    Err(e) => {
                        warn!("leftover data of profile {id} could not be removed: {e}");
                        failed = true;
                    }
                }
            }
            Ok(failed)
        })
        .await;
        match res {
            Ok(Ok(failed)) => self.cleanup_failed.store(failed, Ordering::Relaxed),
            Ok(Err(e)) => {
                warn!("profile data sweep failed (will retry): {e}");
                self.cleanup_failed.store(true, Ordering::Relaxed);
            }
            Err(e) => warn!("profile data sweep task failed: {e}"),
        }
    }

    fn record_error(&self, id: u64, error: String, generation: u64) {
        let mut s = self.status.lock();
        let e = s.entry(id).or_default();
        e.last_error = Some(error);
        e.generation = generation;
    }

    /// Base engine and overlay for one profile, built off the async threads.
    async fn compile(
        &self,
        sig: &(Vec<String>, String),
        default_engine: &Arc<SharedEngine>,
    ) -> Result<Compiled, String> {
        for id in &sig.0 {
            match self.lists.store().get(id) {
                Ok(Some(_)) => {}
                Ok(None) => return Err(format!("list \"{id}\" does not exist")),
                Err(e) => return Err(format!("list \"{id}\": {e}")),
            }
        }
        let engine = self
            .lists
            .engine_for(&sig.0)
            .await
            .map_err(|e| format!("building the lists failed: {e}"))?;
        let (rules, base) = (sig.1.clone(), default_engine.clone());
        let overlay = tokio::task::spawn_blocking(move || overlay_from_rules_shared(&rules, &base))
            .await
            .map_err(|e| format!("rule compile task failed: {e}"))?
            .map_err(|e| format!("rules did not compile: {e}"))?;
        Ok(Compiled { engine, overlay })
    }

    /// Script control and userscript index for a profile name (blocking reads off the async
    /// threads). `None` without a policy store.
    async fn new_control(&self, name: &str) -> Option<Arc<ScriptControl>> {
        let (policy, manager, name) = (self.policy.clone(), self.manager.clone(), name.to_string());
        let control = tokio::task::spawn_blocking(move || {
            if let Some(m) = &manager {
                m.refresh_index_for(&name);
            }
            policy.map(|p| ScriptControl::new(p, &name))
        })
        .await
        .ok()
        .flatten()?;
        control.spawn_expiry();
        Some(control)
    }
}

/// Remove everything a deleted profile's namespace owns: its userscripts, stored
/// values, cookies and live index; its script-policy rules, temporary grants, panel settings,
/// PIN and lockout state; and stop its script control's expiry task. Ids are never reused, so
/// nothing later inherits it. The default profile is refused. Blocking: call from
/// `spawn_blocking`.
pub fn delete_profile_data(
    name: &str,
    manager: Option<&UserscriptManager>,
    policy: Option<&PolicyStore>,
    control: Option<&ScriptControl>,
) -> Result<(), String> {
    if name == userscript_engine::DEFAULT_PROFILE || name == script_policy::DEFAULT_PROFILE {
        return Err("the default profile's data cannot be deleted".into());
    }
    if let Some(c) = control {
        c.stop();
    }
    let mut errors = Vec::new();
    if let Some(m) = manager {
        if let Err(e) = m.delete_profile_scripts(name) {
            errors.push(format!("userscripts: {e}"));
        }
        m.drop_profile_index(name);
    }
    if let Some(p) = policy {
        if let Err(e) = p.delete_profile(name) {
            errors.push(format!("script policy: {e}"));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

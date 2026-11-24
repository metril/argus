//! Per-request context: which profile applies and who is asking.
//!
//! A connection resolves its [`ProfileSlot`] once and every request on it carries a
//! [`RequestCtx`] pointing at that slot. Reading the profile on the request path is one atomic
//! load (`slot.load()`); live profile edits swap the `Arc<Profile>` inside the slot.

use crate::profiles::Profiles;
use filter_engine::{ArcSwap, SharedEngine};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

/// An immutable, precompiled filtering profile (cloned and modified via [`Profile::with`]).
#[derive(Clone)]
pub struct Profile {
    pub id: u64,
    /// Bumped on every edit of the profile (cache key for per-host caches).
    pub generation: u64,
    /// GM / script-policy namespace: `"default"` for id 0 (so stored data keeps working), else
    /// `p<id>`. Stable across renames.
    pub name: Arc<str>,
    /// Display label (the profile's current name); never used as a storage key.
    pub display_name: Arc<str>,
    pub engine: Arc<SharedEngine>,
    /// Small second engine checked after `engine`: an overlay exception or block wins; cosmetic
    /// resources are merged from both.
    pub overlay: Option<Arc<SharedEngine>>,
    /// Profile id as text, attached to block events as their client (built once per profile so
    /// the request path allocates nothing). The API filters the block log by it, so it must stay the
    /// id, never the display name.
    pub label: Arc<str>,
    /// Userscripts of this profile (live index, GM backend, token key). `None`: no userscripts.
    pub userscripts: Option<Arc<userscript_engine::UserscriptManager>>,
    /// Live script index of this profile's namespace, taken once at build time so the request
    /// path loads it with one atomic read (no lock, no hashing). Set with `userscripts`.
    pub script_index: Option<Arc<ArcSwap<userscript_engine::ScriptIndex>>>,
    /// Script control of this profile (compiled policy, header cache, panel settings). `None`:
    /// script control is not available; when present and its master switch is off, the request
    /// path does one atomic load and nothing else.
    pub script_control: Option<Arc<crate::scriptctl::ScriptControl>>,
}

impl Profile {
    /// The engine generation (engine + extended-rule index) as one consistent snapshot.
    pub fn generation(&self) -> Arc<filter_engine::Generation> {
        self.engine.generation()
    }

    /// The extended-rule index of the live generation (shares the engine's atomic swap).
    pub fn ext_index(generation: &filter_engine::Generation) -> Option<&ext_rules::ExtIndex> {
        generation.aux::<ext_rules::ExtIndex>()
    }

    pub fn new(id: u64, generation: u64, engine: Arc<SharedEngine>) -> Self {
        let name: Arc<str> = if id == DEFAULT_PROFILE_ID {
            Arc::from(userscript_engine::DEFAULT_PROFILE)
        } else {
            Arc::from(common::profile_store::namespace(id))
        };
        Self {
            id,
            generation,
            display_name: name.clone(),
            name,
            engine,
            overlay: None,
            label: Arc::from(id.to_string()),
            userscripts: None,
            script_index: None,
            script_control: None,
        }
    }

    /// A copy with `f` applied; every other field is carried over.
    pub fn with(&self, f: impl FnOnce(&mut Profile)) -> Profile {
        let mut p = self.clone();
        f(&mut p);
        p
    }

    /// The same profile with userscripts attached.
    pub fn with_userscripts(
        mut self,
        manager: Option<Arc<userscript_engine::UserscriptManager>>,
    ) -> Self {
        self.script_index = manager.as_ref().map(|m| m.index_handle(&self.name));
        self.userscripts = manager;
        self
    }

    /// The same profile with script control attached.
    pub fn with_script_control(
        mut self,
        control: Option<Arc<crate::scriptctl::ScriptControl>>,
    ) -> Self {
        self.script_control = control;
        self
    }

    /// The same profile with an overlay engine.
    pub fn with_overlay(mut self, overlay: Option<Arc<SharedEngine>>) -> Self {
        self.overlay = overlay;
        self
    }

    /// This profile's userscript manager.
    pub fn userscript_manager(&self) -> Option<&Arc<userscript_engine::UserscriptManager>> {
        self.userscripts.as_ref()
    }
}

/// Swappable holder of the current profile; connections keep the slot, not the profile.
pub type ProfileSlot = Arc<ArcSwap<Profile>>;

/// Id of the single built-in profile.
pub const DEFAULT_PROFILE_ID: u64 = 0;

/// Build the default profile's slot around `engine`.
pub fn default_profile_slot(engine: Arc<SharedEngine>) -> ProfileSlot {
    Arc::new(ArcSwap::from_pointee(Profile::new(
        DEFAULT_PROFILE_ID,
        0,
        engine,
    )))
}

/// What the proxy knows about the request's origin. Cheap to build per connection (two `Arc`
/// refcount bumps at most) and passed by reference per request.
#[derive(Clone)]
pub struct RequestCtx {
    pub profile: ProfileSlot,
    pub client_addr: SocketAddr,
    /// Authenticated proxy user, when proxy auth is in use.
    pub auth_user: Option<Arc<str>>,
    /// Profile-table epoch this context was resolved at. It lives inside the swapped value, so
    /// the context and its epoch can never be paired up wrongly by concurrent re-resolutions.
    pub epoch: u64,
    /// The connection arrived on the transparent listener (for the request log).
    pub transparent: bool,
    /// Switches of the listener that accepted the connection (`None`: defaults).
    pub listener: Option<Arc<crate::listener_flags::ListenerFlags>>,
    /// The extension session this connection authenticated as on the extension listener.
    pub ext: Option<u64>,
    /// The cookie store (Firefox container, private window) the connection's credentials named;
    /// empty for the default store and for Chrome.
    pub ext_store: Option<Arc<str>>,
}

impl RequestCtx {
    pub fn new(profile: ProfileSlot, client_addr: SocketAddr, auth_user: Option<Arc<str>>) -> Self {
        Self {
            profile,
            client_addr,
            auth_user,
            epoch: 0,
            transparent: false,
            listener: None,
            ext: None,
            ext_store: None,
        }
    }

    fn with_listener(
        mut self,
        transparent: bool,
        listener: Option<Arc<crate::listener_flags::ListenerFlags>>,
    ) -> Self {
        self.transparent = transparent;
        self.listener = listener;
        self
    }

    /// Whether ad blocking applies to this connection's listener.
    #[inline]
    pub fn adblock_on(&self) -> bool {
        self.listener.as_ref().is_none_or(|l| l.adblock())
    }

    fn at_epoch(mut self, epoch: u64) -> Self {
        self.epoch = epoch;
        self
    }

    /// Context for an unattributed client on the given profile.
    pub fn anonymous(profile: ProfileSlot) -> Self {
        Self::new(profile, SocketAddr::from(([0, 0, 0, 0], 0)), None)
    }
}

/// Per-connection profile state: the resolved [`RequestCtx`] and the epoch it was resolved at.
/// A request costs one epoch load and one `Arc` clone; a changed epoch re-resolves (device
/// reassignment), a profile edit needs nothing (the slot already points at the new profile).
pub struct ConnCtx {
    client_addr: SocketAddr,
    /// Device token digest from the CONNECT head or the first plain proxy request. Never changes
    /// afterwards; headers seen inside a tunnel are not consulted.
    digest: OnceLock<[u8; 32]>,
    /// The resolved context; its `epoch` is compared against the live one on every request.
    cur: ArcSwap<RequestCtx>,
    /// Plain-HTTP proxy connection whose first request still decides the token.
    awaiting_token: AtomicBool,
    /// The token was revoked while the connection was open and tokens are required.
    revoked: AtomicBool,
    /// Arrived on the transparent listener.
    transparent: AtomicBool,
    /// Switches of the accepting listener.
    listener: arc_swap::ArcSwapOption<crate::listener_flags::ListenerFlags>,
    /// Accepted on the extension-only listener.
    ext_listener: AtomicBool,
    /// Extension session the connection authenticated as (0: none), and the profile id it pins
    /// (0: none). Set once, from the CONNECT head or the first plain request.
    ext_session: std::sync::atomic::AtomicU64,
    ext_pin: std::sync::atomic::AtomicU64,
    ext_store: OnceLock<Arc<str>>,
}

impl ConnCtx {
    /// Resolved by the peer address alone (transparent mode, and the starting point of every
    /// explicit connection).
    pub fn new(profiles: &Profiles, client_addr: SocketAddr) -> Self {
        let (slot, epoch) = profiles.resolve_by_digest(client_addr.ip(), None);
        Self {
            client_addr,
            digest: OnceLock::new(),
            cur: ArcSwap::from_pointee(RequestCtx::new(slot, client_addr, None).at_epoch(epoch)),
            awaiting_token: AtomicBool::new(false),
            revoked: AtomicBool::new(false),
            transparent: AtomicBool::new(false),
            listener: arc_swap::ArcSwapOption::empty(),
            ext_listener: AtomicBool::new(false),
            ext_session: std::sync::atomic::AtomicU64::new(0),
            ext_pin: std::sync::atomic::AtomicU64::new(0),
            ext_store: OnceLock::new(),
        }
    }

    /// Mark the connection as accepted on the extension-only listener.
    pub fn mark_ext_listener(&self) {
        self.ext_listener.store(true, Ordering::Relaxed);
    }

    pub fn is_ext_listener(&self) -> bool {
        self.ext_listener.load(Ordering::Relaxed)
    }

    /// The cookie store the connection's credentials named (empty: default).
    pub fn ext_store(&self) -> Arc<str> {
        self.ext_store
            .get()
            .cloned()
            .unwrap_or_else(|| Arc::from(""))
    }

    /// The extension session this connection authenticated as.
    pub fn ext_session(&self) -> Option<u64> {
        match self.ext_session.load(Ordering::Relaxed) {
            0 => None,
            s => Some(s),
        }
    }

    /// Bind the connection (once) to extension session `session`, optionally pinning it to
    /// `profile`, and re-resolve. Later calls are ignored: nothing inside a tunnel can rebind.
    pub fn set_ext(&self, profiles: &Profiles, session: u64, store: &str, profile: Option<u64>) {
        let _ = self.ext_store.set(Arc::from(store));
        if self
            .ext_session
            .compare_exchange(0, session, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            self.ext_pin.store(profile.unwrap_or(0), Ordering::Relaxed);
            self.reresolve(profiles, false);
        }
    }

    /// Record which listener accepted the connection (call before the first request).
    pub fn set_listener(
        &self,
        flags: Option<Arc<crate::listener_flags::ListenerFlags>>,
        transparent: bool,
    ) {
        self.transparent.store(transparent, Ordering::Relaxed);
        self.listener.store(flags.clone());
        let mut ctx = (**self.cur.load()).clone();
        ctx.transparent = transparent;
        ctx.listener = flags;
        self.cur.store(Arc::new(ctx));
    }

    /// Whether MITM is on for this connection's listener (default on).
    /// The accepting listener's switches.
    pub fn listener_flags(&self) -> Option<Arc<crate::listener_flags::ListenerFlags>> {
        self.listener.load_full()
    }

    pub fn mitm_on(&self) -> bool {
        self.listener.load().as_ref().is_none_or(|l| l.mitm())
    }

    /// Whether HTTP/2 is on for this connection's listener (default on).
    pub fn http2_on(&self) -> bool {
        self.listener.load().as_ref().is_none_or(|l| l.http2())
    }

    pub fn client_addr(&self) -> SocketAddr {
        self.client_addr
    }

    /// Whether `digest` names a known device.
    pub fn token_known(profiles: &Profiles, digest: &[u8; 32]) -> bool {
        profiles.table().resolve_digest(digest).is_some()
    }

    /// Pin the device token (once) and re-resolve. A second call is ignored.
    pub fn set_token(&self, profiles: &Profiles, digest: [u8; 32]) {
        if self.digest.set(digest).is_ok() {
            self.reresolve(profiles, false);
        }
    }

    /// Mark a plain-HTTP proxy connection: its first request carries the token.
    pub fn await_token(&self) {
        self.awaiting_token.store(true, Ordering::Relaxed);
    }

    /// True exactly once on an `await_token` connection (the first request).
    pub fn take_awaiting(&self) -> bool {
        self.awaiting_token.load(Ordering::Relaxed)
            && self.awaiting_token.swap(false, Ordering::Relaxed)
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Relaxed)
    }

    fn reresolve(&self, profiles: &Profiles, require_token: bool) {
        let d = self.digest.get();
        let (mut slot, epoch) = profiles.resolve_by_digest(self.client_addr.ip(), d);
        let pin = self.ext_pin.load(Ordering::Relaxed);
        if pin != 0 {
            if let Some(p) = profiles.table().slot(pin) {
                slot = p.clone();
            }
        }
        if require_token && d.is_some_and(|d| !Self::token_known(profiles, d)) {
            self.revoked.store(true, Ordering::Relaxed);
        }
        let mut ctx = RequestCtx::new(slot, self.client_addr, None)
            .at_epoch(epoch)
            .with_listener(
                self.transparent.load(Ordering::Relaxed),
                self.listener.load_full(),
            );
        ctx.ext = self.ext_session();
        ctx.ext_store = self.ext_store.get().cloned();
        self.cur.store(Arc::new(ctx));
    }

    /// The context for this request: one epoch load, re-resolved only when it moved.
    #[inline]
    pub fn current(&self, profiles: &Profiles, require_token: bool) -> Arc<RequestCtx> {
        let cur = self.cur.load_full();
        if cur.epoch == profiles.epoch() {
            return cur;
        }
        self.reresolve(profiles, require_token);
        self.cur.load_full()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn profile_edit_reaches_holders_of_the_slot() {
        let slot = default_profile_slot(Arc::new(SharedEngine::new()));
        let ctx = RequestCtx::anonymous(slot.clone());
        assert_eq!(ctx.profile.load().generation, 0);
        let engine = ctx.profile.load().engine.clone();
        slot.store(Arc::new(Profile::new(DEFAULT_PROFILE_ID, 1, engine)));
        assert_eq!(ctx.profile.load().generation, 1);
    }

    fn table_for(ip: &str, id: u64, default: &ProfileSlot) -> crate::profiles::ProfileTable {
        let slot: ProfileSlot = Arc::new(ArcSwap::from_pointee(Profile::new(
            id,
            0,
            Arc::new(SharedEngine::new()),
        )));
        crate::profiles::ProfileTable::builder(default.clone())
            .profile(id, slot)
            .ip(ip.parse().unwrap(), id)
            .build()
    }

    /// Two streams re-resolve across a publish and finish in the worst order: the connection must
    /// still end up on the profile of the newest table.
    #[test]
    fn interleaved_reresolution_cannot_pin_the_old_profile() {
        let default = default_profile_slot(Arc::new(SharedEngine::new()));
        let profiles = Profiles::new(default.clone());
        profiles.publish(table_for("10.0.0.5", 1, &default));
        let addr: SocketAddr = "10.0.0.5:4000".parse().unwrap();
        let conn = ConnCtx::new(&profiles, addr);
        assert_eq!(conn.current(&profiles, false).profile.load().id, 1);
        // Stream A resolved against the old table, then a publish moves the device to profile 2,
        // stream B resolved against the new one and installed it first; A installs last.
        let (old_slot, old_epoch) = profiles.resolve_by_digest(addr.ip(), None);
        profiles.publish(table_for("10.0.0.5", 2, &default));
        let (new_slot, new_epoch) = profiles.resolve_by_digest(addr.ip(), None);
        conn.cur.store(Arc::new(
            RequestCtx::new(new_slot, addr, None).at_epoch(new_epoch),
        ));
        conn.cur.store(Arc::new(
            RequestCtx::new(old_slot, addr, None).at_epoch(old_epoch),
        ));
        assert_eq!(conn.current(&profiles, false).profile.load().id, 2);
    }

    /// Streams of one connection re-resolving while tables are published: once publishing stops,
    /// every next request sees the last table's profile.
    #[test]
    fn concurrent_reresolution_converges_on_the_last_publish() {
        let default = default_profile_slot(Arc::new(SharedEngine::new()));
        let profiles = Arc::new(Profiles::new(default.clone()));
        profiles.publish(table_for("10.0.0.5", 1, &default));
        let addr: SocketAddr = "10.0.0.5:4000".parse().unwrap();
        for _ in 0..10 {
            let conn = Arc::new(ConnCtx::new(&profiles, addr));
            let stop = Arc::new(AtomicBool::new(false));
            let readers: Vec<_> = (0..4)
                .map(|_| {
                    let (c, p, st) = (conn.clone(), profiles.clone(), stop.clone());
                    std::thread::spawn(move || {
                        while !st.load(Ordering::Relaxed) {
                            c.current(&p, false);
                        }
                    })
                })
                .collect();
            for i in 0..100u64 {
                profiles.publish(table_for("10.0.0.5", 1 + i % 2, &default));
            }
            profiles.publish(table_for("10.0.0.5", 3, &default));
            stop.store(true, Ordering::Relaxed);
            readers.into_iter().for_each(|r| r.join().unwrap());
            assert_eq!(conn.current(&profiles, false).profile.load().id, 3);
        }
    }
}

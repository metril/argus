//! Per-request context: which profile applies and who is asking.
//!
//! A connection resolves its [`ProfileSlot`] once and every request on it carries a
//! [`RequestCtx`] pointing at that slot. Reading the profile on the request path is one atomic
//! load (`slot.load()`); live profile edits swap the `Arc<Profile>` inside the slot.

use crate::profiles::Profiles;
use filter_engine::{ArcSwap, SharedEngine};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

/// An immutable, precompiled filtering profile (cloned and modified via [`Profile::with`]).
#[derive(Clone)]
pub struct Profile {
    pub id: u64,
    /// Bumped on every edit of the profile (cache key for per-host caches).
    pub generation: u64,
    /// GM / script-policy namespace: `"default"` for id 0 (so stored data keeps working), else
    /// the profile's own name.
    pub name: Arc<str>,
    pub engine: Arc<SharedEngine>,
    /// Small second engine checked after `engine`: an overlay exception or block wins; cosmetic
    /// resources are merged from both.
    pub overlay: Option<Arc<SharedEngine>>,
    /// Client label attached to block events (the profile id for now), built once per profile so
    /// the request path allocates nothing.
    pub label: Arc<str>,
    /// Userscripts of this profile (live index, GM backend, token key). `None`: no userscripts.
    pub userscripts: Option<Arc<userscript_engine::UserscriptManager>>,
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
            Arc::from(id.to_string())
        };
        Self {
            id,
            generation,
            name,
            engine,
            overlay: None,
            label: Arc::from(id.to_string()),
            userscripts: None,
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
}

impl RequestCtx {
    pub fn new(profile: ProfileSlot, client_addr: SocketAddr, auth_user: Option<Arc<str>>) -> Self {
        Self {
            profile,
            client_addr,
            auth_user,
        }
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
    cur: ArcSwap<RequestCtx>,
    epoch: AtomicU64,
    /// Plain-HTTP proxy connection whose first request still decides the token.
    awaiting_token: AtomicBool,
    /// The token was revoked while the connection was open and tokens are required.
    revoked: AtomicBool,
}

impl ConnCtx {
    /// Resolved by the peer address alone (transparent mode, and the starting point of every
    /// explicit connection).
    pub fn new(profiles: &Profiles, client_addr: SocketAddr) -> Self {
        let (slot, epoch) = profiles.resolve_by_digest(client_addr.ip(), None);
        Self {
            client_addr,
            digest: OnceLock::new(),
            cur: ArcSwap::from_pointee(RequestCtx::new(slot, client_addr, None)),
            epoch: AtomicU64::new(epoch),
            awaiting_token: AtomicBool::new(false),
            revoked: AtomicBool::new(false),
        }
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
        let (slot, epoch) = profiles.resolve_by_digest(self.client_addr.ip(), d);
        if require_token && d.is_some_and(|d| !Self::token_known(profiles, d)) {
            self.revoked.store(true, Ordering::Relaxed);
        }
        self.cur
            .store(Arc::new(RequestCtx::new(slot, self.client_addr, None)));
        self.epoch.store(epoch, Ordering::Release);
    }

    /// The context for this request: one epoch load, re-resolved only when it moved.
    #[inline]
    pub fn current(&self, profiles: &Profiles, require_token: bool) -> Arc<RequestCtx> {
        if profiles.epoch() != self.epoch.load(Ordering::Acquire) {
            self.reresolve(profiles, require_token);
        }
        self.cur.load_full()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_edit_reaches_holders_of_the_slot() {
        let slot = default_profile_slot(Arc::new(SharedEngine::new()));
        let ctx = RequestCtx::anonymous(slot.clone());
        assert_eq!(ctx.profile.load().generation, 0);
        let engine = ctx.profile.load().engine.clone();
        slot.store(Arc::new(Profile::new(DEFAULT_PROFILE_ID, 1, engine)));
        assert_eq!(ctx.profile.load().generation, 1);
    }
}

//! Per-request context: which profile applies and who is asking.
//!
//! A connection resolves its [`ProfileSlot`] once and every request on it carries a
//! [`RequestCtx`] pointing at that slot. Reading the profile on the request path is one atomic
//! load (`slot.load()`); live profile edits swap the `Arc<Profile>` inside the slot.

use filter_engine::{ArcSwap, SharedEngine};
use std::net::SocketAddr;
use std::sync::Arc;

/// An immutable, precompiled filtering profile. For now it is just the engine handle plus ids;
/// later phases add script policy, overlay engines and userscript indexes.
pub struct Profile {
    pub id: u64,
    /// Bumped on every edit of the profile (cache key for per-host caches).
    pub generation: u64,
    pub engine: Arc<SharedEngine>,
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
        Self {
            id,
            generation,
            engine,
            label: Arc::from(id.to_string()),
            userscripts: None,
            script_control: None,
        }
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

    /// The userscript manager, only for the profile that owns the stored scripts (the default
    /// profile until profiles get their own script sets).
    pub fn userscript_manager(&self) -> Option<&Arc<userscript_engine::UserscriptManager>> {
        if self.id == DEFAULT_PROFILE_ID {
            self.userscripts.as_ref()
        } else {
            None
        }
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

    /// Context for an unattributed client on the default profile.
    pub fn anonymous(profile: ProfileSlot) -> Self {
        Self::new(profile, SocketAddr::from(([0, 0, 0, 0], 0)), None)
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

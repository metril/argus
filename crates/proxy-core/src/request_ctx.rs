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
}

/// Swappable holder of the current profile; connections keep the slot, not the profile.
pub type ProfileSlot = Arc<ArcSwap<Profile>>;

/// Id of the single built-in profile.
pub const DEFAULT_PROFILE_ID: u64 = 0;

/// Build the default profile's slot around `engine`.
pub fn default_profile_slot(engine: Arc<SharedEngine>) -> ProfileSlot {
    Arc::new(ArcSwap::from_pointee(Profile {
        id: DEFAULT_PROFILE_ID,
        generation: 0,
        engine,
    }))
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
        slot.store(Arc::new(Profile {
            id: DEFAULT_PROFILE_ID,
            generation: 1,
            engine,
        }));
        assert_eq!(ctx.profile.load().generation, 1);
    }
}

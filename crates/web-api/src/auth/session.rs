//! Session management with token revocation
//!
//! Provides session tracking and token revocation capabilities:
//! - Active session tracking
//! - Token revocation (logout, security events)
//! - Session metadata (IP, user agent, last activity)

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Session data for active sessions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    /// User ID
    pub user_id: Uuid,
    /// Username
    pub username: String,
    /// Session creation time
    pub created_at: DateTime<Utc>,
    /// Last activity time
    pub last_activity: DateTime<Utc>,
    /// Client IP address
    pub ip_address: Option<IpAddr>,
    /// User agent string
    pub user_agent: Option<String>,
    /// JTI of the refresh token
    pub refresh_token_jti: String,
}

/// Session manager for tracking active sessions and revoked tokens
pub struct SessionManager {
    /// Active sessions by session ID
    active_sessions: Arc<DashMap<Uuid, SessionData>>,
    /// Sessions by user ID (for listing user's sessions)
    user_sessions: Arc<DashMap<Uuid, HashSet<Uuid>>>,
    /// Revoked token JTIs with expiration tracking
    revoked_tokens: Arc<DashMap<String, Instant>>,
    /// Cleanup interval for expired revocations
    revocation_ttl: Duration,
    /// Last cleanup time
    last_cleanup: Arc<RwLock<Instant>>,
}

impl SessionManager {
    /// Create a new session manager
    ///
    /// # Arguments
    /// * `revocation_ttl` - How long to keep revoked token records (should be >= max token lifetime)
    pub fn new(revocation_ttl: Duration) -> Self {
        Self {
            active_sessions: Arc::new(DashMap::new()),
            user_sessions: Arc::new(DashMap::new()),
            revoked_tokens: Arc::new(DashMap::new()),
            revocation_ttl,
            last_cleanup: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Create a new session
    ///
    /// # Arguments
    /// * `user_id` - User's UUID
    /// * `username` - User's username
    /// * `refresh_token_jti` - JTI of the refresh token for this session
    /// * `ip_address` - Client IP address (optional)
    /// * `user_agent` - User agent string (optional)
    ///
    /// # Returns
    /// * `Uuid` - Session ID
    pub fn create_session(
        &self,
        user_id: Uuid,
        username: String,
        refresh_token_jti: String,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
    ) -> Uuid {
        let session_id = Uuid::new_v4();
        let now = Utc::now();

        let session = SessionData {
            user_id,
            username,
            created_at: now,
            last_activity: now,
            ip_address,
            user_agent,
            refresh_token_jti,
        };

        self.active_sessions.insert(session_id, session);

        // Track session under user
        self.user_sessions
            .entry(user_id)
            .or_insert_with(HashSet::new)
            .insert(session_id);

        session_id
    }

    /// Update session activity timestamp
    pub fn touch_session(&self, session_id: &Uuid) {
        if let Some(mut session) = self.active_sessions.get_mut(session_id) {
            session.last_activity = Utc::now();
        }
    }

    /// Get session data
    pub fn get_session(&self, session_id: &Uuid) -> Option<SessionData> {
        self.active_sessions.get(session_id).map(|s| s.clone())
    }

    /// Get all sessions for a user
    pub fn get_user_sessions(&self, user_id: &Uuid) -> Vec<(Uuid, SessionData)> {
        let session_ids = match self.user_sessions.get(user_id) {
            Some(ids) => ids.clone(),
            None => return Vec::new(),
        };

        session_ids
            .iter()
            .filter_map(|id| {
                self.active_sessions
                    .get(id)
                    .map(|session| (*id, session.clone()))
            })
            .collect()
    }

    /// Revoke a session (logout)
    ///
    /// This removes the session and marks its refresh token as revoked.
    pub fn revoke_session(&self, session_id: &Uuid) -> bool {
        if let Some((_, session)) = self.active_sessions.remove(session_id) {
            // Revoke the refresh token
            self.revoke_token(&session.refresh_token_jti);

            // Remove from user's session list
            if let Some(mut user_sessions) = self.user_sessions.get_mut(&session.user_id) {
                user_sessions.remove(session_id);
            }

            return true;
        }
        false
    }

    /// Revoke all sessions for a user (e.g., password change, security event)
    pub fn revoke_all_user_sessions(&self, user_id: &Uuid) {
        if let Some((_, session_ids)) = self.user_sessions.remove(user_id) {
            for session_id in session_ids {
                if let Some((_, session)) = self.active_sessions.remove(&session_id) {
                    self.revoke_token(&session.refresh_token_jti);
                }
            }
        }
    }

    /// Revoke a specific token by JTI
    pub fn revoke_token(&self, jti: &str) {
        self.revoked_tokens.insert(jti.to_string(), Instant::now());
        self.maybe_cleanup();
    }

    /// Check if a token JTI is revoked
    pub fn is_token_revoked(&self, jti: &str) -> bool {
        self.revoked_tokens.contains_key(jti)
    }

    /// Cleanup expired revocation records
    fn maybe_cleanup(&self) {
        let mut last = self.last_cleanup.write();
        if last.elapsed() > self.revocation_ttl / 2 {
            self.cleanup_expired_revocations();
            *last = Instant::now();
        }
    }

    /// Remove expired revocation records
    fn cleanup_expired_revocations(&self) {
        let now = Instant::now();
        self.revoked_tokens
            .retain(|_, revoked_at| now.duration_since(*revoked_at) < self.revocation_ttl);
    }

    /// Get active session count
    pub fn active_session_count(&self) -> usize {
        self.active_sessions.len()
    }

    /// Get revoked token count
    pub fn revoked_token_count(&self) -> usize {
        self.revoked_tokens.len()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        // Default TTL of 8 days (slightly longer than refresh token lifetime)
        Self::new(Duration::from_secs(8 * 24 * 60 * 60))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_get_session() {
        let manager = SessionManager::default();
        let user_id = Uuid::new_v4();

        let session_id = manager.create_session(
            user_id,
            "testuser".to_string(),
            "jti123".to_string(),
            Some("127.0.0.1".parse().unwrap()),
            Some("TestAgent".to_string()),
        );

        let session = manager.get_session(&session_id).unwrap();
        assert_eq!(session.user_id, user_id);
        assert_eq!(session.username, "testuser");
    }

    #[test]
    fn test_revoke_session() {
        let manager = SessionManager::default();
        let user_id = Uuid::new_v4();

        let session_id = manager.create_session(
            user_id,
            "testuser".to_string(),
            "jti456".to_string(),
            None,
            None,
        );

        assert!(manager.get_session(&session_id).is_some());
        assert!(manager.revoke_session(&session_id));
        assert!(manager.get_session(&session_id).is_none());
        assert!(manager.is_token_revoked("jti456"));
    }

    #[test]
    fn test_revoke_all_user_sessions() {
        let manager = SessionManager::default();
        let user_id = Uuid::new_v4();

        let _s1 = manager.create_session(
            user_id,
            "testuser".to_string(),
            "jti1".to_string(),
            None,
            None,
        );
        let _s2 = manager.create_session(
            user_id,
            "testuser".to_string(),
            "jti2".to_string(),
            None,
            None,
        );

        assert_eq!(manager.get_user_sessions(&user_id).len(), 2);

        manager.revoke_all_user_sessions(&user_id);

        assert_eq!(manager.get_user_sessions(&user_id).len(), 0);
        assert!(manager.is_token_revoked("jti1"));
        assert!(manager.is_token_revoked("jti2"));
    }
}

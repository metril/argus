//! Session management with persistent revocation.
//!
//! A session is the unit of login: both the access and the refresh JWT carry its id (`sid`), and
//! a request is only authenticated while that session exists. Revoking a session therefore kills
//! both tokens at once, and because sessions are written through to a sled tree, revocation (and
//! login state) survive a restart. Refresh tokens rotate: presenting an already-rotated refresh
//! token revokes the whole session (token theft detection).

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

/// Persisted session record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    pub user_id: Uuid,
    pub username: String,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub ip_address: Option<IpAddr>,
    pub user_agent: Option<String>,
    /// JTI of the refresh token currently valid for this session.
    pub refresh_token_jti: String,
    pub expires_at: DateTime<Utc>,
}

/// Outcome of presenting a refresh token.
#[derive(Debug, PartialEq, Eq)]
pub enum RotateOutcome {
    Rotated,
    /// An old (already rotated) refresh token was replayed; the session was revoked.
    Reused,
    Missing,
}

/// Active sessions, backed by an optional sled tree for persistence.
pub struct SessionManager {
    sessions: DashMap<Uuid, SessionData>,
    tree: Option<sled::Tree>,
}

impl SessionManager {
    /// Create a manager; with a tree, live sessions are loaded and every change is persisted.
    pub fn new(tree: Option<sled::Tree>) -> Self {
        let sessions = DashMap::new();
        if let Some(tree) = &tree {
            let now = Utc::now();
            for (k, v) in tree.iter().flatten() {
                let id = Uuid::from_slice(&k).ok();
                let data = serde_json::from_slice::<SessionData>(&v).ok();
                match (id, data) {
                    (Some(id), Some(d)) if d.expires_at > now => {
                        sessions.insert(id, d);
                    }
                    _ => {
                        let _ = tree.remove(&k);
                    }
                }
            }
        }
        Self { sessions, tree }
    }

    fn persist(&self, id: &Uuid) {
        if let (Some(tree), Some(s)) = (&self.tree, self.sessions.get(id)) {
            if let Ok(bytes) = serde_json::to_vec(&*s) {
                let _ = tree.insert(id.as_bytes(), bytes);
            }
        }
    }

    fn unpersist(&self, id: &Uuid) {
        if let Some(tree) = &self.tree {
            let _ = tree.remove(id.as_bytes());
        }
    }

    /// Register a session under a pre-generated id (the id is embedded in the JWTs).
    #[allow(clippy::too_many_arguments)]
    pub fn create_session(
        &self,
        id: Uuid,
        user_id: Uuid,
        username: String,
        refresh_token_jti: String,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
        ttl_secs: u64,
    ) {
        let now = Utc::now();
        self.sessions.insert(
            id,
            SessionData {
                user_id,
                username,
                created_at: now,
                last_activity: now,
                ip_address,
                user_agent,
                refresh_token_jti,
                expires_at: now + chrono::Duration::seconds(ttl_secs as i64),
            },
        );
        self.persist(&id);
    }

    /// The session if it exists and has not expired.
    pub fn get_session(&self, id: &Uuid) -> Option<SessionData> {
        let s = self.sessions.get(id)?;
        if s.expires_at <= Utc::now() {
            return None;
        }
        Some(s.clone())
    }

    /// Cheap liveness check used on every cookie-authenticated request.
    pub fn is_active(&self, id: &Uuid) -> bool {
        self.sessions
            .get(id)
            .is_some_and(|s| s.expires_at > Utc::now())
    }

    /// Record activity (in memory only).
    pub fn touch_session(&self, id: &Uuid) {
        if let Some(mut s) = self.sessions.get_mut(id) {
            s.last_activity = Utc::now();
        }
    }

    /// Swap the refresh JTI after a successful refresh, detecting replay of an old one.
    pub fn rotate(&self, id: &Uuid, presented_jti: &str, new_jti: String) -> RotateOutcome {
        let outcome = match self.sessions.get_mut(id) {
            None => return RotateOutcome::Missing,
            Some(mut s) if s.refresh_token_jti == presented_jti && s.expires_at > Utc::now() => {
                s.refresh_token_jti = new_jti;
                s.last_activity = Utc::now();
                RotateOutcome::Rotated
            }
            Some(_) => RotateOutcome::Reused,
        };
        match outcome {
            RotateOutcome::Rotated => self.persist(id),
            RotateOutcome::Reused => {
                self.revoke_session(id);
            }
            RotateOutcome::Missing => {}
        }
        outcome
    }

    /// Sessions of one user, newest first.
    pub fn get_user_sessions(&self, user_id: &Uuid) -> Vec<(Uuid, SessionData)> {
        let mut v: Vec<_> = self
            .sessions
            .iter()
            .filter(|e| e.user_id == *user_id && e.expires_at > Utc::now())
            .map(|e| (*e.key(), e.value().clone()))
            .collect();
        v.sort_by(|a, b| b.1.created_at.cmp(&a.1.created_at));
        v
    }

    /// Every live session, newest first.
    pub fn all_sessions(&self) -> Vec<(Uuid, SessionData)> {
        let mut v: Vec<_> = self
            .sessions
            .iter()
            .filter(|e| e.expires_at > Utc::now())
            .map(|e| (*e.key(), e.value().clone()))
            .collect();
        v.sort_by(|a, b| b.1.created_at.cmp(&a.1.created_at));
        v
    }

    /// Revoke one session (both its tokens stop working immediately).
    pub fn revoke_session(&self, id: &Uuid) -> bool {
        let removed = self.sessions.remove(id).is_some();
        if removed {
            self.unpersist(id);
        }
        removed
    }

    /// Revoke all of a user's sessions, optionally keeping one.
    pub fn revoke_user_sessions(&self, user_id: &Uuid, except: Option<&Uuid>) -> usize {
        let ids: Vec<Uuid> = self
            .sessions
            .iter()
            .filter(|e| e.user_id == *user_id && Some(e.key()) != except)
            .map(|e| *e.key())
            .collect();
        ids.iter().filter(|id| self.revoke_session(id)).count()
    }

    /// Drop expired sessions (called periodically).
    pub fn purge_expired(&self) {
        let now = Utc::now();
        let ids: Vec<Uuid> = self
            .sessions
            .iter()
            .filter(|e| e.expires_at <= now)
            .map(|e| *e.key())
            .collect();
        for id in ids {
            self.revoke_session(&id);
        }
    }

    pub fn active_session_count(&self) -> usize {
        self.sessions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(m: &SessionManager, user: Uuid, jti: &str) -> Uuid {
        let id = Uuid::new_v4();
        m.create_session(id, user, "u".into(), jti.into(), None, None, 3600);
        id
    }

    #[test]
    fn revoke_and_rotate() {
        let m = SessionManager::new(None);
        let user = Uuid::new_v4();
        let sid = make(&m, user, "j1");
        assert!(m.is_active(&sid));
        assert_eq!(m.rotate(&sid, "j1", "j2".into()), RotateOutcome::Rotated);
        // Replaying the rotated token revokes the session.
        assert_eq!(m.rotate(&sid, "j1", "j3".into()), RotateOutcome::Reused);
        assert!(!m.is_active(&sid));
        assert_eq!(m.rotate(&sid, "j2", "j4".into()), RotateOutcome::Missing);
    }

    #[test]
    fn revoke_user_sessions_keeps_exception() {
        let m = SessionManager::new(None);
        let user = Uuid::new_v4();
        let keep = make(&m, user, "a");
        make(&m, user, "b");
        assert_eq!(m.revoke_user_sessions(&user, Some(&keep)), 1);
        assert_eq!(m.get_user_sessions(&user).len(), 1);
    }

    #[test]
    fn sessions_and_revocations_survive_restart() {
        let dir = tempfile::tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        let tree = db.open_tree("sessions").unwrap();
        let user = Uuid::new_v4();
        let (live, dead) = {
            let m = SessionManager::new(Some(tree.clone()));
            let live = make(&m, user, "a");
            let dead = make(&m, user, "b");
            m.revoke_session(&dead);
            (live, dead)
        };
        let m2 = SessionManager::new(Some(tree));
        assert!(m2.is_active(&live));
        assert!(!m2.is_active(&dead));
    }
}

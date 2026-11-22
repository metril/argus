//! Session management with persistent revocation.
//!
//! A session is the unit of login: both the access and the refresh JWT carry its id (`sid`), and
//! a request is only authenticated while that session exists. Revoking a session therefore kills
//! both tokens at once, and because every change is committed to the database (fsync) before the
//! in-memory copy changes, revocation and login state survive a restart. Refresh tokens rotate:
//! presenting an already-rotated refresh token revokes the whole session (token theft detection);
//! the compare-and-swap of the refresh id and the revocation happen in one transaction.
//!
//! Durability: create / rotate / revoke / purge are `Immediate` and must be called from a
//! blocking context. Activity timestamps are written lazily (at most once a minute per session)
//! through the coalescing writer, and only update a session that still exists, so a late write
//! can never resurrect a revoked session.

use chrono::{DateTime, Utc};
use common::db::redb::{Durability, ReadableTable};
use common::db::{tables, Db, DbError};
use dashmap::DashMap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};

/// `last_activity` is persisted at most this often per session.
const TOUCH_INTERVAL_SECS: i64 = 60;

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

fn json<T: Serialize>(v: &T) -> ApiResult<Vec<u8>> {
    serde_json::to_vec(v).map_err(|e| ApiError::Internal(e.to_string()))
}

/// Active sessions: in-memory index over the database (the database is authoritative).
pub struct SessionManager {
    sessions: DashMap<Uuid, SessionData>,
    db: Arc<Db>,
    /// Serialises mutations so memory always follows the committed database state.
    write_lock: Mutex<()>,
    /// Unix seconds of the last queued activity write per session.
    touched: DashMap<Uuid, i64>,
}

impl SessionManager {
    /// Create a manager and load live sessions; expired ones are dropped in one transaction.
    pub fn new(db: Arc<Db>) -> ApiResult<Self> {
        let sessions = DashMap::new();
        let now = Utc::now();
        let dead = db.write::<_, ApiError>(Durability::Immediate, |t| {
            let mut tb = t.open_table(tables::SESSIONS).map_err(DbError::from)?;
            let mut dead = Vec::new();
            for item in tb.iter().map_err(DbError::from)? {
                let (k, v) = item.map_err(DbError::from)?;
                let id = Uuid::parse_str(k.value()).ok();
                match (id, serde_json::from_slice::<SessionData>(v.value())) {
                    (Some(id), Ok(d)) if d.expires_at > now => {
                        sessions.insert(id, d);
                    }
                    _ => dead.push(k.value().to_string()),
                }
            }
            for k in &dead {
                tb.remove(k.as_str()).map_err(DbError::from)?;
            }
            Ok(dead.len())
        })?;
        if dead > 0 {
            tracing::debug!("dropped {dead} expired sessions at startup");
        }
        Ok(Self {
            sessions,
            db,
            write_lock: Mutex::new(()),
            touched: DashMap::new(),
        })
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
    ) -> ApiResult<()> {
        let now = Utc::now();
        let data = SessionData {
            user_id,
            username,
            created_at: now,
            last_activity: now,
            ip_address,
            user_agent,
            refresh_token_jti,
            expires_at: now + chrono::Duration::seconds(ttl_secs as i64),
        };
        let bytes = json(&data)?;
        let _g = self.write_lock.lock();
        self.db.write::<_, ApiError>(Durability::Immediate, |t| {
            t.open_table(tables::SESSIONS)
                .map_err(DbError::from)?
                .insert(id.to_string().as_str(), bytes.as_slice())
                .map_err(DbError::from)?;
            Ok(())
        })?;
        self.sessions.insert(id, data);
        Ok(())
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

    /// Record activity: in memory at once, on disk at most once a minute (coalesced, no fsync,
    /// never on the caller's thread, and only if the session still exists).
    pub fn touch_session(&self, id: &Uuid) {
        let now = Utc::now();
        match self.sessions.get_mut(id) {
            Some(mut s) => s.last_activity = now,
            None => return,
        }
        let ts = now.timestamp();
        let due = {
            let mut e = self.touched.entry(*id).or_insert(0);
            let due = ts - *e >= TOUCH_INTERVAL_SECS;
            if due {
                *e = ts;
            }
            due
        };
        if !due {
            return;
        }
        let key = id.to_string();
        self.db.defer(move |t| {
            let mut tb = t.open_table(tables::SESSIONS)?;
            let cur = tb.get(key.as_str())?.map(|g| g.value().to_vec());
            if let Some(mut s) = cur.and_then(|b| serde_json::from_slice::<SessionData>(&b).ok()) {
                s.last_activity = now;
                if let Ok(b) = serde_json::to_vec(&s) {
                    tb.insert(key.as_str(), b.as_slice())?;
                }
            }
            Ok(())
        });
    }

    /// Swap the refresh JTI after a successful refresh, detecting replay of an old one. The
    /// check-and-swap (or the revocation on replay) is a single transaction.
    pub fn rotate(
        &self,
        id: &Uuid,
        presented_jti: &str,
        new_jti: String,
    ) -> ApiResult<RotateOutcome> {
        let _g = self.write_lock.lock();
        let key = id.to_string();
        let now = Utc::now();
        let (outcome, updated) = self.db.write::<_, ApiError>(Durability::Immediate, |t| {
            let mut tb = t.open_table(tables::SESSIONS).map_err(DbError::from)?;
            let cur = tb
                .get(key.as_str())
                .map_err(DbError::from)?
                .map(|g| g.value().to_vec());
            let Some(cur) = cur else {
                return Ok((RotateOutcome::Missing, None));
            };
            let mut s: SessionData =
                serde_json::from_slice(&cur).map_err(|e| ApiError::Internal(e.to_string()))?;
            if s.refresh_token_jti == presented_jti && s.expires_at > now {
                s.refresh_token_jti = new_jti;
                s.last_activity = now;
                tb.insert(key.as_str(), json(&s)?.as_slice())
                    .map_err(DbError::from)?;
                Ok((RotateOutcome::Rotated, Some(s)))
            } else {
                tb.remove(key.as_str()).map_err(DbError::from)?;
                Ok((RotateOutcome::Reused, None))
            }
        })?;
        match (&outcome, updated) {
            (RotateOutcome::Rotated, Some(s)) => {
                self.sessions.insert(*id, s);
            }
            _ => {
                self.sessions.remove(id);
                self.touched.remove(id);
            }
        }
        Ok(outcome)
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

    /// Remove `ids` in one transaction, then from memory. Returns how many existed.
    fn remove_many(&self, ids: &[Uuid]) -> ApiResult<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        let _g = self.write_lock.lock();
        self.db.write::<_, ApiError>(Durability::Immediate, |t| {
            let mut tb = t.open_table(tables::SESSIONS).map_err(DbError::from)?;
            for id in ids {
                tb.remove(id.to_string().as_str()).map_err(DbError::from)?;
            }
            Ok(())
        })?;
        let n = ids
            .iter()
            .filter(|id| {
                self.touched.remove(*id);
                self.sessions.remove(*id).is_some()
            })
            .count();
        Ok(n)
    }

    /// Revoke one session (both its tokens stop working immediately).
    pub fn revoke_session(&self, id: &Uuid) -> ApiResult<bool> {
        Ok(self.remove_many(&[*id])? > 0)
    }

    /// Revoke all of a user's sessions, optionally keeping one (single transaction).
    pub fn revoke_user_sessions(&self, user_id: &Uuid, except: Option<&Uuid>) -> ApiResult<usize> {
        let ids: Vec<Uuid> = self
            .sessions
            .iter()
            .filter(|e| e.user_id == *user_id && Some(e.key()) != except)
            .map(|e| *e.key())
            .collect();
        self.remove_many(&ids)
    }

    /// Drop expired sessions (called periodically).
    pub fn purge_expired(&self) -> ApiResult<usize> {
        let now = Utc::now();
        let ids: Vec<Uuid> = self
            .sessions
            .iter()
            .filter(|e| e.expires_at <= now)
            .map(|e| *e.key())
            .collect();
        self.remove_many(&ids)
    }

    pub fn active_session_count(&self) -> usize {
        self.sessions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mgr() -> (SessionManager, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let m = SessionManager::new(Db::open(dir.path()).unwrap()).unwrap();
        (m, dir)
    }

    fn make(m: &SessionManager, user: Uuid, jti: &str) -> Uuid {
        let id = Uuid::new_v4();
        m.create_session(id, user, "u".into(), jti.into(), None, None, 3600)
            .unwrap();
        id
    }

    #[test]
    fn revoke_and_rotate() {
        let (m, _d) = mgr();
        let user = Uuid::new_v4();
        let sid = make(&m, user, "j1");
        assert!(m.is_active(&sid));
        assert_eq!(
            m.rotate(&sid, "j1", "j2".into()).unwrap(),
            RotateOutcome::Rotated
        );
        // Replaying the rotated token revokes the session.
        assert_eq!(
            m.rotate(&sid, "j1", "j3".into()).unwrap(),
            RotateOutcome::Reused
        );
        assert!(!m.is_active(&sid));
        assert_eq!(
            m.rotate(&sid, "j2", "j4".into()).unwrap(),
            RotateOutcome::Missing
        );
    }

    #[test]
    fn replay_revocation_is_durable() {
        let dir = tempfile::tempdir().unwrap();
        let sid = {
            let m = SessionManager::new(Db::open(dir.path()).unwrap()).unwrap();
            let sid = make(&m, Uuid::new_v4(), "j1");
            m.rotate(&sid, "j1", "j2".into()).unwrap();
            assert_eq!(
                m.rotate(&sid, "j1", "j3".into()).unwrap(),
                RotateOutcome::Reused
            );
            sid
        };
        let m2 = SessionManager::new(Db::open(dir.path()).unwrap()).unwrap();
        assert!(!m2.is_active(&sid));
    }

    #[test]
    fn concurrent_rotation_with_same_token_lets_one_win() {
        let (m, _d) = mgr();
        let m = Arc::new(m);
        let sid = make(&m, Uuid::new_v4(), "j1");
        let outcomes: Vec<_> = (0..4)
            .map(|i| {
                let m = m.clone();
                std::thread::spawn(move || m.rotate(&sid, "j1", format!("n{i}")).unwrap())
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect();
        assert_eq!(
            outcomes
                .iter()
                .filter(|o| **o == RotateOutcome::Rotated)
                .count(),
            1
        );
        // The losers saw a replay, which killed the session.
        assert!(!m.is_active(&sid));
    }

    #[test]
    fn revoke_user_sessions_keeps_exception() {
        let (m, _d) = mgr();
        let user = Uuid::new_v4();
        let keep = make(&m, user, "a");
        make(&m, user, "b");
        assert_eq!(m.revoke_user_sessions(&user, Some(&keep)).unwrap(), 1);
        assert_eq!(m.get_user_sessions(&user).len(), 1);
    }

    #[test]
    fn sessions_and_revocations_survive_restart() {
        let dir = tempfile::tempdir().unwrap();
        let user = Uuid::new_v4();
        let (live, dead) = {
            let m = SessionManager::new(Db::open(dir.path()).unwrap()).unwrap();
            let live = make(&m, user, "a");
            let dead = make(&m, user, "b");
            m.revoke_session(&dead).unwrap();
            (live, dead)
        };
        let m2 = SessionManager::new(Db::open(dir.path()).unwrap()).unwrap();
        assert!(m2.is_active(&live));
        assert!(!m2.is_active(&dead));
    }

    #[test]
    fn expired_sessions_are_purged_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let m = SessionManager::new(Db::open(dir.path()).unwrap()).unwrap();
        let id = Uuid::new_v4();
        m.create_session(id, Uuid::new_v4(), "u".into(), "j".into(), None, None, 0)
            .unwrap();
        assert_eq!(m.purge_expired().unwrap(), 1);
        drop(m);
        let m2 = SessionManager::new(Db::open(dir.path()).unwrap()).unwrap();
        assert_eq!(m2.active_session_count(), 0);
    }

    #[test]
    fn late_activity_write_cannot_resurrect_a_revoked_session() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(dir.path()).unwrap();
        let m = SessionManager::new(db.clone()).unwrap();
        let sid = make(&m, Uuid::new_v4(), "j");
        m.touch_session(&sid); // queues an activity write
        m.revoke_session(&sid).unwrap();
        db.flush_deferred();
        drop(m);
        let m2 = SessionManager::new(db).unwrap();
        assert!(!m2.is_active(&sid));
    }
}

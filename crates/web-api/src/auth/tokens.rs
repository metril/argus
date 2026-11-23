//! Personal access tokens: `abk_<id>_<secret>`.
//!
//! The 256-bit secret is shown once; only its BLAKE3 digest is stored (a fast hash is sound for
//! high-entropy secrets, and keeps bcrypt off the request path). Verification is a map lookup by
//! id, one hash and a constant-time compare. All tokens are cached in memory; create and revoke
//! commit to the database (fsync, call from a blocking context) and then update the cache, so
//! revocation takes effect on the very next request and survives a crash. `last_used_at` is
//! written lazily through the coalescing writer, as a read-modify-write inside the transaction
//! that only touches an existing row, so it can neither lose nor undo a revocation.

use api_types::{ApiTokenInfo, Scope};
use chrono::{DateTime, Utc};
use common::db::redb::{Durability, ReadableTable};
use common::db::{tables, Db, DbError};
use dashmap::DashMap;
use parking_lot::Mutex;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};

pub const TOKEN_PREFIX: &str = "abk";
/// `last_used_at` is persisted at most this often per token.
const LAST_USED_INTERVAL_SECS: i64 = 60;

/// Persisted token record (never contains the secret).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredToken {
    pub id: String,
    pub name: String,
    pub scopes: Vec<Scope>,
    pub profiles: Option<Vec<String>>,
    /// Hex BLAKE3 digest of the full secret string.
    pub digest: String,
    pub created_by: Uuid,
    pub created_by_name: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// In-memory view of a token.
pub struct CachedToken {
    pub stored: StoredToken,
    digest: blake3::Hash,
    /// Unix seconds of the last use seen in memory (0 = never).
    last_used: AtomicI64,
    /// Unix seconds of the last time `last_used_at` was written to disk.
    last_persisted: AtomicI64,
}

impl CachedToken {
    fn new(stored: StoredToken) -> Self {
        let digest = blake3::Hash::from_hex(&stored.digest).unwrap_or(blake3::Hash::from([0; 32]));
        let last = stored.last_used_at.map(|t| t.timestamp()).unwrap_or(0);
        Self {
            stored,
            digest,
            last_used: AtomicI64::new(last),
            last_persisted: AtomicI64::new(last),
        }
    }

    pub fn info(&self) -> ApiTokenInfo {
        let s = &self.stored;
        let used = self.last_used.load(Ordering::Relaxed);
        ApiTokenInfo {
            id: s.id.clone(),
            name: s.name.clone(),
            scopes: s.scopes.clone(),
            profiles: s.profiles.clone(),
            created_by: s.created_by.to_string(),
            created_by_name: s.created_by_name.clone(),
            created_at: s.created_at.to_rfc3339(),
            expires_at: s.expires_at.map(|t| t.to_rfc3339()),
            last_used_at: DateTime::from_timestamp(used, 0)
                .filter(|_| used > 0)
                .map(|t| t.to_rfc3339()),
            revoked: s.revoked_at.is_some(),
        }
    }
}

/// Why a presented token was rejected.
#[derive(Debug, PartialEq, Eq)]
pub enum TokenReject {
    Malformed,
    Unknown,
    Revoked,
    Expired,
}

pub struct TokenStore {
    db: Arc<Db>,
    cache: DashMap<String, Arc<CachedToken>>,
    /// Serialises mutations so the cache always follows the committed database state.
    write_lock: Mutex<()>,
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn digest_of(secret: &str) -> blake3::Hash {
    blake3::hash(secret.as_bytes())
}

fn json(t: &StoredToken) -> ApiResult<Vec<u8>> {
    serde_json::to_vec(t).map_err(|e| ApiError::Internal(e.to_string()))
}

impl TokenStore {
    /// Load every stored token into the in-memory cache.
    pub fn new(db: Arc<Db>) -> ApiResult<Self> {
        let cache = DashMap::new();
        db.read::<_, ApiError>(|r| {
            let t = r.open_table(tables::API_TOKENS).map_err(DbError::from)?;
            for item in t.iter().map_err(DbError::from)? {
                let (_, v) = item.map_err(DbError::from)?;
                if let Ok(t) = serde_json::from_slice::<StoredToken>(v.value()) {
                    cache.insert(t.id.clone(), Arc::new(CachedToken::new(t)));
                }
            }
            Ok(())
        })?;
        Ok(Self {
            db,
            cache,
            write_lock: Mutex::new(()),
        })
    }

    /// Mint a token; returns its metadata and the one-time secret string.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        &self,
        name: String,
        scopes: Vec<Scope>,
        profiles: Option<Vec<String>>,
        created_by: Uuid,
        created_by_name: String,
        expires_at: Option<DateTime<Utc>>,
    ) -> ApiResult<(ApiTokenInfo, String)> {
        let id = random_hex(8);
        let secret = random_hex(32); // 256 bits
        let full = format!("{TOKEN_PREFIX}_{id}_{secret}");
        let stored = StoredToken {
            id: id.clone(),
            name,
            scopes,
            profiles,
            digest: digest_of(&full).to_hex().to_string(),
            created_by,
            created_by_name,
            created_at: Utc::now(),
            expires_at,
            last_used_at: None,
            revoked_at: None,
        };
        let bytes = json(&stored)?;
        let _g = self.write_lock.lock();
        self.db.write::<_, ApiError>(Durability::Immediate, |t| {
            t.open_table(tables::API_TOKENS)
                .map_err(DbError::from)?
                .insert(id.as_str(), bytes.as_slice())
                .map_err(DbError::from)?;
            Ok(())
        })?;
        let cached = Arc::new(CachedToken::new(stored));
        let info = cached.info();
        self.cache.insert(id, cached);
        Ok((info, full))
    }

    /// Whether token `id` still exists and is neither revoked nor expired (for long-lived
    /// streams that must stop when their token is revoked).
    pub fn is_live(&self, id: &str) -> bool {
        self.cache.get(id).is_some_and(|e| {
            e.stored.revoked_at.is_none() && e.stored.expires_at.is_none_or(|t| t > Utc::now())
        })
    }

    /// Check a presented `abk_<id>_<secret>` string.
    pub fn verify(&self, presented: &str) -> Result<Arc<CachedToken>, TokenReject> {
        let mut parts = presented.splitn(3, '_');
        let (prefix, id, secret) = (parts.next(), parts.next(), parts.next());
        let (Some(TOKEN_PREFIX), Some(id), Some(secret)) = (prefix, id, secret) else {
            return Err(TokenReject::Malformed);
        };
        if secret.is_empty() {
            return Err(TokenReject::Malformed);
        }
        let entry = self
            .cache
            .get(id)
            .map(|e| e.clone())
            .ok_or(TokenReject::Unknown)?;
        // `blake3::Hash` equality is constant-time.
        if digest_of(presented) != entry.digest {
            return Err(TokenReject::Unknown);
        }
        if entry.stored.revoked_at.is_some() {
            return Err(TokenReject::Revoked);
        }
        if entry.stored.expires_at.is_some_and(|t| t <= Utc::now()) {
            return Err(TokenReject::Expired);
        }
        Ok(entry)
    }

    /// Note a use. The disk write happens at most once a minute per token, coalesced with
    /// other deferred writes, and never on the caller's thread.
    pub fn mark_used(&self, token: &Arc<CachedToken>) {
        let now = Utc::now().timestamp();
        token.last_used.store(now, Ordering::Relaxed);
        let last = token.last_persisted.load(Ordering::Relaxed);
        if now - last < LAST_USED_INTERVAL_SECS
            || token
                .last_persisted
                .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
                .is_err()
        {
            return;
        }
        let id = token.stored.id.clone();
        self.db.defer(move |t| {
            let mut tb = t.open_table(tables::API_TOKENS)?;
            let cur = tb.get(id.as_str())?.map(|g| g.value().to_vec());
            if let Some(mut s) = cur.and_then(|b| serde_json::from_slice::<StoredToken>(&b).ok()) {
                s.last_used_at = DateTime::from_timestamp(now, 0);
                if let Ok(b) = serde_json::to_vec(&s) {
                    tb.insert(id.as_str(), b.as_slice())?;
                }
            }
            Ok(())
        });
    }

    pub fn get(&self, id: &str) -> Option<Arc<CachedToken>> {
        self.cache.get(id).map(|e| e.clone())
    }

    /// Tokens (including revoked ones), newest first, optionally only one creator's.
    pub fn list(&self, created_by: Option<&Uuid>) -> Vec<ApiTokenInfo> {
        let mut v: Vec<_> = self
            .cache
            .iter()
            .filter(|e| created_by.is_none_or(|u| e.stored.created_by == *u))
            .map(|e| (e.stored.created_at, e.info()))
            .collect();
        v.sort_by(|a, b| b.0.cmp(&a.0));
        v.into_iter().map(|(_, i)| i).collect()
    }

    /// Revoke `ids` in one transaction, then in the cache. Returns the revoked count.
    fn revoke_many(&self, ids: &[String]) -> ApiResult<usize> {
        let _g = self.write_lock.lock();
        let now = Utc::now();
        let updated: Vec<StoredToken> = ids
            .iter()
            .filter_map(|id| self.get(id))
            .filter(|c| c.stored.revoked_at.is_none())
            .map(|c| {
                let mut s = c.stored.clone();
                s.revoked_at = Some(now);
                s.last_used_at = DateTime::from_timestamp(c.last_used.load(Ordering::Relaxed), 0)
                    .filter(|t| t.timestamp() > 0);
                s
            })
            .collect();
        if updated.is_empty() {
            return Ok(0);
        }
        self.db.write::<_, ApiError>(Durability::Immediate, |t| {
            let mut tb = t.open_table(tables::API_TOKENS).map_err(DbError::from)?;
            for s in &updated {
                tb.insert(s.id.as_str(), json(s)?.as_slice())
                    .map_err(DbError::from)?;
            }
            Ok(())
        })?;
        let n = updated.len();
        for s in updated {
            self.cache
                .insert(s.id.clone(), Arc::new(CachedToken::new(s)));
        }
        Ok(n)
    }

    /// Revoke a token; effective for the next request. Returns false if unknown.
    pub fn revoke(&self, id: &str) -> ApiResult<bool> {
        if self.get(id).is_none() {
            return Ok(false);
        }
        self.revoke_many(&[id.to_string()])?;
        Ok(true)
    }

    /// Revoke every token created by a user (account deleted), atomically.
    pub fn revoke_all_for_user(&self, user: &Uuid) -> ApiResult<usize> {
        let ids: Vec<String> = self
            .cache
            .iter()
            .filter(|e| e.stored.created_by == *user && e.stored.revoked_at.is_none())
            .map(|e| e.key().clone())
            .collect();
        self.revoke_many(&ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (TokenStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let s = TokenStore::new(Db::open(dir.path()).unwrap()).unwrap();
        (s, dir)
    }

    fn make(store: &TokenStore) -> (ApiTokenInfo, String) {
        store
            .create(
                "t".into(),
                vec![Scope::ListsRead],
                None,
                Uuid::new_v4(),
                "u".into(),
                None,
            )
            .unwrap()
    }

    #[test]
    fn verify_and_revoke_immediately() {
        let (store, _d) = store();
        let (info, secret) = make(&store);
        assert!(secret.starts_with("abk_") && secret.len() > 80);
        assert!(store.verify(&secret).is_ok());
        assert_eq!(
            store.verify(&format!("{secret}x")).err(),
            Some(TokenReject::Unknown)
        );
        assert_eq!(store.verify("abk_nope").err(), Some(TokenReject::Malformed));
        store.revoke(&info.id).unwrap();
        assert_eq!(store.verify(&secret).err(), Some(TokenReject::Revoked));
        assert!(!store.revoke("missing").unwrap());
    }

    #[test]
    fn expired_token_rejected_and_secret_not_stored() {
        let (store, _d) = store();
        let (_, secret) = store
            .create(
                "t".into(),
                vec![Scope::ListsRead],
                None,
                Uuid::new_v4(),
                "u".into(),
                Some(Utc::now() - chrono::Duration::seconds(1)),
            )
            .unwrap();
        assert_eq!(store.verify(&secret).err(), Some(TokenReject::Expired));
        let json = serde_json::to_string(&store.list(None)).unwrap();
        assert!(!json.contains(&secret));
    }

    #[test]
    fn tokens_persist_across_restart() {
        let dir = tempfile::tempdir().unwrap();
        let (id, secret) = {
            let s = TokenStore::new(Db::open(dir.path()).unwrap()).unwrap();
            let (i, sec) = make(&s);
            (i.id, sec)
        };
        let s2 = TokenStore::new(Db::open(dir.path()).unwrap()).unwrap();
        assert!(s2.verify(&secret).is_ok());
        s2.revoke(&id).unwrap();
        drop(s2);
        let s3 = TokenStore::new(Db::open(dir.path()).unwrap()).unwrap();
        assert_eq!(s3.verify(&secret).err(), Some(TokenReject::Revoked));
    }

    #[test]
    fn revoke_all_for_user_is_one_transaction_and_visible_at_once() {
        let (store, dir) = store();
        let user = Uuid::new_v4();
        let secrets: Vec<_> = (0..3)
            .map(|_| {
                store
                    .create(
                        "t".into(),
                        vec![Scope::ListsRead],
                        None,
                        user,
                        "u".into(),
                        None,
                    )
                    .unwrap()
                    .1
            })
            .collect();
        let other = make(&store).1;
        assert_eq!(store.revoke_all_for_user(&user).unwrap(), 3);
        for s in &secrets {
            assert_eq!(store.verify(s).err(), Some(TokenReject::Revoked));
        }
        assert!(store.verify(&other).is_ok());
        // Durable: a fresh store from disk agrees.
        drop(store);
        let again = TokenStore::new(Db::open(dir.path()).unwrap()).unwrap();
        assert_eq!(again.verify(&secrets[0]).err(), Some(TokenReject::Revoked));
        assert!(again.verify(&other).is_ok());
    }

    #[test]
    fn last_used_is_coalesced_and_never_undoes_revocation() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(dir.path()).unwrap();
        let s = TokenStore::new(db.clone()).unwrap();
        let (info, secret) = make(&s);
        let cached = s.verify(&secret).unwrap();
        s.mark_used(&cached); // queues a deferred write
        s.revoke(&info.id).unwrap();
        db.flush_deferred();
        drop(s);
        let s2 = TokenStore::new(db).unwrap();
        assert_eq!(s2.verify(&secret).err(), Some(TokenReject::Revoked));
        assert!(s2.get(&info.id).unwrap().stored.last_used_at.is_some());
    }
}

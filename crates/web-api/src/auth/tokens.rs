//! Personal access tokens: `abk_<id>_<secret>`.
//!
//! The 256-bit secret is shown once; only its BLAKE3 digest is stored (a fast hash is sound for
//! high-entropy secrets, and keeps bcrypt off the request path). Verification is a map lookup by
//! id, one hash and a constant-time compare. All tokens are cached in memory and writes go
//! through the cache first, so revocation takes effect on the very next request.

use api_types::{ApiTokenInfo, Scope};
use chrono::{DateTime, Utc};
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
    tree: Option<sled::Tree>,
    cache: DashMap<String, Arc<CachedToken>>,
    /// Serialises writes so a background `last_used_at` flush cannot overwrite a revocation.
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

impl TokenStore {
    pub fn new(tree: Option<sled::Tree>) -> Self {
        let cache = DashMap::new();
        if let Some(tree) = &tree {
            for (_, v) in tree.iter().flatten() {
                if let Ok(t) = serde_json::from_slice::<StoredToken>(&v) {
                    cache.insert(t.id.clone(), Arc::new(CachedToken::new(t)));
                }
            }
        }
        Self {
            tree,
            cache,
            write_lock: Mutex::new(()),
        }
    }

    fn write(&self, t: &StoredToken) -> ApiResult<()> {
        if let Some(tree) = &self.tree {
            tree.insert(
                t.id.as_bytes(),
                serde_json::to_vec(t).map_err(|e| ApiError::Internal(e.to_string()))?,
            )?;
        }
        Ok(())
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
        let _g = self.write_lock.lock();
        self.write(&stored)?;
        let cached = Arc::new(CachedToken::new(stored));
        let info = cached.info();
        self.cache.insert(id, cached);
        Ok((info, full))
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

    /// Note a use. The disk write happens at most once a minute per token and off the request
    /// path (blocking pool).
    pub fn mark_used(self: &Arc<Self>, token: &Arc<CachedToken>) {
        let now = Utc::now().timestamp();
        token.last_used.store(now, Ordering::Relaxed);
        let last = token.last_persisted.load(Ordering::Relaxed);
        if self.tree.is_none()
            || now - last < LAST_USED_INTERVAL_SECS
            || token
                .last_persisted
                .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
                .is_err()
        {
            return;
        }
        let this = self.clone();
        let id = token.stored.id.clone();
        let flush = move || {
            let _g = this.write_lock.lock();
            if let Some(cur) = this.cache.get(&id) {
                let mut s = cur.stored.clone();
                s.last_used_at = DateTime::from_timestamp(now, 0);
                let _ = this.write(&s);
            }
        };
        match tokio::runtime::Handle::try_current() {
            Ok(h) => {
                h.spawn_blocking(flush);
            }
            Err(_) => flush(),
        }
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

    /// Revoke a token; effective for the next request. Returns false if unknown.
    pub fn revoke(&self, id: &str) -> ApiResult<bool> {
        let _g = self.write_lock.lock();
        let Some(cur) = self.get(id) else {
            return Ok(false);
        };
        if cur.stored.revoked_at.is_some() {
            return Ok(true);
        }
        let mut s = cur.stored.clone();
        s.revoked_at = Some(Utc::now());
        s.last_used_at = DateTime::from_timestamp(cur.last_used.load(Ordering::Relaxed), 0)
            .filter(|t| t.timestamp() > 0);
        self.write(&s)?;
        self.cache
            .insert(id.to_string(), Arc::new(CachedToken::new(s)));
        Ok(true)
    }

    /// Revoke every token created by a user (account deleted).
    pub fn revoke_all_for_user(&self, user: &Uuid) -> ApiResult<usize> {
        let ids: Vec<String> = self
            .cache
            .iter()
            .filter(|e| e.stored.created_by == *user && e.stored.revoked_at.is_none())
            .map(|e| e.key().clone())
            .collect();
        for id in &ids {
            self.revoke(id)?;
        }
        Ok(ids.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let store = TokenStore::new(None);
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
    }

    #[test]
    fn expired_token_rejected_and_secret_not_stored() {
        let store = TokenStore::new(None);
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
        let tree = sled::open(dir.path()).unwrap().open_tree("t").unwrap();
        let (id, secret) = {
            let s = TokenStore::new(Some(tree.clone()));
            let (i, sec) = make(&s);
            (i.id, sec)
        };
        let s2 = TokenStore::new(Some(tree));
        assert!(s2.verify(&secret).is_ok());
        s2.revoke(&id).unwrap();
        let s3 = TokenStore::new(s2.tree.clone());
        assert_eq!(s3.verify(&secret).err(), Some(TokenReject::Revoked));
    }
}

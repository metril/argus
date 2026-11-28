//! Personal access tokens: `abk_<id>_<secret>`.
//!
//! The 256-bit secret is shown once; only its BLAKE3 digest is stored (a fast hash is sound for
//! high-entropy secrets, and keeps bcrypt off the request path). Verification is a map lookup by
//! id, one hash and a constant-time compare. All tokens are cached in memory; create and revoke
//! commit to the database (fsync, call from a blocking context) and then update the cache, so
//! revocation takes effect on the very next request and survives a crash. `last_used_at` is
//! written lazily through the coalescing writer, as a read-modify-write inside the transaction
//! that only touches an existing row, so it can neither lose nor undo a revocation.

use api_types::{ApiTokenInfo, Scope, TokenPurpose};
use chrono::{DateTime, Utc};
use common::db::redb::{Durability, ReadableTable};
use common::db::{tables, Db, DbError};
use dashmap::DashMap;
use parking_lot::Mutex;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
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
    #[serde(default)]
    pub purpose: TokenPurpose,
    /// Non-secret display form: prefix, id and the last four characters.
    #[serde(default)]
    pub secret_hint: String,
    /// Digest of the secret before the last regeneration; accepted until `prev_valid_until`.
    #[serde(default)]
    pub prev_digest: Option<String>,
    #[serde(default)]
    pub prev_valid_until: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_used_addr: Option<String>,
    #[serde(default)]
    pub updated_at: Option<DateTime<Utc>>,
    /// Scope names this release does not know (written by a newer one). Kept verbatim, ignored
    /// for authorisation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unknown_scopes: Vec<String>,
}

/// Parse a stored record, keeping scope names this release does not know in `unknown_scopes`
/// instead of failing the whole record.
fn parse_stored(bytes: &[u8]) -> Result<StoredToken, serde_json::Error> {
    let mut v: serde_json::Value = serde_json::from_slice(bytes)?;
    let mut unknown: Vec<String> = Vec::new();
    if let Some(arr) = v.get_mut("scopes").and_then(|s| s.as_array_mut()) {
        arr.retain(|s| match s.as_str() {
            Some(n) if n.parse::<Scope>().is_err() => {
                unknown.push(n.to_string());
                false
            }
            _ => true,
        });
    }
    let mut t: StoredToken = serde_json::from_value(v)?;
    for u in unknown {
        if !t.unknown_scopes.contains(&u) {
            t.unknown_scopes.push(u);
        }
    }
    // A scope kept as unknown by an earlier release may be known now: grant it again.
    let names = std::mem::take(&mut t.unknown_scopes);
    for n in names {
        match n.parse::<Scope>() {
            Ok(s) => {
                if !t.scopes.contains(&s) {
                    t.scopes.push(s);
                }
            }
            Err(_) => t.unknown_scopes.push(n),
        }
    }
    Ok(t)
}

fn expired_conflict(msg: &'static str) -> ApiError {
    ApiError::coded(axum::http::StatusCode::CONFLICT, "token_expired", msg)
}

/// Changes to apply with [`TokenStore::update`]; `None` leaves a field as it is.
#[derive(Debug, Default)]
pub struct TokenUpdate {
    pub name: Option<String>,
    pub scopes: Option<Vec<Scope>>,
    /// `Some(None)` removes the restriction.
    pub profiles: Option<Option<Vec<String>>>,
    pub purpose: Option<TokenPurpose>,
    /// `Some(None)` removes the expiry.
    pub expires_at: Option<Option<DateTime<Utc>>>,
}

/// In-memory view of a token.
pub struct CachedToken {
    pub stored: StoredToken,
    digest: blake3::Hash,
    prev_digest: Option<blake3::Hash>,
    /// Unix seconds of the last use seen in memory (0 = never).
    last_used: AtomicI64,
    /// Unix seconds of the last time `last_used_at` was written to disk.
    last_persisted: AtomicI64,
    /// Address of the last use seen in memory.
    last_addr: Mutex<Option<String>>,
}

impl CachedToken {
    fn new(stored: StoredToken) -> Self {
        let digest = blake3::Hash::from_hex(&stored.digest).unwrap_or(blake3::Hash::from([0; 32]));
        let prev_digest = stored
            .prev_digest
            .as_deref()
            .and_then(|h| blake3::Hash::from_hex(h).ok());
        let last = stored.last_used_at.map(|t| t.timestamp()).unwrap_or(0);
        let addr = stored.last_used_addr.clone();
        Self {
            stored,
            digest,
            prev_digest,
            last_used: AtomicI64::new(last),
            last_persisted: AtomicI64::new(last),
            last_addr: Mutex::new(addr),
        }
    }

    /// The stored record with the in-memory last-use facts folded in.
    fn snapshot(&self) -> StoredToken {
        let mut s = self.stored.clone();
        s.last_used_at = DateTime::from_timestamp(self.last_used.load(Ordering::Relaxed), 0)
            .filter(|t| t.timestamp() > 0);
        s.last_used_addr = self.last_addr.lock().clone();
        s
    }

    /// A new cached entry for `stored` that keeps this one's last-use facts.
    fn successor(&self, mut stored: StoredToken) -> CachedToken {
        let snap = self.snapshot();
        stored.last_used_at = snap.last_used_at;
        stored.last_used_addr = snap.last_used_addr;
        let next = CachedToken::new(stored);
        next.last_persisted.store(
            self.last_persisted.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        next
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
            unknown_scopes: s.unknown_scopes.clone(),
            purpose: s.purpose,
            secret_hint: if s.secret_hint.is_empty() {
                format!("{TOKEN_PREFIX}_{}_…", s.id)
            } else {
                s.secret_hint.clone()
            },
            last_used_addr: self.last_addr.lock().clone(),
            updated_at: s.updated_at.map(|t| t.to_rfc3339()),
            prev_valid_until: s
                .prev_valid_until
                .filter(|t| s.prev_digest.is_some() && *t > Utc::now())
                .map(|t| t.to_rfc3339()),
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

/// Display form of a secret: prefix, id and the last four characters.
fn hint_of(id: &str, full: &str) -> String {
    let tail: String = full
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{TOKEN_PREFIX}_{id}_…{tail}")
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
                let (key, v) = item.map_err(DbError::from)?;
                match parse_stored(v.value()) {
                    Ok(t) => {
                        cache.insert(t.id.clone(), Arc::new(CachedToken::new(t)));
                    }
                    Err(e) => {
                        tracing::warn!("Skipping unreadable API token record {}: {e}", key.value())
                    }
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
        purpose: TokenPurpose,
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
            purpose,
            secret_hint: hint_of(&id, &full),
            prev_digest: None,
            prev_valid_until: None,
            last_used_addr: None,
            updated_at: None,
            unknown_scopes: Vec::new(),
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
        self.verify_at(presented, Utc::now())
    }

    /// [`verify`](Self::verify) at an explicit time (the clock is injectable for tests).
    pub fn verify_at(
        &self,
        presented: &str,
        now: DateTime<Utc>,
    ) -> Result<Arc<CachedToken>, TokenReject> {
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
        let given = digest_of(presented);
        let current = given == entry.digest;
        // The previous secret keeps working until its grace time ends.
        let previous = entry.prev_digest.is_some_and(|p| given == p)
            && entry.stored.prev_valid_until.is_some_and(|t| t > now);
        if !(current | previous) {
            return Err(TokenReject::Unknown);
        }
        if entry.stored.revoked_at.is_some() {
            return Err(TokenReject::Revoked);
        }
        if entry.stored.expires_at.is_some_and(|t| t <= now) {
            return Err(TokenReject::Expired);
        }
        Ok(entry)
    }

    /// Note a use. The disk write happens at most once a minute per token, coalesced with
    /// other deferred writes, and never on the caller's thread.
    pub fn mark_used(&self, token: &Arc<CachedToken>, addr: Option<IpAddr>) {
        let now = Utc::now().timestamp();
        token.last_used.store(now, Ordering::Relaxed);
        let addr = addr.map(|a| a.to_string());
        if addr.is_some() {
            *token.last_addr.lock() = addr.clone();
        }
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
            if let Some(mut s) = cur.and_then(|b| parse_stored(&b).ok()) {
                s.last_used_at = DateTime::from_timestamp(now, 0);
                if addr.is_some() {
                    s.last_used_addr = addr;
                }
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

    /// Tokens, newest first, optionally only one creator's. Revoked ones only with
    /// `include_revoked`.
    pub fn list(&self, created_by: Option<&Uuid>, include_revoked: bool) -> Vec<ApiTokenInfo> {
        let mut v: Vec<_> = self
            .cache
            .iter()
            .filter(|e| include_revoked || e.stored.revoked_at.is_none())
            .filter(|e| created_by.is_none_or(|u| e.stored.created_by == *u))
            .map(|e| (e.stored.created_at, e.info()))
            .collect();
        v.sort_by(|a, b| b.0.cmp(&a.0));
        v.into_iter().map(|(_, i)| i).collect()
    }

    /// Delete tokens that died (revoked or expired, whichever came first) before `cutoff`, in
    /// one transaction, then drop them from the cache. Returns the number deleted. The audit
    /// log keeps their creation and revocation history.
    pub fn purge_dead(&self, cutoff: DateTime<Utc>) -> ApiResult<usize> {
        let _g = self.write_lock.lock();
        let dead: Vec<String> = self
            .cache
            .iter()
            .filter(|e| {
                let s = &e.stored;
                [s.revoked_at, s.expires_at]
                    .into_iter()
                    .flatten()
                    .min()
                    .is_some_and(|t| t < cutoff)
            })
            .map(|e| e.key().clone())
            .collect();
        if dead.is_empty() {
            return Ok(0);
        }
        self.db.write::<_, ApiError>(Durability::Immediate, |t| {
            let mut tb = t.open_table(tables::API_TOKENS).map_err(DbError::from)?;
            for id in &dead {
                tb.remove(id.as_str()).map_err(DbError::from)?;
            }
            Ok(())
        })?;
        for id in &dead {
            self.cache.remove(id);
        }
        Ok(dead.len())
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
                let mut s = c.snapshot();
                s.revoked_at = Some(now);
                // The previous secret stays recorded, so it is answered "revoked" like the
                // current one (verify checks revocation after the digest match).
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

    /// Commit `stored` as the new record of token `id` and swap the cache entry (caller holds
    /// `write_lock`).
    fn commit(&self, old: &CachedToken, stored: StoredToken) -> ApiResult<Arc<CachedToken>> {
        let bytes = json(&stored)?;
        self.db.write::<_, ApiError>(Durability::Immediate, |t| {
            t.open_table(tables::API_TOKENS)
                .map_err(DbError::from)?
                .insert(stored.id.as_str(), bytes.as_slice())
                .map_err(DbError::from)?;
            Ok(())
        })?;
        let next = Arc::new(old.successor(stored));
        self.cache.insert(next.stored.id.clone(), next.clone());
        Ok(next)
    }

    /// A live (not revoked) token, or the error to answer.
    fn live_entry(&self, id: &str) -> ApiResult<Arc<CachedToken>> {
        match self.get(id) {
            Some(c) if c.stored.revoked_at.is_none() => Ok(c),
            Some(_) => Err(ApiError::bad_request("Token is revoked")),
            None => Err(ApiError::NotFound("Token not found".into())),
        }
    }

    /// Apply `changes` to a token. The secret is untouched.
    pub fn update(&self, id: &str, changes: TokenUpdate) -> ApiResult<ApiTokenInfo> {
        let _g = self.write_lock.lock();
        let old = self.live_entry(id)?;
        if old.stored.expires_at.is_some_and(|t| t <= Utc::now()) {
            return Err(expired_conflict(
                "The token has expired. Regenerate it with a new expiry instead.",
            ));
        }
        let mut s = old.snapshot();
        if let Some(n) = changes.name {
            s.name = n;
        }
        if let Some(sc) = changes.scopes {
            s.scopes = sc;
        }
        if let Some(p) = changes.profiles {
            s.profiles = p;
        }
        if let Some(p) = changes.purpose {
            s.purpose = p;
        }
        if let Some(e) = changes.expires_at {
            s.expires_at = e;
        }
        s.updated_at = Some(Utc::now());
        Ok(self.commit(&old, s)?.info())
    }

    /// Issue a new secret for token `id` (same id and settings). The old secret keeps working
    /// until `now + grace_secs`. Returns the metadata and the one-time secret string.
    pub fn regenerate(
        &self,
        id: &str,
        grace_secs: u32,
        now: DateTime<Utc>,
        new_expiry: Option<Option<DateTime<Utc>>>,
    ) -> ApiResult<(ApiTokenInfo, String)> {
        let _g = self.write_lock.lock();
        let old = self.live_entry(id)?;
        let expired = old.stored.expires_at.is_some_and(|t| t <= now);
        if expired && new_expiry.is_none() {
            return Err(expired_conflict(
                "The token has expired. Give a new expiry to regenerate it.",
            ));
        }
        // A revived token must not bring its old secret back.
        let grace_secs = if expired { 0 } else { grace_secs };
        let full = format!("{TOKEN_PREFIX}_{id}_{}", random_hex(32));
        let mut s = old.snapshot();
        if grace_secs > 0 {
            s.prev_digest = Some(old.stored.digest.clone());
            s.prev_valid_until = Some(now + chrono::Duration::seconds(grace_secs as i64));
        } else {
            s.prev_digest = None;
            s.prev_valid_until = None;
        }
        s.digest = digest_of(&full).to_hex().to_string();
        s.secret_hint = hint_of(id, &full);
        if let Some(e) = new_expiry {
            s.expires_at = e;
        }
        s.updated_at = Some(now);
        let info = self.commit(&old, s)?.info();
        Ok((info, full))
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
                TokenPurpose::Custom,
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
                TokenPurpose::Custom,
            )
            .unwrap();
        assert_eq!(store.verify(&secret).err(), Some(TokenReject::Expired));
        let json = serde_json::to_string(&store.list(None, true)).unwrap();
        assert!(!json.contains(&secret));
    }

    #[test]
    fn list_hides_revoked_unless_asked() {
        let (store, _d) = store();
        let (a, _) = make(&store);
        let (b, _) = make(&store);
        store.revoke(&a.id).unwrap();
        let ids = |all| {
            store
                .list(None, all)
                .into_iter()
                .map(|t| t.id)
                .collect::<Vec<_>>()
        };
        assert_eq!(ids(false), vec![b.id.clone()]);
        assert_eq!(ids(true).len(), 2);
    }

    /// Rewrite a stored token's dates directly (the store only stamps "now").
    fn age(store: &TokenStore, id: &str, f: impl FnOnce(&mut StoredToken)) {
        let mut s = store.get(id).unwrap().stored.clone();
        f(&mut s);
        let bytes = json(&s).unwrap();
        store
            .db
            .write::<_, ApiError>(Durability::Immediate, |t| {
                t.open_table(tables::API_TOKENS)
                    .map_err(DbError::from)?
                    .insert(id, bytes.as_slice())
                    .map_err(DbError::from)?;
                Ok(())
            })
            .unwrap();
        store
            .cache
            .insert(id.to_string(), Arc::new(CachedToken::new(s)));
    }

    #[test]
    fn purge_dead_removes_only_long_dead_tokens() {
        let (store, dir) = store();
        let old = Utc::now() - chrono::Duration::days(100);
        let cutoff = Utc::now() - chrono::Duration::days(90);
        let (old_revoked, _) = make(&store);
        age(&store, &old_revoked.id, |s| s.revoked_at = Some(old));
        let (recent_revoked, _) = make(&store);
        store.revoke(&recent_revoked.id).unwrap();
        let (old_expired, _) = make(&store);
        age(&store, &old_expired.id, |s| s.expires_at = Some(old));
        let (recent_expired, _) = make(&store);
        age(&store, &recent_expired.id, |s| {
            s.expires_at = Some(Utc::now() - chrono::Duration::days(1))
        });
        let (live, live_secret) = make(&store);
        assert_eq!(store.purge_dead(cutoff).unwrap(), 2);
        assert!(store.get(&old_revoked.id).is_none());
        assert!(store.get(&old_expired.id).is_none());
        assert!(store.get(&recent_revoked.id).is_some());
        assert!(store.get(&recent_expired.id).is_some());
        assert!(store.verify(&live_secret).is_ok());
        assert_eq!(store.purge_dead(cutoff).unwrap(), 0);
        // Gone from disk too.
        let db = store.db.clone();
        drop(store);
        let again = TokenStore::new(db).unwrap();
        assert!(again.get(&old_revoked.id).is_none() && again.get(&live.id).is_some());
        drop(dir);
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
                        TokenPurpose::Custom,
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
    fn old_records_without_new_fields_load() {
        let old = serde_json::json!({
            "id": "abc", "name": "n", "scopes": ["lists:read"], "profiles": null,
            "digest": "00", "created_by": Uuid::nil(), "created_by_name": "u",
            "created_at": "2026-01-01T00:00:00Z", "expires_at": null,
            "last_used_at": null, "revoked_at": null
        });
        let s: StoredToken = serde_json::from_value(old).unwrap();
        assert_eq!(s.purpose, TokenPurpose::Custom);
        assert!(s.secret_hint.is_empty() && s.prev_digest.is_none() && s.updated_at.is_none());
        let info = CachedToken::new(s).info();
        assert_eq!(info.secret_hint, "abk_abc_…");
        assert!(info.last_used_addr.is_none());
    }

    #[test]
    fn hint_shows_id_and_tail_but_not_the_secret() {
        let (store, _d) = store();
        let (info, secret) = make(&store);
        assert_eq!(
            info.secret_hint,
            format!("abk_{}_…{}", info.id, &secret[secret.len() - 4..])
        );
        assert!(!secret.contains(&info.secret_hint));
        assert!(info.secret_hint.len() < 40);
    }

    #[test]
    fn regenerate_grace_window_with_injected_clock() {
        let (store, _d) = store();
        let (info, old) = make(&store);
        let t0 = Utc::now();
        let (renewed, new) = store.regenerate(&info.id, 60, t0, None).unwrap();
        assert_ne!(new, old);
        assert_eq!(renewed.id, info.id);
        assert!(renewed.prev_valid_until.is_some());
        assert_ne!(renewed.secret_hint, info.secret_hint);
        let at = |s: i64| t0 + chrono::Duration::seconds(s);
        assert!(store.verify_at(&new, at(0)).is_ok());
        assert!(store.verify_at(&old, at(30)).is_ok());
        assert_eq!(
            store.verify_at(&old, at(61)).err(),
            Some(TokenReject::Unknown)
        );
        assert!(store.verify_at(&new, at(61)).is_ok());
        // No grace: the old secret dies at once.
        let (_, newer) = store.regenerate(&info.id, 0, t0, None).unwrap();
        assert_eq!(store.verify_at(&new, t0).err(), Some(TokenReject::Unknown));
        assert!(store.verify_at(&newer, t0).is_ok());
    }

    #[test]
    fn revoke_kills_current_and_previous_secret_and_blocks_edits() {
        let (store, _d) = store();
        let (info, old) = make(&store);
        let (_, new) = store.regenerate(&info.id, 3600, Utc::now(), None).unwrap();
        assert!(store.verify(&old).is_ok());
        store.revoke(&info.id).unwrap();
        assert_eq!(store.verify(&old).err(), Some(TokenReject::Revoked));
        assert_eq!(store.verify(&new).err(), Some(TokenReject::Revoked));
        assert!(store.regenerate(&info.id, 0, Utc::now(), None).is_err());
        assert!(store.update(&info.id, TokenUpdate::default()).is_err());
    }

    #[test]
    fn unknown_scopes_survive_load_list_revoke_and_rewrite() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(dir.path()).unwrap();
        let rec = serde_json::json!({
            "id": "fut", "name": "n", "scopes": ["lists:read", "made:up"], "profiles": null,
            "digest": "00", "created_by": Uuid::nil(), "created_by_name": "u",
            "created_at": "2026-01-01T00:00:00Z", "expires_at": null,
            "last_used_at": null, "revoked_at": null
        });
        let put = |id: &str, b: Vec<u8>| {
            db.write::<_, ApiError>(Durability::Immediate, |t| {
                t.open_table(tables::API_TOKENS)
                    .map_err(DbError::from)?
                    .insert(id, b.as_slice())
                    .map_err(DbError::from)?;
                Ok(())
            })
            .unwrap()
        };
        put("fut", serde_json::to_vec(&rec).unwrap());
        put("bad", b"{not json".to_vec());
        let s = TokenStore::new(db.clone()).unwrap();
        let c = s.get("fut").expect("loads");
        assert_eq!(c.stored.scopes, vec![Scope::ListsRead]);
        assert!(s.get("bad").is_none());
        let listed = s.list(None, false);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].unknown_scopes, vec!["made:up".to_string()]);
        assert!(s.revoke("fut").unwrap());
        drop(s);
        let again = TokenStore::new(db).unwrap();
        let c = again.get("fut").unwrap();
        assert!(c.stored.revoked_at.is_some());
        assert_eq!(c.stored.unknown_scopes, vec!["made:up".to_string()]);
    }

    #[test]
    fn a_kept_unknown_scope_that_is_now_known_is_granted_again() {
        let rec = serde_json::json!({
            "id": "x", "name": "n", "scopes": ["lists:read"], "profiles": null,
            "digest": "00", "created_by": Uuid::nil(), "created_by_name": "u",
            "created_at": "2026-01-01T00:00:00Z", "expires_at": null,
            "last_used_at": null, "revoked_at": null,
            "unknown_scopes": ["bypass:site", "lists:read", "made:up"]
        });
        let t = parse_stored(&serde_json::to_vec(&rec).unwrap()).unwrap();
        assert_eq!(t.scopes, vec![Scope::ListsRead, Scope::BypassSite]);
        assert_eq!(t.unknown_scopes, vec!["made:up".to_string()]);
    }

    #[test]
    fn expired_tokens_refuse_edits_and_regenerate_needs_a_new_expiry() {
        let (store, _d) = store();
        let (info, old) = make(&store);
        age(&store, &info.id, |s| {
            s.expires_at = Some(Utc::now() - chrono::Duration::seconds(5))
        });
        assert!(store.update(&info.id, TokenUpdate::default()).is_err());
        assert!(store.regenerate(&info.id, 60, Utc::now(), None).is_err());
        let exp = Utc::now() + chrono::Duration::days(1);
        let (_, new) = store
            .regenerate(&info.id, 60, Utc::now(), Some(Some(exp)))
            .unwrap();
        assert!(store.verify(&new).is_ok());
        assert_eq!(store.verify(&old).err(), Some(TokenReject::Unknown));
    }

    #[test]
    fn grace_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let (old, new) = {
            let s = TokenStore::new(Db::open(dir.path()).unwrap()).unwrap();
            let (info, old) = make(&s);
            let (_, new) = s.regenerate(&info.id, 600, Utc::now(), None).unwrap();
            (old, new)
        };
        let s = TokenStore::new(Db::open(dir.path()).unwrap()).unwrap();
        assert!(s.verify(&old).is_ok() && s.verify(&new).is_ok());
    }

    #[test]
    fn update_changes_fields_keeps_secret_and_last_use() {
        let (store, _d) = store();
        let (info, secret) = make(&store);
        let cached = store.verify(&secret).unwrap();
        store.mark_used(&cached, Some("10.0.0.7".parse().unwrap()));
        let exp = Utc::now() + chrono::Duration::days(3);
        let out = store
            .update(
                &info.id,
                TokenUpdate {
                    name: Some("renamed".into()),
                    scopes: Some(vec![Scope::StatsRead]),
                    profiles: Some(Some(vec!["1".into()])),
                    purpose: Some(TokenPurpose::Monitoring),
                    expires_at: Some(Some(exp)),
                },
            )
            .unwrap();
        assert_eq!(out.name, "renamed");
        assert_eq!(out.scopes, vec![Scope::StatsRead]);
        assert_eq!(out.profiles, Some(vec!["1".to_string()]));
        assert_eq!(out.purpose, TokenPurpose::Monitoring);
        assert!(out.updated_at.is_some() && out.last_used_at.is_some());
        assert_eq!(out.last_used_addr.as_deref(), Some("10.0.0.7"));
        assert!(store.verify(&secret).is_ok());
        let cleared = store
            .update(
                &info.id,
                TokenUpdate {
                    profiles: Some(None),
                    expires_at: Some(None),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(cleared.profiles.is_none() && cleared.expires_at.is_none());
    }

    #[test]
    fn last_used_address_is_recorded_and_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(dir.path()).unwrap();
        let s = TokenStore::new(db.clone()).unwrap();
        let (info, secret) = make(&s);
        let cached = s.verify(&secret).unwrap();
        assert!(cached.info().last_used_addr.is_none());
        s.mark_used(&cached, Some("192.168.1.9".parse().unwrap()));
        assert_eq!(cached.info().last_used_addr.as_deref(), Some("192.168.1.9"));
        db.flush_deferred();
        drop(s);
        let s2 = TokenStore::new(db).unwrap();
        assert_eq!(
            s2.get(&info.id).unwrap().info().last_used_addr.as_deref(),
            Some("192.168.1.9")
        );
    }

    #[test]
    fn last_used_is_coalesced_and_never_undoes_revocation() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(dir.path()).unwrap();
        let s = TokenStore::new(db.clone()).unwrap();
        let (info, secret) = make(&s);
        let cached = s.verify(&secret).unwrap();
        s.mark_used(&cached, None); // queues a deferred write
        s.revoke(&info.id).unwrap();
        db.flush_deferred();
        drop(s);
        let s2 = TokenStore::new(db).unwrap();
        assert_eq!(s2.verify(&secret).err(), Some(TokenReject::Revoked));
        assert!(s2.get(&info.id).unwrap().stored.last_used_at.is_some());
    }
}

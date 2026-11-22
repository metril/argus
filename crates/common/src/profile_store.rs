//! Persistent per-device profiles and devices (redb tables `PROFILES`, `DEVICES`,
//! `DEVICE_TOKENS`).
//!
//! Profile id [`DEFAULT_PROFILE_ID`] (0) is the built-in `default` profile. It is never stored:
//! its lists and rules are the existing global list enablement and custom rules, so
//! [`ProfileStore::get`] returns a synthetic record with empty `lists`/`rules`, and it cannot be
//! put, renamed or deleted. [`ProfileStore::put`] with `id == 0` creates a new profile (the id is
//! assigned); with a nonzero id it updates that profile.
//!
//! Deleting a profile that devices still reference is refused with [`ProfileError::Conflict`].
//!
//! Every write is an `Immediate` (fsynced) commit; [`ProfileStore::subscribe`] is bumped only
//! after it returned. All methods block on the database: call them from `spawn_blocking` on
//! async threads.

use crate::db::{redb::ReadableTable, tables, Db, DbError};
use base64::Engine as _;
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use rand::RngCore;
use redb::Durability;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::watch;

/// Id of the built-in default profile.
pub const DEFAULT_PROFILE_ID: u64 = 0;
/// Name of the built-in default profile.
pub const DEFAULT_PROFILE_NAME: &str = "default";
/// Largest accepted overlay rules text, in bytes.
pub const MAX_RULES_BYTES: usize = 256 * 1024;
/// Prefix of every device token.
pub const TOKEN_PREFIX: &str = "abd_";
const MAX_NAME_CHARS: usize = 64;
const MAX_DESCRIPTION_CHARS: usize = 500;
const MAX_LISTS: usize = 1000;
const MAX_IPS: usize = 64;

/// Profile store error.
#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    /// The input is not acceptable (bad name, address, size...).
    #[error("{0}")]
    Invalid(String),
    /// The referenced profile or device does not exist.
    #[error("{0} not found")]
    NotFound(&'static str),
    /// The change collides with existing state (duplicate name or address, profile in use).
    #[error("{0}")]
    Conflict(String),
    #[error(transparent)]
    Db(#[from] DbError),
}

pub type Result<T> = std::result::Result<T, ProfileError>;

fn db<E: Into<DbError>>(e: E) -> ProfileError {
    ProfileError::Db(e.into())
}
fn invalid<T>(m: impl Into<String>) -> Result<T> {
    Err(ProfileError::Invalid(m.into()))
}

/// A stored profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileRecord {
    pub id: u64,
    pub name: String,
    pub description: String,
    /// Enabled filter list ids.
    pub lists: Vec<String>,
    /// Custom overlay rules text.
    pub rules: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A stored device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub id: u64,
    pub name: String,
    pub profile_id: u64,
    /// Addresses (as /32, /128) and prefixes that select this device.
    pub ips: Vec<IpNet>,
    /// BLAKE3 digest of the current token. Only [`ProfileStore::issue_token`] and
    /// [`ProfileStore::revoke_token`] change it; [`ProfileStore::put_device`] ignores it.
    pub token_digest: Option<[u8; 32]>,
    /// Last 4 characters of the current token.
    pub token_hint: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// BLAKE3 digest of a token as presented (the whole `abd_...` string's bytes).
pub fn token_digest(raw: &[u8]) -> [u8; 32] {
    *blake3::hash(raw).as_bytes()
}

fn default_profile() -> ProfileRecord {
    ProfileRecord {
        id: DEFAULT_PROFILE_ID,
        name: DEFAULT_PROFILE_NAME.into(),
        description: "Built-in profile: the global lists and custom rules".into(),
        lists: Vec::new(),
        rules: String::new(),
        created_at: DateTime::<Utc>::UNIX_EPOCH,
        updated_at: DateTime::<Utc>::UNIX_EPOCH,
    }
}

fn valid_name(name: &str) -> bool {
    let n = name.chars().count();
    (1..=MAX_NAME_CHARS).contains(&n)
        && !name.starts_with(' ')
        && !name.ends_with(' ')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' '))
}

fn normalize_net(n: IpNet) -> Result<IpNet> {
    let n = n.trunc();
    let (min, family) = match n {
        IpNet::V4(_) => (8, "IPv4"),
        IpNet::V6(_) => (16, "IPv6"),
    };
    if n.prefix_len() < min {
        return invalid(format!(
            "{n}: {family} prefixes broader than /{min} are refused"
        ));
    }
    let a = n.network();
    if a.is_loopback() || a.is_unspecified() || a.is_multicast() {
        return invalid(format!(
            "{n}: loopback, unspecified and multicast are refused"
        ));
    }
    // An IPv4-mapped IPv6 address names an IPv4 host; refuse the special ones the same way.
    if let IpAddr::V6(v6) = a {
        if let Some(v4) = v6.to_ipv4_mapped() {
            if v4.is_loopback() || v4.is_unspecified() || v4.is_multicast() {
                return invalid(format!(
                    "{n}: loopback, unspecified and multicast are refused"
                ));
            }
        }
    }
    Ok(n)
}

/// Handle to the profile tables.
pub struct ProfileStore {
    db: Arc<Db>,
    tx: watch::Sender<u64>,
}

impl ProfileStore {
    /// Open over the shared database (tables are created with the schema).
    pub fn open(db: &Arc<Db>) -> Result<Self> {
        Ok(Self {
            db: db.clone(),
            tx: watch::channel(0).0,
        })
    }

    /// A receiver whose value increases by one after every committed change.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.tx.subscribe()
    }

    fn committed(&self) {
        self.tx.send_modify(|v| *v += 1);
    }

    fn write<T>(&self, f: impl FnOnce(&redb::WriteTransaction) -> Result<T>) -> Result<T> {
        let out = self.db.write(Durability::Immediate, f)?;
        self.committed();
        Ok(out)
    }

    // ---- profiles ---------------------------------------------------------------------------

    /// All profiles, the default first, then by id.
    pub fn list(&self) -> Result<Vec<ProfileRecord>> {
        let mut out = vec![default_profile()];
        self.db.read(|r| {
            let t = r.open_table(tables::PROFILES).map_err(db)?;
            for i in t.iter().map_err(db)? {
                let (_, v) = i.map_err(db)?;
                out.push(decode(v.value())?);
            }
            Ok::<_, ProfileError>(())
        })?;
        Ok(out)
    }

    pub fn get(&self, id: u64) -> Result<Option<ProfileRecord>> {
        if id == DEFAULT_PROFILE_ID {
            return Ok(Some(default_profile()));
        }
        self.db.read(|r| {
            let t = r.open_table(tables::PROFILES).map_err(db)?;
            let v = t.get(id).map_err(db)?;
            v.map(|v| decode(v.value())).transpose()
        })
    }

    /// Create (`id == 0`, id assigned) or update (nonzero id) a profile; returns the stored
    /// record. Names are unique case-insensitively and `default` is reserved.
    pub fn put(&self, mut p: ProfileRecord) -> Result<ProfileRecord> {
        if !valid_name(&p.name) {
            return invalid(
                "name must be 1-64 characters of letters, digits, space, '_', '-', '.'",
            );
        }
        if p.description.chars().count() > MAX_DESCRIPTION_CHARS {
            return invalid("description too long");
        }
        if p.rules.len() > MAX_RULES_BYTES {
            return invalid(format!("rules exceed {MAX_RULES_BYTES} bytes"));
        }
        if p.lists.len() > MAX_LISTS {
            return invalid("too many lists");
        }
        let mut seen = HashSet::new();
        p.lists.retain(|l| seen.insert(l.clone()));
        let now = Utc::now();
        self.write(|txn| {
            let mut t = txn.open_table(tables::PROFILES).map_err(db)?;
            let mut next = 1u64;
            let mut existing = None;
            for i in t.iter().map_err(db)? {
                let (k, v) = i.map_err(db)?;
                let other: ProfileRecord = decode(v.value())?;
                next = next.max(k.value() + 1);
                if other.id == p.id {
                    existing = Some(other);
                } else if other.name.eq_ignore_ascii_case(&p.name) {
                    return Err(ProfileError::Conflict(format!(
                        "a profile named \"{}\" already exists",
                        p.name
                    )));
                }
            }
            if p.name.eq_ignore_ascii_case(DEFAULT_PROFILE_NAME) {
                return Err(ProfileError::Conflict(
                    "\"default\" is the built-in profile's name".into(),
                ));
            }
            if p.id == DEFAULT_PROFILE_ID {
                p.id = next;
                p.created_at = now;
            } else {
                p.created_at = existing
                    .ok_or(ProfileError::NotFound("profile"))?
                    .created_at;
            }
            p.updated_at = now;
            t.insert(p.id, encode(&p)?.as_slice()).map_err(db)?;
            Ok(p)
        })
    }

    /// Delete a profile. `Ok(false)` if it does not exist; the default cannot be deleted and a
    /// profile with devices is refused.
    pub fn delete(&self, id: u64) -> Result<bool> {
        if id == DEFAULT_PROFILE_ID {
            return Err(ProfileError::Conflict(
                "the default profile cannot be deleted".into(),
            ));
        }
        self.write(|txn| {
            let d = txn.open_table(tables::DEVICES).map_err(db)?;
            for i in d.iter().map_err(db)? {
                let (_, v) = i.map_err(db)?;
                let dev: DeviceRecord = decode(v.value())?;
                if dev.profile_id == id {
                    return Err(ProfileError::Conflict(format!(
                        "profile is used by device \"{}\"; move or delete its devices first",
                        dev.name
                    )));
                }
            }
            let mut t = txn.open_table(tables::PROFILES).map_err(db)?;
            let removed = t.remove(id).map_err(db)?.is_some();
            Ok(removed)
        })
    }

    // ---- devices ----------------------------------------------------------------------------

    pub fn devices(&self) -> Result<Vec<DeviceRecord>> {
        self.db.read(|r| {
            let t = r.open_table(tables::DEVICES).map_err(db)?;
            t.iter()
                .map_err(db)?
                .map(|i| decode(i.map_err(db)?.1.value()))
                .collect()
        })
    }

    pub fn device(&self, id: u64) -> Result<Option<DeviceRecord>> {
        self.db.read(|r| {
            let t = r.open_table(tables::DEVICES).map_err(db)?;
            let v = t.get(id).map_err(db)?;
            v.map(|v| decode(v.value())).transpose()
        })
    }

    /// The device holding the token whose [`token_digest`] is `digest`.
    pub fn device_by_token_digest(&self, digest: &[u8; 32]) -> Result<Option<DeviceRecord>> {
        self.db.read(|r| {
            let t = r.open_table(tables::DEVICE_TOKENS).map_err(db)?;
            let Some(id) = t.get(digest.as_slice()).map_err(db)?.map(|v| v.value()) else {
                return Ok(None);
            };
            let d = r.open_table(tables::DEVICES).map_err(db)?;
            let v = d.get(id).map_err(db)?;
            v.map(|v| decode(v.value())).transpose()
        })
    }

    /// Create (`id == 0`, id assigned) or update (nonzero id) a device. The token fields of `d`
    /// are ignored (see [`DeviceRecord::token_digest`]). Addresses are normalized to their
    /// network; loopback, unspecified, multicast and too-broad prefixes are refused, and an
    /// identical address/prefix on another device is a conflict.
    pub fn put_device(&self, mut d: DeviceRecord) -> Result<DeviceRecord> {
        let name = d.name.trim();
        if name.is_empty()
            || name.chars().count() > MAX_NAME_CHARS
            || name.contains(char::is_control)
        {
            return invalid("device name must be 1-64 characters without control characters");
        }
        d.name = name.to_string();
        if d.ips.len() > MAX_IPS {
            return invalid(format!("at most {MAX_IPS} addresses per device"));
        }
        let mut nets = Vec::with_capacity(d.ips.len());
        for n in &d.ips {
            let n = normalize_net(*n)?;
            if nets.contains(&n) {
                return invalid(format!("{n} listed twice"));
            }
            nets.push(n);
        }
        d.ips = nets;
        let now = Utc::now();
        self.write(|txn| {
            if d.profile_id != DEFAULT_PROFILE_ID {
                let p = txn.open_table(tables::PROFILES).map_err(db)?;
                if p.get(d.profile_id).map_err(db)?.is_none() {
                    return Err(ProfileError::NotFound("profile"));
                }
            }
            let mut t = txn.open_table(tables::DEVICES).map_err(db)?;
            let mut next = 1u64;
            let mut existing = None;
            for i in t.iter().map_err(db)? {
                let (k, v) = i.map_err(db)?;
                let other: DeviceRecord = decode(v.value())?;
                next = next.max(k.value() + 1);
                if other.id == d.id {
                    existing = Some(other);
                    continue;
                }
                if let Some(n) = d.ips.iter().find(|n| other.ips.contains(n)) {
                    return Err(ProfileError::Conflict(format!(
                        "{n} already belongs to device \"{}\"",
                        other.name
                    )));
                }
            }
            if d.id == 0 {
                d.id = next;
                d.created_at = now;
                d.token_digest = None;
                d.token_hint = None;
            } else {
                let old = existing.ok_or(ProfileError::NotFound("device"))?;
                d.created_at = old.created_at;
                d.token_digest = old.token_digest;
                d.token_hint = old.token_hint;
            }
            t.insert(d.id, encode(&d)?.as_slice()).map_err(db)?;
            Ok(d)
        })
    }

    /// Delete a device and its token. `Ok(false)` if it does not exist.
    pub fn delete_device(&self, id: u64) -> Result<bool> {
        self.write(|txn| {
            let mut t = txn.open_table(tables::DEVICES).map_err(db)?;
            let old = t
                .remove(id)
                .map_err(db)?
                .map(|v| decode::<DeviceRecord>(v.value()))
                .transpose()?;
            let Some(old) = old else { return Ok(false) };
            if let Some(dg) = old.token_digest {
                txn.open_table(tables::DEVICE_TOKENS)
                    .map_err(db)?
                    .remove(dg.as_slice())
                    .map_err(db)?;
            }
            Ok(true)
        })
    }

    // ---- tokens -----------------------------------------------------------------------------

    /// Issue a new token for `device`, replacing any previous one. Returns the raw token
    /// (`abd_<base64url of 256 random bits>`), the only time it exists outside the caller; only
    /// its BLAKE3 digest and last 4 characters are stored.
    pub fn issue_token(&self, device: u64) -> Result<String> {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let raw = format!(
            "{TOKEN_PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
        );
        let digest = token_digest(raw.as_bytes());
        let hint = raw[raw.len() - 4..].to_string();
        self.write(|txn| {
            let mut t = txn.open_table(tables::DEVICES).map_err(db)?;
            let mut d: DeviceRecord = t
                .get(device)
                .map_err(db)?
                .map(|v| decode(v.value()))
                .transpose()?
                .ok_or(ProfileError::NotFound("device"))?;
            let mut tok = txn.open_table(tables::DEVICE_TOKENS).map_err(db)?;
            if let Some(old) = d.token_digest {
                tok.remove(old.as_slice()).map_err(db)?;
            }
            tok.insert(digest.as_slice(), device).map_err(db)?;
            d.token_digest = Some(digest);
            d.token_hint = Some(hint);
            t.insert(device, encode(&d)?.as_slice()).map_err(db)?;
            Ok(())
        })?;
        Ok(raw)
    }

    /// Remove a device's token. `Ok(false)` if the device has none (or does not exist).
    pub fn revoke_token(&self, device: u64) -> Result<bool> {
        self.write(|txn| {
            let mut t = txn.open_table(tables::DEVICES).map_err(db)?;
            let Some(mut d) = t
                .get(device)
                .map_err(db)?
                .map(|v| decode::<DeviceRecord>(v.value()))
                .transpose()?
            else {
                return Ok(false);
            };
            let Some(old) = d.token_digest.take() else {
                return Ok(false);
            };
            d.token_hint = None;
            txn.open_table(tables::DEVICE_TOKENS)
                .map_err(db)?
                .remove(old.as_slice())
                .map_err(db)?;
            t.insert(device, encode(&d)?.as_slice()).map_err(db)?;
            Ok(true)
        })
    }
}

fn encode<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(v).map_err(|e| ProfileError::Db(DbError::Storage(e.to_string())))
}

fn decode<T: for<'a> Deserialize<'a>>(b: &[u8]) -> Result<T> {
    serde_json::from_slice(b).map_err(|e| ProfileError::Db(DbError::Storage(e.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, Arc<Db>, ProfileStore) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(dir.path()).unwrap();
        let s = ProfileStore::open(&db).unwrap();
        (dir, db, s)
    }

    fn prof(name: &str) -> ProfileRecord {
        ProfileRecord {
            id: 0,
            name: name.into(),
            description: String::new(),
            lists: vec!["b".into(), "a".into()],
            rules: "||x.test^".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn dev(name: &str, profile: u64, ips: &[&str]) -> DeviceRecord {
        DeviceRecord {
            id: 0,
            name: name.into(),
            profile_id: profile,
            ips: ips
                .iter()
                .map(|s| {
                    s.parse::<IpNet>()
                        .unwrap_or_else(|_| IpNet::from(s.parse::<IpAddr>().unwrap()))
                })
                .collect(),
            token_digest: None,
            token_hint: None,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn round_trip_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let (p, d) = {
            let db = Db::open(dir.path()).unwrap();
            let s = ProfileStore::open(&db).unwrap();
            let p = s.put(prof("Kids")).unwrap();
            let d = s
                .put_device(dev("tablet", p.id, &["192.168.1.5", "10.1.0.0/16"]))
                .unwrap();
            (p, d)
        };
        let db = Db::open(dir.path()).unwrap();
        let s = ProfileStore::open(&db).unwrap();
        assert_eq!(s.get(p.id).unwrap().unwrap(), p);
        assert_eq!(s.device(d.id).unwrap().unwrap(), d);
        assert_eq!(s.list().unwrap().len(), 2);
        assert_eq!(s.devices().unwrap()[0].ips[0].to_string(), "192.168.1.5/32");
        assert!(s.delete_device(d.id).unwrap());
        assert!(s.delete(p.id).unwrap());
        assert!(!s.delete(p.id).unwrap());
    }

    #[test]
    fn token_digest_at_rest_and_reissue() {
        let (dir, _db, s) = store();
        let d = s.put_device(dev("phone", 0, &["192.168.1.9"])).unwrap();
        let raw = s.issue_token(d.id).unwrap();
        assert!(raw.starts_with("abd_") && raw.len() == 4 + 43);
        let rec = s.device(d.id).unwrap().unwrap();
        let dg = token_digest(raw.as_bytes());
        assert_eq!(rec.token_digest, Some(dg));
        assert_eq!(rec.token_hint.as_deref(), Some(&raw[raw.len() - 4..]));
        assert_eq!(s.device_by_token_digest(&dg).unwrap().unwrap().id, d.id);
        let bytes = std::fs::read(dir.path().join(crate::db::FILE_NAME)).unwrap();
        let has = |n: &[u8]| bytes.windows(n.len()).any(|w| w == n);
        assert!(!has(raw.as_bytes()), "raw token must not be on disk");
        assert!(has(&dg), "digest is the key at rest");

        let raw2 = s.issue_token(d.id).unwrap();
        assert_ne!(raw, raw2);
        assert!(s.device_by_token_digest(&dg).unwrap().is_none());
        assert!(s
            .device_by_token_digest(&token_digest(raw2.as_bytes()))
            .unwrap()
            .is_some());
        // Updating the device cannot touch the token.
        let mut upd = rec.clone();
        upd.token_digest = None;
        upd.name = "phone2".into();
        let got = s.put_device(upd).unwrap();
        assert_eq!(got.token_digest, Some(token_digest(raw2.as_bytes())));
        assert!(s.revoke_token(d.id).unwrap());
        assert!(!s.revoke_token(d.id).unwrap());
        assert!(s
            .device_by_token_digest(&token_digest(raw2.as_bytes()))
            .unwrap()
            .is_none());
        assert!(s.issue_token(999).is_err());
    }

    #[test]
    fn validation_rejections() {
        let (_d, _db, s) = store();
        s.put(prof("Kids")).unwrap();
        assert!(matches!(
            s.put(prof("kids")),
            Err(ProfileError::Conflict(_))
        ));
        assert!(matches!(
            s.put(prof("Default")),
            Err(ProfileError::Conflict(_))
        ));
        for bad in ["", "a/b", "x\0", " pad", &"n".repeat(65)] {
            assert!(
                matches!(s.put(prof(bad)), Err(ProfileError::Invalid(_))),
                "{bad:?}"
            );
        }
        let mut big = prof("Big");
        big.rules = "x".repeat(MAX_RULES_BYTES + 1);
        assert!(matches!(s.put(big), Err(ProfileError::Invalid(_))));

        s.put_device(dev("a", 0, &["192.168.1.5", "10.0.0.0/24"]))
            .unwrap();
        for ips in [
            &["192.168.1.5"][..],
            &["10.0.0.7/24"][..], // normalizes to the same prefix
            &["127.0.0.1"][..],
            &["0.0.0.0/8"][..],
            &["::1"][..],
            &["::"][..],
            &["224.0.0.1"][..],
            &["ff02::1"][..],
            &["10.0.0.0/7"][..],
            &["fc00::/15"][..],
            &["1.2.3.4", "1.2.3.4"][..],
        ] {
            assert!(s.put_device(dev("b", 0, ips)).is_err(), "{ips:?}");
        }
        assert!(s
            .put_device(dev("b", 0, &["10.0.0.0/8", "2001:db8::/16"]))
            .is_ok());
        assert!(matches!(
            s.put_device(dev("c", 77, &[])),
            Err(ProfileError::NotFound(_))
        ));
        assert!(s.put_device(dev("", 0, &[])).is_err());
    }

    #[test]
    fn default_profile_protected() {
        let (_d, _db, s) = store();
        let d = s.get(0).unwrap().unwrap();
        assert_eq!(d.name, "default");
        assert_eq!(s.list().unwrap()[0].id, 0);
        assert!(matches!(s.delete(0), Err(ProfileError::Conflict(_))));
        // Putting "default" cannot rename or recreate it.
        assert!(s.put(d).is_err());
        assert_eq!(s.list().unwrap().len(), 1);
    }

    #[test]
    fn delete_refused_while_devices_reference_profile() {
        let (_d, _db, s) = store();
        let p = s.put(prof("Kids")).unwrap();
        let d = s.put_device(dev("t", p.id, &[])).unwrap();
        assert!(matches!(s.delete(p.id), Err(ProfileError::Conflict(_))));
        s.delete_device(d.id).unwrap();
        assert!(s.delete(p.id).unwrap());
    }

    #[test]
    fn update_keeps_created_and_dedupes_lists() {
        let (_d, _db, s) = store();
        let p = s.put(prof("Kids")).unwrap();
        let mut u = p.clone();
        u.name = "Kids2".into();
        u.lists = vec!["a".into(), "a".into()];
        let got = s.put(u).unwrap();
        assert_eq!(got.id, p.id);
        assert_eq!(got.created_at, p.created_at);
        assert_eq!(got.lists, vec!["a"]);
        let mut ghost = p;
        ghost.id = 42;
        assert!(matches!(s.put(ghost), Err(ProfileError::NotFound(_))));
    }

    #[test]
    fn subscribe_fires_once_per_commit() {
        let (_d, _db, s) = store();
        let mut rx = s.subscribe();
        assert_eq!(*rx.borrow(), 0);
        let p = s.put(prof("Kids")).unwrap();
        assert_eq!(*rx.borrow_and_update(), 1);
        let d = s.put_device(dev("t", p.id, &[])).unwrap();
        s.issue_token(d.id).unwrap();
        s.revoke_token(d.id).unwrap();
        assert_eq!(*rx.borrow_and_update(), 4);
        // Failed writes and reads do not fire.
        assert!(s.put(prof("Kids")).is_err());
        let _ = s.list();
        assert!(!rx.has_changed().unwrap());
        s.delete_device(d.id).unwrap();
        assert_eq!(*rx.borrow(), 5);
    }
}

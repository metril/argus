//! Persistent storage of list metadata, raw list content, per-list status and custom rules.
//!
//! Metadata, status, reports and content pointers live in the shared redb database
//! (`common::db`); raw list contents are content-addressed files under `<data_dir>/lists/<sha256>`
//! (written atomically via temp + rename, no fsync: they are re-fetchable caches). Blobs no
//! longer referenced are garbage-collected.
//!
//! Durability: list definitions made by a user (`upsert_durable`, `remove`, `set_enabled`) and the
//! custom rules are `Immediate`; everything the refresher writes (status, reports, summary,
//! content pointers, `upsert`) is `Eventual` so it never fsyncs on an async worker.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use common::db::redb::{
    Durability, ReadTransaction, ReadableTable, ReadableTableMetadata, WriteTransaction,
};
use common::db::{tables, Db};
use filter_engine::{FilterList, ListReport};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::report::BuildSummary;
use crate::{Error, Result};

const CUSTOM_RULES_KEY: &str = "custom_rules";
const TRUST_MIGRATION_KEY: &str = "trust_migration_v1";
const SUMMARY_KEY: &str = "build_summary";
/// Set once the signed catalogue has seeded (or found lists already installed).
const CATALOGUE_SEEDED_KEY: &str = "catalogue_seeded";
/// META keys of the removed Strict / default blocking profiles.
const OLD_PROFILE_KEYS: [&str; 2] = ["default_offered", "strict_profile"];
/// Report key for the custom rules (not a list id: list ids cannot contain NUL).
pub const CUSTOM_REPORT_ID: &str = "\0custom";

/// Fetch outcome of a list, surfaced through the filters API.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ListStatus {
    /// Last time a fetch attempt completed (success, 304 or failure).
    pub last_checked: Option<DateTime<Utc>>,
    /// Last successful fetch (including 304 revalidation).
    pub last_success: Option<DateTime<Utc>>,
    /// Error from the most recent attempt; cleared on success.
    pub last_error: Option<String>,
    /// `Last-Modified` header of the cached copy, for conditional requests.
    pub last_modified: Option<String>,
    /// SHA-256 of the cached content plus its resolved includes (persisted-engine cache key).
    #[serde(default)]
    pub content_sha: Option<String>,
}

/// redb-backed list store.
pub struct ListStore {
    db: Arc<Db>,
    blobs: PathBuf,
    /// Serialises blob writes against garbage collection.
    blob_lock: Mutex<()>,
}

fn ser<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(v).map_err(|e| Error::Storage(e.to_string()))
}

fn de<T: for<'a> Deserialize<'a>>(b: &[u8]) -> Result<T> {
    serde_json::from_slice(b).map_err(|e| Error::Storage(e.to_string()))
}

fn db_err(e: impl Into<common::db::DbError>) -> Error {
    Error::from(e.into())
}

fn sha_hex(content: &[u8]) -> String {
    use std::fmt::Write;
    Sha256::digest(content)
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn include_key(list_id: &str, path: &str) -> String {
    format!("{list_id}\0{path}")
}

impl ListStore {
    /// Open (creating if needed) the store in `data_dir`: database `<data_dir>/argus.redb`,
    /// blobs in `<data_dir>/lists`.
    pub fn new(data_dir: impl AsRef<Path>) -> Result<Self> {
        let db = Db::open(data_dir.as_ref())?;
        Self::with_db(db)
    }

    /// Build a store on an already-open shared database.
    pub fn with_db(db: Arc<Db>) -> Result<Self> {
        let blobs = db.dir().join("lists");
        std::fs::create_dir_all(&blobs)
            .map_err(|e| Error::Storage(format!("create blob dir: {e}")))?;
        let store = Self {
            db,
            blobs,
            blob_lock: Mutex::new(()),
        };
        if let Err(e) = store.gc_blobs() {
            warn!("blob garbage collection failed: {e}");
        }
        Ok(store)
    }

    fn wtx<T>(&self, d: Durability, f: impl FnOnce(&WriteTransaction) -> Result<T>) -> Result<T> {
        self.db.write(d, f)
    }

    fn rtx<T>(&self, f: impl FnOnce(&ReadTransaction) -> Result<T>) -> Result<T> {
        self.db.read(f)
    }

    /// Open the store in `data_dir`.
    pub fn open(data_dir: &Path) -> Result<Arc<Self>> {
        Ok(Arc::new(Self::new(data_dir)?))
    }

    /// The shared database handle.
    pub fn db(&self) -> &Arc<Db> {
        &self.db
    }

    fn put_raw(
        &self,
        table: common::db::redb::TableDefinition<&str, &[u8]>,
        key: &str,
        v: &[u8],
        d: Durability,
    ) -> Result<()> {
        self.wtx(d, |t| {
            t.open_table(table)
                .map_err(db_err)?
                .insert(key, v)
                .map_err(db_err)?;
            Ok(())
        })
    }

    fn get_raw(
        &self,
        table: common::db::redb::TableDefinition<&str, &[u8]>,
        key: &str,
    ) -> Result<Option<Vec<u8>>> {
        self.rtx(|r| {
            let t = r.open_table(table).map_err(db_err)?;
            let v = t.get(key).map_err(db_err)?.map(|g| g.value().to_vec());
            Ok(v)
        })
    }

    pub(crate) fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.get_raw(tables::META, key)
    }

    #[cfg(test)]
    pub(crate) fn put_meta(&self, key: &str, v: &[u8]) -> Result<()> {
        self.put_raw(tables::META, key, v, Durability::Immediate)
    }

    pub fn get_custom_rules(&self) -> Result<String> {
        Ok(self
            .get_raw(tables::META, CUSTOM_RULES_KEY)?
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default())
    }

    pub fn set_custom_rules(&self, rules: &str) -> Result<()> {
        self.put_raw(
            tables::META,
            CUSTOM_RULES_KEY,
            rules.as_bytes(),
            Durability::Immediate,
        )
    }

    // ---- blobs ---------------------------------------------------------------------------

    fn blob_path(&self, sha: &str) -> PathBuf {
        self.blobs.join(sha)
    }

    /// Write `content` as a blob (idempotent) and return its hash.
    fn write_blob(&self, content: &str) -> Result<String> {
        let sha = sha_hex(content.as_bytes());
        let path = self.blob_path(&sha);
        if !path.exists() {
            let tmp = self.blobs.join(format!("{sha}.{}.tmp", std::process::id()));
            std::fs::write(&tmp, content)
                .and_then(|_| std::fs::rename(&tmp, &path))
                .map_err(|e| {
                    let _ = std::fs::remove_file(&tmp);
                    Error::Storage(format!("write blob: {e}"))
                })?;
        }
        Ok(sha)
    }

    fn read_blob(&self, sha: &str) -> Option<String> {
        std::fs::read(self.blob_path(sha))
            .ok()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
    }

    /// Hashes referenced by any list or include.
    fn referenced(&self) -> Result<HashSet<String>> {
        self.rtx(|r| {
            let mut set = HashSet::new();
            for it in r
                .open_table(tables::LIST_CONTENT)
                .map_err(db_err)?
                .iter()
                .map_err(db_err)?
            {
                set.insert(it.map_err(db_err)?.1.value().to_string());
            }
            for it in r
                .open_table(tables::LIST_INCLUDES)
                .map_err(db_err)?
                .iter()
                .map_err(db_err)?
            {
                set.insert(it.map_err(db_err)?.1.value().to_string());
            }
            Ok(set)
        })
    }

    /// Delete blob files nothing references (and leftover temp files). Returns files removed.
    pub fn gc_blobs(&self) -> Result<usize> {
        let _g = self.blob_lock.lock();
        let live = self.referenced()?;
        let mut removed = 0;
        let rd = std::fs::read_dir(&self.blobs)
            .map_err(|e| Error::Storage(format!("read blob dir: {e}")))?;
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let is_blob = name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit());
            let is_tmp = name.ends_with(".tmp");
            if ((is_blob && !live.contains(&name)) || is_tmp)
                && std::fs::remove_file(e.path()).is_ok()
            {
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Number of blob files on disk.
    pub fn blob_count(&self) -> usize {
        std::fs::read_dir(&self.blobs)
            .map(|rd| {
                rd.flatten()
                    .filter(|e| {
                        let n = e.file_name().to_string_lossy().into_owned();
                        n.len() == 64 && n.bytes().all(|b| b.is_ascii_hexdigit())
                    })
                    .count()
            })
            .unwrap_or(0)
    }

    /// Point `table[key]` at `content`'s blob, then drop the previous blob if now unreferenced.
    fn put_blob_ref(
        &self,
        table: common::db::redb::TableDefinition<&str, &str>,
        key: &str,
        content: &str,
    ) -> Result<()> {
        let _g = self.blob_lock.lock();
        let sha = self.write_blob(content)?;
        let old = self.wtx(Durability::Eventual, |t| {
            let mut tb = t.open_table(table).map_err(db_err)?;
            let old = tb
                .insert(key, sha.as_str())
                .map_err(db_err)?
                .map(|g| g.value().to_string());
            Ok(old)
        })?;
        if let Some(old) = old.filter(|o| *o != sha) {
            if !self.referenced()?.contains(&old) {
                let _ = std::fs::remove_file(self.blob_path(&old));
            }
        }
        Ok(())
    }

    fn get_blob_ref(
        &self,
        table: common::db::redb::TableDefinition<&str, &str>,
        key: &str,
    ) -> Result<Option<String>> {
        let sha = self.rtx(|r| {
            let t = r.open_table(table).map_err(db_err)?;
            let v = t.get(key).map_err(db_err)?.map(|g| g.value().to_string());
            Ok::<_, Error>(v)
        })?;
        Ok(sha.and_then(|s| self.read_blob(&s)))
    }

    /// Store the text of list `id`. The stored content digest describes the text being replaced,
    /// so it is dropped BEFORE the text is written: a reader (or a crash) between the two steps
    /// sees a missing digest, which is recomputed from the text, never the old digest paired with
    /// the new text. Identical text changes nothing.
    pub fn put_content(&self, id: &str, content: &str) -> Result<()> {
        if self.get_content(id)?.as_deref() == Some(content) {
            return Ok(());
        }
        let mut status = self.get_status(id)?;
        if status.content_sha.take().is_some() {
            self.set_status(id, &status)?;
        }
        self.put_blob_ref(tables::LIST_CONTENT, id, content)
    }

    pub fn get_content(&self, id: &str) -> Result<Option<String>> {
        self.get_blob_ref(tables::LIST_CONTENT, id)
    }

    /// Cache a resolved `!#include` target of `list_id`.
    pub fn put_include(&self, list_id: &str, path: &str, content: &str) -> Result<()> {
        self.put_blob_ref(tables::LIST_INCLUDES, &include_key(list_id, path), content)
    }

    pub fn get_include(&self, list_id: &str, path: &str) -> Result<Option<String>> {
        self.get_blob_ref(tables::LIST_INCLUDES, &include_key(list_id, path))
    }

    // ---- reports, summary, status ----------------------------------------------------------

    /// What the last build made of this list (format, counts, first errors, metadata).
    pub fn get_report(&self, id: &str) -> Result<Option<ListReport>> {
        self.get_raw(tables::LIST_REPORTS, id)?
            .map(|b| de(&b))
            .transpose()
    }

    pub fn set_report(&self, id: &str, report: &ListReport) -> Result<()> {
        self.put_raw(
            tables::LIST_REPORTS,
            id,
            &ser(report)?,
            Durability::Eventual,
        )
    }

    pub fn get_summary(&self) -> Result<BuildSummary> {
        Ok(match self.get_raw(tables::META, SUMMARY_KEY)? {
            Some(b) => de(&b)?,
            None => BuildSummary::default(),
        })
    }

    pub fn set_summary(&self, summary: &BuildSummary) -> Result<()> {
        self.put_raw(
            tables::META,
            SUMMARY_KEY,
            &ser(summary)?,
            Durability::Eventual,
        )
    }

    pub fn get_status(&self, id: &str) -> Result<ListStatus> {
        Ok(match self.get_raw(tables::LIST_STATUS, id)? {
            Some(b) => de(&b)?,
            None => ListStatus::default(),
        })
    }

    pub fn set_status(&self, id: &str, status: &ListStatus) -> Result<()> {
        self.put_raw(tables::LIST_STATUS, id, &ser(status)?, Durability::Eventual)
    }

    // ---- lists -----------------------------------------------------------------------------

    /// Store a list definition without fsync (refresher bookkeeping).
    pub fn upsert(&self, list: &FilterList) -> Result<()> {
        self.put_raw(tables::LISTS, &list.id, &ser(list)?, Durability::Eventual)
    }

    /// Read-modify-write one list in a single transaction, as currently stored. A deleted list is
    /// skipped (`false`), never resurrected. For fetch results: `f` must only touch fetch
    /// metadata, never `enabled`.
    pub fn update_list(&self, id: &str, f: impl FnOnce(&mut FilterList)) -> Result<bool> {
        self.wtx(Durability::Eventual, |t| {
            let mut tb = t.open_table(tables::LISTS).map_err(db_err)?;
            let cur = tb.get(id).map_err(db_err)?.map(|g| g.value().to_vec());
            let Some(cur) = cur else { return Ok(false) };
            let mut l: FilterList = de(&cur)?;
            f(&mut l);
            tb.insert(id, ser(&l)?.as_slice()).map_err(db_err)?;
            Ok(true)
        })
    }

    /// Like [`Self::update_list`], durably (user-initiated; call from a blocking context).
    pub fn update_list_durable(&self, id: &str, f: impl FnOnce(&mut FilterList)) -> Result<bool> {
        self.wtx(Durability::Immediate, |t| {
            let mut tb = t.open_table(tables::LISTS).map_err(db_err)?;
            let cur = tb.get(id).map_err(db_err)?.map(|g| g.value().to_vec());
            let Some(cur) = cur else { return Ok(false) };
            let mut l: FilterList = de(&cur)?;
            f(&mut l);
            tb.insert(id, ser(&l)?.as_slice()).map_err(db_err)?;
            Ok(true)
        })
    }

    /// Store a new list durably unless one with its id exists (one transaction); whether it was
    /// inserted. Call from a blocking context.
    pub fn insert_if_absent_durable(&self, list: &FilterList) -> Result<bool> {
        self.wtx(Durability::Immediate, |t| {
            let mut tb = t.open_table(tables::LISTS).map_err(db_err)?;
            if tb.get(list.id.as_str()).map_err(db_err)?.is_some() {
                return Ok(false);
            }
            tb.insert(list.id.as_str(), ser(list)?.as_slice())
                .map_err(db_err)?;
            Ok(true)
        })
    }

    /// Store a list definition durably (user-initiated; call from a blocking context).
    pub fn upsert_durable(&self, list: &FilterList) -> Result<()> {
        self.put_raw(tables::LISTS, &list.id, &ser(list)?, Durability::Immediate)
    }

    pub fn get(&self, id: &str) -> Result<Option<FilterList>> {
        self.get_raw(tables::LISTS, id)?.map(|b| de(&b)).transpose()
    }

    /// All lists, sorted by name.
    pub fn get_all(&self) -> Result<Vec<FilterList>> {
        let mut lists = self.rtx(|r| {
            let mut v = Vec::new();
            for it in r
                .open_table(tables::LISTS)
                .map_err(db_err)?
                .iter()
                .map_err(db_err)?
            {
                v.push(de::<FilterList>(it.map_err(db_err)?.1.value())?);
            }
            Ok::<_, Error>(v)
        })?;
        lists.sort_by_key(|l| l.name.to_lowercase());
        Ok(lists)
    }

    pub fn exists(&self, id: &str) -> Result<bool> {
        self.rtx(|r| {
            let t = r.open_table(tables::LISTS).map_err(db_err)?;
            let found = t.get(id).map_err(db_err)?.is_some();
            Ok(found)
        })
    }

    /// Read-modify-write in one transaction, so concurrent toggles cannot lose each other.
    pub fn set_enabled(&self, id: &str, enabled: bool) -> Result<bool> {
        self.wtx(Durability::Immediate, |t| {
            let mut tb = t.open_table(tables::LISTS).map_err(db_err)?;
            let cur = tb.get(id).map_err(db_err)?.map(|g| g.value().to_vec());
            let Some(cur) = cur else { return Ok(false) };
            let mut l: FilterList = de(&cur)?;
            l.enabled = enabled;
            tb.insert(id, ser(&l)?.as_slice()).map_err(db_err)?;
            Ok(true)
        })
    }

    /// Remove a list with its cached content, includes, report and status, atomically.
    pub fn remove(&self, id: &str) -> Result<bool> {
        let _g = self.blob_lock.lock();
        let removed = self
            .db
            .write(Durability::Immediate, |t: &WriteTransaction| {
                let removed = t
                    .open_table(tables::LISTS)
                    .map_err(db_err)?
                    .remove(id)
                    .map_err(db_err)?
                    .is_some();
                t.open_table(tables::LIST_CONTENT)
                    .map_err(db_err)?
                    .remove(id)
                    .map_err(db_err)?;
                t.open_table(tables::LIST_STATUS)
                    .map_err(db_err)?
                    .remove(id)
                    .map_err(db_err)?;
                t.open_table(tables::LIST_REPORTS)
                    .map_err(db_err)?
                    .remove(id)
                    .map_err(db_err)?;
                let mut inc = t.open_table(tables::LIST_INCLUDES).map_err(db_err)?;
                let lo = format!("{id}\0");
                let hi = format!("{id}\u{1}");
                let keys: Vec<String> = inc
                    .range(lo.as_str()..hi.as_str())
                    .map_err(db_err)?
                    .map(|it| it.map(|(k, _)| k.value().to_string()))
                    .collect::<std::result::Result<_, _>>()
                    .map_err(db_err)?;
                for k in keys {
                    inc.remove(k.as_str()).map_err(db_err)?;
                }
                Ok::<_, Error>(removed)
            })?;
        // Blobs may now be unreferenced (inline GC; the lock is already held).
        let live = self.referenced()?;
        if let Ok(rd) = std::fs::read_dir(&self.blobs) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().into_owned();
                if n.len() == 64 && n.bytes().all(|b| b.is_ascii_hexdigit()) && !live.contains(&n) {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
        Ok(removed)
    }

    /// One-time migration: mark installed lists trusted when they are a known uBlock Origin or
    /// AdGuard Base list (by URL). Returns how many were changed; later runs are no-ops.
    pub fn migrate_trust(&self) -> Result<usize> {
        const KEY: &str = TRUST_MIGRATION_KEY;
        if self.get_raw(tables::META, KEY)?.is_some() {
            return Ok(0);
        }
        let mut n = 0;
        for mut l in self.get_all()? {
            if !l.trusted && filter_engine::is_known_trusted_source(&l.url) {
                l.trusted = true;
                self.upsert_durable(&l)?;
                n += 1;
            }
        }
        self.put_raw(tables::META, KEY, b"1", Durability::Immediate)?;
        if n > 0 {
            info!("Marked {n} installed filter lists trusted");
        }
        Ok(n)
    }

    /// Drop the metadata of the removed blocking profiles (`default_offered`, `strict_profile`).
    /// Lists they added stay as ordinary lists. When the store shows a prior run (old profile
    /// keys, the trust migration, a build summary, or any stored list) and the catalogue was
    /// never seeded, mark it seeded in the same transaction so an install whose user deleted
    /// every list is not re-seeded. Must run before [`Self::migrate_trust`], which writes its
    /// own marker on a fresh store.
    pub fn migrate_profiles(&self) -> Result<()> {
        self.wtx(Durability::Immediate, |t| {
            let mut m = t.open_table(tables::META).map_err(db_err)?;
            let mut prior = false;
            for k in OLD_PROFILE_KEYS {
                prior |= m.remove(k).map_err(db_err)?.is_some();
            }
            prior |= m.get(TRUST_MIGRATION_KEY).map_err(db_err)?.is_some();
            prior |= m.get(SUMMARY_KEY).map_err(db_err)?.is_some();
            if !prior {
                let l = t.open_table(tables::LISTS).map_err(db_err)?;
                prior = !l.is_empty().map_err(db_err)?;
            }
            if prior && m.get(CATALOGUE_SEEDED_KEY).map_err(db_err)?.is_none() {
                m.insert(CATALOGUE_SEEDED_KEY, b"1".as_slice())
                    .map_err(db_err)?;
            }
            Ok(())
        })
    }

    /// Whether the catalogue has been seeded (or found a populated store) before.
    pub fn catalogue_seeded(&self) -> Result<bool> {
        Ok(self.get_meta(CATALOGUE_SEEDED_KEY)?.is_some())
    }

    /// One-time seed from the verified catalogue: when it has never run and the store has no
    /// lists, add `wanted` (enabled). A store that already has lists is left untouched. Either way
    /// the flag is set, so a list the user later removes or disables never comes back. Returns the
    /// ids added.
    pub fn seed_catalogue(&self, wanted: Vec<FilterList>) -> Result<Vec<String>> {
        let added = self.wtx(Durability::Immediate, |t| {
            if t.open_table(tables::META)
                .map_err(db_err)?
                .get(CATALOGUE_SEEDED_KEY)
                .map_err(db_err)?
                .is_some()
            {
                return Ok(Vec::new());
            }
            let mut added = Vec::new();
            {
                let mut tb = t.open_table(tables::LISTS).map_err(db_err)?;
                if tb.is_empty().map_err(db_err)? {
                    for l in &wanted {
                        if tb.get(l.id.as_str()).map_err(db_err)?.is_none() {
                            tb.insert(l.id.as_str(), ser(l)?.as_slice())
                                .map_err(db_err)?;
                            added.push(l.id.clone());
                        }
                    }
                }
            }
            t.open_table(tables::META)
                .map_err(db_err)?
                .insert(CATALOGUE_SEEDED_KEY, b"1".as_slice())
                .map_err(db_err)?;
            Ok::<_, Error>(added)
        })?;
        if !added.is_empty() {
            info!("Seeded {} lists from the catalogue", added.len());
        }
        Ok(added)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (ListStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = ListStore::new(dir.path()).unwrap();
        (store, dir)
    }

    #[test]
    fn upsert_get_remove_roundtrip() {
        let (store, _d) = temp_store();
        let list = FilterList::new("l1".into(), "List One".into(), "https://e/x.txt".into());
        store.upsert(&list).unwrap();
        store.set_status("l1", &ListStatus::default()).unwrap();
        assert!(store.exists("l1").unwrap());
        assert!(store.set_enabled("l1", false).unwrap());
        assert!(!store.get("l1").unwrap().unwrap().enabled);
        assert!(store.remove("l1").unwrap());
        assert!(!store.exists("l1").unwrap());
        assert!(!store.remove("l1").unwrap());
        assert!(!store.set_enabled("l1", true).unwrap());
    }

    #[test]
    fn data_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let store = ListStore::new(dir.path()).unwrap();
            let mut l = FilterList::new("keep".into(), "Keep".into(), "https://e/k.txt".into());
            l.rule_count = 42;
            store.upsert(&l).unwrap();
            store.put_content("keep", "||ads.example^\n").unwrap();
            store.put_include("keep", "inc.txt", "||inc^\n").unwrap();
            store.set_custom_rules("||my.ads^\n").unwrap();
            store
                .set_status(
                    "keep",
                    &ListStatus {
                        content_sha: Some("abc".into()),
                        ..Default::default()
                    },
                )
                .unwrap();
        }
        let store = ListStore::new(dir.path()).unwrap();
        assert_eq!(store.get("keep").unwrap().unwrap().rule_count, 42);
        assert_eq!(
            store.get_content("keep").unwrap().as_deref(),
            Some("||ads.example^\n")
        );
        assert_eq!(
            store.get_include("keep", "inc.txt").unwrap().as_deref(),
            Some("||inc^\n")
        );
        assert_eq!(store.get_custom_rules().unwrap(), "||my.ads^\n");
        assert_eq!(
            store.get_status("keep").unwrap().content_sha.as_deref(),
            Some("abc")
        );
    }

    fn wanted(ids: &[&str]) -> Vec<FilterList> {
        ids.iter()
            .map(|i| FilterList::new((*i).into(), (*i).into(), format!("https://e/{i}.txt")))
            .collect()
    }

    #[test]
    fn seed_runs_once_on_an_empty_store() {
        let (store, _d) = temp_store();
        assert_eq!(store.seed_catalogue(wanted(&["a", "b"])).unwrap().len(), 2);
        assert!(store.catalogue_seeded().unwrap());
        store.remove("a").unwrap();
        assert!(store
            .seed_catalogue(wanted(&["a", "b"]))
            .unwrap()
            .is_empty());
        assert!(store.get("a").unwrap().is_none());
    }

    #[test]
    fn seed_leaves_a_populated_store_alone_and_sets_the_flag() {
        let (store, _d) = temp_store();
        store.upsert(&wanted(&["mine"])[0]).unwrap();
        assert!(store.seed_catalogue(wanted(&["a"])).unwrap().is_empty());
        assert!(store.get("a").unwrap().is_none());
        assert!(store.catalogue_seeded().unwrap());
    }

    #[test]
    fn profile_metadata_is_dropped() {
        let (store, _d) = temp_store();
        store.put_meta("default_offered", b"[]").unwrap();
        store.put_meta("strict_profile", b"{}").unwrap();
        store.migrate_profiles().unwrap();
        assert!(store.get_meta("default_offered").unwrap().is_none());
        assert!(store.get_meta("strict_profile").unwrap().is_none());
    }

    #[test]
    fn upgraded_store_with_no_lists_is_not_reseeded() {
        for key in [
            "trust_migration_v1",
            "default_offered",
            "strict_profile",
            "build_summary",
        ] {
            let (store, _d) = temp_store();
            store.put_meta(key, b"1").unwrap();
            store.migrate_profiles().unwrap();
            store.migrate_trust().unwrap();
            assert!(store.catalogue_seeded().unwrap(), "{key}");
            assert!(
                store.seed_catalogue(wanted(&["a"])).unwrap().is_empty(),
                "{key}"
            );
            assert!(store.get("a").unwrap().is_none(), "{key}");
        }
    }

    #[test]
    fn fresh_store_still_seeds_after_migrations() {
        let (store, _d) = temp_store();
        store.migrate_profiles().unwrap();
        store.migrate_trust().unwrap();
        assert!(!store.catalogue_seeded().unwrap());
        assert_eq!(store.seed_catalogue(wanted(&["a"])).unwrap(), vec!["a"]);
    }

    #[test]
    fn trust_migration_marks_known_lists_once() {
        let (store, _d) = temp_store();
        let mk = |id: &str, url: &str| FilterList::new(id.into(), id.into(), url.into());
        store
            .upsert(&mk("ublock-filters", "https://x/y.txt"))
            .unwrap();
        store
            .upsert(&mk(
                "real",
                "https://ublockorigin.github.io/uAssets/filters/filters.min.txt",
            ))
            .unwrap();
        store
            .upsert(&mk(
                "mine",
                "https://ublockorigin.github.io/uAssets/filters/unbreak.min.txt",
            ))
            .unwrap();
        store
            .upsert(&mk(
                "ag",
                "https://filters.adtidy.org/extension/chromium/filters/2.txt",
            ))
            .unwrap();
        store
            .upsert(&mk("easylist", "https://easylist.to/easylist/easylist.txt"))
            .unwrap();
        assert_eq!(store.migrate_trust().unwrap(), 3);
        assert!(
            !store.get("ublock-filters").unwrap().unwrap().trusted,
            "id alone is not trust"
        );
        assert!(store.get("mine").unwrap().unwrap().trusted);
        assert!(store.get("ag").unwrap().unwrap().trusted);
        assert!(!store.get("easylist").unwrap().unwrap().trusted);
        // One-time: a user who un-trusts afterwards is not overridden.
        let mut l = store.get("mine").unwrap().unwrap();
        l.trusted = false;
        store.upsert(&l).unwrap();
        assert_eq!(store.migrate_trust().unwrap(), 0);
        assert!(!store.get("mine").unwrap().unwrap().trusted);
    }

    #[test]
    fn blobs_are_content_addressed_and_collected() {
        let (store, _d) = temp_store();
        let a = FilterList::new("a".into(), "A".into(), "https://e/a".into());
        let b = FilterList::new("b".into(), "B".into(), "https://e/b".into());
        store.upsert(&a).unwrap();
        store.upsert(&b).unwrap();
        // Identical content shares one blob.
        store.put_content("a", "same\n").unwrap();
        store.put_content("b", "same\n").unwrap();
        assert_eq!(store.blob_count(), 1);
        // Replacing content drops the old blob once unreferenced.
        store.put_content("a", "new\n").unwrap();
        assert_eq!(store.blob_count(), 2);
        store.put_include("a", "i", "inc\n").unwrap();
        assert_eq!(store.blob_count(), 3);
        // Removing a list frees its blobs but keeps ones other lists still use.
        store.remove("a").unwrap();
        assert_eq!(store.blob_count(), 1);
        assert_eq!(store.get_content("b").unwrap().as_deref(), Some("same\n"));
        // GC removes orphans and stray temp files.
        std::fs::write(store.blobs.join("f".repeat(64)), "orphan").unwrap();
        std::fs::write(store.blobs.join("x.1.tmp"), "t").unwrap();
        assert_eq!(store.gc_blobs().unwrap(), 2);
        assert_eq!(store.blob_count(), 1);
    }

    #[test]
    fn missing_blob_reads_as_none() {
        let (store, _d) = temp_store();
        store.put_content("a", "x\n").unwrap();
        std::fs::remove_file(store.blob_path(&sha_hex(b"x\n"))).unwrap();
        assert_eq!(store.get_content("a").unwrap(), None);
    }

    #[test]
    fn concurrent_readers_during_writes() {
        let (store, _d) = temp_store();
        let store = Arc::new(store);
        store
            .upsert(&FilterList::new(
                "r".into(),
                "R".into(),
                "https://e/r".into(),
            ))
            .unwrap();
        let w = {
            let s = store.clone();
            std::thread::spawn(move || {
                for i in 0..50 {
                    s.set_status(
                        "r",
                        &ListStatus {
                            last_error: Some(i.to_string()),
                            ..Default::default()
                        },
                    )
                    .unwrap();
                }
            })
        };
        let readers: Vec<_> = (0..4)
            .map(|_| {
                let s = store.clone();
                std::thread::spawn(move || {
                    for _ in 0..50 {
                        assert!(s.get("r").unwrap().is_some());
                        s.get_status("r").unwrap();
                    }
                })
            })
            .collect();
        w.join().unwrap();
        for r in readers {
            r.join().unwrap();
        }
    }

    #[test]
    fn remove_is_atomic_all_or_nothing_for_includes_prefix() {
        // `a` must not swallow the includes of `ab` (prefix range is NUL-delimited).
        let (store, _d) = temp_store();
        for id in ["a", "ab"] {
            store
                .upsert(&FilterList::new(id.into(), id.into(), "https://e/x".into()))
                .unwrap();
            store.put_include(id, "p", &format!("inc-{id}\n")).unwrap();
        }
        store.remove("a").unwrap();
        assert_eq!(
            store.get_include("ab", "p").unwrap().as_deref(),
            Some("inc-ab\n")
        );
        assert_eq!(store.get_include("a", "p").unwrap(), None);
    }
}

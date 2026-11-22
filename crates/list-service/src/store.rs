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
use filter_engine::{default_filter_lists, FilterList, ListReport};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::report::BuildSummary;
use crate::{Error, Result};

const CUSTOM_RULES_KEY: &str = "custom_rules";
const SUMMARY_KEY: &str = "build_summary";
/// Report key for the custom rules (not a list id: list ids cannot contain NUL).
pub(crate) const CUSTOM_REPORT_ID: &str = "\0custom";

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
    /// Open (creating if needed) the store in `data_dir`: database `<data_dir>/adblocker.redb`,
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

    pub fn put_content(&self, id: &str, content: &str) -> Result<()> {
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

    /// Seed the default lists on a fresh install (no-op if any list exists), in one transaction.
    pub fn seed_defaults_if_empty(&self) -> Result<()> {
        let defaults = default_filter_lists();
        let seeded = self.wtx(Durability::Immediate, |t| {
            let mut tb = t.open_table(tables::LISTS).map_err(db_err)?;
            if !tb.is_empty().map_err(db_err)? {
                return Ok(false);
            }
            for l in &defaults {
                tb.insert(l.id.as_str(), ser(l)?.as_slice())
                    .map_err(db_err)?;
            }
            Ok::<_, Error>(true)
        })?;
        if seeded {
            info!("Seeded {} default filter lists", defaults.len());
        }
        Ok(())
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

    #[test]
    fn seed_defaults_only_when_empty() {
        let (store, _d) = temp_store();
        store.seed_defaults_if_empty().unwrap();
        let n = store.get_all().unwrap().len();
        assert!(n >= 4);
        store.remove("easylist").unwrap();
        store.seed_defaults_if_empty().unwrap();
        assert_eq!(store.get_all().unwrap().len(), n - 1);
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

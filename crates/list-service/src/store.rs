//! Persistent storage of list metadata, raw list content, per-list status and custom rules.
//!
//! Backed by sled today; everything sled-specific is private to this module so the backend can be
//! swapped without touching callers.

use std::path::Path;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use filter_engine::{default_filter_lists, FilterList};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{Error, Result};

const LISTS_TREE: &str = "filter_lists";
const CONTENT_TREE: &str = "filter_content";
const META_TREE: &str = "filter_meta";
const STATUS_TREE: &str = "filter_status";
const CUSTOM_RULES_KEY: &str = "custom_rules";

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
}

/// Sled-backed store.
pub struct ListStore {
    db: sled::Db,
}

fn ser<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(v).map_err(|e| Error::Storage(e.to_string()))
}

fn de<T: for<'a> Deserialize<'a>>(b: &[u8]) -> Result<T> {
    serde_json::from_slice(b).map_err(|e| Error::Storage(e.to_string()))
}

impl ListStore {
    /// Open (creating if needed) the store at `path`.
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Storage(format!("create store dir: {e}")))?;
        }
        Ok(Self {
            db: sled::open(path)?,
        })
    }

    /// Open the store at `<data_dir>/lists`.
    pub fn open(data_dir: &Path) -> Result<Arc<Self>> {
        Ok(Arc::new(Self::new(data_dir.join("lists"))?))
    }

    fn tree(&self, name: &str) -> Result<sled::Tree> {
        Ok(self.db.open_tree(name)?)
    }

    pub fn get_custom_rules(&self) -> Result<String> {
        Ok(match self.tree(META_TREE)?.get(CUSTOM_RULES_KEY)? {
            Some(b) => String::from_utf8_lossy(&b).into_owned(),
            None => String::new(),
        })
    }

    pub fn set_custom_rules(&self, rules: &str) -> Result<()> {
        self.tree(META_TREE)?
            .insert(CUSTOM_RULES_KEY, rules.as_bytes())?;
        Ok(())
    }

    pub fn put_content(&self, id: &str, content: &str) -> Result<()> {
        self.tree(CONTENT_TREE)?.insert(id, content.as_bytes())?;
        Ok(())
    }

    pub fn get_content(&self, id: &str) -> Result<Option<String>> {
        Ok(self
            .tree(CONTENT_TREE)?
            .get(id)?
            .map(|b| String::from_utf8_lossy(&b).into_owned()))
    }

    pub fn upsert(&self, list: &FilterList) -> Result<()> {
        self.tree(LISTS_TREE)?
            .insert(list.id.as_bytes(), ser(list)?)?;
        Ok(())
    }

    pub fn get(&self, id: &str) -> Result<Option<FilterList>> {
        self.tree(LISTS_TREE)?.get(id)?.map(|b| de(&b)).transpose()
    }

    /// All lists, sorted by name.
    pub fn get_all(&self) -> Result<Vec<FilterList>> {
        let mut lists = Vec::new();
        for item in self.tree(LISTS_TREE)?.iter() {
            let (_, v) = item?;
            lists.push(de::<FilterList>(&v)?);
        }
        lists.sort_by_key(|l| l.name.to_lowercase());
        Ok(lists)
    }

    pub fn exists(&self, id: &str) -> Result<bool> {
        Ok(self.tree(LISTS_TREE)?.contains_key(id)?)
    }

    pub fn set_enabled(&self, id: &str, enabled: bool) -> Result<bool> {
        match self.get(id)? {
            Some(mut l) => {
                l.enabled = enabled;
                self.upsert(&l)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Remove a list with its cached content and status.
    pub fn remove(&self, id: &str) -> Result<bool> {
        let removed = self.tree(LISTS_TREE)?.remove(id)?.is_some();
        self.tree(CONTENT_TREE)?.remove(id)?;
        self.tree(STATUS_TREE)?.remove(id)?;
        Ok(removed)
    }

    pub fn get_status(&self, id: &str) -> Result<ListStatus> {
        Ok(match self.tree(STATUS_TREE)?.get(id)? {
            Some(b) => de(&b)?,
            None => ListStatus::default(),
        })
    }

    pub fn set_status(&self, id: &str, status: &ListStatus) -> Result<()> {
        self.tree(STATUS_TREE)?.insert(id, ser(status)?)?;
        Ok(())
    }

    /// Seed the default lists on a fresh install (no-op if any list exists).
    pub fn seed_defaults_if_empty(&self) -> Result<()> {
        if !self.tree(LISTS_TREE)?.is_empty() {
            return Ok(());
        }
        let defaults = default_filter_lists();
        for l in &defaults {
            self.upsert(l)?;
        }
        info!("Seeded {} default filter lists", defaults.len());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (ListStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = ListStore::new(dir.path().join("lists")).unwrap();
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
    }

    #[test]
    fn data_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lists");
        {
            let store = ListStore::new(&path).unwrap();
            let mut l = FilterList::new("keep".into(), "Keep".into(), "https://e/k.txt".into());
            l.rule_count = 42;
            store.upsert(&l).unwrap();
            store.put_content("keep", "||ads.example^\n").unwrap();
            store.set_custom_rules("||my.ads^\n").unwrap();
        }
        let store = ListStore::new(&path).unwrap();
        assert_eq!(store.get("keep").unwrap().unwrap().rule_count, 42);
        assert_eq!(
            store.get_content("keep").unwrap().as_deref(),
            Some("||ads.example^\n")
        );
        assert_eq!(store.get_custom_rules().unwrap(), "||my.ads^\n");
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
}

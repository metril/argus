//! Persistent storage for filter-list metadata.
//!
//! Filter lists used to live only in an in-memory `HashMap` inside the (never-shared) filter
//! engine, so anything a user added vanished immediately. This store persists the metadata in Sled
//! — the same embedded database already used for user accounts — so lists survive navigation,
//! restarts, and feed the compile/reload pipeline. It mirrors the `SessionStore` pattern in
//! [`crate::state`].

use crate::error::{ApiError, ApiResult};
use filter_engine::{default_filter_lists, FilterList};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

const LISTS_TREE: &str = "filter_lists";
const CONTENT_TREE: &str = "filter_content";
const META_TREE: &str = "filter_meta";
const CUSTOM_RULES_KEY: &str = "custom_rules";

/// Sled-backed persistent store of [`FilterList`] metadata, keyed by list id.
pub struct FilterListStore {
    db: sled::Db,
}

impl FilterListStore {
    /// Open (creating if needed) the store at `path`.
    pub fn new(path: PathBuf) -> ApiResult<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| ApiError::Internal(format!("create filter store dir: {e}")))?;
        }
        let db = sled::open(path)?;
        Ok(Self { db })
    }

    fn tree(&self) -> ApiResult<sled::Tree> {
        Ok(self.db.open_tree(LISTS_TREE)?)
    }

    fn content_tree(&self) -> ApiResult<sled::Tree> {
        Ok(self.db.open_tree(CONTENT_TREE)?)
    }

    fn meta_tree(&self) -> ApiResult<sled::Tree> {
        Ok(self.db.open_tree(META_TREE)?)
    }

    /// Get the user's custom filter rules (raw adblock syntax, one per line; may include `@@`
    /// allow rules and cosmetic rules). Empty string if unset.
    pub fn get_custom_rules(&self) -> ApiResult<String> {
        match self.meta_tree()?.get(CUSTOM_RULES_KEY.as_bytes())? {
            Some(bytes) => Ok(String::from_utf8_lossy(&bytes).into_owned()),
            None => Ok(String::new()),
        }
    }

    /// Replace the user's custom filter rules.
    pub fn set_custom_rules(&self, rules: &str) -> ApiResult<()> {
        self.meta_tree()?
            .insert(CUSTOM_RULES_KEY.as_bytes(), rules.as_bytes())?;
        Ok(())
    }

    /// Cache the downloaded raw text of a list (used to rebuild the engine on a `304`/failure).
    pub fn put_content(&self, id: &str, content: &str) -> ApiResult<()> {
        self.content_tree()?
            .insert(id.as_bytes(), content.as_bytes())?;
        Ok(())
    }

    /// Read the cached raw text of a list, if any.
    pub fn get_content(&self, id: &str) -> ApiResult<Option<String>> {
        match self.content_tree()?.get(id.as_bytes())? {
            Some(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).into_owned())),
            None => Ok(None),
        }
    }

    /// Insert or replace a list (upsert by id).
    pub fn upsert(&self, list: &FilterList) -> ApiResult<()> {
        let tree = self.tree()?;
        let bytes = serde_json::to_vec(list).map_err(|e| ApiError::Internal(e.to_string()))?;
        tree.insert(list.id.as_bytes(), bytes)?;
        Ok(())
    }

    /// Fetch a single list by id.
    pub fn get(&self, id: &str) -> ApiResult<Option<FilterList>> {
        let tree = self.tree()?;
        match tree.get(id.as_bytes())? {
            Some(bytes) => {
                let list: FilterList = serde_json::from_slice(&bytes)
                    .map_err(|e| ApiError::Internal(e.to_string()))?;
                Ok(Some(list))
            }
            None => Ok(None),
        }
    }

    /// Return all lists, sorted by name for stable display order.
    pub fn get_all(&self) -> ApiResult<Vec<FilterList>> {
        let tree = self.tree()?;
        let mut lists = Vec::new();
        for item in tree.iter() {
            let (_, value) = item.map_err(|e| ApiError::Internal(e.to_string()))?;
            let list: FilterList =
                serde_json::from_slice(&value).map_err(|e| ApiError::Internal(e.to_string()))?;
            lists.push(list);
        }
        lists.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        Ok(lists)
    }

    /// Whether a list with this id exists.
    pub fn exists(&self, id: &str) -> ApiResult<bool> {
        Ok(self.tree()?.contains_key(id.as_bytes())?)
    }

    /// Enable or disable a list; returns false if it doesn't exist.
    pub fn set_enabled(&self, id: &str, enabled: bool) -> ApiResult<bool> {
        match self.get(id)? {
            Some(mut list) => {
                list.enabled = enabled;
                self.upsert(&list)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Remove a list (and its cached content); returns false if it didn't exist.
    pub fn remove(&self, id: &str) -> ApiResult<bool> {
        let removed = self.tree()?.remove(id.as_bytes())?.is_some();
        self.content_tree()?.remove(id.as_bytes())?;
        Ok(removed)
    }

    /// Seed the default filter lists on a fresh install (no-op if any list already exists).
    pub fn seed_defaults_if_empty(&self) -> ApiResult<()> {
        let tree = self.tree()?;
        if !tree.is_empty() {
            return Ok(());
        }
        for list in default_filter_lists() {
            self.upsert(&list)?;
        }
        info!(
            "Seeded {} default filter lists",
            default_filter_lists().len()
        );
        Ok(())
    }
}

/// Convenience: open a store at the adblock data directory's `lists` subdirectory.
pub fn open_filter_store(adblock_data_dir: &std::path::Path) -> ApiResult<Arc<FilterListStore>> {
    let path = adblock_data_dir.join("lists");
    Ok(Arc::new(FilterListStore::new(path)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (FilterListStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = FilterListStore::new(dir.path().join("lists")).unwrap();
        (store, dir)
    }

    #[test]
    fn upsert_get_remove_roundtrip() {
        let (store, _d) = temp_store();
        let list = FilterList::new("l1".into(), "List One".into(), "https://e/x.txt".into());
        store.upsert(&list).unwrap();

        assert!(store.exists("l1").unwrap());
        assert_eq!(store.get("l1").unwrap().unwrap().name, "List One");

        assert!(store.set_enabled("l1", false).unwrap());
        assert!(!store.get("l1").unwrap().unwrap().enabled);

        assert!(store.remove("l1").unwrap());
        assert!(!store.exists("l1").unwrap());
        assert!(!store.remove("l1").unwrap());
    }

    #[test]
    fn custom_rules_roundtrip_and_persist() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lists");
        {
            let store = FilterListStore::new(path.clone()).unwrap();
            assert_eq!(store.get_custom_rules().unwrap(), "");
            store
                .set_custom_rules("||my.ads^\n@@||good.example^\n")
                .unwrap();
        }
        let store = FilterListStore::new(path).unwrap();
        assert_eq!(
            store.get_custom_rules().unwrap(),
            "||my.ads^\n@@||good.example^\n"
        );
    }

    #[test]
    fn data_survives_reopen() {
        // The reported bug: lists vanished. Prove they persist across a store reopen
        // (i.e. a process restart).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lists");
        {
            let store = FilterListStore::new(path.clone()).unwrap();
            let mut list =
                FilterList::new("keep".into(), "Keep Me".into(), "https://e/k.txt".into());
            list.rule_count = 42;
            store.upsert(&list).unwrap();
            store.put_content("keep", "||ads.example^\n").unwrap();
        } // store dropped — simulates shutdown

        let store = FilterListStore::new(path).unwrap();
        let got = store
            .get("keep")
            .unwrap()
            .expect("list persisted across reopen");
        assert_eq!(got.name, "Keep Me");
        assert_eq!(got.rule_count, 42);
        assert_eq!(
            store.get_content("keep").unwrap().as_deref(),
            Some("||ads.example^\n")
        );
    }

    #[test]
    fn seed_defaults_only_when_empty() {
        let (store, _d) = temp_store();
        store.seed_defaults_if_empty().unwrap();
        let n = store.get_all().unwrap().len();
        assert!(n >= 4);

        // Removing one then re-seeding must NOT re-add (tree is non-empty).
        store.remove("easylist").unwrap();
        store.seed_defaults_if_empty().unwrap();
        assert_eq!(store.get_all().unwrap().len(), n - 1);
    }
}

//! Userscript storage (GM_setValue/GM_getValue) on the shared redb database
//!
//! Provides persistent storage for userscript data (GM_setValue/GM_getValue)

use crate::{Error, Result};
use common::db::redb::{Durability, ReadableTable, WriteTransaction};
use common::db::{tables, Db, DbError};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::debug;

/// Storage value that can be any JSON-serializable type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum StorageValue {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<StorageValue>),
    Object(HashMap<String, StorageValue>),
}

impl From<Value> for StorageValue {
    fn from(value: Value) -> Self {
        match value {
            Value::Null => StorageValue::Null,
            Value::Bool(b) => StorageValue::Bool(b),
            Value::Number(n) => StorageValue::Number(n.as_f64().unwrap_or(0.0)),
            Value::String(s) => StorageValue::String(s),
            Value::Array(arr) => {
                StorageValue::Array(arr.into_iter().map(StorageValue::from).collect())
            }
            Value::Object(obj) => {
                let map = obj
                    .into_iter()
                    .map(|(k, v)| (k, StorageValue::from(v)))
                    .collect();
                StorageValue::Object(map)
            }
        }
    }
}

impl From<StorageValue> for Value {
    fn from(val: StorageValue) -> Self {
        match val {
            StorageValue::Null => Value::Null,
            StorageValue::Bool(b) => Value::Bool(b),
            StorageValue::Number(n) => {
                // If the number is a whole integer that fits in i64, use integer representation
                // This preserves equality with the original value (42 == 42, not 42.0)
                if n.fract() == 0.0 && n >= i64::MIN as f64 && n <= i64::MAX as f64 {
                    Value::Number((n as i64).into())
                } else {
                    Value::Number(serde_json::Number::from_f64(n).unwrap_or_else(|| 0.into()))
                }
            }
            StorageValue::String(s) => Value::String(s),
            StorageValue::Array(arr) => Value::Array(arr.into_iter().map(Value::from).collect()),
            StorageValue::Object(obj) => {
                let map = obj.into_iter().map(|(k, v)| (k, Value::from(v))).collect();
                Value::Object(map)
            }
        }
    }
}

fn db_err(e: impl Into<DbError>) -> Error {
    Error::Storage(e.into().to_string())
}

/// Userscript storage manager
///
/// Writes are queued to the database's coalescing writer (no fsync, off the calling thread);
/// an in-memory cache keeps reads consistent with queued writes.
pub struct UserscriptStorage {
    db: Arc<Db>,
    /// In-memory cache for performance
    cache: Arc<RwLock<HashMap<String, StorageValue>>>,
}

impl UserscriptStorage {
    /// Open the shared database in `data_dir`.
    pub fn new(data_dir: PathBuf) -> Result<Self> {
        let db = Db::open(&data_dir)
            .map_err(|e| Error::Storage(format!("Failed to open database at {data_dir:?}: {e}")))?;
        Ok(Self::with_db(db))
    }

    /// Use an already-open shared database.
    pub fn with_db(db: Arc<Db>) -> Self {
        debug!("Userscript storage on {:?}", db.dir());
        Self {
            db,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generate storage key for a script and value name
    fn make_key(script_id: &str, name: &str) -> String {
        format!("{script_id}\0{name}")
    }

    /// Get a value from storage
    pub fn get_value(&self, script_id: &str, name: &str) -> Result<Option<StorageValue>> {
        let key = Self::make_key(script_id, name);

        if let Some(value) = self.cache.read().get(&key) {
            return Ok(Some(value.clone()));
        }

        let bytes = self.db.read(|r| {
            let t = r.open_table(tables::GM_VALUES).map_err(db_err)?;
            let v = t
                .get(key.as_str())
                .map_err(db_err)?
                .map(|g| g.value().to_vec());
            Ok::<_, Error>(v)
        })?;
        match bytes {
            Some(bytes) => {
                let value: StorageValue = serde_json::from_slice(&bytes).map_err(|e| {
                    Error::Storage(format!("Failed to deserialize value for {key}: {e}"))
                })?;
                self.cache.write().insert(key, value.clone());
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    /// Set a value in storage (queued; visible to reads immediately).
    pub fn set_value(&self, script_id: &str, name: &str, value: StorageValue) -> Result<()> {
        let key = Self::make_key(script_id, name);
        let bytes = serde_json::to_vec(&value)
            .map_err(|e| Error::Storage(format!("Failed to serialize value for {key}: {e}")))?;
        self.cache.write().insert(key.clone(), value);
        self.db.defer(move |t| {
            t.open_table(tables::GM_VALUES)?
                .insert(key.as_str(), bytes.as_slice())?;
            Ok(())
        });
        Ok(())
    }

    /// Delete a value from storage
    pub fn delete_value(&self, script_id: &str, name: &str) -> Result<()> {
        let key = Self::make_key(script_id, name);
        // Queued sets must land before the delete, or they would resurrect the value.
        self.db.flush_deferred();
        self.db.write(Durability::Eventual, |t| {
            t.open_table(tables::GM_VALUES)
                .map_err(db_err)?
                .remove(key.as_str())
                .map_err(db_err)?;
            Ok::<_, Error>(())
        })?;
        self.cache.write().remove(&key);
        Ok(())
    }

    /// List all value names for a script
    pub fn list_values(&self, script_id: &str) -> Result<Vec<String>> {
        self.db.flush_deferred();
        let (lo, hi) = (format!("{script_id}\0"), format!("{script_id}\u{1}"));
        self.db.read(|r| {
            let t = r.open_table(tables::GM_VALUES).map_err(db_err)?;
            let mut names = Vec::new();
            for item in t.range(lo.as_str()..hi.as_str()).map_err(db_err)? {
                let (k, _) = item.map_err(db_err)?;
                if let Some(name) = k.value().strip_prefix(lo.as_str()) {
                    names.push(name.to_string());
                }
            }
            Ok::<_, Error>(names)
        })
    }

    /// Remove every value of `script_id` inside an existing transaction.
    pub(crate) fn clear_in_txn(txn: &WriteTransaction, script_id: &str) -> Result<()> {
        let (lo, hi) = (format!("{script_id}\0"), format!("{script_id}\u{1}"));
        let mut t = txn.open_table(tables::GM_VALUES).map_err(db_err)?;
        let keys: Vec<String> = t
            .range(lo.as_str()..hi.as_str())
            .map_err(db_err)?
            .map(|i| i.map(|(k, _)| k.value().to_string()))
            .collect::<std::result::Result<_, _>>()
            .map_err(db_err)?;
        for k in keys {
            t.remove(k.as_str()).map_err(db_err)?;
        }
        Ok(())
    }

    /// Forget cached values of a script.
    pub(crate) fn drop_cache(&self, script_id: &str) {
        let prefix = format!("{script_id}\0");
        self.cache.write().retain(|k, _| !k.starts_with(&prefix));
    }

    /// Clear all values for a script
    pub fn clear_script_storage(&self, script_id: &str) -> Result<()> {
        self.db.flush_deferred();
        self.db
            .write(Durability::Eventual, |t| Self::clear_in_txn(t, script_id))?;
        self.drop_cache(script_id);
        Ok(())
    }

    /// Get database size in bytes
    pub fn size_on_disk(&self) -> Result<u64> {
        Ok(self.db.file_size())
    }

    /// Wait for queued writes to be committed.
    pub fn flush(&self) -> Result<()> {
        self.db.flush_deferred();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_storage_basic_operations() {
        let temp_dir = tempdir().unwrap();
        let storage = UserscriptStorage::new(temp_dir.path().to_path_buf()).unwrap();

        // Test set and get
        storage
            .set_value("test-script", "count", StorageValue::Number(42.0))
            .unwrap();

        let value = storage.get_value("test-script", "count").unwrap();
        assert!(matches!(value, Some(StorageValue::Number(n)) if n == 42.0));

        // Test delete
        storage.delete_value("test-script", "count").unwrap();
        let value = storage.get_value("test-script", "count").unwrap();
        assert!(value.is_none());
    }

    #[test]
    fn test_storage_types() {
        let temp_dir = tempdir().unwrap();
        let storage = UserscriptStorage::new(temp_dir.path().to_path_buf()).unwrap();

        // String
        storage
            .set_value("script1", "name", StorageValue::String("test".to_string()))
            .unwrap();

        // Boolean
        storage
            .set_value("script1", "enabled", StorageValue::Bool(true))
            .unwrap();

        // Array
        storage
            .set_value(
                "script1",
                "items",
                StorageValue::Array(vec![StorageValue::Number(1.0), StorageValue::Number(2.0)]),
            )
            .unwrap();

        assert!(matches!(
            storage.get_value("script1", "name").unwrap(),
            Some(StorageValue::String(_))
        ));
        assert!(matches!(
            storage.get_value("script1", "enabled").unwrap(),
            Some(StorageValue::Bool(true))
        ));
        assert!(matches!(
            storage.get_value("script1", "items").unwrap(),
            Some(StorageValue::Array(_))
        ));
    }

    #[test]
    fn test_list_values() {
        let temp_dir = tempdir().unwrap();
        let storage = UserscriptStorage::new(temp_dir.path().to_path_buf()).unwrap();

        storage
            .set_value(
                "script1",
                "key1",
                StorageValue::String("value1".to_string()),
            )
            .unwrap();
        storage
            .set_value(
                "script1",
                "key2",
                StorageValue::String("value2".to_string()),
            )
            .unwrap();
        storage
            .set_value(
                "script2",
                "key1",
                StorageValue::String("value3".to_string()),
            )
            .unwrap();

        let keys = storage.list_values("script1").unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"key1".to_string()));
        assert!(keys.contains(&"key2".to_string()));
    }

    #[test]
    fn test_clear_script_storage() {
        let temp_dir = tempdir().unwrap();
        let storage = UserscriptStorage::new(temp_dir.path().to_path_buf()).unwrap();

        storage
            .set_value("script1", "key1", StorageValue::Number(1.0))
            .unwrap();
        storage
            .set_value("script1", "key2", StorageValue::Number(2.0))
            .unwrap();

        storage.clear_script_storage("script1").unwrap();

        let keys = storage.list_values("script1").unwrap();
        assert_eq!(keys.len(), 0);
    }

    #[test]
    fn test_cache() {
        let temp_dir = tempdir().unwrap();
        let storage = UserscriptStorage::new(temp_dir.path().to_path_buf()).unwrap();

        storage
            .set_value("script1", "cached", StorageValue::Number(100.0))
            .unwrap();

        // First access - from database
        let value1 = storage.get_value("script1", "cached").unwrap();

        // Second access - from cache
        let value2 = storage.get_value("script1", "cached").unwrap();

        assert!(matches!(value1, Some(StorageValue::Number(n)) if n == 100.0));
        assert_eq!(value1, value2);
    }
}

#[cfg(test)]
mod persistence_tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn values_survive_reopen_and_delete_sticks() {
        let dir = tempdir().unwrap();
        {
            let s = UserscriptStorage::new(dir.path().to_path_buf()).unwrap();
            s.set_value("s", "keep", StorageValue::Number(1.0)).unwrap();
            s.set_value("s", "gone", StorageValue::Bool(true)).unwrap();
            s.delete_value("s", "gone").unwrap();
            s.set_value("t", "other", StorageValue::Null).unwrap();
        }
        let s = UserscriptStorage::new(dir.path().to_path_buf()).unwrap();
        assert_eq!(
            s.get_value("s", "keep").unwrap(),
            Some(StorageValue::Number(1.0))
        );
        assert_eq!(s.get_value("s", "gone").unwrap(), None);
        assert_eq!(s.list_values("s").unwrap(), vec!["keep".to_string()]);
        // Prefix ids do not leak into each other.
        s.set_value("s2", "x", StorageValue::Null).unwrap();
        s.clear_script_storage("s").unwrap();
        assert_eq!(s.get_value("s2", "x").unwrap(), Some(StorageValue::Null));
        assert!(s.list_values("s").unwrap().is_empty());
    }
}

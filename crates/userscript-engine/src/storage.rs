//! Userscript storage using sled database
//!
//! Provides persistent storage for userscript data (GM_setValue/GM_getValue)

use crate::{Error, Result};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sled::Db;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, warn};

/// Storage value that can be any JSON-serializable type
#[derive(Debug, Clone, Serialize, Deserialize)]
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
                Value::Number(serde_json::Number::from_f64(n).unwrap_or_else(|| 0.into()))
            }
            StorageValue::String(s) => Value::String(s),
            StorageValue::Array(arr) => {
                Value::Array(arr.into_iter().map(Value::from).collect())
            }
            StorageValue::Object(obj) => {
                let map = obj.into_iter().map(|(k, v)| (k, Value::from(v))).collect();
                Value::Object(map)
            }
        }
    }
}

/// Userscript storage manager
pub struct UserscriptStorage {
    /// Sled database
    db: Arc<Db>,
    /// In-memory cache for performance
    cache: Arc<RwLock<HashMap<String, StorageValue>>>,
}

impl UserscriptStorage {
    /// Create a new storage instance
    pub fn new(data_dir: PathBuf) -> Result<Self> {
        let db_path = data_dir.join("userscript-storage");
        let db = sled::open(&db_path).map_err(|e| {
            Error::Storage(format!("Failed to open database at {:?}: {}", db_path, e))
        })?;

        debug!("Opened userscript storage database at {:?}", db_path);

        Ok(Self {
            db: Arc::new(db),
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Generate storage key for a script and value name
    fn make_key(script_id: &str, name: &str) -> String {
        format!("{}:{}", script_id, name)
    }

    /// Get a value from storage
    pub fn get_value(&self, script_id: &str, name: &str) -> Result<Option<StorageValue>> {
        let key = Self::make_key(script_id, name);

        // Check cache first
        {
            let cache = self.cache.read();
            if let Some(value) = cache.get(&key) {
                return Ok(Some(value.clone()));
            }
        }

        // Fetch from database
        match self.db.get(&key) {
            Ok(Some(bytes)) => {
                let value: StorageValue = serde_json::from_slice(&bytes).map_err(|e| {
                    Error::Storage(format!("Failed to deserialize value for {}: {}", key, e))
                })?;

                // Update cache
                self.cache.write().insert(key, value.clone());

                Ok(Some(value))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(Error::Storage(format!(
                "Failed to get value for {}: {}",
                key, e
            ))),
        }
    }

    /// Set a value in storage
    pub fn set_value(&self, script_id: &str, name: &str, value: StorageValue) -> Result<()> {
        let key = Self::make_key(script_id, name);

        // Serialize value
        let bytes = serde_json::to_vec(&value).map_err(|e| {
            Error::Storage(format!("Failed to serialize value for {}: {}", key, e))
        })?;

        // Write to database
        self.db
            .insert(&key, bytes)
            .map_err(|e| Error::Storage(format!("Failed to set value for {}: {}", key, e)))?;

        // Update cache
        self.cache.write().insert(key, value);

        // Flush to disk
        self.db.flush().ok();

        Ok(())
    }

    /// Delete a value from storage
    pub fn delete_value(&self, script_id: &str, name: &str) -> Result<()> {
        let key = Self::make_key(script_id, name);

        // Remove from database
        self.db
            .remove(&key)
            .map_err(|e| Error::Storage(format!("Failed to delete value for {}: {}", key, e)))?;

        // Remove from cache
        self.cache.write().remove(&key);

        Ok(())
    }

    /// List all value names for a script
    pub fn list_values(&self, script_id: &str) -> Result<Vec<String>> {
        let prefix = format!("{}:", script_id);
        let mut names = Vec::new();

        for item in self.db.scan_prefix(&prefix) {
            match item {
                Ok((key_bytes, _)) => {
                    if let Ok(key) = std::str::from_utf8(&key_bytes) {
                        if let Some(name) = key.strip_prefix(&prefix) {
                            names.push(name.to_string());
                        }
                    }
                }
                Err(e) => {
                    warn!("Error scanning storage: {}", e);
                }
            }
        }

        Ok(names)
    }

    /// Clear all values for a script
    pub fn clear_script_storage(&self, script_id: &str) -> Result<()> {
        let prefix = format!("{}:", script_id);
        let mut batch = sled::Batch::default();

        // Collect keys to delete
        for item in self.db.scan_prefix(&prefix) {
            if let Ok((key, _)) = item {
                batch.remove(key);
            }
        }

        // Apply batch deletion
        self.db
            .apply_batch(batch)
            .map_err(|e| Error::Storage(format!("Failed to clear storage: {}", e)))?;

        // Clear from cache
        let mut cache = self.cache.write();
        cache.retain(|k, _| !k.starts_with(&prefix));

        Ok(())
    }

    /// Get database size in bytes
    pub fn size_on_disk(&self) -> Result<u64> {
        self.db
            .size_on_disk()
            .map_err(|e| Error::Storage(format!("Failed to get database size: {}", e)))
    }

    /// Flush all pending writes to disk
    pub fn flush(&self) -> Result<()> {
        self.db
            .flush()
            .map_err(|e| Error::Storage(format!("Failed to flush database: {}", e)))?;
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
            .set_value(
                "test-script",
                "count",
                StorageValue::Number(42.0),
            )
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
            .set_value(
                "script1",
                "name",
                StorageValue::String("test".to_string()),
            )
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
                StorageValue::Array(vec![
                    StorageValue::Number(1.0),
                    StorageValue::Number(2.0),
                ]),
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
            .set_value("script1", "key1", StorageValue::String("value1".to_string()))
            .unwrap();
        storage
            .set_value("script1", "key2", StorageValue::String("value2".to_string()))
            .unwrap();
        storage
            .set_value("script2", "key1", StorageValue::String("value3".to_string()))
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

        assert_eq!(
            matches!(value1, Some(StorageValue::Number(n)) if n == 100.0),
            true
        );
        assert_eq!(value1, value2);
    }
}

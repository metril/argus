//! GM_* API implementation
//!
//! Provides Greasemonkey/Tampermonkey API functions for userscripts.
//! This Week 13 implementation focuses on storage APIs as foundation.
//! Week 14 will add GM_xmlhttpRequest, GM_notification, etc.

use crate::{storage::{StorageValue, UserscriptStorage}, Error, Result};
use serde_json::Value;
use std::sync::Arc;
use tracing::debug;

/// GM API context for a specific userscript
pub struct GmApi {
    /// Script ID for storage isolation
    script_id: String,
    /// Storage instance
    storage: Arc<UserscriptStorage>,
    /// Granted capabilities
    grants: Vec<String>,
}

impl GmApi {
    /// Create a new GM API context
    pub fn new(script_id: String, storage: Arc<UserscriptStorage>, grants: Vec<String>) -> Self {
        Self {
            script_id,
            storage,
            grants,
        }
    }

    /// Check if a capability is granted
    fn has_grant(&self, capability: &str) -> Result<()> {
        if self.grants.contains(&capability.to_string()) {
            Ok(())
        } else {
            Err(Error::PermissionDenied(format!(
                "Missing @grant {} declaration",
                capability
            )))
        }
    }

    /// GM_setValue - Store a value
    ///
    /// Stores a value persistently for this script.
    /// Supports string, number, boolean, null, arrays, and objects.
    pub fn set_value(&self, name: &str, value: Value) -> Result<()> {
        self.has_grant("GM_setValue")?;

        debug!("GM_setValue: {} = {:?}", name, value);

        let storage_value = StorageValue::from(value);
        self.storage.set_value(&self.script_id, name, storage_value)
    }

    /// GM_getValue - Retrieve a value
    ///
    /// Retrieves a stored value, or returns the default if not found.
    pub fn get_value(&self, name: &str, default_value: Option<Value>) -> Result<Value> {
        self.has_grant("GM_getValue")?;

        match self.storage.get_value(&self.script_id, name)? {
            Some(storage_value) => {
                let value = Value::from(storage_value);
                debug!("GM_getValue: {} = {:?}", name, value);
                Ok(value)
            }
            None => {
                let default = default_value.unwrap_or(Value::Null);
                debug!("GM_getValue: {} = {:?} (default)", name, default);
                Ok(default)
            }
        }
    }

    /// GM_deleteValue - Delete a value
    ///
    /// Removes a stored value.
    pub fn delete_value(&self, name: &str) -> Result<()> {
        self.has_grant("GM_deleteValue")?;

        debug!("GM_deleteValue: {}", name);

        self.storage.delete_value(&self.script_id, name)
    }

    /// GM_listValues - List all value names
    ///
    /// Returns an array of all stored value names for this script.
    pub fn list_values(&self) -> Result<Vec<String>> {
        self.has_grant("GM_listValues")?;

        let values = self.storage.list_values(&self.script_id)?;

        debug!("GM_listValues: {} keys", values.len());

        Ok(values)
    }

    /// GM_info - Get script and environment info
    ///
    /// Returns metadata about the script and runtime environment.
    pub fn info(&self) -> Value {
        serde_json::json!({
            "script": {
                "id": self.script_id,
                "grants": self.grants,
            },
            "scriptHandler": "AdBlocker Userscript Engine",
            "version": env!("CARGO_PKG_VERSION"),
        })
    }

    /// GM_log - Log a message (deprecated but supported)
    ///
    /// Logs a message. Modern scripts should use console.log instead.
    pub fn log(&self, message: &str) {
        debug!("GM_log: {}", message);
        println!("[{}] {}", self.script_id, message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn create_test_api() -> GmApi {
        let temp_dir = tempdir().unwrap();
        let storage = Arc::new(UserscriptStorage::new(temp_dir.path().to_path_buf()).unwrap());
        let grants = vec![
            "GM_setValue".to_string(),
            "GM_getValue".to_string(),
            "GM_deleteValue".to_string(),
            "GM_listValues".to_string(),
        ];

        GmApi::new("test-script".to_string(), storage, grants)
    }

    #[test]
    fn test_set_get_value() {
        let api = create_test_api();

        // Set a number
        api.set_value("count", Value::Number(42.into())).unwrap();

        // Get the value
        let value = api.get_value("count", None).unwrap();
        assert_eq!(value, Value::Number(42.into()));
    }

    #[test]
    fn test_get_default_value() {
        let api = create_test_api();

        // Get non-existent value with default
        let value = api
            .get_value("missing", Some(Value::String("default".to_string())))
            .unwrap();
        assert_eq!(value, Value::String("default".to_string()));
    }

    #[test]
    fn test_delete_value() {
        let api = create_test_api();

        api.set_value("temp", Value::String("test".to_string()))
            .unwrap();
        api.delete_value("temp").unwrap();

        let value = api.get_value("temp", None).unwrap();
        assert_eq!(value, Value::Null);
    }

    #[test]
    fn test_list_values() {
        let api = create_test_api();

        api.set_value("key1", Value::Number(1.into())).unwrap();
        api.set_value("key2", Value::Number(2.into())).unwrap();

        let keys = api.list_values().unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"key1".to_string()));
        assert!(keys.contains(&"key2".to_string()));
    }

    #[test]
    fn test_permission_check() {
        let temp_dir = tempdir().unwrap();
        let storage = Arc::new(UserscriptStorage::new(temp_dir.path().to_path_buf()).unwrap());
        let api = GmApi::new("test-script".to_string(), storage, vec![]); // No grants

        let result = api.set_value("test", Value::Null);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::PermissionDenied(_))));
    }

    #[test]
    fn test_info() {
        let api = create_test_api();
        let info = api.info();

        assert!(info["script"]["id"].is_string());
        assert!(info["scriptHandler"].is_string());
        assert!(info["version"].is_string());
    }

    #[test]
    fn test_value_types() {
        let api = create_test_api();

        // String
        api.set_value("str", Value::String("hello".to_string()))
            .unwrap();
        assert_eq!(
            api.get_value("str", None).unwrap(),
            Value::String("hello".to_string())
        );

        // Boolean
        api.set_value("bool", Value::Bool(true)).unwrap();
        assert_eq!(api.get_value("bool", None).unwrap(), Value::Bool(true));

        // Array
        let arr = Value::Array(vec![Value::Number(1.into()), Value::Number(2.into())]);
        api.set_value("arr", arr.clone()).unwrap();
        let retrieved = api.get_value("arr", None).unwrap();
        assert!(retrieved.is_array());

        // Object
        let obj = serde_json::json!({"key": "value"});
        api.set_value("obj", obj.clone()).unwrap();
        let retrieved = api.get_value("obj", None).unwrap();
        assert!(retrieved.is_object());
    }
}

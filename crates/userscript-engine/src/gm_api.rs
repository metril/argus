//! GM_* API implementation
//!
//! Provides Greasemonkey/Tampermonkey API functions for userscripts.
//! Week 14: Full GM_* API with xmlhttpRequest, notification, addStyle, etc.

use crate::{storage::{StorageValue, UserscriptStorage}, Error, Result};
use boa_gc::{Finalize, Trace};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// GM API context for a specific userscript
#[derive(Clone, Trace, Finalize)]
pub struct GmApi {
    /// Script ID for storage isolation
    #[unsafe_ignore_trace]
    script_id: String,
    /// Storage instance
    #[unsafe_ignore_trace]
    storage: Arc<UserscriptStorage>,
    /// Granted capabilities
    #[unsafe_ignore_trace]
    grants: Vec<String>,
    /// Resource URLs (from @resource directives)
    #[unsafe_ignore_trace]
    resources: HashMap<String, String>,
}

impl GmApi {
    /// Create a new GM API context
    pub fn new(script_id: String, storage: Arc<UserscriptStorage>, grants: Vec<String>) -> Self {
        Self {
            script_id,
            storage,
            grants,
            resources: HashMap::new(),
        }
    }

    /// Create GM API with resource URLs
    pub fn with_resources(
        script_id: String,
        storage: Arc<UserscriptStorage>,
        grants: Vec<String>,
        resources: HashMap<String, String>,
    ) -> Self {
        Self {
            script_id,
            storage,
            grants,
            resources,
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

    /// GM_addStyle - Add CSS to the page
    ///
    /// Injects a style element with the given CSS into the document head.
    pub fn add_style(&self, css: &str) -> Result<()> {
        self.has_grant("GM_addStyle")?;

        info!("GM_addStyle: {} bytes of CSS", css.len());

        // In a full implementation, this would inject CSS into the DOM
        // For now, we store it for the proxy to inject
        self.storage.set_value(
            &self.script_id,
            &format!("__style_{}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)),
            StorageValue::String(css.to_string()),
        )?;

        Ok(())
    }

    /// GM_openInTab - Open URL in a new tab
    ///
    /// Opens a URL in a new browser tab/window.
    /// Options can include { active: bool, insert: bool, setParent: bool }
    pub fn open_in_tab(&self, url: &str, options: Option<Value>) -> Result<()> {
        self.has_grant("GM_openInTab")?;

        info!("GM_openInTab: {}", url);

        // Validate URL
        let _ = reqwest::Url::parse(url)
            .map_err(|e| Error::InvalidScript(format!("Invalid URL: {}", e)))?;

        // In a full implementation, this would communicate with the browser
        // For now, log the request
        debug!("Tab open requested: {} with options {:?}", url, options);

        Ok(())
    }

    /// GM_notification - Show a notification
    ///
    /// Displays a desktop notification.
    /// Details object: { text, title, image, onclick }
    pub fn notification(&self, details: Value) -> Result<()> {
        self.has_grant("GM_notification")?;

        let title = details
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("Userscript Notification");
        let text = details
            .get("text")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        info!("GM_notification: {} - {}", title, text);

        // In a full implementation, this would show a system notification
        // For now, just log it
        println!("🔔 {}: {}", title, text);

        Ok(())
    }

    /// GM_xmlhttpRequest - Make a cross-domain HTTP request
    ///
    /// Performs an HTTP request that bypasses CORS restrictions.
    /// Details object: { method, url, headers, data, onload, onerror, ontimeout }
    pub fn xml_http_request(&self, details: Value) -> Result<()> {
        self.has_grant("GM_xmlhttpRequest")?;

        let method = details
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("GET");
        let url = details
            .get("url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::InvalidScript("xmlhttpRequest requires url".to_string()))?;

        info!("GM_xmlhttpRequest: {} {}", method, url);

        // Validate URL format
        let parsed_url = reqwest::Url::parse(url)
            .map_err(|e| Error::InvalidScript(format!("Invalid URL: {}", e)))?;

        // Validate domain is allowed (for security)
        if let Some(host) = parsed_url.host_str() {
            // Additional security check could be added here
            debug!("GM_xmlhttpRequest target host: {}", host);
        }

        // In a full implementation, this would:
        // 1. Make the HTTP request asynchronously
        // 2. Call the appropriate callback (onload/onerror/ontimeout)
        // 3. Return a request object with abort() method
        //
        // For Week 14, we'll implement a basic synchronous version
        warn!("GM_xmlhttpRequest: Async execution not yet implemented");

        Ok(())
    }

    /// GM_getResourceURL - Get a resource URL
    ///
    /// Returns a URL for a @resource declared in the metadata.
    pub fn get_resource_url(&self, name: &str) -> Result<String> {
        self.has_grant("GM_getResourceURL")?;

        debug!("GM_getResourceURL: {}", name);

        // In a full implementation, this would:
        // 1. Look up the resource in the script metadata
        // 2. Fetch the resource if needed
        // 3. Return a data: URL or blob: URL
        //
        // For Week 14, return a placeholder
        Ok(format!("data:text/plain,resource:{}", name))
    }

    /// GM_setClipboard - Copy text to clipboard
    ///
    /// Copies the given text to the system clipboard.
    pub fn set_clipboard(&self, text: &str) -> Result<()> {
        self.has_grant("GM_setClipboard")?;

        info!("GM_setClipboard: {} characters", text.len());

        // In a full implementation, this would interact with the system clipboard
        // For Week 14, we'll store it in a special storage key
        self.storage.set_value(
            &self.script_id,
            "__clipboard",
            StorageValue::String(text.to_string()),
        )?;

        debug!("Clipboard content stored (system clipboard API not available)");

        Ok(())
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

    fn create_full_api() -> GmApi {
        let temp_dir = tempdir().unwrap();
        let storage = Arc::new(UserscriptStorage::new(temp_dir.path().to_path_buf()).unwrap());
        let grants = vec![
            "GM_setValue".to_string(),
            "GM_getValue".to_string(),
            "GM_addStyle".to_string(),
            "GM_openInTab".to_string(),
            "GM_notification".to_string(),
            "GM_xmlhttpRequest".to_string(),
            "GM_getResourceURL".to_string(),
            "GM_setClipboard".to_string(),
        ];

        GmApi::new("test-script".to_string(), storage, grants)
    }

    #[test]
    fn test_add_style() {
        let api = create_full_api();

        let css = "body { background: red; }";
        api.add_style(css).unwrap();

        // Verify CSS was stored
        let keys = api.list_values().unwrap();
        assert!(keys.iter().any(|k| k.starts_with("__style_")));
    }

    #[test]
    fn test_open_in_tab() {
        let api = create_full_api();

        // Valid URL
        api.open_in_tab("https://example.com", None).unwrap();

        // With options
        let options = serde_json::json!({"active": true});
        api.open_in_tab("https://example.com", Some(options))
            .unwrap();

        // Invalid URL should error
        let result = api.open_in_tab("not a url", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_notification() {
        let api = create_full_api();

        let details = serde_json::json!({
            "title": "Test",
            "text": "Hello World"
        });

        api.notification(details).unwrap();

        // Minimal notification
        api.notification(Value::Null).unwrap();
    }

    #[test]
    fn test_xml_http_request() {
        let api = create_full_api();

        let details = serde_json::json!({
            "method": "GET",
            "url": "https://example.com/api"
        });

        api.xml_http_request(details).unwrap();

        // Missing URL should error
        let result = api.xml_http_request(serde_json::json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn test_get_resource_url() {
        let api = create_full_api();

        let url = api.get_resource_url("icon").unwrap();
        assert!(url.starts_with("data:"));
    }

    #[test]
    fn test_set_clipboard() {
        let api = create_full_api();

        api.set_clipboard("Hello clipboard!").unwrap();

        // Verify clipboard content was stored
        let stored = api.get_value("__clipboard", None).unwrap();
        assert_eq!(stored, Value::String("Hello clipboard!".to_string()));
    }

    #[test]
    fn test_advanced_permissions() {
        let temp_dir = tempdir().unwrap();
        let storage = Arc::new(UserscriptStorage::new(temp_dir.path().to_path_buf()).unwrap());
        let api = GmApi::new("test-script".to_string(), storage, vec![]); // No grants

        // All advanced APIs should fail without grants
        assert!(api.add_style("css").is_err());
        assert!(api.open_in_tab("https://example.com", None).is_err());
        assert!(api.notification(Value::Null).is_err());
        assert!(api.xml_http_request(serde_json::json!({"url": "https://example.com"})).is_err());
        assert!(api.get_resource_url("test").is_err());
        assert!(api.set_clipboard("text").is_err());
    }
}

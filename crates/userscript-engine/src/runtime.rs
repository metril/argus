//! Userscript runtime and execution orchestration
//!
//! Prepares userscripts for delivery: validation and @require/@resource loading.

use crate::{
    manager::UserscriptManager,
    script::Userscript,
    security::{AuditEvent, ScriptValidator, SecurityAuditor, SecurityPolicy},
    storage::UserscriptStorage,
    Error, Result,
};
use reqwest::Client;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

/// Userscript runtime for managing script execution
pub struct UserscriptRuntime {
    /// Manager for userscript lifecycle
    manager: Arc<UserscriptManager>,
    /// Storage for script data
    storage: Arc<UserscriptStorage>,
    /// HTTP client for fetching @require and @resource
    http_client: Client,
    /// Cache for @require scripts
    require_cache: Arc<parking_lot::RwLock<HashMap<String, String>>>,
    /// Cache for @resource files
    resource_cache: Arc<parking_lot::RwLock<HashMap<String, Vec<u8>>>>,
    /// Security policy
    security_policy: Arc<SecurityPolicy>,
    /// Security auditor
    auditor: Arc<SecurityAuditor>,
    /// Script validator
    validator: Arc<ScriptValidator>,
}

impl UserscriptRuntime {
    /// Create a new userscript runtime with default security policy
    pub fn new(manager: Arc<UserscriptManager>, storage: Arc<UserscriptStorage>) -> Self {
        let security_policy = Arc::new(SecurityPolicy::default());
        Self::with_security(manager, storage, security_policy)
    }

    /// Create a new userscript runtime with custom security policy
    pub fn with_security(
        manager: Arc<UserscriptManager>,
        storage: Arc<UserscriptStorage>,
        security_policy: Arc<SecurityPolicy>,
    ) -> Self {
        let auditor = Arc::new(SecurityAuditor::new(security_policy.clone()));
        let validator = Arc::new(ScriptValidator::new(security_policy.clone()));

        Self {
            manager,
            storage,
            http_client: Client::builder()
                .user_agent("AdBlocker-Userscript/1.0")
                .build()
                .unwrap(),
            require_cache: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            resource_cache: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            security_policy,
            auditor,
            validator,
        }
    }

    /// Get security auditor
    pub fn auditor(&self) -> &Arc<SecurityAuditor> {
        &self.auditor
    }

    /// Get security policy
    pub fn security_policy(&self) -> &Arc<SecurityPolicy> {
        &self.security_policy
    }

    /// Userscript manager
    pub fn manager(&self) -> &Arc<UserscriptManager> {
        &self.manager
    }

    /// Userscript storage
    pub fn storage(&self) -> &Arc<UserscriptStorage> {
        &self.storage
    }

    /// Validate a script and build its deliverable source: all `@require`
    /// dependencies (fetched and cached) followed by the script itself.
    pub async fn prepare_script(&self, script: &Userscript, url: &str) -> Result<String> {
        debug!("Preparing userscript: {}", script.name());

        self.auditor.log_event(
            AuditEvent::ExecutionStart,
            &script.id,
            &format!("Preparing for {}", url),
        );

        self.validator
            .validate_requires(&script.metadata.requires)?;
        self.validator
            .validate_resources(&script.metadata.resources)?;
        self.validator.validate_grants(&script.metadata.grants)?;

        if let Err(e) = self.validator.validate_source(&script.source) {
            self.auditor.log_event(
                AuditEvent::PolicyViolation,
                &script.id,
                &format!("Source validation failed: {}", e),
            );
            return Err(e);
        }

        let mut full_source = String::new();
        for require_url in &script.metadata.requires {
            match self.security_policy.validate_url(require_url) {
                Ok(_) => self.auditor.log_event(
                    AuditEvent::ResourceLoaded,
                    &script.id,
                    &format!("Loading @require: {}", require_url),
                ),
                Err(e) => {
                    self.auditor.log_event(
                        AuditEvent::PermissionDenied,
                        &script.id,
                        &format!("@require blocked: {}", require_url),
                    );
                    return Err(e);
                }
            }
            full_source.push_str(&self.load_require(require_url).await?);
            full_source.push('\n');
        }
        full_source.push_str(&script.source);
        Ok(full_source)
    }

    /// Load a @require dependency
    async fn load_require(&self, url: &str) -> Result<String> {
        // Check cache first
        {
            let cache = self.require_cache.read();
            if let Some(code) = cache.get(url) {
                debug!("@require cache hit: {}", url);
                return Ok(code.clone());
            }
        }

        info!("Fetching @require: {}", url);

        // Fetch from network
        let response = self
            .http_client
            .get(url)
            .send()
            .await
            .map_err(Error::HttpRequest)?;

        if !response.status().is_success() {
            return Err(Error::InvalidScript(format!(
                "Failed to fetch @require {}: {}",
                url,
                response.status()
            )));
        }

        let code = response.text().await.map_err(Error::HttpRequest)?;

        // Cache for future use
        {
            let mut cache = self.require_cache.write();
            cache.insert(url.to_string(), code.clone());
        }

        Ok(code)
    }

    /// Load a @resource file
    pub async fn load_resource(&self, script: &Userscript, name: &str) -> Result<Vec<u8>> {
        // Find resource URL in metadata
        let resource_url = script
            .metadata
            .resources
            .get(name)
            .ok_or_else(|| Error::InvalidScript(format!("Resource not found: {}", name)))?;

        // Validate resource URL
        self.security_policy.validate_url(resource_url)?;

        let cache_key = format!("{}:{}", script.id, name);

        // Check cache
        {
            let cache = self.resource_cache.read();
            if let Some(data) = cache.get(&cache_key) {
                debug!("@resource cache hit: {}", name);
                return Ok(data.clone());
            }
        }

        info!("Fetching @resource: {} from {}", name, resource_url);

        // Audit log
        self.auditor.log_event(
            AuditEvent::NetworkRequest,
            &script.id,
            &format!("Fetching @resource: {}", resource_url),
        );

        // Fetch from network
        let response = self
            .http_client
            .get(resource_url)
            .send()
            .await
            .map_err(Error::HttpRequest)?;

        if !response.status().is_success() {
            return Err(Error::InvalidScript(format!(
                "Failed to fetch @resource {}: {}",
                name,
                response.status()
            )));
        }

        let data = response.bytes().await.map_err(Error::HttpRequest)?.to_vec();

        // Cache for future use
        {
            let mut cache = self.resource_cache.write();
            cache.insert(cache_key, data.clone());
        }

        self.auditor.log_event(
            AuditEvent::ResourceLoaded,
            &script.id,
            &format!("@resource loaded: {} ({} bytes)", name, data.len()),
        );

        Ok(data)
    }

    /// Get data URL for a resource
    pub async fn get_resource_data_url(&self, script: &Userscript, name: &str) -> Result<String> {
        let data = self.load_resource(script, name).await?;

        // Detect MIME type from extension
        let mime_type = self.detect_mime_type(name);

        // Encode as base64 data URL
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &data);
        Ok(format!("data:{};base64,{}", mime_type, b64))
    }

    /// Detect MIME type from filename
    fn detect_mime_type(&self, filename: &str) -> &'static str {
        let ext = filename.rsplit('.').next().unwrap_or("");
        match ext.to_lowercase().as_str() {
            "png" => "image/png",
            "jpg" | "jpeg" => "image/jpeg",
            "gif" => "image/gif",
            "svg" => "image/svg+xml",
            "webp" => "image/webp",
            "css" => "text/css",
            "js" => "application/javascript",
            "json" => "application/json",
            "txt" => "text/plain",
            "html" | "htm" => "text/html",
            _ => "application/octet-stream",
        }
    }

    /// Clear caches
    pub fn clear_caches(&self) {
        info!("Clearing userscript caches");
        self.require_cache.write().clear();
        self.resource_cache.write().clear();
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> CacheStats {
        CacheStats {
            require_cached: self.require_cache.read().len(),
            resource_cached: self.resource_cache.read().len(),
        }
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub require_cached: usize,
    pub resource_cached: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UserscriptManager;
    use tempfile::{tempdir, TempDir};

    // Returns both the runtime and the TempDir to keep the directory alive
    fn create_test_runtime() -> (UserscriptRuntime, TempDir) {
        let temp_dir = tempdir().unwrap();
        let manager = Arc::new(UserscriptManager::new(temp_dir.path().to_path_buf()).unwrap());
        // Use the manager's internal storage (shares its database handle)
        let storage = manager.storage_arc();

        (UserscriptRuntime::new(manager, storage), temp_dir)
    }

    #[tokio::test]
    async fn test_prepare_script_without_requires() {
        let (runtime, _temp_dir) = create_test_runtime();
        let script = Userscript::new(
            "// ==UserScript==\n// @name Test\n// @match *://example.com/*\n// ==/UserScript==\nvar x = 1;".to_string(),
        )
        .unwrap();
        let out = runtime
            .prepare_script(&script, "https://example.com/")
            .await
            .unwrap();
        assert!(out.ends_with("var x = 1;"));
    }

    #[test]
    fn test_mime_type_detection() {
        let (runtime, _temp_dir) = create_test_runtime();

        assert_eq!(runtime.detect_mime_type("icon.png"), "image/png");
        assert_eq!(runtime.detect_mime_type("style.css"), "text/css");
        assert_eq!(
            runtime.detect_mime_type("script.js"),
            "application/javascript"
        );
        assert_eq!(runtime.detect_mime_type("data.json"), "application/json");
        assert_eq!(
            runtime.detect_mime_type("unknown.xyz"),
            "application/octet-stream"
        );
    }

    #[test]
    fn test_cache_stats() {
        let (runtime, _temp_dir) = create_test_runtime();
        let stats = runtime.cache_stats();

        assert_eq!(stats.require_cached, 0);
        assert_eq!(stats.resource_cached, 0);

        // Add to cache
        runtime
            .require_cache
            .write()
            .insert("test.js".to_string(), "code".to_string());

        let stats = runtime.cache_stats();
        assert_eq!(stats.require_cached, 1);

        runtime.clear_caches();
        let stats = runtime.cache_stats();
        assert_eq!(stats.require_cached, 0);
    }
}

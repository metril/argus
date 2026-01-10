//! Userscript runtime and execution orchestration
//!
//! Manages script execution lifecycle, timing, and resource loading.

use crate::{
    executor::ScriptExecutor,
    gm_api::GmApi,
    manager::UserscriptManager,
    metadata::RunAt,
    script::Userscript,
    security::{AuditEvent, ScriptValidator, SecurityAuditor, SecurityPolicy},
    storage::UserscriptStorage,
    Error, Result,
};
use reqwest::Client;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

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

    /// Execute userscripts for a given URL at a specific timing
    pub async fn execute_for_url(&self, url: &str, run_at: RunAt) -> Result<ExecutionResults> {
        info!("Executing userscripts for {} at {:?}", url, run_at);

        let scripts = self.manager.get_scripts_for_url(url);
        let mut results = ExecutionResults::new();

        for script in scripts {
            // Check if script should run at this timing
            if script.metadata.run_at != run_at {
                debug!(
                    "Skipping {} (runs at {:?}, not {:?})",
                    script.name(),
                    script.metadata.run_at,
                    run_at
                );
                continue;
            }

            match self.execute_script(&script, url).await {
                Ok(_) => {
                    info!("Successfully executed: {}", script.name());
                    results.executed.push(script.name().to_string());

                    // Record execution
                    if let Err(e) = self.manager.record_execution(&script.id) {
                        warn!("Failed to record execution: {}", e);
                    }
                }
                Err(e) => {
                    warn!("Failed to execute {}: {}", script.name(), e);
                    results
                        .failed
                        .push((script.name().to_string(), e.to_string()));
                }
            }
        }

        info!(
            "Execution complete: {} succeeded, {} failed",
            results.executed.len(),
            results.failed.len()
        );

        Ok(results)
    }

    /// Execute a single userscript
    async fn execute_script(&self, script: &Userscript, url: &str) -> Result<()> {
        debug!("Executing userscript: {}", script.name());

        // Security audit: log execution start
        self.auditor.log_event(
            AuditEvent::ExecutionStart,
            &script.id,
            &format!("Executing on {}", url),
        );

        // Validate script metadata
        self.validator
            .validate_requires(&script.metadata.requires)?;
        self.validator
            .validate_resources(&script.metadata.resources)?;
        self.validator.validate_grants(&script.metadata.grants)?;

        // Validate script source
        if let Err(e) = self.validator.validate_source(&script.source) {
            self.auditor.log_event(
                AuditEvent::PolicyViolation,
                &script.id,
                &format!("Source validation failed: {}", e),
            );
            return Err(e);
        }

        // Load @require dependencies
        let mut full_source = String::new();

        for require_url in &script.metadata.requires {
            // Validate URL
            match self.security_policy.validate_url(require_url) {
                Ok(_) => {
                    self.auditor.log_event(
                        AuditEvent::ResourceLoaded,
                        &script.id,
                        &format!("Loading @require: {}", require_url),
                    );
                }
                Err(e) => {
                    self.auditor.log_event(
                        AuditEvent::PermissionDenied,
                        &script.id,
                        &format!("@require blocked: {}", require_url),
                    );
                    return Err(e);
                }
            }

            let code = self.load_require(require_url).await?;
            full_source.push_str(&code);
            full_source.push('\n');
        }

        // Add the script itself
        full_source.push_str(&script.source);

        // Create GM API context
        let gm_api = Arc::new(GmApi::new(
            script.id.clone(),
            self.storage.clone(),
            script.metadata.grants.clone(),
        ));

        // Create executor
        let mut executor = ScriptExecutor::new(gm_api)?;

        // Execute with proper error handling
        match executor.execute(&full_source, &script.name()) {
            Ok(_) => {
                self.auditor.log_event(
                    AuditEvent::ExecutionComplete,
                    &script.id,
                    "Script executed successfully",
                );
                Ok(())
            }
            Err(e) => {
                self.auditor.log_event(
                    AuditEvent::ExecutionFailed,
                    &script.id,
                    &format!("Execution failed: {}", e),
                );
                Err(e)
            }
        }
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
            .map_err(|e| Error::HttpRequest(e))?;

        if !response.status().is_success() {
            return Err(Error::InvalidScript(format!(
                "Failed to fetch @require {}: {}",
                url,
                response.status()
            )));
        }

        let code = response
            .text()
            .await
            .map_err(|e| Error::HttpRequest(e))?;

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
            .map_err(|e| Error::HttpRequest(e))?;

        if !response.status().is_success() {
            return Err(Error::InvalidScript(format!(
                "Failed to fetch @resource {}: {}",
                name,
                response.status()
            )));
        }

        let data = response
            .bytes()
            .await
            .map_err(|e| Error::HttpRequest(e))?
            .to_vec();

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
    pub async fn get_resource_data_url(
        &self,
        script: &Userscript,
        name: &str,
    ) -> Result<String> {
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

/// Results from executing userscripts
#[derive(Debug, Clone)]
pub struct ExecutionResults {
    /// Successfully executed scripts
    pub executed: Vec<String>,
    /// Failed scripts with error messages
    pub failed: Vec<(String, String)>,
}

impl ExecutionResults {
    fn new() -> Self {
        Self {
            executed: Vec::new(),
            failed: Vec::new(),
        }
    }

    /// Check if all scripts executed successfully
    pub fn is_success(&self) -> bool {
        self.failed.is_empty()
    }

    /// Get total number of scripts attempted
    pub fn total(&self) -> usize {
        self.executed.len() + self.failed.len()
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub require_cached: usize,
    pub resource_cached: usize,
}

/// Execution context for a page
pub struct PageContext {
    /// URL of the page
    pub url: String,
    /// Document ready state
    pub ready_state: DocumentReadyState,
    /// Injected CSS from GM_addStyle
    pub injected_css: Vec<String>,
}

impl PageContext {
    /// Create a new page context
    pub fn new(url: String) -> Self {
        Self {
            url,
            ready_state: DocumentReadyState::Loading,
            injected_css: Vec::new(),
        }
    }

    /// Get CSS to inject into the page
    pub fn get_css(&self) -> String {
        self.injected_css.join("\n")
    }
}

/// Document ready state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DocumentReadyState {
    /// Document is still loading
    Loading,
    /// DOM is ready but resources may still be loading
    Interactive,
    /// Everything is loaded
    Complete,
}

impl DocumentReadyState {
    /// Check if scripts with given RunAt should execute
    pub fn should_execute(&self, run_at: &RunAt) -> bool {
        match run_at {
            RunAt::DocumentStart => true, // Always run, as early as possible
            RunAt::DocumentEnd => matches!(self, DocumentReadyState::Interactive | DocumentReadyState::Complete),
            RunAt::DocumentIdle => matches!(self, DocumentReadyState::Complete),
            RunAt::ContextMenu => false, // Special case, not automatic
        }
    }
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
        // Use the manager's internal storage to avoid sled lock conflicts
        let storage = manager.storage_arc();

        (UserscriptRuntime::new(manager, storage), temp_dir)
    }

    #[tokio::test]
    async fn test_execute_for_url() {
        let (runtime, _temp_dir) = create_test_runtime();

        // Install a test script
        let script = r#"
// ==UserScript==
// @name         Test Script
// @match        *://example.com/*
// @run-at       document-start
// @grant        GM_setValue
// ==/UserScript==

GM.setValue('test', 'value');
"#;

        runtime
            .manager
            .install(script.to_string())
            .unwrap();

        // Execute scripts for URL
        let results = runtime
            .execute_for_url("https://example.com/page", RunAt::DocumentStart)
            .await
            .unwrap();

        assert_eq!(results.executed.len(), 1);
        assert_eq!(results.failed.len(), 0);
        assert!(results.is_success());
    }

    #[tokio::test]
    async fn test_run_at_filtering() {
        let (runtime, _temp_dir) = create_test_runtime();

        // Install script that runs at document-end
        let script = r#"
// ==UserScript==
// @name         End Script
// @match        *://example.com/*
// @run-at       document-end
// ==/UserScript==

// Simple script that doesn't require console
var x = 1 + 1;
"#;

        runtime
            .manager
            .install(script.to_string())
            .unwrap();

        // Execute at document-start should skip this script
        let results = runtime
            .execute_for_url("https://example.com/page", RunAt::DocumentStart)
            .await
            .unwrap();

        assert_eq!(results.executed.len(), 0);

        // Execute at document-end should run it
        let results = runtime
            .execute_for_url("https://example.com/page", RunAt::DocumentEnd)
            .await
            .unwrap();

        assert_eq!(results.executed.len(), 1);
        assert_eq!(results.failed.len(), 0);
    }

    #[test]
    fn test_mime_type_detection() {
        let (runtime, _temp_dir) = create_test_runtime();

        assert_eq!(runtime.detect_mime_type("icon.png"), "image/png");
        assert_eq!(runtime.detect_mime_type("style.css"), "text/css");
        assert_eq!(runtime.detect_mime_type("script.js"), "application/javascript");
        assert_eq!(runtime.detect_mime_type("data.json"), "application/json");
        assert_eq!(runtime.detect_mime_type("unknown.xyz"), "application/octet-stream");
    }

    #[test]
    fn test_document_ready_state() {
        assert!(DocumentReadyState::Loading.should_execute(&RunAt::DocumentStart));
        assert!(!DocumentReadyState::Loading.should_execute(&RunAt::DocumentEnd));
        assert!(!DocumentReadyState::Loading.should_execute(&RunAt::DocumentIdle));

        assert!(DocumentReadyState::Interactive.should_execute(&RunAt::DocumentStart));
        assert!(DocumentReadyState::Interactive.should_execute(&RunAt::DocumentEnd));
        assert!(!DocumentReadyState::Interactive.should_execute(&RunAt::DocumentIdle));

        assert!(DocumentReadyState::Complete.should_execute(&RunAt::DocumentStart));
        assert!(DocumentReadyState::Complete.should_execute(&RunAt::DocumentEnd));
        assert!(DocumentReadyState::Complete.should_execute(&RunAt::DocumentIdle));
    }

    #[test]
    fn test_execution_results() {
        let mut results = ExecutionResults::new();
        assert!(results.is_success());
        assert_eq!(results.total(), 0);

        results.executed.push("script1".to_string());
        assert!(results.is_success());
        assert_eq!(results.total(), 1);

        results.failed.push(("script2".to_string(), "error".to_string()));
        assert!(!results.is_success());
        assert_eq!(results.total(), 2);
    }

    #[test]
    fn test_page_context() {
        let mut ctx = PageContext::new("https://example.com".to_string());
        assert_eq!(ctx.ready_state, DocumentReadyState::Loading);

        ctx.injected_css.push("body { color: red; }".to_string());
        ctx.injected_css.push("a { color: blue; }".to_string());

        let css = ctx.get_css();
        assert!(css.contains("color: red"));
        assert!(css.contains("color: blue"));
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

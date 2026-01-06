//! Security and sandboxing for userscript execution
//!
//! Provides security hardening including:
//! - Content Security Policy (CSP) enforcement
//! - Resource access control
//! - Script isolation
//! - Security audit logging
//! - Permission validation

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{debug, info, warn};
use url::Url;

/// Security policy for userscript execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicy {
    /// Maximum script execution time (milliseconds)
    pub max_execution_time_ms: u64,
    /// Maximum memory usage (bytes)
    pub max_memory_bytes: u64,
    /// Allowed domains for network requests
    pub allowed_domains: HashSet<String>,
    /// Blocked domains for network requests
    pub blocked_domains: HashSet<String>,
    /// Require HTTPS for external resources
    pub require_https: bool,
    /// Enable strict CSP enforcement
    pub strict_csp: bool,
    /// Maximum @require dependencies
    pub max_requires: usize,
    /// Maximum @resource files
    pub max_resources: usize,
    /// Enable security audit logging
    pub enable_audit_log: bool,
    /// Allowed GM_* API functions (if empty, use @grant declarations)
    pub allowed_gm_apis: HashSet<String>,
    /// Block dangerous APIs regardless of @grant
    pub blocked_gm_apis: HashSet<String>,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            max_execution_time_ms: 30_000, // 30 seconds
            max_memory_bytes: 100 * 1024 * 1024, // 100 MB
            allowed_domains: HashSet::new(), // Empty = allow all
            blocked_domains: Self::default_blocked_domains(),
            require_https: true,
            strict_csp: true,
            max_requires: 20,
            max_resources: 50,
            enable_audit_log: true,
            allowed_gm_apis: HashSet::new(), // Empty = use @grant
            blocked_gm_apis: Self::default_blocked_apis(),
        }
    }
}

impl SecurityPolicy {
    /// Create a permissive policy for development
    pub fn permissive() -> Self {
        Self {
            max_execution_time_ms: 60_000,
            max_memory_bytes: 200 * 1024 * 1024,
            allowed_domains: HashSet::new(),
            blocked_domains: HashSet::new(),
            require_https: false,
            strict_csp: false,
            max_requires: 100,
            max_resources: 100,
            enable_audit_log: false,
            allowed_gm_apis: HashSet::new(),
            blocked_gm_apis: HashSet::new(),
        }
    }

    /// Create a strict policy for production
    pub fn strict() -> Self {
        Self {
            max_execution_time_ms: 10_000,
            max_memory_bytes: 50 * 1024 * 1024,
            allowed_domains: HashSet::new(),
            blocked_domains: Self::default_blocked_domains(),
            require_https: true,
            strict_csp: true,
            max_requires: 10,
            max_resources: 20,
            enable_audit_log: true,
            allowed_gm_apis: HashSet::new(),
            blocked_gm_apis: Self::default_blocked_apis(),
        }
    }

    fn default_blocked_domains() -> HashSet<String> {
        let mut set = HashSet::new();
        // Block localhost and private IP ranges by default
        set.insert("localhost".to_string());
        set.insert("127.0.0.1".to_string());
        set.insert("0.0.0.0".to_string());
        set.insert("10.0.0.0/8".to_string());
        set.insert("172.16.0.0/12".to_string());
        set.insert("192.168.0.0/16".to_string());
        set
    }

    fn default_blocked_apis() -> HashSet<String> {
        let mut set = HashSet::new();
        // These APIs could be used for malicious purposes
        set.insert("unsafeWindow".to_string());
        set.insert("GM_deleteValue".to_string()); // Could delete user data
        set
    }

    /// Check if a domain is allowed for network access
    pub fn is_domain_allowed(&self, domain: &str) -> bool {
        // Check blocked list first
        if self.blocked_domains.contains(domain) {
            return false;
        }

        // Check if domain is a private IP
        if self.is_private_domain(domain) {
            return false;
        }

        // If allowed list is empty, allow all (except blocked)
        if self.allowed_domains.is_empty() {
            return true;
        }

        // Check allowed list
        self.allowed_domains.contains(domain)
    }

    /// Check if domain is private/local
    fn is_private_domain(&self, domain: &str) -> bool {
        domain == "localhost"
            || domain.starts_with("127.")
            || domain.starts_with("10.")
            || domain.starts_with("192.168.")
            || domain.starts_with("172.16.")
            || domain.starts_with("172.17.")
            || domain.starts_with("172.18.")
            || domain.starts_with("172.19.")
            || domain.starts_with("172.20.")
            || domain.starts_with("172.21.")
            || domain.starts_with("172.22.")
            || domain.starts_with("172.23.")
            || domain.starts_with("172.24.")
            || domain.starts_with("172.25.")
            || domain.starts_with("172.26.")
            || domain.starts_with("172.27.")
            || domain.starts_with("172.28.")
            || domain.starts_with("172.29.")
            || domain.starts_with("172.30.")
            || domain.starts_with("172.31.")
    }

    /// Validate URL against security policy
    pub fn validate_url(&self, url_str: &str) -> Result<Url> {
        let url = Url::parse(url_str).map_err(|e| {
            Error::PermissionDenied(format!("Invalid URL: {}", e))
        })?;

        // Check HTTPS requirement
        if self.require_https && url.scheme() != "https" && url.scheme() != "data" {
            return Err(Error::PermissionDenied(format!(
                "HTTPS required but got: {}",
                url.scheme()
            )));
        }

        // Check domain allowlist
        if let Some(domain) = url.host_str() {
            if !self.is_domain_allowed(domain) {
                return Err(Error::PermissionDenied(format!(
                    "Domain not allowed: {}",
                    domain
                )));
            }
        }

        Ok(url)
    }

    /// Check if a GM_* API is allowed
    pub fn is_api_allowed(&self, api_name: &str, grants: &[String]) -> bool {
        // Check if explicitly blocked
        if self.blocked_gm_apis.contains(api_name) {
            return false;
        }

        // If allowed list is specified, use that
        if !self.allowed_gm_apis.is_empty() {
            return self.allowed_gm_apis.contains(api_name);
        }

        // Otherwise, check @grant declarations
        grants.contains(&api_name.to_string())
    }
}

/// Security auditor for logging security events
pub struct SecurityAuditor {
    /// Policy being enforced
    policy: Arc<SecurityPolicy>,
    /// Audit log entries
    entries: parking_lot::RwLock<Vec<AuditEntry>>,
}

impl SecurityAuditor {
    /// Create a new security auditor
    pub fn new(policy: Arc<SecurityPolicy>) -> Self {
        Self {
            policy,
            entries: parking_lot::RwLock::new(Vec::new()),
        }
    }

    /// Log a security event
    pub fn log_event(&self, event: AuditEvent, script_id: &str, details: &str) {
        if !self.policy.enable_audit_log {
            return;
        }

        let entry = AuditEntry {
            timestamp: chrono::Utc::now(),
            event,
            script_id: script_id.to_string(),
            details: details.to_string(),
        };

        match event {
            AuditEvent::PermissionDenied | AuditEvent::PolicyViolation | AuditEvent::SuspiciousActivity => {
                warn!("Security event: {:?} - {} - {}", event, script_id, details);
            }
            _ => {
                debug!("Security event: {:?} - {} - {}", event, script_id, details);
            }
        }

        self.entries.write().push(entry);
    }

    /// Get recent audit entries
    pub fn get_recent_entries(&self, limit: usize) -> Vec<AuditEntry> {
        let entries = self.entries.read();
        entries.iter().rev().take(limit).cloned().collect()
    }

    /// Get entries for a specific script
    pub fn get_script_entries(&self, script_id: &str) -> Vec<AuditEntry> {
        let entries = self.entries.read();
        entries
            .iter()
            .filter(|e| e.script_id == script_id)
            .cloned()
            .collect()
    }

    /// Clear audit log
    pub fn clear(&self) {
        self.entries.write().clear();
        info!("Audit log cleared");
    }

    /// Get audit statistics
    pub fn get_statistics(&self) -> AuditStatistics {
        let entries = self.entries.read();

        let mut stats = AuditStatistics {
            total_events: entries.len(),
            permission_denied: 0,
            api_calls: 0,
            network_requests: 0,
            policy_violations: 0,
            suspicious_activity: 0,
        };

        for entry in entries.iter() {
            match entry.event {
                AuditEvent::PermissionDenied => stats.permission_denied += 1,
                AuditEvent::ApiCall => stats.api_calls += 1,
                AuditEvent::NetworkRequest => stats.network_requests += 1,
                AuditEvent::PolicyViolation => stats.policy_violations += 1,
                AuditEvent::SuspiciousActivity => stats.suspicious_activity += 1,
                _ => {}
            }
        }

        stats
    }
}

/// Security audit event types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditEvent {
    /// Script execution started
    ExecutionStart,
    /// Script execution completed
    ExecutionComplete,
    /// Script execution failed
    ExecutionFailed,
    /// GM_* API call
    ApiCall,
    /// Network request made
    NetworkRequest,
    /// Permission denied
    PermissionDenied,
    /// Resource loaded
    ResourceLoaded,
    /// Policy violation detected
    PolicyViolation,
    /// Suspicious activity detected
    SuspiciousActivity,
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// When the event occurred
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Type of event
    pub event: AuditEvent,
    /// Script that triggered the event
    pub script_id: String,
    /// Additional details
    pub details: String,
}

/// Audit statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStatistics {
    pub total_events: usize,
    pub permission_denied: usize,
    pub api_calls: usize,
    pub network_requests: usize,
    pub policy_violations: usize,
    pub suspicious_activity: usize,
}

/// Validator for userscript content and metadata
pub struct ScriptValidator {
    policy: Arc<SecurityPolicy>,
}

impl ScriptValidator {
    /// Create a new script validator
    pub fn new(policy: Arc<SecurityPolicy>) -> Self {
        Self { policy }
    }

    /// Validate script source code
    pub fn validate_source(&self, source: &str) -> Result<()> {
        // Check for suspicious patterns
        let suspicious_patterns = [
            ("eval(", "Use of eval() is not allowed"),
            ("Function(", "Use of Function constructor is not allowed"),
            ("setTimeout(\"", "setTimeout with string argument is not allowed"),
            ("setInterval(\"", "setInterval with string argument is not allowed"),
        ];

        for (pattern, message) in &suspicious_patterns {
            if source.contains(pattern) {
                return Err(Error::PermissionDenied(format!(
                    "Suspicious code pattern detected: {}",
                    message
                )));
            }
        }

        Ok(())
    }

    /// Validate @require URLs
    pub fn validate_requires(&self, requires: &[String]) -> Result<()> {
        if requires.len() > self.policy.max_requires {
            return Err(Error::PermissionDenied(format!(
                "Too many @require dependencies: {} > {}",
                requires.len(),
                self.policy.max_requires
            )));
        }

        for url in requires {
            self.policy.validate_url(url)?;
        }

        Ok(())
    }

    /// Validate @resource URLs
    pub fn validate_resources(&self, resources: &HashMap<String, String>) -> Result<()> {
        if resources.len() > self.policy.max_resources {
            return Err(Error::PermissionDenied(format!(
                "Too many @resource files: {} > {}",
                resources.len(),
                self.policy.max_resources
            )));
        }

        for (name, url) in resources {
            if name.contains("..") || name.contains("/") || name.contains("\\") {
                return Err(Error::PermissionDenied(format!(
                    "Invalid resource name: {}",
                    name
                )));
            }
            self.policy.validate_url(url)?;
        }

        Ok(())
    }

    /// Validate @grant declarations
    pub fn validate_grants(&self, grants: &[String]) -> Result<()> {
        for grant in grants {
            // Check if grant is blocked
            if self.policy.blocked_gm_apis.contains(grant) {
                return Err(Error::PermissionDenied(format!(
                    "Blocked API requested: {}",
                    grant
                )));
            }

            // Validate grant is a known API
            if !self.is_valid_grant(grant) {
                return Err(Error::PermissionDenied(format!(
                    "Unknown @grant: {}",
                    grant
                )));
            }
        }

        Ok(())
    }

    /// Check if grant is a valid GM_* API
    fn is_valid_grant(&self, grant: &str) -> bool {
        matches!(
            grant,
            "GM_setValue"
                | "GM_getValue"
                | "GM_deleteValue"
                | "GM_listValues"
                | "GM_addStyle"
                | "GM_openInTab"
                | "GM_notification"
                | "GM_xmlhttpRequest"
                | "GM_getResourceURL"
                | "GM_setClipboard"
                | "GM_info"
                | "GM_log"
                | "unsafeWindow"
                | "window.close"
                | "window.focus"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy() {
        let policy = SecurityPolicy::default();
        assert!(policy.require_https);
        assert!(policy.strict_csp);
        assert!(policy.enable_audit_log);
    }

    #[test]
    fn test_permissive_policy() {
        let policy = SecurityPolicy::permissive();
        assert!(!policy.require_https);
        assert!(!policy.strict_csp);
        assert!(!policy.enable_audit_log);
    }

    #[test]
    fn test_domain_validation() {
        let policy = SecurityPolicy::default();

        // Should block localhost
        assert!(!policy.is_domain_allowed("localhost"));
        assert!(!policy.is_domain_allowed("127.0.0.1"));

        // Should allow public domains
        assert!(policy.is_domain_allowed("example.com"));
        assert!(policy.is_domain_allowed("github.com"));
    }

    #[test]
    fn test_url_validation_https() {
        let policy = SecurityPolicy::default();

        // HTTPS should pass
        assert!(policy.validate_url("https://example.com").is_ok());

        // HTTP should fail with strict policy
        assert!(policy.validate_url("http://example.com").is_err());

        // Data URLs should pass
        assert!(policy.validate_url("data:text/plain,hello").is_ok());
    }

    #[test]
    fn test_url_validation_permissive() {
        let policy = SecurityPolicy::permissive();

        // HTTP should pass with permissive policy
        assert!(policy.validate_url("http://example.com").is_ok());
        assert!(policy.validate_url("https://example.com").is_ok());
    }

    #[test]
    fn test_api_permission() {
        let policy = SecurityPolicy::default();
        let grants = vec!["GM_setValue".to_string(), "GM_getValue".to_string()];

        // Granted APIs should be allowed
        assert!(policy.is_api_allowed("GM_setValue", &grants));
        assert!(policy.is_api_allowed("GM_getValue", &grants));

        // Non-granted APIs should be denied
        assert!(!policy.is_api_allowed("GM_xmlhttpRequest", &grants));

        // Blocked APIs should be denied regardless
        assert!(!policy.is_api_allowed("unsafeWindow", &grants));
    }

    #[test]
    fn test_auditor_logging() {
        let policy = Arc::new(SecurityPolicy::default());
        let auditor = SecurityAuditor::new(policy);

        auditor.log_event(AuditEvent::ExecutionStart, "test-script", "Starting execution");
        auditor.log_event(AuditEvent::ApiCall, "test-script", "GM_setValue called");
        auditor.log_event(AuditEvent::ExecutionComplete, "test-script", "Execution finished");

        let entries = auditor.get_recent_entries(10);
        assert_eq!(entries.len(), 3);

        let script_entries = auditor.get_script_entries("test-script");
        assert_eq!(script_entries.len(), 3);
    }

    #[test]
    fn test_audit_statistics() {
        let policy = Arc::new(SecurityPolicy::default());
        let auditor = SecurityAuditor::new(policy);

        auditor.log_event(AuditEvent::ApiCall, "script1", "API call");
        auditor.log_event(AuditEvent::ApiCall, "script1", "API call");
        auditor.log_event(AuditEvent::PermissionDenied, "script1", "Permission denied");
        auditor.log_event(AuditEvent::NetworkRequest, "script2", "Network request");

        let stats = auditor.get_statistics();
        assert_eq!(stats.total_events, 4);
        assert_eq!(stats.api_calls, 2);
        assert_eq!(stats.permission_denied, 1);
        assert_eq!(stats.network_requests, 1);
    }

    #[test]
    fn test_script_validator_source() {
        let policy = Arc::new(SecurityPolicy::default());
        let validator = ScriptValidator::new(policy);

        // Safe code should pass
        assert!(validator.validate_source("console.log('hello');").is_ok());

        // Dangerous patterns should fail
        assert!(validator.validate_source("eval('alert(1)')").is_err());
        assert!(validator.validate_source("Function('return 1')()").is_err());
        assert!(validator.validate_source("setTimeout(\"alert(1)\", 100)").is_err());
    }

    #[test]
    fn test_script_validator_requires() {
        let policy = Arc::new(SecurityPolicy::default());
        let validator = ScriptValidator::new(policy);

        // Valid requires
        let valid_requires = vec!["https://code.jquery.com/jquery-3.6.0.min.js".to_string()];
        assert!(validator.validate_requires(&valid_requires).is_ok());

        // Too many requires
        let too_many: Vec<String> = (0..25)
            .map(|i| format!("https://example.com/lib{}.js", i))
            .collect();
        assert!(validator.validate_requires(&too_many).is_err());

        // HTTP URL should fail with strict policy
        let http_requires = vec!["http://example.com/lib.js".to_string()];
        assert!(validator.validate_requires(&http_requires).is_err());
    }

    #[test]
    fn test_script_validator_resources() {
        let policy = Arc::new(SecurityPolicy::default());
        let validator = ScriptValidator::new(policy);

        // Valid resources
        let mut valid_resources = HashMap::new();
        valid_resources.insert("icon".to_string(), "https://example.com/icon.png".to_string());
        assert!(validator.validate_resources(&valid_resources).is_ok());

        // Invalid resource name
        let mut invalid_name = HashMap::new();
        invalid_name.insert("../evil".to_string(), "https://example.com/file".to_string());
        assert!(validator.validate_resources(&invalid_name).is_err());
    }

    #[test]
    fn test_script_validator_grants() {
        let policy = Arc::new(SecurityPolicy::default());
        let validator = ScriptValidator::new(policy);

        // Valid grants
        let valid_grants = vec!["GM_setValue".to_string(), "GM_getValue".to_string()];
        assert!(validator.validate_grants(&valid_grants).is_ok());

        // Blocked grant
        let blocked_grants = vec!["unsafeWindow".to_string()];
        assert!(validator.validate_grants(&blocked_grants).is_err());

        // Unknown grant
        let unknown_grants = vec!["GM_unknownAPI".to_string()];
        assert!(validator.validate_grants(&unknown_grants).is_err());
    }

    #[test]
    fn test_private_domain_detection() {
        let policy = SecurityPolicy::default();

        // Private domains
        assert!(policy.is_private_domain("localhost"));
        assert!(policy.is_private_domain("127.0.0.1"));
        assert!(policy.is_private_domain("10.0.0.1"));
        assert!(policy.is_private_domain("192.168.1.1"));
        assert!(policy.is_private_domain("172.16.0.1"));

        // Public domains
        assert!(!policy.is_private_domain("example.com"));
        assert!(!policy.is_private_domain("8.8.8.8"));
    }
}

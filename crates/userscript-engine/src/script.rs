//! Userscript representation and management

use crate::{
    matcher::{Options, Rules},
    metadata::UserscriptMetadata,
    Error, Result,
};
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Profile namespace used until profiles land.
pub const DEFAULT_PROFILE: &str = "default";

fn default_profile() -> String {
    DEFAULT_PROFILE.to_string()
}

/// Fetched `@require` body (stored at install time so pages never wait on third parties).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequireBlob {
    pub url: String,
    pub content: String,
}

/// Fetched `@resource`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceBlob {
    pub name: String,
    pub url: String,
    pub mime: String,
    /// Standard base64.
    pub data_b64: String,
}

impl ResourceBlob {
    pub fn bytes(&self) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(&self.data_b64)
            .unwrap_or_default()
    }
}

/// Downloaded dependencies of a script.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScriptAssets {
    pub requires: Vec<RequireBlob>,
    pub resources: Vec<ResourceBlob>,
}

/// A newer version found by an update check, waiting for approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingUpdate {
    pub source: String,
    #[serde(default)]
    pub assets: ScriptAssets,
    pub diff: crate::install::UpdateDiff,
    pub new_version: Option<String>,
    pub found_at: DateTime<Utc>,
    /// Where the new source came from (resolves relative `@require` URLs).
    #[serde(default)]
    pub origin_url: Option<String>,
}

/// Represents a single userscript
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Userscript {
    /// Unique identifier
    pub id: String,
    /// Owning profile (storage namespace).
    #[serde(default = "default_profile")]
    pub profile: String,
    /// Script metadata
    pub metadata: UserscriptMetadata,
    /// Script source code
    pub source: String,
    /// Whether the script is enabled
    pub enabled: bool,
    /// When the script was installed
    pub installed_at: DateTime<Utc>,
    /// When the script was last updated
    pub updated_at: DateTime<Utc>,
    /// When the script was last executed
    pub last_executed: Option<DateTime<Utc>>,
    /// Number of times the script has been executed
    pub execution_count: u64,
    /// Downloaded `@require`/`@resource` content.
    #[serde(default)]
    pub assets: ScriptAssets,
    /// The user approved `@connect *` for this script at install time.
    #[serde(default)]
    pub allow_connect_all: bool,
    /// The user approved sending this script's non-anonymous requests and cookie calls through
    /// the connected browser extension (real browser logins). Granted only during review.
    #[serde(default)]
    pub browser_cookies: bool,
    /// Imported from a bundle without approval: stays off until approved.
    #[serde(default)]
    pub pending_approval: bool,
    /// A found update awaiting approval.
    #[serde(default)]
    pub pending_update: Option<PendingUpdate>,
    /// When an update check last completed for this script.
    #[serde(default)]
    pub last_update_check: Option<DateTime<Utc>>,
}

impl Userscript {
    /// Create a new userscript from source code
    pub fn new(source: String) -> Result<Self> {
        let metadata = UserscriptMetadata::parse(&source)?;
        let id = metadata.unique_id();
        let now = Utc::now();

        Ok(Self {
            id,
            profile: default_profile(),
            metadata,
            source,
            enabled: true,
            installed_at: now,
            updated_at: now,
            last_executed: None,
            execution_count: 0,
            assets: ScriptAssets::default(),
            allow_connect_all: false,
            browser_cookies: false,
            pending_approval: false,
            pending_update: None,
            last_update_check: None,
        })
    }

    /// Update the script source and metadata
    pub fn update(&mut self, new_source: String) -> Result<()> {
        let new_metadata = UserscriptMetadata::parse(&new_source)?;

        // Verify same script (same unique ID)
        if new_metadata.unique_id() != self.id {
            return Err(Error::InvalidScript(
                "Cannot update script with different ID".to_string(),
            ));
        }

        self.metadata = new_metadata;
        self.source = new_source;
        self.updated_at = Utc::now();

        Ok(())
    }

    /// Record script execution
    pub fn record_execution(&mut self) {
        self.last_executed = Some(Utc::now());
        self.execution_count += 1;
    }

    /// Check if script should run on a given URL
    pub fn should_run_on(&self, url: &str) -> bool {
        if !self.enabled {
            return false;
        }
        let (rules, _) = Rules::compile(&self.metadata, Options::default());
        rules.is_match_url(url)
    }

    /// Get script name
    pub fn name(&self) -> &str {
        &self.metadata.name
    }

    /// Get script version
    pub fn version(&self) -> Option<&str> {
        self.metadata.version.as_deref()
    }

    /// Get script description
    pub fn description(&self) -> Option<&str> {
        self.metadata.description.as_deref()
    }

    /// Check if an update is needed based on version comparison
    pub fn needs_update(&self, new_version: &str) -> bool {
        if let Some(current_version) = &self.metadata.version {
            crate::install::is_newer(current_version, new_version)
        } else {
            true // No version = always update
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_userscript() {
        let source = r#"
// ==UserScript==
// @name         Test Script
// @namespace    http://example.com
// @version      1.0.0
// @match        *://example.com/*
// ==/UserScript==

console.log('test');
"#;

        let script = Userscript::new(source.to_string()).unwrap();
        assert_eq!(script.name(), "Test Script");
        assert_eq!(script.version(), Some("1.0.0"));
        assert!(script.enabled);
        assert_eq!(script.execution_count, 0);
    }

    #[test]
    fn test_should_run_on() {
        let source = r#"
// ==UserScript==
// @name         Test Script
// @match        *://example.com/*
// ==/UserScript==
"#;

        let script = Userscript::new(source.to_string()).unwrap();
        assert!(script.should_run_on("https://example.com/page"));
        assert!(!script.should_run_on("https://other.com/page"));
    }

    #[test]
    fn test_update_script() {
        let source_v1 = r#"
// ==UserScript==
// @name         Test Script
// @namespace    http://example.com
// @version      1.0.0
// ==/UserScript==

console.log('v1');
"#;

        let source_v2 = r#"
// ==UserScript==
// @name         Test Script
// @namespace    http://example.com
// @version      2.0.0
// ==/UserScript==

console.log('v2');
"#;

        let mut script = Userscript::new(source_v1.to_string()).unwrap();
        assert_eq!(script.version(), Some("1.0.0"));

        script.update(source_v2.to_string()).unwrap();
        assert_eq!(script.version(), Some("2.0.0"));
        assert!(script.source.contains("v2"));
    }

    #[test]
    fn test_record_execution() {
        let source = r#"
// ==UserScript==
// @name         Test Script
// ==/UserScript==
"#;

        let mut script = Userscript::new(source.to_string()).unwrap();
        assert_eq!(script.execution_count, 0);
        assert!(script.last_executed.is_none());

        script.record_execution();
        assert_eq!(script.execution_count, 1);
        assert!(script.last_executed.is_some());

        script.record_execution();
        assert_eq!(script.execution_count, 2);
    }

    #[test]
    fn test_needs_update() {
        let source = r#"
// ==UserScript==
// @name         Test Script
// @version      1.0.0
// ==/UserScript==
"#;

        let script = Userscript::new(source.to_string()).unwrap();
        assert!(script.needs_update("2.0.0"));
        assert!(!script.needs_update("0.9.0"));
        assert!(!script.needs_update("1.0.0"));
    }
}

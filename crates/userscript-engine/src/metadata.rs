//! Userscript metadata parser
//!
//! Parses the metadata block from Greasemonkey/Tampermonkey userscripts.
//! Format: // ==UserScript== ... // ==/UserScript==

use crate::{Error, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Execution timing for userscripts
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunAt {
    /// Run as soon as possible (before page loads)
    DocumentStart,
    /// Run after DOM is ready but before images load
    DocumentEnd,
    /// Run after page is fully loaded
    DocumentIdle,
    /// Run when context is ready
    ContextMenu,
}

impl Default for RunAt {
    fn default() -> Self {
        RunAt::DocumentEnd
    }
}

impl RunAt {
    /// Parse from metadata value
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "document-start" => RunAt::DocumentStart,
            "document-end" => RunAt::DocumentEnd,
            "document-idle" => RunAt::DocumentIdle,
            "context-menu" => RunAt::ContextMenu,
            _ => RunAt::default(),
        }
    }
}

/// Userscript metadata parsed from script header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserscriptMetadata {
    /// Script name (required)
    pub name: String,
    /// Namespace (optional, used with name for uniqueness)
    pub namespace: Option<String>,
    /// Version string
    pub version: Option<String>,
    /// Author name
    pub author: Option<String>,
    /// Description
    pub description: Option<String>,
    /// Homepage/support URL
    pub homepage: Option<String>,
    /// Icon URL
    pub icon: Option<String>,

    /// URL patterns where script should run (@include)
    pub includes: Vec<String>,
    /// URL patterns to match (@match)
    pub matches: Vec<String>,
    /// URL patterns to exclude (@exclude)
    pub excludes: Vec<String>,

    /// When to inject the script
    pub run_at: RunAt,
    /// Whether to run in frames
    pub noframes: bool,

    /// External scripts to load (@require)
    pub requires: Vec<String>,
    /// Named resources (@resource)
    pub resources: HashMap<String, String>,

    /// Granted capabilities (@grant)
    pub grants: Vec<String>,

    /// Domains allowed for GM_xmlhttpRequest (@connect)
    pub connect: Vec<String>,

    /// Update URL
    pub update_url: Option<String>,
    /// Download URL
    pub download_url: Option<String>,

    /// Localized names
    pub localized_names: HashMap<String, String>,
    /// Localized descriptions
    pub localized_descriptions: HashMap<String, String>,

    /// Raw metadata lines
    pub raw_metadata: Vec<String>,
}

impl UserscriptMetadata {
    /// Create new metadata with just a name
    pub fn new(name: String) -> Self {
        Self {
            name,
            namespace: None,
            version: None,
            author: None,
            description: None,
            homepage: None,
            icon: None,
            includes: Vec::new(),
            matches: Vec::new(),
            excludes: Vec::new(),
            run_at: RunAt::default(),
            noframes: false,
            requires: Vec::new(),
            resources: HashMap::new(),
            grants: Vec::new(),
            connect: Vec::new(),
            update_url: None,
            download_url: None,
            localized_names: HashMap::new(),
            localized_descriptions: HashMap::new(),
            raw_metadata: Vec::new(),
        }
    }

    /// Parse metadata from userscript source code
    pub fn parse(source: &str) -> Result<Self> {
        let mut in_metadata = false;
        let mut metadata_lines = Vec::new();

        for line in source.lines() {
            let trimmed = line.trim();

            if trimmed.starts_with("// ==UserScript==") {
                in_metadata = true;
                continue;
            }

            if trimmed.starts_with("// ==/UserScript==") {
                break;
            }

            if in_metadata {
                metadata_lines.push(trimmed.to_string());
            }
        }

        if metadata_lines.is_empty() {
            return Err(Error::MetadataParsing(
                "No metadata block found".to_string(),
            ));
        }

        Self::parse_metadata_lines(&metadata_lines)
    }

    /// Parse individual metadata lines
    fn parse_metadata_lines(lines: &[String]) -> Result<Self> {
        let mut name = None;
        let mut namespace = None;
        let mut version = None;
        let mut author = None;
        let mut description = None;
        let mut homepage = None;
        let mut icon = None;
        let mut includes = Vec::new();
        let mut matches = Vec::new();
        let mut excludes = Vec::new();
        let mut run_at = RunAt::default();
        let mut noframes = false;
        let mut requires = Vec::new();
        let mut resources = HashMap::new();
        let mut grants = Vec::new();
        let mut connect = Vec::new();
        let mut update_url = None;
        let mut download_url = None;
        let mut localized_names = HashMap::new();
        let mut localized_descriptions = HashMap::new();

        // Regex for parsing metadata lines: // @key value
        let meta_regex = Regex::new(r"^//\s*@(\S+)(?:\s+(.*))?$").unwrap();

        for line in lines {
            if let Some(captures) = meta_regex.captures(line) {
                let key = captures.get(1).map(|m| m.as_str()).unwrap_or("");
                let value = captures.get(2).map(|m| m.as_str().trim()).unwrap_or("");

                match key {
                    "name" => {
                        // Check for localization: @name:locale
                        if let Some(locale) = key.strip_prefix("name:") {
                            localized_names.insert(locale.to_string(), value.to_string());
                        } else {
                            name = Some(value.to_string());
                        }
                    }
                    "namespace" => namespace = Some(value.to_string()),
                    "version" => version = Some(value.to_string()),
                    "author" => author = Some(value.to_string()),
                    "description" => {
                        if let Some(locale) = key.strip_prefix("description:") {
                            localized_descriptions.insert(locale.to_string(), value.to_string());
                        } else {
                            description = Some(value.to_string());
                        }
                    }
                    "homepage" | "homepageURL" | "website" | "supportURL" => {
                        homepage = Some(value.to_string());
                    }
                    "icon" | "iconURL" => icon = Some(value.to_string()),
                    "include" => includes.push(value.to_string()),
                    "match" => matches.push(value.to_string()),
                    "exclude" => excludes.push(value.to_string()),
                    "run-at" => run_at = RunAt::from_str(value),
                    "noframes" => noframes = true,
                    "require" => requires.push(value.to_string()),
                    "resource" => {
                        // Format: @resource resourceName URL
                        let parts: Vec<&str> = value.splitn(2, ' ').collect();
                        if parts.len() == 2 {
                            resources.insert(parts[0].to_string(), parts[1].to_string());
                        }
                    }
                    "grant" => {
                        if value != "none" {
                            grants.push(value.to_string());
                        }
                    }
                    "connect" => connect.push(value.to_string()),
                    "updateURL" => update_url = Some(value.to_string()),
                    "downloadURL" => download_url = Some(value.to_string()),
                    _ => {
                        // Ignore unknown metadata keys
                    }
                }
            }
        }

        let name = name.ok_or_else(|| {
            Error::MetadataParsing("Missing required @name field".to_string())
        })?;

        Ok(Self {
            name,
            namespace,
            version,
            author,
            description,
            homepage,
            icon,
            includes,
            matches,
            excludes,
            run_at,
            noframes,
            requires,
            resources,
            grants,
            connect,
            update_url,
            download_url,
            localized_names,
            localized_descriptions,
            raw_metadata: lines.to_vec(),
        })
    }

    /// Check if script should run on a given URL
    pub fn should_run_on(&self, url: &str) -> bool {
        // Check excludes first
        for exclude in &self.excludes {
            if Self::matches_pattern(url, exclude) {
                return false;
            }
        }

        // Check matches
        for match_pattern in &self.matches {
            if Self::matches_pattern(url, match_pattern) {
                return true;
            }
        }

        // Check includes
        for include in &self.includes {
            if Self::matches_pattern(url, include) {
                return true;
            }
        }

        // If no patterns specified, run everywhere
        self.matches.is_empty() && self.includes.is_empty()
    }

    /// Match URL against pattern (simplified match)
    fn matches_pattern(url: &str, pattern: &str) -> bool {
        // Handle special patterns
        if pattern == "*" || pattern == "<all_urls>" {
            return true;
        }

        // Convert glob pattern to regex
        let regex_pattern = pattern
            .replace(".", "\\.")
            .replace("*", ".*")
            .replace("?", ".");

        if let Ok(regex) = Regex::new(&format!("^{}$", regex_pattern)) {
            regex.is_match(url)
        } else {
            false
        }
    }

    /// Get unique identifier (namespace + name)
    pub fn unique_id(&self) -> String {
        match &self.namespace {
            Some(ns) => format!("{}:{}", ns, self.name),
            None => self.name.clone(),
        }
    }

    /// Check if a capability is granted
    pub fn has_grant(&self, capability: &str) -> bool {
        self.grants.contains(&capability.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_metadata() {
        let source = r#"
// ==UserScript==
// @name         Test Script
// @namespace    http://example.com
// @version      1.0.0
// @description  A test userscript
// @author       Test Author
// @match        *://example.com/*
// @grant        GM_setValue
// @grant        GM_getValue
// ==/UserScript==

console.log('test');
"#;

        let metadata = UserscriptMetadata::parse(source).unwrap();
        assert_eq!(metadata.name, "Test Script");
        assert_eq!(metadata.namespace, Some("http://example.com".to_string()));
        assert_eq!(metadata.version, Some("1.0.0".to_string()));
        assert_eq!(metadata.author, Some("Test Author".to_string()));
        assert_eq!(metadata.matches.len(), 1);
        assert_eq!(metadata.grants.len(), 2);
    }

    #[test]
    fn test_parse_no_metadata() {
        let source = "console.log('no metadata');";
        let result = UserscriptMetadata::parse(source);
        assert!(result.is_err());
    }

    #[test]
    fn test_url_matching() {
        let mut metadata = UserscriptMetadata::new("Test".to_string());
        metadata.matches.push("*://example.com/*".to_string());

        assert!(metadata.should_run_on("https://example.com/page"));
        assert!(metadata.should_run_on("http://example.com/page"));
        assert!(!metadata.should_run_on("https://other.com/page"));
    }

    #[test]
    fn test_exclude_pattern() {
        let mut metadata = UserscriptMetadata::new("Test".to_string());
        metadata.matches.push("*://example.com/*".to_string());
        metadata.excludes.push("*://example.com/admin*".to_string());

        assert!(metadata.should_run_on("https://example.com/page"));
        assert!(!metadata.should_run_on("https://example.com/admin"));
    }

    #[test]
    fn test_run_at_parsing() {
        assert_eq!(RunAt::from_str("document-start"), RunAt::DocumentStart);
        assert_eq!(RunAt::from_str("document-end"), RunAt::DocumentEnd);
        assert_eq!(RunAt::from_str("document-idle"), RunAt::DocumentIdle);
        assert_eq!(RunAt::from_str("unknown"), RunAt::DocumentEnd);
    }

    #[test]
    fn test_unique_id() {
        let mut metadata = UserscriptMetadata::new("MyScript".to_string());
        assert_eq!(metadata.unique_id(), "MyScript");

        metadata.namespace = Some("com.example".to_string());
        assert_eq!(metadata.unique_id(), "com.example:MyScript");
    }

    #[test]
    fn test_has_grant() {
        let mut metadata = UserscriptMetadata::new("Test".to_string());
        metadata.grants.push("GM_setValue".to_string());

        assert!(metadata.has_grant("GM_setValue"));
        assert!(!metadata.has_grant("GM_xmlhttpRequest"));
    }

    #[test]
    fn test_resource_parsing() {
        let source = r#"
// ==UserScript==
// @name         Test Script
// @resource     icon https://example.com/icon.png
// @resource     data https://example.com/data.json
// ==/UserScript==
"#;

        let metadata = UserscriptMetadata::parse(source).unwrap();
        assert_eq!(metadata.resources.len(), 2);
        assert_eq!(
            metadata.resources.get("icon"),
            Some(&"https://example.com/icon.png".to_string())
        );
    }
}

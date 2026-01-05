//! Filter list management and loading

use crate::{Error, Result};
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Represents a single filter list
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterList {
    /// Unique identifier
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// URL to download the list from
    pub url: String,
    /// Whether the list is enabled
    pub enabled: bool,
    /// Last update timestamp
    pub last_updated: Option<DateTime<Utc>>,
    /// Number of rules in the list
    pub rule_count: usize,
    /// ETag for conditional requests
    pub etag: Option<String>,
}

impl FilterList {
    /// Create a new filter list
    pub fn new(id: String, name: String, url: String) -> Self {
        Self {
            id,
            name,
            url,
            enabled: true,
            last_updated: None,
            rule_count: 0,
            etag: None,
        }
    }

    /// Download the filter list content
    pub async fn download(&self, client: &Client) -> Result<String> {
        debug!("Downloading filter list: {}", self.name);

        let mut request = client.get(&self.url);

        // Add ETag for conditional request
        if let Some(etag) = &self.etag {
            request = request.header("If-None-Match", etag);
        }

        let response = request
            .send()
            .await
            .map_err(|e| Error::ListDownload(format!("Failed to download {}: {}", self.name, e)))?;

        if response.status() == 304 {
            debug!("Filter list {} not modified", self.name);
            return Err(Error::ListDownload("Not modified".to_string()));
        }

        if !response.status().is_success() {
            return Err(Error::ListDownload(format!(
                "HTTP {}: {}",
                response.status(),
                self.url
            )));
        }

        let content = response
            .text()
            .await
            .map_err(|e| Error::ListDownload(format!("Failed to read response: {}", e)))?;

        info!("Downloaded filter list {}: {} bytes", self.name, content.len());
        Ok(content)
    }
}

/// Manages multiple filter lists
#[derive(Debug, Clone)]
pub struct FilterListManager {
    lists: Arc<RwLock<HashMap<String, FilterList>>>,
    http_client: Client,
    data_dir: PathBuf,
}

impl FilterListManager {
    /// Create a new filter list manager
    pub fn new(data_dir: PathBuf) -> Self {
        let http_client = Client::builder()
            .user_agent("Mozilla/5.0 (compatible; AdBlocker/0.2.0)")
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap();

        Self {
            lists: Arc::new(RwLock::new(HashMap::new())),
            http_client,
            data_dir,
        }
    }

    /// Add a filter list
    pub fn add_list(&self, list: FilterList) {
        let mut lists = self.lists.write();
        lists.insert(list.id.clone(), list);
    }

    /// Remove a filter list
    pub fn remove_list(&self, id: &str) -> Result<()> {
        let mut lists = self.lists.write();
        lists
            .remove(id)
            .ok_or_else(|| Error::ListNotFound(id.to_string()))?;
        Ok(())
    }

    /// Get a filter list by ID
    pub fn get_list(&self, id: &str) -> Option<FilterList> {
        let lists = self.lists.read();
        lists.get(id).cloned()
    }

    /// Get all filter lists
    pub fn get_all_lists(&self) -> Vec<FilterList> {
        let lists = self.lists.read();
        lists.values().cloned().collect()
    }

    /// Enable or disable a filter list
    pub fn set_enabled(&self, id: &str, enabled: bool) -> Result<()> {
        let mut lists = self.lists.write();
        let list = lists
            .get_mut(id)
            .ok_or_else(|| Error::ListNotFound(id.to_string()))?;
        list.enabled = enabled;
        Ok(())
    }

    /// Download all enabled filter lists
    pub async fn download_all(&self) -> Result<Vec<(String, String)>> {
        let lists = self.get_all_lists();
        let mut results = Vec::new();

        for list in lists {
            if !list.enabled {
                continue;
            }

            match list.download(&self.http_client).await {
                Ok(content) => {
                    results.push((list.id.clone(), content));

                    // Update last_updated timestamp
                    let mut lists_lock = self.lists.write();
                    if let Some(stored_list) = lists_lock.get_mut(&list.id) {
                        stored_list.last_updated = Some(Utc::now());
                    }
                }
                Err(e) => {
                    warn!("Failed to download filter list {}: {}", list.name, e);
                }
            }
        }

        info!("Downloaded {} filter lists", results.len());
        Ok(results)
    }

    /// Load default filter lists
    pub fn load_defaults(&self) {
        // EasyList
        self.add_list(FilterList::new(
            "easylist".to_string(),
            "EasyList".to_string(),
            "https://easylist.to/easylist/easylist.txt".to_string(),
        ));

        // EasyPrivacy
        self.add_list(FilterList::new(
            "easyprivacy".to_string(),
            "EasyPrivacy".to_string(),
            "https://easylist.to/easylist/easyprivacy.txt".to_string(),
        ));

        // AdGuard Base Filter
        self.add_list(FilterList::new(
            "adguard-base".to_string(),
            "AdGuard Base Filter".to_string(),
            "https://filters.adtidy.org/extension/chromium/filters/2.txt".to_string(),
        ));

        // AdGuard Tracking Protection
        self.add_list(FilterList::new(
            "adguard-tracking".to_string(),
            "AdGuard Tracking Protection".to_string(),
            "https://filters.adtidy.org/extension/chromium/filters/3.txt".to_string(),
        ));

        info!("Loaded {} default filter lists", self.lists.read().len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_list_creation() {
        let list = FilterList::new(
            "test".to_string(),
            "Test List".to_string(),
            "https://example.com/filters.txt".to_string(),
        );

        assert_eq!(list.id, "test");
        assert_eq!(list.name, "Test List");
        assert!(list.enabled);
        assert_eq!(list.rule_count, 0);
    }

    #[test]
    fn test_list_manager() {
        let temp_dir = std::env::temp_dir().join("filter-engine-test");
        let manager = FilterListManager::new(temp_dir);

        let list = FilterList::new(
            "test".to_string(),
            "Test List".to_string(),
            "https://example.com/filters.txt".to_string(),
        );

        manager.add_list(list.clone());

        let retrieved = manager.get_list("test");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "Test List");

        let all = manager.get_all_lists();
        assert_eq!(all.len(), 1);

        manager.set_enabled("test", false).unwrap();
        let updated = manager.get_list("test").unwrap();
        assert!(!updated.enabled);

        manager.remove_list("test").unwrap();
        assert!(manager.get_list("test").is_none());
    }
}

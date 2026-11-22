//! Filter list management and loading

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
}

/// The default filter lists seeded for a fresh install.
///
/// Single source of truth, shared by the in-memory manager and the persistent store so both agree
/// on what "the defaults" are.
pub fn default_filter_lists() -> Vec<FilterList> {
    vec![
        FilterList::new(
            "easylist".to_string(),
            "EasyList".to_string(),
            "https://easylist.to/easylist/easylist.txt".to_string(),
        ),
        FilterList::new(
            "easyprivacy".to_string(),
            "EasyPrivacy".to_string(),
            "https://easylist.to/easylist/easyprivacy.txt".to_string(),
        ),
        FilterList::new(
            "adguard-base".to_string(),
            "AdGuard Base Filter".to_string(),
            "https://filters.adtidy.org/extension/chromium/filters/2.txt".to_string(),
        ),
        FilterList::new(
            "adguard-tracking".to_string(),
            "AdGuard Tracking Protection".to_string(),
            "https://filters.adtidy.org/extension/chromium/filters/3.txt".to_string(),
        ),
    ]
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
}

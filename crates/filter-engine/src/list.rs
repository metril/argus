//! Filter list management and loading

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::formats::ListFormat;

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
    /// Rules dropped as duplicates at the last build that used the current download; `None`
    /// when no build has seen this content yet (then `rule_count` is only an approximation).
    #[serde(default)]
    pub duplicate_count: Option<usize>,
    /// ETag for conditional requests
    pub etag: Option<String>,
    /// Format override; `Auto` (the default) detects it from the content.
    #[serde(default)]
    pub format: ListFormat,
    /// Treat every rule in this list as an exception (an allowlist).
    #[serde(default)]
    pub allowlist: bool,
    /// Extended rules from this list may run code in pages and rewrite content (`$replace`,
    /// `$urltransform`, `#%#`, ...). Off unless the user opts the list in.
    #[serde(default)]
    pub trusted: bool,
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
            duplicate_count: None,
            etag: None,
            format: ListFormat::Auto,
            allowlist: false,
            trusted: false,
        }
    }
}

/// Whether this URL is a known uBlock Origin / AdGuard Base list (used to migrate lists installed
/// before catalogue trust existed). Never decided by list id: ids are user-chosen.
pub fn is_known_trusted_source(url: &str) -> bool {
    let u = url.split(['?', '#']).next().unwrap_or(url);
    const UBO: &str = "https://ublockorigin.github.io/uAssets/filters/";
    const UBO_RAW: &str = "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/";
    if let Some(f) = u.strip_prefix(UBO).or_else(|| u.strip_prefix(UBO_RAW)) {
        let name = f.trim_end_matches(".txt").trim_end_matches(".min");
        return matches!(
            name,
            "filters"
                | "privacy"
                | "badware"
                | "quick-fixes"
                | "unbreak"
                | "resource-abuse"
                | "annoyances"
        );
    }
    // AdGuard's own numbered filters: 2 Base, 3 Tracking Protection, 11 Mobile Ads, 17 URL
    // Tracking, 4 Social Media, 14 Annoyances.
    u.strip_prefix("https://filters.adtidy.org/")
        .is_some_and(|r| {
            let Some((_, f)) = r.rsplit_once("/filters/") else {
                return false;
            };
            matches!(
                f,
                "2.txt"
                    | "2_without_easylist.txt"
                    | "3.txt"
                    | "4.txt"
                    | "11.txt"
                    | "14.txt"
                    | "17.txt"
            )
        })
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

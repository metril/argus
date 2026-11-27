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
            "filters" | "privacy" | "badware" | "quick-fixes" | "unbreak" | "resource-abuse"
        );
    }
    // AdGuard's own numbered filters: 2 Base, 3 Tracking Protection, 11 Mobile Ads, 17 URL Tracking.
    u.strip_prefix("https://filters.adtidy.org/")
        .is_some_and(|r| {
            let Some((_, f)) = r.rsplit_once("/filters/") else {
                return false;
            };
            matches!(
                f,
                "2.txt" | "2_without_easylist.txt" | "3.txt" | "11.txt" | "17.txt"
            )
        })
}

/// The default filter lists seeded for a fresh install: the union of uBlock Origin Lite's default
/// set and AdGuard for Windows' recommended lists (Base, Tracking Protection, URL Tracking, Mobile
/// Ads). AdGuard Annoyances and Social Media are left out on purpose: they break embeds, chat
/// widgets and logins. Existing installs keep their set.
///
/// Single source of truth, shared by the in-memory manager and the persistent store so both agree
/// on what "the defaults" are.
pub fn default_filter_lists() -> Vec<FilterList> {
    const UBO: &str = "https://ublockorigin.github.io/uAssets/filters";
    let ubo = |id: &str, name: &str, file: &str| {
        let mut l = FilterList::new(id.into(), name.into(), format!("{UBO}/{file}"));
        l.format = ListFormat::Ubo;
        l.trusted = true;
        l
    };
    let adguard = |id: &str, name: &str, file: &str| {
        let mut l = FilterList::new(
            id.into(),
            name.into(),
            format!("https://filters.adtidy.org/extension/ublock/filters/{file}"),
        );
        l.format = ListFormat::Ubo;
        l.trusted = is_known_trusted_source(&l.url);
        l
    };
    let mut easylist = FilterList::new(
        "easylist".into(),
        "EasyList".into(),
        "https://easylist.to/easylist/easylist.txt".into(),
    );
    easylist.format = ListFormat::Abp;
    let mut easyprivacy = FilterList::new(
        "easyprivacy".into(),
        "EasyPrivacy".into(),
        "https://easylist.to/easylist/easyprivacy.txt".into(),
    );
    easyprivacy.format = ListFormat::Abp;
    let mut lowe = FilterList::new(
        "peter-lowe".into(),
        "Peter Lowe's Ad and tracking server list".into(),
        "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext"
            .into(),
    );
    lowe.format = ListFormat::Hosts;
    vec![
        ubo("ublock-filters", "uBlock filters", "filters.min.txt"),
        ubo(
            "ublock-privacy",
            "uBlock filters - Privacy",
            "privacy.min.txt",
        ),
        ubo(
            "ublock-badware",
            "uBlock filters - Badware risks",
            "badware.min.txt",
        ),
        ubo(
            "ublock-quick-fixes",
            "uBlock filters - Quick fixes",
            "quick-fixes.min.txt",
        ),
        ubo(
            "ublock-unbreak",
            "uBlock filters - Unbreak",
            "unbreak.min.txt",
        ),
        easylist,
        easyprivacy,
        lowe,
        adguard(
            "adguard-base",
            "AdGuard Base filter",
            "2_without_easylist.txt",
        ),
        adguard(
            "adguard-tracking",
            "AdGuard Tracking Protection filter",
            "3.txt",
        ),
        adguard(
            "adguard-url-tracking",
            "AdGuard URL Tracking filter",
            "17.txt",
        ),
        adguard("adguard-mobile", "AdGuard Mobile Ads filter", "11.txt"),
    ]
}

/// A well-known list the UI/API can offer. Metadata only: nothing is fetched unless the user
/// adds the entry as a list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CatalogueEntry {
    pub id: &'static str,
    pub name: &'static str,
    pub url: &'static str,
    pub format: ListFormat,
    pub category: &'static str,
    /// Licence / usage note of the list (check before redistributing).
    pub licence: &'static str,
    /// The licence forbids commercial use.
    pub noncommercial: bool,
}

impl CatalogueEntry {
    /// A (disabled) [`FilterList`] for this entry.
    pub fn to_filter_list(&self) -> FilterList {
        let mut l = FilterList::new(self.id.into(), self.name.into(), self.url.into());
        l.enabled = false;
        l.format = self.format;
        l.trusted = is_known_trusted_source(self.url);
        l
    }
}

/// Default-disabled catalogue of well-known hosts-format, domain-format and IP lists.
pub fn catalogue() -> Vec<CatalogueEntry> {
    use ListFormat::{Domains, Hosts, IpList};
    let e = |id, name, url, format, category, licence| CatalogueEntry {
        id,
        name,
        url,
        format,
        category,
        licence,
        noncommercial: false,
    };
    let nc = |mut e: CatalogueEntry| {
        e.noncommercial = true;
        e
    };
    vec![
        nc(e("peter-lowe", "Peter Lowe's Ad and tracking server list", "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext", Hosts, "ads+tracking", "free for personal use")),
        e("stevenblack-unified", "StevenBlack Unified Hosts", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", Hosts, "ads+malware", "MIT"),
        e("adaway", "AdAway", "https://adaway.org/hosts.txt", Hosts, "ads", "CC BY 3.0"),
        e("blocklistproject-ads", "The Block List Project: Ads", "https://blocklistproject.github.io/Lists/ads.txt", Hosts, "ads", "Unlicense"),
        nc(e("developerdan-ads", "Developer Dan's Ads and Tracking Extended", "https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt", Hosts, "ads+tracking", "CC BY-NC-SA 4.0")),
        e("hagezi-light-domains", "HaGeZi Light (domains)", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt", Domains, "ads+tracking", "GPL-3.0"),
        e("hagezi-pro-domains", "HaGeZi Pro (domains)", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt", Domains, "ads+tracking+malware", "GPL-3.0"),
        e("hagezi-tif-domains", "HaGeZi Threat Intelligence Feeds (domains)", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt", Domains, "malware", "GPL-3.0"),
        e("oisd-small", "OISD Small (domains)", "https://small.oisd.nl/domainswild2", Domains, "ads+tracking+malware", "GPL-3.0"),
        nc(e("phishing-army", "Phishing Army", "https://phishing.army/download/phishing_army_blocklist.txt", Domains, "phishing", "CC BY-NC 4.0")),
        nc(e("spamhaus-drop", "Spamhaus DROP (IP ranges)", "https://www.spamhaus.org/drop/drop.txt", IpList, "malware", "free for non-commercial use")),
        e("feodo-ips", "Feodo Tracker IP Blocklist", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", IpList, "malware", "CC0"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_is_well_formed_and_disabled() {
        let c = catalogue();
        assert!(c.len() >= 10);
        let ids: std::collections::HashSet<_> = c.iter().map(|e| e.id).collect();
        assert_eq!(ids.len(), c.len(), "unique ids");
        for e in &c {
            assert!(e.url.starts_with("https://"));
            assert!(!e.to_filter_list().enabled);
            assert_ne!(e.format, ListFormat::Auto);
        }
        let defaults: Vec<_> = default_filter_lists().into_iter().map(|l| l.id).collect();
        assert!(c
            .iter()
            .all(|e| e.id == "peter-lowe" || !defaults.iter().any(|d| d == e.id)));
    }

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

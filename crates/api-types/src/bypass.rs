//! Bypass: hosts the proxy does not intercept (and, in `full` mode, does not filter or log).

use serde::{Deserialize, Serialize};

/// What the proxy does for a bypassed host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum BypassMode {
    /// Tunnel without MITM; host-level blocking still applies; a `passthrough` event (host
    /// only) is logged.
    NoDecrypt,
    /// No MITM, no filtering, no log event; only an aggregate counter.
    Full,
}

/// A built-in category.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct BypassCategoryDto {
    pub id: String,
    pub title: String,
    pub description: String,
    /// Domains curated in the category.
    pub host_count: usize,
    pub enabled: bool,
    pub mode: BypassMode,
    /// The mode the category ships with.
    pub default_mode: BypassMode,
    /// Its list has been downloaded and verified (or loaded from the verified cache).
    pub loaded: bool,
}

/// Change a category; omitted fields stay.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct UpdateBypassCategory {
    pub enabled: Option<bool>,
    pub mode: Option<BypassMode>,
}

/// The domains of a category.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct BypassHostsResponse {
    /// Matching domains (a bare domain covers its subdomains too; `*.x` only subdomains).
    pub items: Vec<String>,
    /// Matching domains across all pages.
    pub total: usize,
    /// Pass back as `cursor` for the next page (absent on the last page).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub has_more: bool,
}

/// A custom entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct BypassEntryDto {
    pub id: String,
    /// Exact host or `*.suffix`.
    pub pattern: String,
    pub mode: BypassMode,
    /// `custom`, or `migrated` for entries made from the old `tls_passthrough_hosts` setting.
    pub source: String,
    pub note: Option<String>,
    /// Unix seconds.
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct CreateBypassEntry {
    pub pattern: String,
    /// Default `full`.
    pub mode: Option<BypassMode>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct UpdateBypassEntry {
    pub pattern: Option<String>,
    pub mode: Option<BypassMode>,
    /// An empty string clears the note.
    pub note: Option<String>,
}

/// Entries per mode, for the current search text.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct BypassEntryCounts {
    pub all: usize,
    pub no_decrypt: usize,
    pub full: usize,
    /// First characters (`A`-`Z`, `#`) present among the rows matching the current filters.
    #[serde(default)]
    pub letters: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct BypassEntriesPage {
    pub items: Vec<BypassEntryDto>,
    pub next_cursor: Option<String>,
    pub total: usize,
    pub counts: BypassEntryCounts,
    pub limit: u32,
    pub has_more: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<u32>,
}

/// A subscribed exclusion list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct BypassSubscriptionDto {
    pub id: String,
    pub name: String,
    pub url: String,
    pub mode: BypassMode,
    pub enabled: bool,
    pub host_count: usize,
    /// RFC 3339.
    pub last_fetched: Option<String>,
    /// A real failure of the last fetch (network, signature, parse). Skipped lines are not.
    pub last_error: Option<String>,
    /// Lines of the list that were skipped (invalid or too broad); not an error.
    #[serde(default)]
    pub skipped_lines: u32,
    /// Up to 5 of the skipped lines.
    #[serde(default)]
    pub skipped_sample: Vec<String>,
}

/// Subscribe to a list: either give `name` and `url`, or `suggested_id` from
/// `GET /bypass/subscriptions/suggested` (which also supplies the default mode).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct CreateBypassSubscription {
    pub name: Option<String>,
    pub url: Option<String>,
    pub suggested_id: Option<String>,
    /// Default `no_decrypt` (or the suggestion's default).
    pub mode: Option<BypassMode>,
    pub enabled: Option<bool>,
}

/// A ready-made list to subscribe to in one step.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct SuggestedSubscription {
    pub id: String,
    pub name: String,
    pub url: String,
    pub description: String,
    pub default_mode: BypassMode,
    /// A subscription to this URL exists.
    pub subscribed: bool,
}

/// Whether decryption is held back because the first-party lists have not loaded yet.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct FailsafeDto {
    /// HTTPS is tunnelled, not decrypted (hostname/SNI blocking still applies).
    pub active: bool,
    pub reason: Option<String>,
}

/// Bypass-wide settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct BypassSettings {
    /// Tunnel (do not decrypt) sites whose certificate is an Extended Validation one.
    pub ev_no_decrypt: bool,
    /// Decrypt even while an enabled first-party list has not loaded (overrides the fail-safe).
    pub decrypt_without_lists: bool,
    pub failsafe: FailsafeDto,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct UpdateBypassSettings {
    pub ev_no_decrypt: Option<bool>,
    pub decrypt_without_lists: Option<bool>,
}

/// One first-party category in `GET /bypass/argus-lists`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ArgusCategoryDto {
    pub id: String,
    pub name: String,
    pub description: String,
    pub host_count: usize,
    pub enabled: bool,
    pub mode: BypassMode,
    pub loaded: bool,
}

/// State of the first-party lists (argus-lists).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ArgusListsStatus {
    /// Installed release (`vYYYY.MM.DD[.N]`); `null` until a verified copy has loaded.
    pub version: Option<String>,
    /// RFC 3339: when the installed release was fetched.
    pub updated_at: Option<String>,
    /// RFC 3339: the last check, successful or not.
    pub last_checked: Option<String>,
    /// A real failure of the last check (fetch, signature, digest, version). Skipped lines are
    /// not.
    pub last_error: Option<String>,
    /// Lines skipped across the installed lists (invalid or too broad); not an error.
    #[serde(default)]
    pub skipped_lines: u32,
    /// Up to 5 of the skipped lines.
    #[serde(default)]
    pub skipped_sample: Vec<String>,
    pub categories: Vec<ArgusCategoryDto>,
    /// The trusted root set (the signed `roots.json` of the same release).
    #[serde(default)]
    pub roots: Option<RootsStatusDto>,
}

/// State of the trusted root set used to verify upstream servers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct RootsStatusDto {
    /// Serial of the active set; the compiled-in set has its own serial.
    pub serial: u64,
    /// Number of trusted roots.
    pub roots: u32,
    /// A signed set is active (otherwise the compiled-in set).
    pub signed: bool,
    /// RFC 3339: when the active set was installed.
    pub updated_at: Option<String>,
    /// RFC 3339: the last check, successful or not.
    pub last_checked: Option<String>,
    /// A real failure of the last check (fetch, signature, validation, rollback).
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct UpdateBypassSubscription {
    pub name: Option<String>,
    pub url: Option<String>,
    pub mode: Option<BypassMode>,
    pub enabled: Option<bool>,
}

/// The effective answer for one host.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct BypassCheckResponse {
    pub host: String,
    pub bypassed: bool,
    pub mode: Option<BypassMode>,
    /// `builtin:<category>`, `custom`, `migrated` or `sub:<id>`.
    pub source: Option<String>,
    /// The pattern that matched.
    pub pattern: Option<String>,
}

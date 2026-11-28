//! The filter-list catalogue: entries, collections and the signed subscription's status.

use serde::{Deserialize, Serialize};

/// A well-known list that can be added with `POST /lists/catalogue/{id}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct CatalogueEntryResponse {
    pub id: String,
    pub name: String,
    pub url: String,
    /// `abp`, `ubo`, `adguard`, `hosts`, `domains` or `ips`.
    pub format: String,
    pub category: String,
    pub licence: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub homepage: String,
    /// Language/region the list targets (`de`, `fr`, ...).
    #[serde(default)]
    pub region: Option<String>,
    /// The licence forbids commercial use.
    #[serde(default)]
    pub noncommercial: bool,
    #[serde(default)]
    pub licence_note: Option<String>,
    /// Adding it makes the list trusted (extended rules may run).
    #[serde(default)]
    pub trusted: bool,
    /// Recommended: installed and enabled on a fresh install.
    #[serde(default)]
    pub default_enabled: bool,
    /// Already installed as a list.
    pub installed: bool,
}

/// The catalogue and where it came from.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct CatalogueResponse {
    /// `signed` for a fetched argus-lists release, `snapshot` for the signed copy built into the
    /// binary (no release fetched yet), `signed` with no entries while none has loaded.
    pub source: String,
    /// When the signed copy was fetched and verified (RFC 3339); absent for `snapshot` and while
    /// none has loaded.
    pub fetched_at: Option<String>,
    /// Release of the signed copy.
    pub version: Option<String>,
    pub entries: Vec<CatalogueEntryResponse>,
    /// The subscription: source, release in force, outcome of the checks.
    pub status: CatalogueStatus,
    /// Named groups of lists, with counts for this install.
    #[serde(default)]
    pub collections: Vec<CollectionResponse>,
}

/// The signed catalogue subscription (`filters.json` of argus-lists).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct CatalogueStatus {
    /// Where the catalogue is fetched from.
    pub url: String,
    /// Release in force (`vYYYY.MM.DD[.N]`); absent while none has loaded.
    pub version: Option<String>,
    /// `snapshot` (built into the binary), `cache` (loaded from disk at start) or `fetched`.
    pub origin: Option<String>,
    /// When the copy in force was fetched (RFC 3339); absent for `snapshot`.
    pub fetched_at: Option<String>,
    pub last_checked: Option<String>,
    pub next_check: Option<String>,
    /// Last successful check.
    pub last_ok: Option<String>,
    /// Why the last check failed; absent after a success.
    pub last_error: Option<String>,
}

/// A named group of catalogue lists with its state on this install, computed from the lists.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct CollectionResponse {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// What turning the collection on may break.
    #[serde(default)]
    pub warning: Option<String>,
    /// Catalogue ids of its lists.
    pub lists: Vec<String>,
    /// Lists of the collection that are installed.
    pub installed: usize,
    /// Lists of the collection that are installed and enabled.
    pub enabled: usize,
    pub total: usize,
}

/// Request of `POST /lists/catalogue/collections/{id}/apply`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ApplyCollectionRequest {
    /// Only report what would change.
    #[serde(default)]
    pub dry_run: bool,
}

/// What applying a collection does (or did).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ApplyCollectionResponse {
    pub dry_run: bool,
    /// Lists added from the catalogue (enabled).
    pub add: Vec<String>,
    /// Installed lists that get turned on.
    pub enable: Vec<String>,
    /// Lists whose trust changes to what the catalogue says (among those added or enabled).
    pub trust: Vec<String>,
    /// Lists already installed and on, left alone.
    pub already: Vec<String>,
    /// Installed lists that reuse a catalogue id with another URL: never changed by apply.
    #[serde(default)]
    pub conflict: Vec<CollectionConflict>,
}

/// A list that clashes with a catalogue entry of the same id.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct CollectionConflict {
    pub id: String,
    pub reason: String,
}

/// Result of `POST /lists/catalogue/collections/{id}/disable`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct DisableCollectionResponse {
    /// Lists turned off (they stay installed).
    pub disabled: Vec<String>,
}

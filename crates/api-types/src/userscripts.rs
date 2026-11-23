//! Userscript install/update/storage/export DTOs.

use serde::{Deserialize, Serialize};

fn yes() -> bool {
    true
}

/// Start an install: exactly one of `source` or `url`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct PlanUserscriptRequest {
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
}

/// A fetched `@require`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct PlanRequireDto {
    pub url: String,
    pub size_bytes: usize,
    /// An `@require` integrity hash was present and verified.
    pub sri_verified: bool,
}

/// A fetched `@resource`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct PlanResourceDto {
    pub name: String,
    pub url: String,
    pub size_bytes: usize,
    pub sri_verified: bool,
}

/// What an install would grant, to approve with `confirm`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct UserscriptPlanResponse {
    pub plan_id: String,
    pub expires_in_secs: u64,
    pub name: String,
    pub namespace: Option<String>,
    pub version: Option<String>,
    pub description: Option<String>,
    pub grants: Vec<String>,
    pub connect: Vec<String>,
    pub matches: Vec<String>,
    /// Matches (nearly) every site (`<all_urls>`, `*://*/*`, ...).
    pub broad_match: bool,
    /// `@connect *`: needs `allow_connect_all` on confirm.
    pub connect_all: bool,
    pub network: bool,
    pub cookies: bool,
    pub downloads: bool,
    pub clipboard: bool,
    pub notifications: bool,
    pub unsupported: Vec<String>,
    pub warnings: Vec<String>,
    pub requires: Vec<PlanRequireDto>,
    pub resources: Vec<PlanResourceDto>,
    pub already_installed: bool,
    pub installed_version: Option<String>,
    /// Set when the script is already installed: confirming replaces it with this plan.
    #[serde(default)]
    pub update: Option<PlanUpdateDto>,
}

/// Confirm a plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ConfirmPlanRequest {
    /// Approve `@connect *` (rejected if the script does not declare it).
    #[serde(default)]
    pub allow_connect_all: bool,
    #[serde(default = "yes")]
    pub enable: bool,
}

/// Capability changes of an update.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct UpdateDiffDto {
    pub added_matches: Vec<String>,
    pub added_connect: Vec<String>,
    pub added_grants: Vec<String>,
    pub removed_matches: Vec<String>,
    pub removed_connect: Vec<String>,
    pub removed_grants: Vec<String>,
    /// Other widening: removed `@exclude`, dropped `@noframes`, injection mode, earlier
    /// `@run-at`, new or changed `@require`/`@resource`, changed required code.
    #[serde(default)]
    pub widened: Vec<String>,
}

/// What confirming the plan of an already installed script would change.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct PlanUpdateDto {
    pub diff: UpdateDiffDto,
    /// The change widens what the script can match, reach or run; confirming approves it.
    pub needs_reapproval: bool,
    pub is_newer: bool,
}

/// An update waiting for approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct PendingUpdateDto {
    pub new_version: Option<String>,
    pub diff: UpdateDiffDto,
    pub needs_reapproval: bool,
    pub found_at: String,
}

/// Check for an update.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct CheckUpdateRequest {
    /// Apply a non-widening update immediately.
    #[serde(default)]
    pub apply: bool,
}

/// Result of an update check.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct CheckUpdateResponse {
    /// `up_to_date`, `updated` or `pending_approval`.
    pub status: String,
    pub current_version: Option<String>,
    pub new_version: Option<String>,
    pub diff: Option<UpdateDiffDto>,
    pub script: crate::UserscriptResponse,
}

/// Approve a pending update.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ApproveUpdateRequest {
    /// Also approve a newly requested `@connect *`.
    #[serde(default)]
    pub allow_connect_all: bool,
}

/// One stored GM value.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct StorageValueDto {
    pub name: String,
    pub size_bytes: usize,
    /// First 200 characters of the JSON value.
    pub preview: String,
}

/// A script's stored values.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct UserscriptStorageResponse {
    pub used_bytes: u64,
    pub quota_bytes: u64,
    pub values: Vec<StorageValueDto>,
}

/// Exported `@require`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ExportedRequire {
    pub url: String,
    pub content: String,
}

/// Exported `@resource`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ExportedResource {
    pub name: String,
    pub url: String,
    pub mime: String,
    pub data_b64: String,
}

/// Exported dependencies.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ExportedAssets {
    #[serde(default)]
    pub requires: Vec<ExportedRequire>,
    #[serde(default)]
    pub resources: Vec<ExportedResource>,
}

/// One script in a bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ExportedUserscript {
    pub source: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub allow_connect_all: bool,
    #[serde(default)]
    pub assets: ExportedAssets,
    /// GM values (only with `values=true`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "server", schema(value_type = Option<std::collections::HashMap<String, Object>>))]
    pub values: Option<std::collections::BTreeMap<String, serde_json::Value>>,
}

/// Bundle format marker.
pub const USERSCRIPT_BUNDLE_FORMAT: &str = "argus-userscripts-v1";
/// Pre-rename bundle format, still accepted on import.
pub const LEGACY_USERSCRIPT_BUNDLE_FORMAT: &str = "adblocker-userscripts-v1";

/// Export / import bundle (JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct UserscriptBundle {
    pub format: String,
    pub scripts: Vec<ExportedUserscript>,
    /// Import only: `skip` (default) or `replace` existing scripts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_conflict: Option<String>,
    /// Import only: approve the bundle as written (enabled state and `@connect *` approvals).
    /// Without it every imported script arrives disabled and unapproved.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub approve: bool,
}

/// Per-script import outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ImportResultDto {
    pub id: Option<String>,
    pub name: Option<String>,
    /// `installed`, `replaced`, `skipped` or `error`.
    pub status: String,
    pub error: Option<String>,
    /// Imported disabled / without approvals; enable it from the script's page.
    #[serde(default)]
    pub pending_approval: bool,
}

/// Import outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ImportUserscriptsResponse {
    pub results: Vec<ImportResultDto>,
}

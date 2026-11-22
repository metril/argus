//! Shared API DTOs — the single source of truth for the HTTP contract between
//! `web-api` (server) and `web-ui` (wasm client).
//!
//! IDs and timestamps are represented as `String` (the exact JSON wire form:
//! UUIDs as their hyphenated string, timestamps as RFC 3339). This keeps the
//! crate dependency-free for the wasm client. The server converts its internal
//! `Uuid`/`DateTime<Utc>` values to these strings at the response boundary.
//!
//! Server-only concerns — `validator::Validate` and `utoipa::ToSchema` — are
//! gated behind the `server` feature so they never enter the wasm bundle.

use serde::{Deserialize, Serialize};

pub mod scopes;
pub use scopes::{scope_table_markdown, Scope};

mod more;
pub use more::*;

mod policy;
pub use policy::*;

pub mod profiles;
pub use profiles::*;

mod userscripts;
pub use userscripts::*;

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

/// User role for authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum UserRole {
    /// Full administrative access.
    Admin,
    /// Read/write access to configurations.
    User,
    /// Read-only access (dashboard viewing).
    #[default]
    Viewer,
}

impl UserRole {
    /// Whether the role has admin privileges.
    pub fn is_admin(&self) -> bool {
        matches!(self, Self::Admin)
    }

    /// Whether the role can modify settings.
    pub fn can_modify(&self) -> bool {
        matches!(self, Self::Admin | Self::User)
    }
}

/// Login request payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(validator::Validate, utoipa::ToSchema))]
pub struct LoginRequest {
    #[cfg_attr(
        feature = "server",
        validate(length(min = 3, max = 50, message = "Username must be 3-50 characters"))
    )]
    pub username: String,

    #[cfg_attr(
        feature = "server",
        validate(length(min = 8, max = 128, message = "Password must be 8-128 characters"))
    )]
    pub password: String,
}

/// Register request payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(validator::Validate, utoipa::ToSchema))]
pub struct RegisterRequest {
    #[cfg_attr(
        feature = "server",
        validate(length(min = 3, max = 50, message = "Username must be 3-50 characters"))
    )]
    #[cfg_attr(feature = "server", validate(custom(function = "validate_username")))]
    pub username: String,

    #[cfg_attr(
        feature = "server",
        validate(length(min = 8, max = 128, message = "Password must be 8-128 characters"))
    )]
    pub password: String,

    #[cfg_attr(
        feature = "server",
        validate(must_match(other = "password", message = "Passwords must match"))
    )]
    pub password_confirm: String,
}

/// Validate username: alphanumeric with underscores only.
#[cfg(feature = "server")]
pub fn validate_username(username: &str) -> Result<(), validator::ValidationError> {
    if username.chars().all(|c| c.is_alphanumeric() || c == '_') {
        Ok(())
    } else {
        let mut err = validator::ValidationError::new("invalid_username");
        err.message = Some("Username must be alphanumeric with underscores only".into());
        Err(err)
    }
}

/// Safe user info (no sensitive data). `id`/`created_at`/`last_login` are wire
/// strings (UUID / RFC 3339).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct UserInfo {
    pub id: String,
    pub username: String,
    pub role: UserRole,
    pub created_at: String,
    pub last_login: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Effective scopes granted by the role.
    #[serde(default)]
    pub scopes: Vec<Scope>,
}

fn default_true() -> bool {
    true
}

/// Login/register response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct LoginResponse {
    pub user: UserInfo,
    pub expires_in: u64,
    pub message: String,
}

/// Register response is structurally identical to the login response.
pub type RegisterResponse = LoginResponse;

/// Generic `{ "message": ... }` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct MessageResponse {
    pub message: String,
}

/// Active session description.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct SessionInfo {
    pub id: String,
    pub created_at: String,
    pub last_activity: String,
    #[serde(default)]
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_id: String,
    #[serde(default)]
    pub username: String,
    /// True for the session making this request.
    #[serde(default)]
    pub current: bool,
}

// ---------------------------------------------------------------------------
// Proxy
// ---------------------------------------------------------------------------

/// Current proxy configuration (response).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ProxyConfigResponse {
    pub host: String,
    pub port: u16,
    pub max_connections: u32,
    pub enable_http2: bool,
    pub enable_websockets: bool,
    pub enable_mitm: bool,
    pub connection_timeout_secs: u64,
    pub request_timeout_secs: u64,
    pub enable_adblock: bool,
    /// Whether filter lists refresh automatically.
    #[serde(default)]
    pub auto_update: bool,
    /// Hours between automatic list refreshes.
    #[serde(default)]
    pub update_interval_hours: u64,
    /// Transparent-gateway listener port (`None` = off).
    #[serde(default)]
    pub transparent_port: Option<u16>,
    /// TLS hosts never intercepted (exact or `*.suffix`).
    #[serde(default)]
    pub tls_passthrough_hosts: Vec<String>,
    /// Also refuse private-range destinations.
    #[serde(default)]
    pub block_private_destinations: bool,
    /// CIDR exceptions to the destination refusals.
    #[serde(default)]
    pub allowed_destinations: Vec<String>,
    /// CIDRs of clients allowed to use the proxy.
    #[serde(default)]
    pub allowed_clients: Vec<String>,
}

/// Result of a config update: the new config plus which changes are already live and which
/// need a restart.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct UpdateProxyConfigResponse {
    #[serde(flatten)]
    pub config: ProxyConfigResponse,
    /// Fields that took effect immediately.
    pub applied: Vec<String>,
    /// Fields saved to the config file that only apply after a restart.
    pub restart_required: Vec<String>,
}

/// Partial proxy configuration update. Every field is optional; omitted fields
/// are left unchanged.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(validator::Validate, utoipa::ToSchema))]
pub struct UpdateProxyConfigRequest {
    #[cfg_attr(feature = "server", validate(length(min = 1, max = 255)))]
    pub host: Option<String>,

    #[cfg_attr(feature = "server", validate(range(min = 1, max = 65535)))]
    pub port: Option<u16>,

    #[cfg_attr(feature = "server", validate(range(min = 1, max = 100000)))]
    pub max_connections: Option<u32>,

    pub enable_http2: Option<bool>,
    pub enable_websockets: Option<bool>,
    pub enable_mitm: Option<bool>,

    #[cfg_attr(feature = "server", validate(range(min = 1, max = 300)))]
    pub connection_timeout_secs: Option<u64>,

    #[cfg_attr(feature = "server", validate(range(min = 1, max = 600)))]
    pub request_timeout_secs: Option<u64>,

    pub enable_adblock: Option<bool>,

    pub auto_update: Option<bool>,

    #[cfg_attr(feature = "server", validate(range(min = 1, max = 8760)))]
    pub update_interval_hours: Option<u64>,

    /// Transparent listener port; `0` turns it off. Needs a restart.
    pub transparent_port: Option<u16>,
    /// Replaces the TLS passthrough host list. Needs a restart.
    pub tls_passthrough_hosts: Option<Vec<String>>,
    /// Needs a restart.
    pub block_private_destinations: Option<bool>,
    /// CIDR list; replaces the current one. Needs a restart.
    pub allowed_destinations: Option<Vec<String>>,
    /// CIDR list; replaces the current one. Needs a restart.
    pub allowed_clients: Option<Vec<String>>,
}

/// Connection statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ConnectionStats {
    pub total: u64,
    pub active: u64,
}

/// Request statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct RequestStats {
    pub total: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub errors: u64,
}

/// MITM statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct MitmStats {
    pub cached_certificates: usize,
}

/// Upstream and destination failures since start (individual events are only logged at debug
/// level; the log carries one summary per interval).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct FaultStats {
    pub upstream_timeouts: u64,
    pub upstream_errors: u64,
    pub dns_failures: u64,
    /// Connections refused by the destination policy.
    pub destination_refusals: u64,
}

/// Proxy statistics response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ProxyStatsResponse {
    pub connections: ConnectionStats,
    pub requests: RequestStats,
    #[serde(default)]
    pub faults: FaultStats,
    pub mitm: Option<MitmStats>,
}

// ---------------------------------------------------------------------------
// Filters
// ---------------------------------------------------------------------------

/// Generic paginated list response.
/// Uniform page of results for every list endpoint (`?page=1&limit=50`, limit 1..=200).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct Page<T> {
    pub items: Vec<T>,
    /// Total matching items across all pages.
    pub total: usize,
    pub page: u32,
    pub limit: u32,
    pub has_more: bool,
}

impl<T> Page<T> {
    /// Slice `all` into the requested page (`page` is 1-based; `limit` clamped to 1..=200).
    pub fn from_vec(all: Vec<T>, page: Option<u32>, limit: Option<u32>) -> Self {
        let page = page.unwrap_or(1).max(1);
        let limit = limit.unwrap_or(50).clamp(1, 200);
        let total = all.len();
        let start = ((page - 1) as usize).saturating_mul(limit as usize);
        let items: Vec<T> = all.into_iter().skip(start).take(limit as usize).collect();
        Self {
            has_more: start + items.len() < total,
            items,
            total,
            page,
            limit,
        }
    }
}

/// Filter list description.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct FilterListResponse {
    pub id: String,
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub last_updated: Option<String>,
    pub rule_count: usize,
    /// Error from the most recent fetch attempt, if it failed (cached content is still used).
    #[serde(default)]
    pub last_error: Option<String>,
    /// When the list was last fetched or revalidated (RFC 3339).
    #[serde(default)]
    pub last_checked: Option<String>,
    /// Format override (`auto` detects from the content; see the supported-formats table).
    #[serde(default)]
    pub format: String,
    /// Every rule of the list is treated as an exception.
    #[serde(default)]
    pub allowlist: bool,
    /// Trusted lists may use the code-running extended rules (`$replace`, `$urltransform`,
    /// `#%#` scripts, snippets, unknown scriptlets); untrusted lists have those dropped.
    #[serde(default)]
    pub trusted: bool,
}

/// Add a filter list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(validator::Validate, utoipa::ToSchema))]
pub struct AddFilterListRequest {
    #[cfg_attr(feature = "server", validate(length(min = 1, max = 100)))]
    pub id: String,

    #[cfg_attr(feature = "server", validate(length(min = 1, max = 200)))]
    pub name: String,

    #[cfg_attr(
        feature = "server",
        validate(url(message = "Invalid URL"), length(max = 2000))
    )]
    pub url: String,

    pub enabled: Option<bool>,
    /// Format override; default `auto`.
    #[serde(default)]
    pub format: Option<String>,
    /// Treat every rule as an exception (default false).
    #[serde(default)]
    pub allowlist: Option<bool>,
    /// Trust the list's code-running extended rules (default false). Audited.
    #[serde(default)]
    pub trusted: Option<bool>,
}

/// Update a filter list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(validator::Validate, utoipa::ToSchema))]
pub struct UpdateFilterListRequest {
    #[cfg_attr(feature = "server", validate(length(min = 1, max = 200)))]
    pub name: Option<String>,

    #[cfg_attr(
        feature = "server",
        validate(url(message = "Invalid URL"), length(max = 2000))
    )]
    pub url: Option<String>,

    pub enabled: Option<bool>,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub allowlist: Option<bool>,
    /// Change the list's trust; recorded in the audit log.
    #[serde(default)]
    pub trusted: Option<bool>,
}

/// The user's custom filter rules (raw adblock syntax).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct CustomRulesResponse {
    pub rules: String,
}

/// Replace the user's custom filter rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(validator::Validate, utoipa::ToSchema))]
pub struct UpdateCustomRulesRequest {
    #[cfg_attr(feature = "server", validate(length(max = 1_000_000)))]
    pub rules: String,
}

// ---------------------------------------------------------------------------
// Userscripts
// ---------------------------------------------------------------------------

/// Userscript description.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct UserscriptResponse {
    pub id: String,
    pub name: String,
    pub namespace: Option<String>,
    pub version: Option<String>,
    pub description: Option<String>,
    pub author: Option<String>,
    pub enabled: bool,
    pub execution_count: u64,
    pub last_executed: Option<String>,
    pub match_patterns: Vec<String>,
    /// A found update awaiting approval.
    #[serde(default)]
    pub pending_update: Option<PendingUpdateDto>,
    #[serde(default)]
    pub last_update_check: Option<String>,
    #[serde(default)]
    pub grants: Vec<String>,
    #[serde(default)]
    pub connect: Vec<String>,
    /// `@connect *` was approved at install.
    #[serde(default)]
    pub connect_all_approved: bool,
    #[serde(default)]
    pub unsupported: Vec<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub run_at: Option<String>,
    #[serde(default)]
    pub noframes: bool,
    #[serde(default)]
    pub storage_bytes: u64,
    #[serde(default)]
    pub update_url: Option<String>,
    #[serde(default)]
    pub homepage: Option<String>,
    #[serde(default)]
    pub require_count: usize,
    #[serde(default)]
    pub resource_count: usize,
}

/// Install a userscript from source.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct InstallUserscriptRequest {
    pub source: String,
}

/// Toggle a userscript's enabled state.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct SetEnabledRequest {
    pub enabled: bool,
}

/// Userscript engine statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct UserscriptStatsResponse {
    pub total_scripts: usize,
    pub enabled_scripts: usize,
    pub disabled_scripts: usize,
    pub total_executions: u64,
}

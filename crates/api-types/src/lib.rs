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
pub struct MessageResponse {
    pub message: String,
}

/// Active session description.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: String,
    pub created_at: String,
    pub last_activity: String,
    #[serde(default)]
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
}

/// Sessions list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionsResponse {
    pub sessions: Vec<SessionInfo>,
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
#[cfg_attr(feature = "server", derive(validator::Validate))]
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
}

/// Connection statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionStats {
    pub total: u64,
    pub active: u64,
}

/// Request statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestStats {
    pub total: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub errors: u64,
}

/// MITM statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitmStats {
    pub cached_certificates: usize,
}

/// Proxy statistics response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyStatsResponse {
    pub connections: ConnectionStats,
    pub requests: RequestStats,
    pub mitm: Option<MitmStats>,
}

// ---------------------------------------------------------------------------
// Filters
// ---------------------------------------------------------------------------

/// Generic paginated list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    pub data: Vec<T>,
    pub total: usize,
    pub page: u32,
    pub limit: u32,
}

/// Filter list description.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

/// Add a filter list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(validator::Validate))]
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
}

/// Update a filter list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(validator::Validate))]
pub struct UpdateFilterListRequest {
    #[cfg_attr(feature = "server", validate(length(min = 1, max = 200)))]
    pub name: Option<String>,

    #[cfg_attr(
        feature = "server",
        validate(url(message = "Invalid URL"), length(max = 2000))
    )]
    pub url: Option<String>,

    pub enabled: Option<bool>,
}

/// The user's custom filter rules (raw adblock syntax).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRulesResponse {
    pub rules: String,
}

/// Replace the user's custom filter rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(validator::Validate))]
pub struct UpdateCustomRulesRequest {
    #[cfg_attr(feature = "server", validate(length(max = 1_000_000)))]
    pub rules: String,
}

// ---------------------------------------------------------------------------
// Userscripts
// ---------------------------------------------------------------------------

/// Userscript description.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

/// Install a userscript from source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallUserscriptRequest {
    pub source: String,
}

/// Update a userscript's source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateUserscriptRequest {
    pub source: String,
}

/// Toggle a userscript's enabled state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetEnabledRequest {
    pub enabled: bool,
}

/// Userscript engine statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserscriptStatsResponse {
    pub total_scripts: usize,
    pub enabled_scripts: usize,
    pub disabled_scripts: usize,
    pub total_executions: u64,
}

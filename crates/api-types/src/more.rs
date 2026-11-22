//! Request/response DTOs added with the v1 API (errors, accounts, tokens, lists, rules, stats,
//! CA, system, audit). Re-exported from the crate root.

use serde::{Deserialize, Serialize};

use crate::{ProxyStatsResponse, Scope, UserRole};

#[cfg(feature = "server")]
use crate::validate_username;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// One field-level validation problem.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct FieldError {
    pub field: String,
    pub code: String,
    pub message: String,
}

/// Machine-readable error: stable `code`, human `message`, optional field `details`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub details: Vec<FieldError>,
}

/// The single error envelope returned by every failing request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ErrorEnvelope {
    pub error: ErrorBody,
}

// ---------------------------------------------------------------------------
// Account management
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(validator::Validate, utoipa::ToSchema))]
pub struct ChangePasswordRequest {
    pub current_password: String,
    #[cfg_attr(
        feature = "server",
        validate(length(min = 8, max = 128, message = "Password must be 8-128 characters"))
    )]
    pub new_password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(validator::Validate, utoipa::ToSchema))]
pub struct CreateUserRequest {
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
    pub role: UserRole,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct UpdateUserRequest {
    pub role: Option<UserRole>,
    pub enabled: Option<bool>,
}

// ---------------------------------------------------------------------------
// API tokens
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(validator::Validate, utoipa::ToSchema))]
pub struct CreateTokenRequest {
    #[cfg_attr(
        feature = "server",
        validate(length(min = 1, max = 100, message = "Name must be 1-100 characters"))
    )]
    pub name: String,
    /// Must be a non-empty subset of the caller's own scopes.
    pub scopes: Vec<Scope>,
    /// Lifetime in days; omit for a token that never expires.
    #[cfg_attr(feature = "server", validate(range(min = 1, max = 3650)))]
    pub expires_in_days: Option<u32>,
    /// Restrict the token to these profile ids (enforced once profiles exist).
    #[serde(default)]
    pub profiles: Option<Vec<String>>,
}

/// Token metadata. The secret is never part of this type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ApiTokenInfo {
    pub id: String,
    pub name: String,
    pub scopes: Vec<Scope>,
    pub profiles: Option<Vec<String>>,
    pub created_by: String,
    pub created_by_name: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
    pub revoked: bool,
}

/// Returned once on creation; `secret` (`abk_<id>_<secret>`) cannot be retrieved again.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct CreatedTokenResponse {
    pub token: ApiTokenInfo,
    pub secret: String,
}

// ---------------------------------------------------------------------------
// Lists, engine, rules
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ListStatusResponse {
    pub id: String,
    pub enabled: bool,
    pub rule_count: usize,
    pub last_updated: Option<String>,
    pub last_checked: Option<String>,
    pub last_success: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct EngineStatusResponse {
    /// A rebuild is queued or running.
    pub building: bool,
    /// Number of build cycles started since the process began.
    pub build_count: u64,
    pub enabled: bool,
    pub scriptlets_ready: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ScheduleResponse {
    pub auto_update: bool,
    pub interval_hours: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(validator::Validate, utoipa::ToSchema))]
pub struct UpdateScheduleRequest {
    pub auto_update: Option<bool>,
    #[cfg_attr(feature = "server", validate(range(min = 1, max = 8760)))]
    pub interval_hours: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ValidateRulesRequest {
    pub rules: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct RuleLineResult {
    /// 1-based line number.
    pub line: usize,
    pub rule: String,
    pub accepted: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ValidateRulesResponse {
    pub accepted: usize,
    pub rejected: usize,
    /// Comments and blank lines are skipped; every other line appears here.
    pub lines: Vec<RuleLineResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(validator::Validate, utoipa::ToSchema))]
pub struct TestUrlRequest {
    #[cfg_attr(feature = "server", validate(url(message = "Invalid URL")))]
    pub url: String,
    /// Page the request originates from (defaults to the URL itself).
    pub source_url: Option<String>,
    /// `document`, `script`, `image`, `xhr`, ... (defaults to `other`).
    pub resource_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct TestUrlResponse {
    pub blocked: bool,
    pub important: bool,
    pub matched_rule: Option<String>,
    pub exception_rule: Option<String>,
    pub redirected: bool,
    pub rewritten_url: Option<String>,
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct DomainCount {
    pub domain: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct FilterStatsResponse {
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub allowed_requests: u64,
    #[serde(default)]
    pub blocked_by_type: std::collections::HashMap<String, u64>,
    #[serde(default)]
    pub top_blocked_domains: Vec<DomainCount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct BlockedEntry {
    pub time: String,
    pub url: String,
    pub source_url: Option<String>,
    pub resource_type: String,
    pub rule: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct RecentBlockedResponse {
    /// False until the filter engine feeds the buffer (see docs/API.md).
    pub available: bool,
    pub capacity: usize,
    pub entries: Vec<BlockedEntry>,
}

// ---------------------------------------------------------------------------
// CA, system, audit
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct CaInfoResponse {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub expired: bool,
    /// Lower-case hex SHA-256 of the DER certificate.
    pub fingerprint_sha256: String,
    pub pem_url: String,
    pub der_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct SystemStatusResponse {
    pub version: String,
    pub uptime_secs: u64,
    pub mitm_enabled: bool,
    pub active_sessions: usize,
    pub engine: EngineStatusResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct MetricsResponse {
    pub proxy: ProxyStatsResponse,
    pub filter: FilterStatsResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct AuditEntry {
    pub id: String,
    pub at: String,
    /// `user`, `token` or `anonymous`.
    pub actor_type: String,
    pub actor_id: Option<String>,
    pub actor_name: Option<String>,
    pub method: String,
    pub route: String,
    /// Scope(s) the route required, comma separated; empty for public routes.
    pub scope: String,
    /// Path parameter identifying the target (e.g. a list or user id).
    pub target: Option<String>,
    pub status: u16,
    /// `success`, `denied` or `error`.
    pub outcome: String,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct UserscriptSourceResponse {
    pub id: String,
    pub source: String,
}

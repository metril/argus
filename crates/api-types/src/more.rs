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
    /// Profile id to start on; an empty string clears it.
    pub default_profile: Option<String>,
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
    /// Absolute expiry (RFC 3339, must be in the future). Exclusive with `expires_in_days`.
    #[serde(default)]
    pub expires_at: Option<String>,
    /// Restrict the token to these profile ids (enforced once profiles exist).
    #[serde(default)]
    pub profiles: Option<Vec<String>>,
    /// What the token is for (a label for the UI; grants nothing). Default `custom`.
    #[serde(default)]
    pub purpose: Option<TokenPurpose>,
}

/// What a token was made for. A presentation label only; the scopes decide access.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum TokenPurpose {
    Extension,
    Monitoring,
    Script,
    Full,
    ReadOnly,
    #[default]
    Custom,
}

/// Change a token. Absent fields stay as they are. Scopes and profiles are checked like on
/// creation: nothing can be widened beyond what the caller holds, and narrowing is always fine.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(validator::Validate, utoipa::ToSchema))]
pub struct UpdateTokenRequest {
    #[cfg_attr(
        feature = "server",
        validate(length(min = 1, max = 100, message = "Name must be 1-100 characters"))
    )]
    #[serde(default)]
    pub name: Option<String>,
    /// Replaces the scopes; a non-empty subset of the caller's own.
    #[serde(default)]
    pub scopes: Option<Vec<Scope>>,
    /// Replaces the profile restriction (ids of existing profiles).
    #[serde(default)]
    pub profiles: Option<Vec<String>>,
    /// Remove the profile restriction (only for a caller who is not restricted).
    #[serde(default)]
    pub clear_profiles: bool,
    #[serde(default)]
    pub purpose: Option<TokenPurpose>,
    /// New lifetime in days from now. Exclusive with `expires_at` and `never_expires`.
    #[cfg_attr(feature = "server", validate(range(min = 1, max = 3650)))]
    #[serde(default)]
    pub expires_in_days: Option<u32>,
    /// New absolute expiry (RFC 3339, in the future).
    #[serde(default)]
    pub expires_at: Option<String>,
    /// Remove the expiry.
    #[serde(default)]
    pub never_expires: bool,
}

/// Issue a new secret for a token.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(validator::Validate, utoipa::ToSchema))]
pub struct RegenerateTokenRequest {
    /// Seconds the old secret keeps working (0 to 7 days, default 0).
    #[cfg_attr(feature = "server", validate(range(min = 0, max = 604800)))]
    #[serde(default)]
    pub grace_secs: u32,
    /// New lifetime in days. Required (one of the three) for an expired token; on a live token
    /// it replaces the expiry when given.
    #[cfg_attr(feature = "server", validate(range(min = 1, max = 3650)))]
    #[serde(default)]
    pub expires_in_days: Option<u32>,
    /// New absolute expiry (RFC 3339, in the future).
    #[serde(default)]
    pub expires_at: Option<String>,
    /// Remove the expiry.
    #[serde(default)]
    pub never_expires: bool,
}

/// Sign in from the browser extension: checks the credentials like a login, but starts no session
/// and mints a token named `Extension · {browser}` with just the scopes the extension needs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(validator::Validate, utoipa::ToSchema))]
pub struct ExtensionTokenRequest {
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
    /// Browser name for the token label, e.g. `Chrome`.
    #[cfg_attr(
        feature = "server",
        validate(length(min = 1, max = 30, message = "Browser must be 1-30 characters"))
    )]
    pub browser: String,
    /// An earlier extension token of the same user to revoke (ignored if it is not theirs).
    #[serde(default)]
    pub replace_token_id: Option<String>,
}

/// The new extension token; `token` is shown only here.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ExtensionTokenResponse {
    pub token: String,
    pub token_id: String,
    pub user: crate::UserInfo,
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
    /// Scope names this release does not know (set by a newer one); shown as-is, grant nothing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unknown_scopes: Vec<String>,
    #[serde(default)]
    pub purpose: TokenPurpose,
    /// Non-secret display form, e.g. `abk_1a2b3c4d5e6f7a8b_…9f3e`; never enough to rebuild the secret.
    #[serde(default)]
    pub secret_hint: String,
    /// Address of the last request made with the token.
    #[serde(default)]
    pub last_used_addr: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
    /// While in the future, the previous secret still works until then.
    #[serde(default)]
    pub prev_valid_until: Option<String>,
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
    /// Scriptlet/redirect resources currently served (after validation).
    #[serde(default)]
    pub scriptlet_resources: usize,
    /// Resources of the loaded library that failed validation and are not served, with why.
    #[serde(default)]
    pub scriptlet_resources_dropped: Vec<DroppedScriptletResource>,
}

/// A scriptlet resource that failed validation (syntax error, unresolved dependency, ...).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct DroppedScriptletResource {
    pub name: String,
    pub reason: String,
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
    /// Format to convert with (default `auto`: detected from the text).
    #[serde(default)]
    pub format: Option<String>,
    /// Validate as an allowlist (every rule becomes an exception).
    #[serde(default)]
    pub allowlist: Option<bool>,
    /// Judge the rules as a trusted list. Default false: untrusted rules cannot use `$replace`,
    /// `#%#` scripts, snippets and the like, which is the safe reading of third-party text. The
    /// custom rules are built trusted, so validate those with `true`.
    #[serde(default)]
    pub trusted: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct RuleLineResult {
    /// 1-based line number.
    pub line: usize,
    pub rule: String,
    /// `translated` (rewritten into engine syntax), `accepted` (used as written), `handed_off`
    /// (extended rule; see `state`), `duplicate` (already provided by an earlier rule),
    /// `skipped` (recognised, inexpressible) or `rejected`.
    pub outcome: String,
    /// For `handed_off`: `enforced`, `unsupported`, `invalid` or `needs_trust`.
    #[serde(default)]
    pub state: Option<String>,
    /// False only for `rejected`.
    pub accepted: bool,
    /// Why the line was rejected or skipped, or the kind of a handed-off rule.
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ValidateRulesResponse {
    /// Format used (detected when not given).
    #[serde(default)]
    pub format: String,
    /// Lines that are not rejected (translated, accepted, handed off or skipped).
    pub accepted: usize,
    #[serde(default)]
    pub translated: usize,
    #[serde(default)]
    pub handed_off: usize,
    /// Handed-off rules that would not be enforced (unsupported, invalid or needs trust).
    #[serde(default)]
    pub handed_off_issues: usize,
    #[serde(default)]
    pub duplicates: usize,
    #[serde(default)]
    pub skipped: usize,
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
    /// Blocked requests since the first start; survives restarts and statistics resets.
    #[serde(default)]
    pub lifetime_blocked: u64,
    /// All requests since the first start.
    #[serde(default)]
    pub lifetime_total: u64,
    /// Lifetime blocks per category (`ads`, `trackers`, `social`, `annoyances`, `security`,
    /// `other`).
    #[serde(default)]
    pub lifetime_by_category: std::collections::BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct BlockedEntry {
    pub time: String,
    pub url: String,
    /// Host of the initiating page, when known.
    pub source_host: Option<String>,
    pub resource_type: String,
    pub rule: Option<String>,
    /// List the rule came from, when known (domain-set hits).
    pub list_id: Option<String>,
    /// Id of the profile that blocked it (decimal).
    pub client: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct RecentBlockedResponse {
    /// Ring capacity (older events are overwritten).
    pub capacity: usize,
    /// Matching events across all pages.
    pub total: usize,
    pub page: u32,
    pub limit: u32,
    pub has_more: bool,
    /// Newest first.
    pub entries: Vec<BlockedEntry>,
}

/// One time-series bucket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct TimeseriesPoint {
    /// Start of the bucket, Unix seconds.
    pub ts: i64,
    pub requests: u64,
    pub blocked: u64,
    /// Blocks per category; filled for the daily and monthly ranges only.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub by_category: std::collections::BTreeMap<String, u64>,
}

/// Requests and blocks over time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct TimeseriesResponse {
    /// `6h`, `24h`, `7d`, or the persisted daily history `d7`, `d30` (UTC days) and `m12`
    /// (calendar months).
    pub range: String,
    /// Bucket length in seconds (1800, 21600 for `7d`, 86400 for `d7`/`d30`, 2592000 for `m12`).
    pub bucket_secs: i64,
    /// Oldest first, ending with the current bucket.
    pub points: Vec<TimeseriesPoint>,
}

/// What happened to a logged request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum LogAction {
    Allowed,
    Blocked,
    /// An opaque tunnel the proxy did not look inside.
    Passthrough,
    Error,
}

/// Why an `error` event happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum LogErrorKind {
    /// The client refused the proxy's certificate (a bad_certificate, unknown_ca,
    /// certificate_unknown or decrypt_error alert, or an immediate close): typical of
    /// certificate-pinned apps, which are candidates for a bypass.
    ClientRejectedCert,
    UpstreamTimeout,
    UpstreamReset,
    /// TLS to the upstream server failed.
    UpstreamTls,
    Other,
}

/// How the connection reached the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum LogMode {
    Explicit,
    Transparent,
}

/// One request in the live log.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct RequestLogEntry {
    /// RFC 3339 time.
    pub ts: String,
    pub action: LogAction,
    /// HTTP method (`CONNECT` for tunnels).
    pub method: String,
    pub url: String,
    /// Host of the initiating page, when known.
    pub source_host: Option<String>,
    /// Id of the profile that handled it (decimal).
    pub client: Option<String>,
    pub request_type: String,
    pub rule: Option<String>,
    pub list_id: Option<String>,
    /// Upstream status, when there was one.
    pub status: Option<u16>,
    pub mode: LogMode,
    /// Set on `error` events.
    #[serde(default)]
    pub error_kind: Option<LogErrorKind>,
    /// SHA-256 fingerprint (hex) of the upstream server certificate of a decrypted request;
    /// resolves via `GET /certs/{fp}`.
    #[serde(default)]
    pub cert_fp: Option<String>,
    /// How a block was carried out: `aborted` (the request failed like a network error) or
    /// `synthetic` (the requester got a block page, blank frame, GIF or empty success).
    #[serde(default)]
    pub outcome: Option<LogOutcome>,
}

/// How a blocked request was carried out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum LogOutcome {
    Aborted,
    Synthetic,
}

/// Verification outcome of an upstream certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum CertVerdict {
    Ok,
    Invalid,
}

/// Why an upstream certificate was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum CertFailReason {
    Expired,
    NotYetValid,
    NameMismatch,
    UnknownIssuer,
    /// The issuing root no longer vouches for this certificate (issued after its distrust date,
    /// outside its name constraints, or without a valid Certificate Transparency receipt).
    Distrusted,
    Other,
}

/// One certificate of an upstream chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct CertChainEntry {
    pub subject: String,
    pub issuer: String,
    /// RFC 3339.
    pub not_before: String,
    /// RFC 3339.
    pub not_after: String,
    /// SHA-256 of the DER, lowercase hex.
    pub fp: String,
}

/// The real certificate an upstream server presented to the proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct CertInfo {
    /// SHA-256 of the leaf DER, lowercase hex.
    pub fp: String,
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    /// RFC 3339.
    pub not_before: String,
    /// RFC 3339.
    pub not_after: String,
    /// DNS names and IP addresses of the subjectAltName extension.
    pub sans: Vec<String>,
    /// The chain as presented, leaf first.
    pub chain: Vec<CertChainEntry>,
    pub verdict: CertVerdict,
    /// Set when `verdict` is `invalid`.
    pub reason: Option<CertFailReason>,
    /// Verifier message when `verdict` is `invalid`.
    pub detail: Option<String>,
    /// The leaf carries an Extended Validation policy.
    pub ev: bool,
}

/// Snapshot of the request log.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct RequestLogResponse {
    /// Ring capacity (older events are overwritten).
    pub capacity: usize,
    pub total: usize,
    pub page: u32,
    pub limit: u32,
    pub has_more: bool,
    /// Newest first.
    pub entries: Vec<RequestLogEntry>,
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
    /// HTTPS is configured for the web UI but not being served (the page is plain HTTP).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct MetricsResponse {
    pub proxy: ProxyStatsResponse,
    pub filter: FilterStatsResponse,
    pub storage: StorageMetrics,
}

/// Health of the deferred (background) database writes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct StorageMetrics {
    /// Telemetry writes discarded because the write queue was full.
    pub deferred_dropped: u64,
    /// Deferred writes that failed or panicked.
    pub deferred_failed: u64,
    /// Deferred writes waiting to be committed.
    pub deferred_queued: u64,
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

// ---------------------------------------------------------------------------
// List formats, reports, build state, catalogue, handed-off rules
// ---------------------------------------------------------------------------

/// One problem found while building a list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ReportIssueDto {
    /// 1-based line in the source text (the `!#include` line for an included rule); 0 when the
    /// rule could not be traced to a line.
    pub line: usize,
    /// The rule as written in the source.
    #[serde(default)]
    pub rule: String,
    pub reason: String,
    /// Where it failed: `conversion` (the line is not a rule) or `compile` (the engine rejected
    /// the converted rule).
    #[serde(default)]
    pub stage: String,
}

/// Header metadata (`! Title:`, `! Expires:` ...) found in a list.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ListMetaDto {
    pub title: Option<String>,
    pub homepage: Option<String>,
    pub version: Option<String>,
    pub expires_secs: Option<u64>,
    pub redirect: Option<String>,
}

/// What the last build made of one list (or of the custom rules).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ListReport {
    /// List id (`custom` for the custom rules).
    pub id: String,
    /// Format used (detected when the override is `auto`).
    pub format: String,
    pub format_override: String,
    pub allowlist: bool,
    pub total_lines: usize,
    pub network: usize,
    pub cosmetic: usize,
    /// Extended rules handed to the extended-rule index (see `GET /rules/ext`); the four fields
    /// below split them by what the index made of them.
    pub ext: usize,
    #[serde(default)]
    pub ext_enforced: usize,
    #[serde(default)]
    pub ext_unsupported: usize,
    #[serde(default)]
    pub ext_invalid: usize,
    /// Dropped because the list is not trusted.
    #[serde(default)]
    pub ext_needs_trust: usize,
    /// Extended rules per state, every state included (`enforced`, `unsupported`, `invalid`,
    /// `needs_trust`, and any the extended-rule index adds). The four fields above are the same
    /// figures for the states listed first.
    #[serde(default)]
    pub ext_states: std::collections::BTreeMap<String, usize>,
    /// Recognised but inexpressible lines (and AdGuard stubs dropped on purpose).
    pub skipped: usize,
    /// Rules dropped as duplicates.
    pub deduped: usize,
    /// Domain rules dropped because a shorter suffix rule already covers them.
    #[serde(default)]
    pub compressed: usize,
    /// Rules rewritten into engine syntax.
    pub translated: usize,
    /// Rules the engine's compiler rejected.
    pub rejected: usize,
    /// Domain rules a `$badfilter` rule disables (not counted in `network`).
    #[serde(default)]
    pub disabled: usize,
    pub ip_ranges: usize,
    /// Deprecated: `conversion_errors + rejected`. Use the two fields separately.
    pub error_count: usize,
    /// Lines that could not be converted into a rule (not counting `rejected`).
    #[serde(default)]
    pub conversion_errors: usize,
    /// First parse issues, conversion errors first.
    pub issues: Vec<ReportIssueDto>,
    /// Rules already provided by an earlier rule or a shorter domain rule
    /// (`deduped + compressed`).
    #[serde(default)]
    pub redundant_count: usize,
    /// Everything in the list is already provided elsewhere: it contributes no rule of its own.
    #[serde(default)]
    pub redundant: bool,
    /// Invalid rules (conversion errors, compiler rejections, malformed extended rules) reach 1%
    /// of the list's rules, rounded up, at least one. Unsupported, not-enforced and needs-trust
    /// rules never set it.
    #[serde(default)]
    pub attention: bool,
    pub ext_counts: std::collections::BTreeMap<String, usize>,
    pub skipped_reasons: std::collections::BTreeMap<String, usize>,
    pub meta: ListMetaDto,
    /// SHA-256 of the list content (and includes) the report was built from.
    pub content_sha: Option<String>,
}

/// Where the build pipeline is.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum BuildState {
    #[default]
    Idle,
    Fetching {
        done: usize,
        total: usize,
    },
    Compiling,
    /// The last build failed; the previous engine keeps serving.
    Failed {
        error: String,
    },
}

/// Build state and totals of the installed engine.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct BuildSummary {
    pub state: BuildState,
    /// A rebuild is queued or running.
    pub building: bool,
    /// When the installed engine was compiled (RFC 3339).
    pub built_at: Option<String>,
    /// Compile time of the installed engine.
    pub compile_ms: u64,
    /// Duration of the last whole build cycle (downloads and compile).
    pub last_build_ms: u64,
    pub last_build_at: Option<String>,
    pub lists: usize,
    pub network: usize,
    pub cosmetic: usize,
    pub ext: usize,
    pub rejected: usize,
    pub ip_ranges: usize,
    /// Pure domain rules in the compact domain set.
    pub domain_set: usize,
    pub duplicates: usize,
    #[serde(default)]
    pub compressed: usize,
    pub from_persisted: bool,
    /// Handed-off rules by kind.
    pub ext_counts: std::collections::BTreeMap<String, usize>,
    /// What the extended-rule index did with them (absent before the first build).
    #[serde(default)]
    pub ext_stats: Option<ExtStatsDto>,
}

/// Per-kind outcome of building the extended-rule index.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ExtKindStatsDto {
    pub parsed: usize,
    /// Enforced.
    pub active: usize,
    /// Dropped because the source list is not trusted.
    pub dropped_untrusted: usize,
    /// Well-formed but not implemented.
    pub unsupported: usize,
    pub parse_errors: usize,
    pub badfiltered: usize,
    /// Matched by the index but not yet applied by the proxy (not counted in `active`).
    #[serde(default)]
    pub not_enforced: usize,
    /// Meaningless for a proxy (`$popunder`).
    #[serde(default)]
    pub not_applicable: usize,
}

/// A handed-off rule that could not be used.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ExtIssueDto {
    pub kind: String,
    pub list: String,
    pub raw: String,
    pub reason: String,
    pub unsupported: bool,
}

/// Outcome of building the extended-rule index.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ExtStatsDto {
    pub total: usize,
    pub per_kind: std::collections::BTreeMap<String, ExtKindStatsDto>,
    /// Rules dropped for lack of trust, per list id.
    pub dropped_untrusted_by_list: std::collections::BTreeMap<String, usize>,
    pub issues: Vec<ExtIssueDto>,
    pub issues_truncated: usize,
}

/// A handed-off rule and what the extended-rule index did with it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ExtRuleResponse {
    /// Position in the engine's handed-off rule list (stable within one build).
    #[serde(default)]
    pub index: usize,
    pub kind: String,
    pub raw: String,
    pub domains: Vec<String>,
    /// Source list id.
    #[serde(default)]
    pub list: String,
    /// `active`, `dropped_untrusted`, `unsupported`, `invalid`, `badfiltered`, `badfilter`, or
    /// `unknown` (the index was rebuilt while the page was read).
    #[serde(default)]
    pub state: String,
    /// Why the rule is unsupported / invalid.
    #[serde(default)]
    pub reason: Option<String>,
}

/// One rule of a source line, as the build treats it (`GET /lists/{id}/lines`). A line that
/// emits several rules, or a `!#include`, appears once per rule with the same `line`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ListLine {
    /// 1-based line in the source text (the `!#include` line for an included rule).
    pub line: usize,
    /// `comment` (blank, header, comment, directive), `inactive` (in a false `!#if` branch),
    /// `network`, `cosmetic`, `extended`, `duplicate`, `covered`, `disabled` (a domain rule a
    /// `$badfilter` rule switches off), `unsupported` or `invalid`.
    pub status: String,
    /// The rule as written.
    pub rule: String,
    /// For `extended`: the rule kind (`replace`, `html-filter`, ...).
    #[serde(default)]
    pub kind: Option<String>,
    /// For `extended`: the state the extended-rule index gave it: `enforced`, `unsupported`,
    /// `invalid`, `needs_trust`, and any state the index adds.
    #[serde(default)]
    pub state: Option<String>,
    /// Why, for `unsupported`, `invalid` and the unenforced extended states.
    #[serde(default)]
    pub reason: Option<String>,
    /// For `invalid`: `conversion` or `compile`.
    #[serde(default)]
    pub stage: Option<String>,
    /// For `duplicate` and `covered`: the list (id) that already provides the rule.
    #[serde(default)]
    pub list: Option<String>,
    /// A `network` line that is an IP or CIDR range.
    #[serde(default)]
    pub ip: bool,
}

/// A page of [`ListLine`]s with the filter counts of the whole list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ListLinesPage {
    pub items: Vec<ListLine>,
    /// Records matching `status` and `q`.
    pub total: usize,
    pub limit: u32,
    pub has_more: bool,
    /// Opaque; pass it back as `cursor`. A cursor from another build or text is refused with 409
    /// `lines_changed`.
    pub next_cursor: Option<String>,
    /// Records per status for the whole list, whatever `status` and `q` are: `all`, `comment`,
    /// `inactive`, `network`, `cosmetic`, `extended`, `duplicate`, `covered`, `disabled`, `unsupported`,
    /// `invalid`, one per extended-rule state (`enforced`, `needs_trust`, `not_enforced`,
    /// `not_applicable`), and the groups `issues` (unsupported, invalid, needs_trust,
    /// not_enforced), `applied` (network, cosmetic, enforced) and `ignored` (inactive,
    /// disabled, not_applicable). `unsupported` and `invalid` include extended rules in that state.
    pub counts: std::collections::BTreeMap<String, usize>,
    /// The format used (detected when the list's override is `auto`).
    pub format: String,
    /// The list was judged inside the live build. When false (disabled, or changed since the
    /// last build) it was judged on its own: nothing is `duplicate` or `covered` by another list.
    pub in_build: bool,
    /// Lines in the source text.
    pub total_lines: usize,
}

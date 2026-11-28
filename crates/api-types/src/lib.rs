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

mod bypass;
mod more;
pub use bypass::*;
pub use more::*;

mod policy;
pub use policy::*;

pub mod profiles;
pub use profiles::*;

mod userscripts;
pub use userscripts::*;

mod ext;
pub use ext::*;

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
    /// Profile (decimal id) the account starts on in the UI, if one was set.
    #[serde(default)]
    pub default_profile: Option<String>,
    /// Active sessions of this account (filled in by the users endpoints).
    #[serde(default)]
    pub session_count: u32,
}

/// Whether the first-run account can still be registered.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct RegistrationStatus {
    /// `POST /auth/register` will be accepted.
    pub open: bool,
    /// No account exists yet: the next registration creates the administrator.
    pub first_run: bool,
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
    /// Port of the extension-only listener (`None` = off): the Argus browser extension sends its
    /// browser through it so documents are bound to the extension session.
    #[serde(default)]
    pub ext_port: Option<u16>,
    /// How a blocked subresource is answered: `fail` (the request fails like a network error;
    /// documents, subdocuments and images keep their block page, blank frame and GIF) or
    /// `synthetic` (every block gets a well-formed success response).
    #[serde(default = "default_block_response")]
    pub block_response: String,
    /// TLS hosts never intercepted (exact or `*.suffix`).
    #[serde(default)]
    pub tls_passthrough_hosts: Vec<String>,
    /// Also refuse private-range destinations.
    #[serde(default)]
    pub block_private_destinations: bool,
    /// Connect to origins with the requesting browser's TLS/HTTP2 fingerprint.
    #[serde(default)]
    pub browser_like_upstream: bool,
    /// Another proxy Argus's own upstream traffic goes through.
    #[serde(default)]
    pub upstream_proxy: UpstreamProxyDto,
    /// CIDR exceptions to the destination refusals.
    #[serde(default)]
    pub allowed_destinations: Vec<String>,
    /// CIDRs of clients allowed to use the proxy.
    #[serde(default)]
    pub allowed_clients: Vec<String>,
    /// Upstream DNS resolution.
    #[serde(default)]
    pub dns: DnsDto,
    /// Effective switches of the explicit-proxy listener.
    #[serde(default)]
    pub explicit: ListenerFlagsView,
    /// Effective switches of the transparent listener.
    #[serde(default)]
    pub transparent: ListenerFlagsView,
    /// Address the web API listens on.
    #[serde(default)]
    pub webui_host: String,
    #[serde(default)]
    pub webui_port: u16,
    /// Source of the signed first-party lists.
    #[serde(default)]
    pub bypass: BypassSourceDto,
    /// Opt in: keep service workers from bypassing the injection on filtered sites (replaces
    /// their script with a self-unregistering no-op worker; offline apps and push stop working).
    #[serde(default)]
    pub guard_service_workers: bool,
    /// Hosts (exact or `*.suffix`) the guard leaves alone.
    #[serde(default)]
    pub guard_service_workers_exempt: Vec<String>,
    /// Stealth Mode.
    #[serde(default)]
    pub stealth: StealthDto,
    /// CNAME uncloaking.
    #[serde(default)]
    pub cname: CnameDto,
    /// Entries kept by the request log (per ring, about 1 KB each).
    #[serde(default = "default_request_log_capacity")]
    pub request_log_capacity: u32,
    /// Where the listeners are actually bound right now (absent without a running proxy).
    #[serde(default)]
    pub bind: Option<BindResult>,
}

/// Protocol spoken to the upstream proxy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum UpstreamProxyKind {
    /// HTTP `CONNECT`.
    #[default]
    Http,
    /// SOCKS5.
    Socks5,
}

/// The upstream proxy as read. The password is never returned: `password` is `"set"` or `"unset"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct UpstreamProxyDto {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub kind: UpstreamProxyKind,
    #[serde(default)]
    pub host: String,
    #[serde(default = "default_upstream_proxy_port")]
    pub port: u16,
    #[serde(default)]
    pub username: String,
    /// `"set"` or `"unset"`.
    #[serde(default)]
    pub password: String,
}

fn default_upstream_proxy_port() -> u16 {
    8080
}

impl Default for UpstreamProxyDto {
    fn default() -> Self {
        Self {
            enabled: false,
            kind: UpstreamProxyKind::Http,
            host: String::new(),
            port: default_upstream_proxy_port(),
            username: String::new(),
            password: "unset".into(),
        }
    }
}

/// Partial update of the upstream proxy; omitted fields keep their value. An empty or omitted
/// `password` keeps the saved one; clearing `username` also clears the password.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct UpstreamProxyUpdate {
    pub enabled: Option<bool>,
    pub kind: Option<UpstreamProxyKind>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// Outcome of testing the upstream proxy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct UpstreamProxyTestResult {
    pub ok: bool,
    /// Time to connect through the proxy and finish a TLS handshake.
    pub latency_ms: Option<u64>,
    /// Why it failed.
    pub error: Option<String>,
    /// The host the test connected to.
    pub target: String,
}

/// Upstream DNS settings: what Argus uses to resolve names for its own connections.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct DnsDto {
    /// Upstream lines in AdGuard syntax (`1.1.1.1`, `tls://...`, `https://...`, `h3://...`,
    /// `quic://...`, `sdns://...`, `[/domain/]upstream`); empty uses the system resolver.
    #[serde(default)]
    pub servers: Vec<String>,
    /// File path or http(s) URL with more upstream lines.
    #[serde(default)]
    pub upstreams_source: String,
    /// `load_balance`, `parallel` or `fastest_ip`.
    #[serde(default)]
    pub mode: String,
    /// Plain-IP resolvers for the host names of encrypted upstreams.
    #[serde(default)]
    pub bootstrap: Vec<String>,
    /// Used only when every upstream fails.
    #[serde(default)]
    pub fallback: Vec<String>,
    /// Send PTR lookups and LAN names to the private resolvers.
    #[serde(default)]
    pub private_rdns: bool,
    /// Plain-IP resolvers for those; empty uses the system resolver.
    #[serde(default)]
    pub private_resolvers: Vec<String>,
    /// Maximum cached names.
    pub cache_size: u64,
    /// Lower clamp on cached TTLs, seconds.
    pub min_ttl_secs: u64,
    /// Upper clamp on cached TTLs, seconds.
    pub max_ttl_secs: u64,
    /// How long failed lookups are cached, seconds.
    pub negative_ttl_secs: u64,
    /// Serve expired answers while refreshing them in the background.
    #[serde(default)]
    pub optimistic_cache: bool,
    /// Validate DNSSEC and refuse answers that fail.
    #[serde(default)]
    pub dnssec: bool,
    /// Resolve AAAA records.
    #[serde(default)]
    pub ipv6: bool,
    /// `off`, `auto` or `custom`.
    #[serde(default)]
    pub ecs: String,
    /// Subnet for `ecs = custom`, e.g. `203.0.113.0/24`.
    #[serde(default)]
    pub ecs_subnet: String,
    /// Per-upstream query timeout, milliseconds.
    #[serde(default)]
    pub timeout_ms: u64,
}

/// Partial DNS update; omitted fields keep their value.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct DnsUpdate {
    pub servers: Option<Vec<String>>,
    pub upstreams_source: Option<String>,
    pub mode: Option<String>,
    pub bootstrap: Option<Vec<String>>,
    pub fallback: Option<Vec<String>>,
    pub private_rdns: Option<bool>,
    pub private_resolvers: Option<Vec<String>>,
    pub cache_size: Option<u64>,
    pub min_ttl_secs: Option<u64>,
    pub max_ttl_secs: Option<u64>,
    pub negative_ttl_secs: Option<u64>,
    pub optimistic_cache: Option<bool>,
    pub dnssec: Option<bool>,
    pub ipv6: Option<bool>,
    pub ecs: Option<String>,
    pub ecs_subnet: Option<String>,
    pub timeout_ms: Option<u64>,
}

/// Health and speed of one configured upstream.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct DnsUpstreamStat {
    /// Short label of the upstream (`tls://dns.google:853`).
    pub upstream: String,
    /// `upstream`, `fallback`, `bootstrap` or `private`.
    pub role: String,
    /// `udp`, `tcp`, `tls`, `https`, `h3`, `quic` or `dnscrypt`.
    pub transport: String,
    pub queries: u64,
    pub failures: u64,
    pub consecutive_failures: u32,
    /// Smoothed round-trip time, milliseconds.
    pub rtt_ms: Option<f64>,
    pub last_rtt_ms: Option<f64>,
    pub healthy: bool,
    pub last_error: Option<String>,
    /// Seconds since the last good answer.
    pub last_ok_secs_ago: Option<u64>,
}

/// Live upstream-DNS figures.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct DnsStatsResponse {
    pub upstreams: Vec<DnsUpstreamStat>,
    /// Names in the cache.
    pub cached_names: u64,
    /// Lookups answered from the cache.
    pub cache_hits: u64,
    /// Lookups that went to the upstreams.
    pub cache_misses: u64,
}

/// Outcome of one upstream in "Test upstreams".
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct DnsTestResult {
    pub upstream: String,
    /// `upstream`, `fallback`, `bootstrap`, `private` or `system`.
    pub role: String,
    pub ok: bool,
    pub latency_ms: Option<f64>,
    pub error: Option<String>,
    /// Addresses returned for the probe name.
    pub answers: Vec<String>,
}

/// Result of probing every upstream once.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct DnsTestResponse {
    /// The name that was looked up.
    pub name: String,
    pub results: Vec<DnsTestResult>,
}

/// Where the signed first-party lists come from. Empty = the built-in location and key.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct BypassSourceDto {
    /// Directory the signed lists are fetched from.
    pub lists_base_url: String,
    /// Minisign public key (base64 line) the lists must be signed with.
    pub lists_public_key: String,
}

/// Partial update of [`BypassSourceDto`]; omitted fields keep their value. Applied live: the
/// lists, trusted roots and catalogues check again right away. A mirror must not serve older
/// releases than the ones already installed: those are refused.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct BypassSourceUpdate {
    pub lists_base_url: Option<String>,
    pub lists_public_key: Option<String>,
}

/// CNAME uncloaking (uBlock Origin's `cname*` advanced settings): a request that is not blocked is
/// judged again under the canonical name its host resolves to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct CnameDto {
    pub enabled: bool,
    /// Canonical names (and their subdomains) never uncloaked; `*` matches everything.
    pub ignore_list: Vec<String>,
    pub ignore_first_party: bool,
    pub ignore_exceptions: bool,
    pub ignore_root_document: bool,
    /// Seconds a canonical name is remembered (1 to 86400).
    pub max_ttl_secs: u64,
    pub replay_full_url: bool,
}

impl Default for CnameDto {
    fn default() -> Self {
        Self {
            enabled: true,
            ignore_list: Vec::new(),
            ignore_first_party: true,
            ignore_exceptions: true,
            ignore_root_document: true,
            max_ttl_secs: 600,
            replay_full_url: false,
        }
    }
}

/// Partial update of [`CnameDto`]; omitted fields keep their value. Applied live.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct CnameUpdate {
    pub enabled: Option<bool>,
    pub ignore_list: Option<Vec<String>>,
    pub ignore_first_party: Option<bool>,
    pub ignore_exceptions: Option<bool>,
    pub ignore_root_document: Option<bool>,
    pub max_ttl_secs: Option<u64>,
    pub replay_full_url: Option<bool>,
}

/// Stealth Mode settings (AdGuard parity). Off as a whole until `enabled`; each option then
/// follows its own switch. See the Settings page for what each one does and may break.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct StealthDto {
    pub enabled: bool,
    pub hide_search_queries: bool,
    pub send_dnt: bool,
    pub strip_tracking_params: bool,
    pub hide_referer: bool,
    pub referer_custom: String,
    pub hide_user_agent: bool,
    pub user_agent_custom: String,
    pub mask_ip: bool,
    pub mask_ip_address: String,
    pub remove_x_client_data: bool,
    pub third_party_cookies: bool,
    pub third_party_cookie_minutes: u32,
    pub first_party_cookies: bool,
    pub first_party_cookie_minutes: u32,
    pub block_etag: bool,
    pub block_third_party_auth: bool,
    pub block_webrtc: bool,
    pub block_push: bool,
    pub block_location: bool,
    pub block_flash: bool,
    pub block_java: bool,
}

/// Partial update of [`StealthDto`]; omitted fields keep their value. Applied live.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct StealthUpdate {
    pub enabled: Option<bool>,
    pub hide_search_queries: Option<bool>,
    pub send_dnt: Option<bool>,
    pub strip_tracking_params: Option<bool>,
    pub hide_referer: Option<bool>,
    pub referer_custom: Option<String>,
    pub hide_user_agent: Option<bool>,
    pub user_agent_custom: Option<String>,
    pub mask_ip: Option<bool>,
    pub mask_ip_address: Option<String>,
    pub remove_x_client_data: Option<bool>,
    pub third_party_cookies: Option<bool>,
    pub third_party_cookie_minutes: Option<u32>,
    pub first_party_cookies: Option<bool>,
    pub first_party_cookie_minutes: Option<u32>,
    pub block_etag: Option<bool>,
    pub block_third_party_auth: Option<bool>,
    pub block_webrtc: Option<bool>,
    pub block_push: Option<bool>,
    pub block_location: Option<bool>,
    pub block_flash: Option<bool>,
    pub block_java: Option<bool>,
}

/// A listener's effective switches (its own setting, else the global one).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ListenerFlagsView {
    pub enable_mitm: bool,
    pub enable_http2: bool,
    pub enable_websockets: bool,
    pub enable_adblock: bool,
}

/// Partial update of one listener's switches; omitted fields keep their current setting.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ListenerFlagsUpdate {
    pub enable_mitm: Option<bool>,
    pub enable_http2: Option<bool>,
    pub enable_websockets: Option<bool>,
    pub enable_adblock: Option<bool>,
}

/// Actual listener addresses.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct BindResult {
    /// Explicit proxy, `ip:port`.
    pub proxy: Option<String>,
    /// Transparent listener, `ip:port` (`None` = off).
    pub transparent: Option<String>,
    /// Web API, `ip:port`.
    pub webui: Option<String>,
    /// The explicit listener is down (a move failed and could not be undone); retry the change.
    #[serde(default)]
    pub proxy_down: bool,
    #[serde(default)]
    pub transparent_down: bool,
    /// The web API listener is down (same cause); this response came from an older listener.
    #[serde(default)]
    pub webui_down: bool,
    /// Set when this update moved the web API: open it here. The old address keeps answering
    /// for 30 seconds.
    pub webui_moved_to: Option<String>,
    /// The web API could not use its configured port at startup (set with `webui_moved_to`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webui_error: Option<String>,
    /// Why the explicit listener is down, when it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_error: Option<String>,
    /// Why the transparent listener is down, when it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transparent_error: Option<String>,
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

    /// Transparent listener port; `0` turns it off. Applied live (the listener is rebound).
    pub transparent_port: Option<u16>,
    /// Extension listener port; `0` turns it off. Applied live.
    pub ext_port: Option<u16>,
    /// `fail` or `synthetic`; applied live.
    pub block_response: Option<String>,
    /// Replaces the TLS passthrough host list. Applied live.
    pub tls_passthrough_hosts: Option<Vec<String>>,
    /// Applied live.
    pub block_private_destinations: Option<bool>,
    pub browser_like_upstream: Option<bool>,
    /// Upstream proxy settings; applied live (new connections go through the proxy at once).
    pub upstream_proxy: Option<UpstreamProxyUpdate>,
    /// CIDR list; replaces the current one. Applied live.
    pub allowed_destinations: Option<Vec<String>>,
    /// CIDR list; replaces the current one. Applied live.
    pub allowed_clients: Option<Vec<String>>,
    /// DNS settings; applied live (the resolver is rebuilt and its cache flushed).
    pub dns: Option<DnsUpdate>,
    /// Switches of the explicit-proxy listener only. Applied live.
    pub explicit: Option<ListenerFlagsUpdate>,
    /// Switches of the transparent listener only. Applied live.
    pub transparent: Option<ListenerFlagsUpdate>,
    /// Web API listen address; the listener is rebound live.
    #[cfg_attr(feature = "server", validate(length(min = 1, max = 255)))]
    pub webui_host: Option<String>,
    /// Web API listen port; the listener is rebound live.
    #[cfg_attr(feature = "server", validate(range(min = 1, max = 65535)))]
    pub webui_port: Option<u16>,
    /// Source of the signed first-party lists; applied live.
    pub bypass: Option<BypassSourceUpdate>,
    /// Neutralise service workers on filtered sites; applied live.
    pub guard_service_workers: Option<bool>,
    /// Replaces the guard's exempt host list; applied live.
    pub guard_service_workers_exempt: Option<Vec<String>>,
    /// Stealth Mode settings; applied live.
    pub stealth: Option<StealthUpdate>,
    /// CNAME uncloaking settings; applied live.
    pub cname: Option<CnameUpdate>,
    /// Entries kept by the request log (100 to 500000); applied live, keeping the newest when
    /// it shrinks.
    #[cfg_attr(feature = "server", validate(range(min = 100, max = 500000)))]
    pub request_log_capacity: Option<u32>,
}

fn default_block_response() -> String {
    "fail".into()
}

fn default_request_log_capacity() -> u32 {
    1000
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
    /// Transparent-gateway listener.
    #[serde(default)]
    pub transparent: TransparentStatus,
    /// Live counters of the explicit-proxy listener.
    #[serde(default)]
    pub explicit: ListenerCounters,
    /// Requests and tunnels handled in `full` bypass since the proxy started.
    #[serde(default)]
    pub bypassed_total: u64,
    /// Bypass fail-safe: HTTPS is tunnelled until the first-party lists have loaded.
    #[serde(default)]
    pub failsafe: FailsafeDto,
}

/// Live traffic of one listener.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ListenerCounters {
    pub active_connections: u64,
    /// Requests served per second over the last few seconds.
    pub requests_per_sec: f64,
    /// Distinct client addresses seen in the last 5 minutes.
    pub clients: u64,
}

/// State of the transparent-gateway listener.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct TransparentStatus {
    pub enabled: bool,
    /// Bound address (`ip:port`) while enabled and running; else the configured one.
    pub address: Option<String>,
    /// TLS hosts that are tunnelled instead of intercepted (exact or `*.suffix`).
    pub tls_passthrough_hosts: Vec<String>,
    /// Live traffic of the transparent listener (`active_connections`, `requests_per_sec`,
    /// `clients`).
    #[serde(flatten)]
    pub counters: ListenerCounters,
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
    /// Pass back as `cursor` for the next page (absent on the last page). Cursor paging is
    /// stable under inserts and deletes; `page` is the older offset form of the same list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
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
            next_cursor: None,
        }
    }
}

/// Filter list description.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct FilterListResponse {
    pub id: String,
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub last_updated: Option<String>,
    pub rule_count: usize,
    /// Rules of this list dropped as duplicates of an earlier list (or of itself) at the last
    /// build of its current download; `rule_count + duplicate_count` is the list's total.
    /// Absent until a build has seen the current download.
    #[serde(default)]
    pub duplicate_count: Option<usize>,
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
    /// Needs a look: the last fetch failed, an enabled list was never fetched or is more than
    /// 7 days old, or the last build found more problems in it than it tolerates (see
    /// `ListReport.attention`).
    #[serde(default)]
    pub attention: bool,
    /// Every rule of the list is already provided by another rule: it adds nothing of its own.
    #[serde(default)]
    pub redundant: bool,
}

/// Filter lists per status, for the current search text.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct FilterListCounts {
    pub all: usize,
    /// Enabled.
    pub on: usize,
    /// Disabled.
    pub off: usize,
    /// Fetch error or stale.
    pub attn: usize,
    /// First characters (`A`-`Z`, `#`) present among the rows matching the current filters.
    #[serde(default)]
    pub letters: Vec<String>,
}

/// A page of filter lists plus per-status counts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct FilterListsPage {
    pub items: Vec<FilterListResponse>,
    /// Pass as `cursor` for the next page; `null` on the last page.
    pub next_cursor: Option<String>,
    /// Lists matching `q` and `status`, across all pages.
    pub total: usize,
    pub counts: FilterListCounts,
    pub limit: u32,
    pub has_more: bool,
    /// Echoed only when the deprecated `page` parameter was used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<u32>,
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
    /// Browser logins (extension relay of non-anonymous requests and cookies) were approved.
    #[serde(default)]
    pub browser_cookies_approved: bool,
    /// Set when the script is approved for browser logins but its last request fell back to the
    /// proxy's own cookie jar (no connected extension, or no host permission).
    #[serde(default)]
    pub browser_logins_unavailable: bool,
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
    /// Last install or update (RFC 3339).
    #[serde(default)]
    pub updated_at: String,
    /// Uses features the proxy cannot run (see `unsupported`).
    #[serde(default)]
    pub error: bool,
    /// Imported without approval; stays off until approved.
    #[serde(default)]
    pub pending_approval: bool,
}

/// Userscripts per status, for the current search text.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct UserscriptCounts {
    pub all: usize,
    pub enabled: usize,
    pub disabled: usize,
    /// Scripts with unsupported features (may also be enabled).
    pub error: usize,
    /// Scripts that need a look: pending update, error, or awaiting approval.
    #[serde(default)]
    pub attention: usize,
    /// Scripts with a pending update.
    #[serde(default)]
    pub updates: usize,
    /// First characters (`A`-`Z`, `#`) present among the rows matching the current filters.
    #[serde(default)]
    pub letters: Vec<String>,
}

/// A page of userscripts plus per-status counts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct UserscriptsPage {
    pub items: Vec<UserscriptResponse>,
    pub next_cursor: Option<String>,
    pub total: usize,
    pub counts: UserscriptCounts,
    pub limit: u32,
    pub has_more: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<u32>,
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

/// Where the web UI's HTTPS certificate comes from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum WebUiTlsMode {
    /// Plain HTTP (or a reverse proxy terminates TLS).
    #[default]
    Off,
    /// A certificate issued by the Argus CA, renewed automatically.
    ArgusCa,
    /// A certificate and key the admin uploaded.
    Uploaded,
}

/// Public details of a web UI certificate. The private key is never exposed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct WebUiCertInfo {
    pub subject: String,
    pub issuer: String,
    /// DNS names and IP addresses the certificate is valid for.
    pub sans: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub fingerprint_sha256: String,
}

/// Built-in HTTPS for the web UI: the saved setting, the certificate it uses and whether the
/// listener is serving TLS right now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct WebUiTlsStatus {
    pub mode: WebUiTlsMode,
    pub sans: Vec<String>,
    pub redirect_http: bool,
    /// The listener is serving TLS now.
    pub active: bool,
    /// The certificate for the current mode (`None` when off or none is stored yet).
    pub cert: Option<WebUiCertInfo>,
    /// An uploaded certificate is stored (usable by switching to `uploaded`).
    pub uploaded: bool,
    /// Why the stored setting is not in effect (e.g. certificate could not be loaded).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Set the web UI's HTTPS mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct WebUiTlsRequest {
    pub mode: WebUiTlsMode,
    /// Names for the Argus CA certificate (required for `argus_ca`).
    #[serde(default)]
    pub sans: Vec<String>,
    #[serde(default)]
    pub redirect_http: bool,
}

/// Upload a certificate chain and its private key (PEM). Switches the mode to `uploaded`.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct WebUiTlsUpload {
    pub cert_pem: String,
    pub key_pem: String,
    #[serde(default)]
    pub redirect_http: bool,
}

impl std::fmt::Debug for WebUiTlsUpload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebUiTlsUpload").finish_non_exhaustive()
    }
}

//! Shared application state
//!
//! Defines the shared state that is passed to all handlers via Arc<AppState>.

use crate::audit::AuditStore;
use crate::auth::authz::RouteTable;
use crate::auth::models::User;
use crate::auth::session::SessionManager;
use crate::auth::tokens::TokenStore;
use crate::config::ApiConfig;
use crate::error::{ApiError, ApiResult};
use chrono::Utc;
use common::config::ProxyConfig;
use common::db::redb::{Durability, ReadableTable};
use common::db::{tables, Db, DbError};
use filter_engine::{FilterStats, SharedEngine};
use governor::{DefaultDirectRateLimiter, DefaultKeyedRateLimiter, Quota};
use list_service::{ListService, ListStore};
use parking_lot::RwLock;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Instant;
use userscript_engine::{UserscriptManager, UserscriptRuntime};
use uuid::Uuid;

/// Main application state shared across all handlers
/// Build outcome of one profile, as the proxy last saw it.
#[derive(Debug, Clone, Default)]
pub struct ProfileBuildInfo {
    pub last_error: Option<String>,
    pub last_built: Option<chrono::DateTime<chrono::Utc>>,
}

/// Live proxy facts about profiles and devices that the stores do not hold. Implemented by the
/// proxy and passed in at startup, so this crate does not depend on it.
pub trait ProfileRuntime: Send + Sync {
    /// Last build result of profile `id` (`None`: never built or unknown).
    fn build_info(&self, profile_id: u64) -> Option<ProfileBuildInfo>;
    /// When a connection last resolved to device `id`.
    fn device_last_seen(&self, device_id: u64) -> Option<chrono::DateTime<chrono::Utc>>;
}

/// Where the proxy's listeners are bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyBind {
    pub proxy: std::net::SocketAddr,
    pub transparent: Option<std::net::SocketAddr>,
    /// Not listening (a failed move could not be undone); the address is the last known one.
    pub proxy_down: bool,
    pub transparent_down: bool,
    pub proxy_error: Option<String>,
    pub transparent_error: Option<String>,
}

/// Caps on concurrent live-log streams, in total and per user.
pub struct LogStreamLimits {
    max_total: std::sync::atomic::AtomicUsize,
    max_per_user: std::sync::atomic::AtomicUsize,
    /// How often a stream re-checks its caller, milliseconds.
    recheck_ms: std::sync::atomic::AtomicU64,
    open: parking_lot::Mutex<(usize, std::collections::HashMap<Uuid, usize>)>,
}

/// Releases a stream slot when dropped.
pub struct LogStreamGuard {
    limits: Arc<LogStreamLimits>,
    user: Uuid,
}

impl LogStreamLimits {
    pub fn new(max_total: usize, max_per_user: usize) -> Self {
        Self {
            max_total: max_total.into(),
            max_per_user: max_per_user.into(),
            recheck_ms: 15_000.into(),
            open: Default::default(),
        }
    }

    /// How often a stream re-checks that its caller may still watch.
    pub fn recheck_every(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.recheck_ms.load(Ordering::Relaxed))
    }

    /// Change the re-check period (tests).
    pub fn set_recheck_every(&self, d: std::time::Duration) {
        self.recheck_ms
            .store(d.as_millis() as u64, Ordering::Relaxed);
    }

    /// Change the caps (tests).
    pub fn set(&self, max_total: usize, max_per_user: usize) {
        self.max_total.store(max_total, Ordering::Relaxed);
        self.max_per_user.store(max_per_user, Ordering::Relaxed);
    }

    /// Take a slot for `user`, or say why not (429).
    pub fn acquire(self: &Arc<Self>, user: Uuid) -> ApiResult<LogStreamGuard> {
        let mut g = self.open.lock();
        let mine = g.1.get(&user).copied().unwrap_or(0);
        if g.0 >= self.max_total.load(Ordering::Relaxed) {
            return Err(ApiError::RateLimitExceeded(
                "too many live log streams open on the server".into(),
            ));
        }
        if mine >= self.max_per_user.load(Ordering::Relaxed) {
            return Err(ApiError::RateLimitExceeded(
                "too many live log streams open for this account".into(),
            ));
        }
        g.0 += 1;
        g.1.insert(user, mine + 1);
        Ok(LogStreamGuard {
            limits: self.clone(),
            user,
        })
    }
}

impl Drop for LogStreamGuard {
    fn drop(&mut self) {
        let mut g = self.limits.open.lock();
        g.0 = g.0.saturating_sub(1);
        if let Some(n) = g.1.get_mut(&self.user) {
            *n -= 1;
            if *n == 0 {
                g.1.remove(&self.user);
            }
        }
    }
}

/// Live traffic of one listener.
#[derive(Debug, Clone, Copy, Default)]
pub struct ListenerCounters {
    pub active_connections: u64,
    pub requests_per_sec: f64,
    pub clients: u64,
}

/// Live changes to the running proxy. Implemented by the proxy and attached at startup
/// ([`AppState::runtime`]), so this crate does not depend on it. Without one (tests, no proxy)
/// listener and access changes are saved and reported as `restart_required`.
#[async_trait::async_trait]
pub trait RuntimeControl: Send + Sync {
    /// Move the proxy listeners; on failure nothing changed and the message says why.
    async fn rebind_proxy(
        &self,
        host: &str,
        port: u16,
        transparent_port: Option<u16>,
    ) -> Result<ProxyBind, String>;
    /// Apply the client ACL, TLS passthrough hosts, destination rules, DNS, limits and
    /// per-listener switches, all or nothing.
    async fn apply_access(&self, config: &ProxyConfig) -> Result<(), String>;
    /// Counters of the explicit and transparent listeners.
    fn listener_counters(&self) -> (ListenerCounters, ListenerCounters);
    /// Current bind addresses.
    async fn proxy_bind(&self) -> Option<ProxyBind>;
    /// Tell the proxy where the web API listens (loop protection).
    async fn note_webui(&self, host: &str, port: u16);
    /// Issue the web UI's HTTPS certificate from the Argus CA for `sans` (DNS names and IP
    /// literals). Returns `(certificate PEM, key PEM)`.
    async fn issue_webui_cert(&self, _sans: &[String]) -> Result<(String, String), String> {
        Err("this build cannot issue certificates".into())
    }
}

pub struct AppState {
    /// Proxy state wrapper
    pub proxy_state: Arc<ProxyState>,

    /// Filter engine statistics (thread-safe handle into `shared_engine`'s stats).
    pub filter_stats: FilterStats,

    /// Shared compiled adblock engine (Send/Sync handle; the real engine is thread-local).
    pub shared_engine: Arc<SharedEngine>,

    /// Persistent store of filter-list metadata + cached content.
    pub filter_store: Arc<ListStore>,
    /// Shared list service (fetch/compile/install); also owns `filter_store`.
    pub list_service: Arc<ListService>,

    /// Shared pooled HTTP client for downloading filter lists.
    pub http_client: reqwest::Client,

    /// Userscript manager
    pub userscript_manager: Arc<UserscriptManager>,

    /// Pending two-step userscript installs.
    pub userscript_plans: crate::userscript_ops::PlanStore,

    /// Userscript runtime
    pub userscript_runtime: Arc<UserscriptRuntime>,

    /// Session store for authentication (persistent user data)
    pub session_store: Arc<SessionStore>,

    /// Session manager (in-memory active sessions)
    pub session_manager: Arc<SessionManager>,

    /// JWT configuration
    pub jwt_config: Arc<JwtConfig>,

    /// bcrypt hash (at the configured cost) verified against when a login names no usable
    /// account, so the response time does not reveal which usernames exist.
    pub dummy_hash: String,

    /// Rate limiters
    pub rate_limiters: Arc<RateLimiters>,

    /// Path to proxy configuration file for reloading
    pub config_path: Arc<RwLock<PathBuf>>,

    /// API server settings (CSRF, cookies, trusted proxies, ...).
    pub api_config: ApiConfig,

    /// Personal access tokens.
    pub tokens: Arc<TokenStore>,

    /// Persisted audit log.
    pub audit: Arc<AuditStore>,

    /// Profiles and devices (shared with the proxy, which reacts to its change notifications).
    pub profiles: Arc<common::profile_store::ProfileStore>,

    /// Live build status and device activity from the proxy (`None` without a proxy).
    pub profile_runtime: Option<Arc<dyn ProfileRuntime>>,

    /// Script policy rules (per profile), compiled snapshots and blocked-source reports.
    pub policy: Arc<script_policy::store::PolicyStore>,

    /// Process start, for uptime.
    pub started_at: Instant,

    /// Bypass entries, categories and subscriptions (installed by the proxy at startup; a
    /// persisted default is created on first use otherwise).
    pub bypass: OnceLock<Arc<common::bypass::BypassEngine>>,

    /// Upstream certificates the proxy has seen (installed by the proxy; empty otherwise).
    pub certs: OnceLock<Arc<common::certstore::CertStore>>,

    /// Status of the trusted root set (installed by the proxy; absent otherwise).
    pub roots: OnceLock<Arc<common::certstore::RootsStatusCell>>,

    /// Fetches full certificate chains on demand (installed by the proxy).
    pub chain_probe: OnceLock<Arc<dyn common::certstore::ChainProbe>>,

    /// The first-party list manager (installed by the proxy; created on first use otherwise).
    pub argus: OnceLock<Arc<list_service::ArgusLists>>,
    /// Signed filter-list catalogue (argus-lists).
    pub filter_catalogue:
        OnceLock<Arc<list_service::SignedDoc<list_service::FilterCatalogueEntry>>>,
    /// Signed userscript catalogue (argus-lists).
    pub userscript_catalogue:
        OnceLock<Arc<list_service::SignedDoc<list_service::UserscriptCatalogueEntry>>>,

    /// Serialises config updates and reloads (ETag check through save and commit).
    pub config_lock: tokio::sync::Mutex<()>,

    /// Caps on concurrent live-log streams (5 per user, 64 in all).
    pub log_streams: Arc<LogStreamLimits>,

    /// Request / block counts over time (fed by a sampler started with the server).
    pub timeseries: crate::timeseries::Timeseries,

    /// Live control of the proxy listeners and access lists (`None` without a proxy).
    pub runtime: OnceLock<Arc<dyn RuntimeControl>>,

    /// The running web API server, for rebinding its own listener (set by `start_server`).
    pub web_server: OnceLock<Arc<crate::server::WebServer>>,

    /// Settings overlay written by config updates (the base file may be read-only).
    pub overlay_path: Arc<RwLock<PathBuf>>,

    /// Serialised OpenAPI document; set once by `create_router`.
    pub spec_json: OnceLock<String>,

    /// Route -> required scopes, derived from the OpenAPI spec by `create_router`.
    pub route_auth: OnceLock<RouteTable>,
}

/// Proxy state wrapper
pub struct ProxyState {
    /// Proxy configuration (hot-reloadable)
    pub config: Arc<RwLock<ProxyConfig>>,

    /// Runtime statistics
    pub stats: Arc<ProxyStats>,

    /// Live upstream request timeout (ms), shared with the proxy's `ProxyContext`.
    pub request_timeout_ms: Arc<AtomicU64>,

    /// MITM enabled flag (for stats display)
    pub mitm_enabled: bool,

    /// Cached certificate count (updated periodically if MITM is enabled)
    pub mitm_cached_certs: Arc<AtomicU64>,
}

/// Proxy runtime statistics
pub struct ProxyStats {
    /// Total connections accepted
    pub connections_total: AtomicU64,

    /// Currently active connections
    pub connections_active: AtomicU64,

    /// Total requests processed
    pub requests_total: AtomicU64,

    /// Total bytes received
    pub bytes_received: AtomicU64,

    /// Total bytes sent
    pub bytes_sent: AtomicU64,

    /// Total errors encountered
    pub errors_total: AtomicU64,
}

impl Default for ProxyStats {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyStats {
    pub fn new() -> Self {
        Self {
            connections_total: AtomicU64::new(0),
            connections_active: AtomicU64::new(0),
            requests_total: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            errors_total: AtomicU64::new(0),
        }
    }

    /// Record a new connection
    pub fn record_connection(&self) {
        self.connections_total.fetch_add(1, Ordering::Relaxed);
        self.connections_active.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a connection close
    pub fn record_connection_close(&self) {
        self.connections_active.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record a request
    pub fn record_request(&self) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record bytes transferred
    pub fn record_bytes(&self, received: u64, sent: u64) {
        self.bytes_received.fetch_add(received, Ordering::Relaxed);
        self.bytes_sent.fetch_add(sent, Ordering::Relaxed);
    }

    /// Record an error
    pub fn record_error(&self) {
        self.errors_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Get current statistics snapshot
    pub fn snapshot(&self) -> ProxyStatsSnapshot {
        ProxyStatsSnapshot {
            connections_total: self.connections_total.load(Ordering::Relaxed),
            connections_active: self.connections_active.load(Ordering::Relaxed),
            requests_total: self.requests_total.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            errors_total: self.errors_total.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of proxy statistics
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProxyStatsSnapshot {
    pub connections_total: u64,
    pub connections_active: u64,
    pub requests_total: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub errors_total: u64,
}

/// JWT configuration
pub struct JwtConfig {
    /// Secret key for signing JWTs
    pub secret: String,

    /// Access token expiry in seconds
    pub access_token_expiry_secs: u64,

    /// Refresh token expiry in seconds
    pub refresh_token_expiry_secs: u64,

    /// Issuer
    pub issuer: String,

    /// Audience
    pub audience: String,
}

/// User accounts (persistent), on the shared database.
///
/// Durability: user changes are `Immediate` and must be made from a blocking context (see
/// [`blocking`]); `last_login` is written lazily through the coalescing writer.
pub struct SessionStore {
    db: Arc<Db>,
    /// Serialises changes that must preserve the "at least one enabled admin" invariant.
    pub admin_lock: parking_lot::Mutex<()>,
}

fn user_json(user: &User) -> ApiResult<Vec<u8>> {
    serde_json::to_vec(user).map_err(|e| ApiError::Internal(e.to_string()))
}

impl SessionStore {
    /// Open the shared database in the directory `path`.
    pub fn new(path: PathBuf) -> ApiResult<Self> {
        Ok(Self::with_db(Db::open(&path)?))
    }

    pub fn with_db(db: Arc<Db>) -> Self {
        Self {
            db,
            admin_lock: parking_lot::Mutex::new(()),
        }
    }

    /// The shared database handle (other stores keep their tables in it).
    pub fn db(&self) -> Arc<Db> {
        self.db.clone()
    }

    /// Number of enabled administrators.
    pub fn enabled_admin_count(&self) -> ApiResult<usize> {
        Ok(self
            .get_all_users()?
            .iter()
            .filter(|u| u.enabled && u.role.is_admin())
            .count())
    }

    /// Store a user and its username index entry in one transaction. A username already taken
    /// by another user fails with `AlreadyExists` and nothing is written; renaming a user moves
    /// the index entry atomically.
    pub fn store_user(&self, user: &User) -> ApiResult<()> {
        let bytes = user_json(user)?;
        let id = user.id.to_string();
        self.db.write::<_, ApiError>(Durability::Immediate, |t| {
            let mut users = t.open_table(tables::USERS).map_err(DbError::from)?;
            let mut names = t.open_table(tables::USERNAMES).map_err(DbError::from)?;
            let owner = names
                .get(user.username.as_str())
                .map_err(DbError::from)?
                .map(|g| g.value().to_string());
            if owner.is_some_and(|o| o != id) {
                return Err(ApiError::AlreadyExists(format!("User '{}'", user.username)));
            }
            let previous = users
                .get(id.as_str())
                .map_err(DbError::from)?
                .and_then(|g| serde_json::from_slice::<User>(g.value()).ok());
            if let Some(prev) = previous.filter(|p| p.username != user.username) {
                names
                    .remove(prev.username.as_str())
                    .map_err(DbError::from)?;
            }
            users
                .insert(id.as_str(), bytes.as_slice())
                .map_err(DbError::from)?;
            names
                .insert(user.username.as_str(), id.as_str())
                .map_err(DbError::from)?;
            Ok(())
        })
    }

    fn load(&self, id: &str) -> ApiResult<Option<User>> {
        self.db.read::<_, ApiError>(|r| {
            let users = r.open_table(tables::USERS).map_err(DbError::from)?;
            let found = users.get(id).map_err(DbError::from)?;
            found
                .map(|g| {
                    serde_json::from_slice(g.value()).map_err(|e| ApiError::Internal(e.to_string()))
                })
                .transpose()
        })
    }

    /// Get a user by ID
    pub fn get_user(&self, id: &Uuid) -> ApiResult<Option<User>> {
        self.load(&id.to_string())
    }

    /// Get a user by username (index and user are read from one snapshot).
    pub fn get_user_by_username(&self, username: &str) -> ApiResult<Option<User>> {
        self.db.read::<_, ApiError>(|r| {
            let names = r.open_table(tables::USERNAMES).map_err(DbError::from)?;
            let users = r.open_table(tables::USERS).map_err(DbError::from)?;
            let Some(id) = names
                .get(username)
                .map_err(DbError::from)?
                .map(|g| g.value().to_string())
            else {
                return Ok(None);
            };
            let found = users.get(id.as_str()).map_err(DbError::from)?;
            found
                .map(|g| {
                    serde_json::from_slice(g.value()).map_err(|e| ApiError::Internal(e.to_string()))
                })
                .transpose()
        })
    }

    /// Update the user's last login timestamp (queued; coalesced, no fsync).
    pub fn update_last_login(&self, id: &Uuid) -> ApiResult<()> {
        let id = id.to_string();
        let now = Utc::now();
        self.db.defer(move |t| {
            let mut users = t.open_table(tables::USERS)?;
            let cur = users.get(id.as_str())?.map(|g| g.value().to_vec());
            if let Some(mut u) = cur.and_then(|b| serde_json::from_slice::<User>(&b).ok()) {
                u.last_login = Some(now);
                if let Ok(b) = serde_json::to_vec(&u) {
                    users.insert(id.as_str(), b.as_slice())?;
                }
            }
            Ok(())
        });
        Ok(())
    }

    /// Check if a username exists
    pub fn username_exists(&self, username: &str) -> ApiResult<bool> {
        self.db.read::<_, ApiError>(|r| {
            let names = r.open_table(tables::USERNAMES).map_err(DbError::from)?;
            let found = names.get(username).map_err(DbError::from)?.is_some();
            Ok(found)
        })
    }

    /// Delete a user and its username index entry in one transaction.
    pub fn delete_user(&self, id: &Uuid) -> ApiResult<bool> {
        let id = id.to_string();
        self.db.write::<_, ApiError>(Durability::Immediate, |t| {
            let mut users = t.open_table(tables::USERS).map_err(DbError::from)?;
            let mut names = t.open_table(tables::USERNAMES).map_err(DbError::from)?;
            let old = users
                .remove(id.as_str())
                .map_err(DbError::from)?
                .and_then(|g| serde_json::from_slice::<User>(g.value()).ok());
            match old {
                Some(u) => {
                    names.remove(u.username.as_str()).map_err(DbError::from)?;
                    Ok(true)
                }
                None => Ok(false),
            }
        })
    }

    /// Get all users
    pub fn get_all_users(&self) -> ApiResult<Vec<User>> {
        self.db.read::<_, ApiError>(|r| {
            let users = r.open_table(tables::USERS).map_err(DbError::from)?;
            let mut result = Vec::new();
            for item in users.iter().map_err(DbError::from)? {
                let (_, v) = item.map_err(DbError::from)?;
                result.push(
                    serde_json::from_slice::<User>(v.value())
                        .map_err(|e| ApiError::Internal(e.to_string()))?,
                );
            }
            Ok(result)
        })
    }
}

/// Run a storage operation on the blocking pool: redb write transactions fsync, so they must
/// never run on an async worker thread.
pub async fn blocking<T, F>(f: F) -> ApiResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> ApiResult<T> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| ApiError::Internal(format!("storage task failed: {e}")))?
}

/// Rate limiters: global, per client IP, stricter per-IP for auth endpoints, and per principal
/// (user session or API token).
pub struct RateLimiters {
    global: DefaultDirectRateLimiter,
    ip: DefaultKeyedRateLimiter<IpAddr>,
    auth: DefaultKeyedRateLimiter<IpAddr>,
    principal: DefaultKeyedRateLimiter<String>,
    checks: std::sync::atomic::AtomicU64,
}

fn per_minute(n: u64) -> Quota {
    Quota::per_minute(
        NonZeroU32::new(n.clamp(1, u32::MAX as u64) as u32).unwrap_or(NonZeroU32::MIN),
    )
}

impl RateLimiters {
    pub fn new(global_rpm: u64, ip_rpm: u64, principal_rpm: u64, auth_rpm: u64) -> Self {
        Self {
            global: governor::RateLimiter::direct(per_minute(global_rpm)),
            ip: governor::RateLimiter::keyed(per_minute(ip_rpm)),
            auth: governor::RateLimiter::keyed(per_minute(auth_rpm)),
            principal: governor::RateLimiter::keyed(per_minute(principal_rpm)),
            checks: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn housekeeping(&self) {
        if self.checks.fetch_add(1, Ordering::Relaxed) % 4096 == 4095 {
            self.ip.retain_recent();
            self.auth.retain_recent();
            self.principal.retain_recent();
        }
    }

    pub fn check_global(&self) -> bool {
        self.global.check().is_ok()
    }

    pub fn check_ip(&self, ip: IpAddr) -> bool {
        self.housekeeping();
        self.ip.check_key(&ip).is_ok()
    }

    pub fn check_auth(&self, ip: IpAddr) -> bool {
        self.auth.check_key(&ip).is_ok()
    }

    pub fn check_principal(&self, key: &str) -> bool {
        self.principal.check_key(&key.to_string()).is_ok()
    }
}

/// Build the application state from components, with a script policy store of its own.
#[allow(clippy::too_many_arguments)]
pub async fn build_state(
    api_config: ApiConfig,
    proxy_config: ProxyConfig,
    shared_engine: Arc<SharedEngine>,
    list_service: Arc<ListService>,
    http_client: reqwest::Client,
    userscript_manager: Arc<UserscriptManager>,
    userscript_runtime: Arc<UserscriptRuntime>,
    config_path: PathBuf,
    request_timeout_ms: Arc<AtomicU64>,
) -> ApiResult<Arc<AppState>> {
    build_state_with_policy(
        api_config,
        proxy_config,
        shared_engine,
        list_service,
        http_client,
        userscript_manager,
        userscript_runtime,
        config_path,
        request_timeout_ms,
        None,
    )
    .await
}

/// Build the application state, sharing `policy` (the proxy path reads the same store) when
/// given.
#[allow(clippy::too_many_arguments)]
pub async fn build_state_with_policy(
    api_config: ApiConfig,
    proxy_config: ProxyConfig,
    shared_engine: Arc<SharedEngine>,
    list_service: Arc<ListService>,
    http_client: reqwest::Client,
    userscript_manager: Arc<UserscriptManager>,
    userscript_runtime: Arc<UserscriptRuntime>,
    config_path: PathBuf,
    request_timeout_ms: Arc<AtomicU64>,
    policy: Option<Arc<script_policy::store::PolicyStore>>,
) -> ApiResult<Arc<AppState>> {
    build_state_full(
        api_config,
        proxy_config,
        shared_engine,
        list_service,
        http_client,
        userscript_manager,
        userscript_runtime,
        config_path,
        request_timeout_ms,
        policy,
        None,
        None,
    )
    .await
}

/// Like [`build_state_with_policy`], also sharing `profiles` (the proxy resolves devices through
/// the same store) when given. When `None`, a store is opened over the session database.
#[allow(clippy::too_many_arguments)]
pub async fn build_state_full(
    api_config: ApiConfig,
    proxy_config: ProxyConfig,
    shared_engine: Arc<SharedEngine>,
    list_service: Arc<ListService>,
    http_client: reqwest::Client,
    userscript_manager: Arc<UserscriptManager>,
    userscript_runtime: Arc<UserscriptRuntime>,
    config_path: PathBuf,
    request_timeout_ms: Arc<AtomicU64>,
    policy: Option<Arc<script_policy::store::PolicyStore>>,
    profiles: Option<Arc<common::profile_store::ProfileStore>>,
    profile_runtime: Option<Arc<dyn ProfileRuntime>>,
) -> ApiResult<Arc<AppState>> {
    let overlay_dir = api_config.session.storage_path.clone();
    crate::auth::password::validate_bcrypt_cost(api_config.auth.bcrypt_cost)?;
    if api_config.auth.bcrypt_cost < crate::auth::password::RECOMMENDED_MIN_BCRYPT_COST {
        tracing::warn!(
            "auth.bcrypt_cost = {} is weak; use {} or more outside of tests",
            api_config.auth.bcrypt_cost,
            crate::auth::password::RECOMMENDED_MIN_BCRYPT_COST
        );
    }

    // Initialize JWT config
    let jwt_config = Arc::new(JwtConfig {
        secret: load_or_generate_jwt_secret(&api_config.auth.jwt_secret_path).await?,
        access_token_expiry_secs: api_config.auth.access_token_expiry_seconds,
        refresh_token_expiry_secs: api_config.auth.refresh_token_expiry_seconds,
        issuer: api_config.auth.issuer.clone(),
        audience: api_config.auth.audience.clone(),
    });

    let dummy_hash = {
        let cost = api_config.auth.bcrypt_cost;
        tokio::task::spawn_blocking(move || {
            crate::auth::password::hash_password("dummy-password-never-matches", cost)
        })
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))??
    };

    // Initialize session store (persistent user data)
    let session_store = Arc::new(SessionStore::new(api_config.session.storage_path.clone())?);
    let db = session_store.db();
    let profiles = match profiles {
        Some(p) => p,
        None => Arc::new(
            common::profile_store::ProfileStore::open(&db)
                .map_err(|e| ApiError::Internal(format!("profile store: {e}")))?,
        ),
    };
    let policy =
        policy.unwrap_or_else(|| Arc::new(script_policy::store::PolicyStore::new(db.clone())));

    // Sessions (committed before revocation takes effect), tokens and audit share the db.
    let session_manager = Arc::new(SessionManager::new(db.clone())?);
    let tokens = Arc::new(TokenStore::new(db.clone())?);
    let audit = Arc::new(AuditStore::new(
        db,
        api_config.audit.max_entries,
        api_config.audit.retention_days,
    )?);

    // Initialize rate limiters
    let rate_limiters = Arc::new(RateLimiters::new(
        api_config.rate_limit.global_requests_per_minute,
        api_config.rate_limit.ip_requests_per_minute,
        api_config.rate_limit.user_requests_per_minute,
        api_config.network.auth_requests_per_minute as u64,
    ));

    // Create proxy state
    let mitm_enabled = proxy_config.mitm.enabled;
    let proxy_state = Arc::new(ProxyState {
        config: Arc::new(RwLock::new(proxy_config)),
        stats: Arc::new(ProxyStats::new()),
        request_timeout_ms,
        mitm_enabled,
        mitm_cached_certs: Arc::new(AtomicU64::new(0)),
    });

    // Stats live in the shared engine; the handle is cheap to clone and thread-safe.
    let filter_stats = shared_engine.stats_handle();

    Ok(Arc::new(AppState {
        proxy_state,
        filter_stats,
        shared_engine,
        filter_store: list_service.store().clone(),
        list_service,
        http_client,
        userscript_manager,
        userscript_runtime,
        userscript_plans: Default::default(),
        session_store,
        session_manager,
        jwt_config,
        dummy_hash,
        rate_limiters,
        config_path: Arc::new(RwLock::new(config_path)),
        api_config,
        tokens,
        audit,
        profiles,
        profile_runtime,
        policy,
        started_at: Instant::now(),
        bypass: OnceLock::new(),
        certs: OnceLock::new(),
        roots: OnceLock::new(),
        chain_probe: OnceLock::new(),
        argus: OnceLock::new(),
        filter_catalogue: OnceLock::new(),
        userscript_catalogue: OnceLock::new(),
        config_lock: tokio::sync::Mutex::new(()),
        log_streams: Arc::new(LogStreamLimits::new(64, 5)),
        timeseries: Default::default(),
        runtime: OnceLock::new(),
        web_server: OnceLock::new(),
        overlay_path: Arc::new(RwLock::new(common::config::default_overlay_path(
            &overlay_dir,
        ))),
        spec_json: OnceLock::new(),
        route_auth: OnceLock::new(),
    }))
}

/// Load JWT secret from file or generate a new one
async fn load_or_generate_jwt_secret(path: &PathBuf) -> ApiResult<String> {
    use rand::Rng;

    // Try to load existing secret
    if path.exists() {
        let secret = tokio::fs::read_to_string(path).await?;
        return Ok(secret.trim().to_string());
    }

    // Generate new secret
    let secret: [u8; 32] = rand::thread_rng().gen();
    let secret_base64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, secret);

    // Create parent directory if needed
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    // Save to file with restrictive permissions
    tokio::fs::write(path, &secret_base64).await?;

    // Set permissions to 0600 (owner read/write only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, permissions)?;
    }

    tracing::info!("Generated new JWT secret at {:?}", path);

    Ok(secret_base64)
}

impl AppState {
    /// The first-party list manager.
    pub fn argus(&self) -> &Arc<list_service::ArgusLists> {
        self.argus.get_or_init(|| {
            let bypass = self.bypass().clone();
            let cfg = list_service::ArgusConfig::from_config(
                &self.proxy_state.config.read().bypass,
                bypass.data_dir().map(|d| d.join("argus-lists")),
            );
            list_service::ArgusLists::new(bypass, self.list_service.clone(), cfg)
        })
    }

    /// Make the bypass lists and both catalogues read the lists base URL and key from the live config on every
    /// refresh. Holds the state weakly (the catalogues live inside it).
    pub fn follow_live_catalogue_config(self: &Arc<Self>) {
        let (a, b, c) = (
            Arc::downgrade(self),
            Arc::downgrade(self),
            Arc::downgrade(self),
        );
        let cfg = |w: &std::sync::Weak<Self>| {
            let s = w.upgrade()?;
            Some(s.catalogue_cfg())
        };
        let fallback = self.catalogue_cfg();
        let (fb, fc) = (fallback.clone(), fallback.clone());
        self.argus()
            .set_config_source(move || cfg(&c).unwrap_or_else(|| fc.clone()));
        self.filter_catalogue()
            .set_config_source(move || cfg(&a).unwrap_or_else(|| fb.clone()));
        self.userscript_catalogue()
            .set_config_source(move || cfg(&b).unwrap_or_else(|| fallback.clone()));
    }

    /// The lists base URL, key and cache directory from the live config.
    pub fn catalogue_cfg(&self) -> list_service::ArgusConfig {
        list_service::ArgusConfig::from_config(
            &self.proxy_state.config.read().bypass,
            self.bypass().data_dir().map(|d| d.join("argus-lists")),
        )
    }

    /// The signed filter-list catalogue (empty until verified).
    pub fn filter_catalogue(
        &self,
    ) -> &Arc<list_service::SignedDoc<list_service::FilterCatalogueEntry>> {
        self.filter_catalogue.get_or_init(|| {
            list_service::SignedDoc::new(
                "filters",
                Some(self.list_service.clone()),
                self.catalogue_cfg(),
            )
        })
    }

    /// The signed userscript catalogue (empty until verified).
    pub fn userscript_catalogue(
        &self,
    ) -> &Arc<list_service::SignedDoc<list_service::UserscriptCatalogueEntry>> {
        self.userscript_catalogue.get_or_init(|| {
            list_service::SignedDoc::new(
                "userscripts",
                Some(self.list_service.clone()),
                self.catalogue_cfg(),
            )
        })
    }

    /// The upstream certificate store.
    pub fn certs(&self) -> &Arc<common::certstore::CertStore> {
        self.certs.get_or_init(Default::default)
    }

    /// The bypass engine.
    pub fn bypass(&self) -> &Arc<common::bypass::BypassEngine> {
        self.bypass.get_or_init(|| {
            let path = self
                .overlay_path
                .read()
                .parent()
                .map_or_else(|| "bypass.json".into(), |p| p.join("bypass.json"));
            Arc::new(common::bypass::BypassEngine::load(path))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use api_types::UserRole;

    fn store() -> (SessionStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        (SessionStore::new(dir.path().to_path_buf()).unwrap(), dir)
    }

    fn user(name: &str) -> User {
        User::new(name.into(), "hash".into(), UserRole::Viewer)
    }

    #[test]
    fn roundtrip_and_index() {
        let (s, _d) = store();
        let u = user("alice");
        s.store_user(&u).unwrap();
        assert_eq!(s.get_user(&u.id).unwrap().unwrap().username, "alice");
        assert_eq!(s.get_user_by_username("alice").unwrap().unwrap().id, u.id);
        assert!(s.username_exists("alice").unwrap());
        assert!(s.delete_user(&u.id).unwrap());
        assert!(!s.username_exists("alice").unwrap());
        assert!(s.get_user(&u.id).unwrap().is_none());
        assert!(!s.delete_user(&u.id).unwrap());
    }

    #[test]
    fn duplicate_username_writes_nothing() {
        let (s, _d) = store();
        let first = user("bob");
        s.store_user(&first).unwrap();
        let dup = user("bob");
        assert!(matches!(
            s.store_user(&dup),
            Err(ApiError::AlreadyExists(_))
        ));
        // Neither the user row nor the index moved.
        assert!(s.get_user(&dup.id).unwrap().is_none());
        assert_eq!(s.get_user_by_username("bob").unwrap().unwrap().id, first.id);
        assert_eq!(s.get_all_users().unwrap().len(), 1);
    }

    #[test]
    fn concurrent_creation_of_one_username_has_one_winner() {
        let (s, _d) = store();
        let s = Arc::new(s);
        let wins: usize = (0..8)
            .map(|_| {
                let s = s.clone();
                std::thread::spawn(move || s.store_user(&user("carol")).is_ok())
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| usize::from(h.join().unwrap()))
            .sum();
        assert_eq!(wins, 1);
        assert_eq!(s.get_all_users().unwrap().len(), 1);
    }

    #[test]
    fn rename_moves_the_index_atomically() {
        let (s, _d) = store();
        let mut u = user("old");
        s.store_user(&u).unwrap();
        u.username = "new".into();
        s.store_user(&u).unwrap();
        assert!(!s.username_exists("old").unwrap());
        assert_eq!(s.get_user_by_username("new").unwrap().unwrap().id, u.id);
    }

    #[test]
    fn users_survive_restart_and_last_login_is_queued() {
        let dir = tempfile::tempdir().unwrap();
        let id = {
            let s = SessionStore::new(dir.path().to_path_buf()).unwrap();
            let u = user("dave");
            s.store_user(&u).unwrap();
            s.update_last_login(&u.id).unwrap();
            u.id
        };
        let s = SessionStore::new(dir.path().to_path_buf()).unwrap();
        let u = s.get_user_by_username("dave").unwrap().unwrap();
        assert_eq!(u.id, id);
        assert!(u.last_login.is_some());
    }

    #[test]
    fn legacy_sled_directory_does_not_break_startup() {
        let dir = tempfile::tempdir().unwrap();
        let old = dir.path().join("sessions");
        std::fs::create_dir_all(&old).unwrap();
        std::fs::write(old.join("conf"), b"x").unwrap();
        std::fs::write(old.join("db"), b"x").unwrap();
        let s = SessionStore::new(dir.path().to_path_buf()).unwrap();
        s.store_user(&user("erin")).unwrap();
        assert_eq!(s.get_all_users().unwrap().len(), 1);
    }

    #[test]
    fn newer_schema_is_rejected_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        {
            let db = Db::open(dir.path()).unwrap();
            db.write::<_, DbError>(Durability::Immediate, |t| {
                t.open_table(tables::META)?
                    .insert("schema_version", 999u32.to_be_bytes().as_slice())?;
                Ok(())
            })
            .unwrap();
        }
        let err = SessionStore::new(dir.path().to_path_buf()).err().unwrap();
        assert!(err.to_string().contains("newer"), "{err}");
    }
}

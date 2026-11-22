//! Shared application state
//!
//! Defines the shared state that is passed to all handlers via Arc<AppState>.

use crate::auth::models::User;
use crate::auth::session::SessionManager;
use crate::config::ApiConfig;
use crate::error::{ApiError, ApiResult};
use chrono::Utc;
use common::config::ProxyConfig;
use dashmap::DashMap;
use filter_engine::{FilterStats, SharedEngine};
use governor::{Quota, RateLimiter};
use list_service::{ListService, ListStore};
use parking_lot::RwLock;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use userscript_engine::{UserscriptManager, UserscriptRuntime};
use uuid::Uuid;

/// Main application state shared across all handlers
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

    /// Userscript runtime
    pub userscript_runtime: Arc<UserscriptRuntime>,

    /// Session store for authentication (persistent user data)
    pub session_store: Arc<SessionStore>,

    /// Session manager (in-memory active sessions)
    pub session_manager: Arc<SessionManager>,

    /// JWT configuration
    pub jwt_config: Arc<JwtConfig>,

    /// Rate limiters
    pub rate_limiters: Arc<RateLimiters>,

    /// Path to proxy configuration file for reloading
    pub config_path: Arc<RwLock<PathBuf>>,
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

/// Session store for user authentication and session management
pub struct SessionStore {
    /// Sled database for persistent storage
    db: sled::Db,
}

impl SessionStore {
    pub fn new(path: PathBuf) -> ApiResult<Self> {
        let db = sled::open(path)?;
        Ok(Self { db })
    }

    /// Get the users tree
    fn users_tree(&self) -> ApiResult<sled::Tree> {
        Ok(self.db.open_tree("users")?)
    }

    /// Get the username index tree
    fn username_index(&self) -> ApiResult<sled::Tree> {
        Ok(self.db.open_tree("username_index")?)
    }

    /// Store a user in the database
    pub fn store_user(&self, user: &User) -> ApiResult<()> {
        let users = self.users_tree()?;
        let index = self.username_index()?;

        let user_bytes = serde_json::to_vec(user).map_err(|e| ApiError::Internal(e.to_string()))?;

        // Store user by ID
        users.insert(user.id.as_bytes(), user_bytes)?;

        // Store username -> ID index
        index.insert(user.username.as_bytes(), user.id.as_bytes())?;

        Ok(())
    }

    /// Get a user by ID
    pub fn get_user(&self, id: &Uuid) -> ApiResult<Option<User>> {
        let users = self.users_tree()?;

        match users.get(id.as_bytes())? {
            Some(bytes) => {
                let user: User = serde_json::from_slice(&bytes)
                    .map_err(|e| ApiError::Internal(e.to_string()))?;
                Ok(Some(user))
            }
            None => Ok(None),
        }
    }

    /// Get a user by username
    pub fn get_user_by_username(&self, username: &str) -> ApiResult<Option<User>> {
        let index = self.username_index()?;

        match index.get(username.as_bytes())? {
            Some(id_bytes) => {
                let id =
                    Uuid::from_slice(&id_bytes).map_err(|e| ApiError::Internal(e.to_string()))?;
                self.get_user(&id)
            }
            None => Ok(None),
        }
    }

    /// Update user's last login timestamp
    pub fn update_last_login(&self, id: &Uuid) -> ApiResult<()> {
        if let Some(mut user) = self.get_user(id)? {
            user.last_login = Some(Utc::now());
            self.store_user(&user)?;
        }
        Ok(())
    }

    /// Check if a username exists
    pub fn username_exists(&self, username: &str) -> ApiResult<bool> {
        let index = self.username_index()?;
        Ok(index.contains_key(username.as_bytes())?)
    }

    /// Delete a user
    pub fn delete_user(&self, id: &Uuid) -> ApiResult<bool> {
        let users = self.users_tree()?;
        let index = self.username_index()?;

        if let Some(user) = self.get_user(id)? {
            users.remove(id.as_bytes())?;
            index.remove(user.username.as_bytes())?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Get all users
    pub fn get_all_users(&self) -> ApiResult<Vec<User>> {
        let users = self.users_tree()?;
        let mut result = Vec::new();

        for item in users.iter() {
            let (_, value) = item.map_err(|e| ApiError::Internal(e.to_string()))?;
            let user: User =
                serde_json::from_slice(&value).map_err(|e| ApiError::Internal(e.to_string()))?;
            result.push(user);
        }

        Ok(result)
    }
}

/// Multi-tier rate limiters
pub struct RateLimiters {
    /// Global rate limiter (all requests)
    pub global: Arc<
        RwLock<
            RateLimiter<
                governor::state::direct::NotKeyed,
                governor::state::InMemoryState,
                governor::clock::DefaultClock,
            >,
        >,
    >,

    /// Per-IP rate limiters
    pub per_ip: Arc<
        DashMap<
            IpAddr,
            RateLimiter<
                governor::state::direct::NotKeyed,
                governor::state::InMemoryState,
                governor::clock::DefaultClock,
            >,
        >,
    >,

    /// Per-user rate limiters
    pub per_user: Arc<
        DashMap<
            String,
            RateLimiter<
                governor::state::direct::NotKeyed,
                governor::state::InMemoryState,
                governor::clock::DefaultClock,
            >,
        >,
    >,
}

impl RateLimiters {
    pub fn new(global_rpm: u64, _ip_rpm: u64, _user_rpm: u64) -> Self {
        // Convert to NonZeroU32, defaulting to 1 if 0 or too large
        let global_rpm_u32 = NonZeroU32::new(global_rpm.min(u32::MAX as u64) as u32)
            .unwrap_or(NonZeroU32::new(1).unwrap());
        let global_quota = Quota::per_minute(global_rpm_u32);
        let global_limiter = RateLimiter::direct(global_quota);

        Self {
            global: Arc::new(RwLock::new(global_limiter)),
            per_ip: Arc::new(DashMap::new()),
            per_user: Arc::new(DashMap::new()),
        }
    }
}

/// Build the application state from components
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
    // Initialize JWT config
    let jwt_config = Arc::new(JwtConfig {
        secret: load_or_generate_jwt_secret(&api_config.auth.jwt_secret_path).await?,
        access_token_expiry_secs: api_config.auth.access_token_expiry_seconds,
        refresh_token_expiry_secs: api_config.auth.refresh_token_expiry_seconds,
        issuer: api_config.auth.issuer.clone(),
        audience: api_config.auth.audience.clone(),
    });

    // Initialize session store (persistent user data)
    let session_store = Arc::new(SessionStore::new(api_config.session.storage_path.clone())?);

    // Initialize session manager (in-memory active sessions)
    let session_manager = Arc::new(SessionManager::default());

    // Initialize rate limiters
    let rate_limiters = Arc::new(RateLimiters::new(
        api_config.rate_limit.global_requests_per_minute,
        api_config.rate_limit.ip_requests_per_minute,
        api_config.rate_limit.user_requests_per_minute,
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
        session_store,
        session_manager,
        jwt_config,
        rate_limiters,
        config_path: Arc::new(RwLock::new(config_path)),
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

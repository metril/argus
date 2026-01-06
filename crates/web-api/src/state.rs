//! Shared application state
//!
//! Defines the shared state that is passed to all handlers via Arc<AppState>.

use crate::config::ApiConfig;
use crate::error::ApiResult;
use dashmap::DashMap;
use filter_engine::{FilterEngine, FilterStats};
use governor::{Quota, RateLimiter};
use parking_lot::RwLock;
use std::num::NonZeroU32;
use proxy_core::{config::ProxyConfig, mitm::MitmHandler};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use userscript_engine::{UserscriptManager, UserscriptRuntime, UserscriptStorage};

/// Main application state shared across all handlers
pub struct AppState {
    /// Proxy state wrapper
    pub proxy_state: Arc<ProxyState>,

    /// Filter engine statistics (thread-safe, shared with the filter engine)
    /// The actual FilterEngine is not stored here because adblock::Engine is not Send/Sync.
    /// Instead, we share just the stats which are already thread-safe via Arc.
    pub filter_stats: FilterStats,

    /// Userscript manager
    pub userscript_manager: Arc<UserscriptManager>,

    /// Userscript runtime
    pub userscript_runtime: Arc<UserscriptRuntime>,

    /// Session store for authentication
    pub session_store: Arc<SessionStore>,

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

    /// MITM handler reference for cert cache stats
    pub mitm_handler: Option<Arc<MitmHandler>>,
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
    pub access_token_expiry: u64,

    /// Refresh token expiry in seconds
    pub refresh_token_expiry: u64,

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

    /// Get the revoked tokens tree
    fn revoked_tree(&self) -> ApiResult<sled::Tree> {
        Ok(self.db.open_tree("revoked_tokens")?)
    }
}

/// Multi-tier rate limiters
pub struct RateLimiters {
    /// Global rate limiter (all requests)
    pub global: Arc<RwLock<RateLimiter<governor::state::direct::NotKeyed, governor::state::InMemoryState, governor::clock::DefaultClock>>>,

    /// Per-IP rate limiters
    pub per_ip: Arc<DashMap<IpAddr, RateLimiter<governor::state::direct::NotKeyed, governor::state::InMemoryState, governor::clock::DefaultClock>>>,

    /// Per-user rate limiters
    pub per_user: Arc<DashMap<String, RateLimiter<governor::state::direct::NotKeyed, governor::state::InMemoryState, governor::clock::DefaultClock>>>,
}

impl RateLimiters {
    pub fn new(global_rpm: u64, ip_rpm: u64, user_rpm: u64) -> Self {
        // Convert to NonZeroU32, defaulting to 1 if 0 or too large
        let global_rpm_u32 = NonZeroU32::new(global_rpm.min(u32::MAX as u64) as u32).unwrap_or(NonZeroU32::new(1).unwrap());
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
pub async fn build_state(
    api_config: ApiConfig,
    proxy_config: ProxyConfig,
    mitm_handler: Option<Arc<MitmHandler>>,
    filter_engine: FilterEngine,
    userscript_manager: Arc<UserscriptManager>,
    userscript_runtime: Arc<UserscriptRuntime>,
    config_path: PathBuf,
) -> ApiResult<Arc<AppState>> {
    // Initialize JWT config
    let jwt_config = Arc::new(JwtConfig {
        secret: load_or_generate_jwt_secret(&api_config.auth.jwt_secret_path).await?,
        access_token_expiry: api_config.auth.access_token_expiry_seconds,
        refresh_token_expiry: api_config.auth.refresh_token_expiry_seconds,
        issuer: api_config.auth.issuer.clone(),
        audience: api_config.auth.audience.clone(),
    });

    // Initialize session store
    let session_store = Arc::new(SessionStore::new(api_config.session.storage_path.clone())?);

    // Initialize rate limiters
    let rate_limiters = Arc::new(RateLimiters::new(
        api_config.rate_limit.global_requests_per_minute,
        api_config.rate_limit.ip_requests_per_minute,
        api_config.rate_limit.user_requests_per_minute,
    ));

    // Create proxy state
    let proxy_state = Arc::new(ProxyState {
        config: Arc::new(RwLock::new(proxy_config)),
        stats: Arc::new(ProxyStats::new()),
        mitm_handler,
    });

    // Get a cloneable stats handle from the filter engine
    // The FilterEngine itself cannot be stored in AppState because adblock::Engine is not Send/Sync
    let filter_stats = filter_engine.stats_handle();

    Ok(Arc::new(AppState {
        proxy_state,
        filter_stats,
        userscript_manager,
        userscript_runtime,
        session_store,
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

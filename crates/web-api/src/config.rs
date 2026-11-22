//! API configuration
//!
//! Configuration for the web API server including JWT settings, rate limits, and server settings.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// API server configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ApiConfig {
    /// Server settings
    pub server: ServerConfig,

    /// Authentication settings
    pub auth: AuthConfig,

    /// Rate limiting settings
    pub rate_limit: RateLimitConfig,

    /// Security settings
    pub security: SecurityConfig,

    /// Session storage settings
    pub session: SessionConfig,

    /// WebUI settings
    pub webui: WebUiConfig,

    /// Audit log retention.
    #[serde(default)]
    pub audit: AuditConfig,

    /// Client-address handling and auth-endpoint limits.
    #[serde(default)]
    pub network: NetworkConfig,
}

/// Audit log bounds: whichever limit is hit first prunes the oldest entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    pub max_entries: usize,
    pub retention_days: u32,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            max_entries: 10_000,
            retention_days: 90,
        }
    }
}

/// Network-facing settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Reverse proxies whose `X-Forwarded-For` / `X-Real-IP` headers are trusted. Empty means
    /// the socket peer address is always used.
    pub trusted_proxies: Vec<std::net::IpAddr>,
    /// Per-IP limit for login/register/refresh.
    pub auth_requests_per_minute: u32,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            trusted_proxies: Vec::new(),
            auth_requests_per_minute: 10,
        }
    }
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Host to bind to
    pub host: String,

    /// Port to listen on
    pub port: u16,

    /// Number of worker threads (0 = auto)
    pub workers: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 3000,
            workers: 0, // Auto-detect
        }
    }
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Path to JWT secret file
    pub jwt_secret_path: PathBuf,

    /// Access token expiry in seconds (1 hour)
    pub access_token_expiry_seconds: u64,

    /// Refresh token expiry in seconds (7 days)
    pub refresh_token_expiry_seconds: u64,

    /// bcrypt cost factor (higher = more secure but slower)
    pub bcrypt_cost: u32,

    /// JWT issuer
    pub issuer: String,

    /// JWT audience
    pub audience: String,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            jwt_secret_path: PathBuf::from("data/jwt_secret"),
            access_token_expiry_seconds: 3600,    // 1 hour
            refresh_token_expiry_seconds: 604800, // 7 days
            bcrypt_cost: 12,
            issuer: "adblocker-api".to_string(),
            audience: "adblocker-ui".to_string(),
        }
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Global requests per minute
    pub global_requests_per_minute: u64,

    /// Per-IP requests per minute
    pub ip_requests_per_minute: u64,

    /// Per-user requests per minute
    pub user_requests_per_minute: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            global_requests_per_minute: 10000,
            ip_requests_per_minute: 100,
            user_requests_per_minute: 1000,
        }
    }
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable CSRF protection
    pub enable_csrf: bool,

    /// Require HTTPS in production
    pub require_https: bool,

    /// Allowed CORS origins
    pub cors_origins: Vec<String>,

    /// Cookie secure flag
    pub cookie_secure: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_csrf: true,
            require_https: false,     // Development default
            cors_origins: Vec::new(), // same-origin only unless allowlisted
            cookie_secure: false,     // Development default
        }
    }
}

/// Session storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Directory holding `adblocker.redb` (the one database file shared by users, sessions,
    /// tokens, audit and userscripts)
    pub storage_path: PathBuf,

    /// Cleanup interval in seconds
    pub cleanup_interval_seconds: u64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            storage_path: PathBuf::from("data/sessions"),
            cleanup_interval_seconds: 3600, // 1 hour
        }
    }
}

/// WebUI configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebUiConfig {
    /// Enable serving WebUI static files
    pub enabled: bool,

    /// Path to WebUI dist directory
    pub dist_path: PathBuf,
}

impl Default for WebUiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dist_path: PathBuf::from("crates/web-ui/dist"),
        }
    }
}

impl ApiConfig {
    /// Load configuration from TOML file
    pub fn from_file(path: &str) -> crate::error::ApiResult<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: ApiConfig = toml::from_str(&content).map_err(|e| {
            crate::error::ApiError::Internal(format!("Failed to parse config: {}", e))
        })?;
        Ok(config)
    }

    /// Save configuration to TOML file
    pub fn to_file(&self, path: &str) -> crate::error::ApiResult<()> {
        let content = toml::to_string_pretty(self).map_err(|e| {
            crate::error::ApiError::Internal(format!("Failed to serialize config: {}", e))
        })?;
        std::fs::write(path, content)?;
        Ok(())
    }
}

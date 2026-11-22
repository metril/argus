//! Configuration types shared across crates

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub proxy: ProxySettings,
    pub mitm: MitmSettings,
    pub performance: PerformanceSettings,
    #[serde(default)]
    pub adblock: AdblockSettings,
    #[serde(default)]
    pub userscripts: UserscriptSettings,
    #[serde(default)]
    pub webui: WebUiSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxySettings {
    pub host: String,
    pub port: u16,
    pub enable_http2: bool,
    pub enable_http3: bool,
    pub enable_websockets: bool,
    /// Extra PEM root CA files trusted when connecting to upstream servers (in addition to the
    /// built-in web roots), e.g. a private/corporate CA.
    #[serde(default)]
    pub extra_upstream_ca_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitmSettings {
    pub enabled: bool,
    pub ca_cert_path: PathBuf,
    pub ca_key_path: PathBuf,
    pub cert_cache_size: usize,
    pub cert_ttl_days: u64,
    pub cert_idle_timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSettings {
    pub max_connections: usize,
    pub max_cert_generations: usize,
    pub max_html_buffers: usize,
    pub connection_timeout_secs: u64,
    pub request_timeout_secs: u64,
    #[serde(default)]
    pub connection_rate_limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdblockSettings {
    pub enabled: bool,
    pub data_dir: PathBuf,
    pub auto_update: bool,
    pub update_interval_hours: u64,
    /// URL of a uBO-compatible scriptlet/redirect resource library (JSON array of resources).
    /// Downloaded once and cached so `##+js(...)` scriptlet rules can inject. Empty disables it.
    #[serde(default = "default_scriptlet_resources_url")]
    pub scriptlet_resources_url: String,
}

fn default_scriptlet_resources_url() -> String {
    // uBlock Origin's scriptlet source directory (GitHub contents API). Every `.js` file is
    // downloaded, concatenated, and converted to adblock-rust resources at runtime. Fetched on the
    // user's machine (not vendored) since uBO's scriptlets are GPLv3.
    "https://api.github.com/repos/gorhill/uBlock/contents/src/js/resources".to_string()
}

impl Default for AdblockSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            data_dir: PathBuf::from("data/filters"),
            auto_update: true,
            update_interval_hours: 24,
            scriptlet_resources_url: default_scriptlet_resources_url(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserscriptSettings {
    pub enabled: bool,
    pub data_dir: PathBuf,
}

impl Default for UserscriptSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            data_dir: PathBuf::from("data/userscripts"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebUiSettings {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub jwt_secret_path: PathBuf,
    pub session_storage_path: PathBuf,
    pub cors_origins: Vec<String>,
    pub rate_limit_global_rpm: u64,
    pub rate_limit_ip_rpm: u64,
    pub rate_limit_user_rpm: u64,
}

impl Default for WebUiSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            host: "127.0.0.1".to_string(),
            port: 3000,
            jwt_secret_path: PathBuf::from("data/jwt_secret"),
            session_storage_path: PathBuf::from("data/sessions"),
            cors_origins: vec!["http://localhost:5173".to_string()],
            rate_limit_global_rpm: 10000,
            rate_limit_ip_rpm: 100,
            rate_limit_user_rpm: 1000,
        }
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            proxy: ProxySettings {
                host: "0.0.0.0".to_string(),
                port: 8080,
                enable_http2: true,
                enable_http3: false,
                enable_websockets: true,
                extra_upstream_ca_paths: Vec::new(),
            },
            mitm: MitmSettings {
                enabled: true,
                ca_cert_path: PathBuf::from("certs/root-ca.crt"),
                ca_key_path: PathBuf::from("certs/root-ca.key"),
                cert_cache_size: 1000,
                cert_ttl_days: 30,
                cert_idle_timeout_secs: 3600,
            },
            performance: PerformanceSettings {
                max_connections: 10000,
                max_cert_generations: 10,
                max_html_buffers: 200,
                connection_timeout_secs: 30,
                request_timeout_secs: 60,
                connection_rate_limit: Some(1000),
            },
            adblock: AdblockSettings::default(),
            userscripts: UserscriptSettings::default(),
            webui: WebUiSettings::default(),
        }
    }
}

impl ProxyConfig {
    /// Load configuration from a TOML file
    pub fn from_file(path: &str) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Io(format!("Failed to read config file: {}", e)))?;

        toml::from_str(&content)
            .map_err(|e| ConfigError::Parse(format!("Failed to parse config: {}", e)))
    }

    /// Save configuration to a TOML file
    pub fn to_file(&self, path: &str) -> Result<(), ConfigError> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| ConfigError::Serialize(format!("Failed to serialize config: {}", e)))?;

        std::fs::write(path, content)
            .map_err(|e| ConfigError::Io(format!("Failed to write config file: {}", e)))?;

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("I/O error: {0}")]
    Io(String),
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("Serialize error: {0}")]
    Serialize(String),
}

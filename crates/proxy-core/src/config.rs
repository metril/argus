//! Proxy configuration

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub proxy: ProxySettings,
    pub mitm: MitmSettings,
    pub performance: PerformanceSettings,
    #[serde(default)]
    pub adblock: AdblockSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxySettings {
    pub host: String,
    pub port: u16,
    pub max_connections: usize,
    pub enable_http2: bool,
    pub enable_http3: bool,
    pub enable_websockets: bool,
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
    pub max_cert_generations: usize,
    pub max_html_buffers: usize,
    pub connection_timeout_secs: u64,
    pub request_timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdblockSettings {
    pub enabled: bool,
    pub data_dir: PathBuf,
    pub auto_update: bool,
    pub update_interval_hours: u64,
}

impl Default for AdblockSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            data_dir: PathBuf::from("data/filters"),
            auto_update: true,
            update_interval_hours: 24,
        }
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            proxy: ProxySettings {
                host: "0.0.0.0".to_string(),
                port: 8080,
                max_connections: 10000,
                enable_http2: true,
                enable_http3: false,
                enable_websockets: true,
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
                max_cert_generations: 10,
                max_html_buffers: 200,
                connection_timeout_secs: 30,
                request_timeout_secs: 60,
            },
            adblock: AdblockSettings::default(),
        }
    }
}

impl ProxyConfig {
    /// Load configuration from a TOML file
    pub fn from_file(path: &str) -> crate::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| crate::Error::Config(format!("Failed to read config file: {}", e)))?;

        toml::from_str(&content)
            .map_err(|e| crate::Error::Config(format!("Failed to parse config: {}", e)))
    }

    /// Save configuration to a TOML file
    pub fn to_file(&self, path: &str) -> crate::Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| crate::Error::Config(format!("Failed to serialize config: {}", e)))?;

        std::fs::write(path, content)
            .map_err(|e| crate::Error::Config(format!("Failed to write config file: {}", e)))?;

        Ok(())
    }
}

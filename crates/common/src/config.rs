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
    pub script_control: ScriptControlSettings,
    #[serde(default)]
    pub webui: WebUiSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxySettings {
    pub host: String,
    pub port: u16,
    pub enable_http2: bool,
    /// Optional second listener for transparent-gateway mode (traffic redirected by the OS, no
    /// proxy configuration on the client). Off when unset. Linux only.
    #[serde(default)]
    pub transparent_port: Option<u16>,
    /// TLS hosts never intercepted (tunnelled opaquely) in both entry modes: exact names or
    /// `*.suffix` entries (the latter match subdomains only, not the apex).
    #[serde(default)]
    pub tls_passthrough_hosts: Vec<String>,
    /// Also refuse upstream destinations in private ranges (RFC 1918, ULA `fc00::/7`, CGNAT
    /// `100.64/10`). Loopback, link-local (cloud metadata), multicast and the proxy's own
    /// listeners are always refused.
    #[serde(default)]
    pub block_private_destinations: bool,
    /// CIDR exceptions that override the destination refusals (except loops onto the proxy's own
    /// listeners).
    #[serde(default)]
    pub allowed_destinations: Vec<String>,
    /// CIDRs of clients allowed to use the proxy (both listeners); others are closed at accept.
    /// Default: loopback, private, link-local, ULA and CGNAT sources. An empty list allows no one.
    #[serde(default = "default_allowed_clients")]
    pub allowed_clients: Vec<String>,
    pub enable_websockets: bool,
    /// Extra PEM root CA files trusted when connecting to upstream servers (in addition to the
    /// built-in web roots), e.g. a private/corporate CA.
    #[serde(default)]
    pub extra_upstream_ca_paths: Vec<PathBuf>,
    /// Explicit-proxy connections must present a known device token (`Proxy-Authorization:
    /// Basic`, password = token); others get `407`. Off: unknown devices fall back to their IP.
    #[serde(default)]
    pub require_device_token: bool,
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
    /// Max simultaneous filter-list downloads.
    #[serde(default = "default_list_fetch_concurrency")]
    pub list_fetch_concurrency: usize,
    /// Per-list download timeout in seconds.
    #[serde(default = "default_list_fetch_timeout_secs")]
    pub list_fetch_timeout_secs: u64,
    /// Maximum accepted size of a downloaded list, in bytes.
    #[serde(default = "default_max_list_bytes")]
    pub max_list_bytes: usize,
    /// Destinations the control plane (list, `!#include` and resource downloads) may fetch from
    /// although they are private: CIDRs / IPs, or host names (a listed name may resolve to
    /// private addresses). Private ranges are refused by default and loopback, link-local and
    /// other reserved addresses always (unless given as a CIDR/IP here).
    #[serde(default)]
    pub allowed_fetch_destinations: Vec<String>,
    /// Keep the query string of URLs in the recent-blocked list. Off by default: query strings
    /// often carry tokens, so they are stripped before storing.
    #[serde(default)]
    pub recent_blocked_keep_query: bool,
    /// Leave response bodies alone when the origin sends `Cache-Control: no-transform`
    /// (header-only edits still apply). Many CDNs set it on everything; turn this off to rewrite
    /// those pages anyway.
    #[serde(default = "default_true")]
    pub respect_no_transform: bool,
}

fn default_true() -> bool {
    true
}

/// Default client ACL: local and private networks only.
pub fn default_allowed_clients() -> Vec<String> {
    [
        "127.0.0.0/8",
        "::1/128",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "169.254.0.0/16",
        "fc00::/7",
        "fe80::/10",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn default_list_fetch_concurrency() -> usize {
    4
}

fn default_list_fetch_timeout_secs() -> u64 {
    30
}

fn default_max_list_bytes() -> usize {
    50 * 1024 * 1024
}

fn default_scriptlet_resources_url() -> String {
    // Raw-file base URL of uBlock Origin's scriptlet directory. A fixed list of files is fetched
    // from it, concatenated and converted to adblock-rust resources; a pinned snapshot is bundled
    // in the binary as the offline fallback and this copy replaces it when available.
    "https://raw.githubusercontent.com/gorhill/uBlock/master/src/js/resources".to_string()
}

impl Default for AdblockSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            data_dir: PathBuf::from("data/filters"),
            auto_update: true,
            update_interval_hours: 24,
            scriptlet_resources_url: default_scriptlet_resources_url(),
            list_fetch_concurrency: default_list_fetch_concurrency(),
            list_fetch_timeout_secs: default_list_fetch_timeout_secs(),
            max_list_bytes: default_max_list_bytes(),
            allowed_fetch_destinations: Vec::new(),
            recent_blocked_keep_query: false,
            respect_no_transform: true,
        }
    }
}

/// What the proxy does about service workers on sites that get userscripts. A service worker
/// sees every same-origin request of its pages, including the userscript bundles (and their
/// tokens) and GM responses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceWorkerPolicy {
    /// Do nothing: service workers work everywhere and can read what the page can.
    Allow,
    /// Refuse service-worker script fetches (registration fails) and unregister existing
    /// workers, on hosts where a userscript with network, download or cookie grants applies.
    #[default]
    BlockWhenPrivileged,
    /// Same, for every host the proxy filters.
    Block,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserscriptSettings {
    pub enabled: bool,
    /// Hours between scheduled update checks of scripts that have an update URL (0 = off).
    #[serde(default)]
    pub update_check_interval_hours: u64,
    /// Apply found updates automatically, only when they do not widen `@match`/`@connect`/`@grant`.
    #[serde(default)]
    pub auto_apply_updates: bool,
    /// `allow`, `block_when_privileged` (default) or `block`; see [`ServiceWorkerPolicy`].
    #[serde(default)]
    pub service_worker_policy: ServiceWorkerPolicy,
}

/// Script control (NoScript-style policy) and its in-page panel. The rules and the master switch
/// live in the database and the management API; these are deployment settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScriptControlSettings {
    /// Offer the in-page panel at all (each profile can also turn it off).
    pub panel_enabled: bool,
    /// Reserved host name the proxy answers itself for panel confirmations. It must never
    /// resolve on the real internet: keep a `.invalid` name.
    pub panel_host: String,
    /// Dashboard base URL the panel links to (empty: derived from the `webui` settings).
    pub dashboard_url: String,
}

impl Default for ScriptControlSettings {
    fn default() -> Self {
        Self {
            panel_enabled: true,
            panel_host: "adblock.invalid".into(),
            dashboard_url: String::new(),
        }
    }
}

/// When session cookies carry the `Secure` attribute.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CookieSecure {
    /// Only for requests that arrived over HTTPS, so plain-HTTP LAN access keeps working.
    #[default]
    Auto,
    Always,
    Never,
}

impl Serialize for CookieSecure {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(match self {
            CookieSecure::Auto => "auto",
            CookieSecure::Always => "always",
            CookieSecure::Never => "never",
        })
    }
}

impl<'de> Deserialize<'de> for CookieSecure {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Bool(bool),
            Str(String),
        }
        match Raw::deserialize(d)? {
            Raw::Bool(true) => Ok(CookieSecure::Always),
            Raw::Bool(false) => Ok(CookieSecure::Never),
            Raw::Str(s) => match s.to_ascii_lowercase().as_str() {
                "auto" => Ok(CookieSecure::Auto),
                "always" => Ok(CookieSecure::Always),
                "never" => Ok(CookieSecure::Never),
                other => Err(serde::de::Error::custom(format!(
                    "cookie_secure must be auto, always or never, not {other:?}"
                ))),
            },
        }
    }
}

impl CookieSecure {
    /// Whether to set `Secure` for a request that did (`https`) or did not arrive over HTTPS.
    pub fn applies(self, https: bool) -> bool {
        match self {
            CookieSecure::Auto => https,
            CookieSecure::Always => true,
            CookieSecure::Never => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebUiSettings {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub jwt_secret_path: PathBuf,
    pub cors_origins: Vec<String>,
    pub rate_limit_global_rpm: u64,
    pub rate_limit_ip_rpm: u64,
    pub rate_limit_user_rpm: u64,
    /// `Secure` flag on session cookies: `auto` (default; set when the request arrived over
    /// HTTPS through a trusted proxy), `always` or `never`.
    #[serde(default)]
    pub cookie_secure: CookieSecure,
    /// Reverse proxies (IP addresses) whose `X-Forwarded-For` / `X-Forwarded-Proto` headers are
    /// trusted. Empty: the socket peer is always used and requests count as plain HTTP.
    #[serde(default)]
    pub trusted_proxies: Vec<std::net::IpAddr>,
}

impl Default for WebUiSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            host: "127.0.0.1".to_string(),
            port: 3000,
            jwt_secret_path: PathBuf::from("data/jwt_secret"),
            cors_origins: vec!["http://localhost:5173".to_string()],
            rate_limit_global_rpm: 10000,
            rate_limit_ip_rpm: 100,
            rate_limit_user_rpm: 1000,
            cookie_secure: CookieSecure::Auto,
            trusted_proxies: Vec::new(),
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
                transparent_port: None,
                tls_passthrough_hosts: Vec::new(),
                block_private_destinations: false,
                allowed_destinations: Vec::new(),
                allowed_clients: default_allowed_clients(),
                enable_websockets: true,
                extra_upstream_ca_paths: Vec::new(),
                require_device_token: false,
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
            script_control: ScriptControlSettings::default(),
            webui: WebUiSettings::default(),
        }
    }
}

impl ProxyConfig {
    /// Load configuration from a TOML file
    pub fn from_file(path: &str) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Io(format!("Failed to read config file: {}", e)))?;

        Self::from_toml(&content)
    }

    /// Parse configuration from TOML text. Settings that no longer exist are an error, not
    /// silently ignored.
    pub fn from_toml(content: &str) -> Result<Self, ConfigError> {
        let parse = |e: toml::de::Error| ConfigError::Parse(format!("Failed to parse config: {e}"));
        let doc: toml::Table = content.parse().map_err(parse)?;
        for (section, key, hint) in REMOVED_SETTINGS {
            if doc.get(*section).and_then(|s| s.get(*key)).is_some() {
                return Err(ConfigError::Parse(format!(
                    "`[{section}] {key}` was removed: {hint}. Delete it from the config file."
                )));
            }
        }
        toml::from_str(content).map_err(parse)
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

/// Settings that used to exist: `(section, key, what replaced them)`.
const REMOVED_SETTINGS: &[(&str, &str, &str)] = &[
    (
        "userscripts",
        "data_dir",
        "userscripts are stored in `<adblock.data_dir>/adblocker.redb`",
    ),
    (
        "webui",
        "session_storage_path",
        "sessions are stored in `<adblock.data_dir>/adblocker.redb`",
    ),
];

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("I/O error: {0}")]
    Io(String),
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("Serialize error: {0}")]
    Serialize(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removed_settings_are_rejected_with_a_clear_message() {
        let base = toml::to_string(&ProxyConfig::default()).unwrap();
        assert!(ProxyConfig::from_toml(&base).is_ok());
        let bad = base.replace("[webui]", "[webui]\nsession_storage_path = \"x\"");
        let e = ProxyConfig::from_toml(&bad).unwrap_err().to_string();
        assert!(
            e.contains("session_storage_path") && e.contains("removed"),
            "{e}"
        );
        let bad = base.replace("[userscripts]", "[userscripts]\ndata_dir = \"x\"");
        assert!(ProxyConfig::from_toml(&bad)
            .unwrap_err()
            .to_string()
            .contains("data_dir"));
    }
}

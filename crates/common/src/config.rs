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
    #[serde(default)]
    pub dns: DnsSettings,
    /// Where the first-party bypass lists come from.
    #[serde(default)]
    pub bypass: BypassConfig,
}

/// First-party bypass lists (see `bypass`): normally left at the defaults. The overrides exist
/// for testing and for mirroring the lists internally.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BypassConfig {
    /// Base URL the `<id>.txt`, `<id>.txt.minisig`, `meta.json` and `meta.json.minisig` files are
    /// fetched from. Empty = the argus-lists GitHub release.
    #[serde(default)]
    pub lists_base_url: String,
    /// Minisign public key (base64 line) the lists must be signed with. Empty = the key
    /// compiled into the binary.
    #[serde(default)]
    pub lists_public_key: String,
}

/// Upstream DNS resolution and caching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsSettings {
    /// Resolver addresses (`ip` or `ip:port`, UDP with TCP fallback). Empty uses the system
    /// resolver configuration (`/etc/resolv.conf`).
    #[serde(default)]
    pub servers: Vec<String>,
    /// Maximum cached names.
    #[serde(default = "default_dns_cache_size")]
    pub cache_size: u64,
    /// Lower clamp on cached TTLs, seconds.
    #[serde(default = "default_dns_min_ttl")]
    pub min_ttl_secs: u64,
    /// Upper clamp on cached TTLs, seconds.
    #[serde(default = "default_dns_max_ttl")]
    pub max_ttl_secs: u64,
    /// How long failed lookups (NXDOMAIN, errors) are cached, seconds.
    #[serde(default = "default_dns_negative_ttl")]
    pub negative_ttl_secs: u64,
}

fn default_dns_cache_size() -> u64 {
    4096
}
fn default_dns_min_ttl() -> u64 {
    10
}
fn default_dns_max_ttl() -> u64 {
    300
}
fn default_dns_negative_ttl() -> u64 {
    10
}

impl DnsSettings {
    /// Check the values a user can set: servers are `ip` or `ip:port`, the cache holds at least
    /// one name, and `min_ttl_secs <= max_ttl_secs`.
    pub fn validate(&self) -> Result<(), String> {
        for s in &self.servers {
            let ok =
                s.parse::<std::net::SocketAddr>().is_ok() || s.parse::<std::net::IpAddr>().is_ok();
            if !ok {
                return Err(format!(
                    "dns.servers: {s:?} is not an IP address or ip:port"
                ));
            }
        }
        if self.cache_size == 0 || self.cache_size > 10_000_000 {
            return Err("dns.cache_size must be between 1 and 10000000".into());
        }
        if self.min_ttl_secs > self.max_ttl_secs {
            return Err("dns.min_ttl_secs must not exceed dns.max_ttl_secs".into());
        }
        if self.max_ttl_secs > 7 * 86_400 || self.negative_ttl_secs > 86_400 {
            return Err(
                "dns: max_ttl_secs is limited to 7 days and negative_ttl_secs to 1 day".into(),
            );
        }
        Ok(())
    }
}

impl Default for DnsSettings {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            cache_size: default_dns_cache_size(),
            min_ttl_secs: default_dns_min_ttl(),
            max_ttl_secs: default_dns_max_ttl(),
            negative_ttl_secs: default_dns_negative_ttl(),
        }
    }
}

/// Per-listener switches; `None` inherits the global setting.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerOverrides {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_mitm: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_http2: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_websockets: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_adblock: Option<bool>,
}

/// A listener's effective switches (override, else the global value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListenerFlagValues {
    pub mitm: bool,
    pub http2: bool,
    pub websockets: bool,
    pub adblock: bool,
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
    /// Optional listener for the Argus browser extension (proxy authentication binds a browser to
    /// its extension session; see `docs/USERSCRIPT-PROTOCOL.md` section 8). Off when unset. It
    /// answers `407` to anything without the extension's credentials; bound to `proxy.host`.
    #[serde(default)]
    pub ext_port: Option<u16>,
    /// Settings of the explicit-proxy listener (`[proxy.explicit]`). A key left out falls back
    /// to the global setting (`mitm.enabled`, `proxy.enable_http2`, `proxy.enable_websockets`,
    /// `adblock.enabled`).
    #[serde(default)]
    pub explicit: ListenerOverrides,
    /// Settings of the transparent listener (`[proxy.transparent]`); same fallbacks.
    #[serde(default)]
    pub transparent: ListenerOverrides,
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
    /// Concurrent connection cap; 0 derives it from the soft file-descriptor limit.
    pub max_connections: usize,
    pub max_cert_generations: usize,
    pub max_html_buffers: usize,
    pub connection_timeout_secs: u64,
    pub request_timeout_secs: u64,
    /// New connections admitted per second. A missing key means [`DEFAULT_CONNECTION_RATE_LIMIT`];
    /// unlimited must be asked for explicitly with `0`.
    #[serde(default = "default_connection_rate_limit")]
    pub connection_rate_limit: Option<u32>,
}

/// Default for `performance.connection_rate_limit` (connections per second).
pub const DEFAULT_CONNECTION_RATE_LIMIT: u32 = 10_000;

fn default_connection_rate_limit() -> Option<u32> {
    Some(DEFAULT_CONNECTION_RATE_LIMIT)
}

impl PerformanceSettings {
    /// The admission rate in connections per second; `0` is unlimited. `None` (only possible
    /// when built in code) means the default, never unlimited.
    pub fn effective_connection_rate_limit(&self) -> u32 {
        self.connection_rate_limit
            .unwrap_or(DEFAULT_CONNECTION_RATE_LIMIT)
    }
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
    /// Threads of the dedicated list-build pool (parse, convert, compile). 0 = half the cores, at
    /// least 1. A rebuild runs at low priority on these threads so it does not take the cores the
    /// proxy workers need. A 100k-rule rebuild takes about the same (about 240 ms) with 1, 2 or 4
    /// threads, so lowering this costs little build time.
    #[serde(default)]
    pub build_threads: usize,
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
            build_threads: 0,
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
    /// Built-in HTTPS for the web UI.
    #[serde(default)]
    pub tls: WebUiTls,
}

/// Where the web UI's TLS certificate comes from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
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

/// Built-in HTTPS for the web UI. Uploaded PEM files live under `<data_dir>/webui-tls/` and are
/// never part of the configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WebUiTls {
    pub mode: WebUiTlsMode,
    /// Host names and IP addresses the Argus CA certificate is issued for.
    pub sans: Vec<String>,
    /// Answer plain-HTTP requests on the same port with a redirect to HTTPS.
    pub redirect_http: bool,
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
            tls: WebUiTls::default(),
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
                ext_port: None,
                explicit: ListenerOverrides::default(),
                transparent: ListenerOverrides::default(),
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
                max_connections: 0,
                max_cert_generations: 10,
                max_html_buffers: 200,
                connection_timeout_secs: 30,
                request_timeout_secs: 60,
                connection_rate_limit: Some(10_000),
            },
            adblock: AdblockSettings::default(),
            userscripts: UserscriptSettings::default(),
            script_control: ScriptControlSettings::default(),
            webui: WebUiSettings::default(),
            dns: DnsSettings::default(),
            bypass: BypassConfig::default(),
        }
    }
}

impl ProxyConfig {
    /// Effective switches of the transparent (`true`) or explicit (`false`) listener.
    pub fn listener_flags(&self, transparent: bool) -> ListenerFlagValues {
        let o = if transparent {
            &self.proxy.transparent
        } else {
            &self.proxy.explicit
        };
        ListenerFlagValues {
            mitm: o.enable_mitm.unwrap_or(self.mitm.enabled),
            http2: o.enable_http2.unwrap_or(self.proxy.enable_http2),
            websockets: o.enable_websockets.unwrap_or(self.proxy.enable_websockets),
            // `adblock.enabled` stays the engine's master switch; a listener is on unless it opts out.
            adblock: o.enable_adblock.unwrap_or(true),
        }
    }

    /// Whether any listener wants this feature (what must be set up at startup).
    pub fn any_listener(&self, f: impl Fn(ListenerFlagValues) -> bool) -> bool {
        f(self.listener_flags(false)) || f(self.listener_flags(true))
    }

    /// Load configuration from a TOML file
    pub fn from_file(path: &str) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Io(format!("Failed to read config file: {}", e)))?;

        Self::from_toml(&content)
    }

    /// Load the base file (read-only in containers), then lay the settings overlay on top. A
    /// missing overlay is fine; a broken one is an error naming it.
    pub fn load_layered(
        base: &std::path::Path,
        overlay: &std::path::Path,
    ) -> Result<Self, ConfigError> {
        let mut table = read_table(base)?.ok_or_else(|| {
            ConfigError::Io(format!(
                "Failed to read config file: {} not found",
                base.display()
            ))
        })?;
        if let Some(over) = read_table(overlay)? {
            merge_tables(&mut table, over);
        }
        Self::from_toml(&table.to_string())
    }

    /// Persist the settings that differ from the base file to `overlay`, atomically (temp file
    /// in the same directory, then rename). The base file is never written.
    pub fn save_overlay(
        &self,
        base: &std::path::Path,
        overlay: &std::path::Path,
    ) -> Result<(), ConfigError> {
        let new = toml::Table::try_from(self)
            .map_err(|e| ConfigError::Serialize(format!("Failed to serialize config: {e}")))?;
        // The base *as the proxy reads it* (file values plus the built-in defaults of keys the
        // file leaves out), so unchanged settings are not written just because the file omits
        // them.
        let base_effective = std::fs::read_to_string(base)
            .ok()
            .and_then(|t| Self::from_toml(&t).ok())
            .unwrap_or_default();
        let base_cfg = toml::Table::try_from(&base_effective)
            .map_err(|e| ConfigError::Serialize(e.to_string()))?;
        let mut diff = diff_tables(&base_cfg, &new);
        // An unset option has no TOML spelling: `0` is how the overlay switches it off.
        let had = base_effective.proxy.transparent_port.is_some();
        if had && self.proxy.transparent_port.is_none() {
            diff.entry("proxy")
                .or_insert_with(|| toml::Value::Table(Default::default()))
                .as_table_mut()
                .expect("table")
                .insert("transparent_port".into(), toml::Value::Integer(0));
        }
        if base_effective.proxy.ext_port.is_some() && self.proxy.ext_port.is_none() {
            diff.entry("proxy")
                .or_insert_with(|| toml::Value::Table(Default::default()))
                .as_table_mut()
                .expect("table")
                .insert("ext_port".into(), toml::Value::Integer(0));
        }
        let text = format!(
            "# Settings saved from the web UI; they override the base config file.\n{}",
            toml::to_string_pretty(&diff).map_err(|e| ConfigError::Serialize(e.to_string()))?
        );
        write_atomic(overlay, text.as_bytes())
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
        let mut cfg: Self = toml::from_str(content).map_err(parse)?;
        // `0` means off (the overlay's spelling of "unset").
        if cfg.proxy.transparent_port == Some(0) {
            cfg.proxy.transparent_port = None;
        }
        if cfg.proxy.ext_port == Some(0) {
            cfg.proxy.ext_port = None;
        }
        Ok(cfg)
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

/// Where UI-saved settings live: `CONFIG_OVERLAY_PATH`, else `<data_dir>/settings.toml`.
pub fn default_overlay_path(data_dir: &std::path::Path) -> PathBuf {
    match std::env::var_os("CONFIG_OVERLAY_PATH") {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => data_dir.join("settings.toml"),
    }
}

fn read_table(path: &std::path::Path) -> Result<Option<toml::Table>, ConfigError> {
    match std::fs::read_to_string(path) {
        Ok(t) => t
            .parse::<toml::Table>()
            .map(Some)
            .map_err(|e| ConfigError::Parse(format!("Failed to parse {}: {e}", path.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(ConfigError::Io(format!(
            "Failed to read {}: {e}",
            path.display()
        ))),
    }
}

/// `over` wins; tables merge key by key, everything else is replaced.
fn merge_tables(base: &mut toml::Table, over: toml::Table) {
    for (k, v) in over {
        match (base.get_mut(&k), v) {
            (Some(toml::Value::Table(b)), toml::Value::Table(o)) => merge_tables(b, o),
            (_, v) => {
                base.insert(k, v);
            }
        }
    }
}

/// The entries of `new` that differ from `base`.
fn diff_tables(base: &toml::Table, new: &toml::Table) -> toml::Table {
    let mut out = toml::Table::new();
    for (k, v) in new {
        match (base.get(k), v) {
            (Some(toml::Value::Table(b)), toml::Value::Table(n)) => {
                let d = diff_tables(b, n);
                if !d.is_empty() {
                    out.insert(k.clone(), toml::Value::Table(d));
                }
            }
            (Some(b), v) if b == v => {}
            (_, v) => {
                out.insert(k.clone(), v.clone());
            }
        }
    }
    out
}

/// Write `bytes` to `path` via a temp file in the same directory and a rename.
pub fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> Result<(), ConfigError> {
    use std::io::Write;
    let io = |what: &str, e: std::io::Error| {
        ConfigError::Io(format!("Failed to {what} {}: {e}", path.display()))
    };
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    std::fs::create_dir_all(dir).map_err(|e| io("create the directory of", e))?;
    // Unique per call: the pid alone is 1 in every container, so two writers would share it.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let tmp = path.with_extension(format!(
        "tmp{}-{}-{nanos}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let result = (|| {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if let Err(e) = result {
        let _ = std::fs::remove_file(&tmp);
        return Err(io("write", e));
    }
    Ok(())
}

/// Settings that used to exist: `(section, key, what replaced them)`.
const REMOVED_SETTINGS: &[(&str, &str, &str)] = &[
    (
        "userscripts",
        "data_dir",
        "userscripts are stored in `<adblock.data_dir>/argus.redb`",
    ),
    (
        "webui",
        "session_storage_path",
        "sessions are stored in `<adblock.data_dir>/argus.redb`",
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

/// Descriptors budgeted per proxied connection: the client socket, its upstream socket and one
/// idle pooled upstream socket.
pub const FDS_PER_CONNECTION: u64 = 3;
/// Fixed descriptors set aside for listeners, files, the database and the control plane.
pub const FD_RESERVE: u64 = 512;
const MAX_CONNECTIONS_CAP: usize = 100_000;
const MAX_CONNECTIONS_FLOOR: usize = 16;

/// Connection cap for a descriptor limit (`u64::MAX` = unlimited): [`FDS_PER_CONNECTION`] per
/// connection after [`FD_RESERVE`], so clients + upstreams + idle pool stay within the limit.
pub fn max_connections_for_limit(limit: u64) -> usize {
    let usable = limit.saturating_sub(FD_RESERVE) / FDS_PER_CONNECTION;
    usize::try_from(usable)
        .unwrap_or(usize::MAX)
        .clamp(MAX_CONNECTIONS_FLOOR, MAX_CONNECTIONS_CAP)
}

/// Idle upstream connections kept per origin, scaled down when descriptors are scarce so the
/// pool's share of the budget (one descriptor per connection slot) stays small.
pub fn pool_idle_per_host(max_connections: usize) -> usize {
    (max_connections / 16).clamp(1, 32)
}

/// Raise the soft `RLIMIT_NOFILE` to the hard limit (once per process) and return the limit now
/// in force; `u64::MAX` means unlimited. `None` when it cannot be read.
pub fn raise_nofile_limit() -> Option<u64> {
    static LIMIT: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    *LIMIT.get_or_init(raise_nofile_limit_once)
}

#[cfg(unix)]
fn raise_nofile_limit_once() -> Option<u64> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes into the provided struct.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
        return None;
    }
    if lim.rlim_cur < lim.rlim_max {
        let want = libc::rlimit {
            rlim_cur: lim.rlim_max,
            rlim_max: lim.rlim_max,
        };
        // SAFETY: setrlimit only reads the provided struct.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &want) } == 0 {
            lim.rlim_cur = lim.rlim_max;
        }
        // On failure (some platforms reject an infinite or oversized value) the soft limit
        // stays as it was and is what gets budgeted.
    }
    #[allow(clippy::unnecessary_cast)] // rlim_t differs per platform
    let (cur, infinity) = (lim.rlim_cur as u64, libc::RLIM_INFINITY as u64);
    Some(if cur == infinity { u64::MAX } else { cur })
}

#[cfg(not(unix))]
fn raise_nofile_limit_once() -> Option<u64> {
    None
}

/// Connection cap derived from the (raised) soft `RLIMIT_NOFILE`.
pub fn derive_max_connections() -> usize {
    raise_nofile_limit().map_or(10_000, max_connections_for_limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_config_without_listener_tables_loads_and_falls_back_to_globals() {
        let mut c = ProxyConfig::default();
        c.proxy.enable_http2 = false;
        c.adblock.enabled = true;
        // The legacy shape has no `[proxy.explicit]` / `[proxy.transparent]` tables at all.
        let text = toml::to_string_pretty(&c)
            .unwrap()
            .replace("[proxy.explicit]\n", "")
            .replace("[proxy.transparent]\n", "");
        assert!(!text.contains("[proxy.explicit]") && !text.contains("[proxy.transparent]"));
        let back = ProxyConfig::from_toml(&text).unwrap();
        for t in [false, true] {
            let f = back.listener_flags(t);
            assert_eq!(
                (f.mitm, f.http2, f.websockets, f.adblock),
                (true, false, true, true),
                "transparent={t}"
            );
        }
    }

    #[test]
    fn listener_tables_override_the_globals_per_listener() {
        let mut c = ProxyConfig::default();
        c.adblock.enabled = true;
        c.proxy.transparent.enable_adblock = Some(false);
        c.proxy.explicit.enable_http2 = Some(false);
        let text = toml::to_string_pretty(&c).unwrap();
        let back = ProxyConfig::from_toml(&text).unwrap();
        let (e, t) = (back.listener_flags(false), back.listener_flags(true));
        assert!(e.adblock && !t.adblock, "adblock off on transparent only");
        assert!(!e.http2 && t.http2, "http2 off on explicit only");
        assert!(back.any_listener(|f| f.adblock));
        assert!(back.proxy.explicit.enable_mitm.is_none());
    }

    fn base_text() -> String {
        let mut c = ProxyConfig::default();
        c.proxy.transparent_port = Some(3129);
        toml::to_string_pretty(&c).unwrap()
    }

    fn layer_dir() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let (b, o) = (
            d.path().join("default.toml"),
            d.path().join("data/settings.toml"),
        );
        std::fs::write(&b, base_text()).unwrap();
        (d, b, o)
    }

    #[test]
    fn overlay_merges_over_base_and_missing_overlay_is_fine() {
        let (_d, b, o) = layer_dir();
        assert_eq!(ProxyConfig::load_layered(&b, &o).unwrap().proxy.port, 8080);
        std::fs::create_dir_all(o.parent().unwrap()).unwrap();
        std::fs::write(&o, "[proxy]\nport = 9090\n").unwrap();
        let c = ProxyConfig::load_layered(&b, &o).unwrap();
        assert_eq!(
            (c.proxy.port, c.proxy.transparent_port, c.proxy.enable_http2),
            (9090, Some(3129), true)
        );
        std::fs::write(&o, "[proxy\nport").unwrap();
        let e = ProxyConfig::load_layered(&b, &o).unwrap_err().to_string();
        assert!(e.contains("settings.toml"), "{e}");
    }

    #[test]
    fn save_overlay_writes_only_differences_atomically_and_round_trips() {
        let (_d, b, o) = layer_dir();
        let mut c = ProxyConfig::load_layered(&b, &o).unwrap();
        c.proxy.port = 9191;
        c.proxy.transparent_port = None;
        c.proxy.tls_passthrough_hosts = vec!["bank.test".into()];
        c.save_overlay(&b, &o).unwrap();
        let text = std::fs::read_to_string(&o).unwrap();
        assert!(
            text.contains("port = 9191") && !text.contains("enable_http2"),
            "{text}"
        );
        assert_eq!(
            std::fs::read_to_string(&b).unwrap(),
            base_text(),
            "base is never written"
        );
        // No temp files left behind.
        let left: Vec<_> = std::fs::read_dir(o.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(left, ["settings.toml"]);
        let back = ProxyConfig::load_layered(&b, &o).unwrap();
        assert_eq!(back.proxy.port, 9191);
        assert_eq!(
            back.proxy.transparent_port, None,
            "0 in the overlay means off"
        );
        assert_eq!(back.proxy.tls_passthrough_hosts, ["bank.test"]);
    }

    #[test]
    fn overlay_holds_only_values_that_differ_even_when_the_base_file_omits_keys() {
        let d = tempfile::tempdir().unwrap();
        let (b, o) = (
            d.path().join("default.toml"),
            d.path().join("settings.toml"),
        );
        // A sparse base: most keys are left to the built-in defaults.
        std::fs::write(
            &b,
            toml::to_string_pretty(&ProxyConfig::default())
                .unwrap()
                .lines()
                .filter(|l| !l.starts_with("list_fetch") && !l.starts_with("max_list_bytes"))
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .unwrap();
        let mut c = ProxyConfig::load_layered(&b, &o).unwrap();
        c.performance.request_timeout_secs = 77;
        c.save_overlay(&b, &o).unwrap();
        let text = std::fs::read_to_string(&o).unwrap();
        assert!(text.contains("request_timeout_secs = 77"), "{text}");
        for unchanged in [
            "list_fetch",
            "max_list_bytes",
            "[dns]",
            "[userscripts]",
            "extra_upstream_ca_paths",
            "require_device_token",
        ] {
            assert!(
                !text.contains(unchanged),
                "{unchanged} written though unchanged:\n{text}"
            );
        }
        // Setting a value back to the default drops it from the overlay again.
        c.performance.request_timeout_secs =
            ProxyConfig::load_layered(&b, std::path::Path::new("/nonexistent"))
                .unwrap()
                .performance
                .request_timeout_secs;
        c.save_overlay(&b, &o).unwrap();
        assert!(!std::fs::read_to_string(&o)
            .unwrap()
            .contains("request_timeout_secs"));
    }

    #[test]
    fn save_overlay_failure_leaves_the_old_overlay_intact() {
        let (_d, b, o) = layer_dir();
        let c = ProxyConfig::load_layered(&b, &o).unwrap();
        c.save_overlay(&b, &o).unwrap();
        // A directory where the file should go makes the rename fail.
        let blocked = o.parent().unwrap().join("dir.toml");
        std::fs::create_dir(&blocked).unwrap();
        assert!(c.save_overlay(&b, &blocked).is_err());
        assert!(o.exists());
    }

    #[test]
    fn descriptor_budget_for_soft_limits() {
        // 1024: (1024 - 512) / 3
        assert_eq!(max_connections_for_limit(1024), 170);
        assert_eq!(max_connections_for_limit(65_536), 21_674);
        assert_eq!(max_connections_for_limit(u64::MAX), 100_000);
        for limit in [1024u64, 4096, 65_536, 1_048_576] {
            let n = max_connections_for_limit(limit) as u64;
            assert!(
                n * FDS_PER_CONNECTION + FD_RESERVE <= limit,
                "{limit}: {n} connections overflow the limit"
            );
        }
        assert_eq!(pool_idle_per_host(170), 10);
        assert_eq!(pool_idle_per_host(100_000), 32);
        assert_eq!(pool_idle_per_host(1), 1);
    }

    #[test]
    fn raising_the_limit_reaches_the_hard_limit() {
        let now = raise_nofile_limit().unwrap();
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit writes into the provided struct.
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) }, 0);
        // Either the soft limit equals the hard one, or raising was refused and it is unchanged.
        #[allow(clippy::unnecessary_cast)] // rlim_t differs per platform
        let soft = lim.rlim_cur as u64;
        assert!(now >= soft || now == u64::MAX);
    }

    #[test]
    fn missing_rate_limit_is_the_default_and_zero_is_explicit_unlimited() {
        let base = toml::to_string(&ProxyConfig::default()).unwrap();
        let without: String = base
            .lines()
            .filter(|l| !l.starts_with("connection_rate_limit"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!without.contains("connection_rate_limit"));
        let c = ProxyConfig::from_toml(&without).unwrap();
        assert_eq!(c.performance.effective_connection_rate_limit(), 10_000);
        let zero = base
            .lines()
            .map(|l| {
                if l.starts_with("connection_rate_limit") {
                    "connection_rate_limit = 0"
                } else {
                    l
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        let c = ProxyConfig::from_toml(&zero).unwrap();
        assert_eq!(c.performance.effective_connection_rate_limit(), 0);
    }

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

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
    /// Stealth Mode: privacy edits to requests, responses and pages.
    #[serde(default)]
    pub stealth: StealthSettings,
}

fn on() -> bool {
    true
}

/// Stealth Mode (AdGuard parity). The master switch is off by default; once it is on, each option
/// follows its own switch, whose defaults are AdGuard's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StealthSettings {
    #[serde(default)]
    pub enabled: bool,
    // General.
    /// Hide the search query: a click from a search engine's results sends no query to the site.
    #[serde(default = "on")]
    pub hide_search_queries: bool,
    /// Send `DNT: 1` and `Sec-GPC: 1`, and set `navigator.doNotTrack` / `globalPrivacyControl`.
    #[serde(default = "on")]
    pub send_dnt: bool,
    /// Remove tracking parameters (`utm_*`, `fbclid`, `gclid`, ...) from URLs.
    #[serde(default)]
    pub strip_tracking_params: bool,
    /// Hide the Referer from third parties (replaced by `referer_custom`, else the target's own
    /// origin).
    #[serde(default = "on")]
    pub hide_referer: bool,
    #[serde(default)]
    pub referer_custom: String,
    /// Reduce the User-Agent to a generic one of the same browser family.
    #[serde(default)]
    pub hide_user_agent: bool,
    #[serde(default)]
    pub user_agent_custom: String,
    /// Send `X-Forwarded-For: <mask_ip_address>`.
    #[serde(default)]
    pub mask_ip: bool,
    #[serde(default)]
    pub mask_ip_address: String,
    /// Remove Chrome's `X-Client-Data` header.
    #[serde(default = "on")]
    pub remove_x_client_data: bool,
    // Tracking methods.
    /// Self-destruct third-party cookies after `third_party_cookie_minutes` (0 blocks them).
    #[serde(default = "on")]
    pub third_party_cookies: bool,
    #[serde(default = "default_3p_cookie_minutes")]
    pub third_party_cookie_minutes: u32,
    /// Self-destruct first-party cookies after `first_party_cookie_minutes` (0 blocks them).
    #[serde(default)]
    pub first_party_cookies: bool,
    #[serde(default = "default_1p_cookie_minutes")]
    pub first_party_cookie_minutes: u32,
    /// Strip ETag / If-None-Match on third-party requests.
    #[serde(default = "on")]
    pub block_etag: bool,
    /// Drop the Authorization header on third-party requests.
    #[serde(default)]
    pub block_third_party_auth: bool,
    // Browser API.
    #[serde(default)]
    pub block_webrtc: bool,
    #[serde(default)]
    pub block_push: bool,
    #[serde(default)]
    pub block_location: bool,
    /// No effect: browsers no longer run Flash.
    #[serde(default = "on")]
    pub block_flash: bool,
    /// Makes `navigator.javaEnabled()` false; browsers no longer run Java applets.
    #[serde(default = "on")]
    pub block_java: bool,
}

fn default_3p_cookie_minutes() -> u32 {
    2880
}

fn default_1p_cookie_minutes() -> u32 {
    4320
}

impl Default for StealthSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            hide_search_queries: true,
            send_dnt: true,
            strip_tracking_params: false,
            hide_referer: true,
            referer_custom: String::new(),
            hide_user_agent: false,
            user_agent_custom: String::new(),
            mask_ip: false,
            mask_ip_address: String::new(),
            remove_x_client_data: true,
            third_party_cookies: true,
            third_party_cookie_minutes: default_3p_cookie_minutes(),
            first_party_cookies: false,
            first_party_cookie_minutes: default_1p_cookie_minutes(),
            block_etag: true,
            block_third_party_auth: false,
            block_webrtc: false,
            block_push: false,
            block_location: false,
            block_flash: true,
            block_java: true,
        }
    }
}

/// Whether a User-Agent names a browser family the upstream emulation can mirror (the same
/// families `proxy_core::browser_profile` recognises).
pub fn ua_family_known(ua: &str) -> bool {
    ["Firefox/", "FxiOS/", "CriOS/", "Chrome/", "Edg/"]
        .iter()
        .any(|m| ua.contains(m))
        || (ua.contains("Safari/") && ua.contains("Version/"))
}

impl StealthSettings {
    /// Reject values that cannot be applied.
    pub fn validate(&self) -> Result<(), String> {
        if !self.mask_ip_address.is_empty()
            && self.mask_ip_address.parse::<std::net::IpAddr>().is_err()
        {
            return Err("mask_ip_address must be an IP address".into());
        }
        for (n, v) in [
            ("referer_custom", &self.referer_custom),
            ("user_agent_custom", &self.user_agent_custom),
        ] {
            if v.len() > 1024 || v.bytes().any(|b| b < 0x20 || b == 0x7f) {
                return Err(format!("{n} is not a valid header value"));
            }
        }
        if !self.user_agent_custom.is_empty() && !ua_family_known(&self.user_agent_custom) {
            return Err(
                "user_agent_custom must be a Chrome, Edge, Firefox or Safari User-Agent".into(),
            );
        }
        if !self.referer_custom.is_empty() && url::Url::parse(&self.referer_custom).is_err() {
            return Err("referer_custom must be a URL".into());
        }
        Ok(())
    }
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

/// How queries are spread over the upstream servers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsMode {
    /// One upstream per query, picked at random weighted by measured speed (the default).
    #[default]
    LoadBalance,
    /// Ask every upstream at once; the first answer wins.
    Parallel,
    /// Ask every upstream, then race connections to the returned addresses; fastest first.
    FastestIp,
}

/// EDNS Client Subnet (RFC 7871) behaviour.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsEcs {
    /// Send none.
    #[default]
    Off,
    /// The proxy host's own public address, truncated to /24 (IPv4) or /56 (IPv6). Sent only
    /// when that address is public.
    Auto,
    /// The subnet in `ecs_subnet`.
    Custom,
}

/// Upstream DNS resolution and caching (what Argus uses to resolve names for its own upstream
/// connections; it is not a DNS server).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsSettings {
    /// Upstream resolvers, one AdGuard-syntax line each: `1.1.1.1`, `tls://dns.google`,
    /// `https://dns.google/dns-query`, `h3://...`, `quic://...`, `sdns://...`, and per-domain
    /// `[/example.com/]10.0.0.1` (`[/lan/]#` = the default upstreams). Empty uses the system
    /// resolver configuration (`/etc/resolv.conf`).
    #[serde(default)]
    pub servers: Vec<String>,
    /// Optional file path or http(s) URL holding more upstream lines (read on every apply).
    #[serde(default)]
    pub upstreams_source: String,
    /// How queries are spread over the upstreams.
    #[serde(default)]
    pub mode: DnsMode,
    /// Plain-IP resolvers used only to resolve the host names of encrypted upstreams. Empty
    /// uses the system resolver for that.
    #[serde(default)]
    pub bootstrap: Vec<String>,
    /// Used only when every upstream fails. Empty: the lookup fails.
    #[serde(default)]
    pub fallback: Vec<String>,
    /// Send PTR lookups and LAN names (`.lan`, `.local`, RFC 1918 reverse zones...) to the
    /// private resolvers instead of the upstreams.
    #[serde(default = "default_true")]
    pub private_rdns: bool,
    /// Resolvers for those names (plain IPs). Empty uses the system resolver.
    #[serde(default)]
    pub private_resolvers: Vec<String>,
    /// Maximum cached names.
    #[serde(default = "default_dns_cache_size")]
    pub cache_size: u64,
    /// Lower clamp on cached TTLs, seconds.
    #[serde(default = "default_dns_min_ttl")]
    pub min_ttl_secs: u64,
    /// Upper clamp on cached TTLs, seconds.
    #[serde(default = "default_dns_max_ttl")]
    pub max_ttl_secs: u64,
    /// How long failed lookups (NXDOMAIN, no addresses) are cached, seconds.
    #[serde(default = "default_dns_negative_ttl")]
    pub negative_ttl_secs: u64,
    /// Serve an expired cached answer at once and refresh it in the background.
    #[serde(default)]
    pub optimistic_cache: bool,
    /// Validate DNSSEC; answers that fail validation are refused.
    #[serde(default)]
    pub dnssec: bool,
    /// Resolve AAAA records. Off: only IPv4 addresses are used.
    #[serde(default = "default_true")]
    pub ipv6: bool,
    /// EDNS Client Subnet.
    #[serde(default)]
    pub ecs: DnsEcs,
    /// Subnet for `ecs = "custom"`, e.g. `203.0.113.0/24`.
    #[serde(default)]
    pub ecs_subnet: String,
    /// Per-upstream query timeout, milliseconds.
    #[serde(default = "default_dns_timeout_ms")]
    pub timeout_ms: u64,
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
fn default_dns_timeout_ms() -> u64 {
    5000
}

/// `ip/prefix` as used by `dns.ecs_subnet`.
pub fn parse_ecs_subnet(s: &str) -> Result<(std::net::IpAddr, u8), String> {
    let (ip, len) = s
        .trim()
        .split_once('/')
        .ok_or("expected a subnet like 203.0.113.0/24")?;
    let ip: std::net::IpAddr = ip.parse().map_err(|_| "invalid subnet address")?;
    let len: u8 = len.parse().map_err(|_| "invalid prefix length")?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    if len == 0 || len > max {
        return Err(format!("prefix length must be 1..={max}"));
    }
    Ok((ip, len))
}

/// Only the line number: the text may come from a file and must not be echoed back.
fn fmt_errs(what: &str, errs: Vec<(usize, String)>) -> String {
    format!("{what}, line {}: not valid", errs[0].0)
}

impl DnsSettings {
    /// Check the values a user can set: every list line parses, the cache holds at least one
    /// name, and `min_ttl_secs <= max_ttl_secs`.
    pub fn validate(&self) -> Result<(), String> {
        dns_syntax::parse_upstreams(&self.servers).map_err(|e| fmt_errs("dns.servers", e))?;
        dns_syntax::parse_flat(&self.fallback).map_err(|e| fmt_errs("dns.fallback", e))?;
        dns_syntax::parse_plain(&self.bootstrap).map_err(|e| fmt_errs("dns.bootstrap", e))?;
        dns_syntax::parse_plain(&self.private_resolvers)
            .map_err(|e| fmt_errs("dns.private_resolvers", e))?;
        if self
            .servers
            .len()
            .max(self.fallback.len())
            .max(self.bootstrap.len())
            > 256
        {
            return Err("dns: at most 256 lines per list".into());
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
        if !(100..=60_000).contains(&self.timeout_ms) {
            return Err("dns.timeout_ms must be between 100 and 60000".into());
        }
        if self.ecs == DnsEcs::Custom {
            parse_ecs_subnet(&self.ecs_subnet).map_err(|e| format!("dns.ecs_subnet: {e}"))?;
        }
        let src = self.upstreams_source.trim();
        if src.len() > 2048 {
            return Err("dns.upstreams_source is too long".into());
        }
        if src.contains("://") {
            match url::Url::parse(src) {
                Ok(u) if u.scheme() == "https" => {}
                Ok(_) => return Err("dns.upstreams_source URLs must be https".into()),
                Err(_) => return Err("dns.upstreams_source is not a valid URL".into()),
            }
        }
        Ok(())
    }
}

impl Default for DnsSettings {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            upstreams_source: String::new(),
            mode: DnsMode::default(),
            bootstrap: Vec::new(),
            fallback: Vec::new(),
            private_rdns: true,
            private_resolvers: Vec::new(),
            cache_size: default_dns_cache_size(),
            min_ttl_secs: default_dns_min_ttl(),
            max_ttl_secs: default_dns_max_ttl(),
            negative_ttl_secs: default_dns_negative_ttl(),
            optimistic_cache: false,
            dnssec: false,
            ipv6: true,
            ecs: DnsEcs::Off,
            ecs_subnet: String::new(),
            timeout_ms: default_dns_timeout_ms(),
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

/// What a blocked request gets back (`proxy.block_response`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlockResponse {
    /// The request fails like a network error, as in an extension blocker: xhr/fetch, scripts,
    /// styles, pings, media, fonts, objects, other and WebSockets are aborted (HTTP/2: that one
    /// stream is reset with CANCEL; HTTP/1: the connection is closed). Documents still get the
    /// block page, subdocuments a blank page and images a 1x1 GIF. Upstream failures (no DNS
    /// answer, refused, TLS failure, timeout) fail the same way for every non-document request,
    /// as on a direct connection; documents get the 502/504 error page.
    #[default]
    Fail,
    /// Every block gets a well-formed success response (204, empty 200, GIF), and upstream
    /// failures get a synthesized 502/504 for every type (debugging).
    Synthetic,
}

impl BlockResponse {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fail => "fail",
            Self::Synthetic => "synthetic",
        }
    }
}

impl std::str::FromStr for BlockResponse {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "fail" => Ok(Self::Fail),
            "synthetic" => Ok(Self::Synthetic),
            o => Err(format!(
                "block_response must be fail or synthetic, not {o:?}"
            )),
        }
    }
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
    /// How a blocked subresource is answered (see [`BlockResponse`]).
    #[serde(default)]
    pub block_response: BlockResponse,
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
    /// How the proxy connects to origin servers (`[proxy.upstream]`).
    #[serde(default)]
    pub upstream: UpstreamSettings,
}

/// Upstream connection behaviour.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamSettings {
    /// Connect to origins the way the browser behind the request would (its TLS and HTTP/2
    /// fingerprint, header order), so sites that reject non-browser clients accept the proxy. Off
    /// uses the same client without the browser fingerprint.
    #[serde(default = "default_true")]
    pub browser_like: bool,
    /// Send Argus's own upstream traffic through another proxy (`[proxy.upstream.proxy]`).
    #[serde(default)]
    pub proxy: UpstreamProxy,
}

impl Default for UpstreamSettings {
    fn default() -> Self {
        Self {
            browser_like: true,
            proxy: UpstreamProxy::default(),
        }
    }
}

/// Protocol spoken to the upstream proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamProxyKind {
    /// HTTP `CONNECT`.
    #[default]
    Http,
    /// SOCKS5 (no remote DNS: Argus always sends the address it resolved and vetted).
    Socks5,
}

/// An upstream proxy Argus connects through. DNS lookups stay on Argus: the destination policy
/// is applied to the address Argus resolved, and only that address is sent to the proxy.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamProxy {
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
    #[serde(default)]
    pub password: String,
}

fn default_upstream_proxy_port() -> u16 {
    8080
}

impl Default for UpstreamProxy {
    fn default() -> Self {
        Self {
            enabled: false,
            kind: UpstreamProxyKind::Http,
            host: String::new(),
            port: default_upstream_proxy_port(),
            username: String::new(),
            password: String::new(),
        }
    }
}

impl std::fmt::Debug for UpstreamProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamProxy")
            .field("enabled", &self.enabled)
            .field("kind", &self.kind)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field(
                "password",
                &if self.password.is_empty() {
                    "unset"
                } else {
                    "set"
                },
            )
            .finish()
    }
}

impl UpstreamProxy {
    /// The host without IPv6 brackets, whitespace or a trailing dot.
    pub fn bare_host(&self) -> &str {
        self.host
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .trim_end_matches('.')
    }

    /// Check the fields of an enabled proxy.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        let host = self.bare_host();
        if host.is_empty() {
            return Err("upstream proxy: host is required".into());
        }
        if host.parse::<std::net::IpAddr>().is_err()
            && !host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
        {
            return Err(format!("upstream proxy: {host:?} is not a host name or IP"));
        }
        if self.port == 0 {
            return Err("upstream proxy: port must be 1-65535".into());
        }
        // RFC 1929 length-prefixed fields.
        if self.username.len() > 255 || self.password.len() > 255 {
            return Err("upstream proxy: username and password are limited to 255 bytes".into());
        }
        if self.username.is_empty() && !self.password.is_empty() {
            return Err("upstream proxy: a password needs a username".into());
        }
        Ok(())
    }
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
    /// Entries kept by the request log (and, separately, by its blocked-only view): about 1 KB
    /// each per ring. Applied live; 100 to 500000.
    #[serde(default = "default_request_log_capacity")]
    pub request_log_capacity: usize,
    /// Leave response bodies alone when the origin sends `Cache-Control: no-transform`
    /// (header-only edits still apply). Many CDNs set it on everything; turn this off to rewrite
    /// those pages anyway.
    #[serde(default)]
    pub respect_no_transform: bool,
    /// On by default: keep service workers from serving documents without Argus's injection. On
    /// filtered sites a worker script is answered with a self-unregistering no-op worker and
    /// existing workers are unregistered by the page, so offline apps and push notifications stop
    /// working there. Full-bypass hosts, `guard_service_workers_exempt` hosts and sites with
    /// blocking off (or a `@@$document` / `$elemhide` / `$jsinject` exception) are never touched.
    #[serde(default = "default_true")]
    pub guard_service_workers: bool,
    /// Hosts (exact, or `*.suffix` for subdomains) the service-worker guard leaves alone.
    #[serde(default)]
    pub guard_service_workers_exempt: Vec<String>,
}

/// Smallest and largest accepted `adblock.request_log_capacity`.
pub const REQUEST_LOG_CAPACITY_RANGE: std::ops::RangeInclusive<usize> = 100..=500_000;

fn default_request_log_capacity() -> usize {
    1000
}

/// `Err` with a message unless `n` is an allowed request-log capacity.
pub fn validate_request_log_capacity(n: usize) -> Result<(), String> {
    if REQUEST_LOG_CAPACITY_RANGE.contains(&n) {
        Ok(())
    } else {
        Err(format!(
            "request_log_capacity: use {} to {}",
            REQUEST_LOG_CAPACITY_RANGE.start(),
            REQUEST_LOG_CAPACITY_RANGE.end()
        ))
    }
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
            request_log_capacity: default_request_log_capacity(),
            respect_no_transform: false,
            guard_service_workers: true,
            guard_service_workers_exempt: Vec::new(),
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
                block_response: BlockResponse::default(),
                explicit: ListenerOverrides::default(),
                transparent: ListenerOverrides::default(),
                tls_passthrough_hosts: Vec::new(),
                block_private_destinations: false,
                allowed_destinations: Vec::new(),
                allowed_clients: default_allowed_clients(),
                enable_websockets: true,
                extra_upstream_ca_paths: Vec::new(),
                require_device_token: false,
                upstream: Default::default(),
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
            stealth: StealthSettings::default(),
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
        validate_request_log_capacity(cfg.adblock.request_log_capacity)
            .map_err(|e| ConfigError::Parse(format!("[adblock] {e}")))?;
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
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        // Owner-only: the settings overlay can hold the upstream proxy password.
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        let mut f = opts.open(&tmp)?;
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

/// Upper bound on the idle connections (over all groups and origins) the browser-like upstream client keeps
/// idle: a quarter of the connection budget, so the pool never holds more descriptors than that.
pub fn pool_total_idle(max_connections: usize) -> usize {
    (max_connections / 4).max(16)
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
    fn request_log_capacity_defaults_and_is_bounded() {
        let with = |n: usize| {
            let mut c = ProxyConfig::default();
            c.adblock.request_log_capacity = n;
            ProxyConfig::from_toml(&toml::to_string_pretty(&c).unwrap())
        };
        assert_eq!(ProxyConfig::default().adblock.request_log_capacity, 1000);
        for ok in [100, 1000, 500_000] {
            assert_eq!(with(ok).unwrap().adblock.request_log_capacity, ok);
        }
        for bad in [0, 99, 500_001] {
            assert!(with(bad).is_err(), "{bad}");
            assert!(validate_request_log_capacity(bad).is_err());
        }
    }

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

    #[test]
    fn dns_settings_validate_every_list_and_option() {
        let ok = DnsSettings {
            servers: vec!["tls://dns.google".into(), "[/lan/]10.0.0.1".into()],
            bootstrap: vec!["1.1.1.1".into()],
            fallback: vec!["https://dns.quad9.net/dns-query".into()],
            private_resolvers: vec!["192.168.1.1".into()],
            ecs: DnsEcs::Custom,
            ecs_subnet: "203.0.113.0/24".into(),
            ..Default::default()
        };
        ok.validate().unwrap();
        let bad = |f: fn(&mut DnsSettings)| {
            let mut d = ok.clone();
            f(&mut d);
            d.validate().unwrap_err()
        };
        assert!(bad(|d| d.servers.push("nonsense".into())).contains("dns.servers, line 3"));
        assert!(bad(|d| d.fallback.push("[/a.com/]1.1.1.1".into())).contains("dns.fallback"));
        assert!(bad(|d| d.bootstrap = vec!["tls://dns.google".into()]).contains("dns.bootstrap"));
        assert!(bad(|d| d.private_resolvers = vec!["x".into()]).contains("private"));
        assert!(bad(|d| d.ecs_subnet = "203.0.113.0".into()).contains("ecs_subnet"));
        assert!(bad(|d| d.timeout_ms = 5).contains("timeout_ms"));
        assert!(bad(|d| d.upstreams_source = "http://[bad".into()).contains("upstreams_source"));
    }

    #[test]
    fn dns_settings_persist_in_the_overlay() {
        let (_d, b, o) = layer_dir();
        let mut c = ProxyConfig::load_layered(&b, &o).unwrap();
        c.dns.servers = vec!["tls://dns.google".into(), "[/lan/]#".into()];
        c.dns.mode = DnsMode::FastestIp;
        c.dns.optimistic_cache = true;
        c.dns.ecs = DnsEcs::Auto;
        c.save_overlay(&b, &o).unwrap();
        let text = std::fs::read_to_string(&o).unwrap();
        assert!(
            text.contains("fastest_ip") && text.contains("optimistic_cache"),
            "{text}"
        );
        let back = ProxyConfig::load_layered(&b, &o).unwrap();
        assert_eq!(back.dns.servers, c.dns.servers);
        assert_eq!(back.dns.mode, DnsMode::FastestIp);
        assert!(back.dns.optimistic_cache && back.dns.ecs == DnsEcs::Auto);
        assert!(
            back.dns.ipv6 && back.dns.private_rdns,
            "untouched defaults stay"
        );
    }
}

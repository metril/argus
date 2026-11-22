//! Blocklist formats: detection and conversion to ABP/uBO filter syntax.
//!
//! Everything here is pure (no I/O). [`detect`] guesses a list's format from a sample of its lines;
//! [`convert`] turns a list in any supported format into ABP/uBO rule text that adblock-rust
//! compiles, plus a side list of extended rules the engine cannot express ([`ExtRule`]) and any
//! IP ranges ([`IpRange`]) that cannot be hostname rules.
//!
//! Domain semantics: an entry `d` in a hosts/domain/DNS list blocks `d` and all its subdomains,
//! so it becomes `||d^`. Surge/Clash `DOMAIN` (exact) and Little Snitch `denied-remote-hosts`
//! become exact-host rules.

mod abp;
mod ext;
mod hostlike;
mod iplist;
mod proxyrules;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::{Hash, Hasher};

use serde::{Deserialize, Serialize};

pub use abp::{find_includes, preprocess_and_meta};
pub use ext::{classify_rejected, scriptlet_alias_table, ExtKind, ExtRule};
pub use iplist::{IpRange, IpSet};

/// Bumped whenever conversion output could change for the same input (part of the persisted
/// engine's cache key).
pub const CONVERTER_VERSION: u32 = 1;

/// Max number of per-line errors kept in [`ConvertStats::errors`].
pub const MAX_ERRORS: usize = 50;

/// A blocklist format. `Auto` means "detect from content".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ListFormat {
    #[default]
    Auto,
    /// Adblock Plus / EasyList syntax.
    Abp,
    /// uBlock Origin static filters (`!#include`, `!#if`, `##+js`).
    Ubo,
    /// AdGuard filter syntax (`#%#`, `#$#`, `$$`, `$denyallow`, ...).
    Adguard,
    /// `0.0.0.0 domain` hosts files.
    Hosts,
    /// One domain per line.
    Domains,
    Dnsmasq,
    Unbound,
    /// BIND response policy zone files.
    Rpz,
    /// Pi-hole lists: domains and regex lines.
    Pihole,
    /// AdGuard Home DNS filtering syntax.
    AdguardHome,
    /// Little Snitch `.lsrules` JSON.
    LittleSnitch,
    /// Surge / Quantumult X / Shadowrocket / Loon rule lists.
    Surge,
    /// Clash / Mihomo rule providers (YAML `payload:`).
    Clash,
    /// Plain IP / CIDR / range lists.
    IpList,
}

impl ListFormat {
    pub const ALL: [ListFormat; 15] = [
        Self::Auto,
        Self::Abp,
        Self::Ubo,
        Self::Adguard,
        Self::Hosts,
        Self::Domains,
        Self::Dnsmasq,
        Self::Unbound,
        Self::Rpz,
        Self::Pihole,
        Self::AdguardHome,
        Self::LittleSnitch,
        Self::Surge,
        Self::Clash,
        Self::IpList,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Abp => "abp",
            Self::Ubo => "ubo",
            Self::Adguard => "adguard",
            Self::Hosts => "hosts",
            Self::Domains => "domains",
            Self::Dnsmasq => "dnsmasq",
            Self::Unbound => "unbound",
            Self::Rpz => "rpz",
            Self::Pihole => "pihole",
            Self::AdguardHome => "adguard-home",
            Self::LittleSnitch => "little-snitch",
            Self::Surge => "surge",
            Self::Clash => "clash",
            Self::IpList => "ip-list",
        }
    }

    /// True for the ABP-family formats that pass through to adblock-rust.
    pub fn is_abp_family(self) -> bool {
        matches!(self, Self::Abp | Self::Ubo | Self::Adguard)
    }
}

impl std::str::FromStr for ListFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let s = s.trim().to_ascii_lowercase();
        Self::ALL
            .into_iter()
            .find(|f| f.as_str() == s)
            .ok_or_else(|| format!("unknown list format `{s}`"))
    }
}

impl std::fmt::Display for ListFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Counters from one conversion.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvertStats {
    /// Lines in the input (including comments and blanks).
    pub total_lines: usize,
    /// Output rules emitted (an input line may emit several, or an IP range).
    pub converted: usize,
    /// Recognised lines that cannot be expressed (non-blocking entries, localhost, unsupported
    /// directives, ...).
    pub skipped: usize,
    /// First [`MAX_ERRORS`] invalid lines as `(line_no (1-based), reason)`.
    pub errors: Vec<(usize, String)>,
    /// Total invalid lines (not capped).
    pub error_count: usize,
    /// Extended rules diverted to [`Converted::ext`], per [`ExtKind::as_str`].
    pub ext_counts: BTreeMap<String, usize>,
    /// Rules rewritten into supported syntax (scriptlet aliases, `:style()`, `$denyallow`, ...).
    pub translated: usize,
    /// Lines skipped by category (e.g. `rpz-nsdname`, `dnstype`, `header`), for the UI.
    pub skipped_reasons: BTreeMap<String, usize>,
}

impl ConvertStats {
    pub(crate) fn error(&mut self, line_no: usize, reason: impl Into<String>) {
        self.error_count += 1;
        if self.errors.len() < MAX_ERRORS {
            self.errors.push((line_no, reason.into()));
        }
    }

    pub(crate) fn skip(&mut self, reason: &str) {
        self.skipped += 1;
        *self.skipped_reasons.entry(reason.to_string()).or_default() += 1;
    }

    pub(crate) fn ext(&mut self, kind: ExtKind) {
        *self
            .ext_counts
            .entry(kind.as_str().to_string())
            .or_default() += 1;
    }
}

/// Header metadata parsed from list comments.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListMeta {
    pub title: Option<String>,
    pub homepage: Option<String>,
    pub version: Option<String>,
    /// `! Expires:` clamped to 1 hour .. 14 days.
    pub expires_secs: Option<u64>,
    pub redirect: Option<String>,
}

/// Conversion options.
#[derive(Debug, Clone, Default)]
pub struct ConvertOptions {
    /// Format override; `Auto` detects.
    pub format: ListFormat,
    /// Make every converted rule an exception (`@@...`).
    pub allowlist: bool,
    /// Resolved `!#include` targets, by the path as written in the list (see [`find_includes`]).
    pub includes: HashMap<String, String>,
}

/// Result of [`convert`].
#[derive(Debug, Clone, Default)]
pub struct Converted {
    /// The format that was used (detected when the override was `Auto`).
    pub format: ListFormat,
    /// ABP/uBO rule text, one rule per line (no comments).
    pub rules: String,
    /// Rules the engine cannot express, for a later phase to implement.
    pub ext: Vec<ExtRule>,
    /// IP ranges to block (matched against IP-literal request hosts).
    pub ip_block: Vec<IpRange>,
    /// IP ranges to allow (wins over `ip_block`).
    pub ip_allow: Vec<IpRange>,
    pub stats: ConvertStats,
    pub meta: ListMeta,
}

/// Guess the format of `content` from a sample of its lines.
///
/// Robust to a BOM, CRLF line endings, comments and mixed junk: each sampled line votes for the
/// format(s) it could belong to and the majority wins; unrecognisable content is treated as ABP.
pub fn detect(content: &str) -> ListFormat {
    let content = content.strip_prefix('\u{feff}').unwrap_or(content);
    let trimmed = content.trim_start();
    if trimmed.starts_with('{') && abp::looks_like_snitch(trimmed) {
        return ListFormat::LittleSnitch;
    }

    #[derive(Default)]
    struct V {
        abp: u32,
        hosts: u32,
        dnsmasq: u32,
        unbound: u32,
        rpz: u32,
        proxy: u32,
        clash: u32,
        ip: u32,
        domain: u32,
        regex: u32,
        // refinements within the ABP family
        adguard: u32,
        ubo: u32,
        agh: u32,
    }
    let mut v = V::default();
    let mut seen = 0u32;
    let mut header_abp = false;
    for (n, raw) in content.lines().enumerate() {
        if n > 4000 || seen >= 600 {
            break;
        }
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let lower_head = line
            .get(..8)
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();
        if lower_head.starts_with("[adblock") || lower_head.starts_with("[ublock") {
            header_abp = true;
            if lower_head.starts_with("[ublock") {
                v.ubo += 3;
            }
            continue;
        }
        if lower_head.starts_with("[adguard") {
            header_abp = true;
            v.adguard += 3;
            continue;
        }
        if line.starts_with('!') {
            if line.starts_with("!#") {
                v.ubo += 1;
                v.abp += 1;
            } else if line.len() > 2 {
                v.abp += 1;
            }
            continue;
        }
        if line.starts_with('#') && !line.starts_with("##") && !line.starts_with("#@#") {
            // `# comment`: hosts/domain/dnsmasq/unbound style (or uBO comment). No vote.
            continue;
        }
        if line.starts_with(';') || line.starts_with("//") {
            continue;
        }
        seen += 1;
        let low = line.to_ascii_lowercase();
        if line.starts_with("$TTL") || line.starts_with("$ORIGIN") || low.contains(" soa ") {
            v.rpz += 5;
            continue;
        }
        if low.contains(" cname ") || low.ends_with(" cname .") {
            v.rpz += 1;
            continue;
        }
        if low == "payload:" || low == "rules:" {
            v.clash += 5;
            continue;
        }
        if low == "[rule]" {
            v.proxy += 3;
            continue;
        }
        if low.starts_with("- ") {
            v.clash += 1;
            continue;
        }
        if low.starts_with("address=/") || low.starts_with("server=/") || low.starts_with("local=/")
        {
            v.dnsmasq += 1;
            continue;
        }
        if low.starts_with("local-zone:") || low.starts_with("local-data:") {
            v.unbound += 1;
            continue;
        }
        if low == "server:" {
            v.unbound += 1;
            continue;
        }
        if proxyrules::is_rule_line(&low) {
            v.proxy += 1;
            continue;
        }
        if hostlike::is_hosts_line(line) {
            v.hosts += 1;
            continue;
        }
        if iplist::parses_as_ip_entry(line) {
            v.ip += 1;
            continue;
        }
        if abp::is_abp_like(line) {
            v.abp += 1;
            if abp::is_adguard_only(line) {
                v.adguard += 1;
            }
            if line.contains("##+js(") || line.starts_with("!#") {
                v.ubo += 1;
            }
            if abp::is_agh_dns_only(line) {
                v.agh += 1;
            }
            continue;
        }
        if hostlike::is_plain_domain(line) {
            v.domain += 1;
            continue;
        }
        if hostlike::is_regex_like(line) {
            v.regex += 1;
        }
    }

    let abp_votes = v.abp + if header_abp { 3 } else { 0 };
    let ranked = [
        (abp_votes, 10, ListFormat::Abp),
        (v.rpz, 9, ListFormat::Rpz),
        (v.clash, 8, ListFormat::Clash),
        (v.proxy, 7, ListFormat::Surge),
        (v.dnsmasq, 6, ListFormat::Dnsmasq),
        (v.unbound, 5, ListFormat::Unbound),
        (v.hosts, 4, ListFormat::Hosts),
        (v.ip, 3, ListFormat::IpList),
        (v.domain + v.regex, 2, ListFormat::Domains),
    ];
    let (top, _, mut fmt) = ranked
        .iter()
        .copied()
        .filter(|r| r.0 > 0)
        .max_by_key(|r| (r.0, r.1))
        .unwrap_or((0, 0, ListFormat::Abp));
    if top == 0 {
        return ListFormat::Abp;
    }
    match fmt {
        ListFormat::Abp => {
            // Pure-DNS ABP-looking content: AdGuard Home.
            if v.agh > 0 && v.adguard == 0 && v.ubo == 0 {
                fmt = ListFormat::AdguardHome;
            } else if v.adguard > 0 && v.adguard >= v.ubo {
                fmt = ListFormat::Adguard;
            } else if v.ubo > 0 {
                fmt = ListFormat::Ubo;
            }
        }
        ListFormat::Domains if v.regex > 0 => fmt = ListFormat::Pihole,
        _ => {}
    }
    fmt
}

/// Convert `content` according to `opts` (see module docs).
pub fn convert(content: &str, opts: &ConvertOptions) -> Converted {
    let content = content.strip_prefix('\u{feff}').unwrap_or(content);
    let format = if opts.format == ListFormat::Auto {
        detect(content)
    } else {
        opts.format
    };
    let mut c = match format {
        ListFormat::Abp | ListFormat::Ubo | ListFormat::Adguard | ListFormat::Auto => {
            abp::convert_abp(content, opts)
        }
        ListFormat::Hosts => hostlike::convert_hosts(content, opts),
        ListFormat::Domains => hostlike::convert_domains(content, opts),
        ListFormat::Dnsmasq => hostlike::convert_dnsmasq(content, opts),
        ListFormat::Unbound => hostlike::convert_unbound(content, opts),
        ListFormat::Rpz => hostlike::convert_rpz(content, opts),
        ListFormat::Pihole => hostlike::convert_pihole(content, opts),
        ListFormat::AdguardHome => hostlike::convert_agh(content, opts),
        ListFormat::LittleSnitch => hostlike::convert_snitch(content, opts),
        ListFormat::Surge => proxyrules::convert_surge(content, opts),
        ListFormat::Clash => proxyrules::convert_clash(content, opts),
        ListFormat::IpList => iplist::convert_ip_list(content, opts),
    };
    c.format = format;
    if format != ListFormat::Abp && format != ListFormat::Ubo && format != ListFormat::Adguard {
        // Non-ABP formats still carry `# Title:`-style header metadata.
        c.meta = abp::scan_meta(content);
    }
    c
}

/// Convenience: the rule text lines of a conversion, owned (for callers that need `&str` slices).
pub fn rule_lines(c: &Converted) -> impl Iterator<Item = &str> {
    c.rules.lines()
}

/// Drop rule lines already present in `seen` (and duplicates within `rules`), recording the rest.
/// Returns the deduplicated text and the number of lines dropped. `seen` holds 64-bit line hashes
/// so a 1M-rule list costs about 16 MB.
pub fn dedupe(rules: &str, seen: &mut HashSet<u64>) -> (String, usize) {
    let mut out = String::with_capacity(rules.len());
    let mut dropped = 0;
    for line in rules.lines() {
        if line.is_empty() {
            continue;
        }
        let mut h = std::collections::hash_map::DefaultHasher::new();
        line.hash(&mut h);
        if seen.insert(h.finish()) {
            out.push_str(line);
            out.push('\n');
        } else {
            dropped += 1;
        }
    }
    (out, dropped)
}

// ---- shared helpers ---------------------------------------------------------------------------

/// Hostnames that appear in hosts files but are not block targets.
const LOCAL_NAMES: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
    "0.0.0.0",
    "localdomain",
];

pub(crate) fn is_local_name(h: &str) -> bool {
    LOCAL_NAMES.contains(&h)
}

/// Normalise a hostname: lowercase, drop a trailing dot, IDN to punycode, validate labels.
/// IP literals, single-label names and invalid characters are rejected.
pub(crate) fn norm_host(s: &str) -> Result<String, &'static str> {
    let s = s.trim().trim_end_matches('.');
    if s.is_empty() {
        return Err("empty hostname");
    }
    let ascii: String = if s.is_ascii() {
        s.to_ascii_lowercase()
    } else {
        match url::Host::parse(s) {
            Ok(url::Host::Domain(d)) => d,
            _ => return Err("invalid internationalised hostname"),
        }
    };
    if ascii.len() > 253 {
        return Err("hostname too long");
    }
    let mut labels = 0;
    for label in ascii.split('.') {
        labels += 1;
        let b = label.as_bytes();
        if b.is_empty() || b.len() > 63 {
            return Err("invalid label length");
        }
        if b[0] == b'-' || b[b.len() - 1] == b'-' {
            return Err("label starts or ends with `-`");
        }
        if !b
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_')
        {
            return Err("invalid character in hostname");
        }
    }
    if labels < 2 {
        return Err("single-label hostname");
    }
    if ascii
        .rsplit('.')
        .next()
        .is_some_and(|tld| tld.bytes().all(|c| c.is_ascii_digit()))
    {
        return Err("looks like an IP address");
    }
    Ok(ascii)
}

/// Accumulates output rules, applying the allowlist flag.
pub(crate) struct Out {
    pub buf: String,
    pub allow: bool,
    pub stats: ConvertStats,
    pub ext: Vec<ExtRule>,
    pub ip_block: Vec<IpRange>,
    pub ip_allow: Vec<IpRange>,
}

impl Out {
    pub fn new(content: &str, opts: &ConvertOptions) -> Self {
        let mut stats = ConvertStats::default();
        stats.total_lines = content.lines().count();
        Self {
            buf: String::new(),
            allow: opts.allowlist,
            stats,
            ext: Vec::new(),
            ip_block: Vec::new(),
            ip_allow: Vec::new(),
        }
    }

    fn push(&mut self, rule_body: &str, exception: bool) {
        if exception || self.allow {
            self.buf.push_str("@@");
        }
        self.buf.push_str(rule_body);
        self.buf.push('\n');
        self.stats.converted += 1;
    }

    /// Block (or, in an allowlist / when `exception`, allow) `d` and its subdomains.
    pub fn domain(&mut self, d: &str, exception: bool) {
        self.push(&format!("||{d}^"), exception);
    }

    /// The exact host only (no subdomains), over http/https/ws/wss.
    pub fn exact_host(&mut self, d: &str, exception: bool) {
        for scheme in ["http", "https", "ws", "wss"] {
            self.push(&format!("|{scheme}://{d}^"), exception);
        }
    }

    /// Host-only keyword match (not the path).
    pub fn keyword(&mut self, kw: &str, exception: bool) {
        self.push(
            &format!("/^[a-z][a-z0-9+.-]*:\\/\\/[^\\/?#]*{}/", regex::escape(kw)),
            exception,
        );
    }

    /// A raw regex (already in `/.../` form).
    pub fn raw(&mut self, rule: &str, exception: bool) {
        self.push(rule, exception);
    }

    pub fn ip(&mut self, r: IpRange, exception: bool) {
        self.stats.converted += 1;
        if exception || self.allow {
            self.ip_allow.push(r);
        } else {
            self.ip_block.push(r);
        }
    }

    pub fn finish(self, meta: ListMeta) -> Converted {
        Converted {
            format: ListFormat::Auto,
            rules: self.buf,
            ext: self.ext,
            ip_block: self.ip_block,
            ip_allow: self.ip_allow,
            stats: self.stats,
            meta,
        }
    }
}

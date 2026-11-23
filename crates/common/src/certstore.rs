//! Upstream server certificates seen by the proxy, kept so users can inspect the REAL origin
//! certificate (the certificate a client sees is Argus's minted leaf).
//!
//! Parsed certificate data is keyed by SHA-256 fingerprint of the leaf and is host-independent.
//! Verdicts are keyed by `host:port` (port defaulted to 443), so one site presenting another's
//! public chain can never change that site's verdict, and two ports of one host stay apart.
//! The proxy records an `ok` verdict from a response that completed (full verification) and an
//! `invalid` one from a dedicated probe handshake after an upstream TLS failure. The store also
//! remembers which profiles saw each `host:port`, so profile-restricted callers only get hosts
//! their profiles visited. Everything is capped in bytes. A chain is parsed only when its
//! fingerprint is new.

use std::sync::Arc;
use std::time::Duration;

use moka::sync::Cache;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Default capacity of each cache.
pub const DEFAULT_CAPACITY: u64 = 4096;
/// Default byte budget of the parsed-certificate cache.
pub const DEFAULT_BYTES: u64 = 32 * 1024 * 1024;
/// Byte budget of the per-host profile memory.
pub const SEEN_BYTES: u64 = 2 * 1024 * 1024;
/// Most SANs kept per certificate.
const MAX_SANS: usize = 100;
/// Longest stored subject, issuer, SAN or detail string, in bytes.
const MAX_STR: usize = 256;
/// Most chain entries parsed per handshake.
const MAX_CHAIN: usize = 10;
/// Entries not touched for this long are dropped.
/// Most profiles remembered per host.
const MAX_PROFILES: usize = 32;
/// Default port when none is given.
pub const DEFAULT_PORT: u16 = 443;
const TTL_IDLE: Duration = Duration::from_secs(24 * 3600);

/// Outcome of verifying the upstream chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Ok,
    Invalid,
}

/// Why verification failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailReason {
    Expired,
    NotYetValid,
    NameMismatch,
    UnknownIssuer,
    Other,
}

/// One certificate of the presented chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainEntry {
    pub subject: String,
    pub issuer: String,
    /// RFC 3339.
    pub not_before: String,
    /// RFC 3339.
    pub not_after: String,
    /// Lowercase hex SHA-256 of the DER.
    pub fp: String,
}

/// A parsed upstream certificate with the verdict of its latest verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertInfo {
    /// Lowercase hex SHA-256 of the leaf DER.
    pub fp: String,
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    /// RFC 3339.
    pub not_before: String,
    /// RFC 3339.
    pub not_after: String,
    /// DNS names and IP addresses of the subjectAltName extension.
    pub sans: Vec<String>,
    /// Presented chain, leaf first.
    pub chain: Vec<ChainEntry>,
    pub verdict: Verdict,
    /// Set when `verdict` is `invalid`.
    pub reason: Option<FailReason>,
    /// Verifier's message when `verdict` is `invalid`.
    pub detail: Option<String>,
    /// Leaf carries an Extended Validation policy.
    pub ev: bool,
}

/// Host-independent facts of one certificate.
struct Parsed {
    fp: String,
    subject: String,
    issuer: String,
    serial: String,
    not_before: String,
    not_after: String,
    nb_ts: i64,
    na_ts: i64,
    sans: Vec<String>,
    chain: Vec<ChainEntry>,
    ev: bool,
}

impl Parsed {
    /// Approximate heap bytes, for the cache weigher.
    fn weight(&self) -> u32 {
        let chain: usize = self
            .chain
            .iter()
            .map(|c| c.subject.len() + c.issuer.len() + c.fp.len() + 96)
            .sum();
        let sans: usize = self.sans.iter().map(|s| s.len() + 24).sum();
        let n = 256
            + chain
            + sans
            + self.subject.len()
            + self.issuer.len()
            + self.serial.len()
            + self.fp.len();
        u32::try_from(n).unwrap_or(u32::MAX)
    }
}

/// A `host:port`'s verification result for one fingerprint.
struct HostRecord {
    fp: String,
    verdict: Verdict,
    reason: Option<FailReason>,
    detail: Option<String>,
}

/// Fetches a host's certificate chain on demand (a probe handshake) and records it in the
/// store; implemented by the proxy so the API need not depend on it.
pub trait ChainProbe: Send + Sync {
    /// Fingerprint of the leaf `host:port` presented, once its chain is recorded.
    fn probe<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<String>> + Send + 'a>>;
}

impl CertInfo {
    /// Only the leaf is known (and it is not self-signed): the full chain could be fetched.
    pub fn is_leaf_only(&self) -> bool {
        self.chain.len() <= 1 && self.subject != self.issuer
    }
}

/// Upstream certificate store.
pub struct CertStore {
    parsed: Cache<String, Arc<Parsed>>,
    hosts: Cache<String, Arc<HostRecord>>,
    /// Profile ids that saw each `host:port`.
    seen: Cache<String, Arc<Mutex<Vec<String>>>>,
}

impl std::fmt::Debug for CertStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertStore").finish_non_exhaustive()
    }
}

impl Default for CertStore {
    fn default() -> Self {
        Self::new(DEFAULT_BYTES, DEFAULT_CAPACITY)
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Lowercase hex SHA-256 of `der`.
pub fn fingerprint(der: &[u8]) -> String {
    hex(&Sha256::digest(der))
}

/// Canonical `host:port` key. Accepts `host`, `host:port`, `[v6]`, `[v6]:port` and a bare IPv6
/// literal; lowercase, no trailing dot, port defaulted to [`DEFAULT_PORT`]. IPv6 keeps its
/// brackets.
pub fn parse_hostport(s: &str) -> String {
    let h = s.trim();
    let (host, port) = if let Some(rest) = h.strip_prefix('[') {
        let (inner, after) = rest.split_once(']').unwrap_or((rest, ""));
        (inner, after.strip_prefix(':').and_then(|p| p.parse().ok()))
    } else if h.matches(':').count() == 1 {
        let (a, p) = h.split_once(':').unwrap_or((h, ""));
        (a, p.parse().ok())
    } else {
        (h, None)
    };
    hostport(host, port.unwrap_or(DEFAULT_PORT))
}

/// Canonical `host:port` key from a bare host (with or without IPv6 brackets) and a port.
pub fn hostport(host: &str, port: u16) -> String {
    let h = host.trim().trim_start_matches('[').trim_end_matches(']');
    let h = h.trim_end_matches('.').to_ascii_lowercase();
    if h.contains(':') {
        format!("[{h}]:{port}")
    } else {
        format!("{h}:{port}")
    }
}

fn cap(s: &str) -> String {
    if s.len() <= MAX_STR {
        return s.to_string();
    }
    let mut n = MAX_STR;
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    s[..n].to_string()
}

fn ts(t: x509_parser::time::ASN1Time) -> String {
    chrono::DateTime::from_timestamp(t.timestamp(), 0)
        .unwrap_or_default()
        .to_rfc3339()
}

fn ip_text(b: &[u8]) -> Option<String> {
    match b.len() {
        4 => Some(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string()),
        16 => {
            let a: [u8; 16] = b.try_into().ok()?;
            Some(std::net::Ipv6Addr::from(a).to_string())
        }
        _ => None,
    }
}

impl CertStore {
    /// `max_bytes`: budget of the parsed-certificate cache; `max_hosts`: entries of the verdict
    /// cache.
    pub fn new(max_bytes: u64, max_hosts: u64) -> Self {
        Self {
            parsed: Cache::builder()
                .max_capacity(max_bytes)
                .weigher(|_k: &String, v: &Arc<Parsed>| v.weight())
                .time_to_idle(TTL_IDLE)
                .build(),
            hosts: Cache::builder()
                .max_capacity(max_hosts)
                .time_to_idle(TTL_IDLE)
                .build(),
            seen: Cache::builder()
                .max_capacity(SEEN_BYTES)
                .weigher(|k: &String, v: &Arc<Mutex<Vec<String>>>| {
                    let n: usize = v.lock().iter().map(|p| p.len() + 32).sum();
                    u32::try_from(k.len() + n + 64).unwrap_or(u32::MAX)
                })
                .time_to_idle(TTL_IDLE)
                .build(),
        }
    }

    /// Parse and keep `chain_der` unless its leaf is known with at least as long a chain.
    fn ensure_parsed(&self, fp: &str, chain_der: &[&[u8]], ev: &dyn Fn() -> bool) -> bool {
        if let Some(p) = self.parsed.get(fp) {
            if p.chain.len() >= chain_der.len().min(MAX_CHAIN) {
                return true;
            }
        }
        match Self::parse(fp, chain_der, ev()) {
            Some(p) => {
                self.parsed.insert(fp.to_string(), Arc::new(p));
                true
            }
            None => false,
        }
    }

    fn put(&self, key: &str, rec: HostRecord) {
        if let Some(old) = self.hosts.get(key) {
            if old.fp == rec.fp && old.verdict == rec.verdict && old.reason == rec.reason {
                return;
            }
        }
        self.hosts.insert(key.to_string(), Arc::new(rec));
    }

    /// A response completed over a connection that presented the leaf `der`: full verification
    /// passed, so `hostport` gets an `ok` verdict. Returns the leaf fingerprint.
    pub fn record_ok(&self, hostport: &str, der: &[u8], ev: &dyn Fn() -> bool) -> Option<String> {
        let fp = fingerprint(der);
        if !self.ensure_parsed(&fp, &[der], ev) {
            return None;
        }
        self.put(
            &parse_hostport(hostport),
            HostRecord {
                fp: fp.clone(),
                verdict: Verdict::Ok,
                reason: None,
                detail: None,
            },
        );
        Some(fp)
    }

    /// Record what a probe handshake to `hostport` saw: the chain (leaf first) and the result of
    /// verifying it. Returns the leaf fingerprint.
    pub fn record_probe(
        &self,
        hostport: &str,
        chain_der: &[&[u8]],
        result: Result<(), (FailReason, String)>,
        ev: &dyn Fn() -> bool,
    ) -> Option<String> {
        let fp = fingerprint(chain_der.first()?);
        if !self.ensure_parsed(&fp, chain_der, ev) {
            return None;
        }
        let (verdict, reason, detail) = match result {
            Ok(()) => (Verdict::Ok, None, None),
            Err((r, d)) => (Verdict::Invalid, Some(r), Some(cap(&d))),
        };
        self.put(
            &parse_hostport(hostport),
            HostRecord {
                fp: fp.clone(),
                verdict,
                reason,
                detail,
            },
        );
        Some(fp)
    }

    /// Remember that `profile` saw `hostport`.
    pub fn note_seen(&self, hostport: &str, profile: &str) {
        let key = parse_hostport(hostport);
        if let Some(v) = self.seen.get(&key) {
            if v.lock().iter().any(|p| p == profile) {
                return;
            }
        }
        // Re-insert so the weigher sees the grown set.
        let mut ids = self
            .seen
            .get(&key)
            .map(|v| v.lock().clone())
            .unwrap_or_default();
        if ids.len() < MAX_PROFILES && !ids.iter().any(|p| p == profile) {
            ids.push(profile.to_string());
        }
        self.seen.insert(key, Arc::new(Mutex::new(ids)));
    }

    /// Profiles that saw `hostport`.
    pub fn seen_by(&self, hostport: &str) -> Vec<String> {
        self.seen
            .get(&parse_hostport(hostport))
            .map(|v| v.lock().clone())
            .unwrap_or_default()
    }

    fn parse(fp: &str, chain_der: &[&[u8]], ev: bool) -> Option<Parsed> {
        let (_, leaf) = x509_parser::parse_x509_certificate(chain_der.first()?).ok()?;
        let sans = leaf
            .subject_alternative_name()
            .ok()
            .flatten()
            .map(|e| {
                use x509_parser::extensions::GeneralName;
                e.value
                    .general_names
                    .iter()
                    .filter_map(|g| match g {
                        GeneralName::DNSName(d) => Some(cap(d)),
                        GeneralName::IPAddress(b) => ip_text(b),
                        _ => None,
                    })
                    .take(MAX_SANS)
                    .collect()
            })
            .unwrap_or_default();
        let chain = chain_der
            .iter()
            .take(MAX_CHAIN)
            .filter_map(|der| {
                let (_, c) = x509_parser::parse_x509_certificate(der).ok()?;
                Some(ChainEntry {
                    subject: cap(&c.subject().to_string()),
                    issuer: cap(&c.issuer().to_string()),
                    not_before: ts(c.validity().not_before),
                    not_after: ts(c.validity().not_after),
                    fp: fingerprint(der),
                })
            })
            .collect();
        Some(Parsed {
            fp: fp.to_string(),
            subject: cap(&leaf.subject().to_string()),
            issuer: cap(&leaf.issuer().to_string()),
            serial: cap(&leaf.raw_serial_as_string()),
            not_before: ts(leaf.validity().not_before),
            not_after: ts(leaf.validity().not_after),
            nb_ts: leaf.validity().not_before.timestamp(),
            na_ts: leaf.validity().not_after.timestamp(),
            sans,
            chain,
            ev,
        })
    }

    /// The certificate `fp`. With `host` (`host` or `host:port`), the verdict that host last got for exactly this
    /// certificate; otherwise (or when that host presented another one) a host-independent
    /// verdict from the validity period alone, which says nothing about trust or name.
    pub fn info(&self, fp: &str, host: Option<&str>) -> Option<CertInfo> {
        let fp = fp.to_ascii_lowercase();
        let p = self.parsed.get(&fp)?;
        let rec = host
            .and_then(|h| self.hosts.get(&parse_hostport(h)))
            .filter(|r| r.fp == fp);
        let (verdict, reason, detail) = match rec {
            Some(r) => (r.verdict, r.reason, r.detail.clone()),
            None => {
                let now = chrono::Utc::now().timestamp();
                if now > p.na_ts {
                    (Verdict::Invalid, Some(FailReason::Expired), None)
                } else if now < p.nb_ts {
                    (Verdict::Invalid, Some(FailReason::NotYetValid), None)
                } else {
                    (
                        Verdict::Ok,
                        None,
                        Some("Validity period only; pass ?host= for a host's verdict".into()),
                    )
                }
            }
        };
        Some(CertInfo {
            fp: p.fp.clone(),
            subject: p.subject.clone(),
            issuer: p.issuer.clone(),
            serial: p.serial.clone(),
            not_before: p.not_before.clone(),
            not_after: p.not_after.clone(),
            sans: p.sans.clone(),
            chain: p.chain.clone(),
            verdict,
            reason,
            detail,
            ev: p.ev,
        })
    }

    /// The latest certificate `host` (`host` or `host:port`) presented, with its verdict.
    pub fn by_host(&self, host: &str) -> Option<CertInfo> {
        let r = self.hosts.get(&parse_hostport(host))?;
        self.info(&r.fp, Some(host))
    }

    /// Number of distinct certificates held (after pending maintenance).
    pub fn len(&self) -> u64 {
        self.parsed.run_pending_tasks();
        self.parsed.entry_count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert(name: &str) -> Vec<u8> {
        rcgen::generate_simple_self_signed(vec![name.to_string()])
            .unwrap()
            .cert
            .der()
            .to_vec()
    }

    const NO_EV: &dyn Fn() -> bool = &|| false;

    #[test]
    fn dedupes_by_fingerprint_and_links_hosts() {
        let s = CertStore::default();
        let d = cert("a.test");
        let fp1 = s.record_ok("A.test", &d, NO_EV).unwrap();
        let fp2 = s.record_ok("b.test:443", &d, NO_EV).unwrap();
        assert_eq!(fp1, fp2);
        assert_eq!(fp1, fingerprint(&d));
        assert_eq!(s.len(), 1);
        let info = s.by_host("a.test").unwrap();
        assert_eq!(info.sans, vec!["a.test".to_string()]);
        assert_eq!(info.verdict, Verdict::Ok);
        assert_eq!(s.by_host("b.test").unwrap().fp, fp1);
        assert!(s.info(&fp1.to_uppercase(), None).is_some());
    }

    #[test]
    fn ports_of_one_host_are_independent() {
        let s = CertStore::default();
        let (a, b) = (cert("h.test"), cert("h.test"));
        let fa = s.record_ok("h.test:443", &a, NO_EV).unwrap();
        let fb = s
            .record_probe(
                "h.test:8443",
                &[b.as_slice()],
                Err((FailReason::Expired, "old".into())),
                NO_EV,
            )
            .unwrap();
        assert_ne!(fa, fb);
        assert_eq!(s.by_host("h.test").unwrap().fp, fa);
        assert_eq!(s.by_host("h.test:8443").unwrap().fp, fb);
        assert_eq!(s.by_host("h.test:8443").unwrap().verdict, Verdict::Invalid);
        assert_eq!(s.by_host("h.test").unwrap().verdict, Verdict::Ok);
    }

    #[test]
    fn another_hosts_failure_never_changes_a_verdict() {
        let s = CertStore::default();
        let d = cert("bank.test");
        let fp = s.record_ok("bank.test", &d, NO_EV).unwrap();
        s.record_probe(
            "evil.test",
            &[d.as_slice()],
            Err((FailReason::NameMismatch, "bad name".into())),
            NO_EV,
        );
        assert_eq!(s.info(&fp, Some("bank.test")).unwrap().verdict, Verdict::Ok);
        let evil = s.info(&fp, Some("evil.test")).unwrap();
        assert_eq!(evil.reason, Some(FailReason::NameMismatch));
        assert_eq!(s.info(&fp, None).unwrap().verdict, Verdict::Ok);
    }

    #[test]
    fn host_keys_are_canonical() {
        assert_eq!(parse_hostport("Example.COM."), "example.com:443");
        assert_eq!(parse_hostport("example.com:8443"), "example.com:8443");
        assert_eq!(parse_hostport("[2001:db8::1]:444"), "[2001:db8::1]:444");
        assert_eq!(parse_hostport("2001:db8::1"), "[2001:db8::1]:443");
        assert_eq!(hostport("[::1]", 443), "[::1]:443");
        assert_eq!(hostport("::1", 443), parse_hostport("[::1]"));
    }

    #[test]
    fn profiles_are_remembered_per_host_and_bounded() {
        let s = CertStore::default();
        s.note_seen("a.test", "1");
        s.note_seen("a.test:443", "1");
        s.note_seen("a.test", "2");
        assert_eq!(s.seen_by("a.test"), vec!["1".to_string(), "2".to_string()]);
        assert!(s.seen_by("b.test").is_empty());
        for i in 0..100 {
            s.note_seen("c.test", &i.to_string());
        }
        assert_eq!(s.seen_by("c.test").len(), MAX_PROFILES);
    }

    #[test]
    fn memory_is_bounded_in_bytes_and_sans_are_capped() {
        let names: Vec<String> = (0..500)
            .map(|i| format!("{}{i}.test", "n".repeat(300)))
            .collect();
        let d = rcgen::generate_simple_self_signed(names)
            .unwrap()
            .cert
            .der()
            .to_vec();
        let tiny = CertStore::new(1024, 16);
        tiny.record_ok("big.test", &d, NO_EV).unwrap();
        // The entry outweighs the whole budget, so it is evicted instead of held.
        assert!(tiny.len() <= 1);
        let roomy = CertStore::default();
        roomy.record_ok("big.test", &d, NO_EV).unwrap();
        let i = roomy.by_host("big.test").unwrap();
        assert_eq!(i.sans.len(), MAX_SANS);
        assert!(i.sans.iter().all(|x| x.len() <= MAX_STR));
    }

    #[test]
    fn garbage_is_not_stored() {
        let s = CertStore::default();
        assert!(s.record_ok("a.test", b"nope", NO_EV).is_none());
        assert!(s.record_probe("a.test", &[], Ok(()), NO_EV).is_none());
        assert!(s.by_host("a.test").is_none());
    }
}

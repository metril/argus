//! Upstream server certificates seen by the proxy, kept so users can inspect the REAL origin
//! certificate (the certificate a client sees is Argus's minted leaf).
//!
//! Parsed certificate data is keyed by SHA-256 fingerprint of the leaf and is host-independent.
//! Verdicts are keyed by host (the TLS verifier sees no port), so one host presenting another
//! site's public chain can never change that site's verdict. An `ok` verdict counts only after
//! the handshake signature check proved the server holds the key ([`CertStore::confirm`]); an
//! `invalid` one is recorded at once (the handshake is rejected anyway) against the host that
//! was attempted. The parsed cache is capped in bytes. A chain is parsed only when its
//! fingerprint is new.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use moka::sync::Cache;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Default capacity of each cache.
pub const DEFAULT_CAPACITY: u64 = 4096;
/// Default byte budget of the parsed-certificate cache.
pub const DEFAULT_BYTES: u64 = 32 * 1024 * 1024;
/// Most SANs kept per certificate.
const MAX_SANS: usize = 100;
/// Longest stored subject, issuer, SAN or detail string, in bytes.
const MAX_STR: usize = 256;
/// Most chain entries parsed per handshake.
const MAX_CHAIN: usize = 10;
/// Entries not touched for this long are dropped.
/// Waiting `ok` verdicts kept before the table is reset.
const MAX_PENDING: usize = 1024;
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

/// A host's verification result for one fingerprint.
struct HostRecord {
    host: String,
    fp: String,
    verdict: Verdict,
    reason: Option<FailReason>,
    detail: Option<String>,
    at: Instant,
}

/// Upstream certificate store.
pub struct CertStore {
    parsed: Cache<String, Arc<Parsed>>,
    hosts: Cache<String, Arc<HostRecord>>,
    /// `ok` verdicts waiting for the signature check, by leaf fingerprint.
    pending: Mutex<HashMap<String, Vec<Arc<HostRecord>>>>,
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

/// Canonical key of a host: lowercase, IPv6 without brackets, no trailing dot, no port. The TLS
/// verifier and URL hosts spell the same host differently; both go through this.
pub fn host_key(host: &str) -> String {
    let h = host.trim();
    let h = if let Some(rest) = h.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else if h.matches(':').count() == 1 {
        h.split(':').next().unwrap_or(h)
    } else {
        h
    };
    h.trim_end_matches('.').to_ascii_lowercase()
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
            pending: Mutex::new(HashMap::new()),
        }
    }

    fn ensure_parsed(&self, fp: &str, chain_der: &[&[u8]], ev: &dyn Fn() -> bool) -> bool {
        if self.parsed.contains_key(fp) {
            return true;
        }
        match Self::parse(fp, chain_der, ev()) {
            Some(p) => {
                self.parsed.insert(fp.to_string(), Arc::new(p));
                true
            }
            None => false,
        }
    }

    /// Record the chain `host` presented (leaf first) and the verification result; returns the
    /// leaf fingerprint. A failure is recorded against `host` at once. A success is held until
    /// [`Self::confirm`] sees the handshake signature verify for that fingerprint.
    pub fn record(
        &self,
        host: &str,
        chain_der: &[&[u8]],
        result: Result<(), (FailReason, String)>,
        ev: &dyn Fn() -> bool,
    ) -> Option<String> {
        let leaf = chain_der.first()?;
        let fp = fingerprint(leaf);
        if !self.ensure_parsed(&fp, chain_der, ev) {
            return None;
        }
        let (verdict, reason, detail) = match result {
            Ok(()) => (Verdict::Ok, None, None),
            Err((r, d)) => (Verdict::Invalid, Some(r), Some(cap(&d))),
        };
        let rec = Arc::new(HostRecord {
            host: host_key(host),
            fp: fp.clone(),
            verdict,
            reason,
            detail,
            at: Instant::now(),
        });
        if verdict == Verdict::Invalid {
            self.hosts.insert(rec.host.clone(), rec);
        } else {
            let mut p = self.pending.lock();
            if p.len() >= MAX_PENDING {
                p.clear();
            }
            p.entry(fp.clone()).or_default().push(rec);
        }
        Some(fp)
    }

    /// The handshake signature verified for the certificate `fp`: its waiting `ok` verdicts count.
    pub fn confirm(&self, fp: &str) {
        let recs = self.pending.lock().remove(fp);
        for r in recs.into_iter().flatten() {
            self.hosts.insert(r.host.clone(), r);
        }
    }

    /// Make sure the leaf `der` a connection presented is known (a resumed session skips the
    /// verifier); returns its fingerprint.
    pub fn note_peer(&self, der: &[u8]) -> Option<String> {
        let fp = fingerprint(der);
        self.ensure_parsed(&fp, &[der], &|| false).then_some(fp)
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

    /// The certificate `fp`. With `host`, the verdict that host last got for exactly this
    /// certificate; otherwise (or when that host presented another one) a host-independent
    /// verdict from the validity period alone, which says nothing about trust or name.
    pub fn info(&self, fp: &str, host: Option<&str>) -> Option<CertInfo> {
        let fp = fp.to_ascii_lowercase();
        let p = self.parsed.get(&fp)?;
        let rec = host
            .and_then(|h| self.hosts.get(&host_key(h)))
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

    /// The latest certificate `host` presented, with its verdict.
    pub fn by_host(&self, host: &str) -> Option<CertInfo> {
        let r = self.hosts.get(&host_key(host))?;
        self.info(&r.fp, Some(host))
    }

    /// Fingerprint of a certificate `host` was rejected for at or after `since` (the start of
    /// the failed attempt).
    pub fn invalid_since(&self, host: &str, since: Instant) -> Option<String> {
        self.hosts
            .get(&host_key(host))
            .filter(|r| r.verdict == Verdict::Invalid && r.at >= since)
            .map(|r| r.fp.clone())
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
        let fp1 = s.record("A.test", &[d.as_slice()], Ok(()), NO_EV).unwrap();
        let fp2 = s.record("b.test", &[d.as_slice()], Ok(()), NO_EV).unwrap();
        assert_eq!(fp1, fp2);
        assert_eq!(fp1, fingerprint(&d));
        assert_eq!(s.len(), 1);
        assert!(
            s.by_host("a.test").is_none(),
            "unconfirmed ok is not served"
        );
        s.confirm(&fp1);
        let info = s.by_host("a.test").unwrap();
        assert_eq!(info.sans, vec!["a.test".to_string()]);
        assert_eq!(info.verdict, Verdict::Ok);
        assert_eq!(info.chain.len(), 1);
        assert_eq!(s.by_host("b.test").unwrap().fp, fp1);
        assert!(s.info(&fp1.to_uppercase(), None).is_some());
    }

    #[test]
    fn another_hosts_failure_never_changes_a_verdict() {
        let s = CertStore::default();
        let d = cert("bank.test");
        let fp = s
            .record("bank.test", &[d.as_slice()], Ok(()), NO_EV)
            .unwrap();
        s.confirm(&fp);
        // evil.test replays bank.test's public chain and is rejected.
        s.record(
            "evil.test",
            &[d.as_slice()],
            Err((FailReason::NameMismatch, "bad name".into())),
            NO_EV,
        );
        assert_eq!(s.info(&fp, Some("bank.test")).unwrap().verdict, Verdict::Ok);
        let evil = s.info(&fp, Some("evil.test")).unwrap();
        assert_eq!(evil.reason, Some(FailReason::NameMismatch));
        // Without a host, only the validity period speaks.
        assert_eq!(s.info(&fp, None).unwrap().verdict, Verdict::Ok);
    }

    #[test]
    fn replayed_chain_without_a_valid_signature_is_never_confirmed() {
        let s = CertStore::default();
        let d = cert("bank.test");
        s.record("bank.test", &[d.as_slice()], Ok(()), NO_EV)
            .unwrap();
        // The signature check never succeeds: nothing is served.
        assert!(s.by_host("bank.test").is_none());
    }

    #[test]
    fn invalid_since_needs_a_fresh_invalid_record() {
        let s = CertStore::default();
        let d = cert("a.test");
        let before = Instant::now();
        s.record(
            "[::1]",
            &[d.as_slice()],
            Err((FailReason::Expired, "x".into())),
            NO_EV,
        );
        assert!(
            s.invalid_since("::1", before).is_some(),
            "IPv6 spellings meet"
        );
        assert!(s.invalid_since("::1", Instant::now()).is_none(), "stale");
        assert!(s.invalid_since("other.test", before).is_none());
    }

    #[test]
    fn host_keys_are_canonical() {
        assert_eq!(host_key("Example.COM."), "example.com");
        assert_eq!(host_key("example.com:8443"), "example.com");
        assert_eq!(host_key("[2001:db8::1]:443"), "2001:db8::1");
        assert_eq!(host_key("2001:db8::1"), "2001:db8::1");
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
        let s = CertStore::new(1024, 16);
        s.record("big.test", &[d.as_slice()], Ok(()), NO_EV)
            .unwrap();
        s.confirm(&fingerprint(&d));
        let info = s.by_host("big.test");
        if let Some(i) = info {
            assert!(i.sans.len() <= MAX_SANS);
            assert!(i.sans.iter().all(|x| x.len() <= MAX_STR));
        }
        // The entry outweighs the whole budget, so it is evicted instead of held.
        assert!(s.len() <= 1);
        let roomy = CertStore::default();
        roomy
            .record("big.test", &[d.as_slice()], Ok(()), NO_EV)
            .unwrap();
        roomy.confirm(&fingerprint(&d));
        let i = roomy.by_host("big.test").unwrap();
        assert_eq!(i.sans.len(), MAX_SANS);
    }

    #[test]
    fn garbage_is_not_stored() {
        let s = CertStore::default();
        assert!(s
            .record("a.test", &[b"nope".as_slice()], Ok(()), NO_EV)
            .is_none());
        assert!(s.record("a.test", &[], Ok(()), NO_EV).is_none());
        assert!(s.by_host("a.test").is_none());
    }
}

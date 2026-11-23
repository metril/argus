//! Upstream server certificates seen by the proxy, kept so users can inspect the REAL origin
//! certificate (the certificate a client sees is Argus's minted leaf).
//!
//! Two size-capped caches: parsed [`CertInfo`] by SHA-256 fingerprint of the leaf, and host to the
//! latest fingerprint. A certificate is parsed only the first time its fingerprint is seen.

use std::time::Duration;

use moka::sync::Cache;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Default capacity of each cache.
pub const DEFAULT_CAPACITY: u64 = 4096;
/// Most chain entries parsed per handshake.
const MAX_CHAIN: usize = 10;
/// Entries not touched for this long are dropped.
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

/// The two caches.
pub struct CertStore {
    by_fp: Cache<String, std::sync::Arc<CertInfo>>,
    by_host: Cache<String, String>,
}

impl std::fmt::Debug for CertStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertStore").finish_non_exhaustive()
    }
}

impl Default for CertStore {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
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
    pub fn new(capacity: u64) -> Self {
        Self {
            by_fp: Cache::builder()
                .max_capacity(capacity)
                .time_to_idle(TTL_IDLE)
                .build(),
            by_host: Cache::builder()
                .max_capacity(capacity)
                .time_to_idle(TTL_IDLE)
                .build(),
        }
    }

    /// Record the chain a host presented (leaf first) and the verification result. Returns the
    /// leaf fingerprint. The chain is parsed only when the fingerprint is new; a known one just
    /// gets its verdict refreshed (the verdict depends on the host and the time).
    pub fn record(
        &self,
        host: &str,
        chain_der: &[&[u8]],
        result: Result<(), (FailReason, String)>,
        ev: &dyn Fn() -> bool,
    ) -> Option<String> {
        let leaf = chain_der.first()?;
        let fp = fingerprint(leaf);
        let (verdict, reason, detail) = match result {
            Ok(()) => (Verdict::Ok, None, None),
            Err((r, d)) => (Verdict::Invalid, Some(r), Some(d)),
        };
        match self.by_fp.get(&fp) {
            Some(known) if known.verdict == verdict && known.reason == reason => {}
            Some(known) => {
                let mut next = (*known).clone();
                next.verdict = verdict;
                next.reason = reason;
                next.detail = detail;
                self.by_fp.insert(fp.clone(), std::sync::Arc::new(next));
            }
            None => {
                let info = Self::parse(&fp, chain_der, verdict, reason, detail, ev())?;
                self.by_fp.insert(fp.clone(), std::sync::Arc::new(info));
            }
        }
        self.by_host.insert(host.to_ascii_lowercase(), fp.clone());
        Some(fp)
    }

    fn parse(
        fp: &str,
        chain_der: &[&[u8]],
        verdict: Verdict,
        reason: Option<FailReason>,
        detail: Option<String>,
        ev: bool,
    ) -> Option<CertInfo> {
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
                        GeneralName::DNSName(d) => Some((*d).to_string()),
                        GeneralName::IPAddress(b) => ip_text(b),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let chain = chain_der
            .iter()
            .take(MAX_CHAIN)
            .filter_map(|der| {
                let (_, c) = x509_parser::parse_x509_certificate(der).ok()?;
                Some(ChainEntry {
                    subject: c.subject().to_string(),
                    issuer: c.issuer().to_string(),
                    not_before: ts(c.validity().not_before),
                    not_after: ts(c.validity().not_after),
                    fp: fingerprint(der),
                })
            })
            .collect();
        Some(CertInfo {
            fp: fp.to_string(),
            subject: leaf.subject().to_string(),
            issuer: leaf.issuer().to_string(),
            serial: leaf.raw_serial_as_string(),
            not_before: ts(leaf.validity().not_before),
            not_after: ts(leaf.validity().not_after),
            sans,
            chain,
            verdict,
            reason,
            detail,
            ev,
        })
    }

    /// The certificate with this (lowercase hex SHA-256) fingerprint.
    pub fn get(&self, fp: &str) -> Option<std::sync::Arc<CertInfo>> {
        self.by_fp.get(&fp.to_ascii_lowercase())
    }

    /// Fingerprint of the latest certificate `host` presented.
    pub fn fp_for_host(&self, host: &str) -> Option<String> {
        self.by_host.get(&host.to_ascii_lowercase())
    }

    /// The latest certificate `host` presented.
    pub fn by_host(&self, host: &str) -> Option<std::sync::Arc<CertInfo>> {
        self.get(&self.fp_for_host(host)?)
    }

    /// Number of distinct certificates held (after pending maintenance).
    pub fn len(&self) -> u64 {
        self.by_fp.run_pending_tasks();
        self.by_fp.entry_count()
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

    #[test]
    fn dedupes_by_fingerprint_and_links_hosts() {
        let s = CertStore::new(8);
        let d = cert("a.test");
        let fp1 = s
            .record("A.test", &[d.as_slice()], Ok(()), &|| false)
            .unwrap();
        let fp2 = s
            .record("b.test", &[d.as_slice()], Ok(()), &|| false)
            .unwrap();
        assert_eq!(fp1, fp2);
        assert_eq!(fp1, fingerprint(&d));
        assert_eq!(s.len(), 1);
        let info = s.by_host("a.test").unwrap();
        assert_eq!(info.sans, vec!["a.test".to_string()]);
        assert_eq!(info.verdict, Verdict::Ok);
        assert_eq!(info.chain.len(), 1);
        assert_eq!(s.fp_for_host("b.test").unwrap(), fp1);
        assert!(s.get(&fp1.to_uppercase()).is_some());
    }

    #[test]
    fn verdict_is_refreshed_for_a_known_fingerprint() {
        let s = CertStore::new(8);
        let d = cert("a.test");
        let fp = s
            .record("a.test", &[d.as_slice()], Ok(()), &|| false)
            .unwrap();
        s.record(
            "c.test",
            &[d.as_slice()],
            Err((FailReason::NameMismatch, "bad name".into())),
            &|| false,
        );
        let i = s.get(&fp).unwrap();
        assert_eq!(i.verdict, Verdict::Invalid);
        assert_eq!(i.reason, Some(FailReason::NameMismatch));
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn garbage_is_not_stored() {
        let s = CertStore::new(8);
        assert!(s
            .record("a.test", &[b"nope".as_slice()], Ok(()), &|| false)
            .is_none());
        assert!(s.record("a.test", &[], Ok(()), &|| false).is_none());
        assert!(s.by_host("a.test").is_none());
    }
}

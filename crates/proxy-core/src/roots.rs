//! The trusted root set: the compiled-in Mozilla bundle as a floor, replaced live by a signed
//! `roots.json` from the first-party argus-lists release.
//!
//! One active set serves both verification (the trust anchors) and chain display (each anchor's
//! genuine certificate, found by one hash probe on its (subject, key)). It is swapped atomically;
//! a handshake loads it once and a pooled connection simply finishes on the set it started with.
//!
//! Per root the signed file can carry a `distrust_after` date (leaf `notBefore`), a
//! `sct_not_after` date (the leaf must carry a valid Certificate Transparency receipt logged by
//! then) and `permitted_dns_names` (name constraints). They are enforced on every chain anchored
//! at that root, in the same single verification pass; roots without any rule cost nothing extra.

use std::borrow::Cow;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use base64::Engine;
use common::certstore::{RootsStatus, RootsStatusCell};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::sct::{CtLog, LogState};
use crate::{Error, Result};

/// Serial of the compiled-in set (a date-based serial, like the published sets). A signed set
/// must have a strictly greater serial; raise this with each release that ships a newer floor.
pub const FLOOR_SERIAL: u64 = 2026112300;
/// Fewest roots a signed set may hold (a near-empty set would break TLS everywhere). The set is
/// the stricter of Mozilla and Chrome, so it holds fewer roots than the Mozilla bundle alone.
pub const MIN_ROOTS: usize = 50;
/// Most roots and logs read from a signed file.
const MAX_ROOTS: usize = 2000;
const MAX_LOGS: usize = 1000;
/// Between successful checks (as the first-party lists).
const CHECK_EVERY: Duration = Duration::from_secs(6 * 3600);

// ---------------------------------------------------------------- roots.json

#[derive(Debug, Deserialize)]
struct RootsFile {
    schema: u32,
    serial: u64,
    #[serde(default)]
    generated_at: Option<String>,
    roots: Vec<RootJson>,
    #[serde(default)]
    ct_logs: Vec<LogJson>,
}

#[derive(Debug, Deserialize)]
struct RootJson {
    sha256: String,
    #[serde(default)]
    subject: String,
    der: String,
    #[serde(default)]
    distrust_after: Option<String>,
    #[serde(default)]
    sct_not_after: Option<String>,
    #[serde(default)]
    permitted_dns_names: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct LogJson {
    log_id: String,
    key: String,
    state: String,
    state_since: String,
    #[serde(default)]
    temporal_interval: Option<IntervalJson>,
}

#[derive(Debug, Deserialize)]
struct IntervalJson {
    start: String,
    end: String,
}

/// One root of a validated set.
#[derive(Debug, Clone)]
pub struct RootEntry {
    der: Cow<'static, [u8]>,
    /// Unix seconds: a leaf with a later `notBefore` is refused.
    distrust_after: Option<i64>,
    /// Unix seconds: a leaf needs a valid receipt logged no later than this.
    sct_not_after: Option<i64>,
    /// Lowercase DNS suffixes the root may issue for; empty means unconstrained.
    permitted_dns: Vec<String>,
}

impl RootEntry {
    fn bundled(der: &'static [u8]) -> Self {
        Self {
            der: Cow::Borrowed(der),
            distrust_after: None,
            sct_not_after: None,
            permitted_dns: Vec::new(),
        }
    }

    fn has_rules(&self) -> bool {
        self.distrust_after.is_some()
            || self.sct_not_after.is_some()
            || !self.permitted_dns.is_empty()
    }
}

/// A validated signed set.
#[derive(Debug)]
pub struct RootsData {
    pub serial: u64,
    pub generated_at: Option<String>,
    roots: Vec<RootEntry>,
    ct_logs: Vec<CtLog>,
}

impl RootsData {
    pub fn root_count(&self) -> usize {
        self.roots.len()
    }

    /// Parse and validate `bytes`: schema 1, every certificate parses and matches its digest, at
    /// least [`MIN_ROOTS`] roots, well-formed logs. The signature and the serial are the
    /// caller's to check.
    pub fn parse(bytes: &[u8]) -> std::result::Result<Self, String> {
        let f: RootsFile = serde_json::from_slice(bytes).map_err(|e| format!("roots.json: {e}"))?;
        if f.schema != 1 {
            return Err(format!("roots.json: unsupported schema {}", f.schema));
        }
        if f.roots.len() < MIN_ROOTS {
            return Err(format!(
                "roots.json has {} roots; at least {MIN_ROOTS} are required",
                f.roots.len()
            ));
        }
        if f.roots.len() > MAX_ROOTS || f.ct_logs.len() > MAX_LOGS {
            return Err("roots.json is implausibly large".into());
        }
        let b64 = base64::engine::general_purpose::STANDARD;
        let time = |t: &str, what: &str| -> std::result::Result<i64, String> {
            chrono::DateTime::parse_from_rfc3339(t)
                .map(|d| d.timestamp())
                .map_err(|_| format!("roots.json: bad {what} {t:?}"))
        };
        let mut roots = Vec::with_capacity(f.roots.len());
        for r in &f.roots {
            let der = b64
                .decode(r.der.trim())
                .map_err(|_| format!("root {:?}: bad base64", r.subject))?;
            let digest: String = Sha256::digest(&der)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            if !digest.eq_ignore_ascii_case(r.sha256.trim()) {
                return Err(format!(
                    "root {:?}: digest does not match its certificate",
                    r.subject
                ));
            }
            x509_parser::parse_x509_certificate(&der)
                .map_err(|_| format!("root {:?}: not a certificate", r.subject))?;
            webpki::anchor_from_trusted_cert(&CertificateDer::from(der.as_slice()))
                .map_err(|_| format!("root {:?}: unusable as a trust anchor", r.subject))?;
            let opt =
                |t: &Option<String>, what: &str| -> std::result::Result<Option<i64>, String> {
                    t.as_deref().map(|t| time(t, what)).transpose()
                };
            roots.push(RootEntry {
                der: Cow::Owned(der),
                distrust_after: opt(&r.distrust_after, "distrust_after")?,
                sct_not_after: opt(&r.sct_not_after, "sct_not_after")?,
                permitted_dns: r
                    .permitted_dns_names
                    .iter()
                    .map(|n| n.trim().trim_start_matches('.').to_ascii_lowercase())
                    .filter(|n| !n.is_empty())
                    .collect(),
            });
        }
        let mut ct_logs = Vec::with_capacity(f.ct_logs.len());
        for l in &f.ct_logs {
            let key = b64
                .decode(l.key.trim())
                .map_err(|_| "ct log: bad key".to_string())?;
            let id = b64
                .decode(l.log_id.trim())
                .map_err(|_| "ct log: bad log_id".to_string())?;
            let want: [u8; 32] = Sha256::digest(&key).into();
            if id.as_slice() != want {
                return Err("ct log: log_id is not the hash of its key".into());
            }
            let state = match l.state.as_str() {
                "usable" => LogState::Usable,
                "qualified" => LogState::Qualified,
                "readonly" => LogState::ReadOnly,
                "retired" => LogState::Retired,
                // pending, rejected or a state added later: not a log whose receipts count.
                _ => continue,
            };
            ct_logs.push(CtLog {
                id: want,
                key,
                state,
                state_since: time(&l.state_since, "state_since")?,
                interval: l
                    .temporal_interval
                    .as_ref()
                    .map(|i| {
                        Ok::<_, String>((
                            time(&i.start, "interval start")?,
                            time(&i.end, "interval end")?,
                        ))
                    })
                    .transpose()?,
            });
        }
        Ok(Self {
            serial: f.serial,
            generated_at: f.generated_at,
            roots,
            ct_logs,
        })
    }
}

// ---------------------------------------------------------------- active set

/// Why a chain was refused although its path verified.
#[derive(Debug)]
pub struct Distrusted(pub String);

impl std::fmt::Display for Distrusted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Distrusted {}

fn distrusted(msg: impl Into<String>) -> rustls::Error {
    rustls::Error::InvalidCertificate(rustls::CertificateError::Other(rustls::OtherError(
        Arc::new(Distrusted(msg.into())),
    )))
}

type Index = HashMap<Vec<u8>, RootEntry>;

fn key(subject: &[u8], spki: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(4 + subject.len() + spki.len());
    k.extend_from_slice(&(subject.len() as u32).to_be_bytes());
    k.extend_from_slice(subject);
    k.extend_from_slice(spki);
    k
}

fn index_insert(index: &mut Index, entry: RootEntry) {
    if let Ok(a) = webpki::anchor_from_trusted_cert(&CertificateDer::from(entry.der.as_ref())) {
        index.insert(
            key(a.subject.as_ref(), a.subject_public_key_info.as_ref()),
            entry,
        );
    }
}

/// The compiled-in Mozilla bundle (`webpki-root-certs`, the same release as `webpki-roots`),
/// indexed once per process and shared by every floor set. The data is `'static`: not copied.
fn floor_index() -> Arc<Index> {
    static FLOOR: std::sync::OnceLock<Arc<Index>> = std::sync::OnceLock::new();
    FLOOR
        .get_or_init(|| {
            let mut m = Index::new();
            for c in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
                index_insert(&mut m, RootEntry::bundled(c.as_ref()));
            }
            Arc::new(m)
        })
        .clone()
}

/// A root set in force: trust anchors for verification and the certificates behind them.
pub struct ActiveRoots {
    store: rustls::RootCertStore,
    base: Arc<Index>,
    extra: Index,
    ct_logs: HashMap<[u8; 32], CtLog>,
    /// Any root with a rule: only then does a handshake look at the leaf's dates and names.
    pub serial: u64,
    pub root_count: usize,
    pub signed: bool,
    algs: rustls::crypto::WebPkiSupportedAlgorithms,
    /// Verified receipt results per leaf fingerprint: earliest valid timestamp, in ms.
    sct_cache: moka::sync::Cache<String, Option<u64>>,
}

/// The DER certificates of PEM files of extra CAs, read once.
pub fn load_extras(extra_ca_paths: &[PathBuf]) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    for path in extra_ca_paths {
        let pem = std::fs::read(path).map_err(|e| {
            Error::Config(format!(
                "Failed to read upstream CA {}: {e}",
                path.display()
            ))
        })?;
        let mut n = 0;
        for cert in rustls_pemfile::certs(&mut pem.as_slice()) {
            let cert = cert.map_err(|e| {
                Error::Config(format!("Invalid upstream CA {}: {e}", path.display()))
            })?;
            out.push(cert.as_ref().to_vec());
            n += 1;
        }
        if n == 0 {
            return Err(Error::Config(format!(
                "Upstream CA {} contains no PEM certificates",
                path.display()
            )));
        }
    }
    Ok(out)
}

fn add_extras(
    ders: &[Vec<u8>],
    store: &mut rustls::RootCertStore,
    extra: &mut Index,
) -> Result<()> {
    for der in ders {
        store
            .add(CertificateDer::from(der.clone()))
            .map_err(|e| Error::Config(format!("Invalid upstream CA: {e}")))?;
        index_insert(extra, RootEntry::bundled_owned(der.clone()));
    }
    Ok(())
}

impl RootEntry {
    fn bundled_owned(der: Vec<u8>) -> Self {
        Self {
            der: Cow::Owned(der),
            distrust_after: None,
            sct_not_after: None,
            permitted_dns: Vec::new(),
        }
    }
}

impl ActiveRoots {
    fn new(
        store: rustls::RootCertStore,
        base: Arc<Index>,
        extra: Index,
        data: Option<&RootsData>,
        root_count: usize,
    ) -> Self {
        Self {
            store,
            base,
            extra,
            ct_logs: data
                .map(|d| d.ct_logs.iter().map(|l| (l.id, l.clone())).collect())
                .unwrap_or_default(),
            serial: data.map_or(FLOOR_SERIAL, |d| d.serial),
            root_count,
            signed: data.is_some(),
            algs: rustls::crypto::ring::default_provider().signature_verification_algorithms,
            sct_cache: moka::sync::Cache::builder().max_capacity(4096).build(),
        }
    }

    /// The compiled-in set plus the extra CAs.
    pub fn floor(extra_ca_paths: &[PathBuf]) -> Result<Self> {
        Self::floor_with(&load_extras(extra_ca_paths)?)
    }

    /// The compiled-in set plus already-read extra CAs.
    pub fn floor_with(extras: &[Vec<u8>]) -> Result<Self> {
        let mut store = rustls::RootCertStore::empty();
        store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut extra = Index::new();
        add_extras(extras, &mut store, &mut extra)?;
        let n = webpki_roots::TLS_SERVER_ROOTS.len();
        Ok(Self::new(store, floor_index(), extra, None, n))
    }

    /// A signed set plus the extra CAs.
    pub fn from_data(data: &RootsData, extras: &[Vec<u8>]) -> Result<Self> {
        let mut store = rustls::RootCertStore::empty();
        let mut base = Index::new();
        for r in &data.roots {
            let cert = CertificateDer::from(r.der.as_ref());
            let anchor = webpki::anchor_from_trusted_cert(&cert)
                .map_err(|e| Error::Config(format!("root unusable: {e}")))?;
            store.roots.push(anchor.to_owned());
            index_insert(&mut base, r.clone());
        }
        let mut extra = Index::new();
        add_extras(extras, &mut store, &mut extra)?;
        Ok(Self::new(
            store,
            Arc::new(base),
            extra,
            Some(data),
            data.roots.len(),
        ))
    }

    /// The trust anchors, for clients that verify on their own.
    pub fn store(&self) -> &rustls::RootCertStore {
        &self.store
    }

    fn entry(&self, anchor: &rustls::pki_types::TrustAnchor<'_>) -> Option<&RootEntry> {
        let k = key(
            anchor.subject.as_ref(),
            anchor.subject_public_key_info.as_ref(),
        );
        // The set's own entry first: an extra CA identical to a public root must not drop that
        // root's rules.
        self.base.get(&k).or_else(|| self.extra.get(&k))
    }

    /// The genuine certificate of the root `anchor`, if it is in this set. One hash probe.
    pub fn root_der(&self, anchor: &rustls::pki_types::TrustAnchor<'_>) -> Option<&[u8]> {
        self.entry(anchor).map(|e| e.der.as_ref())
    }

    /// Verify the chain presented for `server_name`, once: the path to a trust anchor of this
    /// set, the name, then the anchor's own rules (distrust date, name constraints,
    /// Certificate Transparency). Returns the verified path as DER, leaf first, ending with the
    /// anchor's genuine certificate when it is known; nothing is copied.
    ///
    /// On failure the error is the one the standard verifier gives (so reasons stay accurate),
    /// or [`Distrusted`] for a rule of the signed set.
    pub fn verify<'a>(
        &'a self,
        end_entity: &'a CertificateDer<'a>,
        intermediates: &'a [CertificateDer<'a>],
        server_name: &ServerName<'_>,
        now: UnixTime,
    ) -> std::result::Result<Vec<&'a [u8]>, rustls::Error> {
        let standard = || -> rustls::Error {
            // Re-run the standard check only to name the failure exactly as rustls does.
            let parsed = match rustls::server::ParsedCertificate::try_from(end_entity) {
                Ok(p) => p,
                Err(e) => return e,
            };
            match rustls::client::verify_server_cert_signed_by_trust_anchor(
                &parsed,
                &self.store,
                intermediates,
                now,
                self.algs.all,
            )
            .and_then(|()| rustls::client::verify_server_name(&parsed, server_name))
            {
                Err(e) => e,
                Ok(()) => rustls::Error::General("certificate verification failed".into()),
            }
        };
        let ee = webpki::EndEntityCert::try_from(end_entity).map_err(|_| standard())?;
        // The anchor's rules run inside the path search: a path that breaks them is rejected
        // and webpki keeps looking (another intermediate, another anchor).
        let rule_err: std::cell::RefCell<Option<rustls::Error>> = Default::default();
        let rules = |p: &webpki::VerifiedPath<'_>| -> std::result::Result<(), webpki::Error> {
            let Some(entry) = self.entry(p.anchor()) else {
                return Ok(());
            };
            if !entry.has_rules() {
                return Ok(());
            }
            let first = p.intermediate_certificates().next().map(|c| c.der());
            let issuer = first.as_ref().map_or(entry.der.as_ref(), |d| d.as_ref());
            match self.enforce(entry, end_entity.as_ref(), issuer, now) {
                Ok(()) => Ok(()),
                Err(e) => {
                    *rule_err.borrow_mut() = Some(e);
                    Err(webpki::Error::UnknownIssuer)
                }
            }
        };
        let path = match ee.verify_for_usage(
            self.algs.all,
            &self.store.roots,
            intermediates,
            now,
            webpki::KeyUsage::server_auth(),
            None,
            Some(&rules),
        ) {
            Ok(p) => p,
            // Every path failed: name a rule that rejected one, else the standard reason.
            Err(_) => return Err(rule_err.take().unwrap_or_else(standard)),
        };
        ee.verify_is_valid_for_subject_name(server_name)
            .map_err(|_| standard())?;

        let mut out: Vec<&'a [u8]> = vec![end_entity.as_ref()];
        for c in path.intermediate_certificates() {
            // Each is one of `intermediates` (the path only borrows them).
            let der = c.der();
            let found = intermediates
                .iter()
                .find(|i| i.as_ref() == der.as_ref())
                .ok_or_else(standard)?;
            out.push(found.as_ref());
        }
        if let Some(entry) = self.entry(path.anchor()) {
            out.push(entry.der.as_ref());
        }
        Ok(out)
    }

    /// The anchor's rules for a candidate path: the leaf and its issuer (the first intermediate
    /// or the root itself).
    fn enforce(
        &self,
        root: &RootEntry,
        leaf_der: &[u8],
        issuer: &[u8],
        now: UnixTime,
    ) -> std::result::Result<(), rustls::Error> {
        let (_, leaf) = x509_parser::parse_x509_certificate(leaf_der)
            .map_err(|_| distrusted("leaf certificate cannot be read"))?;
        if let Some(limit) = root.distrust_after {
            if leaf.validity().not_before.timestamp() > limit {
                return Err(distrusted(
                    "the issuing root no longer vouches for certificates issued this late",
                ));
            }
        }
        if !root.permitted_dns.is_empty() {
            use x509_parser::extensions::GeneralName;
            let sans = leaf.subject_alternative_name().ok().flatten();
            for g in sans.iter().flat_map(|e| e.value.general_names.iter()) {
                match g {
                    GeneralName::DNSName(d) => {
                        let n = d
                            .to_ascii_lowercase()
                            .trim_start_matches("*.")
                            .trim_end_matches('.')
                            .to_string();
                        if n.is_empty() {
                            return Err(distrusted("the certificate has an empty DNS name"));
                        }
                        let allowed = root
                            .permitted_dns
                            .iter()
                            .any(|p| n == *p || n.ends_with(&format!(".{p}")));
                        if !allowed {
                            return Err(distrusted(format!(
                                "the issuing root may not issue for {n} (name constraint)"
                            )));
                        }
                    }
                    // An address is outside any DNS constraint: refuse it.
                    GeneralName::IPAddress(_) => {
                        return Err(distrusted(
                            "the issuing root may not issue for IP addresses (name constraint)",
                        ))
                    }
                    _ => {}
                }
            }
        }
        // Until the date has passed, the receipt rule is not in force yet.
        if let Some(limit) = root
            .sct_not_after
            .filter(|l| i64::try_from(now.as_secs()).is_ok_and(|n| n > *l))
        {
            let fp = common::certstore::fingerprint(leaf_der);
            let earliest = self.sct_cache.get_with(fp, || {
                let spki = x509_parser::parse_x509_certificate(issuer)
                    .ok()
                    .map(|(_, c)| c.public_key().raw.to_vec())?;
                crate::sct::earliest_valid_sct_ms(leaf_der, &spki, &self.ct_logs)
            });
            match earliest {
                Some(ms) if i64::try_from(ms / 1000).is_ok_and(|s| s <= limit) => {}
                Some(_) => {
                    return Err(distrusted(
                        "the certificate was logged too late for the issuing root",
                    ))
                }
                None => {
                    return Err(distrusted(
                        "no valid Certificate Transparency receipt for the issuing root",
                    ))
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------- live handle

/// What the active set is built from: the signed data (if any) and the extra CAs, read once.
struct HandleState {
    data: Option<Arc<RootsData>>,
    extras: Vec<Vec<u8>>,
}

/// The active root set, swappable at any time, with its status.
pub struct RootsHandle {
    active: ArcSwap<ActiveRoots>,
    state: parking_lot::Mutex<HandleState>,
    pub cell: Arc<RootsStatusCell>,
}

impl RootsHandle {
    /// Start on the compiled-in floor plus the extra CAs.
    pub fn floor(extra_ca_paths: &[PathBuf]) -> Result<Arc<Self>> {
        let extras = load_extras(extra_ca_paths)?;
        let a = ActiveRoots::floor_with(&extras)?;
        let cell = Arc::new(RootsStatusCell::default());
        *cell.status.write() = RootsStatus {
            serial: a.serial,
            roots: a.root_count,
            signed: false,
            ..Default::default()
        };
        Ok(Arc::new(Self {
            active: ArcSwap::from_pointee(a),
            state: parking_lot::Mutex::new(HandleState { data: None, extras }),
            cell,
        }))
    }

    /// The set in force: one atomic load.
    pub fn load(&self) -> arc_swap::Guard<Arc<ActiveRoots>> {
        self.active.load()
    }

    /// The set in force, owned.
    pub fn load_full(&self) -> Arc<ActiveRoots> {
        self.active.load_full()
    }

    /// Serial of the set in force.
    pub fn serial(&self) -> u64 {
        self.active.load().serial
    }

    /// Replace the set with a validated one. Fails (changing nothing) unless its serial is
    /// greater than the one in force and the floor.
    pub fn install(&self, data: Arc<RootsData>) -> std::result::Result<(), String> {
        let mut st = self.state.lock();
        let cur = self.serial();
        if data.serial <= cur || data.serial <= FLOOR_SERIAL {
            return Err(format!(
                "serial {} is not newer than {} (the one in force); not installing it",
                data.serial, cur
            ));
        }
        let next = ActiveRoots::from_data(&data, &st.extras).map_err(|e| e.to_string())?;
        let (serial, roots) = (next.serial, next.root_count);
        self.active.store(Arc::new(next));
        st.data = Some(data);
        let mut s = self.cell.status.write();
        s.serial = serial;
        s.roots = roots;
        s.signed = true;
        s.updated_at = Some(chrono::Utc::now().to_rfc3339());
        s.last_error = None;
        Ok(())
    }

    /// First half of a live change of the extra CA files: read and check them. No side effects;
    /// the result is applied with [`Self::commit_extras`].
    pub fn prepare_extras(&self, extra_ca_paths: &[PathBuf]) -> Result<Vec<Vec<u8>>> {
        let ders = load_extras(extra_ca_paths)?;
        // Make sure every certificate is usable, so the commit cannot fail.
        ActiveRoots::floor_with(&ders)?;
        Ok(ders)
    }

    /// Second half: rebuild the active set from the current data with these extra CAs and swap
    /// it in.
    pub fn commit_extras(&self, extras: Vec<Vec<u8>>) {
        let mut st = self.state.lock();
        if st.extras == extras {
            return;
        }
        let next = match &st.data {
            Some(d) => ActiveRoots::from_data(d, &extras),
            None => ActiveRoots::floor_with(&extras),
        };
        match next {
            Ok(n) => {
                self.active.store(Arc::new(n));
                st.extras = extras;
            }
            Err(e) => tracing::warn!("trusted roots: extra CAs not applied: {e}"),
        }
    }

    /// Prepare and commit in one step (tests, and callers with nothing to roll back).
    pub fn set_extras(&self, extra_ca_paths: &[PathBuf]) -> Result<()> {
        self.commit_extras(self.prepare_extras(extra_ca_paths)?);
        Ok(())
    }
}

// ---------------------------------------------------------------- verifiers

/// The TLS server verifier of every upstream dial: standard verification against the live set,
/// optionally recording the verified chain for display.
pub struct LiveVerifier {
    handle: Arc<RootsHandle>,
    store: Option<Arc<common::certstore::CertStore>>,
    algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl std::fmt::Debug for LiveVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveVerifier").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for RootsHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RootsHandle").finish_non_exhaustive()
    }
}

impl LiveVerifier {
    pub fn new(handle: Arc<RootsHandle>, store: Option<Arc<common::certstore::CertStore>>) -> Self {
        Self {
            handle,
            store,
            algs: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for LiveVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // One atomic load per handshake; a swap mid-flight cannot tear it.
        let active = self.handle.load();
        let path = active.verify(end_entity, intermediates, server_name, now)?;
        if let Some(store) = &self.store {
            if store.wants_chain(end_entity.as_ref(), 1 + intermediates.len()) {
                store.record_chain(&path, &|| crate::ev::is_ev_der(end_entity.as_ref()));
            }
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algs.supported_schemes()
    }
}

// ---------------------------------------------------------------- subscription

/// Fetches, verifies and installs the signed root set; keeps the verified copy on the data
/// volume next to the first-party lists.
pub struct RootsManager {
    handle: Arc<RootsHandle>,
    svc: Option<Arc<list_service::ListService>>,
    base_url: String,
    public_key: String,
    cache_dir: Option<PathBuf>,
    /// Highest serial ever accepted, kept apart from the cache so it outlives it.
    min_serial: std::sync::atomic::AtomicU64,
    /// One check at a time.
    busy: tokio::sync::Mutex<()>,
}

/// What a check did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootsOutcome {
    Installed { serial: u64 },
    Current { serial: u64 },
}

fn atomic_write(path: &Path, bytes: &[u8]) -> std::result::Result<(), String> {
    common::config::write_atomic(path, bytes).map_err(|e| e.to_string())
}

impl RootsManager {
    pub fn new(
        handle: Arc<RootsHandle>,
        svc: Arc<list_service::ListService>,
        cfg: &list_service::ArgusConfig,
    ) -> Arc<Self> {
        Arc::new(Self {
            handle,
            svc: Some(svc),
            base_url: cfg.base_url.clone(),
            public_key: cfg.public_key.clone(),
            cache_dir: cfg.cache_dir.clone(),
            min_serial: Default::default(),
            busy: tokio::sync::Mutex::new(()),
        })
    }

    fn url(&self, file: &str) -> String {
        format!("{}/{file}", self.base_url.trim_end_matches('/'))
    }

    /// Check the signature and the content of a fetched or cached copy.
    fn check(&self, bytes: &[u8], sig: &str) -> std::result::Result<RootsData, String> {
        list_service::verify_minisign(&self.public_key, bytes, sig)
            .map_err(|e| format!("roots.json: {e}"))?;
        RootsData::parse(bytes)
    }

    /// Load the last good verified copy from the cache, if any (verified again on every load).
    pub fn init_cache(&self) {
        let Some(dir) = &self.cache_dir else {
            return;
        };
        // The highest serial ever accepted: enforced even when the cache itself is gone.
        if let Some(n) = std::fs::read_to_string(dir.join("roots.serial"))
            .ok()
            .and_then(|t| t.trim().parse::<u64>().ok())
        {
            self.min_serial
                .fetch_max(n, std::sync::atomic::Ordering::Relaxed);
        }
        let (Ok(bytes), Ok(sig)) = (
            std::fs::read(dir.join("roots.json")),
            std::fs::read_to_string(dir.join("roots.json.minisig")),
        ) else {
            return;
        };
        let min = self.min_serial.load(std::sync::atomic::Ordering::Relaxed);
        match self.check(&bytes, &sig).and_then(|d| {
            if d.serial < min {
                tracing::warn!(
                    "trusted roots: the cached set (serial {}) is older than the highest ever accepted ({min}); running on the built-in set until the next fetch",
                    d.serial
                );
                return Err(format!(
                    "serial {} is older than {min}, the highest accepted",
                    d.serial
                ));
            }
            self.handle.install(Arc::new(d))
        }) {
            Ok(()) => tracing::info!(
                "trusted roots: serial {} from the cache",
                self.handle.serial()
            ),
            Err(e) => tracing::warn!("trusted roots: ignoring the cached copy: {e}"),
        }
    }

    /// Look for a newer signed set and install it. A bad signature, an invalid file or a serial
    /// that is not newer is refused and leaves the set in force as it was.
    pub async fn refresh(&self) -> std::result::Result<RootsOutcome, String> {
        let _g = self.busy.lock().await;
        let fetched = self.fetch().await;
        self.finish(match fetched {
            Ok((text, sig)) => self.apply(text, sig).await,
            Err(e) => Err(e),
        })
    }

    /// Verify, validate and install a copy that is already in hand (also what tests drive).
    pub async fn refresh_from(
        &self,
        text: String,
        sig: String,
    ) -> std::result::Result<RootsOutcome, String> {
        let _g = self.busy.lock().await;
        self.finish(self.apply(text, sig).await)
    }

    /// Record the outcome of a check in the status.
    fn finish<T>(&self, r: std::result::Result<T, String>) -> std::result::Result<T, String> {
        let mut s = self.handle.cell.status.write();
        s.last_checked = Some(chrono::Utc::now().to_rfc3339());
        match &r {
            Err(e) => s.last_error = Some(e.clone()),
            // A good check ends the earlier failure.
            Ok(_) => s.last_error = None,
        }
        r
    }

    async fn fetch(&self) -> std::result::Result<(String, String), String> {
        let svc = self.svc.as_ref().ok_or("no fetcher")?;
        let text = svc.fetch_exclusion_list(&self.url("roots.json")).await?;
        let sig = svc
            .fetch_exclusion_list(&self.url("roots.json.minisig"))
            .await?;
        Ok((text, sig))
    }

    async fn apply(&self, text: String, sig: String) -> std::result::Result<RootsOutcome, String> {
        let key = self.public_key.clone();
        let (text, sig, data) = tokio::task::spawn_blocking(move || {
            list_service::verify_minisign(&key, text.as_bytes(), &sig)
                .map_err(|e| format!("roots.json: {e}"))?;
            let data = RootsData::parse(text.as_bytes())?;
            Ok::<_, String>((text, sig, data))
        })
        .await
        .map_err(|e| e.to_string())??;
        let cur = self.handle.serial();
        if data.serial == cur && cur > FLOOR_SERIAL {
            return Ok(RootsOutcome::Current { serial: cur });
        }
        // Never go below the highest serial ever accepted (it outlives the cache).
        let min = self.min_serial.load(std::sync::atomic::Ordering::Relaxed);
        if data.serial < min {
            return Err(format!(
                "serial {} is older than {min}, the highest ever accepted; not installing it",
                data.serial
            ));
        }
        let serial = data.serial;
        // The rest of the rollback protection and the build live in `install`.
        self.handle.install(Arc::new(data))?;
        self.min_serial
            .fetch_max(serial, std::sync::atomic::Ordering::Relaxed);
        if let Some(dir) = self.cache_dir.clone() {
            let (t, s) = (text.into_bytes(), sig.into_bytes());
            let written = tokio::task::spawn_blocking(move || {
                // The serial first, then the data, the signature last: a half-written cache
                // fails verification, never lies.
                atomic_write(&dir.join("roots.serial"), serial.to_string().as_bytes())?;
                atomic_write(&dir.join("roots.json"), &t)?;
                atomic_write(&dir.join("roots.json.minisig"), &s)
            })
            .await
            .map_err(|e| e.to_string())
            .and_then(|r| r);
            // The set is already in force: a cache that cannot be written is only a warning.
            if let Err(e) = written {
                tracing::warn!("trusted roots: could not cache serial {serial}: {e}");
            }
        }
        Ok(RootsOutcome::Installed { serial })
    }

    /// Load the cache now, then keep the set current: retry with backoff until the first
    /// success, afterwards every few hours (or when nudged through the status cell).
    pub fn start(self: &Arc<Self>) {
        self.init_cache();
        let this = self.clone();
        tokio::spawn(async move {
            let mut backoff = Duration::from_secs(10);
            loop {
                let wait = match this.refresh().await {
                    Ok(o) => {
                        backoff = Duration::from_secs(10);
                        tracing::info!("trusted roots: {o:?}");
                        CHECK_EVERY
                    }
                    Err(e) => {
                        tracing::warn!("trusted roots: {e}");
                        let w = backoff;
                        backoff = (backoff * 2).min(Duration::from_secs(900));
                        w
                    }
                };
                tokio::select! {
                    _ = tokio::time::sleep(wait) => {}
                    _ = this.handle.cell.wake.notified() => {}
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sct::testkit::{ca, leaf_with_scts, Receipt, TestCa, TestLog};
    use common::certstore::{fingerprint, CertStore, FailReason};
    use rustls::client::danger::ServerCertVerifier;
    use std::io::Cursor;

    const REAL_ROOTS: &[u8] = include_bytes!("../tests/fixtures/roots.json");
    const REAL_SIG: &str = include_str!("../tests/fixtures/roots.json.minisig");
    /// 2023-11-14, the receipt time used by the fixtures (ms).
    const T: u64 = 1_700_000_000_000;

    // ------------------------------------------------------------ signing fixtures

    fn keypair() -> (minisign::PublicKeyBox, minisign::SecretKey) {
        let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        (kp.pk.to_box().unwrap(), kp.sk)
    }

    fn pk_b64(pk: &minisign::PublicKeyBox) -> String {
        pk.to_string().lines().nth(1).unwrap().to_string()
    }

    fn sign(sk: &minisign::SecretKey, pk: &minisign::PublicKeyBox, data: &[u8]) -> String {
        let pk = pk.clone().into_public_key().unwrap();
        minisign::sign(Some(&pk), sk, Cursor::new(data), Some("t"), Some("c"))
            .unwrap()
            .to_string()
    }

    fn b64(b: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(b)
    }

    fn hex(b: &[u8]) -> String {
        Sha256::digest(b)
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect()
    }

    /// One root of a fixture file.
    struct Root {
        der: Vec<u8>,
        distrust_after: Option<&'static str>,
        sct_not_after: Option<&'static str>,
        permitted: Vec<&'static str>,
    }

    impl Root {
        fn plain(der: &[u8]) -> Self {
            Self {
                der: der.to_vec(),
                distrust_after: None,
                sct_not_after: None,
                permitted: vec![],
            }
        }
    }

    /// A signed `roots.json` body: the given roots plus filler roots up to `total`.
    fn roots_json(
        serial: u64,
        roots: &[Root],
        logs: &[(&TestLog, &str, i64)],
        total: usize,
    ) -> String {
        let mut list: Vec<serde_json::Value> = roots
            .iter()
            .map(|r| {
                serde_json::json!({
                    "sha256": hex(&r.der),
                    "subject": "CN=fixture",
                    "der": b64(&r.der),
                    "distrust_after": r.distrust_after,
                    "sct_not_after": r.sct_not_after,
                    "permitted_dns_names": r.permitted,
                })
            })
            .collect();
        while list.len() < total {
            let filler = ca(&format!("filler {}", list.len()));
            list.push(serde_json::json!({
                "sha256": hex(&filler.der), "subject": "CN=filler", "der": b64(&filler.der),
                "distrust_after": null, "sct_not_after": null, "permitted_dns_names": [],
            }));
        }
        let ct_logs: Vec<_> = logs
            .iter()
            .map(|(l, state, since)| {
                serde_json::json!({
                    "log_id": b64(&l.id), "key": b64(&l.spki), "operator": "test",
                    "state": state, "type": "rfc6962",
                    "state_since": chrono::DateTime::from_timestamp(*since, 0).unwrap().to_rfc3339(),
                    "temporal_interval": null,
                })
            })
            .collect();
        serde_json::json!({
            "schema": 1, "serial": serial, "generated_at": "2026-11-23T00:00:00Z",
            "sources": {}, "roots": list, "ct_logs": ct_logs,
        })
        .to_string()
    }

    struct Rig {
        manager: Arc<RootsManager>,
        handle: Arc<RootsHandle>,
        pk: minisign::PublicKeyBox,
        sk: minisign::SecretKey,
        dir: tempfile::TempDir,
    }

    fn rig() -> Rig {
        let (pk, sk) = keypair();
        let dir = tempfile::tempdir().unwrap();
        let handle = RootsHandle::floor(&[]).unwrap();
        let manager = manager_for(&handle, &pk_b64(&pk), dir.path());
        Rig {
            manager,
            handle,
            pk,
            sk,
            dir,
        }
    }

    fn manager_for(handle: &Arc<RootsHandle>, key: &str, cache: &Path) -> Arc<RootsManager> {
        Arc::new(RootsManager {
            handle: handle.clone(),
            svc: None,
            base_url: "http://unused.test".into(),
            public_key: key.to_string(),
            cache_dir: Some(cache.to_path_buf()),
            min_serial: Default::default(),
            busy: tokio::sync::Mutex::new(()),
        })
    }

    impl Rig {
        async fn push(&self, body: &str) -> std::result::Result<RootsOutcome, String> {
            let sig = sign(&self.sk, &self.pk, body.as_bytes());
            self.manager.refresh_from(body.to_string(), sig).await
        }
    }

    /// Run the live verifier like a handshake does.
    fn handshake(
        h: &Arc<RootsHandle>,
        store: Option<&Arc<CertStore>>,
        leaf: &[u8],
        extra: &[Vec<u8>],
        host: &str,
    ) -> std::result::Result<(), rustls::Error> {
        let v = LiveVerifier::new(h.clone(), store.cloned());
        let inter: Vec<_> = extra
            .iter()
            .map(|d| CertificateDer::from(d.clone()))
            .collect();
        v.verify_server_cert(
            &CertificateDer::from(leaf.to_vec()),
            &inter,
            &ServerName::try_from(host.to_string()).unwrap(),
            &[],
            UnixTime::now(),
        )
        .map(|_| ())
    }

    fn reason(e: &rustls::Error) -> FailReason {
        crate::upstream::fail_reason(e)
    }

    // ------------------------------------------------------------ the real file

    #[test]
    fn the_real_published_file_verifies_against_the_compiled_in_key_and_parses() {
        list_service::verify_minisign(common::bypass::ARGUS_LISTS_PUBLIC_KEY, REAL_ROOTS, REAL_SIG)
            .expect("real signature");
        let d = RootsData::parse(REAL_ROOTS).expect("real file parses");
        assert_eq!(d.serial, 2026112302);
        assert_eq!(d.root_count(), 93);
        assert_eq!(d.ct_logs.len(), 89);
        assert!(
            d.serial > FLOOR_SERIAL,
            "the real set is newer than the floor"
        );
        assert!(d.roots.iter().any(|r| r.sct_not_after.is_some()));
        assert!(d.roots.iter().any(|r| r.distrust_after.is_some()));
        // It builds into a working set whose roots map back to their certificates.
        let active = ActiveRoots::from_data(&d, &[]).unwrap();
        assert_eq!(active.root_count, 93);
        let any = &active.store.roots[0];
        assert!(active.root_der(any).is_some());
        // A tampered copy of the real file no longer verifies.
        let mut bad = REAL_ROOTS.to_vec();
        let n = bad.len() / 2;
        bad[n] ^= 1;
        assert!(list_service::verify_minisign(
            common::bypass::ARGUS_LISTS_PUBLIC_KEY,
            &bad,
            REAL_SIG
        )
        .is_err());
    }

    // ------------------------------------------------------------ install and swap

    #[tokio::test]
    async fn a_signed_set_installs_live_and_new_connections_use_it() {
        let r = rig();
        let private = ca("private root");
        let leaf = leaf_with_scts(&private, "a.test", &[]);
        // Under the floor the private root is unknown.
        let e = handshake(&r.handle, None, &leaf, &[], "a.test").unwrap_err();
        assert_eq!(reason(&e), FailReason::UnknownIssuer);
        assert_eq!(r.handle.serial(), FLOOR_SERIAL);

        let body = roots_json(
            FLOOR_SERIAL + 5,
            &[Root::plain(&private.der)],
            &[],
            MIN_ROOTS,
        );
        assert_eq!(
            r.push(&body).await.unwrap(),
            RootsOutcome::Installed {
                serial: FLOOR_SERIAL + 5
            }
        );
        // The next handshake uses the new set, no rebuild of anything.
        handshake(&r.handle, None, &leaf, &[], "a.test").unwrap();
        let s = r.handle.cell.status.read().clone();
        assert!(s.signed && s.serial == FLOOR_SERIAL + 5 && s.roots == MIN_ROOTS);
        assert!(s.last_error.is_none() && s.last_checked.is_some());
        // The same serial again is current, not an error.
        assert_eq!(
            r.push(&body).await.unwrap(),
            RootsOutcome::Current {
                serial: FLOOR_SERIAL + 5
            }
        );
    }

    #[tokio::test]
    async fn bad_signature_lower_serial_and_too_few_roots_keep_the_current_set() {
        let r = rig();
        let private = ca("private root");
        let good = roots_json(
            FLOOR_SERIAL + 10,
            &[Root::plain(&private.der)],
            &[],
            MIN_ROOTS,
        );
        r.push(&good).await.unwrap();
        let leaf = leaf_with_scts(&private, "a.test", &[]);
        let keep = |r: &Rig| {
            assert_eq!(r.handle.serial(), FLOOR_SERIAL + 10, "set kept");
            handshake(&r.handle, None, &leaf, &[], "a.test").expect("still trusted");
        };

        // Signed by someone else.
        let (other_pk, other_sk) = keypair();
        let newer = roots_json(FLOOR_SERIAL + 20, &[], &[], MIN_ROOTS);
        let sig = sign(&other_sk, &other_pk, newer.as_bytes());
        let e = r
            .manager
            .refresh_from(newer.clone(), sig)
            .await
            .unwrap_err();
        assert!(e.contains("signature"), "{e}");
        keep(&r);
        // Tampered after signing.
        let sig = sign(&r.sk, &r.pk, newer.as_bytes());
        let e = r
            .manager
            .refresh_from(newer.replace("\"serial\"", " \"serial\""), sig)
            .await
            .unwrap_err();
        assert!(e.contains("signature"), "{e}");
        keep(&r);
        // Rollback: validly signed, lower serial.
        let older = roots_json(FLOOR_SERIAL + 3, &[], &[], MIN_ROOTS);
        let e = r.push(&older).await.unwrap_err();
        assert!(e.contains("older than") || e.contains("not newer"), "{e}");
        keep(&r);
        // Fewer roots than allowed.
        let few = roots_json(FLOOR_SERIAL + 30, &[], &[], MIN_ROOTS - 1);
        let e = r.push(&few).await.unwrap_err();
        assert!(e.contains("roots"), "{e}");
        keep(&r);
        // Not schema 1, and a digest that does not match.
        let bad_schema = roots_json(FLOOR_SERIAL + 40, &[], &[], MIN_ROOTS).replacen(
            "\"schema\":1",
            "\"schema\":2",
            1,
        );
        assert!(r.push(&bad_schema).await.unwrap_err().contains("schema"));
        let bad_digest = roots_json(FLOOR_SERIAL + 41, &[], &[], MIN_ROOTS).replacen(
            "\"sha256\":\"",
            "\"sha256\":\"00",
            1,
        );
        assert!(r.push(&bad_digest).await.is_err());
        keep(&r);
        // Every failure shows in the status.
        assert!(r.handle.cell.status.read().last_error.is_some());
    }

    #[tokio::test]
    async fn the_verified_copy_is_cached_and_reloaded_and_a_tampered_cache_is_ignored() {
        let r = rig();
        let private = ca("private root");
        let body = roots_json(
            FLOOR_SERIAL + 7,
            &[Root::plain(&private.der)],
            &[],
            MIN_ROOTS,
        );
        r.push(&body).await.unwrap();
        assert!(r.dir.path().join("roots.json").exists());

        // A restart: a fresh handle loads the cache.
        let fresh = RootsHandle::floor(&[]).unwrap();
        manager_for(&fresh, &pk_b64(&r.pk), r.dir.path()).init_cache();
        assert_eq!(fresh.serial(), FLOOR_SERIAL + 7);
        // Rollback protection survives the restart: an older signed file is refused.
        let m = manager_for(&fresh, &pk_b64(&r.pk), r.dir.path());
        let older = roots_json(FLOOR_SERIAL + 2, &[], &[], MIN_ROOTS);
        let sig = sign(&r.sk, &r.pk, older.as_bytes());
        assert!(m.refresh_from(older, sig).await.is_err());

        // A tampered cache loads nothing.
        let mut bytes = std::fs::read(r.dir.path().join("roots.json")).unwrap();
        bytes[10] ^= 1;
        std::fs::write(r.dir.path().join("roots.json"), bytes).unwrap();
        let fresh = RootsHandle::floor(&[]).unwrap();
        manager_for(&fresh, &pk_b64(&r.pk), r.dir.path()).init_cache();
        assert_eq!(fresh.serial(), FLOOR_SERIAL);
    }

    // ------------------------------------------------------------ display

    #[tokio::test]
    async fn the_chain_ends_with_the_active_sets_genuine_root_certificate() {
        let r = rig();
        let root = ca("display root");
        let leaf = leaf_with_scts(&root, "a.test", &[]);
        r.push(&roots_json(
            FLOOR_SERIAL + 1,
            &[Root::plain(&root.der)],
            &[],
            MIN_ROOTS,
        ))
        .await
        .unwrap();
        let store = Arc::new(CertStore::default());
        // The server presents nothing but its leaf; the root comes from the active set.
        handshake(&r.handle, Some(&store), &leaf, &[], "a.test").unwrap();
        let info = store.info(&fingerprint(&leaf), None).unwrap();
        assert_eq!(info.chain.len(), 2);
        assert_eq!(info.chain[1].fp, fingerprint(&root.der));
    }

    #[test]
    fn every_public_trust_anchor_maps_to_its_genuine_root_certificate() {
        // `webpki-roots` (the store) and `webpki-root-certs` (the index) are the same release.
        let active = ActiveRoots::floor(&[]).unwrap();
        assert!(!webpki_roots::TLS_SERVER_ROOTS.is_empty());
        for a in webpki_roots::TLS_SERVER_ROOTS {
            let der = active
                .root_der(a)
                .unwrap_or_else(|| panic!("no certificate for anchor {:?}", a.subject));
            let (_, x) = x509_parser::parse_x509_certificate(der).unwrap();
            assert!(x.subject().as_raw().ends_with(a.subject.as_ref()));
            assert_eq!(
                x.subject().as_raw(),
                x.issuer().as_raw(),
                "a self-signed root"
            );
        }
    }

    #[test]
    fn an_extra_ca_resolves_through_the_same_index() {
        let c = ca("extra root");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            b64(&c.der)
        );
        std::fs::write(&path, pem).unwrap();
        let active = ActiveRoots::floor(&[path]).unwrap();
        let anchor = webpki::anchor_from_trusted_cert(&CertificateDer::from(c.der.as_slice()))
            .unwrap()
            .to_owned();
        assert_eq!(active.root_der(&anchor), Some(c.der.as_slice()));
    }

    #[tokio::test]
    async fn a_lookalike_root_the_server_presents_is_never_the_root_entry() {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
        let mut rp = CertificateParams::new(vec![]).unwrap();
        rp.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        rp.distinguished_name.push(DnType::CommonName, "look root");
        let key = KeyPair::generate().unwrap();
        let spki = rcgen::PublicKeyData::subject_public_key_info(&key);
        let real = rp.self_signed(&key).unwrap();
        let lookalike = rp.clone().self_signed(&key).unwrap();
        assert_ne!(real.der(), lookalike.der());
        let issuer = TestCa {
            der: real.der().to_vec(),
            issuer: Issuer::new(rp, key),
            spki,
        };
        let leaf = leaf_with_scts(&issuer, "a.test", &[]);
        let r = rig();
        r.push(&roots_json(
            FLOOR_SERIAL + 1,
            &[Root::plain(real.der())],
            &[],
            MIN_ROOTS,
        ))
        .await
        .unwrap();
        let store = Arc::new(CertStore::default());
        handshake(
            &r.handle,
            Some(&store),
            &leaf,
            &[lookalike.der().to_vec()],
            "a.test",
        )
        .unwrap();
        let chain = store.info(&fingerprint(&leaf), None).unwrap().chain;
        assert_eq!(chain.last().unwrap().fp, fingerprint(real.der()));
        assert!(chain.iter().all(|c| c.fp != fingerprint(lookalike.der())));
    }

    #[tokio::test]
    async fn failing_verification_stores_nothing_and_a_replay_for_another_name_too() {
        let r = rig();
        let root = ca("root");
        r.push(&roots_json(
            FLOOR_SERIAL + 1,
            &[Root::plain(&root.der)],
            &[],
            MIN_ROOTS,
        ))
        .await
        .unwrap();
        let store = Arc::new(CertStore::default());
        let genuine = leaf_with_scts(&root, "bank.test", &[]);
        assert!(handshake(&r.handle, Some(&store), &genuine, &[], "evil.test").is_err());
        assert!(store.is_empty());
        handshake(&r.handle, Some(&store), &genuine, &[], "bank.test").unwrap();
        assert_eq!(store.len(), 1);
    }

    fn inter_params() -> rcgen::CertificateParams {
        let mut p = rcgen::CertificateParams::new(vec![]).unwrap();
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p.distinguished_name
            .push(rcgen::DnType::CommonName, "inter");
        p
    }

    fn leaf_under(issuer: &rcgen::Issuer<'static, rcgen::KeyPair>, name: &str) -> Vec<u8> {
        let mut p = rcgen::CertificateParams::new(vec![name.to_string()]).unwrap();
        p.distinguished_name.push(rcgen::DnType::CommonName, name);
        let key = rcgen::KeyPair::generate().unwrap();
        p.signed_by(&key, issuer).unwrap().der().to_vec()
    }

    #[tokio::test]
    async fn a_forged_same_name_intermediate_never_replaces_the_verified_one() {
        let root = ca("root");
        let r = rig();
        r.push(&roots_json(
            FLOOR_SERIAL + 1,
            &[Root::plain(&root.der)],
            &[],
            MIN_ROOTS,
        ))
        .await
        .unwrap();
        let p = inter_params();
        let key = rcgen::KeyPair::generate().unwrap();
        let real = p.signed_by(&key, &root.issuer).unwrap();
        let inter = rcgen::Issuer::new(p, key);
        // Same subject, another key: webpki rejects it, a name-only walk would pick it.
        let forged = inter_params()
            .self_signed(&rcgen::KeyPair::generate().unwrap())
            .unwrap();
        let leaf = leaf_under(&inter, "good.test");
        let store = Arc::new(CertStore::default());
        let extra = [forged.der().to_vec(), real.der().to_vec()];
        handshake(&r.handle, Some(&store), &leaf, &extra, "good.test").unwrap();
        let fps: Vec<_> = store
            .info(&fingerprint(&leaf), None)
            .unwrap()
            .chain
            .into_iter()
            .map(|c| c.fp)
            .collect();
        assert_eq!(
            fps,
            vec![
                fingerprint(&leaf),
                fingerprint(real.der()),
                fingerprint(&root.der)
            ]
        );
    }

    #[tokio::test]
    async fn a_cross_signed_intermediate_follows_the_path_that_verified() {
        let root = ca("root");
        let other_root = ca("other root");
        let r = rig();
        r.push(&roots_json(
            FLOOR_SERIAL + 1,
            &[Root::plain(&root.der)],
            &[],
            MIN_ROOTS,
        ))
        .await
        .unwrap();
        let p = inter_params();
        let key = rcgen::KeyPair::generate().unwrap();
        let der = key.serialize_der();
        let real = p.signed_by(&key, &root.issuer).unwrap();
        // The same subject and key, certified by a root nobody here trusts.
        let cross = inter_params()
            .signed_by(
                &rcgen::KeyPair::try_from(der.as_slice()).unwrap(),
                &other_root.issuer,
            )
            .unwrap();
        let inter = rcgen::Issuer::new(p, key);
        let leaf = leaf_under(&inter, "good.test");
        let store = Arc::new(CertStore::default());
        handshake(
            &r.handle,
            Some(&store),
            &leaf,
            &[cross.der().to_vec(), real.der().to_vec()],
            "good.test",
        )
        .unwrap();
        let chain = store.info(&fingerprint(&leaf), None).unwrap().chain;
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[1].fp, fingerprint(real.der()));
        assert_eq!(chain[2].fp, fingerprint(&root.der));
    }

    // ------------------------------------------------------------ rules

    const FAR: &str = "2100-01-01T00:00:00Z";

    #[tokio::test]
    async fn distrust_after_refuses_leaves_issued_after_the_date_with_a_clear_reason() {
        let root = ca("late root");
        // The test leaf's notBefore is in 1975.
        let leaf = leaf_with_scts(&root, "a.test", &[]);
        let ok = rig();
        ok.push(&roots_json(
            FLOOR_SERIAL + 1,
            &[Root {
                distrust_after: Some(FAR),
                ..Root::plain(&root.der)
            }],
            &[],
            MIN_ROOTS,
        ))
        .await
        .unwrap();
        handshake(&ok.handle, None, &leaf, &[], "a.test").unwrap();

        let early = rig();
        early
            .push(&roots_json(
                FLOOR_SERIAL + 1,
                &[Root {
                    distrust_after: Some("1970-01-01T00:00:00Z"),
                    ..Root::plain(&root.der)
                }],
                &[],
                MIN_ROOTS,
            ))
            .await
            .unwrap();
        let e = handshake(&early.handle, None, &leaf, &[], "a.test").unwrap_err();
        assert_eq!(reason(&e), FailReason::Distrusted);
        assert!(e.to_string().contains("no longer vouches"), "{e}");
    }

    #[tokio::test]
    async fn permitted_dns_names_are_enforced_as_name_constraints() {
        let root = ca("constrained root");
        let r = rig();
        r.push(&roots_json(
            FLOOR_SERIAL + 1,
            &[Root {
                permitted: vec!["example.test"],
                ..Root::plain(&root.der)
            }],
            &[],
            MIN_ROOTS,
        ))
        .await
        .unwrap();
        for ok in ["example.test", "www.example.test"] {
            handshake(&r.handle, None, &leaf_with_scts(&root, ok, &[]), &[], ok).unwrap();
        }
        for bad in ["other.test", "notexample.test"] {
            let e =
                handshake(&r.handle, None, &leaf_with_scts(&root, bad, &[]), &[], bad).unwrap_err();
            assert_eq!(reason(&e), FailReason::Distrusted, "{bad}");
        }
    }

    #[tokio::test]
    async fn sct_not_after_needs_a_valid_receipt_logged_in_time() {
        let root = ca("sct root");
        let (good, other) = (TestLog::new(), TestLog::new());
        let t_s = (T / 1000) as i64;
        let limit = chrono::DateTime::from_timestamp(t_s + 100, 0)
            .unwrap()
            .to_rfc3339();
        let limit: &'static str = Box::leak(limit.into_boxed_str());
        let r = rig();
        r.push(&roots_json(
            FLOOR_SERIAL + 1,
            &[Root {
                sct_not_after: Some(limit),
                ..Root::plain(&root.der)
            }],
            &[(&good, "usable", 0), (&other, "retired", t_s - 50)],
            MIN_ROOTS,
        ))
        .await
        .unwrap();
        let run = |ts: u64, log: &TestLog, forged: bool, name: &str| {
            let leaf = leaf_with_scts(
                &root,
                name,
                &[Receipt {
                    forged,
                    ..Receipt::ok(log, ts)
                }],
            );
            handshake(&r.handle, None, &leaf, &[], name)
        };
        // A receipt before the date passes.
        run(T, &good, false, "a.test").unwrap();
        // One after the date fails, as does none at all.
        let e = run(T + 200_000, &good, false, "b.test").unwrap_err();
        assert_eq!(reason(&e), FailReason::Distrusted);
        let none = leaf_with_scts(&root, "c.test", &[]);
        assert_eq!(
            reason(&handshake(&r.handle, None, &none, &[], "c.test").unwrap_err()),
            FailReason::Distrusted
        );
        // A forged signature is ignored, so the chain fails.
        assert!(run(T, &good, true, "d.test").is_err());
        // A retired log counts only for a receipt older than its retirement: `other` retired
        // at t_s - 50, so a receipt at T (later) is ignored.
        assert!(run(T, &other, false, "e.test").is_err());
        run(T - 100_000, &other, false, "f.test").unwrap();
    }

    fn pem(der: &[u8]) -> String {
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            b64(der)
        )
    }

    #[tokio::test]
    async fn a_rule_that_rejects_one_path_lets_webpki_find_another() {
        let (constrained, open) = (ca("constrained root"), ca("open root"));
        let r = rig();
        r.push(&roots_json(
            FLOOR_SERIAL + 1,
            &[
                // Receipts required since 2000: a leaf without one fails under this root.
                Root {
                    sct_not_after: Some("2000-01-01T00:00:00Z"),
                    ..Root::plain(&constrained.der)
                },
                Root::plain(&open.der),
            ],
            &[],
            MIN_ROOTS,
        ))
        .await
        .unwrap();
        let p = inter_params();
        let key = rcgen::KeyPair::generate().unwrap();
        let der = key.serialize_der();
        let via_constrained = p.signed_by(&key, &constrained.issuer).unwrap();
        let via_open = inter_params()
            .signed_by(
                &rcgen::KeyPair::try_from(der.as_slice()).unwrap(),
                &open.issuer,
            )
            .unwrap();
        let inter = rcgen::Issuer::new(p, key);
        let leaf = leaf_under(&inter, "good.test");

        // Both cross-signs presented: the unconstrained path is found and is what is stored.
        let store = Arc::new(CertStore::default());
        let both = [via_constrained.der().to_vec(), via_open.der().to_vec()];
        handshake(&r.handle, Some(&store), &leaf, &both, "good.test").unwrap();
        let chain = store.info(&fingerprint(&leaf), None).unwrap().chain;
        assert_eq!(chain[1].fp, fingerprint(via_open.der()));
        assert_eq!(chain[2].fp, fingerprint(&open.der));

        // Only the constrained one: nothing else to try, so the rule's reason is named.
        let only = [via_constrained.der().to_vec()];
        let e = handshake(&r.handle, None, &leaf, &only, "good.test").unwrap_err();
        assert_eq!(reason(&e), FailReason::Distrusted);
    }

    #[tokio::test]
    async fn a_receipt_rule_with_a_future_date_is_not_in_force_yet() {
        let root = ca("future root");
        let r = rig();
        r.push(&roots_json(
            FLOOR_SERIAL + 1,
            &[Root {
                sct_not_after: Some(FAR),
                ..Root::plain(&root.der)
            }],
            &[],
            MIN_ROOTS,
        ))
        .await
        .unwrap();
        // No receipt at all, yet fine: the date has not passed.
        handshake(
            &r.handle,
            None,
            &leaf_with_scts(&root, "a.test", &[]),
            &[],
            "a.test",
        )
        .unwrap();
    }

    #[tokio::test]
    async fn logs_in_an_unknown_state_are_skipped_not_fatal() {
        let r = rig();
        let (known, odd) = (TestLog::new(), TestLog::new());
        let body = roots_json(
            FLOOR_SERIAL + 1,
            &[],
            &[
                (&known, "usable", 0),
                (&odd, "pending", 0),
                (&odd, "rejected", 0),
                (&odd, "from-the-future", 0),
            ],
            MIN_ROOTS,
        );
        r.push(&body).await.expect("the file still installs");
        let d = RootsData::parse(body.as_bytes()).unwrap();
        assert_eq!(d.ct_logs.len(), 1, "only the usable log is kept");
    }

    #[tokio::test]
    async fn extra_cas_can_change_live_and_a_broken_file_blocks_nothing() {
        let private = ca("extra root");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("extra.pem");
        std::fs::write(&path, pem(&private.der)).unwrap();
        let leaf = leaf_with_scts(&private, "a.test", &[]);
        let h = RootsHandle::floor(&[]).unwrap();
        assert!(handshake(&h, None, &leaf, &[], "a.test").is_err());
        h.set_extras(std::slice::from_ref(&path)).unwrap();
        handshake(&h, None, &leaf, &[], "a.test").unwrap();

        // The files are read once: removing one blocks neither a signed install nor the CA.
        std::fs::remove_file(&path).unwrap();
        let (pk, sk) = keypair();
        let m = manager_for(&h, &pk_b64(&pk), dir.path());
        let body = roots_json(FLOOR_SERIAL + 1, &[], &[], MIN_ROOTS);
        let sig = sign(&sk, &pk, body.as_bytes());
        m.refresh_from(body, sig).await.unwrap();
        handshake(&h, None, &leaf, &[], "a.test").unwrap();
        // A broken file is refused and changes nothing.
        assert!(h.set_extras(&[path]).is_err());
        handshake(&h, None, &leaf, &[], "a.test").unwrap();
        // Dropping the extras removes the trust again.
        h.set_extras(&[]).unwrap();
        assert!(handshake(&h, None, &leaf, &[], "a.test").is_err());
    }

    #[tokio::test]
    async fn the_highest_serial_survives_a_lost_cache() {
        let r = rig();
        r.push(&roots_json(FLOOR_SERIAL + 9, &[], &[], MIN_ROOTS))
            .await
            .unwrap();
        std::fs::remove_file(r.dir.path().join("roots.json")).unwrap();
        std::fs::remove_file(r.dir.path().join("roots.json.minisig")).unwrap();
        assert!(r.dir.path().join("roots.serial").exists());

        let fresh = RootsHandle::floor(&[]).unwrap();
        let m = manager_for(&fresh, &pk_b64(&r.pk), r.dir.path());
        m.init_cache();
        assert_eq!(fresh.serial(), FLOOR_SERIAL, "nothing cached to load");
        let older = roots_json(FLOOR_SERIAL + 4, &[], &[], MIN_ROOTS);
        let sig = sign(&r.sk, &r.pk, older.as_bytes());
        let e = m.refresh_from(older, sig).await.unwrap_err();
        assert!(e.contains("highest ever accepted"), "{e}");
        let newer = roots_json(FLOOR_SERIAL + 10, &[], &[], MIN_ROOTS);
        let sig = sign(&r.sk, &r.pk, newer.as_bytes());
        m.refresh_from(newer, sig).await.unwrap();
    }

    #[tokio::test]
    async fn a_good_check_clears_the_error_and_a_cache_failure_is_only_a_warning() {
        let r = rig();
        assert!(r.push("not json").await.is_err());
        assert!(r.handle.cell.status.read().last_error.is_some());
        r.push(&roots_json(FLOOR_SERIAL + 1, &[], &[], MIN_ROOTS))
            .await
            .unwrap();
        assert!(r.handle.cell.status.read().last_error.is_none());
        // A Current outcome ends an earlier failure too.
        assert!(r.push("still not json").await.is_err());
        let same = roots_json(FLOOR_SERIAL + 1, &[], &[], MIN_ROOTS);
        assert_eq!(
            r.push(&same).await.unwrap(),
            RootsOutcome::Current {
                serial: FLOOR_SERIAL + 1
            }
        );
        assert!(r.handle.cell.status.read().last_error.is_none());

        // The cache directory is a file: nothing can be written, yet the set installs.
        let blocker = tempfile::NamedTempFile::new().unwrap();
        let h = RootsHandle::floor(&[]).unwrap();
        let (pk, sk) = keypair();
        let m = manager_for(&h, &pk_b64(&pk), blocker.path());
        let body = roots_json(FLOOR_SERIAL + 2, &[], &[], MIN_ROOTS);
        let sig = sign(&sk, &pk, body.as_bytes());
        m.refresh_from(body, sig).await.unwrap();
        assert_eq!(h.serial(), FLOOR_SERIAL + 2);
        assert!(h.cell.status.read().last_error.is_none());
    }

    #[tokio::test]
    async fn ip_addresses_are_refused_under_a_dns_constrained_root() {
        let root = ca("constrained root");
        let r = rig();
        r.push(&roots_json(
            FLOOR_SERIAL + 1,
            &[Root {
                permitted: vec!["example.test"],
                ..Root::plain(&root.der)
            }],
            &[],
            MIN_ROOTS,
        ))
        .await
        .unwrap();
        let mut p = rcgen::CertificateParams::new(vec!["a.example.test".to_string()]).unwrap();
        p.subject_alt_names
            .push(rcgen::SanType::IpAddress("192.0.2.7".parse().unwrap()));
        p.distinguished_name
            .push(rcgen::DnType::CommonName, "a.example.test");
        let key = rcgen::KeyPair::generate().unwrap();
        let leaf = p.signed_by(&key, &root.issuer).unwrap().der().to_vec();
        let e = handshake(&r.handle, None, &leaf, &[], "a.example.test").unwrap_err();
        assert_eq!(reason(&e), FailReason::Distrusted);
    }

    #[tokio::test]
    async fn an_extra_ca_equal_to_a_public_root_keeps_that_roots_rules() {
        let root = ca("ruled root");
        let r = rig();
        r.push(&roots_json(
            FLOOR_SERIAL + 1,
            &[Root {
                distrust_after: Some("1970-01-01T00:00:00Z"),
                ..Root::plain(&root.der)
            }],
            &[],
            MIN_ROOTS,
        ))
        .await
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("same.pem");
        std::fs::write(&path, pem(&root.der)).unwrap();
        r.handle.set_extras(&[path]).unwrap();
        let leaf = leaf_with_scts(&root, "a.test", &[]);
        let e = handshake(&r.handle, None, &leaf, &[], "a.test").unwrap_err();
        assert_eq!(reason(&e), FailReason::Distrusted);
    }

    #[test]
    fn prepared_extras_change_nothing_until_committed() {
        let private = ca("extra root");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("extra.pem");
        std::fs::write(&path, pem(&private.der)).unwrap();
        let leaf = leaf_with_scts(&private, "a.test", &[]);
        let h = RootsHandle::floor(&[]).unwrap();
        // The extras load (a later prepare step may still fail): the old set stays in force.
        let prepared = h.prepare_extras(&[path]).unwrap();
        assert!(handshake(&h, None, &leaf, &[], "a.test").is_err());
        drop(prepared);
        assert!(handshake(&h, None, &leaf, &[], "a.test").is_err());
        // A broken file fails the prepare itself.
        assert!(h.prepare_extras(&[dir.path().join("missing.pem")]).is_err());
        // Committing applies them.
        let ders = h.prepare_extras(&[dir.path().join("extra.pem")]).unwrap();
        h.commit_extras(ders);
        handshake(&h, None, &leaf, &[], "a.test").unwrap();
    }
}

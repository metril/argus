//! Extended Validation detection: sites whose leaf certificate carries an EV policy are
//! tunnelled instead of decrypted (a user-visible assurance an intercepting certificate would
//! destroy). The verdict comes from a TLS handshake with the upstream server, cached per host.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Policy OIDs that mark an EV certificate: the CA/Browser Forum one (2.23.140.1.1) and the
/// well-known CA-specific ones.
const EV_OIDS: &[&str] = &[
    "2.23.140.1.1",
    "2.16.840.1.114412.2.1",        // DigiCert
    "2.16.840.1.114412.1.3.0.2",    // DigiCert (legacy)
    "1.3.6.1.4.1.6449.1.2.1.5.1",   // Sectigo / Comodo
    "1.3.6.1.4.1.4146.1.1",         // GlobalSign
    "2.16.840.1.114028.10.1.2",     // Entrust
    "2.16.840.1.114413.1.7.23.3",   // GoDaddy
    "2.16.840.1.114414.1.7.23.3",   // Starfield
    "2.16.840.1.113733.1.7.23.6",   // VeriSign / Symantec
    "1.3.6.1.4.1.8024.0.2.100.1.2", // QuoVadis
    "1.2.616.1.113527.2.5.1.1",     // Certum
    "2.16.756.1.89.1.2.1.1",        // SwissSign
    "1.3.159.1.17.1",               // Actalis
    "2.16.578.1.26.1.3.3",          // Buypass
    "2.16.840.1.114404.1.1.2.4.1",  // Trustwave
    "1.3.6.1.4.1.4788.2.202.1",     // D-TRUST
    "1.3.6.1.4.1.34697.2.1",        // AffirmTrust
];

/// Whether a DER certificate carries an EV certificate policy.
pub fn is_ev_der(der: &[u8]) -> bool {
    use x509_parser::extensions::ParsedExtension;
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(der) else {
        return false;
    };
    cert.extensions()
        .iter()
        .any(|e| match e.parsed_extension() {
            ParsedExtension::CertificatePolicies(ps) => ps
                .iter()
                .any(|p| EV_OIDS.contains(&p.policy_id.to_id_string().as_str())),
            _ => false,
        })
}

/// Accepts any certificate: the handshake is only used to read the leaf, not to trust it.
#[derive(Debug)]
struct ReadOnly(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for ReadOnly {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// How long the handshake probe may take. Its own, short limit: a dead or filtered host must not
/// hold a client's whole handshake budget.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Handshake with `addr` as `host` and read its leaf certificate. `None` when the probe could
/// not tell (connect or handshake failed, or timed out).
pub async fn probe(host: &str, addr: SocketAddr, limit: Duration) -> Option<bool> {
    let name = ServerName::try_from(host.to_string()).ok()?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .ok()?;
    let config = builder
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ReadOnly(provider)))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let run = async {
        let tcp = TcpStream::connect(addr).await.ok()?;
        let tls = connector.connect(name, tcp).await.ok()?;
        let (_, conn) = tls.get_ref();
        Some(is_ev_der(conn.peer_certificates()?.first()?.as_ref()))
    };
    tokio::time::timeout(limit.min(PROBE_TIMEOUT), run)
        .await
        .ok()
        .flatten()
}

/// What a probe concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvVerdict {
    /// The leaf certificate carries an EV policy.
    Ev,
    /// It does not.
    NotEv,
    /// The probe failed: unknown. Callers tunnel rather than decrypt.
    Unknown,
}

struct ByVerdict {
    definite: Duration,
    unknown: Duration,
}

impl moka::Expiry<String, EvVerdict> for ByVerdict {
    fn expire_after_create(
        &self,
        _key: &String,
        v: &EvVerdict,
        _now: std::time::Instant,
    ) -> Option<Duration> {
        Some(match v {
            EvVerdict::Unknown => self.unknown,
            _ => self.definite,
        })
    }
}

/// Per-`host:port` EV verdicts. Definite answers are kept for a long time; a failed probe only
/// for a few seconds, so a flaky or briefly dead host is retried soon and is never remembered as
/// "not EV".
pub struct EvCache {
    cache: moka::future::Cache<String, EvVerdict>,
}

impl Default for EvCache {
    fn default() -> Self {
        Self::with_ttls(Duration::from_secs(30 * 60), Duration::from_secs(30))
    }
}

impl EvCache {
    pub fn with_ttls(definite: Duration, unknown: Duration) -> Self {
        Self {
            cache: moka::future::Cache::builder()
                .max_capacity(20_000)
                .expire_after(ByVerdict { definite, unknown })
                .build(),
        }
    }

    /// The cached verdict for `host:port`, or run `check` (concurrent callers share one run).
    pub async fn verdict<F>(&self, host: &str, port: u16, check: F) -> EvVerdict
    where
        F: std::future::Future<Output = EvVerdict>,
    {
        self.cache
            .get_with(format!("{}:{port}", host.to_ascii_lowercase()), check)
            .await
    }

    pub fn clear(&self) {
        self.cache.invalidate_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, CustomExtension, KeyPair};

    /// DER of a certificatePolicies extension naming `oid` (given as arcs).
    fn policies_ext(arcs: &[u64]) -> CustomExtension {
        fn enc(mut v: u64, out: &mut Vec<u8>) {
            let mut tmp = vec![(v & 0x7f) as u8];
            v >>= 7;
            while v > 0 {
                tmp.push((v & 0x7f) as u8 | 0x80);
                v >>= 7;
            }
            tmp.reverse();
            out.extend(tmp);
        }
        let mut body = vec![(arcs[0] * 40 + arcs[1]) as u8];
        for a in &arcs[2..] {
            enc(*a, &mut body);
        }
        let mut oid = vec![0x06, body.len() as u8];
        oid.extend(body);
        let mut info = vec![0x30, oid.len() as u8];
        info.extend(oid);
        let mut seq = vec![0x30, info.len() as u8];
        seq.extend(info);
        CustomExtension::from_oid_content(&[2, 5, 29, 32], seq)
    }

    fn cert(policy: Option<&[u64]>) -> Vec<u8> {
        let mut p = CertificateParams::new(vec!["ev.test".into()]).unwrap();
        if let Some(arcs) = policy {
            p.custom_extensions.push(policies_ext(arcs));
        }
        let key = KeyPair::generate().unwrap();
        p.self_signed(&key).unwrap().der().to_vec()
    }

    #[test]
    fn ev_policy_oids_are_recognised_and_others_are_not() {
        assert!(is_ev_der(&cert(Some(&[2, 23, 140, 1, 1]))), "CA/B Forum EV");
        assert!(
            is_ev_der(&cert(Some(&[2, 16, 840, 1, 114412, 2, 1]))),
            "DigiCert EV"
        );
        assert!(
            is_ev_der(&cert(Some(&[1, 3, 6, 1, 4, 1, 6449, 1, 2, 1, 5, 1]))),
            "Sectigo EV"
        );
        assert!(!is_ev_der(&cert(None)), "no policies");
        assert!(!is_ev_der(&cert(Some(&[2, 23, 140, 1, 2, 1]))), "DV policy");
        assert!(!is_ev_der(&cert(Some(&[2, 23, 140, 1, 2, 2]))), "OV policy");
        assert!(!is_ev_der(b"not a certificate"));
    }

    #[tokio::test]
    async fn definite_verdicts_are_cached_per_host_and_port() {
        let c = EvCache::default();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let count = || calls.load(std::sync::atomic::Ordering::SeqCst);
        for _ in 0..3 {
            let v = c
                .verdict("Bank.TEST", 443, async {
                    calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    EvVerdict::Ev
                })
                .await;
            assert_eq!(v, EvVerdict::Ev);
        }
        assert_eq!(count(), 1);
        // Another port of the same host is its own entry (a different server may answer there).
        let v = c
            .verdict("bank.test", 8443, async {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                EvVerdict::NotEv
            })
            .await;
        assert_eq!((v, count()), (EvVerdict::NotEv, 2));
        assert_eq!(
            c.verdict("bank.test", 443, async { EvVerdict::NotEv })
                .await,
            EvVerdict::Ev
        );
    }

    #[tokio::test]
    async fn a_failed_probe_is_remembered_only_briefly_and_never_as_not_ev() {
        let c = EvCache::with_ttls(Duration::from_secs(60), Duration::from_millis(150));
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let probe_failed = || async {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            EvVerdict::Unknown
        };
        assert_eq!(
            c.verdict("flaky.test", 443, probe_failed()).await,
            EvVerdict::Unknown
        );
        // Still cached for the short TTL (no probe storm) ...
        assert_eq!(
            c.verdict("flaky.test", 443, probe_failed()).await,
            EvVerdict::Unknown
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        // ... then asked again, and a definite answer replaces it.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let v = c.verdict("flaky.test", 443, async { EvVerdict::Ev }).await;
        assert_eq!(
            v,
            EvVerdict::Ev,
            "the failure was not cached as a lasting verdict"
        );
    }

    #[tokio::test]
    async fn the_probe_gives_up_after_its_own_short_timeout_on_a_dead_host() {
        // Accepts the connection and never answers the TLS handshake.
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (_s, _) = l.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let t = std::time::Instant::now();
        // Even with a long overall budget the probe is capped (here by the passed, shorter limit).
        assert_eq!(
            probe("dead.test", addr, Duration::from_millis(300)).await,
            None
        );
        assert!(t.elapsed() < Duration::from_secs(2));
        // And a refused connection is `None` at once, not "not EV".
        assert_eq!(
            probe(
                "dead.test",
                "127.0.0.1:1".parse().unwrap(),
                Duration::from_secs(5)
            )
            .await,
            None
        );
        assert!(PROBE_TIMEOUT <= Duration::from_secs(2));
    }

    /// A TLS server on loopback presenting `policy` (EV or not); returns its port.
    async fn tls_server(policy: Option<&[u64]>) -> u16 {
        let mut p = CertificateParams::new(vec!["site.test".into()]).unwrap();
        if let Some(arcs) = policy {
            p.custom_extensions.push(policies_ext(arcs));
        }
        let key = KeyPair::generate().unwrap();
        let cert = p.self_signed(&key).unwrap();
        let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (s, _) = l.accept().await.unwrap();
                let a = acceptor.clone();
                tokio::spawn(async move {
                    let _ = a.accept(s).await;
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn the_context_probes_ev_non_ev_and_unreachable_hosts_over_a_real_handshake() {
        let ev = tls_server(Some(&[2, 23, 140, 1, 1])).await;
        let dv = tls_server(Some(&[2, 23, 140, 1, 2, 1])).await;
        let opts = crate::upstream::UpstreamOptions {
            resolve_all_to: Some("127.0.0.1".parse().unwrap()),
            ..Default::default()
        };
        let ctx = crate::filtering::ProxyContext::with_upstream(
            Arc::new(filter_engine::SharedEngine::new()),
            &opts,
            true,
        )
        .unwrap();
        let limit = Duration::from_secs(5);
        assert_eq!(ctx.ev_verdict("bank.test", ev, limit).await, EvVerdict::Ev);
        assert_eq!(
            ctx.ev_verdict("shop.test", dv, limit).await,
            EvVerdict::NotEv
        );
        // Nothing listens: unknown (which callers tunnel), never "not EV".
        assert_eq!(
            ctx.ev_verdict("gone.test", 1, limit).await,
            EvVerdict::Unknown
        );
        // IP literals have no SNI and are never EV.
        assert_eq!(
            ctx.ev_verdict("127.0.0.1", ev, limit).await,
            EvVerdict::NotEv
        );
    }
}

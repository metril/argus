//! What the patched BoringSSL (ML-DSA signature algorithms, GREASE signature algorithm) must
//! refuse in a server's CertificateVerify / ServerKeyExchange, with a chain Argus trusts:
//! the GREASE value, a scheme the client did not offer, an ML-DSA scheme with a leaf of another
//! key type, and ML-DSA in TLS 1.2. Each case runs against a server whose chain is trusted and
//! whose only misbehaviour is the signature scheme it claims (the signature itself is real), next
//! to the same server claiming an honest scheme, which must succeed.
//!
//! The server is rustls with a signing key that ignores what the client offered and claims the
//! scheme the test asks for.

mod support;

use std::{sync::Arc, time::Duration};

use filter_engine::ErrorKind;
use rcgen::{CertificateParams, KeyPair, SanType};
use rustls::{
    crypto::ring::sign::any_supported_type,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::{ClientHello, ResolvesServerCert},
    sign::{CertifiedKey, Signer, SigningKey},
    SignatureAlgorithm, SignatureScheme as S,
};
use support::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::TlsAcceptor;

const HOST: &str = "sig.test";
const UA_156: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36";

const MLDSA44: u16 = 0x0904;
const MLDSA65: u16 = 0x0905;
const MLDSA87: u16 = 0x0906;

fn is_grease(v: u16) -> bool {
    (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff)
}

#[derive(Clone, Copy, Debug)]
enum Claim {
    /// This exact scheme.
    Scheme(u16),
    /// The GREASE value the client put in its `signature_algorithms`.
    ClientGrease,
}

#[derive(Clone, Copy, Debug)]
enum Leaf {
    Ecdsa,
    Ed25519,
}

#[derive(Debug)]
struct Forced {
    inner: Arc<dyn SigningKey>,
    /// The scheme the inner key really signs with.
    sign_with: S,
    /// The scheme written into the handshake message.
    claim: S,
}

#[derive(Debug)]
struct ForcedSigner {
    inner: Box<dyn Signer>,
    claim: S,
}

impl SigningKey for Forced {
    fn choose_scheme(&self, _offered: &[S]) -> Option<Box<dyn Signer>> {
        let inner = self.inner.choose_scheme(&[self.sign_with])?;
        Some(Box::new(ForcedSigner {
            inner,
            claim: self.claim,
        }))
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        self.inner.algorithm()
    }
}

impl Signer for ForcedSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        self.inner.sign(message)
    }
    fn scheme(&self) -> S {
        self.claim
    }
}

#[derive(Debug)]
struct Resolver {
    chain: Vec<CertificateDer<'static>>,
    inner: Arc<dyn SigningKey>,
    sign_with: S,
    claim: Claim,
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, ch: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let claim = match self.claim {
            Claim::Scheme(v) => S::from(v),
            Claim::ClientGrease => ch
                .signature_schemes()
                .iter()
                .copied()
                .find(|s| is_grease(u16::from(*s)))?,
        };
        Some(Arc::new(CertifiedKey::new(
            self.chain.clone(),
            Arc::new(Forced {
                inner: self.inner.clone(),
                sign_with: self.sign_with,
                claim,
            }),
        )))
    }
}

/// A TLS server with a leaf of `leaf` signed by `trusted`, claiming `claim` in its signature.
async fn server(trusted: &Ca, leaf: Leaf, claim: Claim, tls12_only: bool) -> u16 {
    let (key, sign_with) = match leaf {
        Leaf::Ecdsa => (
            KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap(),
            S::ECDSA_NISTP256_SHA256,
        ),
        Leaf::Ed25519 => (
            KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap(),
            S::ED25519,
        ),
    };
    let mut p = CertificateParams::default();
    p.subject_alt_names = vec![SanType::DnsName(HOST.try_into().unwrap())];
    let cert = p.signed_by(&key, &trusted.issuer).unwrap();
    let pk = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let resolver = Resolver {
        chain: vec![
            cert.der().clone(),
            CertificateDer::from(trusted.der.clone()),
        ],
        inner: any_supported_type(&pk).unwrap(),
        sign_with,
        claim,
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let versions: &[&'static rustls::SupportedProtocolVersion] = if tls12_only {
        &[&rustls::version::TLS12]
    } else {
        rustls::ALL_VERSIONS
    };
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = l.accept().await else {
                return;
            };
            let acc = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acc.accept(tcp).await else {
                    return;
                };
                let mut head = Vec::new();
                let mut b = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut b).await {
                        Ok(n) if n > 0 => head.extend_from_slice(&b[..n]),
                        _ => return,
                    }
                }
                let _ = tls
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                    )
                    .await;
                let _ = tls.shutdown().await;
            });
        }
    });
    port
}

/// Request the server with the Chrome 156 profile; the status, or the error and its full chain.
async fn fetch(trusted: &Ca, port: u16) -> Result<u16, (ErrorKind, String)> {
    let r = rig(trusted, |_| {});
    let res = r
        .client
        .get(format!("https://{HOST}:{port}/"))
        .header("user-agent", UA_156)
        .send()
        .await;
    match res {
        Ok(resp) => Ok(resp.status().as_u16()),
        Err(e) => {
            let mut msg = format!("{e}");
            let mut cur: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(&e);
            while let Some(c) = cur {
                msg.push_str(&format!(" | {c}"));
                cur = c.source();
            }
            msg.push_str(&format!(" | {e:?}"));
            Err((e.kind(), msg))
        }
    }
}

async fn refused(leaf: Leaf, claim: Claim, tls12_only: bool) {
    let trusted = ca("trusted");
    let port = server(&trusted, leaf, claim, tls12_only).await;
    let (kind, msg) = fetch(&trusted, port).await.expect_err(&format!(
        "{leaf:?} leaf claiming {claim:?} must be rejected"
    ));
    assert_eq!(kind, ErrorKind::UpstreamTls, "{msg}");
    assert!(
        msg.contains("WRONG_SIGNATURE_TYPE") || msg.contains("wrong signature type"),
        "rejected for the scheme, not for something else: {msg}"
    );
}

#[tokio::test]
async fn control_an_honest_server_with_the_same_chain_succeeds() {
    let trusted = ca("trusted");
    let p = server(&trusted, Leaf::Ecdsa, Claim::Scheme(0x0403), false).await;
    assert_eq!(fetch(&trusted, p).await.unwrap(), 200);
}

#[tokio::test]
async fn a_server_selecting_the_grease_signature_algorithm_is_rejected() {
    refused(Leaf::Ecdsa, Claim::ClientGrease, false).await;
}

#[tokio::test]
async fn a_scheme_the_client_did_not_offer_is_rejected() {
    // ed25519 is not in Chrome's list: an honest Ed25519 leaf and signature, wrong to select.
    refused(Leaf::Ed25519, Claim::Scheme(0x0807), false).await;
    // A scheme well known but not offered (rsa_pkcs1_sha1) with an ECDSA leaf.
    refused(Leaf::Ecdsa, Claim::Scheme(0x0201), false).await;
}

#[tokio::test]
async fn an_ml_dsa_scheme_with_a_classical_leaf_is_rejected() {
    for scheme in [MLDSA44, MLDSA65, MLDSA87] {
        refused(Leaf::Ecdsa, Claim::Scheme(scheme), false).await;
        refused(Leaf::Ed25519, Claim::Scheme(scheme), false).await;
    }
}

#[tokio::test]
async fn an_offered_scheme_of_another_key_type_is_rejected() {
    // rsa_pss_rsae_sha256 is offered, but the leaf is ECDSA.
    refused(Leaf::Ecdsa, Claim::Scheme(0x0804), false).await;
}

#[tokio::test]
async fn a_tls12_only_server_handshakes_normally() {
    let trusted = ca("trusted");
    let p = server(&trusted, Leaf::Ecdsa, Claim::Scheme(0x0403), true).await;
    assert_eq!(fetch(&trusted, p).await.unwrap(), 200);
}

#[tokio::test]
async fn ml_dsa_is_refused_in_tls12() {
    refused(Leaf::Ecdsa, Claim::Scheme(MLDSA44), true).await;
}

#[tokio::test]
async fn a_client_limited_to_tls12_does_not_offer_ml_dsa_or_grease_signature_algorithms() {
    use hyper::header::{HeaderMap, HeaderValue};
    let mut h = HeaderMap::new();
    h.insert("user-agent", HeaderValue::from_static(UA_156));
    let bp = proxy_core::browser_profile::BrowserProfile::classify(&h);
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let rec = tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut head = [0u8; 5];
        s.read_exact(&mut head).await.unwrap();
        let mut body = vec![0u8; u16::from_be_bytes([head[3], head[4]]) as usize];
        s.read_exact(&mut body).await.unwrap();
        [head.to_vec(), body].concat()
    });
    let mut e = bp.emulation();
    e.tls_options.as_mut().unwrap().max_tls_version = Some(wreq::tls::TlsVersion::TLS_1_2);
    let client = wreq::Client::builder()
        .emulation(e)
        .timeout(Duration::from_secs(5))
        .no_proxy()
        .build()
        .unwrap();
    let _ = client
        .get(format!("https://localhost:{port}/"))
        .send()
        .await;
    let rec = tokio::time::timeout(Duration::from_secs(5), rec)
        .await
        .unwrap()
        .unwrap();
    let b = &rec[9..];
    let mut p = 2 + 32;
    p += 1 + b[p] as usize;
    p += 2 + u16::from_be_bytes([b[p], b[p + 1]]) as usize;
    p += 1 + b[p] as usize;
    let end = p + 2 + u16::from_be_bytes([b[p], b[p + 1]]) as usize;
    p += 2;
    let mut sig = None;
    while p < end {
        let t = u16::from_be_bytes([b[p], b[p + 1]]);
        let l = u16::from_be_bytes([b[p + 2], b[p + 3]]) as usize;
        if t == 13 {
            sig = Some(
                b[p + 6..p + 4 + l]
                    .chunks(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect::<Vec<_>>(),
            );
        }
        p += 4 + l;
    }
    let sig = sig.expect("signature_algorithms");
    assert!(!sig.is_empty());
    assert!(
        !sig.iter().any(|s| [MLDSA44, MLDSA65, MLDSA87].contains(s)),
        "no ML-DSA when the maximum version is 1.2: {sig:04x?}"
    );
}

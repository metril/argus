//! Recovery for the `trust_anchors` ClientHello extension (Chrome 153+ profiles): a handshake that
//! fails certificate verification with the extension is retried once without it, remembered per
//! host, and a genuine certificate failure is never turned into a success.
//!
//! The origin looks at the raw ClientHello (peeked, not consumed) and presents a chain the client
//! does not trust only for the hellos selected by the test.

mod support;

use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use filter_engine::ErrorKind;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use support::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::TlsAcceptor;

const HOST: &str = "ta.test";
const UA_156: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36";
const UA_149: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36";

/// Extension types and the full records of the ClientHellos, in connection order.
type Hellos = Arc<Mutex<Vec<Vec<u8>>>>;

fn ext_types(rec: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let b = &rec[9..];
    let mut p = 2 + 32;
    p += 1 + b[p] as usize;
    p += 2 + u16::from_be_bytes([b[p], b[p + 1]]) as usize;
    p += 1 + b[p] as usize;
    let end = p + 2 + u16::from_be_bytes([b[p], b[p + 1]]) as usize;
    p += 2;
    let mut out = Vec::new();
    while p < end {
        let t = u16::from_be_bytes([b[p], b[p + 1]]);
        let l = u16::from_be_bytes([b[p + 2], b[p + 3]]) as usize;
        out.push((t, b[p + 4..p + 4 + l].to_vec()));
        p += 4 + l;
    }
    out
}

fn has_trust_anchors(rec: &[u8]) -> bool {
    ext_types(rec).iter().any(|(t, _)| *t == 0xca34)
}

struct TaOrigin {
    port: u16,
    hellos: Hellos,
    /// Connections that completed the TLS handshake and were served.
    served: Arc<AtomicUsize>,
}

impl TaOrigin {
    fn url(&self) -> String {
        format!("https://{HOST}:{}/", self.port)
    }
    fn tcp(&self) -> usize {
        self.hellos.lock().unwrap().len()
    }
    fn with_ta(&self) -> Vec<bool> {
        self.hellos
            .lock()
            .unwrap()
            .iter()
            .map(|r| has_trust_anchors(r))
            .collect()
    }
}

fn acceptor(chain: Vec<Vec<u8>>, key: rcgen::KeyPair) -> TlsAcceptor {
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        chain.into_iter().map(CertificateDer::from).collect(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
    .unwrap();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsAcceptor::from(Arc::new(cfg))
}

/// `bad_with_ta` / `bad_without_ta`: present the untrusted chain to hellos that do / do not carry
/// the `trust_anchors` extension.
async fn origin(trusted: &Ca, bad_with_ta: bool, bad_without_ta: bool) -> TaOrigin {
    let rogue = ca("rogue");
    let (gl, gk) = leaf(trusted, HOST);
    let good = acceptor(vec![gl, trusted.der.clone()], gk);
    let (bl, bk) = leaf(&rogue, HOST);
    let bad = acceptor(vec![bl, rogue.der.clone()], bk);
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let hellos: Hellos = Default::default();
    let served = Arc::new(AtomicUsize::new(0));
    let (h2, s2) = (hellos.clone(), served.clone());
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = l.accept().await else {
                return;
            };
            let (good, bad, h, served) = (good.clone(), bad.clone(), h2.clone(), s2.clone());
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                let rec = loop {
                    let n = tcp.peek(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    if n >= 5 && n >= 5 + u16::from_be_bytes([buf[3], buf[4]]) as usize {
                        break buf[..5 + u16::from_be_bytes([buf[3], buf[4]]) as usize].to_vec();
                    }
                    tokio::time::sleep(Duration::from_millis(2)).await;
                };
                let ta = has_trust_anchors(&rec);
                h.lock().unwrap().push(rec);
                let acc = if (ta && bad_with_ta) || (!ta && bad_without_ta) {
                    bad
                } else {
                    good
                };
                let Ok(mut tls) = acc.accept(tcp).await else {
                    return;
                };
                served.fetch_add(1, Ordering::SeqCst);
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
    TaOrigin {
        port,
        hellos,
        served,
    }
}

fn retries() -> u64 {
    common::faults::snapshot().trust_anchor_retries
}

async fn get(r: &Rig, o: &TaOrigin, ua: &str) -> Result<u16, proxy_core::upstream::UpstreamError> {
    r.client
        .get(o.url())
        .header("user-agent", ua)
        .send()
        .await
        .map(|resp| resp.status().as_u16())
}

#[tokio::test]
async fn a_chain_only_the_trust_anchors_hello_gets_is_retried_without_the_extension() {
    let trusted = ca("trusted");
    let o = origin(&trusted, true, false).await;
    let r = rig(&trusted, |_| {});
    let before = retries();
    assert_eq!(get(&r, &o, UA_156).await.unwrap(), 200);
    assert_eq!(
        o.with_ta(),
        vec![true, false],
        "first with the extension, then without"
    );
    assert_eq!(retries() - before, 1, "the retry is counted");
    assert_eq!(o.served.load(Ordering::SeqCst), 1);

    // The host is remembered: the next request does not try the extension again.
    assert_eq!(get(&r, &o, UA_156).await.unwrap(), 200);
    assert_eq!(
        o.with_ta(),
        vec![true, false, false],
        "no second failed attempt"
    );
    assert_eq!(retries() - before, 1);
}

#[tokio::test]
async fn the_retry_changes_nothing_but_the_extension() {
    let trusted = ca("trusted");
    let o = origin(&trusted, true, false).await;
    let r = rig(&trusted, |_| {});
    get(&r, &o, UA_156).await.unwrap();
    let h = o.hellos.lock().unwrap().clone();
    assert_eq!(h.len(), 2);
    let grease = |v: u16| (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff);
    let view = |rec: &[u8]| {
        let e = ext_types(rec);
        let get = |t: u16| e.iter().find(|(x, _)| *x == t).map(|(_, d)| d.clone());
        let mut types: Vec<u16> = e
            .iter()
            .map(|(t, _)| *t)
            .filter(|t| !grease(*t) && *t != 0xca34)
            .collect();
        types.sort();
        let sig: Vec<u16> = get(13).unwrap()[2..]
            .chunks(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .filter(|s| !grease(*s))
            .collect();
        let groups: Vec<u16> = get(10).unwrap()[2..]
            .chunks(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .filter(|s| !grease(*s))
            .collect();
        (types, sig, groups, get(16))
    };
    assert_eq!(view(&h[0]), view(&h[1]));
    assert!(has_trust_anchors(&h[0]) && !has_trust_anchors(&h[1]));
}

#[tokio::test]
async fn a_chain_that_is_bad_either_way_still_fails() {
    let trusted = ca("trusted");
    let o = origin(&trusted, true, true).await;
    let r = rig(&trusted, |_| {});
    let err = get(&r, &o, UA_156).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::UpstreamTls, "{err}");
    assert_eq!(o.with_ta(), vec![true, false], "one retry, no more");
    assert_eq!(
        o.served.load(Ordering::SeqCst),
        0,
        "no request ever reached the origin"
    );

    // Remembered as useless: one attempt per request from now on, and still a failure.
    let err = get(&r, &o, UA_156).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::UpstreamTls);
    assert_eq!(o.tcp(), 3);
    assert_eq!(o.served.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_good_chain_needs_no_retry() {
    let trusted = ca("trusted");
    let o = origin(&trusted, false, false).await;
    let r = rig(&trusted, |_| {});
    let before = retries();
    assert_eq!(get(&r, &o, UA_156).await.unwrap(), 200);
    assert_eq!(o.with_ta(), vec![true]);
    assert_eq!(retries(), before);
}

#[tokio::test]
async fn a_profile_without_the_extension_is_never_retried() {
    // Chrome 149 sends no trust_anchors: the failure is final and costs one attempt.
    let trusted = ca("trusted");
    let o = origin(&trusted, true, true).await;
    let r = rig(&trusted, |_| {});
    let before = retries();
    let err = get(&r, &o, UA_149).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::UpstreamTls);
    assert_eq!(o.with_ta(), vec![false]);
    assert_eq!(retries(), before);
}

#[tokio::test]
async fn the_plain_client_never_sends_the_extension_or_retries() {
    let trusted = ca("trusted");
    let o = origin(&trusted, false, true).await;
    let r = rig_with(&trusted, false, |_| {});
    let before = retries();
    assert!(get(&r, &o, UA_156).await.is_err());
    assert_eq!(o.tcp(), 1);
    assert_eq!(retries(), before);
}

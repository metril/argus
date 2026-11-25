//! The two upstream clients (rustls and the browser-like wreq one) against the same servers:
//! certificate verification is identical (every rejection happens before any request byte
//! reaches the origin), the browser's headers pass through untouched and in order, and a
//! changed trust set applies to the next handshake.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use common::certstore::{fingerprint, CertStore};
use filter_engine::ErrorKind;
use proxy_core::roots::{RootsData, RootsHandle, FLOOR_SERIAL, MIN_ROOTS};
use proxy_core::upstream::{build_upstream_client, UpstreamClient, UpstreamOptions};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::TlsAcceptor;

struct Ca {
    issuer: Issuer<'static, KeyPair>,
    der: Vec<u8>,
    pem: String,
}

fn ca(name: &str) -> Ca {
    let mut p = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, name);
    p.distinguished_name = dn;
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let key = KeyPair::generate().unwrap();
    let cert = p.self_signed(&key).unwrap();
    Ca {
        der: cert.der().to_vec(),
        pem: cert.pem(),
        issuer: Issuer::new(p, key),
    }
}

/// A leaf for `name` signed by `ca`: (leaf DER, key).
fn leaf(ca: &Ca, name: &str, tweak: impl FnOnce(&mut CertificateParams)) -> (Vec<u8>, KeyPair) {
    let mut p = CertificateParams::default();
    p.subject_alt_names = vec![SanType::DnsName(name.try_into().unwrap())];
    tweak(&mut p);
    let key = KeyPair::generate().unwrap();
    let cert = p.signed_by(&key, &ca.issuer).unwrap();
    (cert.der().to_vec(), key)
}

/// A TLS (http/1.1) origin counting the requests it receives, answering each with `ok`.
struct Origin {
    port: u16,
    requests: Arc<AtomicUsize>,
}

async fn origin(chain: Vec<Vec<u8>>, key: KeyPair) -> Origin {
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
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let requests = Arc::new(AtomicUsize::new(0));
    let n = requests.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let (acceptor, n) = (acceptor.clone(), n.clone());
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 2048];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(k) => buf.extend_from_slice(&chunk[..k]),
                    }
                }
                n.fetch_add(1, Ordering::SeqCst);
                let _ = tls
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                    )
                    .await;
                let _ = tls.shutdown().await;
            });
        }
    });
    Origin { port, requests }
}

impl Origin {
    fn url(&self, host: &str) -> String {
        format!("https://{host}:{}/", self.port)
    }

    fn seen(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

struct Rig {
    client: UpstreamClient,
    roots: Arc<RootsHandle>,
    certs: Arc<CertStore>,
    _dir: tempfile::TempDir,
}

fn write_pem(dir: &tempfile::TempDir, name: &str, pem: &str) -> PathBuf {
    let p = dir.path().join(name);
    std::fs::write(&p, pem).unwrap();
    p
}

/// A client trusting `trusted` (besides the built-in roots), dialling every name to loopback and
/// opening a fresh connection (with a resumable session) per request.
fn rig(browser_like: bool, trusted: &Ca) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let path = write_pem(&dir, "ca.pem", &trusted.pem);
    let roots = RootsHandle::floor(&[path]).unwrap();
    let certs = Arc::new(CertStore::new(8 << 20, 1000));
    let client = build_upstream_client(&UpstreamOptions {
        roots: Some(roots.clone()),
        certs: certs.clone(),
        resolve_all_to: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        pool_max_idle_per_host: Some(0),
        connect_timeout: Some(Duration::from_secs(5)),
        read_timeout: Some(Duration::from_secs(5)),
        browser_like,
        ..Default::default()
    })
    .unwrap();
    assert_eq!(client.is_browser_like(), browser_like);
    Rig {
        client,
        roots,
        certs,
        _dir: dir,
    }
}

const BOTH: [bool; 2] = [false, true];

/// The request failed in the TLS layer, and nothing reached the origin.
async fn refused(r: &Rig, o: &Origin, host: &str, what: &str) {
    let before = o.seen();
    let err = match r.client.get(o.url(host)).send().await {
        Ok(resp) => panic!("{what}: expected a TLS failure, got {}", resp.status()),
        Err(e) => e,
    };
    assert_eq!(
        err.kind(),
        ErrorKind::UpstreamTls,
        "{what}: wrong kind for {err:?}"
    );
    // The server may still be finishing the handshake it saw abort: give it a moment, then
    // check that not one request byte arrived.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(o.seen(), before, "{what}: request bytes reached the origin");
}

async fn ok_body(r: &Rig, o: &Origin, host: &str) -> proxy_core::upstream::UpstreamResponse {
    let resp = r.client.get(o.url(host)).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    resp
}

#[tokio::test]
async fn a_trusted_chain_is_served_and_its_certificate_reported() {
    for bl in BOTH {
        let trusted = ca("trusted");
        let (der, key) = leaf(&trusted, "good.test", |_| {});
        let o = origin(vec![der.clone(), trusted.der.clone()], key).await;
        let r = rig(bl, &trusted);
        let resp = ok_body(&r, &o, "good.test").await;
        assert_eq!(resp.peer_certificate(), Some(der.as_slice()), "bl={bl}");
        assert_eq!(o.seen(), 1);
    }
}

#[tokio::test]
async fn an_unknown_issuer_is_refused_before_any_request() {
    for bl in BOTH {
        let (trusted, stranger) = (ca("trusted"), ca("stranger"));
        let (der, key) = leaf(&stranger, "good.test", |_| {});
        let o = origin(vec![der, stranger.der.clone()], key).await;
        refused(
            &rig(bl, &trusted),
            &o,
            "good.test",
            &format!("unknown issuer bl={bl}"),
        )
        .await;
    }
}

#[tokio::test]
async fn an_expired_certificate_is_refused_before_any_request() {
    for bl in BOTH {
        let trusted = ca("trusted");
        let (der, key) = leaf(&trusted, "good.test", |p| {
            p.not_before = rcgen::date_time_ymd(2000, 1, 1);
            p.not_after = rcgen::date_time_ymd(2001, 1, 1);
        });
        let o = origin(vec![der, trusted.der.clone()], key).await;
        refused(
            &rig(bl, &trusted),
            &o,
            "good.test",
            &format!("expired bl={bl}"),
        )
        .await;
    }
}

#[tokio::test]
async fn a_certificate_for_another_name_is_refused_before_any_request() {
    for bl in BOTH {
        let trusted = ca("trusted");
        let (der, key) = leaf(&trusted, "other.test", |_| {});
        let o = origin(vec![der, trusted.der.clone()], key).await;
        refused(
            &rig(bl, &trusted),
            &o,
            "good.test",
            &format!("name mismatch bl={bl}"),
        )
        .await;
    }
}

/// A signed-set document trusting `root` with a distrust-after date, padded to the minimum size.
fn distrust_set(root: &[u8], distrust_after: &str) -> Arc<RootsData> {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let b64 = |d: &[u8]| base64::engine::general_purpose::STANDARD.encode(d);
    let hex = |d: &[u8]| {
        Sha256::digest(d)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    let mut roots = vec![serde_json::json!({
        "sha256": hex(root), "subject": "CN=fixture", "der": b64(root),
        "distrust_after": distrust_after, "sct_not_after": null, "permitted_dns_names": [],
    })];
    while roots.len() < MIN_ROOTS {
        let filler = ca(&format!("filler {}", roots.len()));
        roots.push(serde_json::json!({
            "sha256": hex(&filler.der), "subject": "CN=filler", "der": b64(&filler.der),
            "distrust_after": null, "sct_not_after": null, "permitted_dns_names": [],
        }));
    }
    let doc = serde_json::json!({
        "schema": 1, "serial": FLOOR_SERIAL + 1, "generated_at": "2026-11-23T00:00:00Z",
        "sources": {}, "roots": roots, "ct_logs": [],
    });
    Arc::new(RootsData::parse(doc.to_string().as_bytes()).unwrap())
}

#[tokio::test]
async fn a_distrusted_root_is_refused_before_any_request() {
    for bl in BOTH {
        let trusted = ca("trusted");
        let (der, key) = leaf(&trusted, "good.test", |_| {});
        let o = origin(vec![der, trusted.der.clone()], key).await;
        let r = rig(bl, &trusted);
        // The signed set trusts the root only for certificates issued before 1970.
        r.roots
            .install(distrust_set(&trusted.der, "1970-01-01T00:00:00Z"))
            .unwrap();
        refused(&r, &o, "good.test", &format!("distrusted bl={bl}")).await;
    }
}

#[tokio::test]
async fn an_extended_validation_certificate_is_recorded_as_such() {
    for bl in BOTH {
        let trusted = ca("trusted");
        let (der, key) = leaf(&trusted, "ev.test", |p| {
            // certificatePolicies ::= SEQUENCE { SEQUENCE { OID 2.23.140.1.1 } }
            p.custom_extensions
                .push(rcgen::CustomExtension::from_oid_content(
                    &[2, 5, 29, 32],
                    vec![
                        0x30, 0x09, 0x30, 0x07, 0x06, 0x05, 0x67, 0x81, 0x0c, 0x01, 0x01,
                    ],
                ));
        });
        let (plain, plain_key) = leaf(&trusted, "plain.test", |_| {});
        let o = origin(vec![der.clone(), trusted.der.clone()], key).await;
        let o2 = origin(vec![plain.clone(), trusted.der.clone()], plain_key).await;
        let r = rig(bl, &trusted);
        ok_body(&r, &o, "ev.test").await;
        ok_body(&r, &o2, "plain.test").await;
        let ev = r.certs.info(&fingerprint(&der), None).expect("ev recorded");
        assert!(ev.ev, "bl={bl}");
        let pl = r
            .certs
            .info(&fingerprint(&plain), None)
            .expect("plain recorded");
        assert!(!pl.ev, "bl={bl}");
    }
}

#[tokio::test]
async fn swapping_the_trusted_roots_applies_to_the_next_handshake() {
    for bl in BOTH {
        let (a, b) = (ca("root a"), ca("root b"));
        let (der, key) = leaf(&a, "good.test", |_| {});
        let o = origin(vec![der, a.der.clone()], key).await;
        let r = rig(bl, &a);
        // Twice: the second handshake resumes the first one's session, and is verified anyway.
        ok_body(&r, &o, "good.test").await;
        ok_body(&r, &o, "good.test").await;
        assert_eq!(o.seen(), 2);
        // The set now trusts another root: a server of the old one is refused, request bytes
        // unsent. A name seen before resumes its session, which the rustls client accepts
        // without asking the verifier again (as before); the browser-like client verifies
        // resumed sessions too.
        let (der2, key2) = leaf(&a, "second.test", |_| {});
        let o2 = origin(vec![der2, a.der.clone()], key2).await;
        let p = write_pem(&r._dir, "b.pem", &b.pem);
        r.roots.set_extras(&[p]).unwrap();
        refused(&r, &o2, "second.test", &format!("root swap bl={bl}")).await;
        if bl {
            refused(&r, &o, "good.test", "root swap, resumed session").await;
            assert_eq!(o.seen(), 2);
        }
    }
}

#[tokio::test]
async fn an_unreachable_origin_is_not_a_tls_error() {
    for bl in BOTH {
        let trusted = ca("trusted");
        let r = rig(bl, &trusted);
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        let e = r
            .client
            .get(format!("https://good.test:{port}/"))
            .send()
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::UpstreamReset, "bl={bl}: {e:?}");
    }
}

/// A plain-TCP origin that records the raw request head.
async fn raw_origin() -> (SocketAddr, Arc<Mutex<Vec<Vec<u8>>>>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let heads = Arc::new(Mutex::new(Vec::new()));
    let h = heads.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            let h = h.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 2048];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(k) => buf.extend_from_slice(&chunk[..k]),
                    }
                }
                h.lock().unwrap().push(buf);
                let _ = s
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                    )
                    .await;
            });
        }
    });
    (addr, heads)
}

#[tokio::test]
async fn the_browsers_headers_reach_the_origin_untouched_and_in_order() {
    let (addr, heads) = raw_origin().await;
    let client = build_upstream_client(&UpstreamOptions {
        browser_like: true,
        ..Default::default()
    })
    .unwrap();
    let ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36";
    let sent = [
        (
            "sec-ch-ua",
            "\"Chromium\";v=\"146\", \"Google Chrome\";v=\"146\"",
        ),
        ("user-agent", ua),
        ("accept", "text/html"),
        ("x-zeta", "1"),
        ("accept-language", "fr-FR"),
        ("x-alpha", "2"),
    ];
    let mut rb = client.get(format!("http://{addr}/p"));
    for (k, v) in sent {
        rb = rb.header(k, v);
    }
    let resp = rb.send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let raw = heads.lock().unwrap()[0].clone();
    let text = String::from_utf8(raw).unwrap();
    let lines: Vec<&str> = text.split("\r\n").collect();
    assert_eq!(lines[0], "GET /p HTTP/1.1", "{text}");
    let names: Vec<String> = lines[1..]
        .iter()
        .take_while(|l| !l.is_empty())
        .map(|l| l.split(':').next().unwrap().to_ascii_lowercase())
        .collect();
    // Exactly the browser's headers, in its order; the client adds only `Host`.
    let ours: Vec<&str> = names
        .iter()
        .map(String::as_str)
        .filter(|n| *n != "host")
        .collect();
    assert_eq!(
        ours,
        [
            "sec-ch-ua",
            "user-agent",
            "accept",
            "x-zeta",
            "accept-language",
            "x-alpha"
        ],
        "{text}"
    );
    assert!(text.contains(&format!("\r\n{}", "sec-ch-ua: ")), "{text}");
    assert!(text.contains(&format!("User-Agent: {ua}")), "{text}");
    assert!(
        !text.to_ascii_lowercase().contains("accept-encoding"),
        "{text}"
    );
    assert_eq!(
        text.matches("\r\nuser-agent").count() + text.matches("\r\nUser-Agent").count(),
        1
    );
}

/// Needs the network: `cargo nextest run -p proxy-core --run-ignored only chrome_ja4`.
#[tokio::test]
#[ignore = "network"]
async fn chrome_ja4_fingerprint_is_presented_to_a_real_server() {
    let client = build_upstream_client(&UpstreamOptions {
        browser_like: true,
        ..Default::default()
    })
    .unwrap();
    let resp = client
        .get("https://tls.peet.ws/api/all")
        .header("user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36")
        .header("sec-ch-ua", "\"Chromium\";v=\"146\", \"Google Chrome\";v=\"146\"")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    use futures_util::TryStreamExt;
    let body: Vec<bytes::Bytes> = resp.bytes_stream().try_collect().await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body.concat()).unwrap();
    let ja4 = json["tls"]["ja4"].as_str().expect("ja4").to_string();
    println!("ja4 = {ja4}");
    let head = ja4.split('_').next().unwrap();
    assert!(head.starts_with("t13d15") && head.ends_with("h2"), "{ja4}");
}

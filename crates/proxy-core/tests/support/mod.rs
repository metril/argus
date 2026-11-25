//! A local TLS + HTTP/2 origin with scripted misbehaviour, and a browser-like client trusting it.
#![allow(dead_code)]

use std::{
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use common::certstore::CertStore;
use proxy_core::roots::RootsHandle;
use proxy_core::upstream::{build_upstream_client, UpstreamClient, UpstreamOptions};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

pub const CHROME_UA: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

pub struct Ca {
    pub issuer: Issuer<'static, KeyPair>,
    pub der: Vec<u8>,
    pub pem: String,
}

pub fn ca(name: &str) -> Ca {
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

pub fn leaf(ca: &Ca, name: &str) -> (Vec<u8>, KeyPair) {
    let mut p = CertificateParams::default();
    p.subject_alt_names = vec![SanType::DnsName(name.try_into().unwrap())];
    let key = KeyPair::generate().unwrap();
    let cert = p.signed_by(&key, &ca.issuer).unwrap();
    (cert.der().to_vec(), key)
}

/// What the origin does with one request.
#[derive(Clone, Copy, Debug)]
pub enum Act {
    /// Answer 200 "ok".
    Ok,
    /// Send GOAWAY (`ENHANCE_YOUR_CALM`) and close, answering nothing.
    Goaway,
    /// Send GOAWAY (`REFUSED_STREAM`, last stream id covering this request) and close.
    GoawayRefused,
    /// Reset the stream with `REFUSED_STREAM`.
    Refuse,
    /// Close the TCP connection without a word.
    Drop,
    /// Never answer.
    Hang,
}

/// Decides per (0-based connection index, 0-based request index on that connection).
pub type Script = Arc<dyn Fn(usize, usize) -> Act + Send + Sync>;

#[derive(Default)]
pub struct Stats {
    /// TCP connections accepted (including ones whose handshake failed).
    pub tcp: AtomicUsize,
    /// TLS connections accepted.
    pub conns: AtomicUsize,
    /// Of those, resumed ones.
    pub resumed: AtomicUsize,
    /// Streams received (answered or not).
    pub requests: AtomicUsize,
    /// Connections currently open on the server side.
    pub open: AtomicUsize,
    /// Connections the origin has dropped on a `close_on` signal.
    pub closed: AtomicUsize,
    /// Streams received per connection, in accept order.
    pub per_conn: Mutex<Vec<usize>>,
}

pub struct Origin {
    pub port: u16,
    pub stats: Arc<Stats>,
}

impl Origin {
    pub fn url(&self, host: &str) -> String {
        format!("https://{host}:{}/", self.port)
    }

    /// Wait (bounded) until `f(stats)` holds.
    pub async fn until(&self, what: &str, f: impl Fn(&Stats) -> bool) {
        for _ in 0..200 {
            if f(&self.stats) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!(
            "timed out waiting for {what}: conns={} resumed={} requests={} open={}",
            self.stats.conns.load(Ordering::SeqCst),
            self.stats.resumed.load(Ordering::SeqCst),
            self.stats.requests.load(Ordering::SeqCst),
            self.stats.open.load(Ordering::SeqCst),
        );
    }
}

pub fn ok_script() -> Script {
    Arc::new(|_, _| Act::Ok)
}

pub async fn h2_origin(chain: Vec<Vec<u8>>, key: KeyPair, script: Script) -> Origin {
    h2_origin_with(chain, key, script, Arc::new(|_| false)).await
}

/// An HTTP/1.1 origin that says keep-alive and then closes the connection after each response.
pub async fn h1_closing_origin(chain: Vec<Vec<u8>>, key: KeyPair) -> Origin {
    h1_closing_origin_after(chain, key, None).await
}

/// Like [`h1_closing_origin`]; with `Some(signal)` each connection stays open after its response
/// until the signal turns `true`, then is dropped (counted in `stats.closed`). The origin runs on
/// its own thread so a blocked client runtime cannot stall it.
pub async fn h1_closing_origin_after(
    chain: Vec<Vec<u8>>,
    key: KeyPair,
    close_on: Option<tokio::sync::watch::Receiver<bool>>,
) -> Origin {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    std_listener.set_nonblocking(true).unwrap();
    let port = std_listener.local_addr().unwrap().port();
    let stats = Arc::new(Stats::default());
    let st = stats.clone();
    let threaded = close_on.is_some();
    let serve = async move {
        let listener = TcpListener::from_std(std_listener).unwrap();
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let (acceptor, st, close_on) = (acceptor.clone(), st.clone(), close_on.clone());
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                st.conns.fetch_add(1, Ordering::SeqCst);
                let mut buf = Vec::new();
                let mut chunk = [0u8; 2048];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(k) => buf.extend_from_slice(&chunk[..k]),
                    }
                }
                st.requests.fetch_add(1, Ordering::SeqCst);
                let _ = tls
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: keep-alive\r\n\r\nok",
                    )
                    .await;
                // Gone without a close_notify, after promising to keep the connection.
                if let Some(mut rx) = close_on {
                    let _ = rx.wait_for(|closed| *closed).await;
                    drop(tls);
                    st.closed.fetch_add(1, Ordering::SeqCst);
                }
            });
        }
    };
    if threaded {
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(serve)
        });
    } else {
        tokio::spawn(serve);
    }
    Origin { port, stats }
}

/// Like [`h2_origin`]; `early(conn)` makes that connection send GOAWAY before any stream.
pub async fn h2_origin_with(
    chain: Vec<Vec<u8>>,
    key: KeyPair,
    script: Script,
    early: Arc<dyn Fn(usize) -> bool + Send + Sync>,
) -> Origin {
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
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let stats = Arc::new(Stats::default());
    let st = stats.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let (acceptor, st, script, early) =
                (acceptor.clone(), st.clone(), script.clone(), early.clone());
            st.tcp.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let idx = st.conns.fetch_add(1, Ordering::SeqCst);
                st.per_conn.lock().unwrap().push(0);
                if matches!(
                    tls.get_ref().1.handshake_kind(),
                    Some(rustls::HandshakeKind::Resumed)
                ) {
                    st.resumed.fetch_add(1, Ordering::SeqCst);
                }
                st.open.fetch_add(1, Ordering::SeqCst);
                serve(tls, idx, st.clone(), script, early(idx)).await;
                st.open.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    Origin { port, stats }
}

async fn serve(
    tls: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    idx: usize,
    st: Arc<Stats>,
    script: Script,
    early_goaway: bool,
) {
    let Ok(mut conn) = h2::server::handshake(tls).await else {
        return;
    };
    if early_goaway {
        conn.abrupt_shutdown(h2::Reason::NO_ERROR);
        while conn.accept().await.is_some() {}
        return;
    }
    while let Some(Ok((_req, mut respond))) = conn.accept().await {
        st.requests.fetch_add(1, Ordering::SeqCst);
        let n = {
            let mut v = st.per_conn.lock().unwrap();
            v[idx] += 1;
            v[idx] - 1
        };
        match script(idx, n) {
            Act::Ok => {
                tokio::spawn(async move {
                    let resp = hyper::Response::builder().status(200).body(()).unwrap();
                    if let Ok(mut s) = respond.send_response(resp, false) {
                        let _ = s.send_data(bytes::Bytes::from_static(b"ok"), true);
                    }
                });
            }
            Act::Refuse => respond.send_reset(h2::Reason::REFUSED_STREAM),
            Act::Goaway => {
                conn.abrupt_shutdown(h2::Reason::ENHANCE_YOUR_CALM);
                while conn.accept().await.is_some() {}
                return;
            }
            Act::GoawayRefused => {
                conn.abrupt_shutdown(h2::Reason::REFUSED_STREAM);
                while conn.accept().await.is_some() {}
                return;
            }
            Act::Drop => return,
            Act::Hang => {
                tokio::spawn(async move {
                    let _keep = respond;
                    tokio::time::sleep(Duration::from_secs(60)).await;
                });
            }
        }
    }
}

pub struct Rig {
    pub client: UpstreamClient,
    pub _dir: tempfile::TempDir,
}

/// A browser-like client trusting `trusted`, dialling every name to loopback.
pub fn rig(trusted: &Ca, tweak: impl FnOnce(&mut UpstreamOptions)) -> Rig {
    rig_with(trusted, true, tweak)
}

/// Like [`rig`], for the browser-like (wreq) or the plain (reqwest) client.
pub fn rig_with(trusted: &Ca, browser_like: bool, tweak: impl FnOnce(&mut UpstreamOptions)) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let path: PathBuf = dir.path().join("ca.pem");
    std::fs::write(&path, &trusted.pem).unwrap();
    let mut opts = UpstreamOptions {
        roots: Some(RootsHandle::floor(&[path]).unwrap()),
        certs: Arc::new(CertStore::new(8 << 20, 1000)),
        resolve_all_to: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        connect_timeout: Some(Duration::from_secs(5)),
        read_timeout: Some(Duration::from_secs(5)),
        browser_like,
        ..Default::default()
    };
    tweak(&mut opts);
    let client = build_upstream_client(&opts).unwrap();
    assert_eq!(client.is_browser_like(), browser_like);
    Rig { client, _dir: dir }
}

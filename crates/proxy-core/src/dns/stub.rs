//! In-process DNS servers on ephemeral ports for tests: UDP, TCP, DoT, DoH (h2) and DoQ. Each
//! test starts its own, so tests share nothing and run in parallel.

use hickory_resolver::proto::op::{Message, OpCode, ResponseCode};
use hickory_resolver::proto::rr::rdata::{opt::EdnsOption, A, AAAA, PTR};
use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// What a stub answers; change it while the server runs.
#[derive(Clone)]
pub struct Behavior {
    /// Exact name (lowercase, no dot) to addresses (A and AAAA by family).
    pub answers: HashMap<String, Vec<IpAddr>>,
    /// Answer for every other name (NXDOMAIN when `None`).
    pub default: Option<Vec<IpAddr>>,
    pub ttl: u32,
    pub delay: Duration,
    /// Never answer.
    pub drop: bool,
    /// Answer every query with this code (SERVFAIL, REFUSED...).
    pub rcode: Option<ResponseCode>,
    /// PTR answers by reversed name.
    pub ptr: HashMap<String, String>,
    /// Set the TC bit on UDP answers (the full answer is sent over TCP).
    pub truncate_udp: bool,
}

impl Default for Behavior {
    fn default() -> Self {
        Self {
            answers: HashMap::new(),
            default: None,
            ttl: 60,
            delay: Duration::ZERO,
            drop: false,
            rcode: None,
            ptr: HashMap::new(),
            truncate_udp: false,
        }
    }
}

impl Behavior {
    pub fn answering(ip: &str) -> Self {
        Self {
            default: Some(vec![ip.parse().unwrap()]),
            ..Self::default()
        }
    }
    pub fn answering_many(ips: &[&str]) -> Self {
        Self {
            default: Some(ips.iter().map(|i| i.parse().unwrap()).collect()),
            ..Self::default()
        }
    }
}

pub struct Stub {
    pub addr: SocketAddr,
    /// Queries received (all types).
    pub queries: Arc<AtomicU64>,
    /// `(name, type)` of every query, in order.
    pub log: Arc<Mutex<Vec<(String, RecordType)>>>,
    /// The ECS subnet of the last query that had one.
    pub last_ecs: Arc<Mutex<Option<(IpAddr, u8)>>>,
    #[allow(dead_code)]
    pub behavior: Arc<Mutex<Behavior>>,
}

impl Stub {
    pub fn count(&self) -> u64 {
        self.queries.load(Ordering::SeqCst)
    }
    pub fn count_type(&self, t: RecordType) -> usize {
        self.log.lock().iter().filter(|(_, x)| *x == t).count()
    }
    #[allow(dead_code)]
    pub fn set(&self, f: impl FnOnce(&mut Behavior)) {
        f(&mut self.behavior.lock());
    }
    /// Names asked, lowercase.
    pub fn names(&self) -> Vec<String> {
        self.log.lock().iter().map(|(n, _)| n.clone()).collect()
    }
}

#[derive(Clone)]
struct Core {
    queries: Arc<AtomicU64>,
    log: Arc<Mutex<Vec<(String, RecordType)>>>,
    last_ecs: Arc<Mutex<Option<(IpAddr, u8)>>>,
    behavior: Arc<Mutex<Behavior>>,
}

impl Core {
    fn new(b: Behavior) -> (Self, Stub, ()) {
        let c = Core {
            queries: Arc::default(),
            log: Arc::default(),
            last_ecs: Arc::default(),
            behavior: Arc::new(Mutex::new(b)),
        };
        let s = Stub {
            addr: "0.0.0.0:0".parse().unwrap(),
            queries: c.queries.clone(),
            log: c.log.clone(),
            last_ecs: c.last_ecs.clone(),
            behavior: c.behavior.clone(),
        };
        (c, s, ())
    }

    /// The reply to `wire`, after the configured delay; `None` = stay silent.
    async fn answer(&self, wire: &[u8], udp: bool) -> Option<Vec<u8>> {
        let q = Message::from_vec(wire).ok()?;
        let b = self.behavior.lock().clone();
        self.queries.fetch_add(1, Ordering::SeqCst);
        let qq = q.queries.first()?.clone();
        let name = qq
            .name()
            .to_utf8()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        self.log.lock().push((name.clone(), qq.query_type()));
        if let Some(e) = &q.edns {
            if let Some(EdnsOption::Subnet(s)) =
                e.option(hickory_resolver::proto::rr::rdata::opt::EdnsCode::Subnet)
            {
                *self.last_ecs.lock() = Some((s.addr(), s.source_prefix()));
            }
        }
        if b.drop {
            return None;
        }
        if !b.delay.is_zero() {
            tokio::time::sleep(b.delay).await;
        }
        let mut r = Message::response(q.metadata.id, OpCode::Query);
        r.metadata.recursion_desired = true;
        r.metadata.recursion_available = true;
        r.queries = q.queries.clone();
        if let Some(e) = q.edns.clone() {
            r.set_edns(e);
        }
        if let Some(c) = b.rcode {
            r.metadata.response_code = c;
            return r.to_vec().ok();
        }
        match qq.query_type() {
            RecordType::A | RecordType::AAAA => {
                let ips = b.answers.get(&name).cloned().or(b.default.clone());
                match ips {
                    None => r.metadata.response_code = ResponseCode::NXDomain,
                    Some(ips) => {
                        for ip in ips {
                            let d = match (ip, qq.query_type()) {
                                (IpAddr::V4(v), RecordType::A) => RData::A(A(v)),
                                (IpAddr::V6(v), RecordType::AAAA) => RData::AAAA(AAAA(v)),
                                _ => continue,
                            };
                            r.add_answer(Record::from_rdata(qq.name().clone(), b.ttl, d));
                        }
                    }
                }
            }
            RecordType::PTR => match b.ptr.get(&name) {
                Some(h) => {
                    let n = Name::from_ascii(format!("{h}.")).unwrap();
                    r.add_answer(Record::from_rdata(
                        qq.name().clone(),
                        b.ttl,
                        RData::PTR(PTR(n)),
                    ));
                }
                None => r.metadata.response_code = ResponseCode::NXDomain,
            },
            _ => {}
        }
        if udp && b.truncate_udp {
            r.answers.clear();
            r.metadata.truncation = true;
        }
        r.to_vec().ok()
    }
}

async fn serve_framed<S>(core: Core, mut s: S)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        let mut l = [0u8; 2];
        if s.read_exact(&mut l).await.is_err() {
            return;
        }
        let mut buf = vec![0u8; u16::from_be_bytes(l) as usize];
        if s.read_exact(&mut buf).await.is_err() {
            return;
        }
        if let Some(r) = core.answer(&buf, false).await {
            let mut out = (r.len() as u16).to_be_bytes().to_vec();
            out.extend(r);
            if s.write_all(&out).await.is_err() {
                return;
            }
        }
    }
}

/// UDP and TCP on the same ephemeral port.
pub async fn start(b: Behavior) -> Stub {
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let udp = tokio::net::UdpSocket::bind(addr).await.unwrap();
    let (core, mut stub, ()) = Core::new(b);
    stub.addr = addr;
    let c = core.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = tcp.accept().await {
            tokio::spawn(serve_framed(c.clone(), s));
        }
    });
    let udp = Arc::new(udp);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        while let Ok((n, peer)) = udp.recv_from(&mut buf).await {
            let (c, u, data) = (core.clone(), udp.clone(), buf[..n].to_vec());
            tokio::spawn(async move {
                if let Some(r) = c.answer(&data, true).await {
                    let _ = u.send_to(&r, peer).await;
                }
            });
        }
    });
    stub
}

/// A self-signed certificate for `dns.test`, and the server and client TLS configs for it.
pub struct Tls {
    pub server: Arc<rustls::ServerConfig>,
    pub client: rustls::ClientConfig,
}

pub fn tls(alpn: &[&[u8]]) -> Tls {
    let ck = rcgen::generate_simple_self_signed(vec!["dns.test".to_string()]).unwrap();
    let der = ck.cert.der().clone();
    let key = rustls::pki_types::PrivateKeyDer::try_from(ck.signing_key.serialize_der()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], key)
        .unwrap();
    server.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Tls {
        server: Arc::new(server),
        client,
    }
}

/// DNS over TLS.
pub async fn start_dot(b: Behavior, t: &Tls) -> Stub {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (core, mut stub, ()) = Core::new(b);
    stub.addr = l.local_addr().unwrap();
    let acc = tokio_rustls::TlsAcceptor::from(t.server.clone());
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let (acc, c) = (acc.clone(), core.clone());
            tokio::spawn(async move {
                if let Ok(s) = acc.accept(s).await {
                    serve_framed(c, s).await;
                }
            });
        }
    });
    stub
}

/// DNS over HTTPS (HTTP/2, POST and GET on any path).
pub async fn start_doh(b: Behavior, t: &Tls) -> Stub {
    use base64::Engine;
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (core, mut stub, ()) = Core::new(b);
    stub.addr = l.local_addr().unwrap();
    let acc = tokio_rustls::TlsAcceptor::from(t.server.clone());
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let (acc, c) = (acc.clone(), core.clone());
            tokio::spawn(async move {
                let Ok(s) = acc.accept(s).await else { return };
                let Ok(mut conn) = h2::server::handshake(s).await else {
                    return;
                };
                while let Some(Ok((req, mut respond))) = conn.accept().await {
                    let c = c.clone();
                    tokio::spawn(async move {
                        let (parts, mut body) = req.into_parts();
                        let wire = if parts.method == hyper::http::Method::GET {
                            let q = parts.uri.query().unwrap_or("");
                            let v = q.strip_prefix("dns=").unwrap_or("");
                            base64::engine::general_purpose::URL_SAFE_NO_PAD
                                .decode(v)
                                .unwrap_or_default()
                        } else {
                            let mut v = Vec::new();
                            while let Some(Ok(d)) = body.data().await {
                                let _ = body.flow_control().release_capacity(d.len());
                                v.extend_from_slice(&d);
                            }
                            v
                        };
                        match c.answer(&wire, false).await {
                            Some(r) => {
                                let resp = hyper::http::Response::builder()
                                    .status(200)
                                    .header("content-type", "application/dns-message")
                                    .body(())
                                    .unwrap();
                                if let Ok(mut s) = respond.send_response(resp, false) {
                                    let _ = s.send_data(bytes::Bytes::from(r), true);
                                }
                            }
                            None => {
                                // Never answered: reset the stream.
                                respond.send_reset(h2::Reason::CANCEL);
                            }
                        }
                    });
                }
            });
        }
    });
    stub
}

fn quic_endpoint(t: &Tls) -> quinn::Endpoint {
    let q = quinn::crypto::rustls::QuicServerConfig::try_from(t.server.clone()).unwrap();
    quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(q)),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap()
}

/// DNS over QUIC (RFC 9250): one query per bidirectional stream, 2-byte length prefix. `t` must
/// have been made with the `doq` ALPN.
pub async fn start_doq(b: Behavior, t: &Tls) -> Stub {
    let ep = quic_endpoint(t);
    let (core, mut stub, ()) = Core::new(b);
    stub.addr = ep.local_addr().unwrap();
    tokio::spawn(async move {
        while let Some(inc) = ep.accept().await {
            let c = core.clone();
            tokio::spawn(async move {
                let Ok(conn) = inc.await else { return };
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    let c = c.clone();
                    tokio::spawn(async move {
                        let mut l = [0u8; 2];
                        if recv.read_exact(&mut l).await.is_err() {
                            return;
                        }
                        let mut buf = vec![0u8; u16::from_be_bytes(l) as usize];
                        if recv.read_exact(&mut buf).await.is_err() {
                            return;
                        }
                        if let Some(r) = c.answer(&buf, false).await {
                            let mut out = (r.len() as u16).to_be_bytes().to_vec();
                            out.extend(r);
                            let _ = send.write_all(&out).await;
                            let _ = send.finish();
                            // Let the client read it before the stream is dropped.
                            let _ = send.stopped().await;
                        }
                    });
                }
            });
        }
    });
    stub
}

/// DNS over HTTP/3. `t` must have been made with the `h3` ALPN.
pub async fn start_h3(b: Behavior, t: &Tls) -> Stub {
    use base64::Engine;
    use bytes::Buf;
    let ep = quic_endpoint(t);
    let (core, mut stub, ()) = Core::new(b);
    stub.addr = ep.local_addr().unwrap();
    tokio::spawn(async move {
        while let Some(inc) = ep.accept().await {
            let c = core.clone();
            tokio::spawn(async move {
                let Ok(conn) = inc.await else { return };
                let Ok(mut h3c) =
                    h3::server::Connection::new(h3_quinn::Connection::new(conn)).await
                else {
                    return;
                };
                while let Ok(Some(resolver)) = h3c.accept().await {
                    let c = c.clone();
                    tokio::spawn(async move {
                        let Ok((req, mut stream)) = resolver.resolve_request().await else {
                            return;
                        };
                        let mut wire = Vec::new();
                        if req.method() == hyper::http::Method::GET {
                            let q = req.uri().query().unwrap_or("");
                            wire = base64::engine::general_purpose::URL_SAFE_NO_PAD
                                .decode(q.strip_prefix("dns=").unwrap_or(""))
                                .unwrap_or_default();
                        } else {
                            while let Ok(Some(mut chunk)) = stream.recv_data().await {
                                wire.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
                            }
                        }
                        if let Some(r) = c.answer(&wire, false).await {
                            let resp = hyper::http::Response::builder()
                                .status(200)
                                .header("content-type", "application/dns-message")
                                .body(())
                                .unwrap();
                            if stream.send_response(resp).await.is_ok() {
                                let _ = stream.send_data(bytes::Bytes::from(r)).await;
                                let _ = stream.finish().await;
                            }
                        }
                    });
                }
            });
        }
    });
    stub
}

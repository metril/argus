use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use parking_lot::Mutex;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::WebSocketStream;

/// A canned response for a route.
#[derive(Clone, Debug)]
pub struct MockResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Wait this long before answering (for timeout tests).
    pub delay: std::time::Duration,
    /// Stream a generated body instead of `body` (large and endless bodies).
    pub stream: Option<StreamSpec>,
}

/// A generated body: `chunk` repeated until `total` bytes have been produced, polling-driven so
/// the origin only generates what the connection actually pulls.
#[derive(Clone, Debug)]
pub struct StreamSpec {
    pub chunk: Bytes,
    /// Bytes to send in all (`usize::MAX` for an endless body).
    pub total: usize,
    /// Bytes generated so far (counts what was pulled by the connection).
    pub sent: Arc<std::sync::atomic::AtomicUsize>,
    /// Pause between chunks.
    pub pause: std::time::Duration,
    /// Raw bytes sent before the repeated chunk (e.g. an HTML head).
    pub prefix: Bytes,
}

impl StreamSpec {
    pub fn new(prefix: impl Into<Bytes>, chunk: impl Into<Bytes>, total: usize) -> Self {
        Self {
            chunk: chunk.into(),
            total,
            sent: Arc::default(),
            pause: std::time::Duration::ZERO,
            prefix: prefix.into(),
        }
    }
    pub fn paused(mut self, pause: std::time::Duration) -> Self {
        self.pause = pause;
        self
    }
}

impl MockResponse {
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.into(),
            delay: std::time::Duration::ZERO,
            stream: None,
        }
    }
    /// A response whose body is generated on demand.
    pub fn streaming(status: u16, spec: StreamSpec) -> Self {
        let mut r = Self::new(status, Vec::new());
        r.stream = Some(spec);
        r
    }
    pub fn delayed(mut self, delay: std::time::Duration) -> Self {
        self.delay = delay;
        self
    }
    pub fn ok(body: impl Into<Vec<u8>>) -> Self {
        Self::new(200, body)
    }
    pub fn html(body: impl Into<Vec<u8>>) -> Self {
        Self::ok(body).header("content-type", "text/html; charset=utf-8")
    }
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

/// A request as the origin actually received it.
#[derive(Clone, Debug)]
pub struct RecordedRequest {
    /// `https` or `http`.
    pub scheme: &'static str,
    pub method: String,
    /// Host header (`host` or `host:port`) as sent to the origin.
    pub host: String,
    pub path_and_query: String,
    pub version: hyper::Version,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl RecordedRequest {
    pub fn path(&self) -> &str {
        self.path_and_query.split('?').next().unwrap_or("")
    }
}

type Handler = Arc<dyn Fn(&RecordedRequest) -> MockResponse + Send + Sync>;

#[derive(Default)]
struct State {
    /// Skip recording requests (load tests: the log would grow without bound).
    no_record: std::sync::atomic::AtomicBool,
    routes: Mutex<HashMap<String, Handler>>,
    requests: Mutex<Vec<RecordedRequest>>,
}

/// In-process origin with its own CA. Answers for any hostname (SNI), serves HTTP/1.1 and
/// HTTP/2 over TLS plus plain HTTP, and echoes WebSocket messages on `/ws`. Unrouted paths get 404.
pub struct TestOrigin {
    ca_pem: String,
    ca_key_pem: String,
    https_port: u16,
    http_port: u16,
    state: Arc<State>,
    tasks: Vec<JoinHandle<()>>,
}

struct SniResolver {
    issuer: Issuer<'static, KeyPair>,
    cache: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

impl std::fmt::Debug for SniResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SniResolver")
    }
}

impl SniResolver {
    fn issue(&self, name: &str) -> Arc<CertifiedKey> {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, name);
        params.distinguished_name = dn;
        params.subject_alt_names = if let Ok(ip) = name.parse::<IpAddr>() {
            vec![SanType::IpAddress(ip)]
        } else if name == "localhost" {
            // Clients dialing an IP literal send no SNI; cover loopback and the public-looking
            // test literal too.
            vec![
                SanType::DnsName(name.try_into().expect("dns name")),
                SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                SanType::IpAddress(crate::PUBLIC_TEST_IP.parse().expect("test ip")),
            ]
        } else {
            vec![SanType::DnsName(name.try_into().expect("dns name"))]
        };
        let key = KeyPair::generate().expect("leaf key");
        let cert = params.signed_by(&key, &self.issuer).expect("sign leaf");
        let der = PrivateKeyDer::try_from(key.serialize_der()).expect("key der");
        let signing = any_supported_type(&der).expect("signing key");
        Arc::new(CertifiedKey::new(
            vec![CertificateDer::from(cert.der().to_vec())],
            signing,
        ))
    }
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = hello.server_name().unwrap_or("localhost").to_string();
        let mut cache = self.cache.lock();
        Some(
            cache
                .entry(name.clone())
                .or_insert_with(|| self.issue(&name))
                .clone(),
        )
    }
}

impl TestOrigin {
    pub async fn start() -> Self {
        Self::start_with_ca(None).await
    }

    /// Start with a given CA (`(cert_pem, key_pem)`, e.g. one saved by an earlier run so an
    /// external proxy can keep trusting it); a fresh CA when `None`.
    pub async fn start_with_ca(ca: Option<(&str, &str)>) -> Self {
        crate::init_crypto();
        let (issuer, ca_key_pem, ca_pem) = match ca {
            Some((cert, key)) => (
                Issuer::from_ca_cert_pem(cert, KeyPair::from_pem(key).expect("ca key pem"))
                    .expect("ca cert pem"),
                key.to_string(),
                cert.to_string(),
            ),
            None => {
                let mut ca_params = CertificateParams::default();
                let mut dn = DistinguishedName::new();
                dn.push(DnType::CommonName, "e2e origin CA");
                ca_params.distinguished_name = dn;
                ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
                ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
                let ca_key = KeyPair::generate().expect("ca key");
                let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
                let (pem, key_pem) = (ca_cert.pem(), ca_key.serialize_pem());
                (Issuer::new(ca_params, ca_key), key_pem, pem)
            }
        };
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SniResolver {
                issuer,
                cache: Mutex::new(HashMap::new()),
            }));
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(tls));

        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let https = TcpListener::bind(SocketAddr::new(lo, 0)).await.unwrap();
        let http = TcpListener::bind(SocketAddr::new(lo, 0)).await.unwrap();
        let https_port = https.local_addr().unwrap().port();
        let http_port = http.local_addr().unwrap().port();
        let state = Arc::new(State::default());

        let mut tasks = Vec::new();
        for (listener, tls) in [(https, Some(acceptor)), (http, None)] {
            let state = state.clone();
            tasks.push(tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        break;
                    };
                    // Nagle plus delayed ACK would add ~40 ms to multi-segment responses.
                    let _ = stream.set_nodelay(true);
                    let state = state.clone();
                    let tls = tls.clone();
                    tokio::spawn(async move {
                        let scheme = if tls.is_some() { "https" } else { "http" };
                        let svc = service_fn(move |req| handle(state.clone(), scheme, req));
                        let builder = AutoBuilder::new(TokioExecutor::new());
                        match tls {
                            Some(acc) => {
                                if let Ok(s) = acc.accept(stream).await {
                                    let _ = builder
                                        .serve_connection_with_upgrades(TokioIo::new(s), svc)
                                        .await;
                                }
                            }
                            None => {
                                let _ = builder
                                    .serve_connection_with_upgrades(TokioIo::new(stream), svc)
                                    .await;
                            }
                        }
                    });
                }
            }));
        }

        Self {
            ca_pem,
            ca_key_pem,
            https_port,
            http_port,
            state,
            tasks,
        }
    }

    pub fn https_port(&self) -> u16 {
        self.https_port
    }

    pub fn http_port(&self) -> u16 {
        self.http_port
    }

    /// PEM of the origin CA (the proxy must trust it).
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    /// PEM of the origin CA's private key.
    pub fn ca_key_pem(&self) -> &str {
        &self.ca_key_pem
    }

    /// Stop (or resume) recording received requests; load tests turn it off.
    pub fn set_recording(&self, on: bool) {
        self.state
            .no_record
            .store(!on, std::sync::atomic::Ordering::Relaxed);
    }

    /// IP all test hostnames resolve to.
    pub fn ip(&self) -> IpAddr {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }

    /// `https://<host>:<https_port><path>`
    pub fn https_url(&self, host: &str, path: &str) -> String {
        format!("https://{host}:{}{path}", self.https_port)
    }

    /// `http://<host>:<http_port><path>`
    pub fn http_url(&self, host: &str, path: &str) -> String {
        format!("http://{host}:{}{path}", self.http_port)
    }

    /// Register a fixed response for an exact path (query ignored).
    pub fn route(&self, path: &str, resp: MockResponse) {
        self.route_fn(path, move |_| resp.clone());
    }

    /// Register a handler for an exact path (query ignored).
    pub fn route_fn(
        &self,
        path: &str,
        f: impl Fn(&RecordedRequest) -> MockResponse + Send + Sync + 'static,
    ) {
        self.state.routes.lock().insert(path.into(), Arc::new(f));
    }

    /// Every request received so far, in arrival order.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.state.requests.lock().clone()
    }

    /// Requests received for `path` (query ignored).
    pub fn requests_for(&self, path: &str) -> Vec<RecordedRequest> {
        self.requests()
            .into_iter()
            .filter(|r| r.path() == path)
            .collect()
    }
}

impl Drop for TestOrigin {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

async fn handle(
    state: Arc<State>,
    scheme: &'static str,
    mut req: Request<Incoming>,
) -> Result<Response<OriginBody>, Infallible> {
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .or_else(|| req.uri().authority().map(|a| a.to_string()))
        .unwrap_or_default();
    let is_ws = req
        .headers()
        .get(hyper::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    let ws_key = req
        .headers()
        .get("sec-websocket-key")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let method = req.method().to_string();
    let version = req.version();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".into());

    let on_upgrade = if is_ws {
        Some(hyper::upgrade::on(&mut req))
    } else {
        None
    };
    let body = req
        .into_body()
        .collect()
        .await
        .map(|b| b.to_bytes().to_vec())
        .unwrap_or_default();
    let rec = RecordedRequest {
        scheme,
        method,
        host,
        path_and_query,
        version,
        headers,
        body,
    };
    if !state.no_record.load(std::sync::atomic::Ordering::Relaxed) {
        state.requests.lock().push(rec.clone());
    }

    if let (Some(up), Some(key), "/ws") = (on_upgrade, ws_key, rec.path()) {
        tokio::spawn(async move {
            if let Ok(upgraded) = up.await {
                let mut ws =
                    WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Server, None)
                        .await;
                while let Some(Ok(msg)) = ws.next().await {
                    if msg.is_text() || msg.is_binary() {
                        if ws.send(msg).await.is_err() {
                            break;
                        }
                    } else if msg.is_close() {
                        break;
                    }
                }
            }
        });
        return Ok(Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header("upgrade", "websocket")
            .header("connection", "Upgrade")
            .header("sec-websocket-accept", derive_accept_key(key.as_bytes()))
            .body(full(Bytes::new()))
            .unwrap());
    }

    let handler = state.routes.lock().get(rec.path()).cloned();
    let mock = match handler {
        Some(h) => h(&rec),
        None => MockResponse::new(404, "not found"),
    };
    if !mock.delay.is_zero() {
        tokio::time::sleep(mock.delay).await;
    }
    let mut b = Response::builder().status(mock.status);
    for (k, v) in &mock.headers {
        b = b.header(k, v);
    }
    let body = match mock.stream {
        None => full(Bytes::from(mock.body)),
        Some(spec) => {
            let first = spec.prefix.clone();
            spec.sent
                .fetch_add(first.len(), std::sync::atomic::Ordering::Relaxed);
            let rest = futures_util::stream::unfold(spec, |spec| async move {
                let sent = spec.sent.load(std::sync::atomic::Ordering::Relaxed);
                if sent >= spec.total {
                    return None;
                }
                if !spec.pause.is_zero() {
                    tokio::time::sleep(spec.pause).await;
                }
                let n = spec.chunk.len().min(spec.total - sent);
                spec.sent.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
                Some((
                    Ok::<_, std::io::Error>(Frame::data(spec.chunk.slice(..n))),
                    spec,
                ))
            });
            let s =
                futures_util::stream::once(
                    async move { Ok::<_, std::io::Error>(Frame::data(first)) },
                )
                .chain(rest);
            http_body_util::StreamBody::new(s).boxed_unsync()
        }
    };
    Ok(b.body(body).unwrap())
}

type OriginBody = http_body_util::combinators::UnsyncBoxBody<Bytes, std::io::Error>;

fn full(b: Bytes) -> OriginBody {
    Full::new(b).map_err(|e| match e {}).boxed_unsync()
}

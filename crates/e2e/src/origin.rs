use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
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
}

impl MockResponse {
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.into(),
        }
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
    routes: Mutex<HashMap<String, Handler>>,
    requests: Mutex<Vec<RecordedRequest>>,
}

/// In-process origin with its own CA. Answers for any hostname (SNI), serves HTTP/1.1 and
/// HTTP/2 over TLS plus plain HTTP, and echoes WebSocket messages on `/ws`. Unrouted paths get 404.
pub struct TestOrigin {
    ca_pem: String,
    https_port: u16,
    http_port: u16,
    state: Arc<State>,
    tasks: Vec<JoinHandle<()>>,
}

struct SniResolver {
    ca_key: KeyPair,
    ca_params: CertificateParams,
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
        params.subject_alt_names = vec![SanType::DnsName(name.try_into().expect("dns name"))];
        let key = KeyPair::generate().expect("leaf key");
        let issuer = Issuer::from_params(&self.ca_params, &self.ca_key);
        let cert = params.signed_by(&key, &issuer).expect("sign leaf");
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
        crate::init_crypto();
        let mut ca_params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "e2e origin CA");
        ca_params.distinguished_name = dn;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_key = KeyPair::generate().expect("ca key");
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
        let ca_pem = ca_cert.pem();

        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SniResolver {
                ca_key,
                ca_params,
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
            https_port,
            http_port,
            state,
            tasks,
        }
    }

    /// PEM of the origin CA (the proxy must trust it).
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
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
) -> Result<Response<Full<Bytes>>, Infallible> {
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
    state.requests.lock().push(rec.clone());

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
            .body(Full::new(Bytes::new()))
            .unwrap());
    }

    let handler = state.routes.lock().get(rec.path()).cloned();
    let mock = match handler {
        Some(h) => h(&rec),
        None => MockResponse::new(404, "not found"),
    };
    let mut b = Response::builder().status(mock.status);
    for (k, v) in &mock.headers {
        b = b.header(k, v);
    }
    Ok(b.body(Full::new(Bytes::from(mock.body))).unwrap())
}

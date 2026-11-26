//! Minimal wreq (BoringSSL) upstream client constructor for the upstream-client rewrite.
//!
//! Phase P0 only: this exists to exercise the two vendored wreq patches (in-handshake certificate
//! verification hook, CONNECT to a locally resolved IP). The proxy path builds its client in
//! `upstream.rs` (`build_upstream_client`).

use std::{sync::Arc, time::Duration};

pub use wreq::tls::{CustomVerify, SslAlert, SslRef};
use wreq::{dns::Resolve, Client, Proxy};
use wreq_util::Emulation;

/// Build a wreq client.
///
/// * `emulation` - browser TLS/HTTP2 fingerprint to present, if any.
/// * `verify` - in-handshake certificate hook. It replaces the built-in chain and hostname
///   verification, so it must verify the peer chain itself.
/// * `resolver` - DNS resolver used for direct connections and for `Proxy::resolve_locally`.
/// * `proxy` - optional upstream proxy; without one the system proxy settings are ignored.
pub fn build_wreq_client(
    emulation: Option<Emulation>,
    verify: Option<CustomVerify>,
    resolver: Option<Arc<dyn Resolve>>,
    proxy: Option<Proxy>,
) -> Result<Client, wreq::Error> {
    let mut b = Client::builder().timeout(Duration::from_secs(15));
    if let Some(e) = emulation {
        b = b.emulation(e);
    }
    if let Some(v) = verify {
        b = b.tls_custom_verify(v);
    }
    if let Some(r) = resolver {
        b = b.dns_resolver(r);
    }
    b = match proxy {
        Some(p) => b.proxy(p),
        None => b.no_proxy(),
    };
    b.build()
}

#[cfg(test)]
mod tests {
    use std::{
        net::SocketAddr,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Mutex,
        },
    };

    use rcgen::{CertificateParams, KeyPair};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };
    use tokio_rustls::TlsAcceptor;
    use wreq::dns::{Addrs, Name, Resolving};

    use super::*;

    const NAME: &str = "example.test";

    /// Resolves everything to 127.0.0.1 and records the names it was asked for.
    #[derive(Default)]
    struct StubResolver {
        names: Mutex<Vec<String>>,
    }

    impl Resolve for StubResolver {
        fn resolve(&self, name: Name) -> Resolving {
            self.names.lock().unwrap().push(name.as_str().to_string());
            Box::pin(async {
                let addrs: Addrs = Box::new(std::iter::once(SocketAddr::from(([127, 0, 0, 1], 0))));
                Ok(addrs)
            })
        }
    }

    /// What the TLS test server observed.
    #[derive(Default)]
    struct Seen {
        handshakes_ok: AtomicUsize,
        handshakes_failed: AtomicUsize,
        requests: Mutex<Vec<String>>,
        resumed: AtomicUsize,
        sni: Mutex<Vec<Option<String>>>,
    }

    struct TlsServer {
        addr: SocketAddr,
        cert_der: Vec<u8>,
        seen: Arc<Seen>,
    }

    fn crypto() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    /// Self-signed TLS server for `NAME`; answers every request with a 200.
    async fn tls_server() -> TlsServer {
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec![NAME.to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let cert_der = cert.der().to_vec();
        let config = rustls::ServerConfig::builder_with_provider(crypto())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert_der.clone())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Seen::default());
        let task_seen = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let (acceptor, seen) = (acceptor.clone(), task_seen.clone());
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        seen.handshakes_failed.fetch_add(1, Ordering::SeqCst);
                        return;
                    };
                    seen.handshakes_ok.fetch_add(1, Ordering::SeqCst);
                    if tls.get_ref().1.handshake_kind() == Some(rustls::HandshakeKind::Resumed) {
                        seen.resumed.fetch_add(1, Ordering::SeqCst);
                    }
                    seen.sni
                        .lock()
                        .unwrap()
                        .push(tls.get_ref().1.server_name().map(str::to_string));
                    if let Some(head) = read_head(&mut tls).await {
                        seen.requests.lock().unwrap().push(head);
                        let _ = tls
                            .write_all(
                                b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                            )
                            .await;
                        let _ = tls.shutdown().await;
                    }
                });
            }
        });
        TlsServer {
            addr,
            cert_der,
            seen,
        }
    }

    /// Read up to the end of an HTTP head; `None` if the peer closed first.
    async fn read_head<S: AsyncReadExt + Unpin>(s: &mut S) -> Option<String> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            match s.read(&mut chunk).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        Some(String::from_utf8_lossy(&buf).into_owned())
    }

    /// Stub HTTP proxy: records each CONNECT head, then splices to the requested `host:port`.
    async fn connect_proxy() -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let heads = Arc::new(Mutex::new(Vec::new()));
        let task_heads = heads.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut client, _)) = listener.accept().await else {
                    return;
                };
                let heads = task_heads.clone();
                tokio::spawn(async move {
                    let Some(head) = read_head(&mut client).await else {
                        return;
                    };
                    heads.lock().unwrap().push(head.clone());
                    let target = head
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .filter(|_| head.starts_with("CONNECT "))
                        .map(str::to_string);
                    let Some(target) = target else {
                        let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
                        return;
                    };
                    let Ok(mut upstream) = TcpStream::connect(&target).await else {
                        let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                        return;
                    };
                    let _ = client
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .await;
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                });
            }
        });
        (addr, heads)
    }

    type HookLog = Arc<Mutex<Vec<(Option<String>, Vec<Vec<u8>>, String)>>>;

    /// A hook that records (SNI, peer chain DER, expected host) and returns `result`.
    fn recording_hook(result: Result<(), SslAlert>) -> (CustomVerify, HookLog) {
        let log: HookLog = Arc::default();
        let task_log = log.clone();
        let hook: CustomVerify = Arc::new(move |ssl: &mut SslRef, host: &str| {
            let sni = ssl
                .servername(wreq::tls::NameType::HOST_NAME)
                .map(str::to_string);
            let chain = ssl
                .peer_cert_chain()
                .map(|c| c.iter().map(|x| x.to_der().unwrap()).collect())
                .unwrap_or_default();
            task_log
                .lock()
                .unwrap()
                .push((sni, chain, host.to_string()));
            result
        });
        (hook, log)
    }

    #[tokio::test]
    async fn rejecting_hook_aborts_handshake_before_any_request_bytes() {
        let server = tls_server().await;
        let (hook, log) = recording_hook(Err(SslAlert::BAD_CERTIFICATE));
        let resolver = Arc::new(StubResolver::default());
        let client = build_wreq_client(None, Some(hook), Some(resolver), None).unwrap();

        let res = client
            .get(format!("https://{NAME}:{}/", server.addr.port()))
            .send()
            .await;
        assert!(res.is_err(), "handshake must fail when the hook rejects");

        // Hook saw the SNI and the server's chain.
        {
            let log = log.lock().unwrap();
            assert_eq!(log.len(), 1);
            assert_eq!(log[0].0.as_deref(), Some(NAME));
            assert_eq!(log[0].1.first(), Some(&server.cert_der));
            assert_eq!(log[0].2, NAME);
        }

        // Let the server finish processing the aborted connection, then check it got no request.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(server.seen.requests.lock().unwrap().is_empty());
        assert_eq!(server.seen.handshakes_failed.load(Ordering::SeqCst), 1);
        assert_eq!(server.seen.handshakes_ok.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn accepting_hook_lets_the_request_through() {
        let server = tls_server().await;
        let (hook, log) = recording_hook(Ok(()));
        let resolver = Arc::new(StubResolver::default());
        let client = build_wreq_client(
            Some(Emulation::builder().profile(Emulation::Chrome147).build()),
            Some(hook),
            Some(resolver),
            None,
        )
        .unwrap();

        let res = client
            .get(format!("https://{NAME}:{}/", server.addr.port()))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status().as_u16(), 200);
        assert_eq!(log.lock().unwrap().len(), 1);
        assert_eq!(server.seen.requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn resolve_locally_connects_to_vetted_ip_and_keeps_sni_and_host() {
        let server = tls_server().await;
        let (proxy_addr, heads) = connect_proxy().await;
        let (hook, _) = recording_hook(Ok(()));
        let resolver = Arc::new(StubResolver::default());
        let port = server.addr.port();
        let proxy = Proxy::all(format!("http://{proxy_addr}"))
            .unwrap()
            .resolve_locally(true);
        let client =
            build_wreq_client(None, Some(hook), Some(resolver.clone()), Some(proxy)).unwrap();

        let res = client
            .get(format!("https://{NAME}:{port}/"))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status().as_u16(), 200);

        // CONNECT carries the vetted IP, not the name; the resolver was consulted for the name.
        let heads = heads.lock().unwrap();
        assert_eq!(heads.len(), 1);
        assert_eq!(
            heads[0].lines().next().unwrap(),
            format!("CONNECT 127.0.0.1:{port} HTTP/1.1")
        );
        assert_eq!(*resolver.names.lock().unwrap(), vec![NAME.to_string()]);

        // The origin saw the hostname as SNI and as the Host header.
        assert_eq!(
            *server.seen.sni.lock().unwrap(),
            vec![Some(NAME.to_string())]
        );
        let req = server.seen.requests.lock().unwrap()[0].to_lowercase();
        assert!(req.contains(&format!("host: {NAME}:{port}")), "{req}");
    }

    #[tokio::test]
    async fn without_resolve_locally_connect_carries_the_hostname() {
        let server = tls_server().await;
        let (proxy_addr, heads) = connect_proxy().await;
        let (hook, _) = recording_hook(Ok(()));
        let resolver = Arc::new(StubResolver::default());
        let proxy = Proxy::all(format!("http://{proxy_addr}")).unwrap();
        let client =
            build_wreq_client(None, Some(hook), Some(resolver.clone()), Some(proxy)).unwrap();
        let port = server.addr.port();

        // The stub proxy cannot resolve the name, so the request fails; only the CONNECT matters.
        let _ = client.get(format!("https://{NAME}:{port}/")).send().await;
        let heads = heads.lock().unwrap();
        assert_eq!(
            heads[0].lines().next().unwrap(),
            format!("CONNECT {NAME}:{port} HTTP/1.1")
        );
        assert!(resolver.names.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn resolve_locally_tunnels_plain_http_via_connect() {
        // Plain-HTTP origin that records its request head.
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = origin.local_addr().unwrap().port();
        let origin_seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let task_seen = origin_seen.clone();
        tokio::spawn(async move {
            let (mut s, _) = origin.accept().await.unwrap();
            if let Some(head) = read_head(&mut s).await {
                task_seen.lock().unwrap().push(head);
                let _ = s
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                    )
                    .await;
            }
        });
        let (proxy_addr, heads) = connect_proxy().await;
        let resolver = Arc::new(StubResolver::default());
        let proxy = Proxy::all(format!("http://{proxy_addr}"))
            .unwrap()
            .resolve_locally(true);
        let client = build_wreq_client(None, None, Some(resolver.clone()), Some(proxy)).unwrap();

        let res = client
            .get(format!("http://{NAME}:{port}/path"))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status().as_u16(), 200);

        let heads = heads.lock().unwrap();
        assert_eq!(
            heads[0].lines().next().unwrap(),
            format!("CONNECT 127.0.0.1:{port} HTTP/1.1")
        );
        assert_eq!(*resolver.names.lock().unwrap(), vec![NAME.to_string()]);
        // Origin-form request inside the tunnel, never absolute-form.
        let req = origin_seen.lock().unwrap()[0].clone();
        assert_eq!(req.lines().next().unwrap(), "GET /path HTTP/1.1");
        assert!(req.to_lowercase().contains(&format!("host: {NAME}:{port}")));
    }

    #[tokio::test]
    async fn hook_runs_again_on_resumed_sessions() {
        let server = tls_server().await;
        let reject = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let calls = Arc::new(AtomicUsize::new(0));
        let (r, c) = (reject.clone(), calls.clone());
        let hook: CustomVerify = Arc::new(move |_: &mut SslRef, _: &str| {
            c.fetch_add(1, Ordering::SeqCst);
            if r.load(Ordering::SeqCst) {
                Err(SslAlert::BAD_CERTIFICATE)
            } else {
                Ok(())
            }
        });
        let client = build_wreq_client(
            Some(Emulation::builder().profile(Emulation::Chrome147).build()),
            Some(hook),
            Some(Arc::new(StubResolver::default())),
            None,
        )
        .unwrap();
        let url = format!("https://{NAME}:{}/", server.addr.port());

        assert_eq!(
            client.get(&url).send().await.unwrap().status().as_u16(),
            200
        );
        // Let the ticket arrive and the first connection go away.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            client.get(&url).send().await.unwrap().status().as_u16(),
            200
        );
        assert_eq!(
            server.seen.resumed.load(Ordering::SeqCst),
            1,
            "2nd must resume"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "hook must run on resumption"
        );

        // A hook that starts rejecting also stops resumed connections.
        reject.store(true, Ordering::SeqCst);
        assert!(client.get(&url).send().await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn hook_gets_the_ip_literal_as_expected_host() {
        let server = tls_server().await;
        let (hook, log) = recording_hook(Ok(()));
        let client = build_wreq_client(None, Some(hook), None, None).unwrap();
        let res = client
            .get(format!("https://127.0.0.1:{}/", server.addr.port()))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status().as_u16(), 200);
        let log = log.lock().unwrap();
        assert_eq!(log[0].2, "127.0.0.1");
        assert_eq!(log[0].0, None, "no SNI for IP literals");
    }

    #[tokio::test]
    async fn panicking_hook_fails_the_request_without_aborting() {
        let server = tls_server().await;
        let hook: CustomVerify = Arc::new(|_: &mut SslRef, _: &str| panic!("boom"));
        let client = build_wreq_client(
            None,
            Some(hook),
            Some(Arc::new(StubResolver::default())),
            None,
        )
        .unwrap();
        let res = client
            .get(format!("https://{NAME}:{}/", server.addr.port()))
            .send()
            .await;
        assert!(res.is_err());
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(server.seen.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn rejecting_hook_through_resolve_locally_proxy_reaches_no_request() {
        let server = tls_server().await;
        let (proxy_addr, heads) = connect_proxy().await;
        let (hook, log) = recording_hook(Err(SslAlert::BAD_CERTIFICATE));
        let proxy = Proxy::all(format!("http://{proxy_addr}"))
            .unwrap()
            .resolve_locally(true);
        let client = build_wreq_client(
            None,
            Some(hook),
            Some(Arc::new(StubResolver::default())),
            Some(proxy),
        )
        .unwrap();
        let port = server.addr.port();

        assert!(client
            .get(format!("https://{NAME}:{port}/"))
            .send()
            .await
            .is_err());
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(heads.lock().unwrap().len(), 1, "tunnel was established");
        assert_eq!(log.lock().unwrap().len(), 1);
        assert_eq!(server.seen.handshakes_ok.load(Ordering::SeqCst), 0);
        assert!(server.seen.requests.lock().unwrap().is_empty());
    }
}

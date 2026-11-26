//! Upstream proxy: stub CONNECT and SOCKS5 proxies record what Argus asks them for.

use super::*;
use crate::dns::{BackendResult, DnsBackend, DnsCacheConfig, DnsFailure, DnsHandle, FailKind};
use crate::upstream::{build_upstream_client, UpstreamOptions};
use common::config::UpstreamProxyKind::{Http, Socks5};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const NAME: &str = "origin.test";
const PUBLIC: &str = "93.184.216.34";

// ---- DNS: fixed answers

struct Fixed(HashMap<String, IpAddr>);

impl DnsBackend for Fixed {
    fn lookup(
        &self,
        name: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = BackendResult> + Send>> {
        let r = self.0.get(name).copied();
        Box::pin(async move {
            match r {
                Some(ip) => Ok((vec![ip], Duration::from_secs(60))),
                None => Err(DnsFailure::new(FailKind::NotFound, "no such host")),
            }
        })
    }
}

fn dns() -> Arc<CachedResolver> {
    let m = [
        (NAME, PUBLIC),
        ("private.test", "10.1.2.3"),
        ("own.test", "127.0.0.1"),
        ("proxy.test", "127.0.0.1"),
    ]
    .into_iter()
    .map(|(n, i)| (n.to_string(), i.parse().unwrap()))
    .collect();
    Arc::new(CachedResolver::new(
        Arc::new(Fixed(m)),
        DnsCacheConfig {
            capacity: 100,
            min_ttl: Duration::from_secs(60),
            max_ttl: Duration::from_secs(60),
            negative_ttl: Duration::from_secs(1),
        },
    ))
}

fn policy(dns: &Arc<CachedResolver>) -> Arc<DestPolicy> {
    Arc::new(
        DestPolicy::new(true, &[])
            .unwrap()
            .with_resolver(Arc::new(DnsHandle(dns.clone()))),
    )
}

// ---- stub proxy

#[derive(Debug, Clone, Default)]
struct Seen {
    /// `ip:port` the client asked for.
    target: String,
    /// SOCKS5 address type.
    atyp: Option<u8>,
}

struct Stub {
    port: u16,
    seen: Arc<Mutex<Vec<Seen>>>,
    conns: Arc<AtomicUsize>,
}

impl Stub {
    fn targets(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .map(|s| s.target.clone())
            .collect()
    }
}

/// A proxy that checks `creds`, records the requested target, and bridges to the same port on
/// loopback (where the test origin listens).
async fn stub(kind: UpstreamProxyKind, creds: Option<(&str, &str)>) -> Stub {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let conns = Arc::new(AtomicUsize::new(0));
    let creds = creds.map(|(u, p)| (u.to_string(), p.to_string()));
    let (s2, c2) = (seen.clone(), conns.clone());
    tokio::spawn(async move {
        loop {
            let Ok((mut c, _)) = l.accept().await else {
                return;
            };
            c2.fetch_add(1, Ordering::SeqCst);
            let (seen, creds) = (s2.clone(), creds.clone());
            tokio::spawn(async move {
                let target = match kind {
                    Http => stub_http(&mut c, creds).await,
                    Socks5 => stub_socks(&mut c, creds).await,
                };
                let Some(target) = target else { return };
                let bridge_port: u16 = target.target.rsplit(':').next().unwrap().parse().unwrap();
                seen.lock().unwrap().push(target);
                if let Ok(mut up) = TcpStream::connect(("127.0.0.1", bridge_port)).await {
                    let _ = tokio::io::copy_bidirectional(&mut c, &mut up).await;
                }
            });
        }
    });
    Stub { port, seen, conns }
}

async fn stub_http(c: &mut TcpStream, creds: Option<(String, String)>) -> Option<Seen> {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if c.read(&mut b).await.ok()? == 0 {
            return None;
        }
        head.push(b[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let target = head.lines().next()?.split_whitespace().nth(1)?.to_string();
    if let Some((u, p)) = creds {
        let want = format!(
            "Proxy-Authorization: Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"))
        );
        if !head.lines().any(|l| l.eq_ignore_ascii_case(&want)) {
            let _ = c
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await;
            return None;
        }
    }
    c.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await
        .ok()?;
    Some(Seen { target, atyp: None })
}

async fn stub_socks(c: &mut TcpStream, creds: Option<(String, String)>) -> Option<Seen> {
    let mut h = [0u8; 2];
    c.read_exact(&mut h).await.ok()?;
    let mut methods = vec![0u8; h[1] as usize];
    c.read_exact(&mut methods).await.ok()?;
    match &creds {
        Some((u, p)) if methods.contains(&2) => {
            c.write_all(&[5, 2]).await.ok()?;
            let mut v = [0u8; 2];
            c.read_exact(&mut v).await.ok()?;
            let mut user = vec![0u8; v[1] as usize];
            c.read_exact(&mut user).await.ok()?;
            let mut pl = [0u8; 1];
            c.read_exact(&mut pl).await.ok()?;
            let mut pass = vec![0u8; pl[0] as usize];
            c.read_exact(&mut pass).await.ok()?;
            let good = user == u.as_bytes() && pass == p.as_bytes();
            c.write_all(&[1, if good { 0 } else { 1 }]).await.ok()?;
            if !good {
                return None;
            }
        }
        Some(_) => {
            c.write_all(&[5, 0xFF]).await.ok()?;
            return None;
        }
        None => c.write_all(&[5, 0]).await.ok()?,
    }
    let mut r = [0u8; 4];
    c.read_exact(&mut r).await.ok()?;
    let target = match r[3] {
        1 => {
            let mut a = [0u8; 4];
            c.read_exact(&mut a).await.ok()?;
            IpAddr::from(a).to_string()
        }
        4 => {
            let mut a = [0u8; 16];
            c.read_exact(&mut a).await.ok()?;
            format!("[{}]", IpAddr::from(a))
        }
        _ => {
            // A domain: record it so a test can fail on it.
            let mut l = [0u8; 1];
            c.read_exact(&mut l).await.ok()?;
            let mut d = vec![0u8; l[0] as usize];
            c.read_exact(&mut d).await.ok()?;
            String::from_utf8_lossy(&d).into_owned()
        }
    };
    let mut p = [0u8; 2];
    c.read_exact(&mut p).await.ok()?;
    c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.ok()?;
    Some(Seen {
        target: format!("{target}:{}", u16::from_be_bytes(p)),
        atyp: Some(r[3]),
    })
}

// ---- TLS origin

struct Ca {
    issuer: Issuer<'static, KeyPair>,
    pem: String,
}

fn ca() -> Ca {
    let mut p = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "proxy-test-ca");
    p.distinguished_name = dn;
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let key = KeyPair::generate().unwrap();
    let cert = p.self_signed(&key).unwrap();
    Ca {
        pem: cert.pem(),
        issuer: Issuer::new(p, key),
    }
}

struct Origin {
    port: u16,
    sni: Arc<Mutex<Vec<Option<String>>>>,
    heads: Arc<Mutex<Vec<String>>>,
}

async fn origin(ca: &Ca) -> Origin {
    let mut p = CertificateParams::default();
    p.subject_alt_names = vec![SanType::DnsName(NAME.try_into().unwrap())];
    let key = KeyPair::generate().unwrap();
    let cert = p.signed_by(&key, &ca.issuer).unwrap();
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(cert.der().to_vec())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
    .unwrap();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let (sni, heads): (Arc<Mutex<Vec<_>>>, Arc<Mutex<Vec<_>>>) = Default::default();
    let (s2, h2) = (sni.clone(), heads.clone());
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = l.accept().await else {
                return;
            };
            let (acceptor, sni, heads) = (acceptor.clone(), s2.clone(), h2.clone());
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                sni.lock()
                    .unwrap()
                    .push(tls.get_ref().1.server_name().map(str::to_string));
                let mut buf = Vec::new();
                let mut chunk = [0u8; 2048];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(k) => buf.extend_from_slice(&chunk[..k]),
                    }
                }
                heads
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf).into_owned());
                let _ = tls
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                    )
                    .await;
                let _ = tls.shutdown().await;
            });
        }
    });
    Origin { port, sni, heads }
}

// ---- rig

struct Rig {
    opts: UpstreamOptions,
    dns: Arc<CachedResolver>,
    policy: Arc<DestPolicy>,
    _dir: tempfile::TempDir,
}

fn cfg(kind: UpstreamProxyKind, port: u16, creds: Option<(&str, &str)>) -> UpstreamProxy {
    UpstreamProxy {
        enabled: true,
        kind,
        host: "127.0.0.1".into(),
        port,
        username: creds.map_or("", |c| c.0).into(),
        password: creds.map_or("", |c| c.1).into(),
    }
}

fn rig(ca: &Ca, browser_like: bool, proxy: Option<UpstreamProxy>) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ca.pem");
    std::fs::write(&path, &ca.pem).unwrap();
    let dns = dns();
    let policy = policy(&dns);
    let handle = Arc::new(ProxyHandle::default());
    if let Some(c) = proxy {
        handle.store(Some(Arc::new(ProxyEndpoint::new(
            c,
            policy.clone(),
            dns.clone(),
        ))));
    }
    let opts = UpstreamOptions {
        roots: Some(crate::roots::RootsHandle::floor(&[path]).unwrap()),
        certs: Arc::new(common::certstore::CertStore::new(8 << 20, 1000)),
        policy: policy.clone(),
        dns: Some(dns.clone()),
        connect_timeout: Some(Duration::from_secs(5)),
        read_timeout: Some(Duration::from_secs(5)),
        pool_max_idle_per_host: Some(0),
        browser_like,
        proxy: handle,
        ..Default::default()
    };
    Rig {
        opts,
        dns,
        policy,
        _dir: dir,
    }
}

fn url(host: &str, port: u16) -> String {
    format!("https://{host}:{port}/")
}

// ---- tests

#[tokio::test]
async fn http_and_socks_send_the_vetted_ip_and_keep_the_name_for_sni_and_host() {
    for kind in [Http, Socks5] {
        for browser_like in [true, false] {
            let ca = ca();
            let o = origin(&ca).await;
            let s = stub(kind, None).await;
            let r = rig(&ca, browser_like, Some(cfg(kind, s.port, None)));
            let client = build_upstream_client(&r.opts).unwrap();
            let resp = client.get(url(NAME, o.port)).send().await.unwrap();
            assert_eq!(resp.status(), 200, "{kind:?} bl={browser_like}");
            // The proxy was asked for the IP Argus resolved, never the name.
            let want = format!("{PUBLIC}:{}", o.port);
            assert_eq!(s.targets(), vec![want], "{kind:?} bl={browser_like}");
            if kind == Socks5 {
                assert_eq!(s.seen.lock().unwrap()[0].atyp, Some(1));
            }
            assert_eq!(o.sni.lock().unwrap()[0].as_deref(), Some(NAME));
            let head = o.heads.lock().unwrap()[0].to_lowercase();
            assert!(head.contains(&format!("host: {NAME}")), "{head}");
        }
    }
}

#[tokio::test]
async fn username_and_password_authenticate_and_wrong_ones_fail_clearly() {
    for kind in [Http, Socks5] {
        let ca = ca();
        let o = origin(&ca).await;
        let s = stub(kind, Some(("alice", "s3cret"))).await;
        let good = rig(
            &ca,
            true,
            Some(cfg(kind, s.port, Some(("alice", "s3cret")))),
        );
        let c = build_upstream_client(&good.opts).unwrap();
        assert_eq!(c.get(url(NAME, o.port)).send().await.unwrap().status(), 200);
        assert_eq!(s.targets().len(), 1, "{kind:?}");

        let bad = rig(&ca, true, Some(cfg(kind, s.port, Some(("alice", "wrong")))));
        let c = build_upstream_client(&bad.opts).unwrap();
        assert!(c.get(url(NAME, o.port)).send().await.is_err(), "{kind:?}");
        assert_eq!(s.targets().len(), 1, "no tunnel for wrong credentials");

        // Argus's own dial says why.
        let ep = ProxyEndpoint::new(
            cfg(kind, s.port, Some(("alice", "wrong"))),
            good.policy.clone(),
            good.dns.clone(),
        );
        let e = ep.connect("93.184.216.34:443".parse().unwrap()).await;
        let msg = e.unwrap_err().to_string();
        assert!(msg.contains("rejected the username or password"), "{msg}");
        // No credentials at all against a proxy that wants them.
        let ep = ProxyEndpoint::new(
            cfg(kind, s.port, None),
            good.policy.clone(),
            good.dns.clone(),
        );
        assert!(ep
            .connect("93.184.216.34:443".parse().unwrap())
            .await
            .is_err());
    }
}

#[tokio::test]
async fn private_and_own_targets_are_refused_and_the_proxy_is_never_contacted() {
    for kind in [Http, Socks5] {
        for browser_like in [true, false] {
            let ca = ca();
            let o = origin(&ca).await;
            let s = stub(kind, None).await;
            let r = rig(&ca, browser_like, Some(cfg(kind, s.port, None)));
            let client = build_upstream_client(&r.opts).unwrap();
            let e = client.get(url("private.test", o.port)).send().await;
            assert!(
                e.as_ref().is_err_and(|e| crate::policy::is_refusal(e)),
                "{kind:?} bl={browser_like}: {e:?}"
            );
            // Own listener: the strict client refuses every address of this host.
            let strict = crate::upstream::build_strict_upstream_client(&r.opts).unwrap();
            let e = strict.get(url("own.test", o.port)).send().await;
            assert!(
                e.as_ref().is_err_and(|e| crate::policy::is_refusal(e)),
                "{kind:?} bl={browser_like}: {e:?}"
            );
            assert_eq!(s.conns.load(Ordering::SeqCst), 0, "proxy was contacted");
            assert!(o.sni.lock().unwrap().is_empty());
        }
    }
}

#[tokio::test]
async fn the_dial_helper_vets_then_tunnels_and_refuses_without_contacting_the_proxy() {
    for kind in [Http, Socks5] {
        let ca = ca();
        let o = origin(&ca).await;
        let s = stub(kind, None).await;
        let r = rig(&ca, true, Some(cfg(kind, s.port, None)));
        let ep = r.opts.proxy.load().unwrap();
        dial(&r.policy, Some(&ep), NAME, o.port, None)
            .await
            .unwrap();
        assert_eq!(s.targets(), vec![format!("{PUBLIC}:{}", o.port)]);
        let before = s.conns.load(Ordering::SeqCst);
        for host in ["private.test", "10.9.9.9", "127.0.0.1"] {
            r.policy
                .set_own_listeners(&[o.port], &["127.0.0.1".parse().unwrap()]);
            let e = dial(&r.policy, Some(&ep), host, o.port, None).await;
            assert!(
                matches!(e, Err(Error::DestinationRefused(_))),
                "{kind:?} {host}"
            );
        }
        assert_eq!(s.conns.load(Ordering::SeqCst), before);
    }
}

#[tokio::test]
async fn an_endpoint_that_is_an_own_listener_is_rejected_but_a_private_one_is_fine() {
    let dns = dns();
    let policy = policy(&dns);
    let own = cfg(Http, 8080, None);
    policy.set_own_listeners(&[8080], &["127.0.0.1".parse().unwrap()]);
    let e = ProxyEndpoint::prepare(&own, policy.clone(), dns.clone()).await;
    assert!(e.unwrap_err().to_string().contains("own listener"));
    // By name too.
    let mut by_name = own.clone();
    by_name.host = "proxy.test".into();
    assert!(
        ProxyEndpoint::prepare(&by_name, policy.clone(), dns.clone())
            .await
            .is_err()
    );
    // A private address on another port is the administrator's choice (block_private is on).
    assert!(
        ProxyEndpoint::prepare(&cfg(Http, 3128, None), policy.clone(), dns.clone())
            .await
            .unwrap()
            .is_some()
    );
    // Disabled: nothing to resolve or check.
    let mut off = own;
    off.enabled = false;
    assert!(ProxyEndpoint::prepare(&off, policy, dns)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn the_proxy_name_is_resolved_on_argus_and_a_changed_address_is_followed() {
    // `proxy.test` resolves to loopback: the client reaches the stub through its alias.
    let ca = ca();
    let o = origin(&ca).await;
    let s = stub(Http, None).await;
    let mut c = cfg(Http, s.port, None);
    c.host = "proxy.test".into();
    let r = rig(&ca, true, Some(c));
    let client = build_upstream_client(&r.opts).unwrap();
    assert_eq!(
        client.get(url(NAME, o.port)).send().await.unwrap().status(),
        200
    );
    assert_eq!(s.conns.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn probes_use_the_proxy() {
    for kind in [Http, Socks5] {
        let ca = ca();
        let o = origin(&ca).await;
        let s = stub(kind, None).await;
        let r = rig(&ca, true, Some(cfg(kind, s.port, None)));
        let ep = r.opts.proxy.load().unwrap();
        // The EV probe.
        let addr = r.policy.resolve(NAME, o.port, None).await.unwrap();
        let _ = crate::ev::probe(NAME, addr, Duration::from_secs(2), Some(&ep)).await;
        assert_eq!(s.targets().len(), 1, "{kind:?}: ev probe");
        // The certificate prober.
        let prober = crate::upstream::CertProber::new(&r.opts).unwrap();
        let _ = prober.probe(NAME, o.port).await;
        assert_eq!(s.targets().len(), 2, "{kind:?}: cert probe");
        assert!(s
            .targets()
            .iter()
            .all(|t| t == &format!("{PUBLIC}:{}", o.port)));
    }
}

#[cfg(feature = "websockets")]
#[tokio::test]
async fn websocket_dials_use_the_proxy() {
    for kind in [Http, Socks5] {
        let ca = ca();
        let o = origin(&ca).await;
        let s = stub(kind, None).await;
        let r = rig(&ca, true, Some(cfg(kind, s.port, None)));
        let ws = crate::websocket::WsUpstream::new(
            r.opts.roots.clone().unwrap(),
            r.policy.clone(),
            None,
            Duration::from_secs(5),
        )
        .unwrap()
        .with_proxy(r.opts.proxy.clone());
        ws.dial(NAME, o.port, true).await.unwrap();
        assert_eq!(
            s.targets(),
            vec![format!("{PUBLIC}:{}", o.port)],
            "{kind:?}"
        );
        for _ in 0..50 {
            if !o.sni.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(o.sni.lock().unwrap()[0].as_deref(), Some(NAME));
        // A private target is refused before the proxy is asked.
        assert!(ws.dial("private.test", o.port, true).await.is_err());
        assert_eq!(s.targets().len(), 1);
    }
}

#[tokio::test]
async fn the_proxy_can_be_switched_live_and_a_bad_config_changes_nothing() {
    let ca = ca();
    let o = origin(&ca).await;
    let s = stub(Http, None).await;
    let mut r = rig(&ca, true, None);
    // Everything dials loopback so the direct path reaches the origin too.
    r.opts.resolve_all_to = Some("127.0.0.1".parse().unwrap());
    let ctx = crate::ProxyContext::with_upstream(
        Arc::new(filter_engine::SharedEngine::new()),
        &r.opts,
        false,
    )
    .unwrap();
    let get = || async {
        ctx.client()
            .get(url(NAME, o.port))
            .send()
            .await
            .map(|r| r.status())
    };
    let (connect, read) = (Duration::from_secs(5), Duration::from_secs(5));
    assert_eq!(get().await.unwrap(), 200);
    assert_eq!(s.conns.load(Ordering::SeqCst), 0, "direct while off");

    // On.
    let on = cfg(Http, s.port, None);
    let ep = ctx.prepare_proxy(&on).await.unwrap();
    let p = ctx.prepare_upstream(connect, read, true, ep).unwrap();
    ctx.commit_upstream(p);
    assert_eq!(get().await.unwrap(), 200);
    assert_eq!(s.conns.load(Ordering::SeqCst), 1, "through the proxy");

    // A config that cannot be applied is refused up front; the old proxy stays in force.
    ctx.policy()
        .set_own_listeners(&[9], &["127.0.0.1".parse().unwrap()]);
    let mut bad = on.clone();
    bad.port = 9;
    assert!(ctx.prepare_proxy(&bad).await.is_err());
    assert!(ctx.proxy_handle().load().unwrap().same_as(&on));
    assert_eq!(get().await.unwrap(), 200);
    assert_eq!(s.conns.load(Ordering::SeqCst), 2);

    // Off again.
    let ep = ctx.prepare_proxy(&UpstreamProxy::default()).await.unwrap();
    assert!(ep.is_none());
    let p = ctx.prepare_upstream(connect, read, true, ep).unwrap();
    ctx.commit_upstream(p);
    assert!(ctx.proxy_handle().load().is_none());
    assert_eq!(get().await.unwrap(), 200);
    assert_eq!(s.conns.load(Ordering::SeqCst), 2, "direct again");
}

#[tokio::test]
async fn the_test_reports_success_latency_and_a_clear_error() {
    let ca = ca();
    let o = origin(&ca).await;
    let s = stub(Http, None).await;
    let mut r = rig(&ca, true, None);
    r.opts.resolve_all_to = Some("127.0.0.1".parse().unwrap());
    let ctx = crate::ProxyContext::with_upstream(
        Arc::new(filter_engine::SharedEngine::new()),
        &r.opts,
        false,
    )
    .unwrap();
    let ok = ctx
        .test_upstream_proxy(&cfg(Http, s.port, None), NAME, o.port)
        .await;
    assert!(ok.is_ok(), "{ok:?}");
    // A dead proxy.
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = dead.local_addr().unwrap().port();
    drop(dead);
    let e = ctx
        .test_upstream_proxy(&cfg(Http, port, None), NAME, o.port)
        .await
        .unwrap_err();
    assert!(e.contains("cannot reach upstream proxy"), "{e}");
}

#[test]
fn the_password_never_shows_in_debug_output() {
    let c = cfg(Http, 1, Some(("alice", "hunter2")));
    assert!(!format!("{c:?}").contains("hunter2"));
}

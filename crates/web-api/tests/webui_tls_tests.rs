//! Built-in HTTPS for the web UI on a real listener (ephemeral port, temp dir, no network):
//! TLS handshake against a test CA, the HTTP to HTTPS redirect, live certificate swap and
//! upload validation.

mod common;

use common::TestContext;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use web_api::{ProxyBind, RuntimeControl};

/// A throwaway CA that signs the certificates the fake runtime "issues".
struct TestCa {
    issuer: Issuer<'static, KeyPair>,
    pem: String,
}

impl TestCa {
    fn new() -> Self {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Test CA");
        p.distinguished_name = dn;
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let pem = p.self_signed(&key).unwrap().pem();
        Self {
            issuer: Issuer::new(p, key),
            pem,
        }
    }

    /// `(certificate PEM, key PEM)` valid for `sans`.
    fn leaf(&self, sans: &[String]) -> (String, String) {
        let key = KeyPair::generate().unwrap();
        let p = CertificateParams::new(sans.to_vec()).unwrap();
        let cert = p.signed_by(&key, &self.issuer).unwrap();
        (cert.pem(), key.serialize_pem())
    }
}

struct Fake(Arc<TestCa>);

#[async_trait::async_trait]
impl RuntimeControl for Fake {
    async fn rebind_proxy(&self, _: &str, port: u16, t: Option<u16>) -> Result<ProxyBind, String> {
        Ok(ProxyBind {
            proxy_down: false,
            transparent_down: false,
            proxy_error: None,
            transparent_error: None,
            proxy: SocketAddr::from(([127, 0, 0, 1], port)),
            transparent: t.map(|p| SocketAddr::from(([127, 0, 0, 1], p))),
        })
    }
    async fn apply_access(&self, _: &::common::config::ProxyConfig) -> Result<(), String> {
        Ok(())
    }
    fn listener_counters(&self) -> (web_api::ListenerCounters, web_api::ListenerCounters) {
        let c = web_api::ListenerCounters {
            active_connections: 0,
            requests_per_sec: 0.0,
            clients: 0,
        };
        (c, c)
    }
    async fn proxy_bind(&self) -> Option<ProxyBind> {
        None
    }
    async fn note_webui(&self, _: &str, _: u16) {}
    async fn issue_webui_cert(&self, sans: &[String]) -> Result<(String, String), String> {
        Ok(self.0.leaf(sans))
    }
}

struct Env {
    ctx: TestContext,
    ca: Arc<TestCa>,
    addr: SocketAddr,
}

async fn start() -> Env {
    let ctx = TestContext::new().await.unwrap();
    let ca = Arc::new(TestCa::new());
    assert!(ctx.state.runtime.set(Arc::new(Fake(ca.clone()))).is_ok());
    let mut cfg = ctx.api_config.clone();
    cfg.server.host = "127.0.0.1".into();
    cfg.server.port = 0;
    tokio::spawn(web_api::start_server(ctx.state.clone(), cfg));
    let web = loop {
        if let Some(w) = ctx.state.web_server.get() {
            break w.clone();
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    };
    let addr = web.addr().await;
    Env { ctx, ca, addr }
}

fn client_config(ca_pem: &str) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut ca_pem.as_bytes()) {
        roots.add(c.unwrap()).unwrap();
    }
    Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth(),
    )
}

/// HTTPS GET over a fresh connection trusting only `ca_pem`: `(response text, leaf SHA-256)`.
async fn https_get(
    addr: SocketAddr,
    ca_pem: &str,
    host: &str,
    path: &str,
) -> Result<(String, String), String> {
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| e.to_string())?;
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).unwrap();
    let mut s = tokio_rustls::TlsConnector::from(client_config(ca_pem))
        .connect(name, tcp)
        .await
        .map_err(|e| e.to_string())?;
    let leaf = s.get_ref().1.peer_certificates().unwrap()[0].clone();
    let fp: String = Sha256::digest(leaf.as_ref())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .map_err(|e| e.to_string())?;
    let mut out = String::new();
    let _ = s.read_to_string(&mut out).await;
    Ok((out, fp))
}

async fn plain_get(addr: SocketAddr, host: &str, path: &str) -> String {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out).await;
    out
}

fn fingerprint(pem: &str) -> String {
    let c = rustls_pemfile::certs(&mut pem.as_bytes())
        .next()
        .unwrap()
        .unwrap();
    Sha256::digest(c.as_ref())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

async fn put_tls(env: &Env, admin: &common::Sess, body: Value) -> axum_test::TestResponse {
    let _ = env;
    admin.put("/api/v1/settings/webui/tls").json(&body).await
}

#[tokio::test]
async fn tls_handshake_redirect_live_swap_and_bad_upload() {
    let env = start().await;
    let admin = env.ctx.admin().await;
    let port = env.addr.port();

    // Plain HTTP works until HTTPS is switched on.
    assert!(plain_get(env.addr, "localhost", "/api/v1/health")
        .await
        .starts_with("HTTP/1.1 200"));

    let r = put_tls(
        &env,
        &admin,
        json!({"mode": "argus_ca", "sans": ["localhost", "127.0.0.1"], "redirect_http": true}),
    )
    .await;
    r.assert_status_ok();
    let st: Value = r.json();
    assert_eq!(st["active"], json!(true));
    assert_eq!(st["mode"], json!("argus_ca"));
    assert!(st["cert"]["sans"]
        .as_array()
        .unwrap()
        .contains(&json!("127.0.0.1")));
    assert!(st.get("key_pem").is_none());

    // A client trusting the test CA completes the handshake and gets the API.
    let (resp, fp1) = https_get(env.addr, &env.ca.pem, "localhost", "/api/v1/health")
        .await
        .unwrap();
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert_eq!(st["cert"]["fingerprint_sha256"], json!(fp1));
    // The IP SAN is honoured too.
    https_get(env.addr, &env.ca.pem, "127.0.0.1", "/api/v1/health")
        .await
        .unwrap();
    // A client that does not trust the CA is refused.
    let other = TestCa::new();
    assert!(https_get(env.addr, &other.pem, "localhost", "/")
        .await
        .is_err());

    // Plain HTTP is redirected (308), keeping host, port and path; the CA download is not.
    let resp = plain_get(env.addr, &format!("localhost:{port}"), "/settings?a=1")
        .await
        .to_lowercase();
    assert!(resp.starts_with("http/1.1 308"), "{resp}");
    assert!(
        resp.contains(&format!("location: https://localhost:{port}/settings?a=1")),
        "{resp}"
    );
    let ca = plain_get(env.addr, "localhost", "/api/v1/ca.crt").await;
    assert!(!ca.starts_with("HTTP/1.1 308"), "{ca}");
    // Redirect off: plain HTTP is served again.
    put_tls(
        &env,
        &admin,
        json!({"mode": "argus_ca", "sans": ["localhost", "127.0.0.1"], "redirect_http": false}),
    )
    .await
    .assert_status_ok();
    assert!(plain_get(env.addr, "localhost", "/api/v1/health")
        .await
        .starts_with("HTTP/1.1 200"));

    // New names: a certificate is issued and the next connection sees it, no rebind.
    put_tls(
        &env,
        &admin,
        json!({"mode": "argus_ca", "sans": ["localhost", "127.0.0.1", "argus.test"], "redirect_http": false}),
    )
    .await
    .assert_status_ok();
    let (_, fp2) = https_get(env.addr, &env.ca.pem, "argus.test", "/api/v1/health")
        .await
        .unwrap();
    assert_ne!(fp1, fp2);
    assert_eq!(
        env.ctx.state.web_server.get().unwrap().addr().await,
        env.addr
    );

    // Same names again reuse the stored certificate instead of reissuing.
    put_tls(
        &env,
        &admin,
        json!({"mode": "argus_ca", "sans": ["localhost", "127.0.0.1", "argus.test"], "redirect_http": false}),
    )
    .await
    .assert_status_ok();
    let (_, fp3) = https_get(env.addr, &env.ca.pem, "argus.test", "/api/v1/health")
        .await
        .unwrap();
    assert_eq!(fp2, fp3);

    // A bad upload (key of another certificate; then garbage) is a 422 and nothing changes.
    let names = vec!["localhost".to_string()];
    let (cert_a, _key_a) = env.ca.leaf(&names);
    let (_cert_b, key_b) = env.ca.leaf(&names);
    for (c, k) in [
        (cert_a.clone(), key_b),
        ("not pem".to_string(), "nope".to_string()),
        (cert_a.clone(), String::new()),
    ] {
        let r = admin
            .post("/api/v1/settings/webui/tls/upload")
            .json(&json!({"cert_pem": c, "key_pem": k}))
            .await;
        assert_eq!(r.status_code(), 422, "{}", r.text());
    }
    let (_, still) = https_get(env.addr, &env.ca.pem, "argus.test", "/api/v1/health")
        .await
        .unwrap();
    assert_eq!(still, fp2, "old certificate is still served");
    let st: Value = admin.get("/api/v1/settings/webui/tls").await.json();
    assert_eq!(st["mode"], json!("argus_ca"));
    assert_eq!(st["uploaded"], json!(false));

    // A good upload is applied live and stored 0600; the key never comes back.
    let (cert_c, key_c) = env.ca.leaf(&names);
    let r = admin
        .post("/api/v1/settings/webui/tls/upload")
        .json(&json!({"cert_pem": cert_c, "key_pem": key_c.clone()}))
        .await;
    r.assert_status_ok();
    assert!(!r.text().contains("PRIVATE KEY"));
    let st: Value = r.json();
    assert_eq!(st["mode"], json!("uploaded"));
    let (_, fp4) = https_get(env.addr, &env.ca.pem, "localhost", "/api/v1/health")
        .await
        .unwrap();
    assert_eq!(fp4, fingerprint(&cert_c));
    let dir = env.ctx.temp_dir.path().join("filters/webui-tls");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for f in ["cert.pem", "key.pem", "argus-cert.pem", "argus-key.pem"] {
            let mode = std::fs::metadata(dir.join(f)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{f}");
        }
    }
    assert_eq!(std::fs::read_to_string(dir.join("key.pem")).unwrap(), key_c);

    // The setting survives in the config overlay (what a restart would load).
    let saved = env.ctx.state.proxy_state.config.read().webui.tls.clone();
    assert_eq!(saved.mode, ::common::config::WebUiTlsMode::Uploaded);

    // Off: TLS handshakes are no longer accepted, plain HTTP works.
    put_tls(&env, &admin, json!({"mode": "off"}))
        .await
        .assert_status_ok();
    assert!(https_get(env.addr, &env.ca.pem, "localhost", "/")
        .await
        .is_err());
    assert!(plain_get(env.addr, "localhost", "/api/v1/health")
        .await
        .starts_with("HTTP/1.1 200"));
}

#[tokio::test]
async fn sessions_over_native_tls_get_secure_cookies() {
    let env = start().await;
    let admin = env.ctx.admin().await;
    put_tls(
        &env,
        &admin,
        json!({"mode": "argus_ca", "sans": ["localhost"], "redirect_http": false}),
    )
    .await
    .assert_status_ok();
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(env.ca.pem.as_bytes()).unwrap())
        .resolve("localhost", env.addr)
        .build()
        .unwrap();
    let body = json!({"username": "admin_user", "password": common::PASSWORD});
    let tls = client
        .post(format!(
            "https://localhost:{}/api/v1/auth/login",
            env.addr.port()
        ))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(tls.status(), 200);
    let cookies: Vec<_> = tls
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    assert!(!cookies.is_empty());
    assert!(cookies.iter().all(|c| c.contains("Secure")), "{cookies:?}");

    // Plain HTTP on the same listener keeps non-Secure cookies (LAN access still works).
    let plain = reqwest::Client::new()
        .post(format!("http://{}/api/v1/auth/login", env.addr))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(plain.status(), 200);
    assert!(plain
        .headers()
        .get_all("set-cookie")
        .iter()
        .all(|v| !v.to_str().unwrap().contains("Secure")));
}

#[tokio::test]
async fn invalid_names_and_missing_runtime_are_rejected() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let r = admin
        .put("/api/v1/settings/webui/tls")
        .json(&json!({"mode": "argus_ca", "sans": ["bad name!"]}))
        .await;
    assert_eq!(r.status_code(), 422);
    let r = admin
        .put("/api/v1/settings/webui/tls")
        .json(&json!({"mode": "argus_ca", "sans": []}))
        .await;
    assert_eq!(r.status_code(), 422);
    // No proxy runtime to issue from: 409, setting unchanged.
    let r = admin
        .put("/api/v1/settings/webui/tls")
        .json(&json!({"mode": "argus_ca", "sans": ["localhost"]}))
        .await;
    assert_eq!(r.status_code(), 409);
    let st: Value = admin.get("/api/v1/settings/webui/tls").await.json();
    assert_eq!(st["mode"], json!("off"));
    // Uploaded mode without an upload.
    let r = admin
        .put("/api/v1/settings/webui/tls")
        .json(&json!({"mode": "uploaded"}))
        .await;
    assert_eq!(r.status_code(), 422);
}

#[tokio::test]
async fn only_admins_may_change_https() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let user = ctx.user(&admin, "bob", "user").await;
    let r = user
        .put("/api/v1/settings/webui/tls")
        .json(&json!({"mode": "off"}))
        .await;
    assert_eq!(r.status_code(), 403);
}

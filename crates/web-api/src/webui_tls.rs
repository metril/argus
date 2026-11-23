//! Built-in HTTPS for the web UI: certificate storage, validation, issuing/renewal and the live
//! TLS state the listener reads on every connection.
//!
//! Files under `<adblock.data_dir>/webui-tls/` (mode 0600, never returned by the API):
//! `cert.pem` + `key.pem` (uploaded) and `argus-cert.pem` + `argus-key.pem` (issued by the
//! Argus CA).

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use api_types::{WebUiCertInfo, WebUiTlsStatus};
use arc_swap::ArcSwapOption;
use chrono::DateTime;
use common::config::{WebUiTls, WebUiTlsMode};
use rustls::ServerConfig;
use sha2::{Digest, Sha256};

use crate::state::AppState;

/// Certificates issued by Argus are renewed when fewer than this many days remain.
pub const RENEW_BEFORE_DAYS: i64 = 30;
/// Validity of an issued certificate (the longest browsers accept).
pub const ISSUED_DAYS: i64 = 397;

/// The TLS configuration the listener reads for every new connection. Swapping it takes effect
/// for the next connection without rebinding; open connections are asked to finish when TLS is
/// switched on or off (or the redirect changes), so nothing keeps the old protocol.
pub struct TlsShared {
    cfg: ArcSwapOption<ServerConfig>,
    redirect: AtomicBool,
    /// Proxies whose `X-Forwarded-Proto: https` means the client already used HTTPS.
    trusted: Vec<IpAddr>,
    epoch: tokio::sync::watch::Sender<u64>,
    header_timeout_ms: std::sync::atomic::AtomicU64,
}

impl TlsShared {
    pub fn new(cfg: Option<Arc<ServerConfig>>, redirect: bool, trusted: Vec<IpAddr>) -> Self {
        Self {
            cfg: ArcSwapOption::new(cfg),
            redirect: AtomicBool::new(redirect),
            trusted,
            epoch: tokio::sync::watch::channel(0).0,
            header_timeout_ms: std::sync::atomic::AtomicU64::new(30_000),
        }
    }
    pub fn set(&self, cfg: Option<Arc<ServerConfig>>, redirect: bool) {
        let (old, old_redirect) = self.snapshot();
        let changed = old.is_some() != cfg.is_some() || old_redirect != redirect;
        self.cfg.store(cfg);
        self.redirect.store(redirect, Ordering::Relaxed);
        if changed {
            self.epoch.send_modify(|e| *e += 1);
        }
    }
    pub fn snapshot(&self) -> (Option<Arc<ServerConfig>>, bool) {
        (self.cfg.load_full(), self.redirect.load(Ordering::Relaxed))
    }
    pub fn trusted(&self) -> &[IpAddr] {
        &self.trusted
    }
    /// Receiver that changes when connections should wind down (subscribe before `snapshot`).
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.epoch.subscribe()
    }
    pub fn header_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.header_timeout_ms.load(Ordering::Relaxed))
    }
    pub fn set_header_timeout(&self, d: std::time::Duration) {
        self.header_timeout_ms
            .store(d.as_millis() as u64, Ordering::Relaxed);
    }
}

/// Facts read from a certificate.
pub struct CertFacts {
    pub info: WebUiCertInfo,
    pub not_after: i64,
}

fn ts(t: i64) -> String {
    DateTime::from_timestamp(t, 0)
        .unwrap_or_default()
        .to_rfc3339()
}

/// Parse the leaf of a PEM chain.
pub fn inspect(cert_pem: &str) -> Result<CertFacts, String> {
    let der = first_cert(cert_pem)?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|e| format!("certificate is not valid X.509: {e}"))?;
    let mut sans = Vec::new();
    for ext in cert.extensions() {
        if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
            ext.parsed_extension()
        {
            for n in &san.general_names {
                match n {
                    x509_parser::extensions::GeneralName::DNSName(d) => sans.push(d.to_string()),
                    x509_parser::extensions::GeneralName::IPAddress(b) => {
                        if let Ok(a) = <[u8; 4]>::try_from(*b) {
                            sans.push(IpAddr::from(a).to_string());
                        } else if let Ok(a) = <[u8; 16]>::try_from(*b) {
                            sans.push(IpAddr::from(a).to_string());
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    let v = cert.validity();
    let fingerprint_sha256 = Sha256::digest(&der)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(CertFacts {
        info: WebUiCertInfo {
            subject: cert.subject().to_string(),
            issuer: cert.issuer().to_string(),
            sans,
            not_before: ts(v.not_before.timestamp()),
            not_after: ts(v.not_after.timestamp()),
            fingerprint_sha256,
        },
        not_after: v.not_after.timestamp(),
    })
}

fn first_cert(cert_pem: &str) -> Result<Vec<u8>, String> {
    rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .next()
        .ok_or_else(|| "no certificate found in the PEM".to_string())?
        .map(|c| c.to_vec())
        .map_err(|e| format!("certificate PEM is invalid: {e}"))
}

/// A rustls server config for `cert_pem` (leaf first) and `key_pem`; fails when either does not
/// parse or the key does not belong to the certificate.
pub fn server_config(cert_pem: &str, key_pem: &str) -> Result<Arc<ServerConfig>, String> {
    let chain = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("certificate PEM is invalid: {e}"))?;
    if chain.is_empty() {
        return Err("no certificate found in the PEM".into());
    }
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .map_err(|e| format!("private key PEM is invalid: {e}"))?
        .ok_or_else(|| "no private key found in the PEM".to_string())?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let certified = rustls::sign::CertifiedKey::from_der(chain.clone(), key.clone_key(), &provider)
        .map_err(|e| format!("private key does not match the certificate: {e}"))?;
    certified
        .keys_match()
        .map_err(|e| format!("private key does not match the certificate: {e}"))?;
    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| format!("private key does not match the certificate: {e}"))?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// Normalise and check a list of certificate names (DNS names or IP addresses).
pub fn validate_sans(sans: &[String]) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for s in sans {
        let s = s.trim();
        if s.is_empty() {
            continue;
        }
        let bare = s
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(s);
        let norm = if let Ok(ip) = bare.parse::<IpAddr>() {
            ip.to_string()
        } else {
            let h = s.to_ascii_lowercase();
            let body = h.strip_prefix("*.").unwrap_or(&h);
            let ok = !body.is_empty()
                && h.len() <= 253
                && body.split('.').all(|l| {
                    !l.is_empty()
                        && l.len() <= 63
                        && !l.starts_with('-')
                        && !l.ends_with('-')
                        && l.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                });
            if !ok {
                return Err(format!("\"{s}\" is not a valid host name or IP address"));
            }
            h
        };
        if !out.contains(&norm) {
            out.push(norm);
        }
    }
    if out.is_empty() {
        return Err("at least one host name or IP address is required".into());
    }
    if out.len() > 20 {
        return Err("at most 20 names are allowed".into());
    }
    Ok(out)
}

/// Whether the certificate covers all `sans` and has enough validity left.
fn fresh_for(f: &CertFacts, sans: &[String], now: i64) -> bool {
    f.not_after - now > RENEW_BEFORE_DAYS * 86400
        && sans.iter().all(|s| f.info.sans.iter().any(|c| c == s))
}

/// Whether `cert_pem` was signed by the CA certificate currently on disk (a regenerated or
/// replaced CA invalidates certificates issued by the old one).
fn signed_by_current_ca(state: &AppState, cert_pem: &str) -> bool {
    let ca_path = state.proxy_state.config.read().mitm.ca_cert_path.clone();
    let Ok(ca_pem) = std::fs::read_to_string(ca_path) else {
        return false;
    };
    let (Ok(ca_der), Ok(leaf_der)) = (first_cert(&ca_pem), first_cert(cert_pem)) else {
        return false;
    };
    let (Ok((_, ca)), Ok((_, leaf))) = (
        x509_parser::parse_x509_certificate(&ca_der),
        x509_parser::parse_x509_certificate(&leaf_der),
    ) else {
        return false;
    };
    leaf.verify_signature(Some(ca.public_key())).is_ok()
}

pub fn tls_dir(state: &AppState) -> PathBuf {
    state
        .proxy_state
        .config
        .read()
        .adblock
        .data_dir
        .join("webui-tls")
}

const UPLOADED: (&str, &str) = ("cert.pem", "key.pem");
const ISSUED: (&str, &str) = ("argus-cert.pem", "argus-key.pem");

fn files_of(dir: &Path, mode: WebUiTlsMode) -> Option<(PathBuf, PathBuf)> {
    let (c, k) = match mode {
        WebUiTlsMode::Off => return None,
        WebUiTlsMode::ArgusCa => ISSUED,
        WebUiTlsMode::Uploaded => UPLOADED,
    };
    Some((dir.join(c), dir.join(k)))
}

/// Write `data` readable by the owner only, atomically: the directory is 0700, the temporary
/// file has a random name and is created exclusively (never through a symlink), and the rename
/// is made durable by syncing the directory.
pub fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("f");
    let tmp = dir.join(format!(".{name}.{:016x}.tmp", rand::random::<u64>()));
    let written = (|| {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return written;
    }
    std::fs::File::open(dir)?.sync_all()
}

/// Previous contents of files a change overwrites, to put back when saving fails.
#[derive(Default)]
pub struct Backup(Vec<(PathBuf, Option<Vec<u8>>)>);

impl Backup {
    pub fn of(paths: &[&Path]) -> Self {
        Self(
            paths
                .iter()
                .map(|p| (p.to_path_buf(), std::fs::read(p).ok()))
                .collect(),
        )
    }
    pub fn restore(self) {
        for (p, old) in self.0 {
            let _ = match old {
                Some(b) => write_private(&p, &b),
                None => std::fs::remove_file(&p),
            };
        }
    }
}

/// Certificate and key PEM for the mode, or `None` when TLS is off. `issued` is true when new
/// files were written (an Argus certificate was (re)issued).
pub struct Material {
    pub cert_pem: String,
    pub key_pem: String,
    pub issued: bool,
}

/// The Argus-issued material: the stored certificate while it covers `sans` and is not about to
/// expire, otherwise a new one (written to disk).
async fn argus_material(state: &AppState, sans: &[String]) -> Result<Material, String> {
    let dir = tls_dir(state);
    let (cp, kp) = files_of(&dir, WebUiTlsMode::ArgusCa).expect("mode has files");
    if let (Ok(c), Ok(k)) = (std::fs::read_to_string(&cp), std::fs::read_to_string(&kp)) {
        if let Ok(f) = inspect(&c) {
            if fresh_for(&f, sans, chrono::Utc::now().timestamp())
                && signed_by_current_ca(state, &c)
                && server_config(&c, &k).is_ok()
            {
                return Ok(Material {
                    cert_pem: c,
                    key_pem: k,
                    issued: false,
                });
            }
        }
    }
    let rt = state
        .runtime
        .get()
        .ok_or_else(|| "the proxy is not running, so no certificate can be issued".to_string())?;
    let (cert_pem, key_pem) = rt.issue_webui_cert(sans).await?;
    let (c2, k2) = (cert_pem.clone(), key_pem.clone());
    tokio::task::spawn_blocking(move || {
        write_private(&cp, c2.as_bytes())?;
        write_private(&kp, k2.as_bytes())
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| format!("could not store the certificate: {e}"))?;
    Ok(Material {
        cert_pem,
        key_pem,
        issued: true,
    })
}

/// The material for `tls`: issued/loaded per its mode. `None` for `Off`.
pub async fn material(state: &AppState, tls: &WebUiTls) -> Result<Option<Material>, String> {
    match tls.mode {
        WebUiTlsMode::Off => Ok(None),
        WebUiTlsMode::ArgusCa => {
            let sans = validate_sans(&tls.sans)?;
            argus_material(state, &sans).await.map(Some)
        }
        WebUiTlsMode::Uploaded => {
            let (cp, kp) = files_of(&tls_dir(state), tls.mode).expect("mode has files");
            let c = std::fs::read_to_string(&cp)
                .map_err(|_| "no certificate has been uploaded yet".to_string())?;
            let k = std::fs::read_to_string(&kp)
                .map_err(|_| "no private key has been uploaded yet".to_string())?;
            Ok(Some(Material {
                cert_pem: c,
                key_pem: k,
                issued: false,
            }))
        }
    }
}

/// Server config for the saved setting, as used at startup.
pub async fn initial(state: &AppState) -> Option<Arc<ServerConfig>> {
    let tls = state.proxy_state.config.read().webui.tls.clone();
    if tls.mode == WebUiTlsMode::Off {
        return None;
    }
    let built = async {
        let m = material(state, &tls)
            .await?
            .ok_or_else(|| "TLS is off".to_string())?;
        server_config(&m.cert_pem, &m.key_pem)
    }
    .await;
    match built {
        Ok(c) => Some(c),
        Err(e) => {
            tracing::warn!("Web UI HTTPS is configured but unavailable ({e}); serving plain HTTP");
            None
        }
    }
}

/// Bring the listener in line with the saved setting: serve TLS if it is configured but not
/// active (startup fallback, either mode), and renew an Argus-issued certificate that is close
/// to expiry, no longer covers its names or was issued by a replaced CA. Holds the config lock
/// so it cannot interleave with a settings change.
pub async fn renew_if_due(state: &AppState) {
    let _g = state.config_lock.lock().await;
    let tls = state.proxy_state.config.read().webui.tls.clone();
    if tls.mode == WebUiTlsMode::Off {
        return;
    }
    let Some(web) = state.web_server.get() else {
        return;
    };
    match material(state, &tls).await {
        Ok(Some(m)) if m.issued || web.tls_snapshot().0.is_none() => {
            match server_config(&m.cert_pem, &m.key_pem) {
                Ok(cfg) => {
                    web.set_tls(Some(cfg), tls.redirect_http);
                    tracing::info!("Web UI HTTPS certificate loaded");
                }
                Err(e) => tracing::warn!("web UI certificate is unusable: {e}"),
            }
        }
        Ok(_) => {}
        Err(e) => tracing::warn!("web UI HTTPS unavailable: {e}"),
    }
}

/// Why HTTPS is configured but not served, if so.
pub fn not_served(state: &AppState) -> Option<String> {
    let mode = state.proxy_state.config.read().webui.tls.mode;
    let active = state
        .web_server
        .get()
        .is_some_and(|w| w.tls_snapshot().0.is_some());
    (mode != WebUiTlsMode::Off && !active).then(|| {
        "HTTPS is configured for the web UI but is not being served; it is plain HTTP right now. \
         Check the certificate under Settings > HTTPS."
            .to_string()
    })
}

/// The saved setting, the certificate it uses and whether TLS is being served.
pub fn status(state: &AppState) -> WebUiTlsStatus {
    let tls = state.proxy_state.config.read().webui.tls.clone();
    let dir = tls_dir(state);
    let mut error = None;
    let cert = files_of(&dir, tls.mode).and_then(|(cp, _)| match std::fs::read_to_string(&cp) {
        Ok(pem) => match inspect(&pem) {
            Ok(f) => Some(f.info),
            Err(e) => {
                error = Some(e);
                None
            }
        },
        Err(_) => None,
    });
    let active = state
        .web_server
        .get()
        .is_some_and(|w| w.tls_snapshot().0.is_some());
    if tls.mode != WebUiTlsMode::Off && !active && error.is_none() {
        error = Some("HTTPS is configured but not being served (see the log)".into());
    }
    WebUiTlsStatus {
        mode: wire_mode(tls.mode),
        sans: tls.sans,
        redirect_http: tls.redirect_http,
        active,
        cert,
        uploaded: dir.join(UPLOADED.0).exists() && dir.join(UPLOADED.1).exists(),
        error,
    }
}

pub fn wire_mode(m: WebUiTlsMode) -> api_types::WebUiTlsMode {
    match m {
        WebUiTlsMode::Off => api_types::WebUiTlsMode::Off,
        WebUiTlsMode::ArgusCa => api_types::WebUiTlsMode::ArgusCa,
        WebUiTlsMode::Uploaded => api_types::WebUiTlsMode::Uploaded,
    }
}

pub fn config_mode(m: api_types::WebUiTlsMode) -> WebUiTlsMode {
    match m {
        api_types::WebUiTlsMode::Off => WebUiTlsMode::Off,
        api_types::WebUiTlsMode::ArgusCa => WebUiTlsMode::ArgusCa,
        api_types::WebUiTlsMode::Uploaded => WebUiTlsMode::Uploaded,
    }
}

pub fn uploaded_paths(state: &AppState) -> (PathBuf, PathBuf) {
    files_of(&tls_dir(state), WebUiTlsMode::Uploaded).expect("mode has files")
}

pub fn issued_paths(state: &AppState) -> (PathBuf, PathBuf) {
    files_of(&tls_dir(state), WebUiTlsMode::ArgusCa).expect("mode has files")
}

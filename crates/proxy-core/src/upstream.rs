//! Construction of the pooled upstream HTTP client.

use crate::{Error, Result};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// Options for [`build_upstream_client`].
#[derive(Debug, Clone, Default)]
pub struct UpstreamOptions {
    /// PEM root CA files trusted in addition to the built-in web roots.
    pub extra_ca_paths: Vec<PathBuf>,
    /// Resolve every upstream hostname to this IP (ports come from the URL). Meant for tests
    /// and controlled environments; leave `None` in normal operation.
    ///
    /// Code-only on purpose: never derived from config or serde.
    pub resolve_all_to: Option<IpAddr>,
    /// TCP connect timeout for upstream connections.
    pub connect_timeout: Option<Duration>,
    /// Idle read timeout between upstream body chunks.
    pub read_timeout: Option<Duration>,
}

impl UpstreamOptions {
    /// Options derived from the proxy configuration.
    pub fn from_config(config: &crate::ProxyConfig) -> Self {
        Self {
            extra_ca_paths: config.proxy.extra_upstream_ca_paths.clone(),
            resolve_all_to: None,
            connect_timeout: Some(Duration::from_secs(
                config.performance.connection_timeout_secs.max(1),
            )),
            read_timeout: Some(Duration::from_secs(
                config.performance.request_timeout_secs.max(1),
            )),
        }
    }
}

/// Root store used for every upstream TLS dial: built-in web roots plus `extra_ca_paths` (PEM
/// files). Shared by the WebSocket path so HTTP and WebSocket trust the same CAs.
pub fn build_root_store(extra_ca_paths: &[PathBuf]) -> Result<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for path in extra_ca_paths {
        let pem = std::fs::read(path).map_err(|e| {
            Error::Config(format!(
                "Failed to read upstream CA {}: {e}",
                path.display()
            ))
        })?;
        let mut n = 0;
        for cert in rustls_pemfile::certs(&mut pem.as_slice()) {
            let cert = cert.map_err(|e| {
                Error::Config(format!("Invalid upstream CA {}: {e}", path.display()))
            })?;
            roots.add(cert).map_err(|e| {
                Error::Config(format!("Invalid upstream CA {}: {e}", path.display()))
            })?;
            n += 1;
        }
        if n == 0 {
            return Err(Error::Config(format!(
                "Upstream CA {} contains no PEM certificates",
                path.display()
            )));
        }
    }
    Ok(roots)
}

struct FixedIpResolver(IpAddr);

impl reqwest::dns::Resolve for FixedIpResolver {
    fn resolve(&self, _name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let addr = SocketAddr::new(self.0, 0);
        Box::pin(async move { Ok(Box::new(std::iter::once(addr)) as reqwest::dns::Addrs) })
    }
}

/// Build the shared upstream client. Redirects are passed through to the downstream client
/// (the proxy must not follow them itself).
pub fn build_upstream_client(opts: &UpstreamOptions) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none());
    for path in &opts.extra_ca_paths {
        let pem = std::fs::read(path).map_err(|e| {
            Error::Config(format!(
                "Failed to read upstream CA {}: {e}",
                path.display()
            ))
        })?;
        let certs = reqwest::Certificate::from_pem_bundle(&pem)
            .map_err(|e| Error::Config(format!("Invalid upstream CA {}: {e}", path.display())))?;
        if certs.is_empty() {
            return Err(Error::Config(format!(
                "Upstream CA {} contains no PEM certificates",
                path.display()
            )));
        }
        for cert in certs {
            builder = builder.add_root_certificate(cert);
        }
    }
    if let Some(t) = opts.connect_timeout {
        builder = builder.connect_timeout(t);
    }
    if let Some(t) = opts.read_timeout {
        builder = builder.read_timeout(t);
    }
    if let Some(ip) = opts.resolve_all_to {
        builder = builder.dns_resolver(Arc::new(FixedIpResolver(ip)));
    }
    builder
        .build()
        .map_err(|e| Error::Config(format!("Failed to build upstream HTTP client: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts_with(path: PathBuf) -> UpstreamOptions {
        UpstreamOptions {
            extra_ca_paths: vec![path],
            ..Default::default()
        }
    }

    #[test]
    fn resolve_override_and_timeouts_come_from_code_not_config() {
        let mut cfg = crate::ProxyConfig::default();
        cfg.performance.connection_timeout_secs = 3;
        cfg.performance.request_timeout_secs = 9;
        let o = UpstreamOptions::from_config(&cfg);
        assert_eq!(o.resolve_all_to, None);
        assert_eq!(o.connect_timeout, Some(Duration::from_secs(3)));
        assert_eq!(o.read_timeout, Some(Duration::from_secs(9)));
        // A config file cannot carry the override: unknown keys are not part of the schema.
        let toml = toml::to_string(&cfg).unwrap();
        assert!(!toml.contains("resolve_all_to"));
    }

    #[test]
    fn root_store_includes_web_roots_and_rejects_empty_ca_file() {
        assert!(!build_root_store(&[]).unwrap().is_empty());
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.pem");
        std::fs::write(&p, "nope").unwrap();
        assert!(build_root_store(&[p]).is_err());
    }

    #[test]
    fn ca_file_without_certificates_is_a_config_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-a-ca.pem");
        std::fs::write(&path, "this is not a certificate\n").unwrap();
        let err = build_upstream_client(&opts_with(path)).unwrap_err();
        assert!(err.to_string().contains("no PEM certificates"), "{err}");
    }

    #[test]
    fn missing_ca_file_is_a_config_error() {
        let err =
            build_upstream_client(&opts_with(PathBuf::from("/nonexistent/ca.pem"))).unwrap_err();
        assert!(
            err.to_string().contains("Failed to read upstream CA"),
            "{err}"
        );
    }
}

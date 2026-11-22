//! Construction of the pooled upstream HTTP client.

use crate::{Error, Result};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

/// Options for [`build_upstream_client`].
#[derive(Debug, Clone, Default)]
pub struct UpstreamOptions {
    /// PEM root CA files trusted in addition to the built-in web roots.
    pub extra_ca_paths: Vec<PathBuf>,
    /// Resolve every upstream hostname to this IP (ports come from the URL). Meant for tests
    /// and controlled environments; leave `None` in normal operation.
    pub resolve_all_to: Option<IpAddr>,
}

impl UpstreamOptions {
    /// Options derived from the proxy configuration.
    pub fn from_config(config: &crate::ProxyConfig) -> Self {
        Self {
            extra_ca_paths: config.proxy.extra_upstream_ca_paths.clone(),
            resolve_all_to: None,
        }
    }
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
        for cert in certs {
            builder = builder.add_root_certificate(cert);
        }
    }
    if let Some(ip) = opts.resolve_all_to {
        builder = builder.dns_resolver(Arc::new(FixedIpResolver(ip)));
    }
    builder
        .build()
        .map_err(|e| Error::Config(format!("Failed to build upstream HTTP client: {e}")))
}

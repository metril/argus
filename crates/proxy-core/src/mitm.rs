//! MITM logic and certificate caching

use crate::{ca::CertificateAuthority, tls, Error, Result};
use moka::future::Cache;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ProducesTickets;
use rustls::ServerConfig;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{debug, info, trace, warn};

/// Cached certificate data, including the ready-to-use TLS server config so a warm connection
/// does no certificate or config construction.
#[derive(Clone)]
pub struct CertificateData {
    pub cert: CertificateDer<'static>,
    pub key: Arc<PrivateKeyDer<'static>>,
    pub server_config: Arc<ServerConfig>,
}

/// MITM handler with certificate caching
pub struct MitmHandler {
    /// Certificate Authority
    ca: Arc<CertificateAuthority>,
    /// Certificate cache (host -> certificate data). `try_get_with` coalesces concurrent misses
    /// for one host into a single generation.
    cert_cache: Cache<String, Arc<CertificateData>>,
    /// Limits concurrent certificate generations across distinct hosts
    cert_gen_semaphore: Arc<Semaphore>,
    /// Offer h2 via ALPN on client connections
    enable_http2: bool,
    /// Shared session-ticket key rotator for TLS resumption across all hosts
    ticketer: Option<Arc<dyn ProducesTickets>>,
    /// Number of leaf certificates actually generated (observability / tests)
    generations: Arc<AtomicU64>,
}

impl MitmHandler {
    /// Create a new MITM handler
    pub fn new(
        ca: Arc<CertificateAuthority>,
        cache_size: usize,
        cache_ttl_secs: u64,
        max_concurrent_generations: usize,
    ) -> Self {
        info!(
            "Initializing MITM handler with cache size: {}, TTL: {}s",
            cache_size, cache_ttl_secs
        );

        let cert_cache = Cache::builder()
            .max_capacity(cache_size as u64)
            .time_to_live(Duration::from_secs(cache_ttl_secs))
            .time_to_idle(Duration::from_secs(cache_ttl_secs / 2))
            .build();

        let ticketer = match tls::new_ticketer() {
            Ok(t) => Some(t),
            Err(e) => {
                warn!("TLS session tickets disabled: {}", e);
                None
            }
        };

        Self {
            ca,
            cert_cache,
            cert_gen_semaphore: Arc::new(Semaphore::new(max_concurrent_generations.max(1))),
            enable_http2: true,
            ticketer,
            generations: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Whether client-facing TLS configs offer h2 (set before first use; default true).
    pub fn with_http2(mut self, enable_http2: bool) -> Self {
        self.enable_http2 = enable_http2;
        self
    }

    /// Number of certificates generated so far.
    pub fn generation_count(&self) -> u64 {
        self.generations.load(Ordering::Relaxed)
    }

    /// Get or generate a certificate (and ready TLS config) for the given host.
    ///
    /// Generation runs on the blocking pool; concurrent first requests for one host share one run.
    pub async fn get_certificate(&self, domain: &str) -> Result<Arc<CertificateData>> {
        let host = Self::normalize_domain(domain);

        if let Some(cert_data) = self.cert_cache.get(&host).await {
            trace!("Cache hit for host: {}", host);
            return Ok(cert_data);
        }

        let ca = self.ca.clone();
        let sem = self.cert_gen_semaphore.clone();
        let ticketer = self.ticketer.clone();
        let enable_http2 = self.enable_http2;
        let generations = self.generations.clone();
        let key = host.clone();

        self.cert_cache
            .try_get_with(key, async move {
                let _permit = sem
                    .acquire()
                    .await
                    .map_err(|e| Error::Internal(format!("Failed to acquire semaphore: {}", e)))?;
                generations.fetch_add(1, Ordering::Relaxed);
                debug!("Generating certificate for host: {}", host);
                tokio::task::spawn_blocking(move || {
                    let (cert, key) = ca.generate_cert(&host)?;
                    let server_config = tls::build_server_config(
                        cert.clone(),
                        key.clone_key(),
                        enable_http2,
                        ticketer,
                    )?;
                    Ok::<_, Error>(Arc::new(CertificateData {
                        cert,
                        key: Arc::new(key),
                        server_config,
                    }))
                })
                .await
                .map_err(|e| Error::Internal(format!("Certificate task failed: {}", e)))?
            })
            .await
            .map_err(|e: Arc<Error>| Error::Certificate(e.to_string()))
    }

    /// Handle a CONNECT request
    pub async fn handle_connect(&self, domain: &str, port: u16) -> Result<Arc<CertificateData>> {
        trace!("Handling CONNECT for {}:{}", domain, port);
        self.get_certificate(domain).await
    }

    /// Normalize a host (strip port and IPv6 brackets, lowercase).
    fn normalize_domain(host: &str) -> String {
        let h = if let Some(rest) = host.strip_prefix('[') {
            rest.split(']').next().unwrap_or(rest)
        } else if host.matches(':').count() > 1 {
            host // bare IPv6 literal
        } else {
            host.split(':').next().unwrap_or(host)
        };
        h.to_lowercase()
    }

    /// Get a reference to the Certificate Authority
    pub fn ca(&self) -> &Arc<CertificateAuthority> {
        &self.ca
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> CacheStats {
        CacheStats {
            entry_count: self.cert_cache.entry_count(),
            weighted_size: self.cert_cache.weighted_size(),
        }
    }

    /// Run pending cache maintenance tasks (useful for testing to ensure stats are updated)
    pub async fn run_pending_tasks(&self) {
        self.cert_cache.run_pending_tasks().await;
    }

    /// Clear the certificate cache
    pub fn clear_cache(&self) {
        info!("Clearing certificate cache");
        self.cert_cache.invalidate_all();
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub entry_count: u64,
    pub weighted_size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::CertificateAuthority;

    fn test_ca() -> (tempfile::TempDir, Arc<CertificateAuthority>) {
        let tmp = tempfile::tempdir().unwrap();
        let ca = Arc::new(
            CertificateAuthority::load_or_generate(
                tmp.path().join("ca.crt"),
                tmp.path().join("ca.key"),
            )
            .expect("Failed to create CA"),
        );
        (tmp, ca)
    }

    #[tokio::test]
    async fn test_cert_caching() {
        let (_tmp, ca) = test_ca();
        let handler = MitmHandler::new(ca, 10, 3600, 5);

        let cert1 = handler.get_certificate("example.com").await.unwrap();
        let cert2 = handler.get_certificate("example.com").await.unwrap();
        assert!(Arc::ptr_eq(&cert1, &cert2));

        handler.run_pending_tasks().await;
        assert_eq!(handler.cache_stats().entry_count, 1);
    }

    #[tokio::test]
    async fn test_domain_normalization() {
        assert_eq!(MitmHandler::normalize_domain("Example.COM"), "example.com");
        assert_eq!(
            MitmHandler::normalize_domain("Example.COM:443"),
            "example.com"
        );
        assert_eq!(
            MitmHandler::normalize_domain("sub.example.com:8443"),
            "sub.example.com"
        );
        assert_eq!(MitmHandler::normalize_domain("[::1]:443"), "::1");
        assert_eq!(MitmHandler::normalize_domain("2001:DB8::1"), "2001:db8::1");
    }

    #[tokio::test]
    async fn test_multiple_domains() {
        let (_tmp, ca) = test_ca();
        let handler = MitmHandler::new(ca, 10, 3600, 5);
        for d in ["example.com", "test.com", "another.com"] {
            handler.get_certificate(d).await.unwrap();
        }
        handler.run_pending_tasks().await;
        assert_eq!(handler.cache_stats().entry_count, 3);
        assert_eq!(handler.generation_count(), 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_first_requests_generate_once() {
        let (_tmp, ca) = test_ca();
        let handler = Arc::new(MitmHandler::new(ca, 10, 3600, 8));
        let tasks: Vec<_> = (0..32)
            .map(|_| {
                let h = handler.clone();
                tokio::spawn(
                    async move { h.get_certificate("Burst.Example.com:443").await.unwrap() },
                )
            })
            .collect();
        let mut certs = Vec::new();
        for t in tasks {
            certs.push(t.await.unwrap());
        }
        assert_eq!(handler.generation_count(), 1);
        assert!(certs.iter().all(|c| Arc::ptr_eq(c, &certs[0])));
    }
}

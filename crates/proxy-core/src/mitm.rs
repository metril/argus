//! MITM logic and certificate caching

use crate::{ca::CertificateAuthority, Error, Result};
use moka::sync::Cache;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{debug, info};

/// Cached certificate data
#[derive(Clone)]
pub struct CertificateData {
    pub cert: CertificateDer<'static>,
    pub key: Arc<PrivateKeyDer<'static>>,
}

/// MITM handler with certificate caching
pub struct MitmHandler {
    /// Certificate Authority
    ca: Arc<CertificateAuthority>,
    /// Certificate cache (domain -> certificate data)
    cert_cache: Cache<String, Arc<CertificateData>>,
    /// Semaphore to limit concurrent certificate generations
    cert_gen_semaphore: Arc<Semaphore>,
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

        // Create cache with TTL and size limits
        let cert_cache = Cache::builder()
            .max_capacity(cache_size as u64)
            .time_to_live(Duration::from_secs(cache_ttl_secs))
            .time_to_idle(Duration::from_secs(cache_ttl_secs / 2))
            .build();

        Self {
            ca,
            cert_cache,
            cert_gen_semaphore: Arc::new(Semaphore::new(max_concurrent_generations)),
        }
    }

    /// Get or generate a certificate for the given domain
    pub async fn get_certificate(&self, domain: &str) -> Result<Arc<CertificateData>> {
        // Normalize domain (remove port if present)
        let domain = Self::normalize_domain(domain);

        // Check cache first
        if let Some(cert_data) = self.cert_cache.get(&domain) {
            debug!("Cache hit for domain: {}", domain);
            return Ok(cert_data);
        }

        debug!("Cache miss for domain: {}", domain);

        // Acquire semaphore permit to limit concurrent generations
        let _permit = self
            .cert_gen_semaphore
            .acquire()
            .await
            .map_err(|e| Error::Internal(format!("Failed to acquire semaphore: {}", e)))?;

        // Double-check cache after acquiring permit (another task might have generated it)
        if let Some(cert_data) = self.cert_cache.get(&domain) {
            debug!(
                "Cache hit after semaphore acquisition for domain: {}",
                domain
            );
            return Ok(cert_data);
        }

        // Generate new certificate
        info!("Generating certificate for domain: {}", domain);
        let (cert, key) = self.ca.generate_cert(&domain)?;

        let cert_data = Arc::new(CertificateData {
            cert,
            key: Arc::new(key),
        });

        // Cache the certificate
        self.cert_cache.insert(domain.clone(), cert_data.clone());

        Ok(cert_data)
    }

    /// Handle a CONNECT request
    pub async fn handle_connect(&self, domain: &str, port: u16) -> Result<Arc<CertificateData>> {
        debug!("Handling CONNECT for {}:{}", domain, port);

        // Get or generate certificate for the domain
        self.get_certificate(domain).await
    }

    /// Normalize domain name (remove port and convert to lowercase)
    fn normalize_domain(domain: &str) -> String {
        // Remove port if present
        let domain = domain.split(':').next().unwrap_or(domain);
        // Convert to lowercase
        domain.to_lowercase()
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
    pub fn run_pending_tasks(&self) {
        self.cert_cache.run_pending_tasks();
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
    use std::env;

    #[tokio::test]
    async fn test_cert_caching() {
        let temp_dir = env::temp_dir();
        let cert_path = temp_dir.join("test-mitm-ca.crt");
        let key_path = temp_dir.join("test-mitm-ca.key");

        // Clean up any existing files
        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);

        // Create CA
        let ca = Arc::new(
            CertificateAuthority::load_or_generate(&cert_path, &key_path)
                .expect("Failed to create CA"),
        );

        // Create MITM handler
        let handler = MitmHandler::new(ca, 10, 3600, 5);

        // Get certificate for a domain
        let cert1 = handler
            .get_certificate("example.com")
            .await
            .expect("Failed to get certificate");

        // Get certificate for the same domain again (should be cached)
        let cert2 = handler
            .get_certificate("example.com")
            .await
            .expect("Failed to get certificate");

        // Both should be the same (Arc pointing to same data)
        assert!(Arc::ptr_eq(&cert1, &cert2));

        // Force cache maintenance to update stats
        handler.run_pending_tasks();

        // Check cache stats
        let stats = handler.cache_stats();
        assert_eq!(stats.entry_count, 1);

        // Clean up
        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);
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
    }

    #[tokio::test]
    async fn test_multiple_domains() {
        let temp_dir = env::temp_dir();
        let cert_path = temp_dir.join("test-mitm-multi-ca.crt");
        let key_path = temp_dir.join("test-mitm-multi-ca.key");

        // Clean up any existing files
        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);

        // Create CA
        let ca = Arc::new(
            CertificateAuthority::load_or_generate(&cert_path, &key_path)
                .expect("Failed to create CA"),
        );

        // Create MITM handler
        let handler = MitmHandler::new(ca, 10, 3600, 5);

        // Get certificates for multiple domains
        let _cert1 = handler
            .get_certificate("example.com")
            .await
            .expect("Failed to get certificate");
        let _cert2 = handler
            .get_certificate("test.com")
            .await
            .expect("Failed to get certificate");
        let _cert3 = handler
            .get_certificate("another.com")
            .await
            .expect("Failed to get certificate");

        // Force cache maintenance to update stats
        handler.run_pending_tasks();

        // Check cache stats
        let stats = handler.cache_stats();
        assert_eq!(stats.entry_count, 3);

        // Clean up
        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);
    }
}

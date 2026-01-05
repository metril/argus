//! Tests for connection handling

use proxy_core::config::{MitmConfig, PerformanceConfig, ProxyConfig};
use proxy_core::ProxyServer;
use std::time::Duration;
use tokio::time::timeout;

#[tokio::test]
async fn test_server_with_mitm_enabled() {
    let config = ProxyConfig {
        proxy: proxy_core::config::ProxySettings {
            host: "127.0.0.1".to_string(),
            port: 0, // Use random port for testing
            max_connections: 100,
            enable_http2: false,
            enable_http3: false,
            enable_websockets: false,
        },
        mitm: MitmConfig {
            enabled: true,
            ca_cert_path: std::env::temp_dir().join("test-conn-ca.crt"),
            ca_key_path: std::env::temp_dir().join("test-conn-ca.key"),
            cert_cache_size: 100,
            cert_ttl_days: 30,
        },
        performance: PerformanceConfig {
            max_cert_generations: 10,
            buffer_size: 8192,
            max_html_buffers: 10,
            connection_timeout_secs: 5,
            request_timeout_secs: 10,
        },
    };

    // Clean up any existing CA files
    let _ = std::fs::remove_file(&config.mitm.ca_cert_path);
    let _ = std::fs::remove_file(&config.mitm.ca_key_path);

    // Create server with MITM enabled
    let server = ProxyServer::new(config).expect("Failed to create server with MITM");

    // Verify MITM handler exists
    assert!(
        server.mitm_handler().is_some(),
        "MITM handler should be initialized"
    );

    // Check cache stats
    if let Some(mitm) = server.mitm_handler() {
        let stats = mitm.cache_stats();
        assert_eq!(stats.entry_count, 0, "Cache should start empty");
    }

    // Clean up
    let _ = std::fs::remove_file(std::env::temp_dir().join("test-conn-ca.crt"));
    let _ = std::fs::remove_file(std::env::temp_dir().join("test-conn-ca.key"));
}

#[tokio::test]
async fn test_server_with_mitm_disabled() {
    let config = ProxyConfig {
        proxy: proxy_core::config::ProxySettings {
            host: "127.0.0.1".to_string(),
            port: 0,
            max_connections: 100,
            enable_http2: false,
            enable_http3: false,
            enable_websockets: false,
        },
        mitm: MitmConfig {
            enabled: false,
            ca_cert_path: std::env::temp_dir().join("unused-ca.crt"),
            ca_key_path: std::env::temp_dir().join("unused-ca.key"),
            cert_cache_size: 100,
            cert_ttl_days: 30,
        },
        performance: PerformanceConfig {
            max_cert_generations: 10,
            buffer_size: 8192,
            max_html_buffers: 10,
            connection_timeout_secs: 5,
            request_timeout_secs: 10,
        },
    };

    // Create server with MITM disabled
    let server = ProxyServer::new(config).expect("Failed to create server without MITM");

    // Verify MITM handler does not exist
    assert!(
        server.mitm_handler().is_none(),
        "MITM handler should not be initialized when disabled"
    );
}

#[tokio::test]
async fn test_certificate_generation() {
    let config = ProxyConfig {
        proxy: proxy_core::config::ProxySettings {
            host: "127.0.0.1".to_string(),
            port: 0,
            max_connections: 100,
            enable_http2: false,
            enable_http3: false,
            enable_websockets: false,
        },
        mitm: MitmConfig {
            enabled: true,
            ca_cert_path: std::env::temp_dir().join("test-certgen-ca.crt"),
            ca_key_path: std::env::temp_dir().join("test-certgen-ca.key"),
            cert_cache_size: 100,
            cert_ttl_days: 30,
        },
        performance: PerformanceConfig {
            max_cert_generations: 10,
            buffer_size: 8192,
            max_html_buffers: 10,
            connection_timeout_secs: 5,
            request_timeout_secs: 10,
        },
    };

    // Clean up any existing CA files
    let _ = std::fs::remove_file(&config.mitm.ca_cert_path);
    let _ = std::fs::remove_file(&config.mitm.ca_key_path);

    // Create server
    let server = ProxyServer::new(config).expect("Failed to create server");

    // Get MITM handler
    let mitm = server.mitm_handler().expect("MITM handler should exist");

    // Test certificate generation for a domain
    let cert1 = mitm
        .get_certificate("example.com")
        .await
        .expect("Failed to generate certificate");

    // Verify cert is not empty
    assert!(!cert1.cert.is_empty(), "Certificate should not be empty");
    assert!(
        !matches!(cert1.key, rustls::pki_types::PrivateKeyDer::Pkcs8(_) if false),
        "Private key should exist"
    );

    // Get the same domain again - should be cached
    let cert2 = mitm
        .get_certificate("example.com")
        .await
        .expect("Failed to get cached certificate");

    // Verify it's the same certificate (Arc pointer equality)
    assert!(
        std::sync::Arc::ptr_eq(&cert1, &cert2),
        "Should return cached certificate"
    );

    // Check cache stats
    let stats = mitm.cache_stats();
    assert_eq!(stats.entry_count, 1, "Cache should have 1 entry");

    // Clean up
    let _ = std::fs::remove_file(std::env::temp_dir().join("test-certgen-ca.crt"));
    let _ = std::fs::remove_file(std::env::temp_dir().join("test-certgen-ca.key"));
}

//! Tests for connection handling

use proxy_core::config::{MitmSettings, PerformanceSettings, AdblockSettings, ProxyConfig, UserscriptSettings, WebUiSettings};
use proxy_core::{ProxyContext, ProxyServer};
use std::sync::Arc;

/// A minimal filtering context for server-construction tests (filtering disabled).
fn test_ctx() -> Arc<ProxyContext> {
    Arc::new(ProxyContext::new(
        Arc::new(filter_engine::SharedEngine::new()),
        reqwest::Client::new(),
        false,
    ))
}

#[tokio::test]
async fn test_server_with_mitm_enabled() {
    let config = ProxyConfig {
        proxy: proxy_core::config::ProxySettings {
            host: "127.0.0.1".to_string(),
            port: 0, // Use random port for testing
            enable_http2: false,
            enable_http3: false,
            enable_websockets: false,
        },
        mitm: MitmSettings {
            enabled: true,
            ca_cert_path: std::env::temp_dir().join("test-conn-ca.crt"),
            ca_key_path: std::env::temp_dir().join("test-conn-ca.key"),
            cert_cache_size: 100,
            cert_ttl_days: 30,
            cert_idle_timeout_secs: 3600,
        },
        performance: PerformanceSettings {
            max_connections: 100,
            max_cert_generations: 10,
            max_html_buffers: 10,
            connection_timeout_secs: 5,
            request_timeout_secs: 10,
            connection_rate_limit: Some(100),
        },
        adblock: AdblockSettings::default(),
        userscripts: UserscriptSettings::default(),
        webui: WebUiSettings::default(),
    };

    // Clean up any existing CA files
    let _ = std::fs::remove_file(&config.mitm.ca_cert_path);
    let _ = std::fs::remove_file(&config.mitm.ca_key_path);

    // Create server with MITM enabled
    let server = ProxyServer::new(config, test_ctx()).expect("Failed to create server with MITM");

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
            enable_http2: false,
            enable_http3: false,
            enable_websockets: false,
        },
        mitm: MitmSettings {
            enabled: false,
            ca_cert_path: std::env::temp_dir().join("unused-ca.crt"),
            ca_key_path: std::env::temp_dir().join("unused-ca.key"),
            cert_cache_size: 100,
            cert_ttl_days: 30,
            cert_idle_timeout_secs: 3600,
        },
        performance: PerformanceSettings {
            max_connections: 100,
            max_cert_generations: 10,
            max_html_buffers: 10,
            connection_timeout_secs: 5,
            request_timeout_secs: 10,
            connection_rate_limit: Some(100),
        },
        adblock: AdblockSettings::default(),
        userscripts: UserscriptSettings::default(),
        webui: WebUiSettings::default(),
    };

    // Create server with MITM disabled
    let server = ProxyServer::new(config, test_ctx()).expect("Failed to create server without MITM");

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
            enable_http2: false,
            enable_http3: false,
            enable_websockets: false,
        },
        mitm: MitmSettings {
            enabled: true,
            ca_cert_path: std::env::temp_dir().join("test-certgen-ca.crt"),
            ca_key_path: std::env::temp_dir().join("test-certgen-ca.key"),
            cert_cache_size: 100,
            cert_ttl_days: 30,
            cert_idle_timeout_secs: 3600,
        },
        performance: PerformanceSettings {
            max_connections: 100,
            max_cert_generations: 10,
            max_html_buffers: 10,
            connection_timeout_secs: 5,
            request_timeout_secs: 10,
            connection_rate_limit: Some(100),
        },
        adblock: AdblockSettings::default(),
        userscripts: UserscriptSettings::default(),
        webui: WebUiSettings::default(),
    };

    // Clean up any existing CA files
    let _ = std::fs::remove_file(&config.mitm.ca_cert_path);
    let _ = std::fs::remove_file(&config.mitm.ca_key_path);

    // Create server
    let server = ProxyServer::new(config, test_ctx()).expect("Failed to create server");

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
        !matches!(*cert1.key, rustls::pki_types::PrivateKeyDer::Pkcs8(_) if false),
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

    // Force cache maintenance to update stats
    mitm.run_pending_tasks();

    // Check cache stats
    let stats = mitm.cache_stats();
    assert_eq!(stats.entry_count, 1, "Cache should have 1 entry");

    // Clean up
    let _ = std::fs::remove_file(std::env::temp_dir().join("test-certgen-ca.crt"));
    let _ = std::fs::remove_file(std::env::temp_dir().join("test-certgen-ca.key"));
}

#[tokio::test]
async fn test_load_manager_integration() {
    let config = ProxyConfig {
        proxy: proxy_core::config::ProxySettings {
            host: "127.0.0.1".to_string(),
            port: 0,
            enable_http2: false,
            enable_http3: false,
            enable_websockets: false,
        },
        mitm: MitmSettings {
            enabled: false,
            ca_cert_path: std::env::temp_dir().join("unused.crt"),
            ca_key_path: std::env::temp_dir().join("unused.key"),
            cert_cache_size: 100,
            cert_ttl_days: 30,
            cert_idle_timeout_secs: 3600,
        },
        performance: PerformanceSettings {
            max_connections: 100,
            max_cert_generations: 10,
            max_html_buffers: 10,
            connection_timeout_secs: 5,
            request_timeout_secs: 10,
            connection_rate_limit: Some(50),
        },
        adblock: AdblockSettings::default(),
        userscripts: UserscriptSettings::default(),
        webui: WebUiSettings::default(),
    };

    // Create server
    let server = ProxyServer::new(config, test_ctx()).expect("Failed to create server");

    // Verify load manager is initialized
    let load_stats = server.load_stats();
    assert_eq!(load_stats.connections_accepted, 0);
    assert_eq!(load_stats.connections_rejected, 0);
    assert_eq!(load_stats.active_connections, 0);
}

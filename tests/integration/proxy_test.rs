//! Integration tests for the proxy server

use proxy_core::config::{ProxyConfig, ProxySettings, MitmSettings, PerformanceSettings};
use proxy_core::server::ProxyServer;
use std::path::PathBuf;
use std::time::Duration;
use tokio::time::timeout;

#[tokio::test]
async fn test_server_starts() {
    // Create a test configuration with a random port
    let config = ProxyConfig {
        proxy: ProxySettings {
            host: "127.0.0.1".to_string(),
            port: 0, // Let OS assign a port
            max_connections: 100,
            enable_http2: false,
            enable_http3: false,
            enable_websockets: false,
        },
        mitm: MitmSettings {
            enabled: false,
            ca_cert_path: PathBuf::from("certs/test-ca.crt"),
            ca_key_path: PathBuf::from("certs/test-ca.key"),
            cert_cache_size: 10,
            cert_ttl_days: 1,
            cert_idle_timeout_secs: 60,
        },
        performance: PerformanceSettings {
            max_cert_generations: 5,
            max_html_buffers: 10,
            connection_timeout_secs: 5,
            request_timeout_secs: 10,
        },
    };

    // Note: This test just verifies the server can be created
    // Actually starting it would block forever
    let _server = ProxyServer::new(config).expect("Failed to create server");
}

#[test]
fn test_config_load() {
    // This test verifies that the default config file can be loaded
    let config_path = "config/default.toml";

    // Only run this test if the config file exists
    if std::path::Path::new(config_path).exists() {
        let config = ProxyConfig::from_file(config_path);
        assert!(config.is_ok(), "Failed to load config: {:?}", config.err());

        let config = config.unwrap();
        assert_eq!(config.proxy.port, 8080);
        assert_eq!(config.proxy.host, "0.0.0.0");
    }
}

#[tokio::test]
async fn test_server_with_http2_enabled() {
    let config = ProxyConfig {
        proxy: ProxySettings {
            host: "127.0.0.1".to_string(),
            port: 0,
            max_connections: 100,
            enable_http2: true,
            enable_http3: false,
            enable_websockets: false,
        },
        mitm: MitmSettings {
            enabled: false,
            ca_cert_path: PathBuf::from("certs/test-http2-ca.crt"),
            ca_key_path: PathBuf::from("certs/test-http2-ca.key"),
            cert_cache_size: 10,
            cert_ttl_days: 1,
            cert_idle_timeout_secs: 60,
        },
        performance: PerformanceSettings {
            max_cert_generations: 5,
            max_html_buffers: 10,
            connection_timeout_secs: 5,
            request_timeout_secs: 10,
        },
    };

    let _server = ProxyServer::new(config).expect("Failed to create server with HTTP/2");
}

#[tokio::test]
async fn test_server_with_mitm_enabled() {
    let temp_dir = std::env::temp_dir();
    let config = ProxyConfig {
        proxy: ProxySettings {
            host: "127.0.0.1".to_string(),
            port: 0,
            max_connections: 100,
            enable_http2: false,
            enable_http3: false,
            enable_websockets: false,
        },
        mitm: MitmSettings {
            enabled: true,
            ca_cert_path: temp_dir.join("integration-test-ca.crt"),
            ca_key_path: temp_dir.join("integration-test-ca.key"),
            cert_cache_size: 10,
            cert_ttl_days: 1,
            cert_idle_timeout_secs: 60,
        },
        performance: PerformanceSettings {
            max_cert_generations: 5,
            max_html_buffers: 10,
            connection_timeout_secs: 5,
            request_timeout_secs: 10,
        },
    };

    // Clean up any existing files
    let _ = std::fs::remove_file(&config.mitm.ca_cert_path);
    let _ = std::fs::remove_file(&config.mitm.ca_key_path);

    let server = ProxyServer::new(config.clone()).expect("Failed to create server with MITM");
    assert!(server.mitm_handler().is_some(), "MITM handler should be initialized");

    // Verify CA files were created
    assert!(config.mitm.ca_cert_path.exists(), "CA certificate should be created");
    assert!(config.mitm.ca_key_path.exists(), "CA private key should be created");

    // Clean up
    let _ = std::fs::remove_file(&config.mitm.ca_cert_path);
    let _ = std::fs::remove_file(&config.mitm.ca_key_path);
}

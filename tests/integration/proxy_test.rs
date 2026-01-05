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

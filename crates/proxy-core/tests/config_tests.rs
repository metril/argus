//! Configuration tests

use proxy_core::config::{
    AdblockSettings, MitmSettings, PerformanceSettings, ProxyConfig, ProxySettings,
    UserscriptSettings, WebUiSettings,
};
use std::path::PathBuf;

#[test]
fn test_default_config() {
    let config = ProxyConfig::default();

    // Test proxy settings
    assert_eq!(config.proxy.host, "0.0.0.0");
    assert_eq!(config.proxy.port, 8080);
    assert!(config.proxy.enable_http2);
    assert!(config.proxy.enable_websockets);

    // Test MITM settings
    assert!(config.mitm.enabled);
    assert_eq!(config.mitm.cert_cache_size, 1000);
    assert_eq!(config.mitm.cert_ttl_days, 30);
    assert_eq!(config.mitm.cert_idle_timeout_secs, 3600);

    // Test performance settings
    assert_eq!(config.performance.max_connections, 0);
    assert_eq!(config.performance.connection_rate_limit, Some(10_000));
    assert_eq!(config.performance.max_cert_generations, 10);
    assert_eq!(config.performance.max_html_buffers, 200);
    assert_eq!(config.performance.connection_timeout_secs, 30);
    assert_eq!(config.performance.request_timeout_secs, 60);
}

#[test]
fn test_config_serialization() {
    let config = ProxyConfig::default();

    // Serialize to TOML
    let toml_str = toml::to_string(&config).expect("Failed to serialize config");

    // Deserialize back
    let deserialized: ProxyConfig =
        toml::from_str(&toml_str).expect("Failed to deserialize config");

    // Verify values match
    assert_eq!(config.proxy.host, deserialized.proxy.host);
    assert_eq!(config.proxy.port, deserialized.proxy.port);
    assert_eq!(config.mitm.enabled, deserialized.mitm.enabled);
}

#[test]
fn test_custom_config() {
    let config = ProxyConfig {
        proxy: ProxySettings {
            host: "127.0.0.1".to_string(),
            port: 9090,
            enable_http2: false,
            transparent_port: None,
            ext_port: None,
            block_response: Default::default(),
            tls_passthrough_hosts: Vec::new(),
            block_private_destinations: false,
            allowed_destinations: Vec::new(),
            allowed_clients: proxy_core::config::default_allowed_clients(),
            enable_websockets: false,
            extra_upstream_ca_paths: Vec::new(),
            require_device_token: false,
            upstream: Default::default(),
            explicit: Default::default(),
            transparent: Default::default(),
        },
        mitm: MitmSettings {
            enabled: false,
            ca_cert_path: PathBuf::from("custom/cert.crt"),
            ca_key_path: PathBuf::from("custom/key.key"),
            cert_cache_size: 500,
            cert_ttl_days: 15,
            cert_idle_timeout_secs: 1800,
        },
        performance: PerformanceSettings {
            max_connections: 5000,
            max_cert_generations: 5,
            max_html_buffers: 100,
            connection_timeout_secs: 15,
            request_timeout_secs: 30,
            connection_rate_limit: Some(500),
        },
        adblock: AdblockSettings::default(),
        userscripts: UserscriptSettings::default(),
        script_control: Default::default(),
        webui: WebUiSettings::default(),
        dns: Default::default(),
        bypass: Default::default(),
        stealth: Default::default(),
        privacy: Default::default(),
    };

    assert_eq!(config.proxy.host, "127.0.0.1");
    assert_eq!(config.proxy.port, 9090);
    assert!(!config.mitm.enabled);
    assert_eq!(config.performance.max_connections, 5000);
    assert_eq!(config.performance.max_cert_generations, 5);
}

#[test]
fn test_config_from_toml_string() {
    let toml_str = r#"
[proxy]
host = "localhost"
port = 3128
enable_http2 = false
enable_websockets = true

[mitm]
enabled = true
ca_cert_path = "certs/ca.crt"
ca_key_path = "certs/ca.key"
cert_cache_size = 100
cert_ttl_days = 7
cert_idle_timeout_secs = 600

[performance]
max_connections = 1000
max_cert_generations = 20
max_html_buffers = 50
connection_timeout_secs = 45
request_timeout_secs = 90
    "#;

    let config: ProxyConfig = toml::from_str(toml_str).expect("Failed to parse TOML");

    assert_eq!(config.proxy.host, "localhost");
    assert_eq!(config.proxy.port, 3128);
    assert!(!config.proxy.enable_http2);
    assert!(config.mitm.enabled);
    assert_eq!(config.mitm.cert_cache_size, 100);
    assert_eq!(config.performance.max_connections, 1000);
    assert_eq!(config.performance.max_cert_generations, 20);
}

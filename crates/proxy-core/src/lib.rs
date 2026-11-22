//! Core proxy server implementation
//!
//! This crate provides the foundational MITM proxy functionality including:
//! - HTTP/1.1 and HTTP/2 support
//! - TLS interception and certificate generation
//! - Connection management (explicit proxy and transparent-gateway entry modes)
//! - Circuit breaker pattern for upstream failures
//! - Memory pressure monitoring and load shedding
//! - Unified load management for production hardening
//! - CA private key encryption at rest

pub mod authority;
pub mod ca;
pub mod ca_encryption;
pub mod circuit_breaker;
pub mod config;
pub mod connection;
pub mod csp;
pub mod error;
pub mod ext;
pub mod filtering;
pub mod http2;
pub mod inject;
pub mod internal;
pub mod load_manager;
pub mod memory_monitor;
pub mod mitm;
pub mod passthrough;
pub mod policy;
pub mod redirect;
pub mod request_ctx;
pub mod request_type;
pub mod rewrite;
pub mod server;
pub mod tls;
pub mod transparent;
pub mod upstream;
#[cfg(feature = "websockets")]
pub mod websocket;

pub use ca_encryption::{
    decrypt_ca_key, encrypt_ca_key, is_encrypted_key, read_encrypted_key, validate_passphrase,
    write_encrypted_key, CaEncryptionConfig,
};
pub use circuit_breaker::{CircuitBreaker, CircuitBreakerConfig, CircuitCheck, CircuitState};
pub use config::ProxyConfig;
pub use error::{Error, Result};
pub use filtering::ProxyContext;
pub use load_manager::{
    AdmissionResult, ConnectionGuard, LoadManager, LoadManagerConfig, LoadManagerStatsSnapshot,
    SharedLoadManager,
};
pub use memory_monitor::{LoadSheddingAction, MemoryMonitor, MemoryMonitorConfig, MemoryPressure};
pub use request_ctx::{Profile, ProfileSlot, RequestCtx};
pub use request_type::RequestType;
pub use server::ProxyServer;

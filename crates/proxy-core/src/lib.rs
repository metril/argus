//! Core proxy server implementation
//!
//! This crate provides the foundational MITM proxy functionality including:
//! - HTTP/1.1 and HTTP/2 support
//! - TLS interception and certificate generation
//! - Request/response pipeline
//! - Connection management

pub mod ca;
pub mod config;
pub mod connection;
pub mod error;
pub mod mitm;
pub mod pipeline;
pub mod server;

pub use config::ProxyConfig;
pub use error::{Error, Result};
pub use server::ProxyServer;

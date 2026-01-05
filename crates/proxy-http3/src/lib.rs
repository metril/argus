//! HTTP/3 and QUIC support for the proxy
//!
//! This module provides HTTP/3 protocol support using QUIC as the transport layer.
//! HTTP/3 is disabled by default and must be explicitly enabled in configuration.

pub mod error;
pub mod http3;
pub mod quic;

pub use error::{Error, Result};
pub use http3::Http3Server;
pub use quic::QuicConfig;

//! HTTP/3 and QUIC support for the proxy
//!
//! This module provides HTTP/3 protocol support using QUIC as the transport layer.
//! HTTP/3 is disabled by default and must be explicitly enabled in configuration.
//!
//! This module also provides WebSocket proxying capabilities.

pub mod error;
pub mod filter;
pub mod http3;
pub mod quic;

pub use error::{Error, Result};
pub use filter::Http3Filter;
pub use http3::Http3Server;
pub use quic::QuicConfig;

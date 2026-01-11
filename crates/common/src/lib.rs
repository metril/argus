//! Common utilities and types shared across all crates

pub mod config;
pub mod error;
pub mod types;

pub use config::{ConfigError, ProxyConfig};
pub use error::{Error, Result};

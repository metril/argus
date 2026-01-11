//! Proxy configuration
//!
//! Re-exports configuration types from the common crate.

pub use common::config::*;

// Add conversion from ConfigError to our Error type
impl From<common::ConfigError> for crate::Error {
    fn from(e: common::ConfigError) -> Self {
        crate::Error::Config(e.to_string())
    }
}

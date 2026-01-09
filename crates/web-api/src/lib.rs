//! Web API - RESTful API backend for the adblocker proxy
//!
//! Provides a secure, production-ready API for managing proxy configuration,
//! filter lists, userscripts, and monitoring.

pub mod auth;
pub mod config;
pub mod error;
pub mod handlers;
pub mod server;
pub mod state;

// Re-export commonly used items
pub use config::ApiConfig;
pub use error::{ApiError, ApiResult};
pub use server::{create_router, start_server};
pub use state::{build_state, AppState, ProxyState, ProxyStats};

//! Middleware modules
//!
//! Provides request/response middleware for:
//! - Rate limiting (multi-tier: global, per-IP, per-user)
//! - Request ID tracking
//! - Request logging

pub mod rate_limit;
pub mod request_id;

pub use rate_limit::rate_limit_middleware;
pub use request_id::request_id_middleware;

//! Middleware modules
//!
//! - request context (request id, real client address)
//! - rate limiting (global, per IP, strict for credential endpoints)
//! - audit logging

pub mod audit;
pub mod rate_limit;
pub mod request_id;

pub use audit::audit_middleware;
pub use rate_limit::rate_limit_middleware;
pub use request_id::{request_id_middleware, ClientInfo};

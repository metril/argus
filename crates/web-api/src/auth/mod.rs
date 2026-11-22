//! Authentication and authorization
//!
//! - bcrypt password hashing
//! - JWT access/refresh tokens in httpOnly cookies, tied to a persisted session
//! - personal access tokens (`Authorization: Bearer abk_...`)
//! - scope-based authorization declared per route (see [`authz`])
//! - CSRF protection for cookie sessions

pub mod authz;
pub mod csrf;
pub mod jwt;
pub mod middleware;
pub mod models;
pub mod password;
pub mod profile;
pub mod session;
pub mod tokens;

pub use authz::{Actor, Principal};
pub use jwt::{generate_access_token, generate_refresh_token, validate_token, TokenPair};
pub use models::{Claims, LoginRequest, RegisterRequest, User, UserRole};
pub use password::{hash_password, verify_password};
pub use profile::{ProfileParam, ProfileQuery};
pub use session::SessionManager;

//! Authentication module
//!
//! Provides secure authentication with:
//! - bcrypt password hashing (cost factor 12)
//! - JWT tokens with httpOnly cookies
//! - Session management with revocation
//! - Rate limiting per IP/username

pub mod jwt;
pub mod middleware;
pub mod models;
pub mod password;
pub mod session;

pub use jwt::{generate_access_token, generate_refresh_token, validate_token, TokenPair};
pub use middleware::auth_middleware;
pub use models::{Claims, LoginRequest, RegisterRequest, User, UserRole};
pub use password::{hash_password, verify_password};
pub use session::SessionManager;

//! Web API - RESTful API backend for the adblocker proxy
//!
//! Provides a secure, production-ready API for managing proxy configuration,
//! filter lists, userscripts, and monitoring.
//!
//! ## API Endpoints
//!
//! ### Health
//! - `GET /api/health` - Health check
//! - `GET /api/metrics` - System metrics
//!
//! ### Authentication
//! - `POST /api/auth/register` - Register new user
//! - `POST /api/auth/login` - Login
//! - `POST /api/auth/logout` - Logout (requires auth)
//! - `POST /api/auth/refresh` - Refresh access token
//! - `GET /api/auth/me` - Get current user (requires auth)
//! - `GET /api/auth/sessions` - List sessions (requires auth)
//! - `DELETE /api/auth/sessions/{id}` - Revoke session (requires auth)
//!
//! ### Proxy Management
//! - `GET /api/proxy/config` - Get configuration (requires auth)
//! - `PUT /api/proxy/config` - Update configuration (requires auth)
//! - `GET /api/proxy/stats` - Get statistics (requires auth)
//! - `POST /api/proxy/reload-config` - Reload from file (requires admin)
//!
//! ### Filter Lists
//! - `GET /api/filters/lists` - List filter lists (requires auth)
//! - `POST /api/filters/lists` - Add filter list (requires auth)
//! - `GET /api/filters/lists/{id}` - Get filter list (requires auth)
//! - `PUT /api/filters/lists/{id}` - Update filter list (requires auth)
//! - `DELETE /api/filters/lists/{id}` - Delete filter list (requires auth)
//! - `GET /api/filters/stats` - Get blocking stats (requires auth)
//! - `POST /api/filters/stats/reset` - Reset stats (requires admin)
//!
//! ### Userscripts
//! - `GET /api/userscripts` - List userscripts (requires auth)
//! - `POST /api/userscripts` - Install userscript (requires auth)
//! - `GET /api/userscripts/{id}` - Get userscript (requires auth)
//! - `GET /api/userscripts/{id}/source` - Get source code (requires auth)
//! - `PUT /api/userscripts/{id}` - Update userscript (requires auth)
//! - `DELETE /api/userscripts/{id}` - Uninstall userscript (requires auth)
//! - `PUT /api/userscripts/{id}/enabled` - Enable/disable (requires auth)
//! - `GET /api/userscripts/stats` - Get statistics (requires auth)

pub mod auth;
pub mod config;
pub mod error;
pub mod filter_service;
pub mod filter_store;
pub mod handlers;
pub mod middleware;
pub mod openapi;
pub mod server;
pub mod state;

// Re-export commonly used items
pub use config::ApiConfig;
pub use error::{ApiError, ApiResult};
pub use filter_service::{ensure_scriptlet_resources, reload_now, trigger_reload};
pub use filter_store::{open_filter_store, FilterListStore};
pub use openapi::ApiDoc;
pub use server::{create_router, start_server};
pub use state::{build_state, AppState, ProxyState, ProxyStats};

//! Web API - versioned REST control plane for the adblocker proxy.
//!
//! Everything lives under `/api/v1`; the OpenAPI document is served at
//! `/api/v1/openapi.json` and a docs UI at `/api/v1/docs`. Routes are registered through their
//! `#[utoipa::path]` declarations (see [`routes`]) and authorization is deny-by-default with
//! one scope declaration per route (see [`auth::authz`]). See `docs/API.md`.

pub mod audit;
pub mod auth;
pub mod config;
pub mod error;
pub mod handlers;
pub mod middleware;
pub mod openapi;
pub mod routes;
pub mod server;
pub mod state;
pub mod userscript_ops;

// Re-export commonly used items
pub use config::ApiConfig;
pub use error::{ApiError, ApiResult};
pub use list_service::{ListService, ListServiceConfig, ListStatus, ListStore};
pub use openapi::ApiDoc;
pub use server::{build_api, create_router, create_router_with, start_server};
pub use state::{
    build_state, build_state_full, build_state_with_policy, AppState, ProxyState, ProxyStats,
};

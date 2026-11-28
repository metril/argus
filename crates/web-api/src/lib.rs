//! Web API - versioned REST control plane for the argus proxy.
//!
//! Everything lives under `/api/v1`; the OpenAPI document is served at
//! `/api/v1/openapi.json` and a docs UI at `/api/v1/docs`. Routes are registered through their
//! `#[utoipa::path]` declarations (see [`routes`]) and authorization is deny-by-default with
//! one scope declaration per route (see [`auth::authz`]). See `docs/API.md`.

pub mod audit;
pub mod auth;
pub mod config;
pub mod daily;
pub mod error;
pub mod handlers;
pub mod middleware;
pub mod openapi;
pub mod routes;
pub mod rule_origin;
pub mod server;
pub mod state;
pub mod timeseries;
pub mod userscript_ops;
pub mod webui_tls;

// Re-export commonly used items
pub use api_types::{ExtAuditEvent, ExtError, ExtIdent, ExtOut};
pub use config::ApiConfig;
pub use error::{ApiError, ApiResult};
pub use list_service::{ListService, ListServiceConfig, ListStatus, ListStore};
pub use openapi::ApiDoc;
pub use server::{build_api, create_router, create_router_with, start_server, WebServer};
pub use state::{
    build_state, build_state_full, build_state_with_policy, AppState, ExtBridge, ListenerCounters,
    ProfileBuildInfo, ProfileRuntime, ProxyBind, ProxyState, ProxyStats, RuntimeControl,
};

//! Axum web server setup and routing

use axum::{
    middleware,
    routing::{delete, get, post},
    Router,
};
use std::sync::Arc;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

use crate::auth::middleware::auth_middleware;
use crate::config::ApiConfig;
use crate::handlers;
use crate::middleware::{rate_limit_middleware, request_id_middleware};
use crate::state::AppState;

/// Create the Axum router with all routes and middleware
pub fn create_router(state: Arc<AppState>, _config: &ApiConfig) -> Router {
    // Build CORS layer
    let cors = CorsLayer::new()
        .allow_origin(Any) // TODO: Configure from config.security.cors_origins
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_credentials(true);

    // Public auth routes (no authentication required)
    let public_auth_routes = Router::new()
        .route("/register", post(handlers::auth::register))
        .route("/login", post(handlers::auth::login))
        .route("/refresh", post(handlers::auth::refresh));

    // Protected auth routes (authentication required)
    let protected_auth_routes = Router::new()
        .route("/logout", post(handlers::auth::logout))
        .route("/me", get(handlers::auth::me))
        .route("/sessions", get(handlers::auth::list_sessions))
        .route("/sessions/{session_id}", delete(handlers::auth::revoke_session))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware));

    // Combine auth routes
    let auth_router = Router::new()
        .merge(public_auth_routes)
        .merge(protected_auth_routes)
        .with_state(state.clone());

    // Health routes (public)
    let health_router = Router::new()
        .route("/health", get(handlers::health::health_check))
        .route("/metrics", get(handlers::health::metrics))
        .with_state(state.clone());

    // Build the main router with global middleware
    // Layers are applied bottom-to-top (last added = outermost)
    Router::new()
        .nest("/api/auth", auth_router)
        .nest("/api", health_router)
        // Innermost: CORS (handles preflight)
        .layer(cors)
        // TraceLayer for request/response logging
        .layer(TraceLayer::new_for_http())
        // Rate limiting
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        // Outermost: Request ID (ensures all logs have request ID)
        .layer(middleware::from_fn(request_id_middleware))
}

/// Start the web server
pub async fn start_server(
    state: Arc<AppState>,
    config: ApiConfig,
) -> crate::error::ApiResult<()> {
    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    tracing::info!("Web API server listening on {}", addr);

    let router = create_router(state, &config);

    axum::serve(listener, router)
        .await
        .map_err(|e| crate::error::ApiError::Internal(e.to_string()))?;

    Ok(())
}

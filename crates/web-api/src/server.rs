//! Axum web server setup and routing

use axum::{
    routing::get,
    Router,
};
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::{
    cors::{CorsLayer, Any},
    trace::TraceLayer,
};

use crate::config::ApiConfig;
use crate::handlers;
use crate::state::AppState;

/// Create the Axum router with all routes and middleware
pub fn create_router(state: Arc<AppState>, config: &ApiConfig) -> Router {
    // Build CORS layer
    let cors = CorsLayer::new()
        .allow_origin(Any) // TODO: Configure from config.security.cors_origins
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_credentials(true);

    // Build the API router
    let api_router = Router::new()
        .route("/health", get(handlers::health::health_check))
        .route("/metrics", get(handlers::health::metrics))
        .with_state(state.clone());

    // Build the main router
    Router::new()
        .nest("/api", api_router)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(cors),
        )
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

//! Axum web server setup and routing

use axum::{
    middleware,
    routing::{delete, get, post, put},
    Router,
};
use std::sync::Arc;
use axum::http::{header, HeaderValue, Method};
use tower_http::{
    cors::CorsLayer,
    trace::TraceLayer,
};

use crate::auth::middleware::auth_middleware;
use crate::config::ApiConfig;
use crate::handlers;
use crate::middleware::{rate_limit_middleware, request_id_middleware};
use crate::state::AppState;

/// Create the Axum router with all routes and middleware
pub fn create_router(state: Arc<AppState>, config: &ApiConfig) -> Router {
    // Build CORS layer from configuration
    // Note: Cannot use `Any` with `allow_credentials(true)`, so we specify allowed values
    let cors = build_cors_layer(&config.security.cors_origins);

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

    // Proxy management routes (protected)
    let proxy_router = Router::new()
        .route("/config", get(handlers::proxy::get_config).put(handlers::proxy::update_config))
        .route("/stats", get(handlers::proxy::get_stats))
        .route("/reload-config", post(handlers::proxy::reload_config))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state.clone());

    // Filter management routes (protected)
    let filters_router = Router::new()
        .route("/lists", get(handlers::filters::list_filter_lists).post(handlers::filters::add_filter_list))
        .route("/lists/{id}", get(handlers::filters::get_filter_list)
            .put(handlers::filters::update_filter_list)
            .delete(handlers::filters::delete_filter_list))
        .route("/stats", get(handlers::filters::get_stats))
        .route("/stats/reset", post(handlers::filters::reset_stats))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state.clone());

    // Userscript management routes (protected)
    let userscripts_router = Router::new()
        .route("/", get(handlers::userscripts::list_userscripts).post(handlers::userscripts::install_userscript))
        .route("/stats", get(handlers::userscripts::get_stats))
        .route("/{id}", get(handlers::userscripts::get_userscript)
            .put(handlers::userscripts::update_userscript)
            .delete(handlers::userscripts::uninstall_userscript))
        .route("/{id}/source", get(handlers::userscripts::get_userscript_source))
        .route("/{id}/enabled", put(handlers::userscripts::set_enabled))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state.clone());

    // Build the main router with global middleware
    // Layers are applied bottom-to-top (last added = outermost)
    Router::new()
        .nest("/api/auth", auth_router)
        .nest("/api/proxy", proxy_router)
        .nest("/api/filters", filters_router)
        .nest("/api/userscripts", userscripts_router)
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

/// Build CORS layer from configuration
///
/// SECURITY: Uses explicit origin allowlist instead of wildcard.
/// Cannot use `Any` with `allow_credentials(true)`.
fn build_cors_layer(origins: &[String]) -> CorsLayer {
    use tower_http::cors::AllowOrigin;

    // Build list of allowed origins
    let allowed_origins: Vec<HeaderValue> = origins
        .iter()
        .filter_map(|origin| origin.parse::<HeaderValue>().ok())
        .collect();

    // Fallback to development origin if none configured
    let origins = if allowed_origins.is_empty() {
        tracing::warn!("No CORS origins configured, using localhost:5173 default");
        vec!["http://localhost:5173".parse::<HeaderValue>().unwrap()]
    } else {
        allowed_origins
    };

    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::ACCEPT,
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::COOKIE,
        ])
        .allow_credentials(true)
        .max_age(std::time::Duration::from_secs(3600)) // Cache preflight for 1 hour
}

//! Axum web server setup: the versioned API, docs UI, static web UI and global middleware.

use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::{
    extract::Request, middleware, middleware::Next, response::Response, routing::any, Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::{
    cors::CorsLayer,
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};
use utoipa_axum::router::OpenApiRouter;
use utoipa_swagger_ui::{Config, SwaggerUi};

use crate::auth::authz::authorize;
use crate::config::ApiConfig;
use crate::error::{envelope, ApiError};
use crate::middleware::{audit_middleware, rate_limit_middleware, request_id_middleware};
use crate::openapi::{finalize, ApiDoc};
use crate::routes::{api_router, API_PREFIX};
use crate::state::AppState;

/// Build the OpenAPI document and route table for an assembled router. Exposed so tests can
/// exercise registration of arbitrary routers.
pub fn build_api(
    router: OpenApiRouter<Arc<AppState>>,
) -> (
    Router<Arc<AppState>>,
    serde_json::Value,
    crate::auth::authz::RouteTable,
) {
    let (router, spec) = OpenApiRouter::with_openapi(<ApiDoc as utoipa::OpenApi>::openapi())
        .nest(API_PREFIX, router)
        .split_for_parts();
    let (doc, table) = finalize(spec);
    (router, doc, table)
}

async fn api_not_found() -> ApiError {
    ApiError::NotFound("No such API route".into())
}

/// Give bodiless 405s the standard error envelope.
async fn normalize_errors(req: Request, next: Next) -> Response {
    let resp = next.run(req).await;
    if resp.status() == StatusCode::METHOD_NOT_ALLOWED
        && !resp.headers().contains_key(header::CONTENT_TYPE)
    {
        let allow = resp.headers().get(header::ALLOW).cloned();
        let mut r = envelope(
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "Method not allowed",
        );
        if let Some(a) = allow {
            r.headers_mut().insert(header::ALLOW, a);
        }
        return r;
    }
    resp
}

/// Create the Axum router with all routes and middleware
pub fn create_router(state: Arc<AppState>, config: &ApiConfig) -> Router {
    create_router_with(state, config, api_router())
}

/// [`create_router`] over an explicit route set (tests add routes to prove deny-by-default).
pub fn create_router_with(
    state: Arc<AppState>,
    config: &ApiConfig,
    api: OpenApiRouter<Arc<AppState>>,
) -> Router {
    let (routes, doc, table) = build_api(api);
    if !table.undeclared.is_empty() || !table.invalid.is_empty() {
        tracing::error!(
            "Routes without a valid authorization declaration (denied by default): {:?} {:?}",
            table.undeclared,
            table.invalid
        );
    }
    let _ = state.spec_json.set(doc.to_string());
    let _ = state.route_auth.set(table);

    // Authorization is a `route_layer`: it only runs for matched routes and sees `MatchedPath`.
    let api = routes
        .route_layer(middleware::from_fn_with_state(state.clone(), authorize))
        .with_state(state.clone());

    let docs: Router = SwaggerUi::new(format!("{API_PREFIX}/docs"))
        .config(Config::from(format!("{API_PREFIX}/openapi.json")))
        .into();

    let mut router = Router::new()
        .merge(api)
        .merge(docs)
        .route("/api/{*rest}", any(api_not_found));

    if config.webui.enabled {
        let dist_path = &config.webui.dist_path;
        if dist_path.exists() {
            let index_file = dist_path.join("index.html");
            let serve_dir = ServeDir::new(dist_path).not_found_service(ServeFile::new(&index_file));
            router = router.fallback_service(serve_dir);
            tracing::info!("WebUI static files enabled from {:?}", dist_path);
        } else {
            tracing::warn!(
                "WebUI dist path {:?} does not exist, static files disabled",
                dist_path
            );
        }
    }

    // Layers: last added = outermost.
    if let Some(cors) = build_cors_layer(&config.security.cors_origins) {
        router = router.layer(cors);
    }
    router
        .layer(middleware::from_fn_with_state(
            state.clone(),
            audit_middleware,
        ))
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .layer(middleware::from_fn(normalize_errors))
        .layer(middleware::from_fn_with_state(state, request_id_middleware))
}

/// Start the web server
pub async fn start_server(state: Arc<AppState>, config: ApiConfig) -> crate::error::ApiResult<()> {
    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Web API server listening on {}", addr);
    warn_if_exposed_without_tls(&config);

    let sessions = state.session_manager.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            tick.tick().await;
            let s = sessions.clone();
            match tokio::task::spawn_blocking(move || s.purge_expired()).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => tracing::warn!("session purge failed: {e}"),
                Err(e) => tracing::warn!("session purge task failed: {e}"),
            }
        }
    });

    let router = create_router(state, &config);
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(())
}

/// The server speaks plain HTTP. Bound beyond loopback, logins and session cookies cross the
/// network in clear unless a TLS-terminating reverse proxy sits in front. Logged once at startup.
fn warn_if_exposed_without_tls(config: &ApiConfig) {
    let host = config.server.host.trim_matches(['[', ']']);
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if !loopback {
        tracing::warn!(
            "Web UI is bound to {host} without TLS: passwords and session cookies are sent in \
             clear text. Put a TLS-terminating reverse proxy in front (and list it under \
             network.trusted_proxies so cookies get the Secure flag) or bind to 127.0.0.1."
        );
    }
}

/// CORS: same-origin only unless origins are allowlisted (then credentials are allowed for
/// exactly those origins).
fn build_cors_layer(origins: &[String]) -> Option<CorsLayer> {
    use tower_http::cors::AllowOrigin;

    let allowed: Vec<HeaderValue> = origins
        .iter()
        .filter_map(|o| o.parse::<HeaderValue>().ok())
        .collect();
    if allowed.is_empty() {
        return None;
    }
    Some(
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(allowed))
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::PATCH,
                Method::DELETE,
                Method::OPTIONS,
            ])
            .allow_headers([
                header::ACCEPT,
                header::AUTHORIZATION,
                header::CONTENT_TYPE,
                header::IF_MATCH,
                header::HeaderName::from_static("x-csrf-token"),
                header::HeaderName::from_static("x-request-id"),
            ])
            .expose_headers([
                header::ETAG,
                header::HeaderName::from_static("x-request-id"),
            ])
            .allow_credentials(true)
            .max_age(std::time::Duration::from_secs(3600)),
    )
}

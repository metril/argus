//! OpenAPI documentation
//!
//! Provides API documentation. Full utoipa integration can be added later.
//! For now, see lib.rs for complete API endpoint documentation.

use crate::auth::models::{LoginRequest, LoginResponse, RegisterRequest, UserInfo, UserRole};
use crate::handlers::proxy::{ProxyConfigResponse, UpdateProxyConfigResponse};
use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
use utoipa::{Modify, OpenApi};

/// API documentation
///
/// This generates an OpenAPI 3.0 specification for the Adblocker Proxy API.
/// See the lib.rs module documentation for complete endpoint reference.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Adblocker Proxy API",
        version = "0.1.0",
        description = r#"
RESTful API for managing the adblocker proxy, filter lists, and userscripts.

## Authentication

Authentication is handled via JWT tokens stored in httpOnly cookies:
- `access_token`: Short-lived (15 min) token for API access
- `refresh_token`: Long-lived (7 days) token for obtaining new access tokens

The first registered user automatically becomes an admin.

## Endpoints

See /api/health for health check.
See lib.rs documentation for complete endpoint reference.
"#,
        license(name = "MIT"),
    ),
    servers(
        (url = "http://localhost:3000", description = "Local development server")
    ),
    paths(
        crate::handlers::health::health_check,
        crate::handlers::health::metrics,
    ),
    components(
        schemas(
            UserRole,
            UserInfo,
            LoginRequest,
            LoginResponse,
            RegisterRequest,
            ProxyConfigResponse,
            UpdateProxyConfigResponse,
        )
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "health", description = "Health check and metrics endpoints"),
        (name = "auth", description = "Authentication and session management"),
        (name = "proxy", description = "Proxy configuration and statistics"),
        (name = "filters", description = "Filter list management"),
        (name = "userscripts", description = "Userscript management")
    )
)]
pub struct ApiDoc;

/// Security scheme modifier
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "cookie_auth",
                SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::new("access_token"))),
            );
        }
    }
}

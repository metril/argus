//! OpenAPI document: base metadata plus the post-processing that turns each operation's single
//! `security(...)` declaration into the published security requirements.
//!
//! Handlers register through `utoipa_axum::routes!`, so a route and its documentation are the same
//! declaration and the spec cannot drift from the router.

use api_types::{ErrorEnvelope, Scope};
use serde_json::{json, Map, Value};
use utoipa::OpenApi;

use crate::auth::authz::RouteTable;

/// Base document; paths are added by the router.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Argus Proxy API",
        version = "1.0.0",
        description = "Control-plane API of the argus proxy. Authenticate with a session cookie or \
`Authorization: Bearer abk_<id>_<secret>`. Every operation lists the scope it requires.",
        license(name = "Proprietary"),
    ),
    components(schemas(ErrorEnvelope, Scope)),
    tags(
        (name = "auth", description = "Login, session cookies, password"),
        (name = "sessions", description = "Session listing and revocation"),
        (name = "users", description = "User accounts"),
        (name = "tokens", description = "Personal API tokens"),
        (name = "lists", description = "Filter lists, refresh and schedule"),
        (name = "rules", description = "Custom rules, validation and URL tests"),
        (name = "engine", description = "Blocking engine rebuilds"),
        (name = "stats", description = "Statistics"),
        (name = "config", description = "Proxy configuration"),
        (name = "ca", description = "CA certificate"),
        (name = "certs", description = "Real upstream server certificates seen by the proxy"),
        (name = "userscripts", description = "Userscripts"),
        (name = "policy", description = "Script policy (NoScript-style per-site capabilities)"),
        (name = "profiles", description = "Per-device filtering profiles"),
        (name = "devices", description = "Devices and their tokens"),
        (name = "audit", description = "Audit log"),
        (name = "system", description = "Health, status, metrics, this document"),
    )
)]
pub struct ApiDoc;

fn error_response(description: &str) -> Value {
    json!({
        "description": description,
        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorEnvelope"}}}
    })
}

/// Finalize the generated document: expand security declarations, add the shared error responses
/// and security schemes, and derive the enforcement [`RouteTable`] from the result.
pub fn finalize(spec: utoipa::openapi::OpenApi) -> (Value, RouteTable) {
    let mut doc = serde_json::to_value(&spec).expect("OpenAPI serializes");
    // Read the declarations first (before expansion).
    let table = RouteTable::from_spec(&doc);

    if let Some(paths) = doc.get_mut("paths").and_then(Value::as_object_mut) {
        for item in paths.values_mut().filter_map(Value::as_object_mut) {
            for (method, op) in item.iter_mut() {
                let Some(op) = op.as_object_mut() else {
                    continue;
                };
                let _ = method;
                let public = op
                    .get("security")
                    .and_then(Value::as_array)
                    .is_some_and(|s| s.iter().any(|r| r.as_object().is_some_and(Map::is_empty)));
                let scopes: Vec<Value> = op
                    .get("security")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .flat_map(|r| r.as_object().into_iter().flat_map(|o| o.values()))
                    .flat_map(|v| v.as_array().cloned().unwrap_or_default())
                    .collect();
                if op.contains_key("security") && !public {
                    // One declaration, two accepted credentials.
                    op.insert(
                        "security".into(),
                        json!([{"bearer_auth": scopes}, {"cookie_auth": scopes}]),
                    );
                }
                let responses = op
                    .entry("responses")
                    .or_insert_with(|| json!({}))
                    .as_object_mut()
                    .expect("responses is an object");
                let mut add = |code: &str, desc: &str| {
                    responses
                        .entry(code.to_string())
                        .or_insert_with(|| error_response(desc));
                };
                if !public {
                    add("401", "Missing, invalid, expired or revoked credentials");
                    add("403", "Missing scope, or CSRF check failed");
                }
                add("429", "Rate limit exceeded");
                add("500", "Internal error");
            }
        }
    }

    let scope_docs: Map<String, Value> = Scope::ALL
        .iter()
        .map(|s| (s.as_str().to_string(), json!(s.description())))
        .collect();
    let components = doc
        .as_object_mut()
        .expect("document is an object")
        .entry("components")
        .or_insert_with(|| json!({}));
    components["securitySchemes"] = json!({
        "bearer_auth": {
            "type": "http",
            "scheme": "bearer",
            "description": "Personal API token: `Authorization: Bearer abk_<id>_<secret>`. \
    Create one with POST /tokens. Per-operation scopes are listed in `x-scopes`."
        },
        "cookie_auth": {
            "type": "apiKey",
            "in": "cookie",
            "name": "access_token",
            "description": "Session cookie from POST /auth/login. Unsafe methods must also send \
    the `X-CSRF-Token` header (value of the `csrf_token` cookie)."
        }
    });
    components["x-scopes"] = Value::Object(scope_docs);
    doc["servers"] = json!([{"url": "/", "description": "This server"}]);
    (doc, table)
}

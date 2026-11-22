//! Audit logging: every state-changing call (and every authorization denial) is recorded with
//! who, what, when, from where and the outcome. Bodies, cookies and credentials are never read.

use api_types::AuditEntry;
use axum::{
    extract::{Request, State},
    http::Method,
    middleware::Next,
    response::Response,
};
use chrono::Utc;
use std::sync::Arc;

use super::request_id::ClientInfo;
use crate::auth::authz::{Actor, AuditActor, AuditMeta};
use crate::state::AppState;

/// First path parameter's actual value, found by aligning the route template with the path.
fn target_of(template: &str, path: &str) -> Option<String> {
    template
        .split('/')
        .zip(path.split('/'))
        .filter(|(t, _)| t.starts_with('{') && t.ends_with('}'))
        .map(|(_, v)| v.to_string())
        .last()
}

pub async fn audit_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let client = req.extensions().get::<ClientInfo>().cloned();

    let response = next.run(req).await;

    let status = response.status().as_u16();
    let meta = response.extensions().get::<AuditMeta>().cloned();
    let unsafe_method = !matches!(method, Method::GET | Method::HEAD | Method::OPTIONS);
    let Some(meta) = meta else { return response };
    if meta.route.is_empty() || !(unsafe_method || status == 403) {
        return response;
    }

    let named = response.extensions().get::<AuditActor>().cloned();
    let (actor_type, actor_id, actor_name) = match (&meta.principal, named) {
        (Some(p), _) => match &p.actor {
            Actor::Token { token_id } => {
                ("token", Some(token_id.clone()), Some(p.username.clone()))
            }
            Actor::Session { .. } => (
                "user",
                Some(p.user_id.to_string()),
                Some(p.username.clone()),
            ),
        },
        (None, Some(a)) => ("user", a.id, Some(a.name)),
        (None, None) => ("anonymous", None, None),
    };
    let entry = AuditEntry {
        id: String::new(),
        at: Utc::now().to_rfc3339(),
        actor_type: actor_type.to_string(),
        actor_id,
        actor_name,
        method: method.to_string(),
        target: target_of(&meta.route, &path),
        route: meta.route,
        scope: meta.required,
        status,
        outcome: match status {
            200..=399 => "success",
            401 | 403 | 429 => "denied",
            _ => "error",
        }
        .to_string(),
        ip: client.as_ref().and_then(|c| c.ip).map(|ip| ip.to_string()),
        user_agent: client.as_ref().and_then(|c| c.user_agent.clone()),
        request_id: client.map(|c| c.request_id),
    };
    if let Err(e) = state.audit.append(entry) {
        tracing::error!("Failed to write audit entry: {e}");
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_target_from_template() {
        assert_eq!(
            target_of(
                "/api/v1/lists/{id}/refresh",
                "/api/v1/lists/easylist/refresh"
            ),
            Some("easylist".into())
        );
        assert_eq!(target_of("/api/v1/lists", "/api/v1/lists"), None);
    }
}

//! "Automatically updated" guarantees: spec drift, route coverage, the authorization matrix,
//! token escalation, CSRF and immediate revocation.

mod common;

use api_types::Scope;
use axum::http::StatusCode;
use common::{TestContext, PASSWORD};
use cookie::Cookie;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use utoipa_axum::routes;
use web_api::auth::authz::{RouteAuth, RouteTable};
use web_api::routes::api_router;

fn docs_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs")
        .join(name)
}

fn update_requested() -> bool {
    std::env::var("UPDATE_OPENAPI").is_ok_and(|v| v != "0" && !v.is_empty())
}

/// Compare `actual` with the committed file, or rewrite it when `UPDATE_OPENAPI=1`.
fn assert_snapshot(name: &str, actual: &str) {
    let path = docs_path(name);
    if update_requested() {
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        expected == actual,
        "docs/{name} is out of date. Regenerate with: UPDATE_OPENAPI=1 cargo test -p web-api --test security_tests"
    );
}

fn spec() -> (Value, RouteTable) {
    let (_, doc, table) = web_api::build_api(api_router());
    (doc, table)
}

// ------------------------------------------------------------------ (a) spec drift

#[test]
fn openapi_snapshot_matches_generated_spec() {
    let (doc, _) = spec();
    let mut text = serde_json::to_string_pretty(&doc).unwrap();
    text.push('\n');
    assert_snapshot("openapi.json", &text);
}

#[test]
fn api_md_scope_table_is_generated_from_the_enum() {
    let path = docs_path("API.md");
    let current = std::fs::read_to_string(&path).expect("docs/API.md exists");
    let (start, end) = ("<!-- scopes:start -->\n", "<!-- scopes:end -->");
    let a = current.find(start).expect("start marker") + start.len();
    let b = current.find(end).expect("end marker");
    let regenerated = format!(
        "{}{}{}",
        &current[..a],
        api_types::scope_table_markdown(),
        &current[b..]
    );
    assert_snapshot("API.md", &regenerated);
}

// ------------------------------------------------------------------ (b) route coverage

/// Walk the real axum route table (parsed from the router's Debug form) as `(METHOD, path)`.
fn router_routes(router: &axum::Router) -> BTreeSet<(String, String)> {
    let dbg = format!("{router:?}");
    let path_re = regex::Regex::new(r#"RouteId\((\d+)\): "([^"]+)""#).unwrap();
    // The router prints its path table once under `node:`; keep the first mapping per id.
    let node = dbg.find("node:").map_or(0, |i| i);
    let mut paths: BTreeMap<String, String> = BTreeMap::new();
    for c in path_re.captures_iter(&dbg[node..]) {
        paths
            .entry(c[1].to_string())
            .or_insert_with(|| c[2].to_string());
    }
    let route_re = regex::Regex::new(
        r"RouteId\((\d+)\): MethodRouter\(MethodRouter \{ get: (\w+), head: \w+, delete: (\w+), options: (\w+), patch: (\w+), post: (\w+), put: (\w+),",
    )
    .unwrap();
    let mut out = BTreeSet::new();
    for c in route_re.captures_iter(&dbg) {
        let Some(path) = paths.get(&c[1]) else {
            continue;
        };
        for (i, m) in ["GET", "DELETE", "OPTIONS", "PATCH", "POST", "PUT"]
            .iter()
            .enumerate()
        {
            if &c[i + 2] != "None" {
                out.insert((m.to_string(), path.clone()));
            }
        }
    }
    out
}

fn spec_ops(doc: &Value) -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    for (path, item) in doc["paths"].as_object().unwrap() {
        for (m, _) in item.as_object().unwrap() {
            out.insert((m.to_uppercase(), path.clone()));
        }
    }
    out
}

#[tokio::test]
async fn every_router_route_is_in_the_spec_with_a_scope_or_public_marker() {
    let ctx = TestContext::new().await.unwrap();
    let (doc, table) = spec();
    assert!(
        table.undeclared.is_empty(),
        "routes lacking `security(...)`: {:?}",
        table.undeclared
    );
    assert!(
        table.invalid.is_empty(),
        "unknown scopes: {:?}",
        table.invalid
    );

    // The docs UI, the /api catch-all and the static web-UI fallback are outside the spec.
    let outside = |p: &str| {
        p.starts_with("/api/v1/docs")
            || p == "/api/{*rest}"
            || p == "/"
            || p.contains("axum_fallback")
    };
    let actual: BTreeSet<_> = router_routes(&ctx.router)
        .into_iter()
        .filter(|(_, p)| !outside(p))
        .collect();
    let documented = spec_ops(&doc);
    assert!(!actual.is_empty());
    assert_eq!(
        actual.difference(&documented).collect::<Vec<_>>(),
        Vec::<&(String, String)>::new(),
        "routes missing from the spec"
    );
    assert_eq!(
        documented.difference(&actual).collect::<Vec<_>>(),
        Vec::<&(String, String)>::new(),
        "spec operations with no route"
    );
    for (m, p) in &actual {
        assert!(
            table.get(m, p).is_some(),
            "{m} {p} has no scope/public declaration"
        );
    }
}

// Registered through `routes!` like every real route, but without a `security(...)` declaration.
#[utoipa::path(get, path = "/undeclared", tag = "test", responses((status = 200, description = "x")))]
async fn undeclared_handler() -> &'static str {
    "secret"
}

#[tokio::test]
async fn route_without_declaration_is_detected_and_denied() {
    let (_, _, table) = web_api::build_api(api_router().routes(routes!(undeclared_handler)));
    assert_eq!(table.undeclared, vec!["GET /api/v1/undeclared".to_string()]);

    let ctx = TestContext::new().await.unwrap();
    let router = web_api::create_router_with(
        ctx.state.clone(),
        &ctx.api_config,
        api_router().routes(routes!(undeclared_handler)),
    );
    let server = axum_test::TestServer::new(router).unwrap();
    // Even a fully privileged caller is refused: deny by default.
    let admin = ctx.admin().await;
    let r = server
        .get("/api/v1/undeclared")
        .add_cookie(Cookie::new("access_token", admin.access.clone()))
        .await;
    assert_eq!(r.status_code(), StatusCode::FORBIDDEN);
    assert_eq!(
        server.get("/api/v1/undeclared").await.status_code(),
        StatusCode::FORBIDDEN
    );
}

#[test]
fn spec_documents_security_errors_and_relative_server() {
    let (doc, table) = spec();
    assert_eq!(doc["servers"][0]["url"], "/");
    let mut ids = BTreeSet::new();
    for (path, item) in doc["paths"].as_object().unwrap() {
        for (m, op) in item.as_object().unwrap() {
            assert!(
                ids.insert(op["operationId"].as_str().unwrap().to_string()),
                "duplicate operationId at {m} {path}"
            );
            let public = matches!(table.get(&m.to_uppercase(), path), Some(RouteAuth::Public));
            if public {
                assert!(op["responses"].get("401").is_none(), "{m} {path}");
            } else {
                let sec = op["security"].as_array().unwrap();
                assert_eq!(sec.len(), 2, "{m} {path} accepts bearer and cookie");
                assert_eq!(
                    op["responses"]["401"]["content"]["application/json"]["schema"]["$ref"],
                    "#/components/schemas/ErrorEnvelope"
                );
                assert!(op["responses"].get("403").is_some());
            }
        }
    }
    assert!(doc["components"]["securitySchemes"]["bearer_auth"].is_object());
    assert_eq!(
        doc["components"]["x-scopes"].as_object().unwrap().len(),
        Scope::ALL.len()
    );
}

// ------------------------------------------------------------------ (c) authorization matrix

fn fill_path(path: &str) -> String {
    let mut p = path.to_string();
    while let (Some(a), Some(b)) = (p.find('{'), p.find('}')) {
        p.replace_range(a..=b, "00000000-0000-0000-0000-000000000000");
    }
    p
}

async fn send(ctx: &TestContext, method: &str, path: &str, secret: Option<&str>) -> StatusCode {
    let req = match method {
        "GET" => ctx.server.get(path),
        "POST" => ctx.server.post(path),
        "PUT" => ctx.server.put(path),
        "PATCH" => ctx.server.patch(path),
        "DELETE" => ctx.server.delete(path),
        m => panic!("method {m}"),
    };
    let req = match secret {
        Some(s) => req.authorization_bearer(s),
        None => req,
    };
    let req = if matches!(method, "POST" | "PUT" | "PATCH") {
        req.json(&json!({}))
    } else {
        req
    };
    // An authorized event stream never finishes; a request still open after a moment passed
    // authorization and is streaming.
    match tokio::time::timeout(std::time::Duration::from_secs(3), req).await {
        Ok(r) => r.status_code(),
        Err(_) if path.ends_with("/logs/stream") => StatusCode::OK,
        Err(_) => panic!("{method} {path} timed out"),
    }
}

#[tokio::test]
async fn authorization_matrix_generated_from_the_spec() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    // Read the spec the server actually publishes.
    let doc: Value = ctx.server.get("/api/v1/openapi.json").await.json();
    let table = RouteTable::from_spec(&doc);

    let all: Vec<&str> = Scope::ALL.iter().map(|s| s.as_str()).collect();
    let mut checked = 0usize;
    for ((method, path), auth) in table.iter() {
        let url = fill_path(path);
        match auth {
            RouteAuth::Public => {
                // Reachable without credentials: never refused by the authorizer.
                let s = send(&ctx, method, &url, None).await;
                assert_ne!(s, StatusCode::FORBIDDEN, "{method} {path} (public)");
            }
            RouteAuth::Authenticated | RouteAuth::Scopes(_) => {
                // 1. no credentials -> 401
                assert_eq!(
                    send(&ctx, method, &url, None).await,
                    StatusCode::UNAUTHORIZED,
                    "{method} {path} without credentials"
                );
                if let RouteAuth::Scopes(required) = auth {
                    // 2. every scope except the required one(s) -> 403
                    let others: Vec<&str> = all
                        .iter()
                        .copied()
                        .filter(|s| !required.iter().any(|r| r.as_str() == *s))
                        .collect();
                    let secret = ctx.token(&admin, &others).await;
                    assert_eq!(
                        send(&ctx, method, &url, Some(&secret)).await,
                        StatusCode::FORBIDDEN,
                        "{method} {path} with all scopes but {required:?}"
                    );
                    // 3. exactly the required scope(s) -> not 401/403
                    let exact: Vec<&str> = required.iter().map(|s| s.as_str()).collect();
                    let secret = ctx.token(&admin, &exact).await;
                    let s = send(&ctx, method, &url, Some(&secret)).await;
                    assert!(
                        s != StatusCode::UNAUTHORIZED && s != StatusCode::FORBIDDEN,
                        "{method} {path} with exactly {exact:?} got {s}"
                    );
                } else {
                    // Any authenticated principal passes.
                    let secret = ctx.token(&admin, &["lists:read"]).await;
                    let s = send(&ctx, method, &url, Some(&secret)).await;
                    assert!(
                        s != StatusCode::UNAUTHORIZED && s != StatusCode::FORBIDDEN,
                        "{method} {path}"
                    );
                }
            }
        }
        checked += 1;
    }
    assert_eq!(checked, table.len());
    assert!(checked >= 50, "matrix covered only {checked} operations");
    println!("authorization matrix covered {checked} operations");
}

// ------------------------------------------------------------------ (d) escalation

#[tokio::test]
async fn token_scopes_cannot_exceed_the_creator() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let bob = ctx.user(&admin, "bob_user", "user").await;

    // A user may mint what the role grants...
    let secret = ctx.token(&bob, &["lists:read", "tokens:self"]).await;
    // ...but not what it lacks.
    for scope in ["config:write", "users:admin", "audit:read"] {
        let r = bob
            .post("/api/v1/tokens")
            .json(&json!({"name": "x", "scopes": [scope]}))
            .await;
        r.assert_status_forbidden();
        assert_eq!(r.json::<Value>()["error"]["code"], "scope_escalation");
    }
    // A token cannot mint a token with scopes it lacks (even ones its owner has)...
    let r = ctx
        .bearer("POST", "/api/v1/tokens", &secret)
        .json(&json!({"name": "x", "scopes": ["lists:write"]}))
        .await;
    r.assert_status_forbidden();
    assert_eq!(r.json::<Value>()["error"]["code"], "scope_escalation");
    // ...but may mint a subset.
    ctx.bearer("POST", "/api/v1/tokens", &secret)
        .json(&json!({"name": "child", "scopes": ["lists:read"]}))
        .await
        .assert_status(StatusCode::CREATED);
    // Empty and unknown scopes are rejected.
    bob.post("/api/v1/tokens")
        .json(&json!({"name": "x", "scopes": []}))
        .await
        .assert_status_bad_request();
    assert!(bob
        .post("/api/v1/tokens")
        .json(&json!({"name": "x", "scopes": ["root:all"]}))
        .await
        .status_code()
        .is_client_error());
    // Tokens cannot be used on another user's behalf: bob cannot revoke admin's token.
    let admin_secret = ctx.token(&admin, &["lists:read"]).await;
    let admin_tokens: Value = admin.get("/api/v1/tokens").await.json();
    let id = admin_tokens["items"][0]["id"].as_str().unwrap();
    assert!(admin_secret.contains(id) || admin_tokens["total"].as_u64().unwrap() >= 1);
    bob.delete(&format!("/api/v1/tokens/{id}"))
        .await
        .assert_status_not_found();
}

#[tokio::test]
async fn token_power_shrinks_when_the_owner_is_demoted() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let bob = ctx.user(&admin, "bob_user", "admin").await;
    let secret = ctx.token(&bob, &["users:admin", "lists:read"]).await;
    ctx.bearer("GET", "/api/v1/lists", &secret)
        .await
        .assert_status_ok();
    let bob_id = bob.get("/api/v1/auth/me").await.json::<Value>()["id"]
        .as_str()
        .unwrap()
        .to_string();
    admin
        .patch(&format!("/api/v1/users/{bob_id}"))
        .json(&json!({"role": "viewer"}))
        .await
        .assert_status_ok();
    // lists:read is still within a viewer's bundle; users:admin no longer is.
    ctx.bearer("GET", "/api/v1/lists", &secret)
        .await
        .assert_status_ok();
    ctx.bearer("GET", "/api/v1/users", &secret)
        .await
        .assert_status_forbidden();
    let me: Value = ctx.bearer("GET", "/api/v1/auth/me", &secret).await.json();
    assert_eq!(me["scopes"], json!(["lists:read"]));
}

#[tokio::test]
async fn token_profile_restriction_is_enforced_by_the_hook() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let r = admin
        .post("/api/v1/tokens")
        .json(&json!({"name": "kids", "scopes": ["tokens:self"], "profiles": ["kids"]}))
        .await;
    r.assert_status(StatusCode::CREATED);
    let secret = r.json::<Value>()["secret"].as_str().unwrap().to_string();
    // A restricted token cannot mint a token for other profiles, and inherits its restriction.
    ctx.bearer("POST", "/api/v1/tokens", &secret)
        .json(&json!({"name": "x", "scopes": ["tokens:self"], "profiles": ["adults"]}))
        .await
        .assert_status_forbidden();
    let child = ctx
        .bearer("POST", "/api/v1/tokens", &secret)
        .json(&json!({"name": "x", "scopes": ["tokens:self"]}))
        .await;
    assert_eq!(child.json::<Value>()["token"]["profiles"], json!(["kids"]));
    let p = web_api::auth::Principal {
        user_id: uuid::Uuid::new_v4(),
        username: "u".into(),
        role: api_types::UserRole::User,
        scopes: Default::default(),
        actor: web_api::auth::Actor::Token {
            token_id: "t".into(),
        },
        profiles: Some(vec!["kids".into()]),
    };
    assert!(p.may_access_profile("kids") && !p.may_access_profile("adults"));
}

// ------------------------------------------------------------------ (e) CSRF

#[tokio::test]
async fn csrf_is_required_for_cookie_writes_but_not_for_bearer() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let body = json!({"id": "c1", "name": "C", "url": "https://example.com/x.txt"});
    let cookie = || Cookie::new("access_token", admin.access.clone());

    // Cookie POST without the token -> 403 csrf_failed.
    let r = ctx
        .server
        .post("/api/v1/lists")
        .add_cookie(cookie())
        .json(&body)
        .await;
    r.assert_status_forbidden();
    assert_eq!(r.json::<Value>()["error"]["code"], "csrf_failed");
    // Wrong token, and a token minted for another session -> 403.
    ctx.server
        .post("/api/v1/lists")
        .add_cookie(cookie())
        .add_header("x-csrf-token", "nope")
        .json(&body)
        .await
        .assert_status_forbidden();
    let other = ctx.login("admin_user").await;
    ctx.server
        .post("/api/v1/lists")
        .add_cookie(cookie())
        .add_header("x-csrf-token", other.csrf.clone())
        .json(&body)
        .await
        .assert_status_forbidden();
    // Cross-origin request carrying a valid token is still refused.
    ctx.server
        .post("/api/v1/lists")
        .add_cookie(cookie())
        .add_header("x-csrf-token", admin.csrf.clone())
        .add_header("origin", "https://evil.example")
        .json(&body)
        .await
        .assert_status_forbidden();
    // Safe methods never need it.
    ctx.server
        .get("/api/v1/lists")
        .add_cookie(cookie())
        .await
        .assert_status_ok();
    // Correct token -> allowed.
    ctx.server
        .post("/api/v1/lists")
        .add_cookie(cookie())
        .add_header("x-csrf-token", admin.csrf.clone())
        .json(&body)
        .await
        .assert_status(StatusCode::CREATED);

    // Bearer POST without a CSRF token -> allowed.
    let secret = ctx.token(&admin, &["lists:write"]).await;
    ctx.bearer("POST", "/api/v1/lists", &secret)
        .json(&json!({"id": "c2", "name": "C2", "url": "https://example.com/y.txt"}))
        .await
        .assert_status(StatusCode::CREATED);
}

#[tokio::test]
async fn csrf_can_be_disabled_by_config() {
    let ctx = TestContext::with_config(|c| c.security.enable_csrf = false)
        .await
        .unwrap();
    let admin = ctx.admin().await;
    ctx.server
        .post("/api/v1/stats/filter/reset")
        .add_cookie(Cookie::new("access_token", admin.access.clone()))
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn cors_is_same_origin_unless_allowlisted() {
    let ctx = TestContext::new().await.unwrap();
    let r = ctx
        .server
        .get("/api/v1/health")
        .add_header("origin", "https://evil.example")
        .await;
    assert!(r.headers().get("access-control-allow-origin").is_none());

    let ctx =
        TestContext::with_config(|c| c.security.cors_origins = vec!["https://ui.example".into()])
            .await
            .unwrap();
    let ok = ctx
        .server
        .get("/api/v1/health")
        .add_header("origin", "https://ui.example")
        .await;
    assert_eq!(
        ok.header("access-control-allow-origin"),
        "https://ui.example"
    );
    let bad = ctx
        .server
        .get("/api/v1/health")
        .add_header("origin", "https://evil.example")
        .await;
    assert!(bad.headers().get("access-control-allow-origin").is_none());
}

#[tokio::test]
async fn cert_endpoints_serve_the_store_to_tokens_and_allow_extension_origins_only_there() {
    let ctx = TestContext::new().await.unwrap();
    let der = rcgen::generate_simple_self_signed(vec!["o.test".to_string()])
        .unwrap()
        .cert
        .der()
        .to_vec();
    let fp = ctx
        .state
        .certs()
        .record_ok("o.test", &der, &|| false)
        .unwrap();
    // Another host replaying the chain gets its own verdict; o.test's is untouched.
    ctx.state.certs().record_probe(
        "evil.test",
        &[der.as_slice()],
        Err((::common::certstore::FailReason::NameMismatch, "bad".into())),
        &|| false,
    );
    ctx.state.certs().note_seen("o.test", "kids");
    let admin = ctx.admin().await;
    let secret = ctx.token(&admin, &["logs:read"]).await;
    let a = ctx
        .bearer("GET", &format!("/api/v1/certs/{fp}"), &secret)
        .await;
    a.assert_status_ok();
    let b = ctx
        .bearer("GET", "/api/v1/certs/by-host/o.test", &secret)
        .add_header("origin", "chrome-extension://abc")
        .await;
    b.assert_status_ok();
    assert_eq!(
        b.header("access-control-allow-origin"),
        "chrome-extension://abc"
    );
    assert_eq!(a.json::<Value>()["fp"], fp);
    assert_eq!(a.json::<Value>()["verdict"], "ok");
    let evil: Value = ctx
        .bearer(
            "GET",
            &format!("/api/v1/certs/{fp}?host=evil.test"),
            &secret,
        )
        .await
        .json();
    assert_eq!(evil["reason"], "name_mismatch");
    let ok: Value = ctx
        .bearer(
            "GET",
            &format!("/api/v1/certs/{fp}?host=O.test:443"),
            &secret,
        )
        .await
        .json();
    assert_eq!(ok["verdict"], "ok");
    // A profile-restricted token sees only hosts its profiles visited; the rest is a plain 404.
    let r = admin
        .post("/api/v1/tokens")
        .json(&json!({"name": "kids", "scopes": ["logs:read"], "profiles": ["kids"]}))
        .await;
    let kid = r.json::<Value>()["secret"].as_str().unwrap().to_string();
    ctx.bearer("GET", "/api/v1/certs/by-host/o.test", &kid)
        .await
        .assert_status_ok();
    ctx.bearer("GET", "/api/v1/certs/by-host/o.test:443", &kid)
        .await
        .assert_status_ok();
    for path in [
        "/api/v1/certs/by-host/evil.test".to_string(),
        "/api/v1/certs/by-host/unknown.test".to_string(),
        "/api/v1/certs/by-host/o.test:8443".to_string(),
        format!("/api/v1/certs/{fp}?host=evil.test"),
        format!("/api/v1/certs/{fp}?host=unknown.test"),
    ] {
        ctx.bearer("GET", &path, &kid)
            .await
            .assert_status(StatusCode::NOT_FOUND);
    }
    ctx.bearer("GET", &format!("/api/v1/certs/{fp}?host=o.test"), &kid)
        .await
        .assert_status_ok();
    ctx.bearer("GET", "/api/v1/certs/by-host/nope.test", &secret)
        .await
        .assert_status(StatusCode::NOT_FOUND);
    ctx.server
        .get("/api/v1/certs/by-host/o.test")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    // Extension origins get no CORS elsewhere.
    let h = ctx
        .server
        .get("/api/v1/health")
        .add_header("origin", "moz-extension://abc")
        .await;
    assert!(h.headers().get("access-control-allow-origin").is_none());
}

/// Probe stand-in: "sees" a fixed chain per host and records it like the real prober.
struct FakeProbe {
    store: std::sync::Arc<::common::certstore::CertStore>,
    chains: Vec<(&'static str, Vec<Vec<u8>>)>,
    calls: std::sync::atomic::AtomicUsize,
}

impl ::common::certstore::ChainProbe for FakeProbe {
    fn probe<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<String>> + Send + 'a>> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let chain = &self.chains.iter().find(|(h, _)| *h == host).unwrap().1;
        let refs: Vec<&[u8]> = chain.iter().map(Vec::as_slice).collect();
        let fp = self.store.record_probe(
            &::common::certstore::hostport(host, port),
            &refs,
            Ok(()),
            &|| false,
        );
        Box::pin(async move { fp })
    }
}

fn chain_for(name: &str) -> Vec<Vec<u8>> {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
    let mut ca = CertificateParams::new(vec![]).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.distinguished_name
        .push(rcgen::DnType::CommonName, "chain test CA");
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca, ca_key);
    let key = KeyPair::generate().unwrap();
    let mut lp = CertificateParams::new(vec![name.to_string()]).unwrap();
    lp.distinguished_name.push(rcgen::DnType::CommonName, name);
    let leaf = lp.signed_by(&key, &issuer).unwrap();
    vec![leaf.der().to_vec(), ca_cert.der().to_vec()]
}

#[tokio::test]
async fn leaf_only_records_are_upgraded_to_the_full_chain_on_lookup() {
    use std::sync::atomic::Ordering::SeqCst;
    let ctx = TestContext::new().await.unwrap();
    let store = ctx.state.certs().clone();
    let full = chain_for("o.test");
    let rotated = chain_for("o.test");
    // The proxy knows only the leaf of o.test and of r.test (which has since rotated).
    let fp = store.record_ok("o.test", &full[0], &|| false).unwrap();
    let old = store.record_ok("r.test", &rotated[0], &|| false).unwrap();
    store.note_seen("o.test", "kids");
    let fake = std::sync::Arc::new(FakeProbe {
        store: store.clone(),
        // r.test now serves a different certificate than the one on record.
        chains: vec![("o.test", full.clone()), ("r.test", chain_for("r.test"))],
        calls: Default::default(),
    });
    ctx.state.chain_probe.set(fake.clone()).ok().unwrap();
    let admin = ctx.admin().await;
    let secret = ctx.token(&admin, &["logs:read"]).await;

    // A restricted token for a host it has not seen: 404 and no probe.
    let r = admin
        .post("/api/v1/tokens")
        .json(&json!({"name": "kids", "scopes": ["logs:read"], "profiles": ["kids"]}))
        .await;
    let kid = r.json::<Value>()["secret"].as_str().unwrap().to_string();
    ctx.bearer("GET", "/api/v1/certs/by-host/r.test", &kid)
        .await
        .assert_status(StatusCode::NOT_FOUND);
    ctx.bearer("GET", &format!("/api/v1/certs/{old}?host=r.test"), &kid)
        .await
        .assert_status(StatusCode::NOT_FOUND);
    assert_eq!(fake.calls.load(SeqCst), 0);

    // A rotated site: the probe sees another certificate, so the record is not upgraded.
    let v: Value = ctx
        .bearer("GET", &format!("/api/v1/certs/{old}?host=r.test"), &secret)
        .await
        .json();
    assert_eq!(fake.calls.load(SeqCst), 1);
    assert_eq!(v["fp"], old.as_str());
    assert_eq!(v["chain"].as_array().unwrap().len(), 1);

    // The probe sees the same certificate: its full chain is stored and returned.
    let v: Value = ctx
        .bearer("GET", "/api/v1/certs/by-host/o.test", &kid)
        .await
        .json();
    assert_eq!(v["fp"], fp.as_str());
    assert_eq!(v["chain"].as_array().unwrap().len(), 2);
    assert_eq!(fake.calls.load(SeqCst), 2);
    // Already full: no further probe.
    ctx.bearer("GET", &format!("/api/v1/certs/{fp}?host=o.test"), &secret)
        .await
        .assert_status_ok();
    assert_eq!(fake.calls.load(SeqCst), 2);
}

// ------------------------------------------------------------------ (f) revocation / expiry

#[tokio::test]
async fn revoked_and_expired_tokens_fail_immediately() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let created = admin
        .post("/api/v1/tokens")
        .json(&json!({"name": "ci", "scopes": ["lists:read"], "expires_in_days": 30}))
        .await;
    let created: Value = created.json();
    let (secret, id) = (
        created["secret"].as_str().unwrap().to_string(),
        created["token"]["id"].as_str().unwrap().to_string(),
    );
    assert!(secret.starts_with(&format!("abk_{id}_")));
    assert_eq!(
        secret.len(),
        "abk_".len() + id.len() + 1 + 64,
        "256-bit secret"
    );
    assert!(created["token"].get("secret").is_none() && created["token"]["expires_at"].is_string());

    assert!(
        admin.get("/api/v1/tokens").await.json::<Value>()["items"][0]["last_used_at"].is_null()
    );
    ctx.bearer("GET", "/api/v1/lists", &secret)
        .await
        .assert_status_ok();
    let listed: Value = admin.get("/api/v1/tokens").await.json();
    assert!(listed["items"][0]["last_used_at"].is_string());
    assert!(
        !listed.to_string().contains(&secret),
        "secrets are never listed"
    );

    // Revoke: the very next request fails.
    admin
        .delete(&format!("/api/v1/tokens/{id}"))
        .await
        .assert_status_ok();
    let r = ctx.bearer("GET", "/api/v1/lists", &secret).await;
    r.assert_status_unauthorized();
    assert_eq!(
        admin.get("/api/v1/tokens").await.json::<Value>()["items"][0]["revoked"],
        true
    );

    // Expired (created directly with a past expiry).
    let user = ctx
        .state
        .session_store
        .get_user_by_username("admin_user")
        .unwrap()
        .unwrap();
    let (_, expired) = ctx
        .state
        .tokens
        .create(
            "old".into(),
            vec![Scope::ListsRead],
            None,
            user.id,
            user.username.clone(),
            Some(chrono::Utc::now() - chrono::Duration::seconds(1)),
        )
        .unwrap();
    ctx.bearer("GET", "/api/v1/lists", &expired)
        .await
        .assert_status_unauthorized();

    // Garbage and wrong-secret tokens, and a bad scheme.
    ctx.bearer("GET", "/api/v1/lists", "abk_deadbeef_cafe")
        .await
        .assert_status_unauthorized();
    ctx.bearer("GET", "/api/v1/lists", &format!("{secret}0"))
        .await
        .assert_status_unauthorized();
    ctx.server
        .get("/api/v1/lists")
        .add_header("authorization", format!("Basic {secret}"))
        .await
        .assert_status_unauthorized();
}

#[tokio::test]
async fn disabling_or_deleting_the_owner_kills_their_tokens() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let bob = ctx.user(&admin, "bob_user", "user").await;
    let secret = ctx.token(&bob, &["lists:read"]).await;
    ctx.bearer("GET", "/api/v1/lists", &secret)
        .await
        .assert_status_ok();
    let bob_id = bob.get("/api/v1/auth/me").await.json::<Value>()["id"]
        .as_str()
        .unwrap()
        .to_string();
    admin
        .patch(&format!("/api/v1/users/{bob_id}"))
        .json(&json!({"enabled": false}))
        .await
        .assert_status_ok();
    ctx.bearer("GET", "/api/v1/lists", &secret)
        .await
        .assert_status_unauthorized();
    admin
        .patch(&format!("/api/v1/users/{bob_id}"))
        .json(&json!({"enabled": true}))
        .await
        .assert_status_ok();
    ctx.bearer("GET", "/api/v1/lists", &secret)
        .await
        .assert_status_ok();
    admin
        .delete(&format!("/api/v1/users/{bob_id}"))
        .await
        .assert_status_ok();
    ctx.bearer("GET", "/api/v1/lists", &secret)
        .await
        .assert_status_unauthorized();
}

#[tokio::test]
async fn per_token_rate_limit_applies() {
    let ctx = TestContext::with_config(|c| c.rate_limit.user_requests_per_minute = 3)
        .await
        .unwrap();
    let admin = ctx.admin().await;
    let secret = ctx.token(&admin, &["lists:read"]).await;
    let mut codes = vec![];
    for _ in 0..5 {
        codes.push(
            ctx.bearer("GET", "/api/v1/lists", &secret)
                .await
                .status_code(),
        );
    }
    assert_eq!(
        codes.iter().filter(|c| **c == StatusCode::OK).count(),
        3,
        "{codes:?}"
    );
    assert_eq!(codes[4], StatusCode::TOO_MANY_REQUESTS);
    // Another token is unaffected.
    let other = ctx.token(&admin, &["lists:read"]).await;
    ctx.bearer("GET", "/api/v1/lists", &other)
        .await
        .assert_status_ok();
    let _ = PASSWORD;
}

#[tokio::test]
async fn login_does_the_same_bcrypt_work_and_answers_identically_for_every_failure() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    ctx.user(&admin, "alice", "viewer").await;
    ctx.user(&admin, "dora", "viewer").await;
    let mut dora = ctx
        .state
        .session_store
        .get_user_by_username("dora")
        .unwrap()
        .unwrap();
    dora.enabled = false;
    ctx.state.session_store.store_user(&dora).unwrap();

    let attempt = |name: &'static str, pw: &'static str| {
        let ctx = &ctx;
        async move {
            let before = web_api::auth::password::verify_call_count();
            let r = ctx
                .server
                .post("/api/v1/auth/login")
                .json(&json!({"username": name, "password": pw}))
                .await;
            let ran = web_api::auth::password::verify_call_count() - before;
            (r.status_code(), r.text(), ran)
        }
    };
    let unknown = attempt("nobody", PASSWORD).await;
    let wrong = attempt("alice", "Wrong-Password-1!").await;
    let disabled = attempt("dora", PASSWORD).await;
    assert_eq!(unknown.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        unknown.2, 1,
        "an unknown user must still cost one bcrypt verify"
    );
    assert_eq!(wrong.2, 1);
    assert_eq!(disabled.2, 1);
    // Same status and identical body for every failure cause.
    assert_eq!((wrong.0, &wrong.1), (unknown.0, &unknown.1));
    assert_eq!((disabled.0, &disabled.1), (unknown.0, &unknown.1));
}

async fn login_set_cookies(
    mode: web_api::config::CookieSecure,
    forwarded_https: bool,
) -> Vec<String> {
    let ctx = TestContext::with_config(|c| c.security.cookie_secure = mode)
        .await
        .unwrap();
    let mut req = ctx.server.post("/api/v1/auth/register");
    if forwarded_https {
        // No trusted proxy is configured, so this header must be ignored.
        req = req.add_header("x-forwarded-proto", "https");
    }
    let resp = req
        .json(
            &json!({"username": "admin_user", "password": PASSWORD, "password_confirm": PASSWORD}),
        )
        .await;
    resp.assert_status_ok();
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn cookie_secure_is_auto_always_or_never() {
    use web_api::config::CookieSecure::*;
    assert_eq!(
        web_api::config::SecurityConfig::default().cookie_secure,
        Auto
    );
    for (mode, want) in [(Auto, false), (Never, false), (Always, true)] {
        let cookies = login_set_cookies(mode, false).await;
        assert_eq!(cookies.len(), 3);
        for c in &cookies {
            assert_eq!(c.contains("Secure"), want, "{mode:?}: {c}");
        }
    }
    // An unproxied `X-Forwarded-Proto: https` is spoofable and must not turn Secure on.
    for c in login_set_cookies(Auto, true).await {
        assert!(!c.contains("Secure"), "{c}");
    }
}

#[test]
fn cookie_secure_config_accepts_words_and_legacy_booleans() {
    use web_api::config::{CookieSecure, SecurityConfig};
    let parse = |v: &str| -> Result<SecurityConfig, _> {
        toml::from_str(&format!(
            "enable_csrf = true\nrequire_https = false\ncors_origins = []\ncookie_secure = {v}"
        ))
    };
    assert_eq!(
        parse("\"always\"").unwrap().cookie_secure,
        CookieSecure::Always
    );
    assert_eq!(parse("true").unwrap().cookie_secure, CookieSecure::Always);
    assert_eq!(parse("false").unwrap().cookie_secure, CookieSecure::Never);
    assert!(parse("\"sometimes\"").is_err());
}

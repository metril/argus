//! The management API over a [`TestProxy`]'s own stores, built through the same wiring the
//! binary uses, so API writes must reach the running proxy.

use std::sync::Arc;

use axum_test::{TestRequest, TestServer};
use serde_json::{json, Value};

use crate::TestProxy;

const PASSWORD: &str = "SecurePassword123!";
const SCOPES: [&str; 13] = [
    "config:read",
    "config:write",
    "logs:read",
    "profiles:read",
    "profiles:write",
    "devices:read",
    "devices:write",
    "policy:read",
    "policy:write",
    "scripts:read",
    "scripts:write",
    "rules:read",
    "rules:write",
];

/// An in-process API server with a registered administrator's token.
pub struct TestApi {
    server: TestServer,
    secret: String,
    pub state: Arc<web_api::AppState>,
    _dir: tempfile::TempDir,
}

fn cookie_from(resp: &axum_test::TestResponse, name: &str) -> String {
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|s| {
            s.strip_prefix(&format!("{name}="))
                .map(|r| r.split(';').next().unwrap_or("").to_string())
        })
        .unwrap_or_else(|| panic!("cookie {name}"))
}

impl TestProxy {
    /// The API over this proxy's profile store, policy store and userscript manager.
    pub async fn api(&self) -> TestApi {
        let h = self.profiles();
        let dir = tempfile::tempdir().expect("api dir");
        let p = dir.path();
        let mut cfg = web_api::ApiConfig::default();
        cfg.auth.jwt_secret_path = p.join("jwt_secret");
        cfg.session.storage_path = p.join("sessions");
        cfg.auth.bcrypt_cost = 4;
        let mut proxy_config = proxy_core::ProxyConfig::default();
        // The test proxy's engine is on; a config save must not switch it off.
        proxy_config.adblock.enabled = true;
        let config_path = p.join("proxy.toml");
        std::fs::write(&config_path, toml::to_string_pretty(&proxy_config).unwrap()).unwrap();
        let state = proxy_core::webui::build_api_state(
            &self.ctx,
            proxy_core::webui::ApiInputs {
                api_config: cfg.clone(),
                proxy_config,
                shared_engine: self.engine.clone(),
                list_service: h.lists.clone(),
                manager: h.manager.clone(),
                policy: h.policy.clone(),
                config_path,
            },
        )
        .await
        .expect("api state");
        let server = TestServer::new(web_api::create_router(state.clone(), &cfg)).expect("server");
        let resp = server
            .post("/api/v1/auth/register")
            .json(&json!({"username": "admin_user", "password": PASSWORD, "password_confirm": PASSWORD}))
            .await;
        resp.assert_status_ok();
        let (access, csrf) = (
            cookie_from(&resp, "access_token"),
            cookie_from(&resp, "csrf_token"),
        );
        let tok = server
            .post("/api/v1/tokens")
            .add_cookie(cookie::Cookie::new("access_token", access))
            .add_header("x-csrf-token", csrf)
            .json(&json!({"name": "e2e", "scopes": SCOPES}))
            .await;
        assert_eq!(tok.status_code(), 201, "{}", tok.text());
        let secret = tok.json::<Value>()["secret"].as_str().unwrap().to_string();
        TestApi {
            server,
            secret,
            state,
            _dir: dir,
        }
    }
}

impl TestApi {
    pub fn get(&self, path: &str) -> TestRequest {
        self.server
            .get(&format!("/api/v1{path}"))
            .authorization_bearer(&self.secret)
    }
    pub fn post(&self, path: &str) -> TestRequest {
        self.server
            .post(&format!("/api/v1{path}"))
            .authorization_bearer(&self.secret)
    }
    pub fn put(&self, path: &str) -> TestRequest {
        self.server
            .put(&format!("/api/v1{path}"))
            .authorization_bearer(&self.secret)
    }
    pub fn delete(&self, path: &str) -> TestRequest {
        self.server
            .delete(&format!("/api/v1{path}"))
            .authorization_bearer(&self.secret)
    }

    /// POST `body`, expect `201`/`200`, return the JSON.
    pub async fn create(&self, path: &str, body: Value) -> Value {
        let r = self.post(path).json(&body).await;
        assert!(r.status_code().is_success(), "{path}: {}", r.text());
        r.json()
    }
}

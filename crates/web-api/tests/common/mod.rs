//! Test helpers: an isolated app per test (own temp dir, in-process transport, no ports).

#![allow(dead_code)]

use axum::Router;
use axum_test::{TestRequest, TestServer};
use common::config::ProxyConfig;
use cookie::Cookie;
use filter_engine::SharedEngine;
use serde_json::{json, Value};
use std::sync::Arc;
use tempfile::TempDir;
use userscript_engine::{UserscriptManager, UserscriptRuntime, UserscriptStorage};
use web_api::config::ApiConfig;
use web_api::state::build_state;
use web_api::{create_router, ApiResult, AppState};
use web_api::{ListService, ListServiceConfig, ListStore};

pub const PASSWORD: &str = "SecurePassword123!";

pub struct TestContext {
    pub router: Router,
    pub server: Arc<TestServer>,
    pub state: Arc<AppState>,
    pub api_config: ApiConfig,
    pub temp_dir: TempDir,
}

impl TestContext {
    pub async fn new() -> ApiResult<Self> {
        Self::with_config(|_| {}).await
    }

    pub async fn with_config(tweak: impl FnOnce(&mut ApiConfig)) -> ApiResult<Self> {
        Self::build(tweak, &[]).await
    }

    /// Like [`Self::new`], with these destinations (CIDRs, IPs, host names) fetchable by the
    /// control plane (e.g. a loopback origin serving a script).
    pub async fn with_fetch_allowed(allowed: &[&str]) -> ApiResult<Self> {
        Self::build(|_| {}, allowed).await
    }

    async fn build(tweak: impl FnOnce(&mut ApiConfig), allowed: &[&str]) -> ApiResult<Self> {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let temp_path = temp_dir.path();

        let mut api_config = ApiConfig::default();
        api_config.auth.jwt_secret_path = temp_path.join("jwt_secret");
        api_config.session.storage_path = temp_path.join("sessions");
        // Tests hash many passwords in an unoptimised build: use bcrypt's minimum cost explicitly.
        api_config.auth.bcrypt_cost = 4;
        tweak(&mut api_config);

        // Tests never reach the real first-party lists: a dead address fails at once.
        let mut proxy_config = ProxyConfig::default();
        proxy_config.bypass.lists_base_url = "http://127.0.0.1:1".into();
        proxy_config.adblock.data_dir = temp_path.join("filters");
        let config_path = temp_path.join("proxy.toml");
        std::fs::write(
            &config_path,
            toml::to_string_pretty(&proxy_config).expect("serialize proxy config"),
        )
        .expect("write proxy config");

        let shared_engine = Arc::new(SharedEngine::new());
        let filter_store =
            ListStore::open(&temp_path.join("filters")).expect("Failed to open filter store");
        let http_client = reqwest::Client::new();
        let guard = (!allowed.is_empty()).then(|| {
            let allowed: Vec<String> = allowed.iter().map(|s| s.to_string()).collect();
            Arc::new(::common::net_policy::NetPolicy::control_plane(&allowed).unwrap())
        });
        let list_service = ListService::new_guarded(
            ListServiceConfig::default(),
            filter_store,
            shared_engine.clone(),
            http_client.clone(),
            guard,
        );

        let userscript_manager = Arc::new(
            UserscriptManager::new(temp_path.join("userscripts"))
                .expect("Failed to create userscript manager"),
        );
        let userscript_storage = Arc::new(
            UserscriptStorage::new(temp_path.join("userscript-storage"))
                .expect("Failed to create userscript storage"),
        );
        let userscript_runtime = Arc::new(UserscriptRuntime::new(
            userscript_manager.clone(),
            userscript_storage,
        ));

        let state = build_state(
            api_config.clone(),
            proxy_config,
            shared_engine,
            list_service,
            http_client,
            userscript_manager,
            userscript_runtime,
            config_path,
            Arc::new(std::sync::atomic::AtomicU64::new(60_000)),
        )
        .await?;

        let router = create_router(state.clone(), &api_config);
        let server =
            Arc::new(TestServer::new(router.clone()).expect("Failed to create test server"));
        Ok(Self {
            router,
            server,
            state,
            api_config,
            temp_dir,
        })
    }

    /// Register the first user (an administrator) and return its session.
    pub async fn admin(&self) -> Sess {
        let resp = self
            .server
            .post("/api/v1/auth/register")
            .json(&json!({"username": "admin_user", "password": PASSWORD, "password_confirm": PASSWORD}))
            .await;
        resp.assert_status_ok();
        Sess::from_response(self.server.clone(), &resp)
    }

    /// Create `name` with `role` through the admin API and log in as them.
    pub async fn user(&self, admin: &Sess, name: &str, role: &str) -> Sess {
        admin
            .post("/api/v1/users")
            .json(&json!({"username": name, "password": PASSWORD, "role": role}))
            .await
            .assert_status(axum::http::StatusCode::CREATED);
        self.login(name).await
    }

    pub async fn login(&self, name: &str) -> Sess {
        let resp = self
            .server
            .post("/api/v1/auth/login")
            .json(&json!({"username": name, "password": PASSWORD}))
            .await;
        resp.assert_status_ok();
        Sess::from_response(self.server.clone(), &resp)
    }

    /// Mint an API token with the given scopes for `sess`; returns the secret.
    pub async fn token(&self, sess: &Sess, scopes: &[&str]) -> String {
        let resp = sess
            .post("/api/v1/tokens")
            .json(&json!({"name": "test", "scopes": scopes}))
            .await;
        resp.assert_status(axum::http::StatusCode::CREATED);
        resp.json::<Value>()["secret"].as_str().unwrap().to_string()
    }

    /// Request authenticated with a bearer token.
    pub fn bearer(&self, method: &str, path: &str, secret: &str) -> TestRequest {
        let r = match method {
            "GET" => self.server.get(path),
            "POST" => self.server.post(path),
            "PUT" => self.server.put(path),
            "PATCH" => self.server.patch(path),
            "DELETE" => self.server.delete(path),
            m => panic!("unsupported method {m}"),
        };
        r.authorization_bearer(secret)
    }
}

/// A cookie session; requests made through it carry the access cookie and CSRF header.
pub struct Sess {
    pub server: Arc<TestServer>,
    pub access: String,
    pub refresh: String,
    pub csrf: String,
}

fn cookie_from(resp: &axum_test::TestResponse, name: &str) -> Option<String> {
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|s| {
            s.strip_prefix(&format!("{name}="))
                .map(|r| r.split(';').next().unwrap_or("").to_string())
        })
}

pub fn extract_access_token(resp: &axum_test::TestResponse) -> Option<String> {
    cookie_from(resp, "access_token")
}

pub fn extract_refresh_token(resp: &axum_test::TestResponse) -> Option<String> {
    cookie_from(resp, "refresh_token")
}

impl Sess {
    pub fn from_response(server: Arc<TestServer>, resp: &axum_test::TestResponse) -> Self {
        Self {
            server,
            access: cookie_from(resp, "access_token").expect("access cookie"),
            refresh: cookie_from(resp, "refresh_token").expect("refresh cookie"),
            csrf: cookie_from(resp, "csrf_token").expect("csrf cookie"),
        }
    }

    fn with(&self, r: TestRequest) -> TestRequest {
        r.add_cookie(Cookie::new("access_token", self.access.clone()))
            .add_header("x-csrf-token", self.csrf.clone())
    }

    pub fn get(&self, p: &str) -> TestRequest {
        self.with(self.server.get(p))
    }
    pub fn post(&self, p: &str) -> TestRequest {
        self.with(self.server.post(p))
    }
    pub fn put(&self, p: &str) -> TestRequest {
        self.with(self.server.put(p))
    }
    pub fn patch(&self, p: &str) -> TestRequest {
        self.with(self.server.patch(p))
    }
    pub fn delete(&self, p: &str) -> TestRequest {
        self.with(self.server.delete(p))
    }
}

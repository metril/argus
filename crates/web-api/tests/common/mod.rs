//! Test helpers and utilities
//!
//! Provides common setup and utilities for integration tests.

use axum::Router;
use common::config::ProxyConfig;
use filter_engine::SharedEngine;
use std::sync::Arc;
use tempfile::TempDir;
use userscript_engine::{UserscriptManager, UserscriptRuntime, UserscriptStorage};
use web_api::config::ApiConfig;
use web_api::open_filter_store;
use web_api::state::build_state;
use web_api::{create_router, ApiResult, AppState};

/// Test context that manages temporary directories and state
pub struct TestContext {
    pub router: Router,
    #[allow(dead_code)]
    pub state: Arc<AppState>,
    #[allow(dead_code)]
    temp_dir: TempDir,
}

impl TestContext {
    /// Create a new test context with fresh state
    pub async fn new() -> ApiResult<Self> {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let temp_path = temp_dir.path();

        // Create API config with temp paths
        let mut api_config = ApiConfig::default();
        api_config.auth.jwt_secret_path = temp_path.join("jwt_secret");
        api_config.session.storage_path = temp_path.join("sessions");

        // Create proxy config
        let proxy_config = ProxyConfig::default();
        let config_path = temp_path.join("proxy.toml");

        // Write initial proxy config
        let config_str =
            toml::to_string_pretty(&proxy_config).expect("Failed to serialize proxy config");
        std::fs::write(&config_path, config_str).expect("Failed to write proxy config");

        // Create shared filter engine + persistent list store (empty for tests)
        let shared_engine = Arc::new(SharedEngine::new());
        let filter_store =
            open_filter_store(&temp_path.join("filters")).expect("Failed to open filter store");
        let http_client = reqwest::Client::new();

        // Create userscript manager, storage and runtime
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

        // Build state
        let state = build_state(
            api_config.clone(),
            proxy_config,
            shared_engine,
            filter_store,
            http_client,
            userscript_manager,
            userscript_runtime,
            config_path,
        )
        .await?;

        // Create router
        let router = create_router(state.clone(), &api_config);

        Ok(Self {
            router,
            state,
            temp_dir,
        })
    }
}

/// Extract access token cookie from response headers
pub fn extract_access_token(response: &axum_test::TestResponse) -> Option<String> {
    for value in response.headers().get_all("set-cookie") {
        if let Ok(s) = value.to_str() {
            if s.starts_with("access_token=") {
                let token = s
                    .split(';')
                    .next()
                    .unwrap()
                    .strip_prefix("access_token=")
                    .unwrap();
                return Some(token.to_string());
            }
        }
    }
    None
}

/// Extract refresh token cookie from response headers
pub fn extract_refresh_token(response: &axum_test::TestResponse) -> Option<String> {
    for value in response.headers().get_all("set-cookie") {
        if let Ok(s) = value.to_str() {
            if s.starts_with("refresh_token=") {
                let token = s
                    .split(';')
                    .next()
                    .unwrap()
                    .strip_prefix("refresh_token=")
                    .unwrap();
                return Some(token.to_string());
            }
        }
    }
    None
}

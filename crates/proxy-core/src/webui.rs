//! Wiring of the web API to the running proxy: one instance of every store they share.
//!
//! Both the binary and the tests build the API state through [`build_api_state`], so the API
//! cannot end up with stores of its own (writes through the API must reach the proxy).

use crate::filtering::ProxyContext;
use chrono::{DateTime, Utc};
use filter_engine::SharedEngine;
use list_service::ListService;
use std::path::PathBuf;
use std::sync::Arc;
use userscript_engine::{UserscriptManager, UserscriptRuntime};
use web_api::{ApiConfig, ApiResult, AppState, ProfileBuildInfo, ProfileRuntime};

/// Build status and device activity of a running proxy, for the API.
pub struct ProxyProfileRuntime {
    ctx: Arc<ProxyContext>,
}

impl ProxyProfileRuntime {
    pub fn new(ctx: Arc<ProxyContext>) -> Self {
        Self { ctx }
    }
}

impl ProfileRuntime for ProxyProfileRuntime {
    fn build_info(&self, profile_id: u64) -> Option<ProfileBuildInfo> {
        let st = self.ctx.profile_builder()?.status();
        st.get(&profile_id).map(|s| ProfileBuildInfo {
            last_error: s.last_error.clone(),
            last_built: s.last_built,
        })
    }

    fn device_last_seen(&self, device_id: u64) -> Option<DateTime<Utc>> {
        let secs = self.ctx.profiles().last_seen(device_id)?;
        DateTime::from_timestamp(secs as i64, 0)
    }
}

/// Everything the API shares with the proxy besides what `ctx` already holds.
pub struct ApiInputs {
    pub api_config: ApiConfig,
    pub proxy_config: crate::config::ProxyConfig,
    pub shared_engine: Arc<SharedEngine>,
    pub list_service: Arc<ListService>,
    pub manager: Arc<UserscriptManager>,
    pub policy: Arc<script_policy::store::PolicyStore>,
    pub config_path: PathBuf,
}

/// The API state over the proxy's own profile store, policy store, userscript manager and
/// build/activity view. `ctx` must already have its profile service set.
pub async fn build_api_state(ctx: &Arc<ProxyContext>, i: ApiInputs) -> ApiResult<Arc<AppState>> {
    let runtime = Arc::new(UserscriptRuntime::new(
        i.manager.clone(),
        i.manager.storage_arc(),
    ));
    web_api::build_state_full(
        i.api_config,
        i.proxy_config,
        i.shared_engine,
        i.list_service,
        reqwest::Client::new(),
        i.manager,
        runtime,
        i.config_path,
        ctx.request_timeout_handle(),
        Some(i.policy),
        ctx.profile_store().cloned(),
        Some(Arc::new(ProxyProfileRuntime::new(ctx.clone()))),
    )
    .await
}

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

#[async_trait::async_trait]
impl web_api::ExtBridge for crate::ext_bridge::ExtHub {
    fn open(
        &self,
        ident: api_types::ExtIdent,
    ) -> (u64, String, tokio::sync::mpsc::Receiver<api_types::ExtOut>) {
        let (id, sid, rx) = crate::ext_bridge::ExtHub::open(self, ident);
        // The extension gets its host list right after the welcome frame.
        if let Some(hub) = self.arc() {
            tokio::spawn(async move { hub.push_hosts(id, true).await });
        }
        (id, sid, rx)
    }

    async fn on_text(&self, session: u64, text: &str) {
        crate::ext_bridge::ExtHub::on_text(self, session, text).await
    }

    async fn on_binary(&self, session: u64, data: Vec<u8>) {
        crate::ext_bridge::ExtHub::on_binary(self, session, &data).await
    }

    fn close(&self, session: u64) {
        crate::ext_bridge::ExtHub::close(self, session)
    }

    fn session_for(&self, sid: &str, token_id: &str) -> Option<u64> {
        crate::ext_bridge::ExtHub::session_for(self, sid, token_id)
    }

    fn menu(
        &self,
        session: u64,
        mdoc: &str,
    ) -> Result<api_types::ExtMenuResponse, api_types::ExtError> {
        crate::ext_bridge::ExtHub::menu(self, session, mdoc)
    }

    fn trigger(
        &self,
        session: u64,
        req: &api_types::ExtTriggerRequest,
    ) -> Result<bool, api_types::ExtError> {
        crate::ext_bridge::ExtHub::trigger(self, session, req)
    }

    fn browser_fallback(&self, profile: &str, script: &str) -> bool {
        crate::ext_bridge::ExtHub::browser_fallback(self, profile, script)
    }

    fn set_audit(&self, sink: Arc<dyn Fn(api_types::ExtAuditEvent) + Send + Sync>) {
        self.set_audit_sink(sink);
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
    let hub = ctx.internal().gm.ext().clone();
    hub.set_ctx(crate::ext_bridge::HubCtx {
        manager: i.manager.clone(),
        profiles: ctx.profile_store().cloned(),
        bypass: ctx.bypass().clone(),
    });
    hub.set_auditor(runtime.auditor().clone());
    let state = web_api::build_state_full(
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
    .await?;
    let _ = state.ext.set(hub.clone());
    {
        // Weak: the state owns the hub, the hub must not keep the state alive.
        let weak = Arc::downgrade(&state);
        web_api::ExtBridge::set_audit(
            hub.as_ref(),
            Arc::new(move |ev| {
                if let Some(s) = weak.upgrade() {
                    s.record_ext_audit(ev);
                }
            }),
        );
    }
    hub.spawn_pusher();
    let _ = state.certs.set(ctx.certs().clone());
    if let Some(r) = ctx.roots() {
        let _ = state.roots.set(r.cell.clone());
    }
    if let Some(p) = ctx.prober() {
        let _ = state.chain_probe.set(p.clone());
    }
    Ok(state)
}

/// Lets the API move the proxy's listeners and swap its access lists while it runs.
pub struct ProxyRuntime(pub Arc<crate::server::ProxyControl>);

fn bind(b: crate::server::BindInfo) -> web_api::ProxyBind {
    web_api::ProxyBind {
        proxy: b.proxy,
        transparent: b.transparent,
        proxy_down: b.proxy_down,
        transparent_down: b.transparent_down,
        proxy_error: b.proxy_error,
        transparent_error: b.transparent_error,
    }
}

#[async_trait::async_trait]
impl web_api::RuntimeControl for ProxyRuntime {
    async fn rebind_proxy(
        &self,
        host: &str,
        port: u16,
        transparent_port: Option<u16>,
    ) -> Result<web_api::ProxyBind, String> {
        self.0
            .rebind(host, port, transparent_port)
            .await
            .map(bind)
            .map_err(|e| e.to_string())
    }

    async fn apply_access(&self, config: &crate::config::ProxyConfig) -> Result<(), String> {
        self.0.apply_access(config).await.map_err(|e| e.to_string())
    }

    fn listener_counters(&self) -> (web_api::ListenerCounters, web_api::ListenerCounters) {
        let (e, t) = self.0.listener_counters();
        let c = |x: crate::listener_flags::ListenerCounters| web_api::ListenerCounters {
            active_connections: x.active_connections,
            requests_per_sec: x.requests_per_sec,
            clients: x.clients,
        };
        (c(e), c(t))
    }

    async fn proxy_bind(&self) -> Option<web_api::ProxyBind> {
        self.0.bind_info().await.map(bind)
    }

    async fn issue_webui_cert(&self, sans: &[String]) -> Result<(String, String), String> {
        self.0
            .issue_webui_cert(sans.to_vec())
            .await
            .map_err(|e| e.to_string())
    }

    async fn note_webui(&self, host: &str, port: u16) {
        self.0.set_webui_listener(host, port).await;
    }
}

use std::path::PathBuf;
use std::sync::Arc;

use filter_engine::{compile_engine, SharedEngine};
use proxy_core::config::{
    AdblockSettings, MitmSettings, PerformanceSettings, ProxyConfig, ProxySettings,
    UserscriptSettings, WebUiSettings,
};
use proxy_core::upstream::{build_upstream_client, UpstreamOptions};
use proxy_core::{ProxyContext, ProxyServer};
use tokio::net::TcpListener;
use tokio::sync::broadcast;

use crate::{EntryMode, TestOrigin};

/// The real proxy running in-process on an ephemeral port.
pub struct TestProxy {
    pub mode: EntryMode,
    pub addr: std::net::SocketAddr,
    /// PEM of the freshly generated proxy CA (what a client must trust).
    pub ca_pem: Vec<u8>,
    pub engine: Arc<SharedEngine>,
    shutdown: broadcast::Sender<()>,
    _dir: tempfile::TempDir,
}

impl TestProxy {
    /// Start a proxy that trusts `origin`'s CA, resolves every hostname to the origin, and
    /// filters with `rules` (filter-list text lines, compiled directly, no downloads).
    pub async fn start(
        mode: EntryMode,
        origin: &TestOrigin,
        rules: &[&str],
    ) -> Result<Self, String> {
        if mode == EntryMode::Transparent {
            return Err("transparent entry mode is not implemented yet".into());
        }
        crate::init_crypto();

        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let ca_cert_path = dir.path().join("ca.crt");
        let ca_key_path = dir.path().join("ca.key");
        let origin_ca_path = dir.path().join("origin-ca.crt");
        std::fs::write(&origin_ca_path, origin.ca_pem()).map_err(|e| e.to_string())?;

        let config = ProxyConfig {
            proxy: ProxySettings {
                host: "127.0.0.1".into(),
                port: 0,
                enable_http2: true,
                enable_http3: false,
                enable_websockets: true,
                extra_upstream_ca_paths: vec![origin_ca_path],
            },
            mitm: MitmSettings {
                enabled: true,
                ca_cert_path: ca_cert_path.clone(),
                ca_key_path,
                cert_cache_size: 100,
                cert_ttl_days: 1,
                cert_idle_timeout_secs: 60,
            },
            performance: PerformanceSettings {
                max_connections: 1000,
                max_cert_generations: 16,
                max_html_buffers: 16,
                connection_timeout_secs: 10,
                request_timeout_secs: 10,
                connection_rate_limit: Some(100_000),
            },
            adblock: AdblockSettings {
                data_dir: PathBuf::from(dir.path()).join("adblock"),
                ..AdblockSettings::default()
            },
            userscripts: UserscriptSettings::default(),
            webui: WebUiSettings::default(),
        };

        let engine = Arc::new(SharedEngine::new());
        engine.set_enabled(true);
        let lines: Vec<String> = rules.iter().map(|r| format!("{r}\n")).collect();
        engine.install(compile_engine(&lines));

        let client = build_upstream_client(&UpstreamOptions {
            resolve_all_to: Some(origin.ip()),
            ..UpstreamOptions::from_config(&config)
        })
        .map_err(|e| e.to_string())?;
        let ctx = Arc::new(ProxyContext::new(engine.clone(), client, true));
        let server = ProxyServer::new(config, ctx).map_err(|e| e.to_string())?;
        let ca_pem = std::fs::read(&ca_cert_path).map_err(|e| e.to_string())?;

        // Bind and keep the listener: connections queue in the backlog until `serve` accepts, so
        // there is nothing to poll for readiness.
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| e.to_string())?;
        let addr = listener.local_addr().map_err(|e| e.to_string())?;
        let (shutdown, _) = broadcast::channel(1);
        let tx = shutdown.clone();
        tokio::spawn(async move {
            let _ = server.serve(listener, tx).await;
        });

        Ok(Self {
            mode,
            addr,
            ca_pem,
            engine,
            shutdown,
            _dir: dir,
        })
    }

    /// `http://127.0.0.1:<port>` of the proxy.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

impl Drop for TestProxy {
    fn drop(&mut self) {
        let _ = self.shutdown.send(());
    }
}

use std::path::PathBuf;
use std::sync::Arc;

use filter_engine::SharedEngine;
use proxy_core::config::{
    AdblockSettings, MitmSettings, PerformanceSettings, ProxyConfig, ProxySettings,
    UserscriptSettings, WebUiSettings,
};
use proxy_core::upstream::UpstreamOptions;
use proxy_core::{ProxyContext, ProxyServer};
use tokio::net::TcpListener;
use tokio::sync::broadcast;

use crate::{EntryMode, TestOrigin};
use parking_lot::Mutex;
use proxy_core::transparent::OriginalDst;
use std::net::SocketAddr;

/// Test [`OriginalDst`]: every transparent connection "was headed" to the origin (its TLS port
/// when the client speaks TLS, its plain port otherwise), unless a destination is forced.
pub struct TestDst {
    https: SocketAddr,
    http: SocketAddr,
    forced: Mutex<Option<SocketAddr>>,
}

impl TestDst {
    /// Report `addr` as the original destination of every later connection.
    pub fn force(&self, addr: SocketAddr) {
        *self.forced.lock() = Some(addr);
    }
}

#[async_trait::async_trait]
impl OriginalDst for TestDst {
    async fn original_dst(&self, stream: &tokio::net::TcpStream) -> std::io::Result<SocketAddr> {
        if let Some(a) = *self.forced.lock() {
            return Ok(a);
        }
        let mut first = [0u8; 1];
        stream.peek(&mut first).await?;
        Ok(if first[0] == 0x16 {
            self.https
        } else {
            self.http
        })
    }
}

/// Compile `rules` as one filter list and install engine and extended-rule index together, the
/// way the list service does. The list is trusted (extended rules that run code are active)
/// unless `rules` contains the comment line `!untrusted`.
pub fn install_rules(engine: &SharedEngine, rules: &[&str]) {
    let trusted = !rules.contains(&"!untrusted");
    let text: String = rules.iter().map(|r| format!("{r}\n")).collect();
    let built = filter_engine::build_set(&[filter_engine::ListInput {
        id: "test".into(),
        content: text,
        format: filter_engine::ListFormat::Abp,
        allowlist: false,
        trusted,
        includes: Default::default(),
    }]);
    let mut ext = built.ext;
    for e in &mut ext {
        e.trusted = trusted;
    }
    let index = Arc::new(ext_rules::ExtIndex::build(&ext));
    let live = filter_engine::build_engine(&built.blob, &engine.resources());
    engine.install_set_with(
        Arc::new(built.blob),
        live,
        Some(index),
        Arc::new(ext),
        Arc::new(built.ip),
        Arc::new(built.domains),
    );
}

/// The real proxy running in-process on an ephemeral port.
pub struct TestProxy {
    pub mode: EntryMode,
    /// The explicit-proxy listener.
    pub addr: std::net::SocketAddr,
    /// The transparent listener (only in [`EntryMode::Transparent`]).
    pub transparent_addr: Option<std::net::SocketAddr>,
    /// The injected original-destination source (transparent mode).
    pub dst: Arc<TestDst>,
    /// PEM of the freshly generated proxy CA (what a client must trust).
    pub ca_pem: Vec<u8>,
    pub engine: Arc<SharedEngine>,
    /// The proxy's MITM handler (cert cache / generation counter).
    pub mitm: Option<Arc<proxy_core::mitm::MitmHandler>>,
    /// The proxy's filtering/forwarding context (live settings).
    pub ctx: Arc<ProxyContext>,
    shutdown: broadcast::Sender<()>,
    dir: Option<tempfile::TempDir>,
}

impl TestProxy {
    /// Replace the installed rules (engine and extended-rule index swap as one generation).
    pub fn install_rules(&self, rules: &[&str]) {
        install_rules(&self.engine, rules);
    }

    /// Start a proxy that trusts `origin`'s CA, resolves every hostname to the origin, and
    /// filters with `rules` (filter-list text lines, compiled directly, no downloads).
    pub async fn start(
        mode: EntryMode,
        origin: &TestOrigin,
        rules: &[&str],
    ) -> Result<Self, String> {
        Self::start_with(mode, origin, rules, &[]).await
    }

    /// Like [`Self::start`] with `tls_passthrough_hosts` configured.
    pub async fn start_with(
        mode: EntryMode,
        origin: &TestOrigin,
        rules: &[&str],
        passthrough: &[&str],
    ) -> Result<Self, String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        Self::start_in_with(mode, origin, rules, passthrough, dir, &|_| {}).await
    }

    /// Like [`Self::start`], letting `tweak` edit the proxy configuration first.
    pub async fn start_tweaked(
        mode: EntryMode,
        origin: &TestOrigin,
        rules: &[&str],
        tweak: &dyn Fn(&mut ProxyConfig),
    ) -> Result<Self, String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        Self::start_in_with(mode, origin, rules, &[], dir, tweak).await
    }

    /// Like [`Self::start`] but on an existing data dir, so a second proxy picks up the CA the
    /// first one generated (a restart).
    pub async fn start_in(
        mode: EntryMode,
        origin: &TestOrigin,
        rules: &[&str],
        dir: tempfile::TempDir,
    ) -> Result<Self, String> {
        Self::start_in_with(mode, origin, rules, &[], dir, &|_| {}).await
    }

    async fn start_in_with(
        mode: EntryMode,
        origin: &TestOrigin,
        rules: &[&str],
        passthrough: &[&str],
        dir: tempfile::TempDir,
        tweak: &dyn Fn(&mut ProxyConfig),
    ) -> Result<Self, String> {
        crate::init_crypto();

        let ca_cert_path = dir.path().join("ca.crt");
        let ca_key_path = dir.path().join("ca.key");
        let origin_ca_path = dir.path().join("origin-ca.crt");
        std::fs::write(&origin_ca_path, origin.ca_pem()).map_err(|e| e.to_string())?;

        let mut config = ProxyConfig {
            proxy: ProxySettings {
                host: "127.0.0.1".into(),
                port: 0,
                enable_http2: true,
                transparent_port: (mode == EntryMode::Transparent).then_some(0),
                tls_passthrough_hosts: passthrough.iter().map(|s| s.to_string()).collect(),
                block_private_destinations: false,
                allowed_destinations: Vec::new(),
                allowed_clients: proxy_core::config::default_allowed_clients(),
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

        tweak(&mut config);

        let engine = Arc::new(SharedEngine::new());
        engine.set_enabled(true);
        install_rules(&engine, rules);

        let ctx = Arc::new(
            ProxyContext::with_upstream(
                engine.clone(),
                &UpstreamOptions {
                    resolve_all_to: Some(origin.ip()),
                    ..UpstreamOptions::from_config(&config)
                },
                true,
            )
            .map_err(|e| e.to_string())?,
        );
        ctx.set_respect_no_transform(config.adblock.respect_no_transform);
        // A public-looking address (TEST-NET-3): the destination policy refuses loopback, and the
        // dial is redirected to the origin by the resolve override anyway.
        let fake = std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 7));
        let dst = Arc::new(TestDst {
            https: SocketAddr::new(fake, origin.https_port()),
            http: SocketAddr::new(fake, origin.http_port()),
            forced: Mutex::new(None),
        });
        let server = ProxyServer::new(config, ctx.clone())
            .map_err(|e| e.to_string())?
            .with_original_dst(dst.clone());
        let mitm = server.mitm_handler().cloned();
        let ca_pem = std::fs::read(&ca_cert_path).map_err(|e| e.to_string())?;

        // Bind and keep the listener: connections queue in the backlog until `serve` accepts, so
        // there is nothing to poll for readiness.
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| e.to_string())?;
        let addr = listener.local_addr().map_err(|e| e.to_string())?;
        let transparent = if mode == EntryMode::Transparent {
            Some(
                TcpListener::bind("127.0.0.1:0")
                    .await
                    .map_err(|e| e.to_string())?,
            )
        } else {
            None
        };
        let transparent_addr = transparent.as_ref().and_then(|l| l.local_addr().ok());
        let (shutdown, _) = broadcast::channel(1);
        let tx = shutdown.clone();
        tokio::spawn(async move {
            let _ = server.serve_all(listener, transparent, tx).await;
        });

        Ok(Self {
            mode,
            addr,
            transparent_addr,
            dst,
            ca_pem,
            engine,
            mitm,
            ctx,
            shutdown,
            dir: Some(dir),
        })
    }

    /// The listener a client of this entry mode dials directly (explicit proxy port, or the
    /// transparent port).
    pub fn entry_addr(&self) -> SocketAddr {
        self.transparent_addr.unwrap_or(self.addr)
    }

    /// `http://127.0.0.1:<port>` of the proxy.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

impl TestProxy {
    /// Stop the proxy and hand back its data dir (CA included) for a restart.
    pub fn stop(mut self) -> tempfile::TempDir {
        let _ = self.shutdown.send(());
        self.dir.take().expect("data dir")
    }
}

impl Drop for TestProxy {
    fn drop(&mut self) {
        let _ = self.shutdown.send(());
    }
}

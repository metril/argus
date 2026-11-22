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
    install_rules_text(engine, text, trusted);
}

/// Compile `text` (one ABP list) and install it as [`install_rules`] does; the same steps the
/// list service runs after a rebuild.
pub fn install_rules_text(engine: &SharedEngine, text: String, trusted: bool) {
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
    userscripts: Mutex<Option<Arc<userscript_engine::UserscriptManager>>>,
    script: Mutex<Option<ScriptHandles>>,
    profiles: Mutex<Option<ProfileHandles>>,
}

/// Per-device profile service attached to the proxy (see [`TestProxy::profiles`]).
#[derive(Clone)]
pub struct ProfileHandles {
    pub store: Arc<common::profile_store::ProfileStore>,
    pub builder: Arc<proxy_core::ProfileBuilder>,
    pub lists: Arc<list_service::ListService>,
    pub policy: Arc<script_policy::store::PolicyStore>,
    pub manager: Arc<userscript_engine::UserscriptManager>,
}

impl ProfileHandles {
    /// Create a profile with overlay `rules`; returns its id.
    pub fn profile(&self, name: &str, rules: &str) -> u64 {
        use common::profile_store::ProfileRecord;
        let now = chrono_now();
        self.store
            .put(ProfileRecord {
                id: 0,
                name: name.into(),
                description: String::new(),
                lists: vec![],
                rules: rules.into(),
                created_at: now,
                updated_at: now,
            })
            .expect("put profile")
            .id
    }

    /// Create a device on `profile` selected by `ips`; returns its id.
    pub fn device(&self, name: &str, profile: u64, ips: &[&str]) -> u64 {
        use common::profile_store::DeviceRecord;
        self.store
            .put_device(DeviceRecord {
                id: 0,
                name: name.into(),
                profile_id: profile,
                ips: ips
                    .iter()
                    .map(|s| {
                        s.parse::<ipnet::IpNet>().unwrap_or_else(|_| {
                            ipnet::IpNet::from(s.parse::<std::net::IpAddr>().expect("ip"))
                        })
                    })
                    .collect(),
                token_digest: None,
                token_hint: None,
                created_at: chrono_now(),
            })
            .expect("put device")
            .id
    }

    /// Issue a token for `device`.
    pub fn token(&self, device: u64) -> String {
        self.store.issue_token(device).expect("issue token")
    }

    /// Rebuild the live table from the stored state now.
    pub async fn sync(&self) {
        self.builder.sync().await;
    }

    /// The storage namespace (userscripts, GM values, policy) of `profile`.
    pub fn namespace(&self, profile: u64) -> String {
        common::profile_store::namespace(profile)
    }
}

fn chrono_now() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now()
}

/// The script-policy store and the control attached to the proxy.
pub type ScriptHandles = (
    Arc<script_policy::store::PolicyStore>,
    Arc<proxy_core::scriptctl::ScriptControl>,
);

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
                require_device_token: false,
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
            script_control: Default::default(),
            webui: WebUiSettings::default(),
            dns: Default::default(),
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
            userscripts: Mutex::new(None),
            script: Mutex::new(None),
            profiles: Mutex::new(None),
        })
    }

    /// The listener a client of this entry mode dials directly (explicit proxy port, or the
    /// transparent port).
    pub fn entry_addr(&self) -> SocketAddr {
        self.transparent_addr.unwrap_or(self.addr)
    }

    /// The proxy's userscript manager (created and attached on first use, backed by a database
    /// inside the proxy's data dir).
    pub fn userscripts(&self) -> Arc<userscript_engine::UserscriptManager> {
        let mut g = self.userscripts.lock();
        if let Some(m) = g.as_ref() {
            return m.clone();
        }
        let dir = self.dir.as_ref().expect("data dir").path().join("us");
        let m = Arc::new(userscript_engine::UserscriptManager::new(dir).expect("manager"));
        self.ctx.set_userscripts(Some(m.clone()));
        *g = Some(m.clone());
        m
    }

    /// The script-policy store and control of the default profile (created and attached on
    /// first use, in a database inside the proxy's data dir). `clock` replaces the system clock.
    pub fn script_control_with(&self, clock: Option<script_policy::store::Clock>) -> ScriptHandles {
        let mut g = self.script.lock();
        if let Some(h) = g.as_ref() {
            return h.clone();
        }
        let dir = self.dir.as_ref().expect("data dir").path().join("pol");
        let db = common::db::Db::open(&dir).expect("policy db");
        let store = Arc::new(match clock {
            Some(c) => script_policy::store::PolicyStore::with_clock(db, c),
            None => script_policy::store::PolicyStore::new(db),
        });
        let control = proxy_core::scriptctl::ScriptControl::new(
            store.clone(),
            script_policy::DEFAULT_PROFILE,
        );
        self.ctx.set_script_control(Some(control.clone()));
        *g = Some((store, control));
        g.as_ref().expect("set").clone()
    }

    /// The per-device profile service (created and attached on first use): a profile store that
    /// accepts loopback device addresses (so devices can be told apart by `127.0.0.N` source
    /// addresses), the policy store, the userscript manager and a running profile builder.
    pub fn profiles(&self) -> ProfileHandles {
        if let Some(h) = self.profiles.lock().as_ref() {
            return h.clone();
        }
        let dir = self.dir.as_ref().expect("data dir").path().to_path_buf();
        let manager = self.userscripts();
        let policy = self.script_control().0;
        let db = common::db::Db::open(&dir.join("prof")).expect("profile db");
        let store = Arc::new(
            common::profile_store::ProfileStore::open_allowing_loopback(&db).expect("store"),
        );
        let list_store = list_service::ListStore::open(&dir.join("lists")).expect("list store");
        let lists = list_service::ListService::new(
            list_service::ListServiceConfig {
                data_dir: dir.join("lists"),
                ..Default::default()
            },
            list_store,
            self.engine.clone(),
            reqwest::Client::new(),
        );
        let builder = proxy_core::ProfileBuilder::start(proxy_core::BuilderDeps {
            ctx: self.ctx.clone(),
            store: store.clone(),
            lists: lists.clone(),
            manager: Some(manager.clone()),
            policy: Some(policy.clone()),
            debounce: std::time::Duration::from_millis(20),
        });
        self.ctx.set_profile_service(store.clone(), builder.clone());
        let h = ProfileHandles {
            store,
            builder,
            lists,
            policy,
            manager,
        };
        *self.profiles.lock() = Some(h.clone());
        h
    }

    pub fn script_control(&self) -> ScriptHandles {
        self.script_control_with(None)
    }

    /// Install `source` for the default profile (no dependencies; `@connect *` not approved).
    pub fn install_userscript(&self, source: &str) -> String {
        self.install_userscript_with(
            source,
            userscript_engine::install::Fetched::default(),
            false,
        )
    }

    /// Install with fetched `@require`/`@resource` bodies and an explicit `@connect *` approval.
    pub fn install_userscript_with(
        &self,
        source: &str,
        fetched: userscript_engine::install::Fetched,
        allow_connect_all: bool,
    ) -> String {
        self.install_userscript_in(
            userscript_engine::DEFAULT_PROFILE,
            source,
            fetched,
            allow_connect_all,
        )
    }

    /// Install into the storage namespace `ns` (see [`ProfileHandles::namespace`]).
    pub fn install_userscript_in(
        &self,
        ns: &str,
        source: &str,
        fetched: userscript_engine::install::Fetched,
        allow_connect_all: bool,
    ) -> String {
        use userscript_engine::install::{finish_install, plan_install, Approvals};
        let plan = plan_install(source, None).expect("plan");
        let script =
            finish_install(plan, fetched, Approvals { allow_connect_all }).expect("finish");
        self.userscripts()
            .install_script(ns, script)
            .expect("install")
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

//! Stored profiles and devices driving the real proxy through `ProfileBuilder`. Port 0, temp
//! dirs, no shared state between tests.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use chrono::Utc;
use common::profile_store::{DeviceRecord, ProfileRecord, ProfileStore};
use filter_engine::{FilterList, SharedEngine};
use list_service::{ListService, ListServiceConfig, ListStore};
use proxy_core::config::{
    AdblockSettings, MitmSettings, PerformanceSettings, ProxyConfig, ProxySettings,
    UserscriptSettings, WebUiSettings,
};
use proxy_core::panel::{ListSiteBlocking, SiteBlocking};
use proxy_core::{BuilderDeps, ProfileBuilder, ProxyContext, ProxyServer};
use script_policy::store::PolicyStore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use userscript_engine::UserscriptManager;

const LOCALHOST: &str = "127.0.0.1";

fn config(port: u16) -> ProxyConfig {
    ProxyConfig {
        proxy: ProxySettings {
            host: LOCALHOST.to_string(),
            port,
            enable_http2: false,
            transparent_port: None,
            ext_port: None,
            tls_passthrough_hosts: Vec::new(),
            block_private_destinations: false,
            allowed_destinations: Vec::new(),
            allowed_clients: proxy_core::config::default_allowed_clients(),
            enable_websockets: false,
            extra_upstream_ca_paths: Vec::new(),
            require_device_token: false,
            upstream: Default::default(),
            explicit: Default::default(),
            transparent: Default::default(),
        },
        mitm: MitmSettings {
            enabled: false,
            ca_cert_path: std::env::temp_dir().join("pb-test-ca.crt"),
            ca_key_path: std::env::temp_dir().join("pb-test-ca.key"),
            cert_cache_size: 10,
            cert_ttl_days: 1,
            cert_idle_timeout_secs: 60,
        },
        performance: PerformanceSettings {
            max_connections: 100,
            max_cert_generations: 10,
            max_html_buffers: 10,
            connection_timeout_secs: 5,
            request_timeout_secs: 10,
            connection_rate_limit: Some(1000),
        },
        adblock: AdblockSettings::default(),
        userscripts: UserscriptSettings::default(),
        script_control: Default::default(),
        webui: WebUiSettings::default(),
        dns: Default::default(),
        bypass: Default::default(),
        stealth: Default::default(),
    }
}

/// Origin answering every request with "origin-hello".
async fn spawn_origin() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                let _ = s.read(&mut buf).await;
                let _ = s
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\norigin-hello",
                    )
                    .await;
            });
        }
    });
    port
}

struct Fx {
    ctx: Arc<ProxyContext>,
    proxy: u16,
    origin: u16,
    store: Arc<ProfileStore>,
    lists: Arc<ListService>,
    builder: Arc<ProfileBuilder>,
    policy: Arc<PolicyStore>,
    manager: Arc<UserscriptManager>,
    default: Arc<SharedEngine>,
    _dir: tempfile::TempDir,
}

/// Lists `ads` (blocks `/ads/`) and `trk` (blocks `/trk/`), both disabled globally.
async fn fixture() -> Fx {
    let dir = tempfile::tempdir().unwrap();
    let db = common::db::Db::open(dir.path()).unwrap();
    let store = Arc::new(ProfileStore::open(&db).unwrap());
    let policy = Arc::new(PolicyStore::new(db.clone()));
    let list_store = ListStore::open(dir.path()).unwrap();
    for (id, rule) in [("ads", "/ads/"), ("trk", "/trk/")] {
        let l = FilterList::new(id.into(), id.into(), format!("http://127.0.0.1:1/{id}.txt"));
        list_store.upsert(&l).unwrap();
        list_store.put_content(id, &format!("{rule}\n")).unwrap();
    }
    let default = Arc::new(SharedEngine::new());
    let lists = ListService::new(
        ListServiceConfig {
            data_dir: dir.path().to_path_buf(),
            ..Default::default()
        },
        list_store,
        default.clone(),
        reqwest::Client::new(),
    );
    let manager = Arc::new(UserscriptManager::new(dir.path().join("us")).unwrap());
    let ctx = Arc::new(
        ProxyContext::new(default.clone(), true).with_policy(Arc::new(
            proxy_core::policy::DestPolicy::new(false, &["127.0.0.0/8".to_string()]).unwrap(),
        )),
    );
    let builder = ProfileBuilder::start(BuilderDeps {
        ctx: ctx.clone(),
        store: store.clone(),
        lists: lists.clone(),
        manager: Some(manager.clone()),
        policy: Some(policy.clone()),
        debounce: Duration::from_millis(20),
    });
    ctx.set_profile_service(store.clone(), builder.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap().port();
    let server = ProxyServer::new(config(proxy), ctx.clone()).unwrap();
    let (tx, _) = tokio::sync::broadcast::channel(1);
    tokio::spawn(async move {
        let _ = server.serve(listener, tx).await;
    });
    Fx {
        ctx,
        proxy,
        origin: spawn_origin().await,
        store,
        lists,
        builder,
        policy,
        manager,
        default,
        _dir: dir,
    }
}

fn profile(name: &str, lists: &[&str], rules: &str) -> ProfileRecord {
    ProfileRecord {
        id: 0,
        name: name.into(),
        description: String::new(),
        lists: lists.iter().map(|s| s.to_string()).collect(),
        rules: rules.into(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn device(name: &str, profile_id: u64, ips: &[&str]) -> DeviceRecord {
    DeviceRecord {
        id: 0,
        name: name.into(),
        profile_id,
        ips: ips.iter().map(|s| s.parse().unwrap()).collect(),
        token_digest: None,
        token_hint: None,
        created_at: Utc::now(),
    }
}

/// A device with a fresh token on profile `profile_id`; returns the raw token.
fn token_device(f: &Fx, name: &str, profile_id: u64) -> (DeviceRecord, String) {
    let d = f.store.put_device(device(name, profile_id, &[])).unwrap();
    let t = f.store.issue_token(d.id).unwrap();
    (d, t)
}

struct Reply {
    status: u16,
    body: String,
}

impl Reply {
    fn reached_origin(&self) -> bool {
        self.status == 200 && self.body == "origin-hello"
    }
}

async fn read_reply(s: &mut TcpStream) -> Reply {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut tmp))
            .await
            .expect("reply timeout")
            .unwrap();
        assert!(n > 0, "closed before head");
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
    let status = head[9..12].parse().unwrap();
    let len = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    while buf.len() < end + len {
        let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut tmp))
            .await
            .expect("body timeout")
            .unwrap();
        assert!(n > 0, "closed mid-body");
        buf.extend_from_slice(&tmp[..n]);
    }
    Reply {
        status,
        body: String::from_utf8_lossy(&buf[end..end + len]).into_owned(),
    }
}

async fn request_with(
    s: &mut TcpStream,
    f: &Fx,
    path: &str,
    token: Option<&str>,
    referer: Option<&str>,
) -> Reply {
    let auth = token
        .map(|t| {
            format!(
                "Proxy-Authorization: Basic {}\r\n",
                base64::engine::general_purpose::STANDARD.encode(format!("dev:{t}"))
            )
        })
        .unwrap_or_default();
    let referer = referer
        .map(|r| format!("Referer: {r}\r\n"))
        .unwrap_or_default();
    let req = format!(
        "GET http://{LOCALHOST}:{o}{path} HTTP/1.1\r\nHost: {LOCALHOST}:{o}\r\n{auth}{referer}\r\n",
        o = f.origin
    );
    s.write_all(req.as_bytes()).await.unwrap();
    read_reply(s).await
}

async fn request(s: &mut TcpStream, f: &Fx, path: &str, token: Option<&str>) -> Reply {
    request_with(s, f, path, token, None).await
}

async fn connect(f: &Fx) -> TcpStream {
    TcpStream::connect((LOCALHOST, f.proxy)).await.unwrap()
}

fn engine_of(f: &Fx, id: u64) -> Arc<SharedEngine> {
    f.ctx
        .profiles()
        .table()
        .slot(id)
        .expect("slot")
        .load()
        .engine
        .clone()
}

#[tokio::test]
async fn stored_profiles_and_devices_drive_requests() {
    let f = fixture().await;
    let a = f.store.put(profile("alpha", &["ads"], "/extra/")).unwrap();
    let b = f.store.put(profile("beta", &["trk"], "")).unwrap();
    let (_, ta) = token_device(&f, "phone", a.id);
    let (_, tb) = token_device(&f, "tablet", b.id);
    f.builder.sync().await;

    let mut s = connect(&f).await;
    // Token a: alpha's list and overlay rules.
    assert!(!request(&mut s, &f, "/ads/1", Some(&ta))
        .await
        .reached_origin());
    assert!(!request(&mut s, &f, "/extra/1", Some(&ta))
        .await
        .reached_origin());
    assert!(request(&mut s, &f, "/trk/1", Some(&ta))
        .await
        .reached_origin());
    // Token b: beta's list only.
    let mut s = connect(&f).await;
    assert!(!request(&mut s, &f, "/trk/1", Some(&tb))
        .await
        .reached_origin());
    assert!(request(&mut s, &f, "/ads/1", Some(&tb))
        .await
        .reached_origin());
    assert!(request(&mut s, &f, "/extra/1", Some(&tb))
        .await
        .reached_origin());
    // No token: the default profile, which has none of those lists.
    let mut s = connect(&f).await;
    assert!(request(&mut s, &f, "/ads/1", None).await.reached_origin());
}

#[tokio::test]
async fn device_addresses_and_prefixes_resolve_to_their_profile() {
    let f = fixture().await;
    let a = f.store.put(profile("alpha", &["ads"], "")).unwrap();
    let b = f.store.put(profile("beta", &["trk"], "")).unwrap();
    f.store
        .put_device(device("one", a.id, &["192.168.1.10/32"]))
        .unwrap();
    f.store
        .put_device(device("net", b.id, &["192.168.1.0/24", "fd00::/64"]))
        .unwrap();
    f.builder.sync().await;
    let id_of = |ip: &str| {
        f.ctx
            .profiles()
            .resolve(ip.parse().unwrap(), None)
            .0
            .load()
            .id
    };
    assert_eq!(id_of("192.168.1.10"), a.id, "exact address");
    assert_eq!(id_of("192.168.1.77"), b.id, "prefix");
    assert_eq!(id_of("fd00::5"), b.id);
    assert_eq!(id_of("10.9.9.9"), 0, "default");
}

#[tokio::test]
async fn rule_edit_reaches_an_open_connection_without_a_new_epoch() {
    let f = fixture().await;
    let a = f.store.put(profile("alpha", &["ads"], "")).unwrap();
    let (_, t) = token_device(&f, "phone", a.id);
    f.builder.sync().await;
    let mut s = connect(&f).await;
    assert!(request(&mut s, &f, "/new/1", Some(&t))
        .await
        .reached_origin());
    let epoch = f.ctx.profiles().epoch();
    let gen = f
        .ctx
        .profiles()
        .table()
        .slot(a.id)
        .unwrap()
        .load()
        .generation;

    let mut edited = f.store.get(a.id).unwrap().unwrap();
    edited.rules = "/new/".into();
    f.store.put(edited).unwrap();
    f.builder.sync().await;

    assert_eq!(
        f.ctx.profiles().epoch(),
        epoch,
        "contents only: no new table"
    );
    assert!(
        f.ctx
            .profiles()
            .table()
            .slot(a.id)
            .unwrap()
            .load()
            .generation
            > gen
    );
    assert!(!request(&mut s, &f, "/new/2", Some(&t))
        .await
        .reached_origin());
}

#[tokio::test]
async fn reassigning_a_device_re_resolves_on_the_next_request() {
    let f = fixture().await;
    let a = f.store.put(profile("alpha", &["ads"], "")).unwrap();
    let b = f.store.put(profile("beta", &["trk"], "")).unwrap();
    let (d, t) = token_device(&f, "phone", a.id);
    f.builder.sync().await;
    let mut s = connect(&f).await;
    assert!(!request(&mut s, &f, "/ads/1", Some(&t))
        .await
        .reached_origin());
    let slot_a = f.ctx.profiles().table().slot(a.id).unwrap().clone();

    let mut moved = f.store.device(d.id).unwrap().unwrap();
    moved.profile_id = b.id;
    f.store.put_device(moved).unwrap();
    f.builder.sync().await;

    // Same keep-alive connection, now judged by beta.
    assert!(request(&mut s, &f, "/ads/2", Some(&t))
        .await
        .reached_origin());
    assert!(!request(&mut s, &f, "/trk/2", Some(&t))
        .await
        .reached_origin());
    // Unchanged profiles keep their slot across the publish.
    assert!(Arc::ptr_eq(
        &slot_a,
        f.ctx.profiles().table().slot(a.id).unwrap()
    ));
}

#[tokio::test]
async fn profiles_with_the_same_lists_share_one_engine() {
    let f = fixture().await;
    let a = f
        .store
        .put(profile("alpha", &["ads", "trk"], "/a/"))
        .unwrap();
    let b = f
        .store
        .put(profile("beta", &["trk", "ads"], "/b/"))
        .unwrap();
    let c = f.store.put(profile("gamma", &["ads"], "")).unwrap();
    f.builder.sync().await;
    // Slots exist once a device references them.
    for p in [&a, &b, &c] {
        f.store.put_device(device(&p.name, p.id, &[])).unwrap();
    }
    f.builder.sync().await;
    assert!(Arc::ptr_eq(&engine_of(&f, a.id), &engine_of(&f, b.id)));
    assert!(!Arc::ptr_eq(&engine_of(&f, a.id), &engine_of(&f, c.id)));
    assert_eq!(f.lists.set_build_count(), 2);
}

#[tokio::test]
async fn failed_build_keeps_previous_state_and_reports_status() {
    let f = fixture().await;
    // First build fails (missing list): serves the default engine and says why.
    let a = f.store.put(profile("alpha", &["nope"], "")).unwrap();
    f.builder.sync().await;
    let st = f.builder.status();
    assert!(st[&a.id].last_error.as_deref().unwrap().contains("nope"));
    assert!(st[&a.id].last_built.is_none());
    assert!(Arc::ptr_eq(&engine_of(&f, a.id), &f.default));

    // A good build replaces it and clears the error.
    let mut rec = f.store.get(a.id).unwrap().unwrap();
    rec.lists = vec!["ads".into()];
    let rec = f.store.put(rec).unwrap();
    f.builder.sync().await;
    assert!(f.builder.status()[&a.id].last_error.is_none());
    assert!(f.builder.status()[&a.id].last_built.is_some());
    let good = engine_of(&f, a.id);
    assert!(!Arc::ptr_eq(&good, &f.default));
    let gen = f
        .ctx
        .profiles()
        .table()
        .slot(a.id)
        .unwrap()
        .load()
        .generation;

    // A later failing edit keeps the previous compiled state and records the error.
    let mut bad = rec;
    bad.lists = vec!["ads".into(), "gone".into()];
    f.store.put(bad).unwrap();
    f.builder.sync().await;
    let st = f.builder.status();
    assert!(st[&a.id].last_error.as_deref().unwrap().contains("gone"));
    assert!(st[&a.id].last_built.is_some());
    assert!(Arc::ptr_eq(&engine_of(&f, a.id), &good));
    assert_eq!(
        f.ctx
            .profiles()
            .table()
            .slot(a.id)
            .unwrap()
            .load()
            .generation,
        gen
    );
}

fn script_source() -> &'static str {
    "// ==UserScript==\n// @name n\n// @namespace t\n// @version 1.0\n// @match *://hit.test/*\n// ==/UserScript==\n1;\n"
}

fn install_script(m: &UserscriptManager, profile: &str) {
    use userscript_engine::install::{finish_install, plan_install, Approvals, Fetched};
    let plan = plan_install(script_source(), None).unwrap();
    let s = finish_install(plan, Fetched::default(), Approvals::default()).unwrap();
    m.install_script(profile, s).unwrap();
}

async fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..200 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test]
async fn deleting_a_profile_removes_its_data_and_stops_its_expiry_task() {
    use script_policy::{Preset, Scope};
    let f = fixture().await;
    let a = f.store.put(profile("doomed", &["ads"], "")).unwrap();
    let ns = common::profile_store::namespace(a.id);
    let d = f.store.put_device(device("phone", a.id, &[])).unwrap();
    f.builder.sync().await;
    let control = f
        .ctx
        .profiles()
        .table()
        .slot(a.id)
        .unwrap()
        .load()
        .script_control
        .clone()
        .expect("script control");
    assert_eq!(control.profile_name(), &ns);
    assert!(control.expiry_running());
    install_script(&f.manager, &ns);
    f.policy
        .create_site_rule(
            &ns,
            Scope::parse("example.com").unwrap(),
            Preset::Trusted,
            None,
        )
        .unwrap();
    for _ in 0..8 {
        f.policy.pin_failed(&ns, "10.0.0.1").unwrap();
    }
    assert_eq!(f.manager.get_all_in(&ns).len(), 1);

    // Devices first (the store refuses to delete a profile in use), then the profile.
    f.store.delete_device(d.id).unwrap();
    assert!(f.store.delete(a.id).unwrap());
    f.builder.sync().await;

    assert!(f.manager.get_all_in(&ns).is_empty());
    assert!(f.manager.index_for(&ns).is_empty());
    assert!(f.policy.rules(&ns).unwrap().site_rules.is_empty());
    assert_eq!(f.policy.pin_wait(&ns, "10.0.0.1").unwrap(), 0);
    assert!(f.ctx.profiles().table().slot(a.id).is_none());
    assert!(!f.builder.status().contains_key(&a.id));
    wait_until("the expiry task to end", || !control.expiry_running()).await;
    assert_eq!(
        f.policy.listener_count(),
        0,
        "deleted profile's listener removed"
    );

    // Recreated under the same name: a new id, so a new empty namespace.
    let again = f.store.put(profile("doomed", &["ads"], "")).unwrap();
    assert_ne!(again.id, a.id);
    f.store.put_device(device("phone", again.id, &[])).unwrap();
    f.builder.sync().await;
    assert!(f.manager.get_all_in(&ns).is_empty());
    assert!(f.policy.rules(&ns).unwrap().site_rules.is_empty());
}

/// A profile created and deleted inside one debounce window (never built), or deleted while the
/// proxy was down, leaves data behind; the next pass sweeps it, and never touches live profiles,
/// the default one, or a profile created after the pass read the store.
#[tokio::test]
async fn leftover_data_of_deleted_profiles_is_swept() {
    use script_policy::{Preset, Scope};
    let f = fixture().await;
    let live = f.store.put(profile("live", &["ads"], "")).unwrap();
    let gone = f.store.put(profile("gone", &["ads"], "")).unwrap();
    let (live_ns, gone_ns) = (
        common::profile_store::namespace(live.id),
        common::profile_store::namespace(gone.id),
    );
    for ns in [&live_ns, &gone_ns] {
        install_script(&f.manager, ns);
        f.policy
            .create_site_rule(
                ns,
                Scope::parse("example.com").unwrap(),
                Preset::Trusted,
                None,
            )
            .unwrap();
        for _ in 0..8 {
            f.policy.pin_failed(ns, "10.0.0.1").unwrap();
        }
    }
    install_script(&f.manager, userscript_engine::DEFAULT_PROFILE);
    // Deleted before the builder ever saw it.
    assert!(f.store.delete(gone.id).unwrap());
    f.builder.sync().await;
    assert!(f.manager.get_all_in(&gone_ns).is_empty(), "scripts swept");
    assert!(f.policy.rules(&gone_ns).unwrap().site_rules.is_empty());
    assert_eq!(f.policy.pin_wait(&gone_ns, "10.0.0.1").unwrap(), 0);
    assert!(!f.manager.stored_profiles().unwrap().contains(&gone_ns));
    assert!(!f.policy.stored_profiles().unwrap().contains(&gone_ns));
    // Everything else is untouched.
    assert_eq!(f.manager.get_all_in(&live_ns).len(), 1);
    assert_eq!(f.policy.rules(&live_ns).unwrap().site_rules.len(), 1);
    assert_eq!(
        f.manager
            .get_all_in(userscript_engine::DEFAULT_PROFILE)
            .len(),
        1
    );
    // A namespace above the id bound (a profile created after the read) is left alone.
    let future = common::profile_store::namespace(live.id + gone.id + 100);
    install_script(&f.manager, &future);
    f.store.put(profile("next", &[], "")).unwrap();
    f.builder.sync().await;
    assert_eq!(f.manager.get_all_in(&future).len(), 1);
}

#[tokio::test]
async fn panel_site_off_applies_to_the_requesting_profile_only() {
    let f = fixture().await;
    let a = f.store.put(profile("alpha", &["ads"], "")).unwrap();
    let b = f.store.put(profile("beta", &["ads"], "")).unwrap();
    let (_, ta) = token_device(&f, "phone", a.id);
    let (_, tb) = token_device(&f, "tablet", b.id);
    f.builder.sync().await;
    let blocking = ListSiteBlocking::new(f.lists.clone(), Some(f.store.clone()));
    let prof_a = f.ctx.profiles().table().slot(a.id).unwrap().load_full();

    let mut sa = connect(&f).await;
    let mut sb = connect(&f).await;
    let page = Some("http://site.test/");
    assert!(!request_with(&mut sa, &f, "/ads/1", Some(&ta), page)
        .await
        .reached_origin());

    assert!(!blocking.disabled(&prof_a, "site.test"));
    blocking.set_disabled(&prof_a, "site.test", true).unwrap();
    assert!(blocking.disabled(&prof_a, "site.test"));
    f.builder.sync().await;

    // Alpha's device is let through on that site; beta's is not; the global rules are untouched.
    assert!(request_with(&mut sa, &f, "/ads/2", Some(&ta), page)
        .await
        .reached_origin());
    assert!(!request_with(&mut sb, &f, "/ads/2", Some(&tb), page)
        .await
        .reached_origin());
    assert!(f.lists.store().get_custom_rules().unwrap().is_empty());
    assert!(f.store.get(b.id).unwrap().unwrap().rules.is_empty());

    // The default profile still uses the global custom rules.
    let default = f.ctx.default_profile().load_full();
    blocking.set_disabled(&default, "site.test", true).unwrap();
    assert!(f
        .lists
        .store()
        .get_custom_rules()
        .unwrap()
        .contains("site.test"));
    assert!(!f.store.get(a.id).unwrap().unwrap().rules.is_empty());
}

#[tokio::test]
async fn background_builder_follows_store_changes_without_sync() {
    let f = fixture().await;
    f.builder.wait_passes(1).await;
    let a = f.store.put(profile("alpha", &["ads"], "")).unwrap();
    let (_, t) = token_device(&f, "phone", a.id);
    let mut s = connect(&f).await;
    for _ in 0..200 {
        if !request(&mut s, &f, "/ads/1", Some(&t))
            .await
            .reached_origin()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the background builder never applied the profile");
}

//! Per-device profiles through the real proxy: token and IP resolution, 407, live edits,
//! reassignment on open connections, overlays, and GM namespaces. Port 0 everywhere, no shared
//! state between tests.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use filter_engine::{compile_engine, SharedEngine};
use proxy_core::config::{
    AdblockSettings, MitmSettings, PerformanceSettings, ProxyConfig, ProxySettings,
    UserscriptSettings, WebUiSettings,
};
use proxy_core::profiles::{token_digest, ProfileTable};
use proxy_core::request_ctx::{Profile, ProfileSlot};
use proxy_core::{ProxyContext, ProxyServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const LOCALHOST: &str = "127.0.0.1";

fn engine(rules: &[&str]) -> Arc<SharedEngine> {
    let e = Arc::new(SharedEngine::new());
    let rules: Vec<String> = rules.iter().map(|r| format!("{r}\n")).collect();
    e.install(compile_engine(&rules));
    e
}

fn slot(id: u64, e: Arc<SharedEngine>) -> ProfileSlot {
    Arc::new(arc_swap::ArcSwap::from_pointee(Profile::new(id, 0, e)))
}

fn config(port: u16, require_token: bool) -> ProxyConfig {
    ProxyConfig {
        proxy: ProxySettings {
            host: LOCALHOST.to_string(),
            port,
            enable_http2: false,
            transparent_port: None,
            tls_passthrough_hosts: Vec::new(),
            block_private_destinations: false,
            allowed_destinations: Vec::new(),
            allowed_clients: proxy_core::config::default_allowed_clients(),
            enable_websockets: false,
            extra_upstream_ca_paths: Vec::new(),
            require_device_token: require_token,
            explicit: Default::default(),
            transparent: Default::default(),
        },
        mitm: MitmSettings {
            enabled: false,
            ca_cert_path: std::env::temp_dir().join("prof-test-ca.crt"),
            ca_key_path: std::env::temp_dir().join("prof-test-ca.key"),
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
    }
}

/// Origin that answers every request with "origin-hello" and records the request heads.
async fn spawn_origin() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let rec = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let rec = rec.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                let n = s.read(&mut buf).await.unwrap_or(0);
                rec.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase());
                let _ = s
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\norigin-hello",
                    )
                    .await;
            });
        }
    });
    (port, seen)
}

struct Fixture {
    ctx: Arc<ProxyContext>,
    proxy: u16,
    origin: u16,
    seen: Arc<Mutex<Vec<String>>>,
}

async fn fixture(default: Arc<SharedEngine>, require_token: bool) -> Fixture {
    let (origin, seen) = spawn_origin().await;
    let ctx = Arc::new(
        ProxyContext::new(default, reqwest::Client::new(), true).with_policy(Arc::new(
            proxy_core::policy::DestPolicy::new(false, &["127.0.0.0/8".to_string()]).unwrap(),
        )),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap().port();
    let server = ProxyServer::new(config(proxy, require_token), ctx.clone()).unwrap();
    let (tx, _) = tokio::sync::broadcast::channel(1);
    tokio::spawn(async move {
        let _ = server.serve(listener, tx).await;
    });
    Fixture {
        ctx,
        proxy,
        origin,
        seen,
    }
}

fn basic(token: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("dev:{token}"))
    )
}

struct Reply {
    status: u16,
    head: String,
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
        assert!(
            n > 0,
            "closed before head: {:?}",
            String::from_utf8_lossy(&buf)
        );
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
        head,
        body: String::from_utf8_lossy(&buf[end..end + len]).into_owned(),
    }
}

async fn request(s: &mut TcpStream, f: &Fixture, path: &str, token: Option<&str>) -> Reply {
    let auth = token
        .map(|t| format!("Proxy-Authorization: {}\r\n", basic(t)))
        .unwrap_or_default();
    let req = format!(
        "GET http://{LOCALHOST}:{}{path} HTTP/1.1\r\nHost: {LOCALHOST}:{}\r\n{auth}\r\n",
        f.origin, f.origin
    );
    s.write_all(req.as_bytes()).await.unwrap();
    read_reply(s).await
}

async fn connect(f: &Fixture) -> TcpStream {
    TcpStream::connect((LOCALHOST, f.proxy)).await.unwrap()
}

/// Publish profiles 1 (`a`) and 2 (`b`) with tokens `tok-a` / `tok-b`; returns their slots.
fn publish_ab(
    f: &Fixture,
    a: &[&str],
    b: &[&str],
    ip_to: Option<u64>,
) -> (ProfileSlot, ProfileSlot) {
    let (sa, sb) = (slot(1, engine(a)), slot(2, engine(b)));
    let t = f.ctx.profiles().table();
    let mut builder = ProfileTable::builder(t.default_slot().clone())
        .profile(1, sa.clone())
        .profile(2, sb.clone())
        .token(token_digest(b"tok-a"), 1)
        .token(token_digest(b"tok-b"), 2);
    if let Some(id) = ip_to {
        builder = builder.ip(LOCALHOST.parse().unwrap(), id);
    }
    drop(t);
    f.ctx.profiles().publish(builder.build());
    (sa, sb)
}

#[tokio::test]
async fn two_profiles_block_differently() {
    let f = fixture(engine(&[]), false).await;
    publish_ab(&f, &["/ads/"], &["/tracker/"], None);
    for (tok, blocked, open) in [
        ("tok-a", "/ads/x", "/tracker/x"),
        ("tok-b", "/tracker/x", "/ads/x"),
    ] {
        let mut s = connect(&f).await;
        assert!(
            !request(&mut s, &f, blocked, Some(tok))
                .await
                .reached_origin(),
            "{tok} {blocked}"
        );
        let mut s = connect(&f).await;
        assert!(
            request(&mut s, &f, open, Some(tok)).await.reached_origin(),
            "{tok} {open}"
        );
    }
    // No token: default profile (no rules).
    let mut s = connect(&f).await;
    assert!(request(&mut s, &f, "/ads/x", None).await.reached_origin());
}

#[tokio::test]
async fn token_beats_ip_and_unknown_token_falls_back_to_ip() {
    let f = fixture(engine(&[]), false).await;
    // 127.0.0.1 -> profile 2 (blocks /tracker/); token a -> profile 1 (blocks /ads/).
    publish_ab(&f, &["/ads/"], &["/tracker/"], Some(2));
    let mut s = connect(&f).await;
    assert!(!request(&mut s, &f, "/ads/x", Some("tok-a"))
        .await
        .reached_origin());
    let mut s = connect(&f).await;
    assert!(request(&mut s, &f, "/tracker/x", Some("tok-a"))
        .await
        .reached_origin());
    // Unknown token: IP fallback (profile 2).
    let mut s = connect(&f).await;
    assert!(!request(&mut s, &f, "/tracker/x", Some("nope"))
        .await
        .reached_origin());
    let mut s = connect(&f).await;
    assert!(request(&mut s, &f, "/ads/x", None).await.reached_origin());
}

#[tokio::test]
async fn unknown_token_gets_407_when_required() {
    let f = fixture(engine(&[]), true).await;
    publish_ab(&f, &["/ads/"], &[], None);
    for tok in [None, Some("nope")] {
        let mut s = connect(&f).await;
        let r = request(&mut s, &f, "/x", tok).await;
        assert_eq!(r.status, 407);
        assert!(r.head.contains("proxy-authenticate: basic realm=\"argus\""));
    }
    let mut s = connect(&f).await;
    assert!(request(&mut s, &f, "/x", Some("tok-a"))
        .await
        .reached_origin());
    // CONNECT: 407 without a known token, 200 with one.
    let mut s = connect(&f).await;
    let req = format!(
        "CONNECT {LOCALHOST}:{} HTTP/1.1\r\nHost: x\r\n\r\n",
        f.origin
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let r = read_reply(&mut s).await;
    assert_eq!(r.status, 407);
    assert!(r.head.contains("proxy-authenticate"));
    let mut s = connect(&f).await;
    let req = format!(
        "CONNECT {LOCALHOST}:{} HTTP/1.1\r\nHost: x\r\nProxy-Authorization: {}\r\n\r\n",
        f.origin,
        basic("tok-a")
    );
    s.write_all(req.as_bytes()).await.unwrap();
    assert_eq!(read_reply(&mut s).await.status, 200);
}

/// Browsers send proxy credentials only after a 407 challenge: with the token required, the
/// challenge-then-retry exchange (the proxy closes after the 407, so the retry arrives on a new
/// connection) identifies the device.
#[tokio::test]
async fn credentials_sent_only_after_a_407_challenge_identify_the_device() {
    let f = fixture(engine(&[]), true).await;
    publish_ab(&f, &["/ads/"], &[], None);
    for (token, reaches_origin) in [("tok-a", false), ("tok-b", true)] {
        let mut s = connect(&f).await;
        let first = request(&mut s, &f, "/ads/x", None).await;
        assert_eq!(first.status, 407, "challenged first");
        let mut s = connect(&f).await;
        let retry = request(&mut s, &f, "/ads/x", Some(token)).await;
        assert_ne!(retry.status, 407, "{}", retry.head);
        assert_eq!(retry.reached_origin(), reaches_origin, "{token}");
    }
}

#[tokio::test]
async fn proxy_authorization_is_never_forwarded() {
    let f = fixture(engine(&[]), false).await;
    publish_ab(&f, &[], &[], None);
    let mut s = connect(&f).await;
    assert!(request(&mut s, &f, "/x", Some("tok-a"))
        .await
        .reached_origin());
    let seen = f.seen.lock().unwrap();
    assert!(!seen.is_empty());
    assert!(
        seen.iter().all(|h| !h.contains("proxy-authorization")),
        "{seen:?}"
    );
}

#[tokio::test]
async fn later_header_on_an_open_connection_cannot_switch_profile() {
    let f = fixture(engine(&[]), false).await;
    publish_ab(&f, &["/ads/"], &["/tracker/"], None);
    let mut s = connect(&f).await;
    assert!(!request(&mut s, &f, "/ads/x", Some("tok-a"))
        .await
        .reached_origin());
    // Same connection, token of b: must still be a (blocks /ads/, allows /tracker/).
    assert!(!request(&mut s, &f, "/ads/y", Some("tok-b"))
        .await
        .reached_origin());
    assert!(request(&mut s, &f, "/tracker/y", Some("tok-b"))
        .await
        .reached_origin());
}

#[tokio::test]
async fn reassignment_reaches_an_open_keepalive_connection() {
    let f = fixture(engine(&[]), false).await;
    publish_ab(&f, &["/ads/"], &[], Some(1));
    let mut s = connect(&f).await;
    assert!(!request(&mut s, &f, "/ads/1", None).await.reached_origin());
    // Move this device to profile 2 (blocks nothing).
    publish_ab(&f, &["/ads/"], &[], Some(2));
    assert!(request(&mut s, &f, "/ads/2", None).await.reached_origin());
}

#[tokio::test]
async fn profile_edit_reaches_an_open_connection_without_reresolve() {
    let f = fixture(engine(&[]), false).await;
    let (sa, _) = publish_ab(&f, &["/ads/"], &[], Some(1));
    let epoch = f.ctx.profiles().epoch();
    let mut s = connect(&f).await;
    assert!(!request(&mut s, &f, "/ads/1", None).await.reached_origin());
    let edited = sa.load().with(|p| p.engine = engine(&[]));
    assert!(f.ctx.profiles().edit(1, Arc::new(edited)));
    assert_eq!(
        f.ctx.profiles().epoch(),
        epoch,
        "edit must not bump the epoch"
    );
    assert!(request(&mut s, &f, "/ads/2", None).await.reached_origin());
}

#[tokio::test]
async fn overlay_exception_beats_base_block_and_overlay_block_beats_base_allow() {
    let f = fixture(engine(&[]), false).await;
    let (sa, _) = publish_ab(&f, &["/ads/"], &[], Some(1));
    let overlay = engine(&["@@/ads/ok", "/extra/"]);
    sa.store(Arc::new(sa.load().with(|p| p.overlay = Some(overlay))));
    let mut s = connect(&f).await;
    assert!(
        request(&mut s, &f, "/ads/ok", None).await.reached_origin(),
        "overlay exception"
    );
    let mut s = connect(&f).await;
    assert!(
        !request(&mut s, &f, "/ads/other", None)
            .await
            .reached_origin(),
        "base block stays"
    );
    let mut s = connect(&f).await;
    assert!(
        !request(&mut s, &f, "/extra/x", None).await.reached_origin(),
        "overlay block"
    );
    let mut s = connect(&f).await;
    assert!(request(&mut s, &f, "/fine", None).await.reached_origin());
}

/// Engine over `rules` that records into `base`'s statistics and obeys its master switch.
fn shared_engine(base: &SharedEngine, rules: &[&str]) -> Arc<SharedEngine> {
    let e = Arc::new(SharedEngine::with_shared(
        base.stats_handle(),
        base.block_log_handle(),
        base.enabled_flag(),
    ));
    let rules: Vec<String> = rules.iter().map(|r| format!("{r}\n")).collect();
    e.install(compile_engine(&rules));
    e
}

#[tokio::test]
async fn overlay_verdicts_are_counted_once() {
    let default = engine(&[]);
    let f = fixture(default.clone(), false).await;
    let base = shared_engine(&default, &["/ads/"]);
    let overlay = shared_engine(&default, &["@@/ads/ok", "/ads/"]);
    let sa = slot(1, base);
    sa.store(Arc::new(sa.load().with(|p| p.overlay = Some(overlay))));
    let t = f.ctx.profiles().table();
    let table = ProfileTable::builder(t.default_slot().clone())
        .profile(1, sa)
        .ip(LOCALHOST.parse().unwrap(), 1)
        .build();
    drop(t);
    f.ctx.profiles().publish(table);
    let stats = default.stats_handle();
    let mut s = connect(&f).await;
    // Overlay exception overrides the base block: allowed, nothing blocked.
    assert!(request(&mut s, &f, "/ads/ok", None).await.reached_origin());
    assert_eq!(
        stats.snapshot().blocked_requests,
        0,
        "exception override leaves no block"
    );
    // Blocked by both engines: one block, not two.
    assert!(!request(&mut s, &f, "/ads/x", None).await.reached_origin());
    assert_eq!(
        stats.snapshot().blocked_requests,
        1,
        "double block counts once"
    );
    assert_eq!(default.recent_blocked(10).len(), 1);
}

#[tokio::test]
async fn gm_values_are_namespaced_per_profile() {
    use proxy_core::gm::{Caller, GmHost};
    use serde_json::json;
    use userscript_engine::install::{finish_install, plan_install, Approvals, Fetched};
    use userscript_engine::token::{self, TokenClaims};
    use userscript_engine::UserscriptManager;

    let dir = tempfile::tempdir().unwrap();
    let m = Arc::new(UserscriptManager::new(dir.path().to_path_buf()).unwrap());
    let src = "// ==UserScript==\n// @name n\n// @namespace t\n// @version 1.0\n// @match *://hit.test/*\n// @grant GM_getValue\n// @grant GM_setValue\n// ==/UserScript==\n1;\n";
    let plan = plan_install(src, None).unwrap();
    let s = finish_install(plan, Fetched::default(), Approvals::default()).unwrap();
    // Each profile namespace holds its own copy; the caller's profile selects the index, the
    // token and the value namespace.
    m.install_script("p2", s.clone()).unwrap();
    m.install_script("p1", s).unwrap();
    let script = m.index_for("p1").iter().next().unwrap().script.clone();
    let caps = token::caps_hash(&script.metadata, script.allow_connect_all);
    let origin = "https://hit.test";
    let tok = |profile: &str| {
        token::mint(
            m.token_key(),
            &TokenClaims {
                profile,
                script_id: &script.id,
                script_version: "1.0",
                origin,
                caps_hash: &caps,
                exp: u64::MAX / 2,
            },
        )
    };
    let host = GmHost::new();
    let call = |profile: &str, route: &str, body: serde_json::Value| {
        let c = Caller {
            manager: &m,
            host: "hit.test",
            origin,
            profile,
        };
        host.json_call(
            &m,
            &c,
            route,
            Some(&tok(profile)),
            body.to_string().as_bytes(),
        )
    };
    let (st, _) = call(
        "p1",
        "values/set",
        json!({"values": {"k": "one"}, "src": "t"}),
    );
    assert_eq!(st, 200);
    let (_, v1) = call("p1", "values/get", json!({"names": ["k"]}));
    let (_, v2) = call("p2", "values/get", json!({"names": ["k"]}));
    assert!(v1.to_string().contains("one"), "{v1}");
    assert!(
        !v2.to_string().contains("one"),
        "profile 2 must not see profile 1's value: {v2}"
    );
    // A token minted for one profile is refused under another.
    let c = Caller {
        manager: &m,
        host: "hit.test",
        origin,
        profile: "p2",
    };
    let (st, _) = host.json_call(
        &m,
        &c,
        "values/get",
        Some(&tok("p1")),
        b"{\"names\":[\"k\"]}",
    );
    assert_eq!(st, 401);
}

#[tokio::test]
async fn userscript_chunks_are_bound_to_the_profile_they_were_planned_for() {
    use hyper::{HeaderMap, Method};
    use proxy_core::gm::{Caller, GmHost};
    use userscript_engine::install::{finish_install, plan_install, Approvals, Fetched};
    use userscript_engine::UserscriptManager;

    let dir = tempfile::tempdir().unwrap();
    let m = Arc::new(UserscriptManager::new(dir.path().to_path_buf()).unwrap());
    let src = "// ==UserScript==\n// @name n\n// @namespace t\n// @version 1.0\n// @match *://hit.test/*\n// ==/UserScript==\n1;\n";
    let s = finish_install(
        plan_install(src, None).unwrap(),
        Fetched::default(),
        Approvals::default(),
    )
    .unwrap();
    m.install_script("p1", s).unwrap();
    let host = GmHost::new();
    let origin = "https://hit.test";
    let plan = |profile: &str| {
        host.plan_document(&m, profile, "hit.test", "https://hit.test/", origin, true)
    };
    assert!(plan("p2").is_none(), "p2 has no scripts");
    let fetch = |planned: &proxy_core::gm::DocPlan, as_profile: &str| {
        let c = Caller {
            manager: &m,
            host: "hit.test",
            origin,
            profile: as_profile,
        };
        let rest = planned.srcs[0].strip_prefix("/__adblock__/us/").unwrap();
        host.serve_chunk(&m, &c, &Method::GET, &HeaderMap::new(), rest)
            .status()
    };
    let planned = plan("p1").unwrap();
    // A requester resolved to another profile cannot take it (and does not consume it).
    assert_eq!(fetch(&planned, "p2"), 404);
    assert_eq!(fetch(&planned, "p1"), 200);
}

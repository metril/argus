//! Format conversion, build reports, the persisted engine, `Expires`, includes and bundled
//! resources, against local HTTP servers (port 0, kept bound). No real network, no sleeps.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use filter_engine::{FilterList, ListFormat, SharedEngine};
use list_service::{BuildState, ListService, ListServiceConfig, ListStore};
use tokio::sync::Notify;

/// A tiny file server: path -> body, request log, failure switch and a gate.
#[derive(Default)]
struct Files {
    bodies: Mutex<HashMap<String, String>>,
    hits: Mutex<Vec<String>>,
    fail: AtomicBool,
    gated: AtomicBool,
    gate: Notify,
    arrived: Notify,
}

impl Files {
    fn set(&self, path: &str, body: &str) {
        self.bodies.lock().unwrap().insert(path.into(), body.into());
    }
    fn hits(&self, path: &str) -> usize {
        self.hits
            .lock()
            .unwrap()
            .iter()
            .filter(|p| *p == path)
            .count()
    }
}

async fn handler(State(f): State<Arc<Files>>, Path(p): Path<String>) -> axum::response::Response {
    let key = format!("/{p}");
    f.hits.lock().unwrap().push(key.clone());
    if f.gated.load(Ordering::SeqCst) {
        f.arrived.notify_one();
        f.gate.notified().await;
    }
    if f.fail.load(Ordering::SeqCst) {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    match f.bodies.lock().unwrap().get(&key) {
        Some(b) => b.clone().into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn serve(f: Arc<Files>) -> SocketAddr {
    let app = Router::new().route("/{*p}", get(handler)).with_state(f);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    addr
}

struct Env {
    svc: Arc<ListService>,
    engine: Arc<SharedEngine>,
    dir: tempfile::TempDir,
}

fn cfg(dir: &std::path::Path) -> ListServiceConfig {
    ListServiceConfig {
        data_dir: dir.to_path_buf(),
        persist_engine: true,
        ..Default::default()
    }
}

fn add_list(store: &ListStore, id: &str, url: String, tweak: impl FnOnce(&mut FilterList)) {
    let mut l = FilterList::new(id.into(), id.into(), url);
    tweak(&mut l);
    store.upsert(&l).unwrap();
}

type ListSpec = (&'static str, String, Box<dyn FnOnce(&mut FilterList)>);

fn env(lists: Vec<ListSpec>, tweak: impl FnOnce(&mut ListServiceConfig)) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let mut c = cfg(dir.path());
    tweak(&mut c);
    let store = ListStore::open(dir.path()).unwrap();
    for (id, url, t) in lists {
        add_list(&store, id, url, t);
    }
    let engine = Arc::new(SharedEngine::new());
    let svc = ListService::new(c, store, engine.clone(), reqwest::Client::new());
    Env { svc, engine, dir }
}

fn one(addr: SocketAddr, path: &str) -> Vec<ListSpec> {
    vec![("l", format!("http://{addr}{path}"), Box::new(|_| {}))]
}

fn blocked(e: &SharedEngine, url: &str) -> bool {
    e.check(url, "http://site.test/", "script").blocked
}

/// A second service over the same store and data dir (a "restart").
fn restart(e: &Env) -> (Arc<ListService>, Arc<SharedEngine>) {
    let engine = Arc::new(SharedEngine::new());
    let svc = ListService::new(
        cfg(e.dir.path()),
        e.svc.store().clone(),
        engine.clone(),
        reqwest::Client::new(),
    );
    (svc, engine)
}

#[tokio::test]
async fn hosts_list_is_converted_detected_and_reported() {
    let f = Arc::new(Files::default());
    f.set("/hosts", "# Title: T\n# Expires: 2 days\n127.0.0.1 localhost\n0.0.0.0 ads.test tracker.test\n0.0.0.0 bad_host!.com\n");
    let addr = serve(f.clone()).await;
    let e = env(one(addr, "/hosts"), |_| {});
    e.svc.reload_now().await;

    assert!(blocked(&e.engine, "http://ads.test/x.js"));
    assert!(
        blocked(&e.engine, "http://sub.tracker.test/x.js"),
        "subdomains are blocked too"
    );
    assert!(!blocked(&e.engine, "http://other.test/x.js"));

    let r = e.svc.report("l").expect("report stored");
    assert_eq!(r.format, ListFormat::Hosts);
    assert_eq!((r.network, r.cosmetic, r.ext, r.rejected), (2, 0, 0, 0));
    assert_eq!((r.skipped, r.error_count), (1, 1));
    assert_eq!(r.errors[0].line, 5);
    assert_eq!(r.meta.title.as_deref(), Some("T"));
    assert_eq!(r.meta.expires_secs, Some(2 * 86_400));
    let s = e.svc.summary();
    assert_eq!((s.lists, s.network, s.from_persisted), (1, 2, false));
    assert_eq!(e.svc.store().get("l").unwrap().unwrap().rule_count, 2);
}

#[tokio::test]
async fn format_override_and_allowlist_flag_apply() {
    let f = Arc::new(Files::default());
    f.set("/block", "||ads.test^\n||cdn.test^\n");
    f.set("/allow", "cdn.test\n");
    let addr = serve(f).await;
    let e = env(
        vec![
            (
                "block",
                format!("http://{addr}/block"),
                Box::new(|_: &mut FilterList| {}),
            ),
            (
                "allow",
                format!("http://{addr}/allow"),
                Box::new(|l: &mut FilterList| {
                    l.allowlist = true;
                    l.format = ListFormat::Domains;
                }),
            ),
        ],
        |_| {},
    );
    e.svc.reload_now().await;
    assert!(blocked(&e.engine, "http://ads.test/a.js"));
    assert!(
        !blocked(&e.engine, "http://cdn.test/a.js"),
        "allowlist list unblocks"
    );
    let r = e.svc.report("allow").unwrap();
    assert_eq!(
        (r.format, r.format_override, r.allowlist),
        (ListFormat::Domains, ListFormat::Domains, true)
    );
    assert_eq!(e.svc.report("block").unwrap().format, ListFormat::Abp);
}

#[tokio::test]
async fn ext_rules_and_ip_ranges_are_exposed() {
    let f = Arc::new(Files::default());
    f.set(
        "/ag",
        "||a.test^$replace=/x/y/\nexample.com##^script:has-text(ad)\n||b.test^\n",
    );
    f.set("/ips", "192.0.2.0/24\n");
    let addr = serve(f).await;
    let e = env(
        vec![
            (
                "ag",
                format!("http://{addr}/ag"),
                Box::new(|l: &mut FilterList| l.format = ListFormat::Adguard),
            ),
            (
                "ips",
                format!("http://{addr}/ips"),
                Box::new(|_: &mut FilterList| {}),
            ),
        ],
        |_| {},
    );
    e.svc.reload_now().await;
    let ext = e.engine.ext_rules();
    assert_eq!(ext.len(), 2);
    assert!(ext
        .iter()
        .any(|x| x.kind == filter_engine::ExtKind::Replace && x.raw.contains("a.test")));
    assert_eq!(
        e.svc.report("ag").unwrap().ext_counts.get("html-filter"),
        Some(&1)
    );
    assert_eq!(e.svc.summary().ext, 2);
    assert_eq!(e.svc.report("ips").unwrap().format, ListFormat::IpList);
    assert!(blocked(&e.engine, "http://192.0.2.9/x"));
    assert!(!blocked(&e.engine, "http://192.0.3.9/x"));
    assert!(blocked(&e.engine, "http://b.test/x"));
}

#[tokio::test]
async fn persisted_engine_serves_before_and_without_the_network() {
    let f = Arc::new(Files::default());
    f.set("/l", "0.0.0.0 ads.test\n");
    let addr = serve(f.clone()).await;
    let e = env(one(addr, "/l"), |_| {});
    e.svc.reload_now().await;
    assert!(e.dir.path().join("engine.bin").exists());
    assert!(!e.dir.path().join("engine.bin.tmp").exists());

    // Restart with the list server hanging: the persisted engine must be live before the fetch
    // is answered, and flagged as loaded rather than compiled.
    f.gated.store(true, Ordering::SeqCst);
    let (svc2, engine2) = restart(&e);
    svc2.trigger();
    f.arrived.notified().await;
    assert!(blocked(&engine2, "http://ads.test/x.js"));
    assert_eq!(engine2.domains().len(), 1, "domain set restored from disk");
    assert!(svc2.summary().from_persisted);
    // Mid-build: busy, fetching 0 of 1.
    assert!(svc2.is_building());
    assert_eq!(
        svc2.summary().state,
        BuildState::Fetching { done: 0, total: 1 }
    );
    f.gated.store(false, Ordering::SeqCst);
    f.fail.store(true, Ordering::SeqCst);
    f.gate.notify_one();
    svc2.wait_idle().await;
    assert!(!svc2.is_building());
    let s = svc2.summary();
    assert_eq!(s.state, BuildState::Idle);
    assert!(s.last_build_at.is_some());
    assert_eq!(s.domain_set, 1);
    // Server down (500): still blocking, still the same engine (nothing changed, no recompile).
    assert!(blocked(&engine2, "http://ads.test/x.js"));
    assert!(svc2.summary().from_persisted);
}

#[tokio::test]
async fn changed_list_content_invalidates_the_persisted_engine() {
    let f = Arc::new(Files::default());
    f.set("/l", "0.0.0.0 ads.test\n");
    let addr = serve(f.clone()).await;
    let e = env(one(addr, "/l"), |_| {});
    e.svc.reload_now().await;

    f.set("/l", "0.0.0.0 other.test\n");
    let (svc2, engine2) = restart(&e);
    svc2.reload_now().await;
    assert!(blocked(&engine2, "http://other.test/x"));
    assert!(!blocked(&engine2, "http://ads.test/x"));
    assert!(!svc2.summary().from_persisted);

    // A different format override is a different key too.
    let (svc3, _) = restart(&e);
    f.fail.store(true, Ordering::SeqCst);
    let store = svc3.store();
    let mut l = store.get("l").unwrap().unwrap();
    l.format = ListFormat::Domains;
    store.upsert(&l).unwrap();
    svc3.reload_now().await;
    assert!(!svc3.summary().from_persisted);
}

#[tokio::test]
async fn corrupt_or_foreign_blob_is_ignored_and_rewritten() {
    let f = Arc::new(Files::default());
    f.set("/l", "0.0.0.0 ads.test\n");
    let addr = serve(f.clone()).await;
    let e = env(one(addr, "/l"), |_| {});
    e.svc.reload_now().await;
    let path = e.dir.path().join("engine.bin");
    let good = std::fs::read(&path).unwrap();

    f.fail.store(true, Ordering::SeqCst); // network is down: only the cache can serve
    let mut bad: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"garbage".to_vec(),
        good[..good.len() / 2].to_vec(),
        good[..good.len() - 1].to_vec(),
    ];
    let mut flipped = good.clone();
    let mid = flipped.len() / 2;
    flipped[mid] ^= 0x55;
    bad.push(flipped);
    for blob in bad {
        std::fs::write(&path, &blob).unwrap();
        let (svc, engine) = restart(&e);
        svc.reload_now().await;
        assert!(
            blocked(&engine, "http://ads.test/x"),
            "falls back to cached lists"
        );
        assert!(!svc.summary().from_persisted);
        // The next successful build rewrites a valid file.
        let (svc, engine) = restart(&e);
        svc.reload_now().await;
        assert!(blocked(&engine, "http://ads.test/x"));
        assert!(svc.summary().from_persisted, "rewritten blob loads");
    }

    // A directory where the file should be is also survivable.
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    let (svc, engine) = restart(&e);
    svc.reload_now().await;
    assert!(blocked(&engine, "http://ads.test/x"));
}

#[tokio::test]
async fn expires_header_defers_refetch_until_forced() {
    let f = Arc::new(Files::default());
    f.set("/l", "! Expires: 4 days\n||ads.test^\n");
    let addr = serve(f.clone()).await;
    let e = env(one(addr, "/l"), |_| {});
    e.svc.reload_now().await;
    assert_eq!(f.hits("/l"), 1);

    // The auto-update path respects Expires: the list is fresh, so no request is made.
    e.svc.trigger_due();
    e.svc.wait_idle().await;
    assert_eq!(f.hits("/l"), 1);
    assert_eq!(e.svc.build_count(), 2);
    // An explicit reload revalidates.
    e.svc.reload_now().await;
    assert_eq!(f.hits("/l"), 2);
}

#[tokio::test]
async fn include_directive_is_fetched_from_the_same_origin_only() {
    let f = Arc::new(Files::default());
    f.set(
        "/dir/list.txt",
        "!#include extra.txt\n!#include http://127.0.0.1:1/evil.txt\n||main.test^\n",
    );
    f.set("/dir/extra.txt", "||included.test^\n");
    let addr = serve(f.clone()).await;
    let e = env(one(addr, "/dir/list.txt"), |_| {});
    e.svc.reload_now().await;
    assert!(blocked(&e.engine, "http://main.test/x"));
    assert!(blocked(&e.engine, "http://included.test/x"));
    assert_eq!(e.svc.report("l").unwrap().format, ListFormat::Ubo);

    // Offline restart: the cached include still resolves.
    f.fail.store(true, Ordering::SeqCst);
    let (svc2, engine2) = restart(&e);
    svc2.store()
        .put_content("l", "!#include extra.txt\n||main.test^\n")
        .unwrap(); // different text: recompile from cache
    svc2.reload_now().await;
    assert!(blocked(&engine2, "http://included.test/x"));
}

#[cfg(feature = "bundled-ubo-resources")]
#[tokio::test]
async fn bundled_scriptlets_work_with_no_network() {
    let f = Arc::new(Files::default());
    f.set("/l", "example.com##+js(abort-on-property-read, foo.bar)\n");
    let addr = serve(f).await;
    let e = env(one(addr, "/l"), |c| {
        // Resource source unreachable: only the bundled snapshot can provide scriptlets.
        c.scriptlet_resources_url = "http://127.0.0.1:1/resources.json".into();
    });
    e.svc.reload_now().await;
    let cos = e.engine.cosmetic_for("https://example.com/");
    assert!(
        !cos.injected_script.is_empty(),
        "bundled resources should resolve the scriptlet"
    );
    // Disabled (empty URL): no bundled resources either.
    let f2 = Arc::new(Files::default());
    f2.set("/l", "example.com##+js(abort-on-property-read, foo.bar)\n");
    let addr2 = serve(f2).await;
    let e2 = env(one(addr2, "/l"), |_| {});
    e2.svc.reload_now().await;
    assert!(e2
        .engine
        .cosmetic_for("https://example.com/")
        .injected_script
        .is_empty());
}

#[tokio::test]
async fn resources_fetch_a_fixed_file_list_and_replace_the_bundled_copy() {
    let f = Arc::new(Files::default());
    f.set(
        "/res/scriptlets.js",
        "builtinScriptlets.push({ name: 'fixture-only.js', fn: fixtureOnly });\nfunction fixtureOnly() { window.fixtureRan = 1; }\n",
    );
    f.set("/l", "example.com##+js(fixture-only)\n");
    let addr = serve(f.clone()).await;
    let e = env(one(addr, "/l"), |c| {
        c.scriptlet_resources_url = format!("http://{addr}/res");
        c.scriptlet_retry_initial = Duration::from_millis(5);
    });
    e.svc.reload_now().await; // bundled (if compiled in) is applied first: no `fixture-only`
    assert!(e
        .engine
        .cosmetic_for("https://example.com/")
        .injected_script
        .is_empty());
    let mut ready = e.svc.scriptlets_ready();
    let s = e.svc.clone();
    tokio::spawn(async move { s.ensure_scriptlet_resources().await });
    ready.wait_for(|r| *r).await.unwrap();
    assert!(e
        .engine
        .cosmetic_for("https://example.com/")
        .injected_script
        .contains("fixtureRan"));
    // Individual raw files, never a directory listing; the required file was requested.
    assert_eq!(f.hits("/res/scriptlets.js"), 1);
    assert!(f
        .hits
        .lock()
        .unwrap()
        .iter()
        .all(|p| p.starts_with("/res/") && p.ends_with(".js") || p == "/l"));
}

#[tokio::test]
async fn cached_resources_work_offline_without_bundled_snapshot() {
    let f = Arc::new(Files::default());
    f.set("/l", "example.com##+js(noopjs)\n");
    let addr = serve(f).await;
    let e = env(one(addr, "/l"), |c| {
        c.scriptlet_resources_url = "http://127.0.0.1:1/resources.json".into();
    });
    // The on-disk cache of a previous successful fetch.
    let json = r#"[{"name":"noopjs.js","aliases":[],"kind":{"mime":"application/javascript"},"content":"KGZ1bmN0aW9uKCl7fSkoKTs="}]"#;
    std::fs::write(e.dir.path().join("resources.json"), json).unwrap();
    e.svc.ensure_scriptlet_resources().await; // cache hit, no network
    e.svc.reload_now().await;
    assert!(!e
        .engine
        .cosmetic_for("https://example.com/")
        .injected_script
        .is_empty());
}

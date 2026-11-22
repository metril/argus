//! Behavioural tests against local HTTP servers (port 0, kept bound), no real network.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use filter_engine::{FilterList, SharedEngine};
use list_service::{ListService, ListServiceConfig, ListStore};
use tokio::sync::Notify;

const RULES: &str = "||ads.test^\n";

#[derive(Default)]
struct Origin {
    /// Requests seen.
    hits: AtomicUsize,
    /// Respond 500 while set.
    fail: std::sync::atomic::AtomicBool,
    /// Last conditional headers received: (if-none-match, if-modified-since).
    last_cond: std::sync::Mutex<(Option<String>, Option<String>)>,
    /// If set, the handler waits on `gate` before answering.
    gated: std::sync::atomic::AtomicBool,
    gate: Notify,
    arrived: Notify,
    body: std::sync::Mutex<String>,
}

async fn list_handler(State(o): State<Arc<Origin>>, headers: HeaderMap) -> Response {
    o.hits.fetch_add(1, Ordering::SeqCst);
    let h = |n| {
        headers
            .get(n)
            .and_then(|v| v.to_str().ok())
            .map(String::from)
    };
    *o.last_cond.lock().unwrap() = (h("if-none-match"), h("if-modified-since"));
    if o.gated.load(Ordering::SeqCst) {
        o.arrived.notify_one();
        o.gate.notified().await;
    }
    if o.fail.load(Ordering::SeqCst) {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    if h("if-none-match").as_deref() == Some("\"v1\"") {
        return StatusCode::NOT_MODIFIED.into_response();
    }
    (
        [
            (header::ETAG, "\"v1\""),
            (header::LAST_MODIFIED, "Wed, 21 Oct 2015 07:28:00 GMT"),
        ],
        o.body.lock().unwrap().clone(),
    )
        .into_response()
}

async fn serve(o: Arc<Origin>) -> SocketAddr {
    *o.body.lock().unwrap() = RULES.to_string();
    let app = Router::new()
        .route("/list.txt", get(list_handler))
        .with_state(o);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

struct Fixture {
    svc: Arc<ListService>,
    engine: Arc<SharedEngine>,
    _dir: tempfile::TempDir,
}

fn fixture(addr: SocketAddr, tweak: impl FnOnce(&mut ListServiceConfig)) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = ListServiceConfig {
        data_dir: dir.path().to_path_buf(),
        ..Default::default()
    };
    tweak(&mut cfg);
    let store = ListStore::open(dir.path()).unwrap();
    store
        .upsert(&FilterList::new(
            "t".into(),
            "T".into(),
            format!("http://{addr}/list.txt"),
        ))
        .unwrap();
    let engine = Arc::new(SharedEngine::new());
    let svc = ListService::new(cfg, store, engine.clone(), reqwest::Client::new());
    Fixture {
        svc,
        engine,
        _dir: dir,
    }
}

fn blocked(e: &SharedEngine) -> bool {
    e.check("http://ads.test/x.js", "http://site.test/", "script")
        .blocked
}

#[tokio::test]
async fn open_seeds_default_lists() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = ListServiceConfig {
        data_dir: dir.path().to_path_buf(),
        ..Default::default()
    };
    let svc = ListService::open(cfg, Arc::new(SharedEngine::new())).unwrap();
    assert!(svc.store().get_all().unwrap().len() >= 4);
}

#[tokio::test]
async fn fetch_compiles_and_blocks_then_uses_etag_and_304() {
    let origin = Arc::new(Origin::default());
    let addr = serve(origin.clone()).await;
    let f = fixture(addr, |_| {});

    f.svc.reload_now().await;
    assert!(blocked(&f.engine));
    let list = f.svc.store().get("t").unwrap().unwrap();
    assert_eq!(list.etag.as_deref(), Some("\"v1\""));
    assert_eq!(list.rule_count, 1);
    let st = f.svc.store().get_status("t").unwrap();
    assert!(st.last_success.is_some() && st.last_error.is_none());
    assert!(st.last_modified.is_some());

    // Second round is conditional with both validators and answered 304; cache still compiles.
    f.svc.reload_now().await;
    let cond = origin.last_cond.lock().unwrap().clone();
    assert_eq!(cond.0.as_deref(), Some("\"v1\""));
    assert_eq!(cond.1.as_deref(), Some("Wed, 21 Oct 2015 07:28:00 GMT"));
    assert_eq!(origin.hits.load(Ordering::SeqCst), 2);
    assert!(blocked(&f.engine));
    assert!(f.svc.store().get_status("t").unwrap().last_error.is_none());
}

#[tokio::test]
async fn size_cap_rejects_oversized_list() {
    let origin = Arc::new(Origin::default());
    let addr = serve(origin.clone()).await;
    *origin.body.lock().unwrap() = "||ads.test^\n".repeat(100);
    let f = fixture(addr, |c| c.max_list_bytes = 64);

    f.svc.reload_now().await;
    assert!(!blocked(&f.engine));
    let st = f.svc.store().get_status("t").unwrap();
    assert!(st.last_error.unwrap().contains("size cap"));
    assert!(f.svc.store().get_content("t").unwrap().is_none());
}

#[tokio::test]
async fn failure_falls_back_to_cache_and_records_error() {
    let origin = Arc::new(Origin::default());
    let addr = serve(origin.clone()).await;
    let f = fixture(addr, |_| {});
    f.svc.reload_now().await;
    assert!(blocked(&f.engine));

    // Fresh engine + service over the same store: origin now fails; cache must still block.
    origin.fail.store(true, Ordering::SeqCst);
    let engine2 = Arc::new(SharedEngine::new());
    let svc2 = ListService::new(
        ListServiceConfig::default(),
        f.svc.store().clone(),
        engine2.clone(),
        reqwest::Client::new(),
    );
    svc2.reload_now().await;
    assert!(blocked(&engine2));
    let st = svc2.store().get_status("t").unwrap();
    assert!(st.last_error.unwrap().contains("500"));
    assert!(st.last_success.is_some());
}

#[tokio::test]
async fn first_build_installs_cache_even_if_origin_is_unreachable() {
    let origin = Arc::new(Origin::default());
    let addr = serve(origin.clone()).await;
    let f = fixture(addr, |_| {});
    f.svc.reload_now().await;

    // Origin hangs forever: the cached rules must be installed before the fetch is awaited.
    origin.gated.store(true, Ordering::SeqCst);
    let engine2 = Arc::new(SharedEngine::new());
    let svc2 = ListService::new(
        ListServiceConfig {
            fetch_timeout: Duration::from_secs(30),
            ..Default::default()
        },
        f.svc.store().clone(),
        engine2.clone(),
        reqwest::Client::new(),
    );
    svc2.trigger();
    origin.arrived.notified().await; // fetch in flight
    assert!(blocked(&engine2), "cached rules served while fetching");
    origin.gate.notify_one();
    svc2.wait_idle().await;
}

#[tokio::test]
async fn single_flight_coalesces_triggers() {
    let origin = Arc::new(Origin::default());
    let addr = serve(origin.clone()).await;
    let f = fixture(addr, |_| {});
    origin.gated.store(true, Ordering::SeqCst);

    f.svc.trigger();
    origin.arrived.notified().await; // build 1 is mid-fetch
    for _ in 0..20 {
        f.svc.trigger();
    }
    origin.gated.store(false, Ordering::SeqCst);
    origin.gate.notify_one();
    f.svc.wait_idle().await;

    // Exactly one build mid-flight plus exactly one follow-up for all 20 later triggers.
    assert_eq!(f.svc.build_count(), 2);
    assert_eq!(origin.hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn burst_of_triggers_never_runs_more_than_two_builds() {
    let origin = Arc::new(Origin::default());
    let addr = serve(origin).await;
    let f = fixture(addr, |_| {});
    for _ in 0..50 {
        f.svc.trigger();
    }
    f.svc.wait_idle().await;
    assert!(
        matches!(f.svc.build_count(), 1 | 2),
        "{}",
        f.svc.build_count()
    );
}

#[tokio::test]
async fn scriptlet_resources_retry_until_available() {
    // Server fails the first request, then serves a ready-made resources array.
    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    let app = Router::new().route(
        "/resources.json",
        get(move || {
            let n = c.fetch_add(1, Ordering::SeqCst);
            async move {
                if n == 0 {
                    (StatusCode::SERVICE_UNAVAILABLE, String::new())
                } else {
                    (StatusCode::OK, "[]".to_string())
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let dir = tempfile::tempdir().unwrap();
    let cfg = ListServiceConfig {
        data_dir: dir.path().to_path_buf(),
        scriptlet_resources_url: format!("http://{addr}/resources.json"),
        scriptlet_retry_initial: Duration::from_millis(5),
        ..Default::default()
    };
    let store = ListStore::open(dir.path()).unwrap();
    let svc = ListService::new(
        cfg,
        store,
        Arc::new(SharedEngine::new()),
        reqwest::Client::new(),
    );
    let mut ready = svc.scriptlets_ready();
    let s = svc.clone();
    tokio::spawn(async move { s.ensure_scriptlet_resources().await });
    ready.wait_for(|r| *r).await.unwrap();
    assert!(calls.load(Ordering::SeqCst) >= 2);
    assert!(dir.path().join("resources.json").exists());
}

//! Control-plane fetch policy: private destinations, redirects, includes, report echo.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Redirect};
use axum::routing::get;
use axum::Router;
use common::net_policy::{control_plane_client, NetPolicy};
use filter_engine::{FilterList, SharedEngine};
use list_service::{ListService, ListServiceConfig, ListStore};

#[derive(Clone, Default)]
struct S {
    hits: Arc<AtomicUsize>,
    other: Arc<std::sync::Mutex<Option<SocketAddr>>>,
}

async fn serve(s: S, extra: Router<S>) -> SocketAddr {
    let app = Router::new()
        .route(
            "/list.txt",
            get(|State(s): State<S>| async move {
                s.hits.fetch_add(1, Ordering::SeqCst);
                "||ads.test^\n"
            }),
        )
        .route(
            "/hop/{n}",
            get(
                |Path(n): Path<u32>| async move { Redirect::temporary(&format!("/hop/{}", n + 1)) },
            ),
        )
        .route(
            "/to-metadata",
            get(|| async { Redirect::temporary("http://169.254.169.254/list.txt") }),
        )
        .route(
            "/to-loopback6",
            get(|| async { Redirect::temporary("http://[::1]:9/list.txt") }),
        )
        .route(
            "/gz",
            get(|| async { ([(header::CONTENT_ENCODING, "gzip")], "||ads.test^\n") }),
        )
        .merge(extra)
        .with_state(s);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    addr
}

struct Fx {
    svc: Arc<ListService>,
    engine: Arc<SharedEngine>,
    _dir: tempfile::TempDir,
}

fn fixture(url: String, allowed: &[&str], tweak: impl FnOnce(&mut ListServiceConfig)) -> Fx {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = ListServiceConfig {
        data_dir: dir.path().to_path_buf(),
        allowed_fetch_destinations: allowed.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    };
    tweak(&mut cfg);
    let store = ListStore::open(dir.path()).unwrap();
    store
        .upsert(&FilterList::new("t".into(), "T".into(), url))
        .unwrap();
    let policy = Arc::new(NetPolicy::control_plane(&cfg.allowed_fetch_destinations).unwrap());
    let client = control_plane_client(policy.clone()).build().unwrap();
    let engine = Arc::new(SharedEngine::new());
    let svc = ListService::new_guarded(cfg, store, engine.clone(), client, Some(policy));
    Fx {
        svc,
        engine,
        _dir: dir,
    }
}

fn blocked(e: &SharedEngine, host: &str) -> bool {
    e.check(
        &format!("http://{host}/x.js"),
        "http://site.test/",
        "script",
    )
    .blocked
}

fn last_error(f: &Fx) -> String {
    f.svc
        .store()
        .get_status("t")
        .unwrap()
        .last_error
        .unwrap_or_default()
}

#[tokio::test]
async fn private_destinations_are_refused_by_default_and_allowlist_opens_them() {
    let s = S::default();
    let addr = serve(s.clone(), Router::new()).await;
    let url = format!("http://{addr}/list.txt");

    let f = fixture(url.clone(), &[], |_| {});
    f.svc.reload_now().await;
    assert_eq!(s.hits.load(Ordering::SeqCst), 0, "must not even connect");
    assert!(last_error(&f).contains("not allowed"), "{}", last_error(&f));
    assert!(!blocked(&f.engine, "ads.test"));

    let f = fixture(url, &["127.0.0.0/8"], |_| {});
    f.svc.reload_now().await;
    assert!(blocked(&f.engine, "ads.test"), "{}", last_error(&f));
}

#[tokio::test]
async fn redirects_to_internal_addresses_and_long_chains_are_refused() {
    let s = S::default();
    let addr = serve(s.clone(), Router::new()).await;
    for (path, why) in [
        ("to-metadata", "not allowed"),
        ("to-loopback6", "not allowed"),
        ("hop/0", "redirect"),
    ] {
        let f = fixture(format!("http://{addr}/{path}"), &["127.0.0.0/8"], |_| {});
        f.svc.reload_now().await;
        let e = last_error(&f);
        assert!(
            !e.is_empty() && e.to_lowercase().contains(why),
            "{path}: {e}"
        );
        assert!(!blocked(&f.engine, "ads.test"));
    }
}

#[tokio::test]
async fn compressed_responses_are_not_accepted() {
    let s = S::default();
    let addr = serve(s, Router::new()).await;
    let f = fixture(format!("http://{addr}/gz"), &["127.0.0.0/8"], |_| {});
    f.svc.reload_now().await;
    assert!(last_error(&f).contains("compressed"), "{}", last_error(&f));
}

async fn include_origin(s: S) -> (SocketAddr, SocketAddr) {
    // Second origin: serves the "secret" include content.
    let other = serve(
        s.clone(),
        Router::new().route("/x.txt", get(|| async { "||secret.test^\n" })),
    )
    .await;
    *s.other.lock().unwrap() = Some(other);
    let main = serve(
        s.clone(),
        Router::new()
            .route(
                "/inc-list.txt",
                get(|| async { "!#include same.txt\n!#include far.txt\n||ads.test^\n" }),
            )
            .route("/same.txt", get(|| async { "||same.test^\n" }))
            .route(
                "/far.txt",
                get(|State(s): State<S>| async move {
                    let o = s.other.lock().unwrap().unwrap();
                    Redirect::temporary(&format!("http://{o}/x.txt")).into_response()
                }),
            ),
    )
    .await;
    (main, other)
}

#[tokio::test]
async fn includes_must_stay_same_origin_after_redirects() {
    let s = S::default();
    let (main, _) = include_origin(s).await;
    let f = fixture(
        format!("http://{main}/inc-list.txt"),
        &["127.0.0.0/8"],
        |_| {},
    );
    f.svc.reload_now().await;
    assert!(blocked(&f.engine, "ads.test"), "{}", last_error(&f));
    assert!(blocked(&f.engine, "same.test"), "same-origin include loads");
    assert!(
        !blocked(&f.engine, "secret.test"),
        "cross-origin redirect include must be dropped"
    );
}

#[tokio::test]
async fn include_total_is_bounded_by_the_size_cap() {
    let s = S::default();
    let big = |tag: &'static str| async move { format!("||{tag}.test^\n{}", "! pad\n".repeat(60)) };
    let main = serve(
        s,
        Router::new()
            .route(
                "/m.txt",
                get(|| async { "!#include a.txt\n!#include b.txt\n||ads.test^\n" }),
            )
            .route("/a.txt", get(move || big("a")))
            .route("/b.txt", get(move || big("b"))),
    )
    .await;
    let f = fixture(format!("http://{main}/m.txt"), &["127.0.0.0/8"], |c| {
        c.max_list_bytes = 500
    });
    f.svc.reload_now().await;
    let n = ["a.test", "b.test"]
        .iter()
        .filter(|h| blocked(&f.engine, h))
        .count();
    assert_eq!(
        n,
        1,
        "the second include exceeds the shared budget: {}",
        last_error(&f)
    );
}

#[tokio::test]
async fn reports_never_echo_long_fetched_lines() {
    let secret = "S3CR3T".repeat(100);
    let body = format!("0.0.0.0 {secret}!!\n0.0.0.0 ok.test\n");
    let main = serve(
        S::default(),
        Router::new().route(
            "/h.txt",
            get(move || {
                let b = body.clone();
                async move { (StatusCode::OK, b) }
            }),
        ),
    )
    .await;
    let f = fixture(format!("http://{main}/h.txt"), &["127.0.0.0/8"], |_| {});
    f.svc.reload_now().await;
    let report = f.svc.report("t").expect("report stored");
    assert!(report.error_count > 0 || report.skipped > 0, "{report:?}");
    let json = serde_json::to_string(&report).unwrap();
    assert!(!json.contains(&secret), "{json}");
    for e in &report.errors {
        assert!(e.reason.chars().count() <= 90, "{}", e.reason);
    }
}

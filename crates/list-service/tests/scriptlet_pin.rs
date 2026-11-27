//! Commit pinning through the git ref advertisement and rate-limit handling, against stub HTTP
//! servers on ephemeral ports.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use filter_engine::SharedEngine;
use list_service::{ListService, ListServiceConfig, ListStore};

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const OTHER: &str = "fedcba9876543210fedcba9876543210fedcba98";

async fn serve(app: Router) -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    addr
}

fn svc(dir: &std::path::Path, tweak: impl FnOnce(&mut ListServiceConfig)) -> Arc<ListService> {
    let mut c = ListServiceConfig {
        data_dir: dir.to_path_buf(),
        scriptlet_retry_initial: Duration::from_millis(5),
        ..Default::default()
    };
    tweak(&mut c);
    let store = ListStore::open(dir).unwrap();
    ListService::new(
        c,
        store,
        Arc::new(SharedEngine::new()),
        reqwest::Client::new(),
    )
}

fn pkt(s: &str) -> String {
    format!("{:04x}{s}", s.len() + 4)
}

fn advertisement() -> String {
    let mut a = pkt("# service=git-upload-pack\n");
    a.push_str("0000");
    a.push_str(&pkt(&format!(
        "{OTHER} HEAD\0multi_ack symref=HEAD:refs/heads/master\n"
    )));
    a.push_str(&pkt(&format!("{OTHER} refs/heads/dev\n")));
    a.push_str(&pkt(&format!("{SHA} refs/heads/master\n")));
    a.push_str(&pkt(&format!("{OTHER} refs/tags/1.0\n")));
    a.push_str("0000");
    a
}

const RAW: &str = "https://raw.githubusercontent.com/gorhill/uBlock/master/src/js/resources";

#[tokio::test]
async fn master_is_resolved_via_git_refs_not_the_rest_api() {
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    let app = Router::new().route(
        "/gorhill/uBlock.git/info/refs",
        get(move || {
            h.fetch_add(1, Ordering::SeqCst);
            async move { advertisement() }
        }),
    );
    let addr = serve(app).await;
    let dir = tempfile::tempdir().unwrap();
    let s = svc(dir.path(), |c| c.git_host_url = format!("http://{addr}"));
    let pinned = s.pin_commit(RAW).await.unwrap();
    assert_eq!(
        pinned,
        format!("https://raw.githubusercontent.com/gorhill/uBlock/{SHA}/src/js/resources")
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    // HEAD and an already pinned URL.
    let head = RAW.replace("/master/", "/HEAD/");
    assert!(s.pin_commit(&head).await.unwrap().contains(OTHER));
    let sha_url = RAW.replace("/master/", &format!("/{SHA}/"));
    assert_eq!(s.pin_commit(&sha_url).await.unwrap(), sha_url);
}

#[tokio::test]
async fn rate_limited_source_is_retried_honouring_retry_after() {
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    let json = r#"[{"name":"noopjs.js","aliases":[],"kind":{"mime":"application/javascript"},"content":"KGZ1bmN0aW9uKCl7fSkoKTs="}]"#;
    let app = Router::new().route(
        "/res.json",
        get(move || {
            let n = h.fetch_add(1, Ordering::SeqCst);
            async move {
                if n == 0 {
                    (
                        StatusCode::FORBIDDEN,
                        [(header::RETRY_AFTER, "1")],
                        "limited",
                    )
                        .into_response()
                } else {
                    json.into_response()
                }
            }
        }),
    );
    let addr = serve(app).await;
    let dir = tempfile::tempdir().unwrap();
    let s = svc(dir.path(), |c| {
        c.scriptlet_resources_url = format!("http://{addr}/res.json");
    });
    let t = Instant::now();
    let mut ready = s.scriptlets_ready();
    let s2 = s.clone();
    tokio::spawn(async move { s2.ensure_scriptlet_resources().await });
    ready.wait_for(|r| *r).await.unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    assert!(
        t.elapsed() >= Duration::from_millis(900),
        "Retry-After: 1 must delay the retry, got {:?}",
        t.elapsed()
    );
}

#[tokio::test]
async fn ratelimit_reset_header_is_honoured() {
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    let json = "[]";
    let app = Router::new().route(
        "/res.json",
        get(move || {
            let n = h.fetch_add(1, Ordering::SeqCst);
            async move {
                if n == 0 {
                    let reset = (std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                        + 2)
                    .to_string();
                    (
                        StatusCode::TOO_MANY_REQUESTS,
                        [
                            ("x-ratelimit-remaining", "0".to_string()),
                            ("x-ratelimit-reset", reset),
                        ],
                        "limited",
                    )
                        .into_response()
                } else {
                    json.into_response()
                }
            }
        }),
    );
    let addr = serve(app).await;
    let dir = tempfile::tempdir().unwrap();
    let s = svc(dir.path(), |c| {
        c.scriptlet_resources_url = format!("http://{addr}/res.json");
    });
    let t = Instant::now();
    let mut ready = s.scriptlets_ready();
    let s2 = s.clone();
    tokio::spawn(async move { s2.ensure_scriptlet_resources().await });
    ready.wait_for(|r| *r).await.unwrap();
    assert!(
        t.elapsed() >= Duration::from_millis(900),
        "{:?}",
        t.elapsed()
    );
}

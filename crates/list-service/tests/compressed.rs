//! Compressed list downloads against a local server (port 0, no real network).

use std::net::SocketAddr;
use std::sync::Arc;

use async_compression::tokio::write::{BrotliEncoder, GzipEncoder, ZstdEncoder};
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use filter_engine::{FilterList, SharedEngine};
use list_service::{ListService, ListServiceConfig, ListStore};
use tokio::io::AsyncWriteExt;

async fn compress(coding: &str, data: &[u8]) -> Vec<u8> {
    macro_rules! enc {
        ($e:expr) => {{
            let mut e = $e;
            e.write_all(data).await.unwrap();
            e.shutdown().await.unwrap();
            e.into_inner()
        }};
    }
    match coding {
        "gzip" => enc!(GzipEncoder::new(Vec::new())),
        "br" => enc!(BrotliEncoder::new(Vec::new())),
        _ => enc!(ZstdEncoder::new(Vec::new())),
    }
}

async fn serve(coding: &'static str, body: Vec<u8>) -> SocketAddr {
    let body = Arc::new(body);
    let app = Router::new().route(
        "/list.txt",
        get(move || {
            let b = body.clone();
            async move { ([(header::CONTENT_ENCODING, coding)], b.to_vec()).into_response() }
        }),
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    addr
}

fn setup(addr: SocketAddr, cap: usize) -> (Arc<ListService>, Arc<SharedEngine>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let cfg = ListServiceConfig {
        data_dir: dir.path().to_path_buf(),
        max_list_bytes: cap,
        ..Default::default()
    };
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
    (svc, engine, dir)
}

fn blocked(e: &SharedEngine) -> bool {
    e.check("http://ads.test/x.js", "http://site.test/", "script")
        .blocked
}

#[tokio::test]
async fn gzip_br_zstd_lists_download_and_block() {
    for coding in ["gzip", "br", "zstd"] {
        let addr = serve(coding, compress(coding, b"||ads.test^\n").await).await;
        let (svc, engine, _d) = setup(addr, 1024 * 1024);
        svc.reload_now().await;
        assert!(blocked(&engine), "{coding}");
    }
}

#[tokio::test]
async fn decoded_size_cap_applies_to_a_small_bomb() {
    // ~100 KB of rules compress to a few hundred bytes; the cap is on decoded bytes.
    let big = "||ads.test^\n".repeat(10_000);
    let packed = compress("gzip", big.as_bytes()).await;
    assert!(packed.len() < 1000);
    let addr = serve("gzip", packed).await;
    let (svc, engine, _d) = setup(addr, 4096);
    svc.reload_now().await;
    assert!(!blocked(&engine));
    let err = svc.store().get_status("t").unwrap().last_error.unwrap();
    assert!(err.contains("size cap"), "{err}");
}

#[tokio::test]
async fn ratio_cap_refuses_extreme_compression() {
    // 8 MB of one byte compresses > 1000:1; well under the size cap, so only the ratio trips.
    let big = vec![b'!'; 8 * 1024 * 1024];
    let addr = serve("zstd", compress("zstd", &big).await).await;
    let (svc, engine, _d) = setup(addr, 50 * 1024 * 1024);
    svc.reload_now().await;
    assert!(!blocked(&engine));
    let err = svc.store().get_status("t").unwrap().last_error.unwrap();
    assert!(err.contains("ratio"), "{err}");
}

#[tokio::test]
async fn unknown_coding_is_refused() {
    let addr = serve("compress", b"||ads.test^\n".to_vec()).await;
    let (svc, engine, _d) = setup(addr, 1024 * 1024);
    svc.reload_now().await;
    assert!(!blocked(&engine));
    let err = svc.store().get_status("t").unwrap().last_error.unwrap();
    assert!(err.contains("unsupported Content-Encoding"), "{err}");
}

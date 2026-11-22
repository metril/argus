//! The default (non-webui) startup path must load lists and install rules by itself.
//! Mirrors what `main` does: `ListService::open` + `start`, no web UI involved.

use std::sync::Arc;

use common::config::AdblockSettings;
use filter_engine::{FilterList, SharedEngine};
use list_service::{ListService, ListServiceConfig, ListStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn start_without_webui_installs_rules_from_list_server() {
    // Local list server, kept bound for the whole test.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let body = "||blocked.test^\n";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            });
        }
    });

    let dir = tempfile::tempdir().unwrap();
    {
        // Pre-populate so `open` does not seed the real default lists (no real network).
        let store = ListStore::open(dir.path()).unwrap();
        store
            .upsert(&FilterList::new(
                "local".into(),
                "Local".into(),
                format!("http://{addr}/list.txt"),
            ))
            .unwrap();
    }

    let settings = AdblockSettings {
        enabled: true,
        data_dir: dir.path().to_path_buf(),
        scriptlet_resources_url: String::new(),
        ..Default::default()
    };
    let engine = Arc::new(SharedEngine::new());
    let svc =
        ListService::open(ListServiceConfig::from_adblock(&settings), engine.clone()).unwrap();
    assert!(
        !engine
            .check("https://blocked.test/a.js", "https://site.test/", "script")
            .blocked
    );

    svc.start();
    svc.wait_idle().await;

    assert!(
        engine
            .check("https://blocked.test/a.js", "https://site.test/", "script")
            .blocked,
        "rules must be installed by the list service alone"
    );
    assert!(
        !engine
            .check("https://ok.test/a.js", "https://site.test/", "script")
            .blocked
    );
}

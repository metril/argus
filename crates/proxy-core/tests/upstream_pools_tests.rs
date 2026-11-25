//! Upstream connections are pooled per downstream connection, evicted when it closes, and TLS
//! sessions are resumed per device (never across devices).

mod support;

use std::{sync::atomic::Ordering, time::Duration};

use futures_util::StreamExt;
use proxy_core::upstream::{UpstreamClient, UpstreamScope};
use support::*;

const HOST: &str = "pool.test";

fn scope(conn_id: u64, device: &str) -> UpstreamScope {
    UpstreamScope {
        conn_id,
        device: device.into(),
    }
}

async fn get(c: &UpstreamClient, o: &Origin, s: UpstreamScope) {
    let resp = c
        .get(o.url(HOST))
        .header("user-agent", CHROME_UA)
        .scope(s)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Vec<_> = resp.bytes_stream().collect().await;
    assert!(body.iter().all(Result::is_ok));
}

async fn setup(tweak: impl FnOnce(&mut proxy_core::upstream::UpstreamOptions)) -> (Rig, Origin) {
    let trusted = ca("trusted");
    let (der, key) = leaf(&trusted, HOST);
    let o = h2_origin(vec![der, trusted.der.clone()], key, ok_script()).await;
    (rig(&trusted, tweak), o)
}

#[tokio::test]
async fn two_downstream_connections_use_two_origin_connections() {
    let (r, o) = setup(|_| {}).await;
    get(&r.client, &o, scope(1, "d")).await;
    get(&r.client, &o, scope(2, "d")).await;
    assert_eq!(o.stats.conns.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn one_downstream_connection_reuses_one_origin_connection() {
    let (r, o) = setup(|_| {}).await;
    for _ in 0..5 {
        get(&r.client, &o, scope(1, "d")).await;
    }
    assert_eq!(o.stats.conns.load(Ordering::SeqCst), 1);
    assert_eq!(o.stats.requests.load(Ordering::SeqCst), 5);
}

#[tokio::test]
async fn closing_the_downstream_connection_closes_its_origin_connections() {
    let (r, o) = setup(|_| {}).await;
    get(&r.client, &o, scope(1, "d")).await;
    get(&r.client, &o, scope(2, "d")).await;
    o.until("both connections open", |s| {
        s.open.load(Ordering::SeqCst) == 2
    })
    .await;
    r.client.evict_conn(1);
    o.until("connection 1 closed", |s| {
        s.open.load(Ordering::SeqCst) == 1
    })
    .await;
    // Connection 2 is untouched and still serves.
    get(&r.client, &o, scope(2, "d")).await;
    assert_eq!(o.stats.conns.load(Ordering::SeqCst), 2);
    r.client.evict_conn(2);
    o.until("all closed", |s| s.open.load(Ordering::SeqCst) == 0)
        .await;
}

#[tokio::test]
async fn tls_sessions_resume_across_connections_of_one_device_only() {
    let (r, o) = setup(|_| {}).await;
    get(&r.client, &o, scope(1, "dev-a")).await;
    assert_eq!(o.stats.resumed.load(Ordering::SeqCst), 0);
    // Another connection of the same device resumes the first one's session...
    get(&r.client, &o, scope(2, "dev-a")).await;
    assert_eq!(o.stats.conns.load(Ordering::SeqCst), 2);
    assert_eq!(o.stats.resumed.load(Ordering::SeqCst), 1, "same device");
    // ... a connection of another device never does, however many sessions are cached.
    get(&r.client, &o, scope(3, "dev-b")).await;
    get(&r.client, &o, scope(4, "dev-c")).await;
    assert_eq!(o.stats.conns.load(Ordering::SeqCst), 4);
    assert_eq!(o.stats.resumed.load(Ordering::SeqCst), 1, "other devices");
}

#[tokio::test]
async fn the_whole_pool_is_bounded() {
    let (r, o) = setup(|opts| opts.pool_max_size = Some(3)).await;
    for id in 1..=10 {
        get(&r.client, &o, scope(id, "d")).await;
    }
    assert_eq!(o.stats.conns.load(Ordering::SeqCst), 10);
    o.until("pool trimmed to its bound", |s| {
        s.open.load(Ordering::SeqCst) <= 3
    })
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(o.stats.open.load(Ordering::SeqCst) <= 3);
}

#[tokio::test]
async fn the_tls_session_cache_is_bounded() {
    // Room for one session: another device's connection pushes this device's out.
    let (r, o) = setup(|opts| opts.tls_session_cap = Some(1)).await;
    get(&r.client, &o, scope(1, "dev-a")).await;
    get(&r.client, &o, scope(2, "dev-b")).await;
    get(&r.client, &o, scope(3, "dev-a")).await;
    assert_eq!(o.stats.resumed.load(Ordering::SeqCst), 0, "evicted session");
    get(&r.client, &o, scope(4, "dev-a")).await;
    assert_eq!(o.stats.resumed.load(Ordering::SeqCst), 1, "kept session");
}

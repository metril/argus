//! A request that failed before any response head arrived is retried exactly once on a fresh
//! upstream connection, when the failure is a reset or GOAWAY-class one and the request can be
//! replayed. Everything else (certificate errors, timeouts, streamed bodies) is not retried.
//!
//! Each test runs in its own process under nextest, so the global fault counters are its own.

mod support;

use std::{sync::atomic::Ordering, sync::Arc, time::Duration};

use filter_engine::ErrorKind;
use proxy_core::upstream::{UpstreamClient, UpstreamRequest, UpstreamScope};
use support::*;

const HOST: &str = "retry.test";

fn scope() -> UpstreamScope {
    UpstreamScope {
        conn_id: 7,
        device: "dev".into(),
    }
}

fn base(c: &UpstreamClient, method: hyper::Method, o: &Origin) -> UpstreamRequest {
    c.request(method, o.url(HOST))
        .header("user-agent", CHROME_UA)
        .scope(scope())
}

fn retries() -> u64 {
    common::faults::snapshot().upstream_retries
}

async fn setup(
    script: Script,
    tweak: impl FnOnce(&mut proxy_core::upstream::UpstreamOptions),
) -> (Rig, Origin) {
    let trusted = ca("trusted");
    let (der, key) = leaf(&trusted, HOST);
    let o = h2_origin(vec![der, trusted.der.clone()], key, script).await;
    (rig(&trusted, tweak), o)
}

fn first_on(conn: usize, act: Act) -> Script {
    Arc::new(move |c, n| if c == conn && n == 0 { act } else { Act::Ok })
}

#[tokio::test]
async fn a_get_survives_a_goaway_on_a_new_connection() {
    let (r, o) = setup(first_on(0, Act::Goaway), |_| {}).await;
    let resp = base(&r.client, hyper::Method::GET, &o)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        o.stats.conns.load(Ordering::SeqCst),
        2,
        "retry used a new connection"
    );
    assert_eq!(o.stats.requests.load(Ordering::SeqCst), 2);
    assert_eq!(retries(), 1);
}

#[tokio::test]
async fn a_get_survives_a_refused_stream() {
    let (r, o) = setup(first_on(0, Act::Refuse), |_| {}).await;
    let resp = base(&r.client, hyper::Method::GET, &o)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(o.stats.conns.load(Ordering::SeqCst), 2);
    assert_eq!(o.stats.requests.load(Ordering::SeqCst), 2);
    assert_eq!(retries(), 1);
}

#[tokio::test]
async fn a_get_survives_a_reused_connection_dropped_without_notice() {
    // The second request on connection 0 finds it dead.
    let script: Script = Arc::new(|c, n| if c == 0 && n == 1 { Act::Drop } else { Act::Ok });
    let (r, o) = setup(script, |_| {}).await;
    let first = base(&r.client, hyper::Method::GET, &o)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), 200);
    let second = base(&r.client, hyper::Method::GET, &o)
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), 200);
    assert_eq!(o.stats.conns.load(Ordering::SeqCst), 2);
    assert_eq!(retries(), 1);
}

#[tokio::test]
async fn a_buffered_post_is_replayed() {
    let (r, o) = setup(first_on(0, Act::Refuse), |_| {}).await;
    let resp = base(&r.client, hyper::Method::POST, &o)
        .body(bytes::Bytes::from_static(b"small"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(o.stats.requests.load(Ordering::SeqCst), 2);
    assert_eq!(retries(), 1);
}

#[tokio::test]
async fn a_streamed_post_is_not_retried() {
    // A streamed body cannot be sent twice: one attempt, then the error.
    let (r, o) = setup(Arc::new(|_, _| Act::Refuse), |_| {}).await;
    let stream = futures_util::stream::iter(vec![Ok::<_, std::io::Error>(
        bytes::Bytes::from_static(b"streamed"),
    )]);
    let err = base(&r.client, hyper::Method::POST, &o)
        .body_stream(stream)
        .send()
        .await
        .unwrap_err();
    assert_ne!(err.kind(), ErrorKind::UpstreamTimeout);
    assert_eq!(o.stats.requests.load(Ordering::SeqCst), 1);
    assert_eq!(retries(), 0, "no retry counted");
}

#[tokio::test]
async fn a_post_without_a_buffered_body_is_not_retried() {
    let (r, o) = setup(Arc::new(|_, _| Act::Refuse), |_| {}).await;
    assert!(base(&r.client, hyper::Method::POST, &o)
        .send()
        .await
        .is_err());
    assert_eq!(o.stats.requests.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_oversized_buffered_body_is_not_replayed() {
    let (r, o) = setup(Arc::new(|_, _| Act::Refuse), |_| {}).await;
    let big = bytes::Bytes::from(vec![b'x'; 64 * 1024 + 1]);
    assert!(base(&r.client, hyper::Method::PUT, &o)
        .body(big)
        .send()
        .await
        .is_err());
    assert_eq!(o.stats.requests.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_certificate_error_is_not_retried() {
    let (trusted, stranger) = (ca("trusted"), ca("stranger"));
    let (der, key) = leaf(&stranger, HOST);
    let o = h2_origin(vec![der, stranger.der.clone()], key, ok_script()).await;
    let r = rig(&trusted, |_| {});
    let err = base(&r.client, hyper::Method::GET, &o)
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::UpstreamTls);
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(o.stats.tcp.load(Ordering::SeqCst), 1, "one dial, no retry");
    assert_eq!(retries(), 0);
}

#[tokio::test]
async fn two_failures_end_in_an_error_after_one_retry() {
    let (r, o) = setup(Arc::new(|_, _| Act::Goaway), |_| {}).await;
    let err = base(&r.client, hyper::Method::GET, &o)
        .send()
        .await
        .unwrap_err();
    assert_ne!(err.kind(), ErrorKind::UpstreamTimeout);
    assert_eq!(
        o.stats.requests.load(Ordering::SeqCst),
        2,
        "one retry, no more"
    );
    assert_eq!(retries(), 1);
}

#[tokio::test]
async fn a_timeout_is_not_retried() {
    let (r, o) = setup(Arc::new(|_, _| Act::Hang), |opts| {
        opts.read_timeout = Some(Duration::from_millis(300));
    })
    .await;
    let sent = tokio::time::timeout(
        Duration::from_secs(3),
        base(&r.client, hyper::Method::GET, &o).send(),
    )
    .await;
    // Either the client's own timeout fired (an error) or the outer one did; neither retries.
    if let Ok(res) = sent {
        assert_eq!(res.unwrap_err().kind(), ErrorKind::UpstreamTimeout);
    }
    assert_eq!(o.stats.requests.load(Ordering::SeqCst), 1);
    assert_eq!(retries(), 0);
}

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
async fn a_buffered_post_after_a_reset_or_goaway_is_not_replayed() {
    // The origin may already have processed it: a buffered body allows a replay, never justifies one.
    for act in [Act::Drop, Act::Goaway] {
        let (r, o) = setup(first_on(0, act), |_| {}).await;
        let err = base(&r.client, hyper::Method::POST, &o)
            .body(bytes::Bytes::from_static(b"small"))
            .send()
            .await;
        assert!(err.is_err(), "{act:?}");
        assert_eq!(o.stats.requests.load(Ordering::SeqCst), 1, "{act:?}");
    }
    assert_eq!(retries(), 0);
}

#[tokio::test]
async fn a_request_unsent_on_a_closed_http1_keepalive_connection_is_sent_again() {
    let trusted = ca("trusted");
    let (der, key) = leaf(&trusted, HOST);
    let o = h1_closing_origin(vec![der, trusted.der.clone()], key).await;
    let r = rig(&trusted, |_| {});
    for _ in 0..2 {
        let resp = base(&r.client, hyper::Method::GET, &o)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }
    // A streamed POST on a fresh connection each time still works: nothing to re-send.
    assert_eq!(o.stats.requests.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_waiter_on_an_http2_connection_that_sends_goaway_first_succeeds() {
    let trusted = ca("trusted");
    let (der, key) = leaf(&trusted, HOST);
    let o = h2_origin_with(
        vec![der, trusted.der.clone()],
        key,
        ok_script(),
        Arc::new(|c| c == 0),
    )
    .await;
    let r = rig(&trusted, |_| {});
    let (a, b) = tokio::join!(
        base(&r.client, hyper::Method::GET, &o).send(),
        base(&r.client, hyper::Method::GET, &o).send()
    );
    assert_eq!(a.unwrap().status(), 200);
    assert_eq!(b.unwrap().status(), 200);
    assert!(o.stats.conns.load(Ordering::SeqCst) >= 2);
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
async fn a_post_is_not_retried_after_a_goaway() {
    let (r, o) = setup(Arc::new(|_, _| Act::Goaway), |_| {}).await;
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
    tokio::time::sleep(Duration::from_millis(60)).await;
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

async fn setup_with(browser_like: bool, script: Script) -> (Rig, Origin) {
    let trusted = ca("trusted");
    let (der, key) = leaf(&trusted, HOST);
    let o = h2_origin(vec![der, trusted.der.clone()], key, script).await;
    (rig_with(&trusted, browser_like, |_| {}), o)
}

#[tokio::test]
async fn a_post_is_sent_at_most_twice_when_refused_stream_repeats() {
    for browser_like in [false, true] {
        let (r, o) = setup_with(browser_like, Arc::new(|_, _| Act::Refuse)).await;
        let err = base(&r.client, hyper::Method::POST, &o)
            .body(bytes::Bytes::from_static(b"small"))
            .send()
            .await;
        assert!(err.is_err(), "browser_like={browser_like}");
        assert_eq!(
            o.stats.requests.load(Ordering::SeqCst),
            2,
            "browser_like={browser_like}: one attempt and one retry"
        );
    }
}

#[tokio::test]
async fn a_goaway_refused_stream_is_not_retried_for_a_post() {
    // The stream is at or below the GOAWAY's last stream id: the origin may have run it.
    for browser_like in [false, true] {
        let (r, o) = setup_with(browser_like, Arc::new(|_, _| Act::GoawayRefused)).await;
        let err = base(&r.client, hyper::Method::POST, &o)
            .body(bytes::Bytes::from_static(b"small"))
            .send()
            .await;
        assert!(err.is_err(), "browser_like={browser_like}");
        assert_eq!(
            o.stats.requests.load(Ordering::SeqCst),
            1,
            "browser_like={browser_like}"
        );
    }
}

#[tokio::test]
async fn the_plain_client_retries_a_get_once_on_a_new_connection() {
    for act in [Act::Refuse, Act::Goaway] {
        let before = retries();
        let (r, o) = setup_with(false, first_on(0, act)).await;
        let resp = base(&r.client, hyper::Method::GET, &o)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "{act:?}");
        assert_eq!(o.stats.conns.load(Ordering::SeqCst), 2, "{act:?}");
        assert_eq!(o.stats.requests.load(Ordering::SeqCst), 2, "{act:?}");
        assert_eq!(retries() - before, 1, "{act:?}");
    }
}

#[tokio::test]
async fn the_plain_clients_retry_uses_a_new_connection_not_an_idle_one() {
    // Connection 0 serves the first request and stays idle in the pool, then refuses the second.
    let script: Script = Arc::new(|c, n| {
        if c == 0 && n == 1 {
            Act::Refuse
        } else {
            Act::Ok
        }
    });
    let (r, o) = setup_with(false, script).await;
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
    assert_eq!(o.stats.conns.load(Ordering::SeqCst), 2, "retry dialled");
    assert_eq!(retries(), 1);
}

/// Smoke test: pooled connections the origin closed behind the client's back never fail a request
/// or need an Argus retry. Which path wreq takes (unsent re-send or a write onto a dead
/// connection) depends on the runtime's I/O-driver timing, so every outcome is tolerated; the
/// regression guard for the re-send's fresh connection is the wreq unit tests (vendor/wreq,
/// `resend_descriptor` and the pool checkout test, run by the `wreq-patches` CI job).
#[tokio::test]
async fn the_wreq_resend_of_an_unstarted_request_dials_a_new_connection() {
    // Every wait is bounded and the whole test is capped: a round where the race does not occur
    // (or the origin does not close in time) is inconclusive and skipped, never a hang.
    tokio::time::timeout(Duration::from_secs(15), resend_smoke())
        .await
        .expect("smoke test exceeded its 15s budget");
}

async fn resend_smoke() {
    // The origin closes each idle HTTP/1.1 connection once signalled. While the client runtime
    // is blocked, the FINs arrive but the pooled connections still look open, so a request
    // checked out onto one is handed back unsent. The one re-send must dial a new connection.
    let trusted = ca("trusted");
    let (der, key) = leaf(&trusted, HOST);
    let (tx, rx) = tokio::sync::watch::channel(false);
    let o = h1_closing_origin_after(vec![der, trusted.der.clone()], key, Some(rx)).await;
    let r = rig(&trusted, |o| {
        o.connect_timeout = Some(Duration::from_secs(3));
        o.read_timeout = Some(Duration::from_secs(3));
    });
    let started = std::time::Instant::now();
    let bounded = Duration::from_secs(4);
    let mut conclusive = 0;
    for round in 0..61 {
        if started.elapsed() > Duration::from_secs(9) {
            break;
        }
        // Fill the pool with several idle connections. A leftover dead connection from an
        // earlier round may fail one of these; that is not what is under test.
        let calls: Vec<_> = (0..8)
            .map(|_| base(&r.client, hyper::Method::GET, &o).send())
            .collect();
        let Ok(results) =
            tokio::time::timeout(bounded, futures_util::future::join_all(calls)).await
        else {
            tx.send_replace(false);
            continue;
        };
        for resp in results.into_iter().flatten() {
            assert_eq!(resp.status(), 200, "round {round}");
        }
        // Make the origin close them, then block this (the client) runtime until it has.
        let target = o.stats.requests.load(Ordering::SeqCst);
        tx.send_replace(true);
        let t0 = std::time::Instant::now();
        while o.stats.closed.load(Ordering::SeqCst) < target
            && t0.elapsed() < Duration::from_secs(1)
        {
            std::thread::sleep(Duration::from_millis(1));
        }
        let closed_in_time = o.stats.closed.load(Ordering::SeqCst) >= target;
        // Vary the ticks preceding the send so the I/O-driver turn lands differently per round.
        for _ in 0..(round % 61) {
            tokio::spawn(async {});
        }
        if closed_in_time {
            let req = base(&r.client, hyper::Method::GET, &o);
            let res =
                tokio::time::timeout(bounded, tokio::spawn(async move { req.send().await })).await;
            // A timeout is inconclusive.
            if let Ok(joined) = res {
                match joined.unwrap() {
                    Ok(resp) => {
                        assert_eq!(resp.status(), 200, "round {round}");
                        conclusive += 1;
                    }
                    // Written to a dead connection before the client noticed: wreq rightly gives
                    // up (`retried: false`). Only a failed *re-send* is a bug.
                    Err(e) => {
                        let e = format!("{e:?}");
                        assert!(
                            e.contains("retried: false") || e.contains("timed out"),
                            "round {round}: re-send failed: {e}"
                        );
                    }
                }
            }
        }
        // The next round's connections must stay open until signalled.
        tx.send_replace(false);
    }
    // Inconclusive rounds are fine; wreq's re-send, not an Argus retry, did any recovery.
    let _ = conclusive;
    assert_eq!(retries(), 0, "no Argus-level retry was needed");
}

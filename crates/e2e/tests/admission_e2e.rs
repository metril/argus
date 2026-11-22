//! Connection admission over real TCP: the default 10,000 new connections/s limit admits an
//! offered load at that rate with no rejections and enforces the limit above it. Outcomes are
//! read from the proxy's own admission counters.
//!
//! Ignored by default: tens of thousands of connections need a release build and a quiet machine
//! (a debug build on a busy host drains the accept queue far below 10k/s, which says nothing about
//! the limiter). Run with
//! `cargo nextest run --release -p e2e --test admission_e2e --run-ignored all`.

use std::time::{Duration, Instant};

use e2e::{EntryMode, TestEnv};
use tokio::net::TcpStream;

/// Offer `rate` new connections/s for `secs` on a fixed schedule from 8 workers (connect, then
/// close). Returns (connected, accepted, rejected, seconds until the last one was seen) as counted by the proxy once it has seen them
/// all.
async fn offer(env: &TestEnv, rate: u64, secs: u64) -> (u64, u64, u64, f64) {
    let addr = env.proxy.entry_addr();
    let workers = 8u64;
    let per_worker = rate * secs / workers;
    let gap = Duration::from_nanos(1_000_000_000 * workers / rate);
    let start = Instant::now() + Duration::from_millis(100);
    let mut hs = Vec::new();
    for w in 0..workers {
        hs.push(tokio::spawn(async move {
            let mut connected = 0u64;
            let mut pending = Vec::new();
            for i in 0..per_worker {
                let at = start + gap * i as u32 + gap * w as u32 / workers as u32;
                tokio::time::sleep_until(at.into()).await;
                // Connect in its own task so a slow handshake does not delay the schedule.
                pending.push(tokio::spawn(async move {
                    let Ok(s) = TcpStream::connect(addr).await else {
                        return false;
                    };
                    // Close with RST: no TIME_WAIT, so tens of thousands of connections do not
                    // exhaust the ephemeral ports other tests need.
                    #[allow(deprecated)] // zero linger never blocks; it makes the close an RST
                    let _ = s.set_linger(Some(Duration::ZERO));
                    true
                }));
            }
            for p in pending {
                connected += p.await.unwrap() as u64;
            }
            connected
        }));
    }
    let mut connected = 0;
    for h in hs {
        connected += h.await.unwrap();
    }
    // Let the accept loop drain its backlog: done when the counters have been still for 1 s (or
    // all connections are accounted for). `elapsed` runs from the first scheduled connection to
    // the last change.
    let deadline = Instant::now() + Duration::from_secs(60);
    let (mut last, mut last_change) = (0, Instant::now());
    loop {
        let s = env.proxy.load_manager.stats();
        let seen = s.connections_accepted + s.connections_rejected;
        if seen != last {
            (last, last_change) = (seen, Instant::now());
        }
        if seen >= connected
            || last_change.elapsed() > Duration::from_secs(1)
            || Instant::now() > deadline
        {
            let elapsed = last_change.duration_since(start).as_secs_f64();
            return (
                connected,
                s.connections_accepted,
                s.connections_rejected,
                elapsed,
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn env_default() -> TestEnv {
    TestEnv::start_tweaked(EntryMode::Explicit, &[], &|c| {
        c.performance.connection_rate_limit = Some(10_000); // the default
        c.performance.max_connections = 0; // auto
    })
    .await
}

#[ignore = "needs a release build and a quiet machine"]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn default_limit_admits_10k_per_second_without_rejections() {
    let env = env_default().await;
    let (connected, accepted, rejected, secs) = offer(&env, 10_000, 3).await;
    eprintln!("connected {connected} accepted {accepted} rejected {rejected} in {secs:.2}s");
    assert_eq!(connected, 30_000);
    assert_eq!(rejected, 0);
    assert_eq!(accepted, connected);
}

#[ignore = "needs a release build and a quiet machine"]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn limit_is_enforced_above_10k_per_second() {
    let env = env_default().await;
    let (connected, accepted, rejected, secs) = offer(&env, 20_000, 3).await;
    eprintln!("connected {connected} accepted {accepted} rejected {rejected} in {secs:.2}s");
    // The limiter admits 10k/s (plus a 100 ms burst) over however long the accept loop took.
    assert!(
        accepted as f64 <= 10_000.0 * secs + 1_500.0,
        "{accepted} accepted in {secs}s"
    );
    assert!(accepted >= 25_000, "{accepted} accepted");
    assert!(rejected >= 15_000, "{rejected} rejected");
}

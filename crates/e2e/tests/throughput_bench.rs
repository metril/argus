//! Bulk-download throughput through the proxy (MITM HTTP/1.1, MITM HTTP/2, opaque tunnel, plain
//! HTTP). A benchmark, not a correctness test: ignored by default, run in release mode with
//!
//!     cargo test --release -p e2e --test throughput_bench -- --ignored --nocapture
//!
//! It prints MB/s per path and repetition; compare before and after a change to the hot path.

use bytes::Bytes;
use e2e::{EntryMode, HttpVersion, MockResponse, StreamSpec, TestClient, TestEnv};
use std::time::Instant;

const TOTAL: usize = 768 * 1024 * 1024;
const REPS: usize = 3;

async fn pull(c: &TestClient, url: &str) -> f64 {
    let t = Instant::now();
    let mut r = c.get(url).await;
    let mut n = 0usize;
    while let Some(chunk) = r.chunk().await.expect("chunk") {
        n += chunk.len();
    }
    assert_eq!(n, TOTAL);
    n as f64 / 1e6 / t.elapsed().as_secs_f64()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn bulk_download_throughput() {
    let env = TestEnv::start(EntryMode::Explicit, &[]).await;
    let chunk = Bytes::from(vec![b'x'; 64 * 1024]);
    env.origin.route_fn("/bulk", {
        let chunk = chunk.clone();
        move |_| MockResponse::streaming(200, StreamSpec::new(Bytes::new(), chunk.clone(), TOTAL))
    });
    env.proxy
        .ctx
        .bypass()
        .update(|s| {
            s.entries.push(common::bypass::Entry {
                id: common::bypass::new_id(),
                pattern: "tunnel.test".into(),
                mode: common::bypass::BypassMode::NoDecrypt,
                source: "custom".into(),
                note: None,
                updated_at: 0,
            });
            Ok(())
        })
        .unwrap();
    let origin_only = TestClient::trusting(
        &env.proxy,
        HttpVersion::Http1,
        &[env.origin.ca_pem().as_bytes()],
    );
    let h1 = env.client_with(HttpVersion::Http1);
    let h2 = env.client_with(HttpVersion::Http2);
    let cases: Vec<(&str, &TestClient, String)> = vec![
        ("mitm-h1", &h1, env.origin.https_url("mitm1.test", "/bulk")),
        ("mitm-h2", &h2, env.origin.https_url("mitm2.test", "/bulk")),
        (
            "tunnel",
            &origin_only,
            env.origin.https_url("tunnel.test", "/bulk"),
        ),
        ("plain", &h1, env.origin.http_url("plain.test", "/bulk")),
    ];
    // Warm up (certificates, pools).
    for (_, c, url) in &cases {
        let _ = pull(c, url).await;
    }
    for (name, c, url) in &cases {
        let mut v = Vec::new();
        for _ in 0..REPS {
            v.push(pull(c, url).await);
        }
        let mean = v.iter().sum::<f64>() / v.len() as f64;
        println!(
            "BENCH {name}: {} MB/s mean {mean:.0}",
            v.iter()
                .map(|x| format!("{x:.0}"))
                .collect::<Vec<_>>()
                .join(" ")
        );
    }
}

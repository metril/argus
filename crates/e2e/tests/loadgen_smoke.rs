//! The load generator's library code drives a tiny closed-loop load through the proxy, over both
//! protocols, with every request class, and sees no errors.

use std::sync::Arc;
use std::time::Duration;

use e2e::loadgen::{
    generate_list, measure, measure_paired, setup_origin, Model, PhaseCfg, Proto, Workload,
};
use e2e::{install_rules_text, EntryMode, TestClient, TestEnv};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closed_loop_through_proxy_has_no_errors() {
    let env = TestEnv::start_tweaked(EntryMode::Explicit, &[], &|c| {
        c.performance.connection_rate_limit = Some(0);
    })
    .await;
    setup_origin(&env.origin);
    let workload = Workload {
        weights: [4, 2, 2, 2],
        hosts: 1,
        seed: 7,
        suffix: "test".into(),
    };
    install_rules_text(&env.proxy.engine, generate_list(500, 1, &workload), true);
    for proto in [Proto::H1, Proto::H2] {
        let cfg = PhaseCfg {
            proto,
            model: Model::Closed { conns: 4 },
            duration: Duration::from_millis(300),
            workload: workload.clone(),
            port: env.origin.https_port(),
            proxied: true,
        };
        let client = Arc::new(TestClient::new(&env.proxy, proto.version()));
        let m = measure(client, "proxy", cfg, Duration::from_millis(100), None).await;
        assert!(
            !m.failed(),
            "{} failed: {:?} {:?}",
            proto.name(),
            m.out.errors,
            m.warm.errors
        );
        assert!(
            m.out.ok > 10,
            "{}: only {} requests",
            proto.name(),
            m.out.ok
        );
        assert!(m.lat().p99 > 0.0);
    }
}

/// Direct and proxy are driven in one run: every scheduled request goes out on both, and each
/// path is judged on its own responses.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn paired_run_drives_both_paths_in_the_same_run() {
    let env = TestEnv::start_tweaked(EntryMode::Explicit, &[], &|_| {}).await;
    setup_origin(&env.origin);
    let workload = Workload {
        weights: [4, 2, 2, 2],
        hosts: 1,
        seed: 7,
        suffix: "test".into(),
    };
    install_rules_text(&env.proxy.engine, generate_list(500, 1, &workload), true);
    let cfg = |proxied| PhaseCfg {
        proto: Proto::H1,
        model: Model::Open {
            rate: 200,
            max_inflight: 256,
        },
        duration: Duration::from_millis(500),
        workload: workload.clone(),
        port: env.origin.https_port(),
        proxied,
    };
    let direct = Arc::new(TestClient::direct(&env.origin, Proto::H1.version()));
    let proxy = Arc::new(TestClient::new(&env.proxy, Proto::H1.version()));
    let (d, p) = measure_paired(
        (direct, cfg(false)),
        (proxy, cfg(true)),
        Duration::from_millis(100),
        None,
    )
    .await;
    for m in [&d, &p] {
        assert!(
            !m.failed(),
            "{}: {:?} {:?}",
            m.path,
            m.out.errors,
            m.warm.errors
        );
        assert!(m.paired);
    }
    // The same schedule fed both paths.
    assert_eq!(d.out.ok, p.out.ok);
    assert!(p.out.ok >= 90, "{}", p.out.ok);
    assert!(p.lat().p99 > 0.0 && d.lat().p99 > 0.0);
}

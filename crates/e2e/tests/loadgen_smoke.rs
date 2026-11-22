//! The load generator's library code drives a tiny closed-loop load through the proxy, over both
//! protocols, with every request class, and sees no errors.

use std::sync::Arc;
use std::time::Duration;

use e2e::loadgen::{generate_list, measure, setup_origin, Model, PhaseCfg, Proto, Workload};
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

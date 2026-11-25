//! The real upstream certificate is recorded and linked from the request log, and an origin with
//! an invalid certificate gets Argus's explanatory page instead of a generic error.

use e2e::{e2e_test, MockResponse};
use filter_engine::{ErrorKind, EventAction};

e2e_test!(
    log_event_links_to_the_origin_certificate,
    rules = Vec::<&str>::new(),
    |env| {
        env.origin.route("/ok", MockResponse::ok("fine"));
        let resp = env
            .client()
            .get(&env.origin.https_url("good.test", "/ok"))
            .await;
        assert_eq!(resp.status(), 200);

        let all = env.proxy.engine.recent_requests(10);
        let ev = all
            .iter()
            .find(|e| e.url.contains("good.test") && e.action == EventAction::Allowed)
            .unwrap_or_else(|| panic!("no event in {all:?}"));
        let fp = ev.cert_fp.clone().expect("cert_fp on a decrypted request");

        let api = env.proxy.api().await;
        let port = env.origin.https_port();
        let r = api.get(&format!("/certs/{fp}?host=good.test:{port}")).await;
        r.assert_status_ok();
        let info: serde_json::Value = r.json();
        assert_eq!(info["fp"], fp.as_str());
        assert_eq!(info["verdict"], "ok");
        assert!(info["subject"].as_str().unwrap().contains("good.test"));
        assert!(info["issuer"].as_str().unwrap().contains("e2e origin CA"));
        assert!(info["sans"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s == "good.test"));
        // The full chain came from the proxied request itself: no probe handshake was needed.
        assert!(info["chain"].as_array().unwrap().len() > 1, "{info}");
        assert_eq!(env.proxy.ctx.prober().unwrap().handshakes(), 0);

        let by_host: serde_json::Value = api
            .get(&format!("/certs/by-host/good.test:{port}"))
            .await
            .json();
        assert_eq!(by_host["fp"], fp.as_str());
        api.get("/certs/by-host/unseen.test")
            .await
            .assert_status_not_found();
    }
);

e2e_test!(
    expired_origin_certificate_gets_an_explanatory_page,
    rules = Vec::<&str>::new(),
    |env| {
        env.origin.route("/", MockResponse::ok("never served"));
        let resp = env
            .client()
            .get(&env.origin.https_url("expired-a.test", "/"))
            .await;
        assert_eq!(resp.status(), 502);
        assert_eq!(
            resp.headers().get("x-adblock").map(|v| v.as_bytes()),
            Some(&b"cert-error"[..])
        );
        let html = resp.text().await.unwrap();
        assert!(html.contains("expired-a.test"), "{html}");
        assert!(html.contains("has expired"), "{html}");
        assert!(html.contains("e2e origin CA"), "{html}");
        assert!(!html.contains("never served"));

        let all = env.proxy.engine.recent_requests(10);
        let ev = all
            .iter()
            .find(|e| e.url.contains("expired-a.test"))
            .unwrap_or_else(|| panic!("no event in {all:?}"));
        assert_eq!(ev.action, EventAction::Error);
        assert_eq!(ev.error_kind, Some(ErrorKind::UpstreamTls));
        let fp = ev.cert_fp.clone().expect("cert_fp on the failed request");
        let api = env.proxy.api().await;
        let info: serde_json::Value = api
            .get(&format!("/certs/{fp}?host=expired-a.test"))
            .await
            .json();
        assert_eq!(info["verdict"], "invalid");
        assert_eq!(info["reason"], "expired");
    }
);

e2e_test!(
    each_response_carries_its_own_connections_certificate,
    rules = Vec::<&str>::new(),
    |env| {
        env.origin.route("/ok", MockResponse::ok("fine"));
        // Two hosts, two certificates, interleaved: every event links to its own host's cert.
        for _ in 0..2 {
            for h in ["one.test", "two.test"] {
                env.client().get(&env.origin.https_url(h, "/ok")).await;
            }
        }
        let api = env.proxy.api().await;
        let all = env.proxy.engine.recent_requests(10);
        assert_eq!(all.len(), 4);
        for e in &all {
            let host = if e.url.contains("one.test") {
                "one.test"
            } else {
                "two.test"
            };
            let fp = e.cert_fp.clone().expect("cert_fp");
            let info: serde_json::Value = api
                .get(&format!(
                    "/certs/{fp}?host={host}:{}",
                    env.origin.https_port()
                ))
                .await
                .json();
            assert!(info["subject"].as_str().unwrap().contains(host), "{info}");
        }
    }
);

#[tokio::test]
async fn tls_info_is_present_on_every_response_even_when_sessions_resume() {
    let origin = e2e::TestOrigin::start().await;
    origin.route("/ok", MockResponse::ok("fine"));
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("ca.pem");
    std::fs::write(&ca, origin.ca_pem()).unwrap();
    let opts = proxy_core::upstream::UpstreamOptions {
        extra_ca_paths: vec![ca],
        resolve_all_to: Some(origin.ip()),
        // No pooling: every request is a new connection that may resume the previous session.
        pool_max_idle_per_host: Some(0),
        ..Default::default()
    };
    let client = proxy_core::upstream::build_upstream_client(&opts).unwrap();
    let url = origin.https_url("resume.test", "/ok");
    let mut fps = Vec::new();
    for _ in 0..3 {
        let r = client.get(&url).send().await.unwrap();
        let der = r
            .peer_certificate()
            .expect("peer certificate on every response")
            .to_vec();
        fps.push(common::certstore::fingerprint(&der));
    }
    assert!(fps.windows(2).all(|w| w[0] == w[1]));
}

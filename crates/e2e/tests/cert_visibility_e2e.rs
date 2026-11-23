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
        let r = api.get(&format!("/certs/{fp}")).await;
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
        assert_eq!(info["chain"].as_array().unwrap().len(), 1);

        let by_host: serde_json::Value = api.get("/certs/by-host/good.test").await.json();
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
        let info: serde_json::Value = api.get(&format!("/certs/{fp}")).await.json();
        assert_eq!(info["verdict"], "invalid");
        assert_eq!(info["reason"], "expired");
    }
);

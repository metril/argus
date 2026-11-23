//! Bypass through the real proxy in both entry modes: `full` leaves no log event and skips
//! filtering, `no_decrypt` tunnels (no MITM) with a host-only passthrough event and keeps
//! host-level blocking, and the old `tls_passthrough_hosts` key still works (migrated).

use common::bypass::{new_id, BypassMode, Entry};
use e2e::{e2e_test, EntryMode, HttpVersion, MockResponse, TestClient, TestEnv};
use filter_engine::{EventAction, EventMode};

fn add(env: &TestEnv, pattern: &str, mode: BypassMode) {
    env.proxy
        .ctx
        .bypass()
        .update(|s| {
            s.entries.push(Entry {
                id: new_id(),
                pattern: pattern.into(),
                mode,
                source: "custom".into(),
                note: None,
                updated_at: 0,
            });
            Ok(())
        })
        .unwrap();
}

fn origin_only_client(env: &TestEnv) -> TestClient {
    // Trusts only the origin's CA: succeeds only when the proxy did not intercept.
    TestClient::trusting(
        &env.proxy,
        HttpVersion::Http1,
        &[env.origin.ca_pem().as_bytes()],
    )
}

fn expected_mode(env: &TestEnv) -> EventMode {
    match env.mode {
        EntryMode::Explicit => EventMode::Explicit,
        EntryMode::Transparent => EventMode::Transparent,
    }
}

e2e_test!(
    full_bypass_is_not_intercepted_filtered_or_logged,
    rules = ["||secret.test^"],
    |env| {
        add(&env, "secret.test", BypassMode::Full);
        env.origin.route("/p", MockResponse::ok("direct"));
        let before = env.proxy.ctx.bypass().bypassed_total();
        let resp = origin_only_client(&env)
            .get(&env.origin.https_url("secret.test", "/p"))
            .await;
        // The blocking rule did not apply and the proxy CA was never presented.
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.text().await.unwrap(), "direct");
        assert_eq!(env.proxy.mitm.as_ref().unwrap().generation_count(), 0);
        let events = env.proxy.engine.recent_requests(20);
        assert!(
            events.iter().all(|e| !e.url.contains("secret.test")),
            "full bypass must leave no log event: {events:?}"
        );
        assert!(
            env.proxy.ctx.bypass().bypassed_total() > before,
            "aggregate counter"
        );
    }
);

e2e_test!(
    no_decrypt_tunnels_with_a_host_only_passthrough_event,
    rules = Vec::<&str>::new(),
    |env| {
        add(&env, "nd.test", BypassMode::NoDecrypt);
        env.origin.route("/p", MockResponse::ok("direct"));
        let resp = origin_only_client(&env)
            .get(&env.origin.https_url("nd.test", "/p?token=SECRET"))
            .await;
        assert_eq!(resp.status(), 200);
        assert_eq!(
            env.proxy.mitm.as_ref().unwrap().generation_count(),
            0,
            "no MITM"
        );
        let events = env.proxy.engine.recent_requests(20);
        let ev = events
            .iter()
            .find(|e| e.action == EventAction::Passthrough && e.url.contains("nd.test"))
            .unwrap_or_else(|| panic!("no passthrough event in {events:?}"));
        assert_eq!(ev.mode, expected_mode(&env));
        // Host only: nothing of the path or query was visible, so nothing is logged.
        assert!(
            !ev.url.contains("SECRET") && !ev.url.contains("/p"),
            "{}",
            ev.url
        );
        assert_eq!(
            env.proxy.ctx.bypass().bypassed_total(),
            0,
            "no_decrypt is not counted"
        );
    }
);

e2e_test!(
    no_decrypt_still_enforces_host_level_blocking,
    rules = ["||blocked-nd.test^"],
    |env| {
        add(&env, "blocked-nd.test", BypassMode::NoDecrypt);
        env.origin.route("/p", MockResponse::ok("direct"));
        let r = origin_only_client(&env)
            .request(
                reqwest::Method::GET,
                &env.origin.https_url("blocked-nd.test", "/p"),
            )
            .send()
            .await;
        assert!(
            r.is_err(),
            "a blocked host must not be reachable through a no_decrypt tunnel"
        );
        assert!(env.origin.requests_for("/p").is_empty());
        let events = env.proxy.engine.recent_requests(20);
        assert!(
            events
                .iter()
                .any(|e| e.action == EventAction::Blocked && e.url.contains("blocked-nd.test")),
            "{events:?}"
        );
    }
);

e2e_test!(
    plain_http_to_a_full_host_is_forwarded_unfiltered_and_unlogged,
    rules = ["||plain-full.test^"],
    |env| {
        add(&env, "plain-full.test", BypassMode::Full);
        env.origin.route("/x", MockResponse::ok("plain-body"));
        let resp = env
            .client()
            .get(&env.origin.http_url("plain-full.test", "/x"))
            .await;
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.text().await.unwrap(), "plain-body");
        let events = env.proxy.engine.recent_requests(20);
        assert!(
            events.iter().all(|e| !e.url.contains("plain-full.test")),
            "{events:?}"
        );
        assert!(env.proxy.ctx.bypass().bypassed_total() >= 1);
    }
);

// The old config key: hosts become `migrated` entries and keep working.
e2e_test!(
    legacy_tls_passthrough_hosts_become_migrated_no_decrypt_entries,
    rules = Vec::<&str>::new(),
    passthrough = ["legacy.test", "*.legacy-wild.test"],
    |env| {
        let hit = env.proxy.ctx.bypass().lookup("legacy.test").unwrap();
        assert_eq!(
            (hit.source.as_str(), hit.mode),
            ("migrated", BypassMode::NoDecrypt)
        );
        assert!(env
            .proxy
            .ctx
            .bypass()
            .lookup("a.legacy-wild.test")
            .is_some());
        env.origin.route("/p", MockResponse::ok("direct"));
        let resp = origin_only_client(&env)
            .get(&env.origin.https_url("legacy.test", "/p"))
            .await;
        assert_eq!(resp.status(), 200);
        assert_eq!(env.proxy.mitm.as_ref().unwrap().generation_count(), 0);
    }
);

// Extended Validation: an upstream leaf certificate with the EV policy is tunnelled (no MITM,
// passthrough event with source `ev`); a normal certificate is intercepted as usual.
e2e_test!(
    ev_sites_are_tunnelled_and_other_sites_are_intercepted,
    rules = Vec::<&str>::new(),
    |env| {
        env.origin.route("/p", MockResponse::ok("direct"));
        // EV host: reachable by a client that trusts only the origin CA, proving no MITM.
        let resp = origin_only_client(&env)
            .get(&env.origin.https_url("ev-bank.test", "/p"))
            .await;
        assert_eq!(resp.status(), 200);
        assert_eq!(
            env.proxy.mitm.as_ref().unwrap().generation_count(),
            0,
            "EV: no certificate minted"
        );
        let events = env.proxy.engine.recent_requests(20);
        let ev = events
            .iter()
            .find(|e| e.action == EventAction::Passthrough && e.url.contains("ev-bank.test"))
            .unwrap_or_else(|| panic!("no passthrough event in {events:?}"));
        assert_eq!(ev.rule.as_deref(), Some("ev"));
        assert_eq!(ev.mode, expected_mode(&env));
        assert_eq!(
            env.proxy.ctx.bypass().bypassed_total(),
            0,
            "not counted as full bypass"
        );

        // Non-EV host: intercepted (the proxy CA is presented and a certificate is minted).
        let resp = env
            .client()
            .get(&env.origin.https_url("plain-site.test", "/p"))
            .await;
        assert_eq!(resp.status(), 200);
        assert_eq!(env.proxy.mitm.as_ref().unwrap().generation_count(), 1);
    }
);

e2e_test!(
    ev_detection_can_be_switched_off_live,
    rules = Vec::<&str>::new(),
    |env| {
        env.proxy
            .ctx
            .bypass()
            .update(|s| {
                s.ev_no_decrypt = false;
                Ok(())
            })
            .unwrap();
        env.origin.route("/p", MockResponse::ok("direct"));
        let resp = env
            .client()
            .get(&env.origin.https_url("ev-shop.test", "/p"))
            .await;
        assert_eq!(resp.status(), 200);
        assert_eq!(
            env.proxy.mitm.as_ref().unwrap().generation_count(),
            1,
            "decrypted again"
        );
    }
);

// Fail-safe: while an enabled first-party list has not loaded, nothing is decrypted.
fn enable_first_party(env: &TestEnv) {
    env.proxy
        .ctx
        .bypass()
        .update(|s| {
            s.ensure_first_party();
            Ok(())
        })
        .unwrap();
}

fn load_all_lists(env: &TestEnv) {
    env.proxy
        .ctx
        .bypass()
        .update(|s| {
            for x in s
                .subscriptions
                .iter_mut()
                .filter(|x| x.id.starts_with("argus:"))
            {
                x.last_fetched = Some(1);
            }
            Ok(())
        })
        .unwrap();
}

e2e_test!(
    failsafe_tunnels_everything_until_the_lists_load_and_then_decrypts_live,
    rules = Vec::<&str>::new(),
    |env| {
        enable_first_party(&env);
        assert!(env.proxy.ctx.bypass().failsafe_active());
        env.origin.route("/p", MockResponse::ok("direct"));
        // Fail-safe: the proxy CA is not presented (a client trusting only the origin CA works)
        // and no certificate is minted, whatever the host.
        let resp = origin_only_client(&env)
            .get(&env.origin.https_url("some-site.test", "/p"))
            .await;
        assert_eq!(resp.status(), 200);
        assert_eq!(
            env.proxy.mitm.as_ref().unwrap().generation_count(),
            0,
            "no MITM"
        );
        let events = env.proxy.engine.recent_requests(20);
        let ev = events
            .iter()
            .find(|e| e.action == EventAction::Passthrough && e.url.contains("some-site.test"))
            .unwrap_or_else(|| panic!("no passthrough event in {events:?}"));
        assert_eq!(ev.rule.as_deref(), Some("failsafe"));
        assert_eq!(ev.mode, expected_mode(&env));

        // The lists load: decryption turns on live, no restart.
        load_all_lists(&env);
        assert!(!env.proxy.ctx.bypass().failsafe_active());
        let resp = env
            .client()
            .get(&env.origin.https_url("other-site.test", "/p"))
            .await;
        assert_eq!(resp.status(), 200);
        assert_eq!(
            env.proxy.mitm.as_ref().unwrap().generation_count(),
            1,
            "decrypted now"
        );
    }
);

e2e_test!(
    failsafe_still_enforces_hostname_blocking,
    rules = ["||blocked-fs.test^"],
    |env| {
        enable_first_party(&env);
        env.origin.route("/p", MockResponse::ok("direct"));
        let r = origin_only_client(&env)
            .request(
                reqwest::Method::GET,
                &env.origin.https_url("blocked-fs.test", "/p"),
            )
            .send()
            .await;
        assert!(
            r.is_err(),
            "SNI-level blocking holds while nothing is decrypted"
        );
        assert!(env.origin.requests_for("/p").is_empty());
        assert!(env
            .proxy
            .engine
            .recent_requests(20)
            .iter()
            .any(|e| e.action == EventAction::Blocked && e.url.contains("blocked-fs.test")));
    }
);

e2e_test!(
    the_admin_override_decrypts_even_while_the_failsafe_would_hold,
    rules = Vec::<&str>::new(),
    |env| {
        enable_first_party(&env);
        env.proxy
            .ctx
            .bypass()
            .update(|s| {
                s.decrypt_without_lists = true;
                Ok(())
            })
            .unwrap();
        assert!(!env.proxy.ctx.bypass().failsafe_active());
        env.origin.route("/p", MockResponse::ok("direct"));
        let resp = env
            .client()
            .get(&env.origin.https_url("override.test", "/p"))
            .await;
        assert_eq!(resp.status(), 200);
        assert_eq!(env.proxy.mitm.as_ref().unwrap().generation_count(), 1);
    }
);

// A client that refuses the proxy's certificate (a pinned app) shows up as an `error` event
// with `error_kind: client_rejected_cert`, in both entry modes.
e2e_test!(
    a_client_rejecting_the_proxy_certificate_is_logged_as_client_rejected_cert,
    rules = Vec::<&str>::new(),
    |env| {
        env.origin.route("/p", MockResponse::ok("x"));
        // Trusts only the origin CA, so the proxy's minted certificate is refused.
        let r = origin_only_client(&env)
            .request(
                reqwest::Method::GET,
                &env.origin.https_url("pinned-app.test", "/p"),
            )
            .send()
            .await;
        assert!(
            r.is_err(),
            "the client must refuse the intercepting certificate"
        );
        let mut found = None;
        for _ in 0..100 {
            found = env
                .proxy
                .engine
                .recent_requests(20)
                .into_iter()
                .find(|e| e.action == EventAction::Error && e.url.contains("pinned-app.test"));
            if found.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let ev = found.expect("an error event for the refused handshake");
        assert_eq!(
            ev.error_kind,
            Some(filter_engine::ErrorKind::ClientRejectedCert),
            "{ev:?}"
        );
        assert_eq!(ev.mode, expected_mode(&env));
    }
);

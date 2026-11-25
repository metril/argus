//! The upstream proxy setting: redacted reads, kept passwords, own-listener refusal, live apply
//! with rollback, persistence, and the connection test.

mod common;

use axum::http::StatusCode;
use common::TestContext;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use web_api::{ProxyBind, RuntimeControl};

#[derive(Default)]
struct Fake {
    /// The upstream proxies `apply_access` was given.
    applied: Mutex<Vec<::common::config::UpstreamProxy>>,
    fail_access: Mutex<Option<String>>,
    tested: Mutex<Vec<::common::config::UpstreamProxy>>,
    test_result: Mutex<Option<Result<u64, String>>>,
}

#[async_trait::async_trait]
impl RuntimeControl for Fake {
    async fn rebind_proxy(&self, _: &str, port: u16, t: Option<u16>) -> Result<ProxyBind, String> {
        Ok(bind(port, t))
    }
    async fn apply_access(&self, c: &::common::config::ProxyConfig) -> Result<(), String> {
        if let Some(e) = self.fail_access.lock().unwrap().clone() {
            return Err(e);
        }
        self.applied
            .lock()
            .unwrap()
            .push(c.proxy.upstream.proxy.clone());
        Ok(())
    }
    fn listener_counters(&self) -> (web_api::ListenerCounters, web_api::ListenerCounters) {
        let c = web_api::ListenerCounters {
            active_connections: 0,
            requests_per_sec: 0.0,
            clients: 0,
        };
        (c, c)
    }
    async fn proxy_bind(&self) -> Option<ProxyBind> {
        Some(bind(8080, None))
    }
    async fn note_webui(&self, _: &str, _: u16) {}
    async fn test_upstream_proxy(
        &self,
        cfg: &::common::config::UpstreamProxy,
        _host: &str,
        _port: u16,
    ) -> Result<std::time::Duration, String> {
        self.tested.lock().unwrap().push(cfg.clone());
        match self.test_result.lock().unwrap().clone() {
            Some(Ok(ms)) => Ok(std::time::Duration::from_millis(ms)),
            Some(Err(e)) => Err(e),
            None => Ok(std::time::Duration::from_millis(1)),
        }
    }
}

fn bind(port: u16, t: Option<u16>) -> ProxyBind {
    ProxyBind {
        proxy_down: false,
        transparent_down: false,
        proxy_error: None,
        transparent_error: None,
        proxy: SocketAddr::from(([127, 0, 0, 1], port)),
        transparent: t.map(|p| SocketAddr::from(([127, 0, 0, 1], p))),
    }
}

async fn put(sess: &common::Sess, body: Value) -> axum_test::TestResponse {
    let etag = sess
        .get("/api/v1/config")
        .await
        .header("etag")
        .to_str()
        .unwrap()
        .to_string();
    sess.put("/api/v1/config")
        .add_header("if-match", etag)
        .json(&body)
        .await
}

fn proxy(extra: Value) -> Value {
    let mut p = json!({"enabled": true, "kind": "socks5", "host": "10.1.2.3", "port": 1080,
        "username": "alice", "password": "hunter2"});
    p.as_object_mut()
        .unwrap()
        .extend(extra.as_object().cloned().unwrap_or_default());
    json!({"upstream_proxy": p})
}

#[tokio::test]
async fn saved_applied_live_persisted_and_the_password_is_never_returned() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let fake = Arc::new(Fake::default());
    assert!(ctx.state.runtime.set(fake.clone()).is_ok());

    let r = put(&admin, proxy(json!({}))).await;
    r.assert_status_ok();
    let body: Value = r.json();
    assert!(body["applied"]
        .as_array()
        .unwrap()
        .contains(&json!("upstream_proxy")));
    let up = &body["upstream_proxy"];
    assert_eq!(up["enabled"], true);
    assert_eq!(up["kind"], "socks5");
    assert_eq!(up["host"], "10.1.2.3");
    assert_eq!(up["port"], 1080);
    assert_eq!(up["username"], "alice");
    assert_eq!(up["password"], "set");

    // The running proxy got the real password; the API shows only "set".
    assert_eq!(
        fake.applied.lock().unwrap().last().unwrap().password,
        "hunter2"
    );
    let got = admin.get("/api/v1/config").await;
    assert!(!got.text().contains("hunter2"));
    assert_eq!(got.json::<Value>()["upstream_proxy"]["password"], "set");
    let defaults = admin.get("/api/v1/config/defaults").await;
    assert_eq!(
        defaults.json::<Value>()["upstream_proxy"]["password"],
        "unset"
    );

    // Persisted, readable by the owner only.
    let path = ctx.state.overlay_path.read().clone();
    let overlay = std::fs::read_to_string(&path).unwrap();
    assert!(
        overlay.contains("hunter2") && overlay.contains("10.1.2.3"),
        "{overlay}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o077,
            0
        );
    }
    admin.post("/api/v1/config/reload").await.assert_status_ok();
    assert_eq!(
        ctx.state
            .proxy_state
            .config
            .read()
            .proxy
            .upstream
            .proxy
            .password,
        "hunter2"
    );
}

#[tokio::test]
async fn an_empty_password_keeps_the_saved_one_and_an_emptied_username_drops_it() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    put(&admin, proxy(json!({}))).await.assert_status_ok();

    put(
        &admin,
        json!({"upstream_proxy": {"enabled": true, "password": ""}}),
    )
    .await
    .assert_status_ok();
    let cfg = ctx
        .state
        .proxy_state
        .config
        .read()
        .proxy
        .upstream
        .proxy
        .clone();
    assert_eq!((cfg.port, cfg.password.as_str()), (1080, "hunter2"));

    put(&admin, json!({"upstream_proxy": {"password": "new-pass"}}))
        .await
        .assert_status_ok();
    assert_eq!(
        ctx.state
            .proxy_state
            .config
            .read()
            .proxy
            .upstream
            .proxy
            .password,
        "new-pass"
    );

    put(&admin, json!({"upstream_proxy": {"username": ""}}))
        .await
        .assert_status_ok();
    let cfg = ctx
        .state
        .proxy_state
        .config
        .read()
        .proxy
        .upstream
        .proxy
        .clone();
    assert_eq!((cfg.username.as_str(), cfg.password.as_str()), ("", ""));
}

#[tokio::test]
async fn bad_settings_and_own_listeners_are_refused_and_nothing_is_saved() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let before = ctx
        .state
        .proxy_state
        .config
        .read()
        .proxy
        .upstream
        .proxy
        .clone();
    for (body, needle) in [
        (proxy(json!({"host": ""})), "host is required"),
        (proxy(json!({"host": "bad host!"})), "not a host name"),
        (proxy(json!({"port": 0})), "port"),
        // The default Argus proxy port on loopback.
        (
            proxy(json!({"host": "127.0.0.1", "port": 8080})),
            "own listeners",
        ),
        (
            proxy(json!({"host": "localhost", "port": 3000})),
            "own listeners",
        ),
        (
            proxy(json!({"username": "", "password": "x"})),
            "needs a username",
        ),
    ] {
        let r = put(&admin, body.clone()).await;
        assert_eq!(r.status_code(), StatusCode::BAD_REQUEST, "{body}");
        assert!(r.text().contains(needle), "{needle}: {}", r.text());
    }
    assert_eq!(
        ctx.state.proxy_state.config.read().proxy.upstream.proxy,
        before
    );
    assert!(!ctx.state.overlay_path.read().exists());
}

#[tokio::test]
async fn a_runtime_that_cannot_apply_the_proxy_changes_nothing() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let fake = Arc::new(Fake::default());
    assert!(ctx.state.runtime.set(fake.clone()).is_ok());
    put(&admin, proxy(json!({}))).await.assert_status_ok();
    let saved = std::fs::read_to_string(ctx.state.overlay_path.read().clone()).unwrap();

    *fake.fail_access.lock().unwrap() =
        Some("upstream proxy 10.9.9.9:1: the proxy's own listener".into());
    let r = put(&admin, proxy(json!({"host": "10.9.9.9", "port": 1}))).await;
    assert_eq!(r.status_code(), StatusCode::BAD_REQUEST);
    assert!(r.text().contains("own listener"), "{}", r.text());
    // The old proxy stays in the running config and on disk.
    let cfg = ctx
        .state
        .proxy_state
        .config
        .read()
        .proxy
        .upstream
        .proxy
        .clone();
    assert_eq!((cfg.host.as_str(), cfg.port), ("10.1.2.3", 1080));
    assert_eq!(
        std::fs::read_to_string(ctx.state.overlay_path.read().clone()).unwrap(),
        saved
    );
}

#[tokio::test]
async fn switching_it_off_applies_live() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let fake = Arc::new(Fake::default());
    assert!(ctx.state.runtime.set(fake.clone()).is_ok());
    put(&admin, proxy(json!({}))).await.assert_status_ok();
    let r = put(&admin, json!({"upstream_proxy": {"enabled": false}})).await;
    r.assert_status_ok();
    assert!(!fake.applied.lock().unwrap().last().unwrap().enabled);
    // The rest is kept for the next time it is switched on.
    assert_eq!(
        ctx.state
            .proxy_state
            .config
            .read()
            .proxy
            .upstream
            .proxy
            .host,
        "10.1.2.3"
    );
}

#[tokio::test]
async fn the_test_endpoint_reports_latency_or_the_error_and_needs_config_write() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let fake = Arc::new(Fake::default());
    assert!(ctx.state.runtime.set(fake.clone()).is_ok());
    put(&admin, proxy(json!({"enabled": false})))
        .await
        .assert_status_ok();

    *fake.test_result.lock().unwrap() = Some(Ok(42));
    // Unsaved values are tested. The saved credentials are not sent to another address.
    let r = admin
        .post("/api/v1/config/upstream-proxy/test")
        .json(&json!({"host": "10.7.7.7", "port": 3128, "kind": "http", "password": ""}))
        .await;
    r.assert_status_ok();
    let v: Value = r.json();
    assert_eq!(
        (v["ok"].clone(), v["latency_ms"].clone()),
        (json!(true), json!(42))
    );
    assert_eq!(v["target"], "www.cloudflare.com");
    let t = fake.tested.lock().unwrap().last().unwrap().clone();
    assert_eq!(
        (
            t.host.as_str(),
            t.port,
            t.username.as_str(),
            t.password.as_str()
        ),
        ("10.7.7.7", 3128, "", "")
    );
    // The same address keeps them.
    admin
        .post("/api/v1/config/upstream-proxy/test")
        .json(&json!({"host": "10.1.2.3", "port": 1080, "kind": "socks5", "password": ""}))
        .await
        .assert_status_ok();
    let t = fake.tested.lock().unwrap().last().unwrap().clone();
    assert_eq!(
        (t.username.as_str(), t.password.as_str()),
        ("alice", "hunter2")
    );
    assert!(t.enabled, "the test runs even while the setting is off");
    assert!(
        !ctx.state
            .proxy_state
            .config
            .read()
            .proxy
            .upstream
            .proxy
            .enabled
    );

    *fake.test_result.lock().unwrap() = Some(Err(
        "upstream proxy rejected the username or password (407)".into(),
    ));
    let v: Value = admin
        .post("/api/v1/config/upstream-proxy/test")
        .json(&json!({}))
        .await
        .json();
    assert_eq!(v["ok"], false);
    // The reason stays in the server log; the caller gets one message for every failure.
    let msg = v["error"].as_str().unwrap();
    assert!(!msg.contains("407") && !msg.contains("password"), "{v}");

    // Read-only roles cannot use it.
    let viewer = ctx.user(&admin, "vera", "viewer").await;
    let r = viewer
        .post("/api/v1/config/upstream-proxy/test")
        .json(&json!({}))
        .await;
    assert_eq!(r.status_code(), StatusCode::FORBIDDEN);
    // Nor an invalid configuration.
    let r = admin
        .post("/api/v1/config/upstream-proxy/test")
        .json(&json!({"host": ""}))
        .await;
    assert_eq!(r.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn saved_credentials_are_never_sent_to_another_address() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    put(&admin, proxy(json!({}))).await.assert_status_ok();
    let saved = |ctx: &TestContext| {
        ctx.state
            .proxy_state
            .config
            .read()
            .proxy
            .upstream
            .proxy
            .clone()
    };

    // Host, port or type changed with an empty password: credentials dropped, not reused.
    for change in [
        json!({"host": "198.51.100.9"}),
        json!({"port": 1081}),
        json!({"kind": "http"}),
    ] {
        let mut body = change.clone();
        body["password"] = json!("");
        put(&admin, json!({"upstream_proxy": body}))
            .await
            .assert_status_ok();
        let c = saved(&ctx);
        assert_eq!(
            (c.username.as_str(), c.password.as_str()),
            ("", ""),
            "{change}"
        );
        put(&admin, proxy(json!({}))).await.assert_status_ok();
    }

    // Supplying both again with the change is honoured.
    put(
        &admin,
        json!({"upstream_proxy": {"host": "198.51.100.9", "username": "bob", "password": "pw"}}),
    )
    .await
    .assert_status_ok();
    let c = saved(&ctx);
    assert_eq!((c.username.as_str(), c.password.as_str()), ("bob", "pw"));
}

#[tokio::test]
async fn the_test_endpoint_is_limited_to_one_at_a_time_and_a_few_a_minute() {
    use web_api::auth::authz::{Actor, Principal};
    let gate = web_api::state::UpstreamTestGate::new(3, std::time::Duration::from_secs(60));
    let who = |id: &str| Principal {
        user_id: uuid::Uuid::nil(),
        username: "u".into(),
        role: api_types::UserRole::Admin,
        scopes: Default::default(),
        actor: Actor::Token {
            token_id: id.into(),
        },
        profiles: None,
    };
    let a = who("a");
    // One in flight: a second is refused until the first finishes.
    let held = gate.admit(&a).unwrap();
    assert!(matches!(
        gate.admit(&a),
        Err(web_api::error::ApiError::RateLimitExceeded(_))
    ));
    drop(held);
    // The refused try still counted; the rate limit (3) is per token.
    drop(gate.admit(&a).unwrap());
    assert!(gate.admit(&a).is_err());
    drop(gate.admit(&who("b")).unwrap());
}

#[tokio::test]
async fn the_test_endpoint_answers_429_when_limited() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    assert!(ctx.state.runtime.set(Arc::new(Fake::default())).is_ok());
    put(&admin, proxy(json!({"enabled": false})))
        .await
        .assert_status_ok();
    let mut last = StatusCode::OK;
    for _ in 0..12 {
        last = admin
            .post("/api/v1/config/upstream-proxy/test")
            .json(&json!({}))
            .await
            .status_code();
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
}

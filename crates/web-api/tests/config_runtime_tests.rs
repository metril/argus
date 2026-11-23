//! Config updates that move listeners: live rebind through `RuntimeControl`, rollback on a bind
//! failure, persistence to the settings overlay, and the web API's own listener.

mod common;

use axum::http::StatusCode;
use common::TestContext;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use web_api::{ProxyBind, RuntimeControl};

#[derive(Default)]
struct Fake {
    calls: Mutex<Vec<(String, u16, Option<u16>)>>,
    access: Mutex<Vec<Vec<String>>>,
    fail_with: Mutex<Option<String>>,
}

#[async_trait::async_trait]
impl RuntimeControl for Fake {
    async fn rebind_proxy(
        &self,
        host: &str,
        port: u16,
        t: Option<u16>,
    ) -> Result<ProxyBind, String> {
        self.calls.lock().unwrap().push((host.into(), port, t));
        if let Some(e) = self.fail_with.lock().unwrap().clone() {
            return Err(e);
        }
        Ok(ProxyBind {
            proxy_down: false,
            transparent_down: false,
            proxy: SocketAddr::from(([127, 0, 0, 1], port)),
            transparent: t.map(|p| SocketAddr::from(([127, 0, 0, 1], p))),
        })
    }
    async fn apply_access(&self, c: &::common::config::ProxyConfig) -> Result<(), String> {
        self.access
            .lock()
            .unwrap()
            .push(c.proxy.allowed_clients.clone());
        Ok(())
    }
    fn listener_counters(&self) -> (web_api::ListenerCounters, web_api::ListenerCounters) {
        let c = |a, r, n| web_api::ListenerCounters {
            active_connections: a,
            requests_per_sec: r,
            clients: n,
        };
        (c(3, 1.5, 2), c(7, 0.5, 4))
    }
    async fn proxy_bind(&self) -> Option<ProxyBind> {
        let (_, p, t) =
            self.calls
                .lock()
                .unwrap()
                .last()
                .cloned()
                .unwrap_or(("".into(), 8080, None));
        Some(ProxyBind {
            proxy_down: false,
            transparent_down: false,
            proxy: SocketAddr::from(([127, 0, 0, 1], p)),
            transparent: t.map(|p| SocketAddr::from(([127, 0, 0, 1], p))),
        })
    }
    async fn note_webui(&self, _: &str, _: u16) {}
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

#[tokio::test]
async fn listener_and_access_changes_apply_live_and_persist_to_the_overlay() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let fake = Arc::new(Fake::default());
    assert!(ctx.state.runtime.set(fake.clone()).is_ok());

    let r = put(
        &admin,
        json!({"port": 9191, "transparent_port": 3129, "allowed_clients": ["10.0.0.0/8"],
               "tls_passthrough_hosts": ["bank.test"]}),
    )
    .await;
    r.assert_status_ok();
    let body: Value = r.json();
    assert_eq!(body["restart_required"], json!([]), "{body}");
    let applied = body["applied"].as_array().unwrap();
    for f in [
        "port",
        "transparent_port",
        "allowed_clients",
        "tls_passthrough_hosts",
    ] {
        assert!(applied.contains(&json!(f)), "{f}: {applied:?}");
    }
    assert_eq!(body["bind"]["proxy"], "127.0.0.1:9191");
    assert_eq!(body["bind"]["transparent"], "127.0.0.1:3129");
    assert_eq!(
        fake.calls.lock().unwrap().last().unwrap(),
        &("0.0.0.0".to_string(), 9191, Some(3129))
    );
    assert_eq!(fake.access.lock().unwrap().last().unwrap(), &["10.0.0.0/8"]);

    let overlay = std::fs::read_to_string(ctx.state.overlay_path.read().clone()).unwrap();
    assert!(
        overlay.contains("port = 9191") && overlay.contains("bank.test"),
        "{overlay}"
    );

    // Turning transparent off (0) persists as 0 and reloads as unset.
    put(&admin, json!({"transparent_port": 0}))
        .await
        .assert_status_ok();
    assert_eq!(fake.calls.lock().unwrap().last().unwrap().2, None);
    assert!(ctx
        .state
        .proxy_state
        .config
        .read()
        .proxy
        .transparent_port
        .is_none());

    // Reload re-reads base + overlay.
    admin.post("/api/v1/config/reload").await.assert_status_ok();
    let cfg = ctx.state.proxy_state.config.read().clone();
    assert_eq!(cfg.proxy.port, 9191);
    assert_eq!(cfg.proxy.tls_passthrough_hosts, ["bank.test"]);

    // /stats/proxy shows the transparent state.
    let s: Value = admin.get("/api/v1/stats/proxy").await.json();
    assert_eq!(s["transparent"]["enabled"], false);
    assert_eq!(
        s["transparent"]["tls_passthrough_hosts"],
        json!(["bank.test"])
    );
}

#[tokio::test]
async fn failed_bind_is_a_409_and_changes_nothing() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let fake = Arc::new(Fake::default());
    *fake.fail_with.lock().unwrap() = Some("cannot bind proxy to 0.0.0.0:80: in use".into());
    assert!(ctx.state.runtime.set(fake.clone()).is_ok());

    let r = put(&admin, json!({"port": 80, "request_timeout_secs": 99})).await;
    assert_eq!(r.status_code(), StatusCode::CONFLICT);
    let v: Value = r.json();
    assert_eq!(v["error"]["code"], "bind_failed");
    assert!(
        v["error"]["message"].as_str().unwrap().contains("in use"),
        "{v}"
    );
    let cfg = ctx.state.proxy_state.config.read().clone();
    assert_eq!(cfg.proxy.port, 8080, "old port kept");
    assert_ne!(
        cfg.performance.request_timeout_secs, 99,
        "nothing else applied either"
    );
    assert!(
        !ctx.state.overlay_path.read().exists(),
        "a failed change is not saved"
    );
}

#[tokio::test]
async fn without_a_running_proxy_listener_changes_need_a_restart() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let r = put(&admin, json!({"port": 9090, "webui_port": 3999})).await;
    r.assert_status_ok();
    assert_eq!(
        r.json::<Value>()["restart_required"],
        json!(["port", "webui_port"])
    );
}

#[tokio::test]
async fn web_api_listener_moves_live_and_a_conflict_keeps_the_old_one() {
    let ctx = TestContext::new().await.unwrap();
    let mut cfg = ctx.api_config.clone();
    cfg.server.host = "127.0.0.1".into();
    cfg.server.port = 0;
    let state = ctx.state.clone();
    tokio::spawn(web_api::start_server(state.clone(), cfg));
    let web = loop {
        if let Some(w) = state.web_server.get() {
            break w.clone();
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    };
    let first = web.addr().await;
    let health = |a: SocketAddr| async move {
        reqwest::get(format!("http://{a}/api/v1/health"))
            .await
            .map(|r| r.status().as_u16())
            .ok()
    };
    assert_eq!(health(first).await, Some(200));

    let second = web.rebind("127.0.0.1", 0).await.unwrap();
    assert_ne!(first, second);
    assert_eq!(health(second).await, Some(200));
    assert_eq!(
        health(first).await,
        Some(200),
        "old listener answers during its grace period"
    );
    assert_eq!(web.addr().await, second);

    let held = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = held.local_addr().unwrap().port();
    let err = web.rebind("127.0.0.1", port).await.unwrap_err();
    assert!(err.contains(&port.to_string()), "{err}");
    assert_eq!(web.addr().await, second);
    assert_eq!(health(second).await, Some(200));
}

#[tokio::test]
async fn per_listener_switches_are_separate_live_and_persisted_in_their_own_tables() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    assert!(ctx.state.runtime.set(Arc::new(Fake::default())).is_ok());

    let r = put(
        &admin,
        json!({"enable_adblock": true, "transparent": {"enable_adblock": false, "enable_http2": false}}),
    )
    .await;
    r.assert_status_ok();
    let b: Value = r.json();
    assert_eq!(b["explicit"]["enable_adblock"], true);
    assert_eq!(b["transparent"]["enable_adblock"], false);
    assert_eq!(b["transparent"]["enable_http2"], false);
    assert_eq!(
        b["explicit"]["enable_http2"], true,
        "explicit inherits the global value"
    );
    let applied = b["applied"].as_array().unwrap();
    assert!(
        applied.contains(&json!("transparent.enable_adblock")),
        "{applied:?}"
    );
    assert_eq!(b["restart_required"], json!([]));
    // The engine stays on while any listener wants blocking.
    assert!(ctx.state.shared_engine.is_enabled());

    let overlay = std::fs::read_to_string(ctx.state.overlay_path.read().clone()).unwrap();
    assert!(
        overlay.contains("[proxy.transparent]") && overlay.contains("enable_adblock = false"),
        "{overlay}"
    );
    assert!(!overlay.contains("[proxy.explicit]"), "{overlay}");

    // It survives a reload, and a GET shows the same effective values.
    admin.post("/api/v1/config/reload").await.assert_status_ok();
    let g: Value = admin.get("/api/v1/config").await.json();
    assert_eq!(g["transparent"]["enable_adblock"], false);
    assert_eq!(g["explicit"]["enable_adblock"], true);
}

#[tokio::test]
async fn web_api_host_change_on_the_same_port_works_and_a_failure_restores_the_old_listener() {
    let ctx = TestContext::new().await.unwrap();
    let mut cfg = ctx.api_config.clone();
    cfg.server.host = "127.0.0.1".into();
    cfg.server.port = 0;
    let state = ctx.state.clone();
    tokio::spawn(web_api::start_server(state.clone(), cfg));
    let web = loop {
        if let Some(w) = state.web_server.get() {
            break w.clone();
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    };
    let first = web.addr().await;
    let health = |a: SocketAddr| async move {
        reqwest::get(format!("http://{a}/api/v1/health"))
            .await
            .map(|r| r.status().as_u16())
            .ok()
    };
    assert_eq!(health(first).await, Some(200));

    // Same port, other host (the old socket holds the port, so it is released first).
    let moved = web.rebind("127.0.0.2", first.port()).await.unwrap();
    assert_eq!(moved, SocketAddr::from(([127, 0, 0, 2], first.port())));
    assert_eq!(health(moved).await, Some(200));
    assert_eq!(health(first).await, None, "old address is closed");

    // A host this machine does not own fails; the working listener is put back.
    let err = web.rebind("192.0.2.1", moved.port()).await.unwrap_err();
    assert!(err.contains("192.0.2.1"), "{err}");
    assert_eq!(web.addr().await, moved);
    assert_eq!(health(moved).await, Some(200), "old listener restored");
}

#[tokio::test]
async fn proxy_stats_report_per_listener_counters() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let before: Value = admin.get("/api/v1/stats/proxy").await.json();
    assert_eq!(
        before["explicit"]["active_connections"], 0,
        "no proxy: zeros"
    );
    assert!(ctx.state.runtime.set(Arc::new(Fake::default())).is_ok());
    let s: Value = admin.get("/api/v1/stats/proxy").await.json();
    assert_eq!(
        s["explicit"],
        json!({"active_connections": 3, "requests_per_sec": 1.5, "clients": 2})
    );
    assert_eq!(s["transparent"]["active_connections"], 7);
    assert_eq!(s["transparent"]["requests_per_sec"], 0.5);
    assert_eq!(s["transparent"]["clients"], 4);
}

#[tokio::test]
async fn concurrent_config_updates_with_one_etag_let_exactly_one_win() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let etag = admin
        .get("/api/v1/config")
        .await
        .header("etag")
        .to_str()
        .unwrap()
        .to_string();
    let send = |t: u64| {
        admin
            .put("/api/v1/config")
            .add_header("if-match", etag.clone())
            .json(&json!({"request_timeout_secs": t}))
    };
    let (a, b) = tokio::join!(send(41), send(42));
    let mut codes = [a.status_code().as_u16(), b.status_code().as_u16()];
    codes.sort();
    assert_eq!(codes, [200, 412], "the second writer sees the new ETag");
    // Reload takes the same lock and still works afterwards.
    admin.post("/api/v1/config/reload").await.assert_status_ok();
}

#[tokio::test]
async fn host_and_webui_host_are_both_validated() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let r = put(
        &admin,
        json!({"host": "127.0.0.1", "webui_host": "not a host"}),
    )
    .await;
    assert_eq!(r.status_code(), StatusCode::BAD_REQUEST);
    assert!(r.text().contains("webui_host"), "{}", r.text());
    let r = put(&admin, json!({"host": "nope", "webui_host": "127.0.0.1"})).await;
    assert_eq!(r.status_code(), StatusCode::BAD_REQUEST);
    assert!(r.text().contains("host"), "{}", r.text());
}

async fn running_web(ctx: &TestContext) -> (Arc<web_api::WebServer>, tokio::task::JoinHandle<()>) {
    let mut cfg = ctx.api_config.clone();
    cfg.server.host = "127.0.0.1".into();
    cfg.server.port = 0;
    let state = ctx.state.clone();
    let h = tokio::spawn(async move {
        let _ = web_api::start_server(state, cfg).await;
    });
    loop {
        if let Some(w) = ctx.state.web_server.get() {
            return (w.clone(), h);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

async fn health(a: SocketAddr) -> Option<u16> {
    reqwest::get(format!("http://{a}/api/v1/health"))
        .await
        .map(|r| r.status().as_u16())
        .ok()
}

#[tokio::test]
async fn revert_reinstates_the_old_web_listener_and_closes_the_new_one() {
    let ctx = TestContext::new().await.unwrap();
    let (web, _h) = running_web(&ctx).await;
    let first = web.addr().await;
    let second = web.rebind("127.0.0.1", 0).await.unwrap();
    assert_eq!(health(second).await, Some(200));
    // A failed save: take the old listener back instead of binding it again.
    assert_eq!(web.revert().await, Some(first));
    assert_eq!(web.addr().await, first);
    assert_eq!(health(first).await, Some(200));
    let mut closed = false;
    for _ in 0..100 {
        if health(second).await.is_none() {
            closed = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    }
    assert!(closed, "the new listener is closed after the revert");
    // Nothing left to revert.
    assert_eq!(web.revert().await, None);
}

#[tokio::test]
async fn a_stop_we_asked_for_does_not_end_the_server_task() {
    let ctx = TestContext::new().await.unwrap();
    let (web, h) = running_web(&ctx).await;
    let first = web.addr().await;
    // Same port, other host: the old listener is closed first; its completion is not "done".
    web.rebind("127.0.0.2", first.port()).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    assert!(!h.is_finished(), "start_server must keep waiting");
    assert!(!web.is_down().await);
}

#[tokio::test]
async fn failed_move_and_failed_restore_mark_the_web_listener_down_and_a_retry_recovers() {
    let ctx = TestContext::new().await.unwrap();
    let (web, h) = running_web(&ctx).await;
    let first = web.addr().await;
    web.__fail_restores(true);
    // Same port, unusable host: the old socket is closed first, the new bind fails, and so
    // does putting the old one back.
    let err = web.rebind("192.0.2.1", first.port()).await.unwrap_err();
    assert!(err.contains("restored"), "{err}");
    assert!(web.is_down().await);
    assert_eq!(health(first).await, None, "nothing is listening");
    // The server task keeps waiting (the stop was ours), and a retry of the same address
    // binds again instead of being mistaken for "unchanged".
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(!h.is_finished());
    web.__fail_restores(false);
    let back = web.rebind("127.0.0.1", first.port()).await.unwrap();
    assert!(!web.is_down().await);
    assert_eq!(health(back).await, Some(200));
}

//! Live listener changes: rebinding the explicit and transparent listeners without a restart.
//! Everything binds ephemeral loopback ports, so the tests run in parallel.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use filter_engine::SharedEngine;
use proxy_core::config::ProxyConfig;
use proxy_core::server::ProxyControl;
use proxy_core::{ProxyContext, ProxyServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const HOST: &str = "127.0.0.1";

struct Running {
    lm: Arc<proxy_core::load_manager::LoadManager>,
    ctl: Arc<ProxyControl>,
    addr: SocketAddr,
    shutdown: tokio::sync::broadcast::Sender<()>,
}

async fn start(transparent: bool) -> Running {
    let mut config = ProxyConfig::default();
    config.proxy.host = HOST.into();
    config.mitm.enabled = false;
    config.proxy.enable_websockets = false;
    let ctx = Arc::new(ProxyContext::new(
        Arc::new(SharedEngine::new()),
        reqwest::Client::new(),
        true,
    ));
    let server = ProxyServer::new(config, ctx).unwrap();
    let ctl = server.control();
    let lm = server.load_manager().clone();
    let l = TcpListener::bind((HOST, 0)).await.unwrap();
    let addr = l.local_addr().unwrap();
    let t = if transparent {
        Some(TcpListener::bind((HOST, 0)).await.unwrap())
    } else {
        None
    };
    let (shutdown, _) = tokio::sync::broadcast::channel(1);
    let tx = shutdown.clone();
    tokio::spawn(async move {
        let _ = server.serve_all(l, t, tx).await;
    });
    // `serve_all` registers its listeners asynchronously.
    for _ in 0..200 {
        if ctl.bind_info().await.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Running {
        lm,
        ctl,
        addr,
        shutdown,
    }
}

async fn accepts(addr: SocketAddr) -> bool {
    TcpStream::connect(addr).await.is_ok()
}

/// Wait until nothing accepts on `addr` (the old accept loop has closed its socket).
async fn closes(addr: SocketAddr) -> bool {
    for _ in 0..100 {
        if !accepts(addr).await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

#[tokio::test]
async fn rebind_moves_the_explicit_listener_and_old_connections_drain() {
    let run = start(false).await;
    // An established connection on the old listener, mid-request.
    let mut inflight = TcpStream::connect(run.addr).await.unwrap();
    inflight
        .write_all(b"GET http://127.0.0.1:1/ HTT")
        .await
        .unwrap();

    let bound = run.ctl.rebind(HOST, 0, None).await.unwrap();
    assert_ne!(bound.proxy, run.addr);
    assert!(bound.transparent.is_none());
    assert_eq!(run.ctl.bind_info().await.unwrap(), bound);
    assert!(accepts(bound.proxy).await, "new listener accepts");
    assert!(closes(run.addr).await, "old listener stops accepting");

    // The connection accepted before the move is still being served (no EOF, no reset).
    let mut b = [0u8; 8];
    let r = tokio::time::timeout(Duration::from_millis(300), inflight.read(&mut b)).await;
    assert!(r.is_err(), "in-flight connection was cut: {r:?}");
    let _ = run.shutdown.send(());
}

#[tokio::test]
async fn bind_conflict_keeps_the_old_listener_and_reports_why() {
    let run = start(false).await;
    let before = run.ctl.bind_info().await.unwrap();
    let held = TcpListener::bind((HOST, 0)).await.unwrap();
    let port = held.local_addr().unwrap().port();

    let err = run
        .ctl
        .rebind(HOST, port, None)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains(&port.to_string()), "{err}");
    assert_eq!(
        run.ctl.bind_info().await.unwrap(),
        before,
        "nothing changed"
    );
    assert!(accepts(run.addr).await, "the old listener never went down");

    // A failing transparent bind rolls back the explicit move made in the same call.
    let err = run
        .ctl
        .rebind(HOST, 0, Some(port))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("transparent"), "{err}");
    assert_eq!(run.ctl.bind_info().await.unwrap(), before);
    assert!(accepts(run.addr).await);
    let _ = run.shutdown.send(());
}

#[tokio::test]
async fn same_port_rebind_with_a_failing_transparent_bind_restores_the_listener() {
    let run = start(false).await;
    let held = TcpListener::bind((HOST, 0)).await.unwrap();
    let port = held.local_addr().unwrap().port();
    // The explicit port is kept (the old socket is released and re-bound), the transparent bind fails.
    let err = run
        .ctl
        .rebind(HOST, run.addr.port(), Some(port))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("transparent"), "{err}");
    assert!(
        accepts(run.addr).await,
        "explicit listener restored on its old address"
    );
    assert_eq!(run.ctl.bind_info().await.unwrap().proxy, run.addr);
    let _ = run.shutdown.send(());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn transparent_listener_turns_on_and_off() {
    let run = start(false).await;
    assert!(run.ctl.bind_info().await.unwrap().transparent.is_none());

    let on = run
        .ctl
        .rebind(HOST, run.addr.port(), Some(0))
        .await
        .unwrap();
    let t = on.transparent.expect("transparent listener is on");
    assert!(accepts(t).await);
    assert!(accepts(on.proxy).await, "explicit listener unaffected");
    assert_eq!(run.ctl.bind_info().await.unwrap(), on);

    let off = run.ctl.rebind(HOST, on.proxy.port(), None).await.unwrap();
    assert!(off.transparent.is_none());
    assert!(closes(t).await, "transparent socket released");
    assert!(accepts(off.proxy).await);
    let _ = run.shutdown.send(());
}

#[tokio::test]
async fn access_lists_apply_live() {
    let run = start(false).await;
    // Empty client list: nobody may connect; the connection is closed at accept.
    let mut config = ProxyConfig::default();
    config.proxy.allowed_clients = vec![];
    run.ctl.apply_access(&config).await.unwrap();
    let mut s = TcpStream::connect(run.addr).await.unwrap();
    let _ = s.write_all(b"GET / HTTP/1.1\r\n\r\n").await;
    let mut b = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(2), s.read(&mut b))
        .await
        .expect("closed promptly")
        .unwrap_or(0);
    assert_eq!(n, 0, "a refused client gets no response");

    // An invalid CIDR is an error and changes nothing.
    config.proxy.allowed_clients = vec!["not-a-cidr".into()];
    assert!(run.ctl.apply_access(&config).await.is_err());
    let _ = run.shutdown.send(());
}

#[tokio::test]
async fn mitm_and_websockets_are_set_up_lazily_on_first_enable() {
    let run = start(false).await;
    assert!(!run.ctl.mitm_ready() && !run.ctl.ws_ready());
    let dir = tempfile::tempdir().unwrap();
    let mut config = ProxyConfig::default();
    config.mitm.enabled = false;
    config.proxy.enable_websockets = false;
    config.mitm.ca_cert_path = dir.path().join("ca.crt");
    config.mitm.ca_key_path = dir.path().join("ca.key");
    assert!(run.ctl.apply_access(&config).await.is_ok());
    assert!(
        !run.ctl.mitm_ready(),
        "still off while no listener wants it"
    );

    // A CA that cannot be created is an error and changes nothing.
    let mut bad = config.clone();
    bad.proxy.explicit.enable_mitm = Some(true);
    bad.mitm.ca_cert_path = "/proc/no-such-dir/ca.crt".into();
    bad.mitm.ca_key_path = "/proc/no-such-dir/ca.key".into();
    assert!(run.ctl.apply_access(&bad).await.is_err());
    assert!(!run.ctl.mitm_ready());

    config.proxy.explicit.enable_mitm = Some(true);
    config.proxy.transparent.enable_websockets = Some(true);
    run.ctl.apply_access(&config).await.unwrap();
    assert!(run.ctl.mitm_ready(), "CA created on first enable");
    assert!(run.ctl.ws_ready(), "WebSocket client built on first enable");
    assert!(dir.path().join("ca.crt").exists());
    let _ = run.shutdown.send(());
}

#[tokio::test]
async fn connection_limit_and_timeouts_apply_live() {
    let run = start(false).await;
    let mut config = ProxyConfig::default();
    config.mitm.enabled = false;
    config.proxy.enable_websockets = false;
    config.performance.max_connections = 1;
    config.performance.connection_timeout_secs = 7;
    config.performance.request_timeout_secs = 11;
    run.ctl.apply_access(&config).await.unwrap();
    let t = run.ctl.timeouts();
    assert_eq!(t.handshake, Duration::from_secs(7));
    assert_eq!(t.header_read, Duration::from_secs(11));
    assert_eq!(t.tunnel_idle, Duration::from_secs(55));
    assert_eq!(run.lm.max_connections(), 1);

    // One connection fills the cap; the next is closed at accept.
    let _held = TcpStream::connect(run.addr).await.unwrap();
    for _ in 0..100 {
        if run.lm.stats().active_connections == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mut second = TcpStream::connect(run.addr).await.unwrap();
    let mut b = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(2), second.read(&mut b))
        .await
        .expect("refused promptly")
        .unwrap_or(0);
    assert_eq!(n, 0);
    // Raising the cap admits again, without a restart.
    config.performance.max_connections = 5;
    run.ctl.apply_access(&config).await.unwrap();
    assert_eq!(run.lm.max_connections(), 5);
    let _ = run.shutdown.send(());
}

#[tokio::test]
async fn upstream_client_is_rebuilt_when_its_timeouts_change() {
    let mut config = ProxyConfig::default();
    config.proxy.host = HOST.into();
    config.mitm.enabled = false;
    config.proxy.enable_websockets = false;
    let opts = proxy_core::upstream::UpstreamOptions {
        connect_timeout: Some(Duration::from_secs(30)),
        read_timeout: Some(Duration::from_secs(60)),
        ..Default::default()
    };
    let ctx =
        Arc::new(ProxyContext::with_upstream(Arc::new(SharedEngine::new()), &opts, true).unwrap());
    let before = ctx.client();
    let server = ProxyServer::new(config.clone(), ctx.clone()).unwrap();
    let ctl = server.control();
    let (tx, _) = tokio::sync::broadcast::channel(1);
    let l = TcpListener::bind((HOST, 0)).await.unwrap();
    let tx2 = tx.clone();
    tokio::spawn(async move {
        let _ = server.serve(l, tx2).await;
    });
    for _ in 0..200 {
        if ctl.bind_info().await.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        ctx.upstream_connect_timeout(),
        Some(Duration::from_secs(30))
    );
    config.performance.connection_timeout_secs = 7;
    ctl.apply_access(&config).await.unwrap();
    assert_eq!(ctx.upstream_connect_timeout(), Some(Duration::from_secs(7)));
    // `before` is still a usable client: requests in flight keep the one they started on.
    drop(before);
    let _ = tx.send(());
}

#[cfg(feature = "websockets")]
#[tokio::test]
async fn websocket_idle_timeout_follows_the_request_timeout_live() {
    let run = start(false).await;
    let mut config = ProxyConfig::default();
    config.mitm.enabled = false;
    config.proxy.enable_websockets = true;
    run.ctl.apply_access(&config).await.unwrap();
    assert_eq!(run.ctl.ws_idle_timeout(), Some(Duration::from_secs(300)));
    config.performance.request_timeout_secs = 11;
    run.ctl.apply_access(&config).await.unwrap();
    assert_eq!(run.ctl.ws_idle_timeout(), Some(Duration::from_secs(55)));
    let _ = run.shutdown.send(());
}

#[tokio::test]
async fn dns_settings_rebuild_the_resolver_and_flush_its_cache_live() {
    let mut config = ProxyConfig::default();
    config.proxy.host = HOST.into();
    config.mitm.enabled = false;
    config.proxy.enable_websockets = false;
    let opts = proxy_core::upstream::UpstreamOptions {
        dns: Some(Arc::new(proxy_core::dns::CachedResolver::from_settings(
            &config.dns,
        ))),
        ..Default::default()
    };
    let ctx =
        Arc::new(ProxyContext::with_upstream(Arc::new(SharedEngine::new()), &opts, true).unwrap());
    let dns = ctx.dns().expect("resolver");
    let server = ProxyServer::new(config.clone(), ctx.clone()).unwrap();
    let ctl = server.control();
    dns.resolve("localhost").await.unwrap();
    assert_eq!(dns.cached_names().await, 1);
    // Unchanged settings keep the cache.
    ctl.apply_access(&config).await.unwrap();
    assert_eq!(dns.cached_names().await, 1);
    config.dns.servers = vec!["127.0.0.1:5353".into()];
    ctl.apply_access(&config).await.unwrap();
    assert_eq!(
        dns.cached_names().await,
        0,
        "servers changed: cache flushed"
    );
    // Invalid settings are refused and leave the resolver alone.
    config.dns.min_ttl_secs = 500;
    config.dns.max_ttl_secs = 5;
    assert!(ctl.apply_access(&config).await.is_err());
}

#[tokio::test]
async fn failed_move_and_failed_restore_mark_the_proxy_down_and_a_retry_recovers() {
    let run = start(false).await;
    let held = TcpListener::bind((HOST, 0)).await.unwrap();
    let held_port = held.local_addr().unwrap().port();
    run.ctl.__fail_restores(true);
    // Same explicit port (so the old socket is closed first); the transparent bind fails, and
    // so does putting the explicit listener back.
    let err = run
        .ctl
        .rebind(HOST, run.addr.port(), Some(held_port))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("could not be restored"), "{err}");
    let info = run.ctl.bind_info().await.unwrap();
    assert!(
        info.proxy_down,
        "bind_info must not claim the old listener is up"
    );
    assert!(!accepts(run.addr).await);
    // A retry binds again (a down listener is never "unchanged").
    run.ctl.__fail_restores(false);
    let back = run.ctl.rebind(HOST, run.addr.port(), None).await.unwrap();
    assert!(!back.proxy_down);
    assert!(accepts(back.proxy).await);
    let _ = run.shutdown.send(());
}

#[tokio::test]
async fn apply_access_changes_nothing_when_any_part_fails() {
    let run = start(false).await;
    let mut bad = ProxyConfig::default();
    bad.mitm.enabled = false;
    bad.proxy.enable_websockets = false;
    // Valid but visible change (nobody may connect) plus a part that fails (the CA).
    bad.proxy.allowed_clients = vec![];
    bad.proxy.explicit.enable_mitm = Some(true);
    bad.mitm.ca_cert_path = "/proc/no-such-dir/ca.crt".into();
    bad.mitm.ca_key_path = "/proc/no-such-dir/ca.key".into();
    assert!(run.ctl.apply_access(&bad).await.is_err());
    // The client list is unchanged: this connection is still served, not closed at accept.
    let mut s = TcpStream::connect(run.addr).await.unwrap();
    let _ = s.write_all(b"GET / HTTP/1.1\r\n").await;
    let mut b = [0u8; 8];
    let r = tokio::time::timeout(Duration::from_millis(400), s.read(&mut b)).await;
    assert!(r.is_err(), "connection was closed: {r:?}");
    let _ = run.shutdown.send(());
}

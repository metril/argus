//! Connection-level behaviour: WebSocket, IP-literal CONNECT, cold-host concurrency.

use e2e::{connect_ws, connect_wss, e2e_test, HttpVersion, MockResponse, TestClient};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

async fn echo(ws: &mut e2e::WsStream, text: &str) {
    ws.send(Message::Text(text.into())).await.unwrap();
    match ws.next().await.expect("frame").expect("ok frame") {
        Message::Text(t) => assert_eq!(t.as_str(), text),
        other => panic!("unexpected frame {other:?}"),
    }
}

e2e_test!(ws_echo_plain, rules = [], |env| {
    let mut ws = connect_ws(&env.proxy, "ws.test", env.origin.http_port(), "/ws").await;
    echo(&mut ws, "hello").await;
    echo(&mut ws, "again").await;
    ws.close(None).await.unwrap();
});

e2e_test!(wss_echo_via_mitm, rules = [], |env| {
    let mut ws = connect_wss(&env.proxy, "wss.test", env.origin.https_port(), "/ws").await;
    echo(&mut ws, "secure hello").await;
    echo(&mut ws, "secure again").await;
    ws.close(None).await.unwrap();
});

// CONNECT-specific: in transparent mode an IP-literal client sends no SNI and is tunnelled
// (see `no_sni_tls_passes_through_untouched`).
e2e_test!(connect_to_ip_literal, rules = [], explicit_only, |env| {
    env.origin.route("/ip", MockResponse::ok("ip-ok"));
    let url = env.origin.https_url(e2e::PUBLIC_TEST_IP, "/ip");
    let resp = env.client_with(HttpVersion::Http1).get(&url).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "ip-ok");
});

e2e_test!(concurrent_first_connections_one_cert, rules = [], |env| {
    env.origin.route("/burst", MockResponse::ok("burst"));
    let url = env.origin.https_url("cold-host.test", "/burst");
    let tasks: Vec<_> = (0..24)
        .map(|_| {
            // One client per task so every request opens its own connection (CONNECT / redirect).
            let client = env.client_with(HttpVersion::Http1);
            let url = url.clone();
            tokio::spawn(async move { client.get(&url).await.status() })
        })
        .collect();
    for t in tasks {
        assert_eq!(t.await.unwrap(), 200);
    }
    let mitm = env.proxy.mitm.as_ref().expect("mitm");
    assert_eq!(mitm.generation_count(), 1);
});

e2e_test!(
    ws_blocked_by_filter_never_reaches_origin,
    rules = ["||blocked-ws.test^$websocket"],
    |env| {
        let tcp = tokio::net::TcpStream::connect(env.proxy.entry_addr())
            .await
            .unwrap();
        let url = format!("ws://blocked-ws.test:{}/ws", env.origin.http_port());
        // `proxy.block_response = fail`: the handshake fails like a network error, no response.
        let err = tokio_tungstenite::client_async(url.clone(), tcp)
            .await
            .unwrap_err();
        assert!(
            !matches!(err, tokio_tungstenite::tungstenite::Error::Http(_)),
            "{err:?}"
        );
        // `synthetic`: an explicit 403.
        env.proxy
            .ctx
            .set_block_response(proxy_core::config::BlockResponse::Synthetic);
        let tcp = tokio::net::TcpStream::connect(env.proxy.entry_addr())
            .await
            .unwrap();
        let err = tokio_tungstenite::client_async(url, tcp).await.unwrap_err();
        assert!(matches!(err, tokio_tungstenite::tungstenite::Error::Http(r) if r.status() == 403));
        assert!(env.origin.requests_for("/ws").is_empty());
    }
);

// No SNI (IP-literal client): nothing to mint a certificate for, so the transparent listener
// tunnels to the original destination and the client sees the ORIGIN's certificate.
e2e_test!(
    no_sni_tls_passes_through_untouched,
    rules = ["||127.0.0.1^"],
    transparent_only,
    |env| {
        env.origin.route("/ip", MockResponse::ok("origin-direct"));
        let ca = env.origin.ca_pem().as_bytes();
        let client = TestClient::trusting(&env.proxy, HttpVersion::Http1, &[ca]);
        let resp = client.get(&env.origin.https_url("127.0.0.1", "/ip")).await;
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.text().await.unwrap(), "origin-direct");
        assert_eq!(env.origin.requests_for("/ip").len(), 1);
        // Not filtered either (the rule above would block an intercepted request).
        assert_eq!(env.proxy.mitm.as_ref().unwrap().generation_count(), 0);
    }
);

// WebSocket upgrade through the transparent listener, plain and TLS.
e2e_test!(ws_echo_plain_and_tls_via_either_entry, rules = [], |env| {
    let mut ws = connect_ws(&env.proxy, "ws2.test", env.origin.http_port(), "/ws").await;
    echo(&mut ws, "plain").await;
    let mut wss = connect_wss(&env.proxy, "wss2.test", env.origin.https_port(), "/ws").await;
    echo(&mut wss, "tls").await;
});

// `ws://` upgrades to a `full`-bypass host skip filtering and logging; without the bypass the
// same rule blocks them.
e2e_test!(
    ws_upgrade_to_a_full_bypass_host_is_unfiltered_and_unlogged,
    rules = ["||fullws.test^", "||filteredws.test^"],
    |env| {
        env.proxy
            .ctx
            .bypass()
            .update(|s| {
                s.entries.push(common::bypass::Entry {
                    id: common::bypass::new_id(),
                    pattern: "fullws.test".into(),
                    mode: common::bypass::BypassMode::Full,
                    source: "custom".into(),
                    note: None,
                    updated_at: 0,
                });
                Ok(())
            })
            .unwrap();
        let before = env.proxy.ctx.bypass().bypassed_total();
        let mut ws = connect_ws(&env.proxy, "fullws.test", env.origin.http_port(), "/ws").await;
        echo(&mut ws, "through").await;
        assert!(env.proxy.ctx.bypass().bypassed_total() > before);
        assert!(
            env.proxy
                .engine
                .recent_requests(20)
                .iter()
                .all(|e| !e.url.contains("fullws.test")),
            "no log event for a full-bypass host"
        );
        // A host that is not bypassed is still blocked by the same kind of rule.
        let tcp = tokio::net::TcpStream::connect(env.proxy.entry_addr())
            .await
            .unwrap();
        let url = format!("ws://filteredws.test:{}/ws", env.origin.http_port());
        let err = tokio_tungstenite::client_async(url, tcp).await.unwrap_err();
        assert!(
            !matches!(err, tokio_tungstenite::tungstenite::Error::Http(_)),
            "{err:?}"
        );
    }
);

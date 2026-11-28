//! Traffic accounting through the real proxy: a known number of bytes crosses every path (plain
//! HTTP, MITM over HTTP/1.1 and HTTP/2, opaque tunnels, SOCKS5, the transparent listener,
//! WebSockets, locally answered requests) and the per-device, per-host totals and the handling
//! split match, within the TLS and HTTP framing overhead the client-facing socket also carries.

use api_types::{ExtIdent, ExtOut};
use common::traffic::{DeviceTraffic, HostTraffic, TrafficSnapshot};
use e2e::{
    connect_ws, connect_wss, e2e_test, ClientOpts, EntryMode, HttpVersion, MockResponse,
    TestClient, TestEnv,
};
use futures_util::{SinkExt, StreamExt};
use proxy_core::ext_bridge::{ExtHub, HubCtx};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;

/// Body size pushed through each path.
const N: u64 = 200_000;
/// What TLS handshakes (certificate chain included) and HTTP framing may add on top.
const TLS_OVERHEAD: u64 = 16 * 1024;
const HTTP_OVERHEAD: u64 = 4 * 1024;

const LOCAL: &str = "i:127.0.0.1";

fn snap(env: &TestEnv) -> TrafficSnapshot {
    let t = env.proxy.traffic();
    t.fold();
    t.snapshot()
}

fn device<'a>(s: &'a TrafficSnapshot, key: &str) -> &'a DeviceTraffic {
    s.devices.iter().find(|d| d.key == key).unwrap_or_else(|| {
        panic!(
            "no device {key} in {:?}",
            s.devices.iter().map(|d| &d.key).collect::<Vec<_>>()
        )
    })
}

fn host<'a>(d: &'a DeviceTraffic, name: &str) -> &'a HostTraffic {
    d.hosts.iter().find(|h| h.host == name).unwrap_or_else(|| {
        panic!(
            "no host {name} in {:?}",
            d.hosts.iter().map(|h| &h.host).collect::<Vec<_>>()
        )
    })
}

fn big(env: &TestEnv) {
    env.origin
        .route("/big", MockResponse::ok(vec![b'x'; N as usize]));
}

fn bypass(env: &TestEnv, pattern: &str, mode: common::bypass::BypassMode) {
    env.proxy
        .ctx
        .bypass()
        .update(|s| {
            s.entries.push(common::bypass::Entry {
                id: common::bypass::new_id(),
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

e2e_test!(plain_http_is_counted_as_plain, rules = [], |env| {
    big(&env);
    let r = env
        .client()
        .get(&env.origin.http_url("plain.test", "/big"))
        .await;
    assert_eq!(r.bytes().await.unwrap().len() as u64, N);
    let s = snap(&env);
    let d = device(&s, LOCAL);
    let h = host(d, "plain.test");
    assert!(
        h.row.down >= N && h.row.down < N + HTTP_OVERHEAD,
        "{}",
        h.row.down
    );
    assert!(h.row.up > 30 && h.row.up < HTTP_OVERHEAD, "{}", h.row.up);
    assert_eq!(h.row.handling.plain, h.row.up + h.row.down);
    assert_eq!(h.row.handling.decrypted + h.row.handling.tunnelled, 0);
    assert_eq!(h.row.connections_total, 1);
    assert_eq!((d.row.up, d.row.down), (h.row.up, h.row.down));
    assert_eq!((s.up_total, s.down_total), (d.row.up, d.row.down));
});

e2e_test!(mitm_http1_is_counted_as_decrypted, rules = [], |env| {
    big(&env);
    let r = env
        .client_with(HttpVersion::Http1)
        .get(&env.origin.https_url("secure1.test", "/big"))
        .await;
    assert_eq!(r.bytes().await.unwrap().len() as u64, N);
    let s = snap(&env);
    let h = host(device(&s, LOCAL), "secure1.test");
    assert!(
        h.row.down >= N && h.row.down < N + TLS_OVERHEAD,
        "{}",
        h.row.down
    );
    assert!(h.row.up > 100 && h.row.up < TLS_OVERHEAD, "{}", h.row.up);
    assert_eq!(h.row.handling.decrypted, h.row.up + h.row.down);
    assert_eq!(h.row.handling.plain + h.row.handling.tunnelled, 0);
});

e2e_test!(mitm_http2_is_counted_as_decrypted, rules = [], |env| {
    big(&env);
    let r = env
        .client_with(HttpVersion::Http2)
        .get(&env.origin.https_url("secure2.test", "/big"))
        .await;
    assert_eq!(r.version(), reqwest::Version::HTTP_2);
    assert_eq!(r.bytes().await.unwrap().len() as u64, N);
    let s = snap(&env);
    let h = host(device(&s, LOCAL), "secure2.test");
    assert!(
        h.row.down >= N && h.row.down < N + TLS_OVERHEAD,
        "{}",
        h.row.down
    );
    assert_eq!(h.row.handling.decrypted, h.row.up + h.row.down);
});

async fn tunnelled(env: TestEnv, mode: common::bypass::BypassMode, name: &str) {
    big(&env);
    bypass(&env, name, mode);
    // Trusts only the origin's CA: succeeds only when the proxy did not intercept.
    let c = TestClient::trusting(
        &env.proxy,
        HttpVersion::Http1,
        &[env.origin.ca_pem().as_bytes()],
    );
    let r = c.get(&env.origin.https_url(name, "/big")).await;
    assert_eq!(r.bytes().await.unwrap().len() as u64, N);
    let s = snap(&env);
    let h = host(device(&s, LOCAL), name);
    assert!(
        h.row.down >= N && h.row.down < N + TLS_OVERHEAD,
        "{}",
        h.row.down
    );
    assert_eq!(h.row.handling.tunnelled, h.row.up + h.row.down);
    assert_eq!(h.row.handling.plain + h.row.handling.decrypted, 0);
}

e2e_test!(
    no_decrypt_tunnel_is_counted_as_tunnelled,
    rules = [],
    |env| {
        tunnelled(env, common::bypass::BypassMode::NoDecrypt, "nd.test").await;
    }
);

e2e_test!(
    full_bypass_tunnel_is_counted_as_tunnelled,
    rules = [],
    |env| {
        tunnelled(env, common::bypass::BypassMode::Full, "full.test").await;
    }
);

e2e_test!(plain_websocket_is_counted, rules = [], |env| {
    let mut ws = connect_ws(&env.proxy, "ws.test", env.origin.http_port(), "/ws").await;
    let text = "w".repeat(10_000);
    ws.send(Message::Text(text.clone())).await.unwrap();
    match ws.next().await.expect("frame").expect("ok") {
        Message::Text(t) => assert_eq!(t.as_str(), text),
        other => panic!("{other:?}"),
    }
    ws.close(None).await.unwrap();
    let s = snap(&env);
    let h = host(device(&s, LOCAL), "ws.test");
    // Masked client frame up, echo down, plus the upgrade exchange either way.
    assert!(
        h.row.up >= 10_000 && h.row.up < 10_000 + HTTP_OVERHEAD,
        "{}",
        h.row.up
    );
    assert!(
        h.row.down >= 10_000 && h.row.down < 10_000 + HTTP_OVERHEAD,
        "{}",
        h.row.down
    );
    assert_eq!(h.row.handling.plain, h.row.up + h.row.down);
});

e2e_test!(
    secure_websocket_is_counted_as_decrypted,
    rules = [],
    |env| {
        let mut ws = connect_wss(&env.proxy, "wss.test", env.origin.https_port(), "/ws").await;
        let text = "s".repeat(10_000);
        ws.send(Message::Text(text.clone())).await.unwrap();
        match ws.next().await.expect("frame").expect("ok") {
            Message::Text(t) => assert_eq!(t.as_str(), text),
            other => panic!("{other:?}"),
        }
        ws.close(None).await.unwrap();
        let s = snap(&env);
        let h = host(device(&s, LOCAL), "wss.test");
        assert!(
            h.row.up >= 10_000 && h.row.up < 10_000 + TLS_OVERHEAD,
            "{}",
            h.row.up
        );
        assert!(
            h.row.down >= 10_000 && h.row.down < 10_000 + TLS_OVERHEAD,
            "{}",
            h.row.down
        );
        assert_eq!(h.row.handling.decrypted, h.row.up + h.row.down);
    }
);

e2e_test!(
    locally_answered_requests_are_marked_local,
    rules = ["||blocked.test^"],
    |env| {
        let c = env.client_with(HttpVersion::Http1);
        // A blocked request and an internal route: answered by the proxy, nothing goes upstream.
        let _ = c
            .try_get(&env.origin.https_url("blocked.test", "/ad.js"))
            .await;
        let r = c
            .get(
                &env.origin
                    .https_url("local.test", "/__adblock__/no-such-route"),
            )
            .await;
        let _ = r.bytes().await;
        assert!(
            env.origin.requests().is_empty(),
            "{:?}",
            env.origin.requests()
        );
        let s = snap(&env);
        let d = device(&s, LOCAL);
        assert!(d.row.down > 0, "downstream bytes are still counted");
        assert!(d.row.local_requests >= 1, "{:?}", d.row);
        let total_local: u64 = d.hosts.iter().map(|h| h.row.local_requests).sum();
        assert_eq!(total_local, d.row.local_requests);
        assert!(d
            .hosts
            .iter()
            .any(|h| h.host == "local.test" && h.row.local_requests == 1));
    }
);

e2e_test!(requests_to_the_origin_are_not_local, rules = [], |env| {
    env.origin.route("/p", MockResponse::ok("hi"));
    let r = env
        .client()
        .get(&env.origin.https_url("up.test", "/p"))
        .await;
    assert_eq!(r.text().await.unwrap(), "hi");
    let s = snap(&env);
    assert_eq!(device(&s, LOCAL).row.local_requests, 0);
});

// Devices told apart by source address and by token, each with its own totals and profile.
e2e_test!(devices_are_told_apart, rules = [], explicit_only, |env| {
    big(&env);
    let h = env.proxy.profiles();
    let p = h.profile("kids", "");
    let dev = h.device("tablet", p, &["127.0.0.2"]);
    let tok_dev = h.device("phone", p, &["127.0.0.9"]);
    let token = h.token(tok_dev);
    h.sync().await;
    let _ = dev;

    let by_ip = env.client_as(&ClientOpts::source("127.0.0.2"));
    by_ip
        .get(&env.origin.http_url("ip.test", "/big"))
        .await
        .bytes()
        .await
        .unwrap();
    let by_token = env.client_as(&ClientOpts::token(&token));
    by_token
        .get(&env.origin.http_url("tok.test", "/big"))
        .await
        .bytes()
        .await
        .unwrap();
    let plain = env.client();
    plain
        .get(&env.origin.http_url("anon.test", "/big"))
        .await
        .bytes()
        .await
        .unwrap();

    let s = snap(&env);
    let digest = common::profile_store::token_digest(token.as_bytes());
    let key: String = format!(
        "t:{}",
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let a = device(&s, "i:127.0.0.2");
    let b = device(&s, &key);
    let c = device(&s, LOCAL);
    assert_eq!(a.profile_id, p);
    assert_eq!(b.profile_id, p);
    assert_eq!(c.profile_id, 0);
    for (d, name) in [(a, "ip.test"), (b, "tok.test"), (c, "anon.test")] {
        assert_eq!(d.hosts.len(), 1, "{:?}", d.hosts);
        assert!(host(d, name).row.down >= N);
        assert!(d.row.down >= N && d.row.down < N + HTTP_OVERHEAD);
    }
});

/// One SOCKS5 CONNECT (as the Firefox extension does it) with session secret `sid`, then a plain
/// GET of `path` on `name`; returns the bytes received.
async fn socks_get(env: &TestEnv, sid: &str, name: &str, path: &str) -> usize {
    let addr = env.proxy.ext_addr().await;
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(&[5, 1, 2]).await.unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.unwrap();
    let mut a = vec![1, 3];
    a.extend_from_slice(b"ext");
    a.push(sid.len() as u8);
    a.extend_from_slice(sid.as_bytes());
    s.write_all(&a).await.unwrap();
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(r, [1, 0]);
    let mut q = vec![5, 1, 0, 3, name.len() as u8];
    q.extend_from_slice(name.as_bytes());
    q.extend_from_slice(&env.origin.http_port().to_be_bytes());
    s.write_all(&q).await.unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0);
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut got = Vec::new();
    s.read_to_end(&mut got).await.unwrap();
    got.len()
}

fn ext_hub(env: &TestEnv) -> Arc<ExtHub> {
    let hub: Arc<ExtHub> = env.proxy.ctx.internal().gm.ext().clone();
    hub.set_ctx(HubCtx {
        manager: env.proxy.userscripts(),
        profiles: None,
        bypass: env.proxy.ctx.bypass().clone(),
    });
    hub
}

type Session = (u64, String, tokio::sync::mpsc::Receiver<ExtOut>);

fn open_session(hub: &ExtHub, token: &str) -> Session {
    hub.open(ExtIdent {
        token_id: token.into(),
        user: "u".into(),
        profiles: None,
    })
}

// SOCKS5 on the extension listener: counted to the extension's bridge token, never to its address.
e2e_test!(
    socks5_is_counted_to_the_extension,
    rules = [],
    explicit_only,
    |env| {
        big(&env);
        let hub = ext_hub(&env);
        let (_sess, sid, _rx) = open_session(&hub, "tok1");
        let got = socks_get(&env, &sid, "socks.test", "/big").await;
        assert!(got as u64 > N);

        let snapshot = snap(&env);
        let d = device(&snapshot, "x:tok1");
        let h = host(d, "socks.test");
        assert!(
            h.row.down >= N && h.row.down < N + HTTP_OVERHEAD,
            "{}",
            h.row.down
        );
        // Greeting, credentials, request and the GET all count as received.
        assert!(h.row.up > 60 && h.row.up < HTTP_OVERHEAD, "{}", h.row.up);
        assert_eq!(h.row.handling.plain, h.row.up + h.row.down);
        assert!(
            snapshot.devices.iter().all(|d| d.key != LOCAL),
            "the SOCKS connection is not attributed to its address"
        );
        assert!(
            !format!("{snapshot:?}").contains(&sid),
            "the session secret is never part of the accounting"
        );
    }
);

// The browser reconnects (a new session of the same bridge token): still one device row.
e2e_test!(
    an_extension_reconnect_stays_one_device,
    rules = [],
    explicit_only,
    |env| {
        env.origin.route("/p", MockResponse::ok("hello"));
        let hub = ext_hub(&env);
        let (s1, sid1, rx1) = open_session(&hub, "tok2");
        socks_get(&env, &sid1, "re.test", "/p").await;
        hub.close(s1);
        drop(rx1);
        let (s2, sid2, _rx2) = open_session(&hub, "tok2");
        assert_ne!(s1, s2);
        socks_get(&env, &sid2, "re.test", "/p").await;
        // Another bridge token is another device.
        let (_s3, sid3, _rx3) = open_session(&hub, "tok3");
        socks_get(&env, &sid3, "re.test", "/p").await;
        let s = snap(&env);
        let keys: Vec<&str> = s.devices.iter().map(|d| d.key.as_str()).collect();
        assert_eq!(s.devices.len(), 2, "{keys:?}");
        let d = device(&s, "x:tok2");
        assert_eq!(host(d, "re.test").row.connections_total, 2);
        device(&s, "x:tok3");
    }
);

// The proxy's own totals (the numbers `/stats/proxy` shows) come from the same source.
e2e_test!(totals_follow_the_same_source, rules = [], |env| {
    big(&env);
    env.client()
        .get(&env.origin.http_url("t.test", "/big"))
        .await
        .bytes()
        .await
        .unwrap();
    let t = env.proxy.traffic();
    t.fold();
    let (up, down) = t.totals();
    assert!(down >= N && up > 0);
    let s = t.snapshot();
    assert_eq!((s.up_total, s.down_total), (up, down));
    t.reset();
    assert_eq!(t.totals(), (0, 0));
    assert!(t.snapshot().devices.is_empty());
    let _ = EntryMode::Explicit;
});

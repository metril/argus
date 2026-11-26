//! WebSocket upgrades over the browser-like client: the ClientHello of the emulated browser,
//! the handshake headers untouched and in order, certificate rejection inside the handshake.
//! (The upstream proxy and destination-policy cases live next to the stub proxies, in
//! `upstream_proxy_tests`.)

#![cfg(feature = "websockets")]

mod support;

use std::sync::{Arc, Mutex};

use proxy_core::upstream::UpstreamError;
use rcgen::KeyPair;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use support::{ca, leaf, rig, CHROME_UA};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::LazyConfigAcceptor;

const FIREFOX_UA: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0";
const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

/// What one connection showed the origin.
#[derive(Clone, Debug, Default)]
struct Seen {
    ciphers: Vec<u16>,
    alpn: Vec<Vec<u8>>,
    head: String,
}

impl Seen {
    /// Cipher suites without the random GREASE value.
    fn ciphers(&self) -> Vec<u16> {
        self.ciphers
            .iter()
            .copied()
            .filter(|c| c & 0x0f0f != 0x0a0a)
            .collect()
    }

    fn has_grease(&self) -> bool {
        self.ciphers.iter().any(|c| c & 0x0f0f == 0x0a0a)
    }

    /// Lower-cased header names after the request line, in order, without `host`.
    fn names(&self) -> Vec<String> {
        self.head
            .split("\r\n")
            .skip(1)
            .take_while(|l| !l.is_empty())
            .map(|l| l.split(':').next().unwrap().to_ascii_lowercase())
            .filter(|n| n != "host")
            .collect()
    }
}

/// A TLS origin that records every ClientHello and request head. A request carrying
/// `Sec-WebSocket-Key` is upgraded (the offered subprotocol and extension are accepted) and then
/// echoed; anything else is answered 200.
async fn origin(chain: Vec<Vec<u8>>, key: KeyPair) -> (u16, Arc<Mutex<Vec<Seen>>>) {
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        chain.into_iter().map(CertificateDer::from).collect(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
    .unwrap();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let cfg = Arc::new(cfg);
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = l.accept().await else {
                return;
            };
            let (cfg, log) = (cfg.clone(), log.clone());
            tokio::spawn(async move {
                let Ok(start) = LazyConfigAcceptor::new(Default::default(), tcp).await else {
                    return;
                };
                let hello = start.client_hello();
                let mut s = Seen {
                    ciphers: hello
                        .cipher_suites()
                        .iter()
                        .map(|c| u16::from(*c))
                        .collect(),
                    alpn: hello
                        .alpn()
                        .map(|a| a.map(<[u8]>::to_vec).collect())
                        .unwrap_or_default(),
                    head: String::new(),
                };
                let Ok(mut tls) = start.into_stream(cfg).await else {
                    return;
                };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 2048];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(k) => buf.extend_from_slice(&chunk[..k]),
                    }
                }
                s.head = String::from_utf8_lossy(&buf).into_owned();
                let lower = s.head.to_ascii_lowercase();
                log.lock().unwrap().push(s);
                if !lower.contains("sec-websocket-key") {
                    let _ = tls
                        .write_all(
                            b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                        )
                        .await;
                    let _ = tls.shutdown().await;
                    return;
                }
                let accept =
                    tokio_tungstenite::tungstenite::handshake::derive_accept_key(KEY.as_bytes());
                let mut resp = format!(
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n"
                );
                if lower.contains("sec-websocket-protocol") {
                    resp.push_str("Sec-WebSocket-Protocol: chat\r\n");
                }
                if lower.contains("permessage-deflate") {
                    resp.push_str("Sec-WebSocket-Extensions: permessage-deflate\r\n");
                }
                resp.push_str("\r\n");
                if tls.write_all(resp.as_bytes()).await.is_err() {
                    return;
                }
                // Echo.
                loop {
                    match tls.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(k) => {
                            if tls.write_all(&chunk[..k]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    (port, seen)
}

fn wait_for(seen: &Arc<Mutex<Vec<Seen>>>, n: usize) -> Vec<Seen> {
    let v = seen.lock().unwrap().clone();
    assert!(v.len() >= n, "origin saw {} of {n} connections", v.len());
    v
}

#[tokio::test]
async fn the_websocket_hello_is_the_emulated_browsers() {
    let trusted = ca("trusted");
    let (der, key) = leaf(&trusted, "ws.test");
    let (port, seen) = origin(vec![der], key).await;
    let r = rig(&trusted, |_| {});
    let url = format!("https://ws.test:{port}/chat");

    let mut ws_hellos = Vec::new();
    for ua in [CHROME_UA, FIREFOX_UA] {
        let (resp, up) = r
            .client
            .get(&url)
            .header("user-agent", ua)
            .header("connection", "Upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-key", KEY)
            .header("sec-websocket-version", "13")
            .send_upgrade()
            .await
            .unwrap();
        assert_eq!(resp.status(), 101);
        assert!(up.is_some());
        let v = wait_for(&seen, ws_hellos.len() + 1);
        ws_hellos.push(v.last().unwrap().clone());
    }
    let (chrome, firefox) = (&ws_hellos[0], &ws_hellos[1]);
    // A browser's WebSocket connection is HTTP/1.1 only.
    assert_eq!(chrome.alpn, vec![b"http/1.1".to_vec()]);
    // Chrome's profile: GREASE, TLS 1.3 suites first; Firefox's differs.
    assert!(chrome.has_grease(), "{:x?}", chrome.ciphers);
    assert_eq!(chrome.ciphers()[0], 0x1301);
    assert_ne!(chrome.ciphers(), firefox.ciphers());

    // The same suites, in the same order, as an ordinary request of that browser.
    let ok = r
        .client
        .get(&url)
        .header("user-agent", CHROME_UA)
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
    let all = wait_for(&seen, 3);
    assert_eq!(all[2].ciphers(), chrome.ciphers());
}

#[tokio::test]
async fn handshake_headers_are_forwarded_untouched_and_in_order() {
    let trusted = ca("trusted");
    let (der, key) = leaf(&trusted, "ws.test");
    let (port, seen) = origin(vec![der], key).await;
    let r = rig(&trusted, |_| {});
    let ext = "permessage-deflate; client_max_window_bits";
    let (resp, up) = r
        .client
        .get(format!("https://ws.test:{port}/chat?room=1"))
        .header("user-agent", CHROME_UA)
        .header("pragma", "no-cache")
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("origin", "https://app.ws.test")
        .header("sec-websocket-version", "13")
        .header("accept-language", "en-US,en;q=0.9")
        .header("cookie", "a=1; b=2")
        .header("sec-websocket-key", KEY)
        .header("sec-websocket-extensions", ext)
        .header("sec-websocket-protocol", "chat")
        .send_upgrade()
        .await
        .unwrap();
    assert_eq!(resp.status(), 101);
    // What the origin negotiated reaches the browser as it answered (so deflate stays consistent).
    assert_eq!(
        resp.headers()["sec-websocket-extensions"],
        "permessage-deflate"
    );
    assert_eq!(resp.headers()["sec-websocket-protocol"], "chat");
    let mut up = up.expect("upgraded");
    up.write_all(b"ping").await.unwrap();
    let mut got = [0u8; 4];
    up.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"ping");

    let s = wait_for(&seen, 1).remove(0);
    assert!(
        s.head.starts_with("GET /chat?room=1 HTTP/1.1\r\n"),
        "{}",
        s.head
    );
    assert_eq!(
        s.names(),
        [
            "user-agent",
            "pragma",
            "connection",
            "upgrade",
            "origin",
            "sec-websocket-version",
            "accept-language",
            "cookie",
            "sec-websocket-key",
            "sec-websocket-extensions",
            "sec-websocket-protocol"
        ],
        "{}",
        s.head
    );
    assert!(
        s.head
            .contains(&format!("Sec-WebSocket-Extensions: {ext}\r\n")),
        "{}",
        s.head
    );
    assert!(s.head.contains("Cookie: a=1; b=2\r\n"), "{}", s.head);
    assert!(
        s.head.contains("Origin: https://app.ws.test\r\n"),
        "{}",
        s.head
    );
}

#[tokio::test]
async fn an_untrusted_certificate_fails_the_upgrade_before_any_request() {
    let trusted = ca("trusted");
    let rogue = ca("rogue");
    let (der, key) = leaf(&rogue, "ws.test");
    let (port, seen) = origin(vec![der], key).await;
    let r = rig(&trusted, |_| {});
    let err = r
        .client
        .get(format!("https://ws.test:{port}/chat"))
        .header("user-agent", CHROME_UA)
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-key", KEY)
        .header("sec-websocket-version", "13")
        .send_upgrade()
        .await
        .map(|_| ())
        .unwrap_err();
    assert!(matches!(err, UpstreamError::Wreq(_)), "{err:?}");
    assert_eq!(err.kind(), filter_engine::ErrorKind::UpstreamTls, "{err}");
    // The handshake was aborted: no request bytes ever reached the origin.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(seen.lock().unwrap().iter().all(|s| s.head.is_empty()));
}

#[tokio::test]
async fn a_name_not_matching_the_certificate_fails_too() {
    let trusted = ca("trusted");
    let (der, key) = leaf(&trusted, "other.test");
    let (port, seen) = origin(vec![der], key).await;
    let r = rig(&trusted, |_| {});
    let err = r
        .client
        .get(format!("https://ws.test:{port}/chat"))
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-key", KEY)
        .send_upgrade()
        .await
        .map(|_| ())
        .unwrap_err();
    assert_eq!(err.kind(), filter_engine::ErrorKind::UpstreamTls, "{err}");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(seen.lock().unwrap().iter().all(|s| s.head.is_empty()));
}

#[tokio::test]
async fn the_plain_client_refuses_upgrades() {
    let trusted = ca("trusted");
    let r = support::rig_with(&trusted, false, |_| {});
    let err = r
        .client
        .get("https://ws.test:1/")
        .send_upgrade()
        .await
        .map(|_| ())
        .unwrap_err();
    assert!(matches!(err, UpstreamError::Invalid(_)), "{err:?}");
}

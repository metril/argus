//! WebSocket client helpers that reach the origin through the proxy.

use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::{client_async, WebSocketStream};

use crate::{EntryMode, TestProxy};

/// Object-safe duplex stream so plain and TLS connections share one type.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

pub type WsStream = WebSocketStream<Box<dyn Io>>;

/// `ws://host:port/path` through the proxy's plain-HTTP path (the proxy gets the upgrade request
/// directly, with a Host header; in transparent mode through the transparent listener).
pub async fn connect_ws(proxy: &TestProxy, host: &str, port: u16, path: &str) -> WsStream {
    let tcp = TcpStream::connect(proxy.entry_addr())
        .await
        .expect("connect proxy");
    let io: Box<dyn Io> = Box::new(tcp);
    let (ws, resp) = client_async(format!("ws://{host}:{port}{path}"), io)
        .await
        .expect("ws handshake");
    assert_eq!(resp.status(), 101);
    ws
}

/// A TLS session with the proxy's interception for `host:port` (client trusts only the proxy
/// CA): CONNECT first in explicit mode, straight to the transparent listener otherwise.
pub async fn tls_via_proxy(
    proxy: &TestProxy,
    host: &str,
    port: u16,
    alpn: &[&[u8]],
) -> tokio_rustls::client::TlsStream<TcpStream> {
    crate::init_crypto();
    let mut tcp = TcpStream::connect(proxy.entry_addr())
        .await
        .expect("connect proxy");
    if proxy.mode == EntryMode::Explicit {
        tcp.write_all(
            format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
        // Read the CONNECT reply byte by byte so no TLS bytes are consumed.
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(tcp.read_u8().await.expect("connect reply"));
        }
        assert!(
            head.starts_with(b"HTTP/1.1 200"),
            "{}",
            String::from_utf8_lossy(&head)
        );
    }

    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&proxy.ca_pem) {
        roots.add(cert.expect("pem cert")).unwrap();
    }
    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    let name = ServerName::try_from(host.to_string()).expect("server name");
    TlsConnector::from(Arc::new(cfg))
        .connect(name, tcp)
        .await
        .expect("tls to proxy")
}

/// `wss://host:port/path` through the proxy's TLS interception.
pub async fn connect_wss(proxy: &TestProxy, host: &str, port: u16, path: &str) -> WsStream {
    let tls = tls_via_proxy(proxy, host, port, &[b"http/1.1"]).await;
    let io: Box<dyn Io> = Box::new(tls);
    let (ws, resp) = client_async(format!("wss://{host}:{port}{path}"), io)
        .await
        .expect("wss handshake");
    assert_eq!(resp.status(), 101);
    ws
}

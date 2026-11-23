//! TLS utilities and helpers

use crate::{Error, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ProducesTickets;
use rustls::ServerConfig;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

/// A session-ticket key rotator shared by every host config (enables TLS session resumption).
pub fn new_ticketer() -> Result<Arc<dyn ProducesTickets>> {
    rustls::crypto::ring::Ticketer::new()
        .map_err(|e| Error::Tls(format!("Failed to create session ticketer: {e}")))
}

/// Build the ready-to-use server config for one leaf certificate: ALPN, session cache and
/// (when a shared `ticketer` is given) stateless session tickets for resumption.
pub fn build_server_config(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    enable_http2: bool,
    ticketer: Option<Arc<dyn ProducesTickets>>,
) -> Result<Arc<ServerConfig>> {
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::Tls(format!("Failed to select TLS versions: {e}")))?
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .map_err(|e| Error::Tls(format!("Failed to create TLS server config: {e}")))?;

    config.alpn_protocols = if enable_http2 {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };
    config.session_storage = rustls::server::ServerSessionMemoryCache::new(1024);
    if let Some(t) = ticketer {
        config.ticketer = t;
    }
    Ok(Arc::new(config))
}

/// A stream that counts the bytes written to it: the handshake only writes once the
/// ClientHello has been received (our ServerHello and certificate), so "we wrote something" tells
/// a client that hung up after our hello from one that never said anything.
pub struct Counted<IO> {
    inner: IO,
    written: Arc<std::sync::atomic::AtomicU64>,
}

impl<IO: AsyncRead + Unpin> AsyncRead for Counted<IO> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for Counted<IO> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let r = std::pin::Pin::new(&mut self.inner).poll_write(cx, data);
        if let std::task::Poll::Ready(Ok(n)) = &r {
            self.written
                .fetch_add(*n as u64, std::sync::atomic::Ordering::Relaxed);
        }
        r
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Whether a failed server-side handshake means the client did not accept our certificate: it
/// sent a bad_certificate / unknown_ca / certificate_unknown / decrypt_error alert, or it hung up
/// after we had answered its ClientHello (`answered_hello`; how certificate-pinned apps refuse).
/// A bare EOF, reset or broken pipe before any ClientHello is just a failed connection.
pub fn client_rejected_cert(e: &std::io::Error, answered_hello: bool) -> bool {
    use rustls::AlertDescription::{BadCertificate, CertificateUnknown, DecryptError, UnknownCA};
    if let Some(rustls::Error::AlertReceived(a)) =
        e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>())
    {
        return matches!(
            a,
            BadCertificate | UnknownCA | CertificateUnknown | DecryptError
        );
    }
    answered_hello
        && matches!(
            e.kind(),
            std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::ConnectionAborted
        )
}

/// Accept a TLS connection, bounded by `timeout`.
pub async fn accept_tls<IO>(
    acceptor: &TlsAcceptor,
    stream: IO,
    timeout: Duration,
) -> Result<TlsStream<Counted<IO>>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let written = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let stream = Counted {
        inner: stream,
        written: written.clone(),
    };
    match tokio::time::timeout(timeout, acceptor.accept(stream)).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e))
            if client_rejected_cert(&e, written.load(std::sync::atomic::Ordering::Relaxed) > 0) =>
        {
            Err(Error::ClientRejectedCert(format!(
                "TLS handshake failed: {e}"
            )))
        }
        Ok(Err(e)) => Err(Error::Tls(format!("TLS handshake failed: {}", e))),
        Err(_) => Err(Error::Timeout),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn acceptor() -> TlsAcceptor {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["pinned.test".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let cfg = build_server_config(
            cert.der().clone(),
            PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
            false,
            None,
        )
        .unwrap();
        TlsAcceptor::from(cfg)
    }

    #[test]
    fn only_certificate_alerts_count_without_a_hello_answer() {
        use rustls::AlertDescription as A;
        let alert = |a| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                rustls::Error::AlertReceived(a),
            )
        };
        for a in [
            A::BadCertificate,
            A::UnknownCA,
            A::CertificateUnknown,
            A::DecryptError,
        ] {
            assert!(client_rejected_cert(&alert(a), false), "{a:?}");
            assert!(client_rejected_cert(&alert(a), true), "{a:?}");
        }
        assert!(!client_rejected_cert(&alert(A::ProtocolVersion), true));
        assert!(!client_rejected_cert(&alert(A::HandshakeFailure), true));
        for k in [
            std::io::ErrorKind::UnexpectedEof,
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::BrokenPipe,
        ] {
            let e = std::io::Error::new(k, "x");
            assert!(client_rejected_cert(&e, true), "{k:?} after our hello");
            assert!(
                !client_rejected_cert(&e, false),
                "{k:?} before any hello is just `other`"
            );
        }
        assert!(!client_rejected_cert(
            &std::io::Error::other("garbage"),
            true
        ));
    }

    #[tokio::test]
    async fn a_bare_close_before_any_client_hello_is_not_a_rejection() {
        let (client, server) = tokio::io::duplex(4096);
        drop(client);
        let e = accept_tls(&acceptor(), server, Duration::from_secs(2))
            .await
            .err()
            .expect("handshake fails");
        assert!(matches!(e, Error::Tls(_)), "{e:?}");
    }

    #[tokio::test]
    async fn a_client_that_hangs_up_after_our_certificate_is_a_rejection() {
        use rustls::pki_types::ServerName;
        let (mut client, server) = tokio::io::duplex(1 << 16);
        let acc = acceptor();
        let srv =
            tokio::spawn(async move { accept_tls(&acc, server, Duration::from_secs(5)).await });
        // A pinned app: sends its ClientHello, reads our flight, then just closes.
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let mut conn = rustls::ClientConnection::new(
            Arc::new(cfg),
            ServerName::try_from("pinned.test").unwrap(),
        )
        .unwrap();
        let mut hello = Vec::new();
        conn.write_tls(&mut hello).unwrap();
        client.write_all(&hello).await.unwrap();
        let mut flight = [0u8; 64];
        let n = client.read(&mut flight).await.unwrap();
        assert!(n > 0, "we answered the hello");
        drop(client);
        let e = srv.await.unwrap().err().expect("handshake fails");
        assert!(matches!(e, Error::ClientRejectedCert(_)), "{e:?}");
    }

    #[tokio::test]
    async fn an_unknown_ca_alert_is_a_rejection() {
        let (client, server) = tokio::io::duplex(1 << 16);
        let acc = acceptor();
        let srv =
            tokio::spawn(async move { accept_tls(&acc, server, Duration::from_secs(5)).await });
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        let r = tokio_rustls::TlsConnector::from(Arc::new(cfg))
            .connect(
                rustls::pki_types::ServerName::try_from("pinned.test").unwrap(),
                client,
            )
            .await;
        assert!(r.is_err(), "the client refuses our certificate");
        let e = srv.await.unwrap().err().expect("handshake fails");
        assert!(matches!(e, Error::ClientRejectedCert(_)), "{e:?}");
    }
}

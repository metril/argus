use std::time::Duration;

use crate::{EntryMode, TestProxy};

/// HTTP version policy for the client (applies to the client-to-proxy TLS session).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    /// Negotiate via ALPN.
    Auto,
    /// Force HTTP/1.1.
    Http1,
    /// Force HTTP/2 (HTTPS only).
    Http2,
}

/// reqwest/rustls client that trusts only the proxy CA and talks through the proxy.
pub struct TestClient {
    inner: reqwest::Client,
}

impl TestClient {
    pub fn new(proxy: &TestProxy, version: HttpVersion) -> Self {
        crate::init_crypto();
        let ca = reqwest::Certificate::from_pem(&proxy.ca_pem).expect("proxy CA pem");
        let mut b = reqwest::Client::builder()
            .use_rustls_tls()
            .tls_built_in_root_certs(false)
            .add_root_certificate(ca)
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none());
        match proxy.mode {
            // CONNECT for https://, absolute-form for http://.
            EntryMode::Explicit => {
                b = b.proxy(reqwest::Proxy::all(proxy.url()).expect("proxy url"));
            }
            // Transparent: no proxy configured; the client dials the transparent listener.
            EntryMode::Transparent => {}
        }
        b = match version {
            HttpVersion::Auto => b,
            HttpVersion::Http1 => b.http1_only(),
            HttpVersion::Http2 => b.http2_prior_knowledge(),
        };
        Self {
            inner: b.build().expect("client"),
        }
    }

    /// The underlying client, for requests beyond GET.
    pub fn reqwest(&self) -> &reqwest::Client {
        &self.inner
    }

    pub async fn get(&self, url: &str) -> reqwest::Response {
        self.inner
            .get(url)
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET {url} failed: {e:?}"))
    }
}

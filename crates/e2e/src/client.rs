use std::time::Duration;

use std::net::{IpAddr, SocketAddr};

use crate::{EntryMode, TestProxy};

/// Sends every hostname to the transparent listener (the port comes from the rewritten URL).
struct ToListener(IpAddr);

impl reqwest::dns::Resolve for ToListener {
    fn resolve(&self, _name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let addr = SocketAddr::new(self.0, 0);
        Box::pin(async move { Ok(Box::new(std::iter::once(addr)) as reqwest::dns::Addrs) })
    }
}

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
///
/// In [`EntryMode::Transparent`] there is no proxy configured: names resolve to the transparent
/// listener and request URLs have their port rewritten to it (SNI and `Host` keep the hostname),
/// so callers always pass the origin-facing URL.
/// Who the client presents itself as: a device token (explicit mode: the proxy password) and/or
/// a chosen local source address (`127.0.0.N`), which the proxy sees as the device address.
#[derive(Debug, Clone, Default)]
pub struct ClientOpts {
    pub token: Option<String>,
    pub source: Option<IpAddr>,
}

impl ClientOpts {
    pub fn token(t: &str) -> Self {
        Self {
            token: Some(t.into()),
            source: None,
        }
    }
    pub fn source(ip: &str) -> Self {
        Self {
            token: None,
            source: Some(ip.parse().expect("ip")),
        }
    }
}

pub struct TestClient {
    inner: reqwest::Client,
    transparent_port: Option<u16>,
}

impl TestClient {
    pub fn new(proxy: &TestProxy, version: HttpVersion) -> Self {
        Self::trusting(proxy, version, &[&proxy.ca_pem])
    }

    /// Client behind the extension-only listener at `ext`, authenticating as
    /// `ext:<sid>[:<store>]` (what the extension's `onAuthRequired` answers).
    pub fn via_ext(proxy: &TestProxy, ext: std::net::SocketAddr, sid: &str, store: &str) -> Self {
        crate::init_crypto();
        let user = if store.is_empty() {
            sid.to_string()
        } else {
            format!("{sid}:{store}")
        };
        let p = reqwest::Proxy::all(format!("http://{ext}"))
            .expect("proxy url")
            .basic_auth("ext", &user);
        Self {
            inner: reqwest::Client::builder()
                .use_rustls_tls()
                .tls_built_in_root_certs(false)
                .timeout(Duration::from_secs(30))
                .redirect(reqwest::redirect::Policy::none())
                .add_root_certificate(
                    reqwest::Certificate::from_pem(&proxy.ca_pem).expect("CA pem"),
                )
                .proxy(p)
                .build()
                .expect("client"),
            transparent_port: None,
        }
    }

    /// Client trusting exactly the given PEM CAs (e.g. the origin CA, to prove a connection
    /// reached the origin without interception).
    pub fn trusting(proxy: &TestProxy, version: HttpVersion, cas: &[&[u8]]) -> Self {
        Self::build(proxy, version, cas, &ClientOpts::default())
    }

    /// Client with a device identity (see [`ClientOpts`]).
    pub fn with_opts(proxy: &TestProxy, version: HttpVersion, opts: &ClientOpts) -> Self {
        Self::build(proxy, version, &[&proxy.ca_pem], opts)
    }

    fn build(proxy: &TestProxy, version: HttpVersion, cas: &[&[u8]], opts: &ClientOpts) -> Self {
        crate::init_crypto();
        let mut b = reqwest::Client::builder()
            .use_rustls_tls()
            .tls_built_in_root_certs(false)
            .timeout(Duration::from_secs(120))
            .redirect(reqwest::redirect::Policy::none())
            .local_address(opts.source);
        for ca in cas {
            b = b.add_root_certificate(reqwest::Certificate::from_pem(ca).expect("CA pem"));
        }
        let mut transparent_port = None;
        match proxy.mode {
            // CONNECT for https://, absolute-form for http://.
            EntryMode::Explicit => {
                let mut p = reqwest::Proxy::all(proxy.url()).expect("proxy url");
                if let Some(t) = &opts.token {
                    p = p.basic_auth("device", t);
                }
                b = b.proxy(p);
            }
            // Transparent: no proxy configured; the client dials the transparent listener.
            EntryMode::Transparent => {
                let addr = proxy.transparent_addr.expect("transparent listener");
                b = b.dns_resolver(std::sync::Arc::new(ToListener(addr.ip())));
                transparent_port = Some(addr.port());
            }
        }
        b = match version {
            HttpVersion::Auto => b,
            HttpVersion::Http1 => b.http1_only(),
            HttpVersion::Http2 => b.http2_prior_knowledge(),
        };
        Self {
            inner: b.build().expect("client"),
            transparent_port,
        }
    }

    fn load_builder(ca: &[u8], version: HttpVersion) -> reqwest::ClientBuilder {
        crate::init_crypto();
        let b = reqwest::Client::builder()
            .use_rustls_tls()
            .tls_built_in_root_certs(false)
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(4096)
            .add_root_certificate(reqwest::Certificate::from_pem(ca).expect("CA pem"));
        match version {
            HttpVersion::Auto => b,
            HttpVersion::Http1 => b.http1_only(),
            HttpVersion::Http2 => b.http2_prior_knowledge(),
        }
    }

    /// Client for load tests that dials `origin` directly (every hostname resolves to it; no
    /// proxy), trusting only the origin CA.
    pub fn direct(origin: &crate::TestOrigin, version: HttpVersion) -> Self {
        let b = Self::load_builder(origin.ca_pem().as_bytes(), version)
            .dns_resolver(std::sync::Arc::new(ToListener(origin.ip())));
        Self {
            inner: b.build().expect("client"),
            transparent_port: None,
        }
    }

    /// Client for load tests behind the explicit proxy at `proxy_url` (any process), trusting
    /// only `ca_pem`, the proxy's CA.
    pub fn explicit(proxy_url: &str, ca_pem: &[u8], version: HttpVersion) -> Self {
        let b = Self::load_builder(ca_pem, version)
            .proxy(reqwest::Proxy::all(proxy_url).expect("proxy url"));
        Self {
            inner: b.build().expect("client"),
            transparent_port: None,
        }
    }

    /// `url` as this client must request it (port rewritten in transparent mode).
    fn map(&self, url: &str) -> reqwest::Url {
        let mut u = reqwest::Url::parse(url).expect("url");
        if let Some(p) = self.transparent_port {
            u.set_port(Some(p)).expect("set port");
        }
        u
    }

    /// Request builder for any method.
    pub fn request(&self, method: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
        self.inner.request(method, self.map(url))
    }

    pub async fn get(&self, url: &str) -> reqwest::Response {
        self.request(reqwest::Method::GET, url)
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET {url} failed: {e:?}"))
    }

    /// GET that returns the transport error instead of panicking (a blocked request that fails
    /// by design under `proxy.block_response = fail`).
    pub async fn try_get(&self, url: &str) -> Result<reqwest::Response, reqwest::Error> {
        self.request(reqwest::Method::GET, url).send().await
    }
}

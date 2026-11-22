//! End-to-end test harness: a real proxy, a real TLS origin and a real client, all in-process.
//!
//! * [`TestOrigin`]: HTTPS (h1 + h2) + plain HTTP + WebSocket echo origin that answers for any
//!   hostname and records every request it receives.
//! * [`TestProxy`]: the production `ProxyServer` on an ephemeral port with a fresh CA and data dir.
//! * [`TestClient`]: reqwest client that trusts only the proxy CA and goes through the proxy.
//! * [`e2e_test!`]: declares a test body once and instantiates it per [`EntryMode`].
//!
//! Every instance owns its listeners (bound to port 0 and never dropped), temp dir and CA, so
//! tests are safe under `cargo nextest` / xdist-style parallelism.
//!
//! Test URLs look like `https://example.test:<origin-port>/path`: the proxy resolves every
//! hostname to the origin's IP and the port comes from the URL, so use [`TestOrigin::https_url`]
//! / [`TestOrigin::http_url`] to build them.

mod client;
mod origin;
mod proxy;
mod ws;

pub use client::{HttpVersion, TestClient};
pub use origin::{MockResponse, RecordedRequest, TestOrigin};
pub use proxy::TestProxy;
pub use ws::{connect_ws, connect_wss, WsStream};

use std::sync::Once;

/// How traffic reaches the proxy.
///
/// Design note for `Transparent` (next phase): the client connects straight to the proxy's
/// transparent listener (no CONNECT, no proxy configuration) and the proxy learns the original
/// destination from an injectable resolver instead of `SO_ORIGINAL_DST`. Until that listener
/// exists, [`TestProxy::start`] returns an error for it and [`e2e_test!`] only instantiates
/// `Explicit`; add `Transparent` to the macro's mode list once it is supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryMode {
    /// Client is configured with an explicit HTTP proxy (CONNECT for HTTPS).
    Explicit,
    /// Client connects directly to the transparent listener.
    Transparent,
}

pub(crate) fn init_crypto() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// A fully wired origin + proxy + client for one test.
pub struct TestEnv {
    pub origin: TestOrigin,
    pub proxy: TestProxy,
    pub mode: EntryMode,
}

impl TestEnv {
    /// Start an origin and a proxy (with `rules` compiled as filter-list lines) for `mode`.
    pub async fn start(mode: EntryMode, rules: &[&str]) -> Self {
        let origin = TestOrigin::start().await;
        let proxy = TestProxy::start(mode, &origin, rules)
            .await
            .expect("start proxy");
        Self {
            origin,
            proxy,
            mode,
        }
    }

    /// Client negotiating the HTTP version automatically.
    pub fn client(&self) -> TestClient {
        self.client_with(HttpVersion::Auto)
    }

    pub fn client_with(&self, version: HttpVersion) -> TestClient {
        TestClient::new(&self.proxy, version)
    }
}

/// Declare an e2e test once; it is instantiated for every supported [`EntryMode`] as
/// `<name>::explicit` (and later `<name>::transparent`).
///
/// ```ignore
/// e2e_test!(allowed_passes, rules = ["||blocked.test^"], |env| {
///     let resp = env.client().get(&env.origin.https_url("a.test", "/")).await;
/// });
/// ```
#[macro_export]
macro_rules! e2e_test {
    ($name:ident, rules = $rules:expr, |$env:ident| $body:block) => {
        mod $name {
            #[allow(unused_imports)]
            use super::*;

            async fn body($env: $crate::TestEnv) $body

            #[tokio::test]
            async fn explicit() {
                body($crate::TestEnv::start($crate::EntryMode::Explicit, &$rules).await).await
            }
        }
    };
}

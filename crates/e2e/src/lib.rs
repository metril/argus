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

mod api;
mod client;
mod codec;
pub mod loadgen;
mod origin;
mod proxy;
mod relay;
mod ws;

pub use api::TestApi;
pub use client::{ClientOpts, HttpVersion, TestClient};
pub use codec::{decode, encode, encode_stacked, Coding};
pub use origin::{MockResponse, RecordedRequest, StreamSpec, TestOrigin};
pub use proxy::{install_rules_text, ProfileHandles, ScriptHandles, TestDst, TestProxy};
pub use relay::SourceRelay;
pub use ws::{connect_ws, connect_ws_via_ext, connect_wss, tls_via_proxy, WsStream};

use std::sync::Once;

/// An IP literal the destination policy accepts (TEST-NET-3), usable as a CONNECT / URL host: the
/// origin's no-SNI certificate covers it and the proxy's resolve override sends it to the origin.
pub const PUBLIC_TEST_IP: &str = "203.0.113.9";

/// How traffic reaches the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryMode {
    /// Client is configured with an explicit HTTP proxy (CONNECT for HTTPS).
    Explicit,
    /// Client connects directly to the transparent listener (no proxy configured, no CONNECT);
    /// the proxy learns the origin's address from the injected [`TestDst`] instead of
    /// `SO_ORIGINAL_DST`, and the hostname from SNI / the `Host` header.
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
        Self::start_with(mode, rules, &[]).await
    }

    /// Like [`Self::start`] with `proxy.tls_passthrough_hosts` set.
    pub async fn start_with(mode: EntryMode, rules: &[&str], passthrough: &[&str]) -> Self {
        let origin = TestOrigin::start().await;
        let proxy = TestProxy::start_with(mode, &origin, rules, passthrough)
            .await
            .expect("start proxy");
        Self {
            origin,
            proxy,
            mode,
        }
    }

    /// Like [`Self::start`] with the proxy configuration edited by `tweak`.
    pub async fn start_tweaked(
        mode: EntryMode,
        rules: &[&str],
        tweak: &dyn Fn(&mut proxy_core::config::ProxyConfig),
    ) -> Self {
        let origin = TestOrigin::start().await;
        let proxy = TestProxy::start_tweaked(mode, &origin, rules, tweak)
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

    /// Client presenting a device identity (token and/or source address).
    pub fn client_as(&self, opts: &ClientOpts) -> TestClient {
        TestClient::with_opts(&self.proxy, HttpVersion::Auto, opts)
    }

    pub fn client_as_with(&self, version: HttpVersion, opts: &ClientOpts) -> TestClient {
        TestClient::with_opts(&self.proxy, version, opts)
    }
}

/// Declare an e2e test once; it is instantiated per [`EntryMode`] as `<name>::explicit` and
/// `<name>::transparent`.
///
/// Forms: `e2e_test!(name, rules = [..], |env| {..})` (both modes), optionally
/// `passthrough = [..]` after `rules` (sets `proxy.tls_passthrough_hosts`), or `explicit_only` /
/// `transparent_only` in the same position for scenarios tied to one entry mode.
///
/// ```ignore
/// e2e_test!(allowed_passes, rules = ["||blocked.test^"], |env| {
///     let resp = env.client().get(&env.origin.https_url("a.test", "/")).await;
/// });
/// ```
#[macro_export]
macro_rules! e2e_test {
    ($name:ident, rules = $rules:expr, |$env:ident| $body:block) => {
        $crate::e2e_test!(@gen $name, $rules, [],
            [(explicit, Explicit), (transparent, Transparent)], |$env| $body);
    };
    ($name:ident, rules = $rules:expr, passthrough = $pt:expr, |$env:ident| $body:block) => {
        $crate::e2e_test!(@gen $name, $rules, $pt,
            [(explicit, Explicit), (transparent, Transparent)], |$env| $body);
    };
    ($name:ident, rules = $rules:expr, explicit_only, |$env:ident| $body:block) => {
        $crate::e2e_test!(@gen $name, $rules, [], [(explicit, Explicit)], |$env| $body);
    };
    ($name:ident, rules = $rules:expr, transparent_only, |$env:ident| $body:block) => {
        $crate::e2e_test!(@gen $name, $rules, [], [(transparent, Transparent)], |$env| $body);
    };
    (@gen $name:ident, $rules:expr, $pt:expr, [$(($fn:ident, $variant:ident)),+], |$env:ident| $body:block) => {
        mod $name {
            #[allow(unused_imports)]
            use super::*;

            async fn body($env: $crate::TestEnv) $body

            $(
                #[tokio::test]
                async fn $fn() {
                    body($crate::TestEnv::start_with(
                        $crate::EntryMode::$variant,
                        &$rules,
                        &$pt,
                    ).await).await
                }
            )+
        }
    };
}

# Vendored crates

Third-party crates copied into the tree so Argus can carry small patches. They are wired in
through `[patch.crates-io]` in the workspace `Cargo.toml` and excluded from the workspace
(`exclude = [...]`), so they are not linted or formatted by our CI. Everything else they depend on
(btls, the http2 fork, tokio-btls, ...) stays a normal crates.io dependency.

Both are Apache-2.0 (see each `LICENSE`; upstream ships no `NOTICE` file). Each modified file
starts with a `// Modified by Argus: <why>` header, as Apache-2.0 section 4 requires.

| Crate | Upstream | Version | Local patches |
|---|---|---|---|
| `wreq` | <https://github.com/0x676e67/wreq> | 6.0.0-rc.31 | 1, 2 |
| `wreq-util` | <https://github.com/0x676e67/wreq-util> | 3.0.0-rc.14 | none (vendored so the pair is updated together) |

Only `src/`, `Cargo.toml`, `LICENSE` and `README.md` are kept; tests, examples and lockfiles
were dropped.

## Local patches

1. **In-handshake certificate verify hook.** `wreq::tls::CustomVerify`
   (`Arc<dyn Fn(&mut SslRef) -> Result<(), SslAlert> + Send + Sync>`),
   `ClientBuilder::tls_custom_verify(CustomVerify)` and
   `TlsConnectorBuilder::custom_verify(Option<CustomVerify>)`. Installed with BoringSSL
   `set_custom_verify_callback(SslVerifyMode::PEER, ..)`, so it runs inside the handshake and a
   failure aborts it before any request bytes are sent. It replaces the built-in chain and hostname
   verification; the hook reads the chain from `SslRef::peer_cert_chain()` and the SNI from
   `SslRef::servername()`. Files: `src/tls.rs`, `src/tls/conn.rs`, `src/client.rs`.
2. **Proxy CONNECT to a locally resolved IP.** `Proxy::resolve_locally(bool)`. For HTTP proxies the
   target host is resolved through the client's `dns_resolver` and the CONNECT line carries the
   first resolved `ip:port`; SNI, certificate verification and the `Host` header keep the
   hostname. Plain `http` targets are tunnelled through CONNECT as well (never absolute-form). No
   effect on SOCKS or Unix-socket proxies. Files: `src/proxy.rs`, `src/proxy/matcher.rs`,
   `src/conn/connector.rs` (the connector's resolver field is no longer gated on the `socks`
   feature).

## Updating

Re-copy `src/` from the new upstream release, then re-apply the patches (grep for
`Modified by Argus`), update the versions above and the pins in `crates/proxy-core/Cargo.toml`.

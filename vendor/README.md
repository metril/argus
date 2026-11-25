# Vendored crates

Third-party crates copied into the tree so Argus can carry small patches. They are wired in
through `[patch.crates-io]` in the workspace `Cargo.toml` and excluded from the workspace
(`exclude = [...]`), so they are not linted or formatted by our CI. Everything else they depend on
(btls, the http2 fork, tokio-btls, ...) stays a normal crates.io dependency.

Both are Apache-2.0 (see each `LICENSE`; upstream ships no `NOTICE` file). Each modified file
starts with a `// Modified by Argus: <why>` header, as Apache-2.0 section 4 requires.

| Crate | Upstream | Version | Local patches |
|---|---|---|---|
| `wreq` | <https://github.com/0x676e67/wreq> | 6.0.0-rc.31 | 1, 2, 3, 4 |
| `wreq-util` | <https://github.com/0x676e67/wreq-util> | 3.0.0-rc.14 | none (vendored so the pair is updated together) |

Only `src/`, `Cargo.toml`, `LICENSE` and `README.md` are kept; tests, examples and lockfiles
were dropped.

## Local patches

1. **In-handshake certificate verify hook.** `wreq::tls::CustomVerify`
   (`Arc<dyn Fn(&mut SslRef, &str) -> Result<(), SslAlert> + Send + Sync>`),
   `ClientBuilder::tls_custom_verify(CustomVerify)` and
   `TlsConnectorBuilder::custom_verify(Option<CustomVerify>)`. Installed with BoringSSL
   `set_custom_verify_callback(SslVerifyMode::PEER, ..)`, so it runs inside the handshake and a
   failure aborts it before any request bytes are sent. It replaces the built-in chain and hostname
   verification, so it must check the identity: it gets the peer chain from
   `SslRef::peer_cert_chain()` and the normalized expected host (name or IP literal, no IPv6
   brackets; stored in `Ssl` ex_data by `setup_ssl`/`setup_ssl2`) as the `&str`, which is set even
   when there is no SNI (IP literals, `tls_sni(false)`). A panic in the hook is caught and becomes
   an `INTERNAL_ERROR` alert. `SSL_CTX_set_reverify_on_resume(1)` (raw `btls_sys` call, btls has no
   wrapper) makes the hook run on resumed sessions too. Files: `src/tls.rs`, `src/tls/conn.rs`,
   `src/client.rs`.
2. **Proxy CONNECT to a locally resolved IP.** `Proxy::resolve_locally(bool)`. For HTTP proxies the
   target host is resolved through the client's `dns_resolver` and the CONNECT line carries the
   first resolved `ip:port`; SNI, certificate verification and the `Host` header keep the
   hostname. Plain `http` targets are tunnelled through CONNECT as well (never absolute-form). No
   effect on SOCKS or Unix-socket proxies. Files: `src/proxy.rs`, `src/proxy/matcher.rs`,
   `src/conn/connector.rs` (the connector's resolver field is no longer gated on the `socks`
   feature).

3. **Per-scope TLS session cache key.** `Group::session(scope)` tags a request group with a
   session scope. The session cache key (`ConnectionDescriptor::session_id`) is the pool key with
   the request group replaced by that scope, so connections of different request groups but one
   scope resume each other's TLS sessions and never another scope's. Without a scope the key is the
   pool key as before. Files: `src/group.rs`, `src/conn/descriptor.rs`, `src/tls/conn.rs`.
4. **Evict a request group's pooled connections.** `Client::evict_group(&Group)` drops the idle
   pooled connections opened for requests of a group (matched by the group's name). Busy
   connections finish their request and age out with the idle timeout. Files: `src/client.rs`,
   `src/client/layer/client.rs`, `src/client/layer/client/pool.rs`, `src/group.rs`,
   `src/conn/descriptor.rs`. `pool_max_size` now bounds the idle connections over all keys
   (the oldest idle connection of the least recently used key is dropped first), not the keys.

## Updating

Re-copy `src/` from the new upstream release, then re-apply the patches (grep for
`Modified by Argus`), update the versions above and the pins in `crates/proxy-core/Cargo.toml`.

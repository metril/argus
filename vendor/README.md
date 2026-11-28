# Vendored crates

Third-party crates copied into the tree so Argus can carry small patches. They are wired in
through `[patch.crates-io]` in the workspace `Cargo.toml` and excluded from the workspace
(`exclude = [...]`), so they are not linted or formatted by our CI. Everything else they depend on
(btls, the http2 fork, tokio-btls, ...) stays a normal crates.io dependency.

Licences: `wreq` and `wreq-util` are Apache-2.0 (see each `LICENSE`; upstream ships no `NOTICE`
file); each modified file starts with a `// Modified by Argus: <why>` header, as Apache-2.0
section 4 requires. `btls-sys` is MIT (`btls-sys/LICENSE-MIT`) and bundles BoringSSL, which has its
own licence (`btls-sys/deps/boringssl/LICENSE`: Apache-2.0, OpenSSL, SSLeay and ISC parts). The
patched BoringSSL files carry `Modified by Argus` markers inside `patches/argus-chrome-tls.patch`.
The Docker image ships these four licence files under `/app/licenses/` (see the `Dockerfile`),
because the binary links BoringSSL and wreq statically.

## Integrity

The vendored trees must equal the crates.io release plus the reviewed Argus patches, and nothing
else. `scripts/verify-vendor.sh` (run by the `wreq-patches` CI job, and by hand before a commit that
touches `vendor/`) downloads each pristine `.crate`, checks its SHA-256 against
`vendor/pristine/crates.sha256` and against the crates.io index checksum, unpacks it and compares
it with the vendored tree with `diff -r`:

* no file may exist on one side only, except the added `btls-sys/patches/argus-chrome-tls.patch`
  and the files dropped on vendoring (tests, examples, lockfiles, cargo's `.cargo_vcs_info.json`
  and `Cargo.toml.orig`);
* no symlinks and no changed exec bits;
* the content differences of the remaining files must equal the committed
  `vendor/pristine/<crate>.diff`, the reviewed patch. After an intended change run
  `scripts/verify-vendor.sh --update` and review the `.diff` in the commit.

`vendor/pristine/` is the reviewed artifact: read its diffs (the patch contents are in them) on every change to `vendor/`.

`--offline` skips the index cross-check. When updating a vendored crate, update the version and
hash in `crates.sha256` (the hash is the one in `Cargo.lock` of a registry build, or the index
`cksum`) and regenerate the `.diff`.

| Crate | Upstream | Version | Local patches |
|---|---|---|---|
| `wreq` | <https://github.com/0x676e67/wreq> | 6.0.0-rc.31 | 1, 2, 3, 4, 5, 6, 7 |
| `wreq-util` | <https://github.com/0x676e67/wreq-util> | 3.0.0-rc.14 | A (Chrome 151, 153 and 156 profiles) |
| `btls-sys` | <https://github.com/0x676e67/btls> | 0.5.6 | B (BoringSSL: ML-DSA signature algorithms, GREASE signature algorithm, `server_padding`) |

For `wreq` and `wreq-util` only `src/`, `Cargo.toml`, `LICENSE` and `README.md` are kept; tests,
examples and lockfiles were dropped.
`btls-sys` is kept whole (its BoringSSL sources under `deps/boringssl`, `build/`, `patches/`, `cmake/`),
because the build applies the patches to a copy of those sources.

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
5. **At most one internal re-send of an unstarted request.** The pooled client re-sends a request
   whose reused connection was closed before it started (the request is handed back unsent, so
   even a streamed body is safe) at most once, and an error returned after that re-send answers
   `Error::is_retried()`, so Argus does not stack its own retry on top. Files:
   `src/client/layer/client.rs`, `src/error.rs`.
6. **The internal re-send takes a fresh connection.** The re-send of patch 5 used to check out
   another idle pooled connection, which may be just as stale. It now runs under a unique pool key
   (`Group::fresh`, `ConnectionDescriptor::fresh`), so it dials; the TLS session cache key is
   unchanged, so resumption still works. Files: `src/client/layer/client.rs`, `src/group.rs`,
   `src/conn/descriptor.rs`.

7. **SOCKS: resolve first, errors expose their cause.** The target is resolved (and vetted by
   the client's resolver) before the proxy is dialled. `SocksError::source` returns the wrapped error, so a
   destination-policy refusal raised by the client's DNS resolver (`DnsResolveFailure`) is still
   found by walking the error chain. File: `src/conn/proxy/socks.rs`.

8. **Chrome ClientHello options (wreq).** `TlsOptions::grease_signature_algorithm` (a GREASE value
   first in `signature_algorithms`), `server_padding_request` (the `server_padding` extension, 0x12e0)
   and `requested_trust_anchors` (the `trust_anchors` extension, 0xca34, with a wire-format list), applied
   with raw `btls_sys` calls (`SSL_CTX_set_grease_signature_algorithm`, `SSL_set_server_padding_request`,
   `SSL_CTX_set1_requested_trust_anchors`). Needs the patched `btls-sys` (patch B). The `foreign-types`
   dependency gives `Ssl::as_ptr`. Files: `src/tls.rs`, `src/tls/conn.rs`, `Cargo.toml`.

A. **Chrome 151, 153 and 156 profiles (wreq-util).** `Profile::Chrome151`, `Chrome153` and `Chrome156`:
   the ML-DSA signature algorithms (`SIGALGS_LIST_ML_DSA`), the GREASE signature algorithm, and the
   trust anchor lists captured from real builds. Files: `src/emulate.rs`,
   `src/emulate/profile/chrome.rs`, `src/emulate/profile/chrome/tls.rs`. See `docs/UPSTREAM-TLS.md`.

B. **BoringSSL ClientHello patch (btls-sys).** `patches/argus-chrome-tls.patch`, applied last by
   `build/main.rs` (one added step there, marked `Modified by Argus`): `SSL_SIGN_ML_DSA_44/65/87`
   (0x0904 to 0x0906) as real signature algorithms (table entry, public key parsing, names
   `mldsa44`, `mldsa65`, `mldsa87`; TLS 1.3 only, skipped when the maximum version is 1.2),
   `SSL_CTX_set_grease_signature_algorithm`, and the client side of `server_padding`
   (`SSL_set_server_padding_request`). Backported from BoringSSL `main`. To regenerate it: copy
   `deps/boringssl`, apply the older patches in `build/main.rs` order with `patch -p1`, edit a second
   copy, and `diff -ruN a b` the two. The workspace `Cargo.toml` points `[patch.crates-io] btls-sys`
   at this directory; the `wreq-patches` CI job passes the same through `--config`.

## Updating

Re-copy `src/` from the new upstream release, then re-apply the patches (grep for
`Modified by Argus`), update the versions above and the pins in `crates/proxy-core/Cargo.toml`.
For `btls-sys`, re-copy the crate and check whether the new BoringSSL has the sigalgs and
extensions already (then drop patch B); otherwise regenerate it as described there.

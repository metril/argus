# Upstream TLS fingerprint (Chrome)

Argus connects to sites with the TLS and HTTP/2 fingerprint of the browser behind each request
(Settings, "browser-like upstream connections"). The browser's own headers are forwarded untouched, so
the handshake has to match the browser the headers claim. A handshake of an older Chrome next to a
newer User-Agent is a known bot signal (Cloudflare turns an automatic check into an interactive one).

## How a profile is chosen

`crates/proxy-core/src/browser_profile.rs` reads the browser version from `Sec-CH-UA` (then
`User-Agent`) and takes the newest profile **at or below** it (`nearest`). A version above the newest
profile uses the newest profile; below the oldest, the oldest. Chrome profiles that differ in the
ClientHello (the rest reuse the one before them):

| Profile | What changed against the one before | Evidence (real build) |
|---|---|---|
| Chrome 100 to 149 | as shipped in `wreq-util` | Chromium 141 (`--disable-field-trial-config`): JA4 `t13d1516h2_8daaf6152771_d8a2da3f94cd` |
| Chrome 151 | `signature_algorithms` starts with the ML-DSA code points 0x0904, 0x0905, 0x0906 | Chrome 151.0.7922.137: `t13d1516h2_8daaf6152771_806a8c22fdea` |
| Chrome 153 | a GREASE value first in `signature_algorithms`; the `trust_anchors` extension (0xca34) with Chrome's list | Chrome for Testing 153.0.8010.12: `t13d1517h2_8daaf6152771_cb7bf5808d99` |
| Chrome 156 | the `trust_anchors` list changed (same JA4) | Chrome for Testing 156.0.8078.4 and 159.0.8154.6: same JA4 |

Edge 151 and newer take the Chrome 151, 153 or 156 profile by the same rule (Edge is Chromium; the
Edge profiles up to 148 are the Chrome ones with other client hints, which a unit test pins, and
Argus forwards the browser's own headers). This is not captured from a real Edge build; to verify it,
run the live test below with `ARGUS_LIVE_CHROME=/path/to/msedge`.

Versions between two profiles (150, 152, 154, 155, 157, 158) get the profile below them. Only
141, 151, 153, 156 and 159 were available to capture, so the exact release in which a step first
appeared (for example whether 150 already sends ML-DSA) is **not known**; add a profile when a
capture shows a change (procedure below).

Everything else is identical in all of them: cipher list, supported groups (X25519MLKEM768 first),
key shares, ALPN, ALPS (new codepoint 17613, `h2`), certificate compression (brotli), PSK modes,
supported versions, ECH GREASE, extension permutation (GREASE first and last, the rest random per
connection), HTTP/2 SETTINGS and header order.

## Field-trial dependent extensions

Whether Chrome sends some extensions depends on its field trials (experiments), so a profile follows
Chrome's built-in defaults, which is what a build without a variations seed sends
(`--disable-field-trial-config`):

* `trust_anchors` (0xca34): off by default in 151, on by default from 153. `--enable-features=TLSTrustAnchorIDs`
  turns it on in 151.
* `server_padding` (0x12e0, data `0000`): sent only when the experiment is on (Chrome's testing
  trial config, or a Finch group). Not part of any profile. The patched BoringSSL can send it
  (`TlsOptions::server_padding_request`).
* A Chrome in an experiment group can therefore differ from the profile. To compare a browser you
  run yourself, use the live test (below).

## Trust anchors and the retry without them

The `trust_anchors` list is Chrome's, but Argus verifies with its own root set. A server that does
trust-anchor negotiation may answer with a chain rooted in an anchor Argus does not trust. Like Chrome,
Argus then retries: when certificate verification fails on a connection whose ClientHello carried
`trust_anchors`, the request is sent again on a new connection with the same profile minus that
extension (`crates/proxy-core/src/trust_anchor_retry.rs`, used by `UpstreamRequest::send` and
`send_upgrade`). The retry verifies the chain in full again, so a genuine certificate failure still
fails (and is reported as the TLS error of the retry). Per `host:port` Argus remembers the outcome:
if the plain handshake verified, the host is dialled without the extension for an hour; if it failed
as well, the host is not retried for five minutes. Every retry is counted in `faults.trust_anchor_retries`
(`GET /stats/proxy`), summarised in the log with the other faults and logged at info level. A request
with a streamed body larger than the replay limit cannot be sent again and gets the TLS error.

## The BoringSSL patch (`vendor/btls-sys`)

The vendored `btls-sys` carries `patches/argus-chrome-tls.patch` (applied after the others by
`build/main.rs`):

* ML-DSA 44, 65 and 87 (0x0904 to 0x0906) as signature algorithms (names `mldsa44`, `mldsa65`,
  `mldsa87`). TLS 1.3 only, never sent when the maximum version is 1.2. These are real entries:
  a server that selected one would be verified with BoringSSL's ML-DSA implementation, and BoringSSL
  only accepts it with an ML-DSA leaf key (an RSA or ECDSA leaf with an ML-DSA scheme is rejected).
  Certificate chains are verified by Argus's hook (rustls `webpki`, no ML-DSA): a classical CA
  chain with an ML-DSA leaf verifies (webpki checks the chain and never uses the leaf's key, then
  BoringSSL verifies CertificateVerify with ML-DSA); only a chain with an ML-DSA CA or intermediate
  fails closed, where Chrome would verify it. No public CA issues ML-DSA certificates today, and
  servers with RSA or ECDSA certificates never select the code points (RFC 8446, 4.2.3).
* `SSL_CTX_set_grease_signature_algorithm`: GREASE value first in `signature_algorithms`.
* `SSL_set_server_padding_request` and the `server_padding` extension (client side).

`trust_anchors` needs no patch (`SSL_CTX_set1_requested_trust_anchors` exists). `vendor/wreq` exposes the
three as `TlsOptions::{grease_signature_algorithm, server_padding_request, requested_trust_anchors}`
(patch 8 in `vendor/README.md`); the profiles are in
`vendor/wreq-util/src/emulate/profile/chrome.rs` and `.../chrome/tls.rs`.

## Tests

* `crates/proxy-core/tests/chrome_tls_tests.rs`: for each fixture the ClientHello of the profile
  chosen for that Chrome version is compared field by field with the capture (JA4, ordered cipher,
  group, key share and signature algorithm lists, extension set, ALPN, ALPS, compression, PSK modes,
  versions, `trust_anchors` bytes, ECH header), and over eight connections the extension order must
  vary and GREASE stay first and last. The mapping from versions to profiles is tested too.
* `crates/proxy-core/tests/trust_anchor_retry_tests.rs`: a local origin that presents an untrusted
  chain only to hellos with (or without) the extension: retry, per-host memory, a chain that is bad
  either way still failing, and that the retry changes nothing but the extension.
* `crates/proxy-core/tests/tls_sigalg_negative_tests.rs`: servers (rustls with a signing key that
  claims any scheme) selecting the GREASE value, a scheme not offered, an ML-DSA scheme with an
  ECDSA or Ed25519 leaf, or ML-DSA in TLS 1.2 are rejected, the honest server with the same chain
  succeeds, and a client limited to TLS 1.2 offers no ML-DSA. There is no RSA-leaf case: the check
  (`EVP_PKEY_id(leaf) == scheme's key type`) is the same for every key type. A positive ML-DSA
  handshake cannot be tested: no ML-DSA certificate or server is available (system openssl is 3.0).
* Live comparison with a real Chrome, never in CI:
  `ARGUS_LIVE_CHROME=/path/to/chrome cargo nextest run -p proxy-core --test chrome_tls_tests --run-ignored only`
  (extra browser flags in `ARGUS_LIVE_CHROME_FLAGS`). It launches that browser against a local
  capture server, builds Argus's handshake for the same version and lists every differing field.

## Adding a profile for a new Chrome

1. Capture. With the browser binary (own throwaway profile, headless, no third party):

   ```
   python3 scripts/chrome-tls/chrome_tls.py capture --chrome /path/to/chrome --out caps.jsonl -n 12
   ```

   It starts a local listener that records the first TLS record of every connection and launches the
   browser at it 12 times with `--disable-field-trial-config`.
2. Compare with what Argus sends:
   `ARGUS_LIVE_CHROME=/path/to/chrome cargo nextest run -p proxy-core --test chrome_tls_tests --run-ignored only`.
   No difference means the nearest profile already matches; only add the fixture. For a third opinion
   `https://tls.peet.ws/api/all` shows JA3, JA4 and the HTTP/2 fingerprint of a real request.
3. Fixture: `python3 scripts/chrome-tls/chrome_tls.py fixture --in caps.jsonl --label NNN --out crates/proxy-core/tests/fixtures/chrome-tls/chrome-NNN.json`.
   The file holds the comparable view of the ClientHello (the keys of `Hello::canon` in the test) and
   the capture's metadata. The samples must agree; resumed (PSK) connections are ignored. ECH GREASE
   picks one of four payload sizes (extension length 186, 218, 250 or 282) at random, so the fixture
   lists the allowed ones.
4. Profile, only if a field differs: add `vN` in `vendor/wreq-util/src/emulate/profile/chrome.rs`
   (`mod_generator!`, reusing `tls_options!` in `chrome/tls.rs`; a new variant when a new option is
   needed), register it in `vendor/wreq-util/src/emulate.rs` and in the `CHROME` table of
   `browser_profile.rs`. A new extension, signature algorithm or group the BoringSSL snapshot does not
   know needs a change to `vendor/btls-sys/patches/argus-chrome-tls.patch` (see `vendor/README.md`).
5. Add a `chrome_NNN_matches_captured_fixture` test and extend the mapping test.

The newest Chrome profile is also the default for an unrecognised browser.

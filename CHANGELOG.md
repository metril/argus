# Changelog

## Unreleased

* Browser-like upstream connections (Settings, on by default; `proxy.upstream.browser_like`):
  Argus connects to sites with the TLS and HTTP/2 fingerprint of the browser behind each request
  (Chrome, Edge, Firefox or Safari, chosen from its client hints and User-Agent) and forwards the
  browser's headers untouched and in order. Certificates are still verified against Argus's
  trusted roots inside the handshake. Switching it off uses the previous client, kept for one
  release. WebSockets still use the previous client.
* Upstream connections of the browser-like client are now pooled per downstream connection (and
  closed with it), so many browsers no longer share one connection to a site. TLS sessions are
  resumed per device, never across devices.

## 0.5.0 — 2026-11-24

* Userscript `@include`/`@exclude` regexes now follow JavaScript semantics (lookaround and
  backreferences work); a pattern that cannot be compiled fails safe and matches nothing. The
  userscript UI words external libraries more clearly.
* Requests addressed to Argus itself now reach its web UI through the proxy instead of a `403`,
  limited to the bound browser (extension listener) and to permitted clients.
* Extension sign-in: the extension signs in against Argus and mints its own API token
  (`POST /api/v1/auth/extension-token`); it revokes it on sign-out (`DELETE /api/v1/tokens/self`).
  Chrome requests per-host permissions at runtime. Script login consent is derived from the
  recorded per-host grants.
* Extension redesign, plus a Browser extension page in the web UI.
* Tokens: expiry presets or a custom date (`expires_at` in the API) and a compact scope table.
* "Argus" is capitalized consistently in user-visible text.

## 0.4.0 — 2026-11-24

* Extension bridge: the Argus extension can connect to the proxy (`GET /api/v1/ext/channel`, token
  scope `userscripts:bridge`). A new extension-only proxy listener (`proxy.ext_port`, Settings in the
  web UI, off by default, applied live) answers `407` to anything without the extension's session
  credentials (`Proxy-Authorization: Basic ext:<sid>`); a connection that authenticates, and every
  document decrypted on it, is bound to that browser's session. No client address and no request
  header is used; normal ports never answer this `407`, and the transparent listener does not bind.
  The extension has a "Use Argus in this browser" switch (Chrome: `proxy.settings`; Firefox:
  `proxy.onRequest`, with per-container and private-window switches and per-store credentials) and
  answers only that listener's `407`. Unbound pages behave exactly as before: no `Server-Timing`
  entry, no per-document record.
* Revoking a token, expiring it, or disabling or deleting its owner closes its live extension
  channels and drops the proxy connections they authenticated (within half a second); the channel
  also re-verifies its token every three pings.
* A slow page can no longer corrupt or stall a relay: a full job queue fails that job with an error
  and tells the extension to cancel, and never delays pongs or other jobs.
* Credentialed requests go through the browser only for hosts Argus decrypts and that are public:
  bypassed, passthrough, Extended Validation (tunnelled), loopback, private and link-local targets,
  and `redirect: "manual"` calls use the script's own jar. Every hop must arrive on a connection
  that authenticated as the job's session. Relay authority comes only from per-host permissions
  (never `<all_urls>`, `*://*/*` or public suffixes); the options page button that asked for all
  sites is gone. Public suffixes are no longer offered as host grants.
* A relayed response that redirects is checked by the proxy before the browser can follow it:
  the target must pass `@connect`, the session's permissions, the public-host and bypass rules,
  the fail-safe and the Extended Validation setting, or the response becomes a `502` without
  `Location` or `Set-Cookie`. Hosts Argus would tunnel (EV with "do not decrypt EV sites" on) are no
  longer relayed to at all.
* The extension listener also speaks SOCKS5 (username/password only), which Firefox uses so that
  every container's connections carry their own store credentials; no identity is placed in any
  request, so none can reach an origin through a tunnelled host. The extension works in Firefox
  again (its explicit CSP no longer upgrades the channel to `wss://`, and the store-relay listeners
  register).
* Hardening of the bridge: a public `mdoc` plus a script token no longer lets another browser,
  container or unauthenticated connection use a document (relays go to the jar, `menu/sync` and
  `menu/wait` are refused); redirects with an empty, doubled or unparsable `Location` are refused;
  relays require a decrypting extension listener and never target Argus's own console or panel;
  revocation also ends upgraded WebSockets; the SOCKS5 handshake has one deadline and refuses
  hosts that do not normalise.
* Real-browser suites (`crates/e2e-browser/tests/extension_chromium.rs`, `extension_firefox.rs`) run
  the built extension against a real Argus process; they are opt-in (`ARGUS_EXT_E2E=1`) and have
  their own CI shard.
* Relays for Firefox containers and private windows use that store's cookies (the fetch is made
  without the default store's, the store's go in per hop and `Set-Cookie` is written back to it);
  menus and documents are scoped to the store. Chrome's incognito windows are served by a second
  (`split`) extension instance with its own session and cookie jar.
* Userscript menu commands are listed and triggered from the extension popup; for pages opened in
  that browser the in-page button is not mounted, and it comes back when the extension is not
  serving the page. A freshly shown or re-attached badge ignores clicks for 300 ms.
* Scripts approved for browser logins (`browser_cookies`, granted only during review, off by
  default) send non-anonymous `GM_xmlhttpRequest` and `GM_cookie` through the extension, with the
  browser's real cookies (never HttpOnly ones). Every hop is checked against the script's `@connect`
  by the proxy; requests and approvals are audited. Without the extension the script's own cookie
  jar is used and its page shows "browser logins unavailable".

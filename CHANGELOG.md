# Changelog

## Unreleased

## 0.9.2 — 2026-11-27

- Signed catalogue entries with `profile: "default"` (Argus Base) are added and enabled once on every install after the verified catalogue loads; the offered ids are kept, so a list you remove or disable stays that way. Strict never touches them. The Filters page badges them "Argus default".

## 0.9.1 — 2026-11-27

- A blocked fetch of an extensionless script URL (e.g. gtag/js) gets the script JS stub when that exact URL is stubbed as a script.
- Parity harness: slow network failures are excluded from scoring.

## 0.9.0 — 2026-11-27

- Opt-in Strict blocking profile (Filters page, `GET`/`PUT /api/v1/lists/profile`): adds AdGuard Annoyances and Social Media, EasyList Cookie, Fanboy Social, uBO Annoyances and every signed `profile: strict` entry (Argus Extra Trackers). It blocks more and may break sites (fix with per-site allow rules). Applied live and persisted; switching back removes only what Strict added. Default is unchanged.
- Catalogue entries carry an optional `profile` field; `strict` entries are never seeded.
- Parity harness: informational `argus-strict` shard and column (not part of the verdict).

## 0.8.6 — 2026-11-27

- A blocked fetch of a .js URL whose script request is stubbed now gets the same stub (anti-adblock size checks).

## 0.8.5 — 2026-11-27

- AdGuard bare-host root exceptions (HTTPS-filtering-off workarounds) are dropped.
- Scriptlet resources: bundled copy installed at startup; uBO pinned via git refs instead of the rate-limited GitHub API.

## 0.8.4 — 2026-11-27

- Generic `$redirect` rules from AdGuard lists now block instead of serving a stub, matching uBO.
- Parity harness: script-only canary for AdGuard on Firefox.

## 0.8.3 — 2026-11-27

* CNAME uncloaking, as uBlock Origin does on Firefox. A request that passes the filters is judged
  again under the canonical name its host resolves to, so `cmp.osano.com` (a CNAME of a
  CloudFront host EasyPrivacy blocks) is blocked. The name comes from the answer Argus already
  fetches to connect (no extra lookup) and is cached with the addresses. Skipped, as in uBO, for
  the page's own host and documents, aliases on the same site, requests an exception rule
  allowed, and names on the ignore list. Blocks are logged with the rule `cname:<name>` and
  answered per `block_response`. Opaque tunnels (no-decrypt bypass, fail-safe) are checked by
  canonical name too. New Settings section "CNAME uncloaking" (`[adblock.cname]` in
  settings.toml, live): on/off, ignore list, same-site, exceptions, page itself, TTL (uBO's
  `dnsCacheTTL`, 600 s) and full-URL replay (off). Every default matches uBO's.

## 0.8.2 — 2026-11-27

* Fresh installs now also enable AdGuard's recommended lists (Base, Tracking Protection, URL
  Tracking, Mobile Ads) on top of uBO Lite's defaults. This covers OEM telemetry, mobile ads and
  email/video trackers. Existing installs are unchanged.
* Parity harness: fixed the Firefox canary (cross-realm TypeError) and the canary hosts.

## 0.8.1 — 2026-11-27

* Upstream failures now look like a direct connection's. A host that does not resolve, refuses or
  resets the connection, fails its TLS handshake or times out used to get a synthesized 502/504
  inside the intercepted tunnel, so a page's `fetch` resolved and counted the dead host as
  reachable (ad-block tests scored Audio Ads, OEM Vendors and Mix too low). With
  `proxy.block_response = "fail"` (the default) every non-document request, WebSockets included,
  now fails as a network error (HTTP/2: that stream is reset; HTTP/1: the connection is closed).
  Documents keep the error page, fault counters and the circuit breaker still count the failure,
  and the request log keeps the entry with its reason. A plain `CONNECT` to a name that does not
  resolve gets a 502 (the browser reports a tunnel failure). `"synthetic"` restores the 502/504
  answers for every type, for debugging.
* Under `block_response = "fail"`, a `$redirect` match on a `no-cors` fetch/XHR/beacon
  (`Sec-Fetch-Mode: no-cors`, `Sec-Fetch-Dest: empty`) is aborted (logged as aborted) instead of
  answered with the stub: the response is opaque to the page, and uBO on Firefox ends up failing
  these. Cors-mode fetch/XHR and script, image and other element loads still get the stub.

## 0.8.0 — 2026-11-27

* Blocked requests now fail like a network error (`proxy.block_response = "fail"`, the default;
  Settings, applied live), as with an extension blocker, so page scripts and ad-block tests no
  longer count a blocked resource as loaded. Scripts, fetch/XHR, styles, pings, media, fonts,
  objects and WebSockets are aborted (HTTP/2: only that stream is reset, with CANCEL; HTTP/1: the
  connection is closed); documents keep the block page, frames a blank page and images a 1x1 GIF.
  `"synthetic"` restores the old always-succeeds answers. A public name that resolves to 0.0.0.0,
  `::` or loopback (a DNS sinkhole) is aborted too and logged as `sinkholed-upstream`. The request
  log shows each block's outcome (`aborted` or `synthetic`).
* Upstream DNS (new DNS page): AdGuard Home-style upstreams with plain, TCP, DoT, DoH, DoH3, DoQ
  and DNSCrypt (`sdns://`), per-domain `[/domain/]` rules, load-balance/parallel/fastest-IP modes,
  bootstrap, fallback and private reverse resolvers, a cache with TTL bounds and optimistic
  serve-stale, DNSSEC, ECS and an AAAA toggle. Live RTT/health and a Test upstreams button. Empty
  keeps the system resolver.
* Trusted lists: the signed catalogue marks the uBlock Origin lists and AdGuard Base as trusted, so
  `trusted-*` scriptlets (YouTube, anti-adblock `rpnt` rules) now run. Existing installs are
  migrated by URL. Fresh installs get uBO Lite's default lists.
* Scriptlets: AdGuard scriptlet names map to uBO's (about 550 more rules work); generic `#%#` and
  `#$#` rules inject instead of being treated as CSS; `:style(remove: true)` removes. Scriptlets and
  hiding now reach about:blank, srcdoc and blob frames. No-transform pages are filtered and the
  service-worker guard is on by default.
* `$popup` rules apply to new tabs the extension reports; `@@` exceptions override extended block
  rules (except `$important`); CSS-initiated requests are attributed to their page.
* Extension: the popup's "Intercepted" status now reflects whether this tab actually went through
  Argus (needs the new `webNavigation` permission).
* CI: an adblock parity harness scores Argus against uBO Lite, uBlock Origin and AdGuard on five
  test sites (weekly); faster CI and image builds.

## 0.7.0 — 2026-11-26

* Element hiding: uBO's procedural engine (`:has`, `:has-text`, `:upward` and the rest)
  runs in the page and re-runs, throttled, as the page changes. Each selector is its own rule, so
  one bad selector no longer drops its neighbours, and exceptions (`#@#`, `$elemhide`,
  `$generichide`) are honoured per selector.
* Redirect resources: uBO's full set of stand-in resources is bundled, with AdGuard's names as
  aliases and 10 AdGuard-only resources added, so `$redirect` rules in the default lists no longer
  fall back to plain blocks. Refreshes are pinned and validated.
* `$removeparam`: regex, negated and bare forms are supported. A new service-worker guard
  (Settings, off by default) stops sites' service workers from serving pages Argus never filtered.
* Stealth mode (Settings, off by default), using AdGuard's options and defaults: hides the
  referrer and search queries, sends Do Not Track and Global Privacy Control, removes X-Client-Data,
  and can shorten third-party cookie lifetimes, reduce the User-Agent and strip tracking
  parameters. `$stealth` exception rules are supported.
* Extension: routing fails closed. While the proxy toggle is on, the browser never silently goes
  direct; if Argus is unreachable the popup says so and offers to turn the proxy off. Sessions
  resume across background-worker and Argus restarts, and private windows get their own session.
* Request log: every request Argus answers itself is now logged too (its own page assets, stand-in
  redirects, script-policy and destination-policy blocks, service-worker refusals). Argus's own
  assets are marked `internal`. The log size is a setting (Settings → Timeouts and limits,
  100–500,000 entries, default 1000) and changes take effect immediately.

## 0.6.2 — 2026-11-25

* Extension (Chrome): no more native proxy sign-in prompt after the browser restarts the
  extension's background worker. A challenge from the extension listener waits for the session to
  reconnect (up to 10 s) and is cancelled rather than handed to the browser; host names are
  compared case- and bracket-insensitively. Sign-out always completes: the token is forgotten
  first, the proxy setting is cleared, and the server-side revoke is best effort (3 s), so the
  address and other settings can be changed again.

## 0.6.1 — 2026-11-25

* The previous upstream client is removed. With browser-like connections off, Argus uses the same
  client without the browser fingerprint (WebSockets too).

## 0.6.0 — 2026-11-25

* Upstream proxy (Settings, off by default; `proxy.upstream.proxy`): Argus can send everything it
  connects to through another proxy, HTTP `CONNECT` or SOCKS5, with an optional username and
  password. DNS lookups stay on Argus: it resolves and vets each target itself (private, reserved
  and its own addresses are still refused) and sends the proxy only that IP, never a name. TLS
  and `Host` still use the name. Web requests, WebSockets, userscript requests, certificate and
  EV probes, passthrough tunnels, and Argus's own fetches (filter lists, bypass lists and the
  root store, extension downloads, userscript imports) all go through it, and nothing connects
  directly while it is on. The fetches keep their destination checks and certificate
  verification and pinning, and follow a settings change on the next request. The proxy itself may be on a private network but never one of Argus's own listeners.
  A Test button checks it (one at a time, ten a minute per token; failures report one generic
  message, the reason goes to the log). The password is write-only (the API reports `set` or
  `unset`) and is kept only while the type, host and port stay the same: change any of them and
  the username and password must be entered again, so saved credentials are never sent to
  another address.
  While it is on and browser-like connections are off, the plain wreq client replaces the
  rustls one (only wreq resolves names locally before tunnelling).
* Browser-like upstream connections (Settings, on by default; `proxy.upstream.browser_like`):
  Argus connects to sites with the TLS and HTTP/2 fingerprint of the browser behind each request
  (Chrome, Edge, Firefox or Safari, chosen from its client hints and User-Agent) and forwards the
  browser's headers untouched and in order. Certificates are still verified against Argus's
  trusted roots inside the handshake. Switching it off uses the previous client, kept for one
  release. WebSockets use these connections too (see below).
* Upstream connections of the browser-like client are now pooled per downstream connection (and
  closed with it), so many browsers no longer share one connection to a site. TLS sessions are
  resumed per device, never across devices.
* A request that fails before any response arrives on a stale upstream connection is retried once
  on a fresh connection, for bodies of up to 64 KiB. Non-idempotent requests (POST and the like)
  are retried only when the site provably never processed them (a refused stream, or nothing was
  sent); idempotent ones (GET, HEAD, OPTIONS, PUT, DELETE) also after a reset or GOAWAY before any
  response. Streamed bodies, timeouts and certificate errors are never retried.
* WebSockets use browser-like connections (when `proxy.upstream.browser_like` is on): the upgrade
  goes out with the TLS fingerprint of the browser behind it (HTTP/1.1 ALPN, as a browser's
  WebSocket connection), the certificate is verified inside the handshake, and the handshake
  headers (Origin, Sec-WebSocket-Protocol, Sec-WebSocket-Extensions, cookies) are forwarded
  untouched and in order. Connections are grouped per downstream connection, TLS sessions
  resumed per device, and the upstream proxy and destination policy apply as for requests.
  Frames are still relayed untouched, so permessage-deflate stays consistent end to end.
* Fixes: typing the proxy port as the Argus address reaches the web UI (with the same client and
  bind restrictions as self-routing); the extension tells a missing server listener from a pending
  connection and links to its setup, which the web UI can turn on; token lists hide revoked tokens
  (`include_revoked=true` shows them) and dead tokens are purged hourly and at startup; upstream
  request errors are logged at `warn` with their full cause; host-blocked sites get the block
  response instead of a certificate (EV) probe.

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

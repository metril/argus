# Userscript delivery and GM endpoint protocol

Audience: whoever wires `crates/userscript-engine` into the proxy. The JS runtime
(`assets/gm.js`) is the only client; everything below is what the server side must implement,
so the JS never needs to be read. Pure-Rust implementations of the operations live in
`userscript_engine::backend` (`GmBackend`), `token`, and `bundle`.

## 1. Model

Userscripts run **in the page's own JavaScript world**: a proxy has no isolated world. The
runtime is injected before any page script, captures the built-ins it needs, and talks to
the proxy over same-origin `fetch` to paths under `/__adblock__/gm/`. Privileged
operations (value storage, cross-origin requests, cookies, resources) are done by the proxy
after it authenticates the caller as "script S of profile P on origin O" and enforces the
script's *server-side* grants and `@connect` list.

Never forward `/__adblock__/` upstream; answer it locally for every host the proxy
intercepts (the page's origin is the proxied host, so requests are same-origin).

## 2. Delivery

1. For an HTML document: resolve the profile (from the connection), call
   `ScriptIndex::candidates(host, url, is_top_frame)`. Empty result: inject nothing.
2. Build the bundle: `bundle::generate(&candidates, &BundleOptions)` with
   `values` = the scripts' current stored values (`GmBackend::values_get(ctx, None)`), so
   `GM_getValue` is synchronous. `BundleOptions::page_origin` must be the document's origin
   in `Origin`-header form (`https://example.com`, no trailing slash, default port omitted).
3. Serve `Bundle::js` as **an external script** (`Content-Type: application/javascript`,
   `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`) at an unguessable, short-lived,
   ideally single-use URL (e.g. `/__adblock__/us/<random>.js`), and inject at the very top of
   `<head>`: `<script src="/__adblock__/us/<random>.js" nonce="..."></script>`: classic,
   synchronous, no `async`/`defer`, so `@run-at document-start` scripts run before page code.
   Do not inline the bundle: script *source* is emitted verbatim (it is code), so a literal
   `</script` in a script would end an inline tag. `Bundle::inline_safe()` reports when inlining
   would also be safe. All metadata/values in the bundle are escaped with `bundle::js_json`
   (`<`, `>`, `&`, U+2028, U+2029 become `\uXXXX`).
4. CSP: use the same nonce mechanism as `boot.js`. `@unwrap` scripts and `GM_addStyle` copy the
   bundle's nonce to elements they create. Trusted Types: not handled by the runtime; if the
   page enforces it, the proxy must allow the policy it creates for `boot.js`, or skip userscripts.
5. One syntax error in any script makes the whole bundle fail to parse. Call `generate` once
   per script and inject several bundles if isolation matters more than size (with
   the shared runtime of 2.1 the 40 KB runtime is not repeated).
6. The runtime removes its own `<script>` element from the DOM at startup and again removes
   any element it injected (`@unwrap`) after execution.

Bundle layout: the runtime (`<gm.js>`, installed once, see 2.1) is called as `run({base, top, handler, handlerVersion}, [{d: descriptor, f: fn}, ...], window, shared)`.
Descriptor `d`: `id, name, runAt, grants (canonical, lowercase), params, token, meta, metaStr,
unwrap, values?, resources?, code?`. `f` is `function(GM_info, GM, <granted GM_*>, unsafeWindow)`
wrapping `@require`s + source in one scope (`this === window`; async function with
`@top-level-await`). `@grant none` gives only `unsafeWindow` (=== `window`). `GM_info`/`GM`
exist whenever any real grant is present. `@unwrap` scripts get no GM API and are injected as a
nonce'd inline `<script>`.

### 2.1 As implemented in `proxy-core` (`src/gm.rs`)

* **One file per script**, as 2.5 suggests: `/__adblock__/us/<doc>.<n>.js`, `n` in injection order
  (run-at group, then install order); a syntax error in one script cannot break another.
* **The runtime is served once**, from a shared, content-hashed, immutable URL
  (`/__adblock__/gm.<hash>.js`, `Cache-Control: immutable`, no secret in it): one nonce'd
  `<script src>` placed before the first bundle. It installs the runtime function, the command
  registry shared by every script of the document, and one non-writable, non-configurable entry
  point under `Symbol.for("adblock.userscript.runtime")`. Each bundle is then only
  `(function(r){if(r)r(cfg,[entries]);})(window[Symbol.for("adblock.userscript.runtime")]);`
  (`BundleOptions::shared_runtime`; without it the bundle starts with the same installer, and a
  later bundle reuses the first install). Secrecy is unchanged: capability tokens, stored values
  and `@resource` bodies still arrive only in the per-document, single-use `no-store` bundle
  responses. A hostile page that finds the entry point can call it, but with entries of its own
  and no token it has no GM authority; it can at most add fake menu commands. Consequence:
  `GM_registerMenuCommand` registers for every script on the page, not just the first.
* The page's `<head>` carries only the `<script src>` tags: no token, no config. The bundle is
  generated when the URL is fetched (stored values read then), served once (`404` afterwards),
  bound to the document's host, and expires 60 s after the document was served. Per-document
  records live in a bounded map (4096, oldest evicted first).
* The scripts' `<script>` tags come after the blocker's own tags, still before any page script.
  The policy gets `script` (nonce), `connect` (when any script has a grant), and `style` (when a
  script uses `GM_addStyle`/`@unwrap`). A response whose CSP is `sandbox` without `allow-scripts`
  gets nothing.
* `origin` for token binding is derived from the connection (scheme, host, port), not from a
  header; the `Origin` header must equal it. `resource` GETs have no `Origin`, so they need
  `Sec-Fetch-Site: same-origin`. POSTs need `Origin` and `Content-Type`; a cross-site request,
  `null` origin or a missing header is `403` with an empty body, and `OPTIONS` is never answered.
* `values/get` also works for scripts that only `@grant GM_addValueChangeListener`.
* Outbound concurrency: 8 per script, 32 per profile (`429` + `quota_exceeded`). The request body is
  buffered up to `Quotas::max_request_body` (64 MiB); the response is streamed with a 256 MiB cap
  and one overall deadline (`timeout`). `Accept-Encoding: identity` is sent unless the script set one.
* The browser's own cookies for `anonymous: false` are attached only through the extension bridge
  (section 8) and only for scripts approved for it (`browser_cookies`); otherwise the proxy cannot
  see them and only the GM jar is used. Not implemented: a shared, cacheable runtime URL.

## 3. Capability token

`v1.<b64url(script_id)>.<exp_unix_secs>.<b64url(HMAC-SHA256(key, msg))>`,
`msg = "adblock-gm-v1" 0 profile 0 script_id 0 script_version 0 origin 0 caps_hash 0 exp`
(0 = NUL byte; `caps_hash` = `token::caps_hash`: sorted canonical grants, sorted `@connect`,
`@connect *` approval flag). Key: supplied by the caller (>= 32 random bytes; rotate on restart
is fine: pages refresh, see `token/refresh`). Default lifetime 1 h; the runtime refreshes at
half-life, or every 20 s when under 4 min remain.

The token **only identifies the claimed script**. The server must, per request:
1. take `profile` from the *connection* (never from the request), `origin` from the `Origin`
   header (reject if absent);
2. `token::claimed_script_id(token)`, load that script from its own store for that profile;
3. `token::verify(key, token, now, profile, origin, |id| record)` with the stored script's
   version and `caps_hash`; reject on any error (`401 unauthorized`);
4. build `ScriptCtx { profile, script: &stored, page_host: host(origin) }` and call
   `GmBackend`, which checks the *stored* grants/enabled flag/`@connect`. Nothing from the
   token or body ever widens authority. Editing a script, changing its grants/`@connect`, a
   different profile or origin, or expiry invalidates old tokens.

Transport: header `X-GM-Token: <token>`. The only exception is `GET /resource` which also
accepts `?t=<token>` so it can back `<img src>`-style use.

## 4. Request rules (all endpoints)

* Base path `/__adblock__/gm/v1/`. Method `POST` (JSON) except `resource` (`GET`) and `xhr`
  (`POST`, binary framing). Fetch is made with `credentials: "omit"`, `cache: "no-store"`,
  `redirect: "error"`.
* Require `Sec-Fetch-Site: same-origin` (when present) and `Origin` equal to the token's origin;
  reject `Origin: null`. Content-Type must be exactly `application/json` (or
  `application/x-gm-frame` for `xhr`). Never emit CORS headers. Respond with
  `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`.
* Cap request bodies (`Quotas::max_request_body` for xhr, 2 MiB JSON otherwise).

### Envelope and errors

Success: `200 {"ok":true,"result":<json>}`. Failure: `{"ok":false,"error":{"code","message"}}`
with the status from `ErrorCode::http_status()`: `unauthorized` 401, `not_granted` /
`connect_denied` / `disabled` 403, `quota_exceeded` 413, `bad_request` 400, `not_found` 404,
`unsupported` 501, `internal` 500. (`GmError::to_json()` builds the body.)

## 5. Endpoints

All map 1:1 onto `GmBackend` methods; "grant" = any of the listed canonical grants.

| Path | Body | Result | Grant |
|---|---|---|---|
| `values/get` | `{"names": ["a"] \| null}` (null = all) | `{name: value}` (missing names omitted) | getValue / getValues / listValues |
| `values/set` | `{"values": {name: json}, "src": "<tab id>"}` | `null` | setValue / setValues |
| `values/delete` | `{"names": [..], "src": ".."}` | `null` | deleteValue / deleteValues |
| `values/list` | `{}` | `[names]` | listValues |
| `values/changes` | `{"since": null \| seq}` | `{"seq": n, "reset": bool, "changes": [{seq,name,old,new,src}]}` | addValueChangeListener |
| `token/refresh` | `{}` | `{"token": "...", "exp": n}` (mint a new token for the verified script) | none beyond a valid token |
| `cookie` | `{"op":"list","url","name"?}` / `{"op":"set","url","cookie":{...}}` / `{"op":"delete","url","name"}` | list: `[Cookie]`, else `null` | cookie (+ `@connect` on the URL) |
| `resource?name=N&t=TOKEN` | (GET) | raw bytes, `Content-Type` = stored MIME | getResourceText / getResourceURL |
| `xhr` | framed, see 5.1 | framed stream | xmlhttpRequest (`op:"xhr"`) / download (`op:"download"`) |

Values are JSON. Quotas (`Quotas`, per call to `values/set`, all-or-nothing): per value,
per script, per profile; exceeding any gives `quota_exceeded`. Storage is namespaced by
(profile, script id) (`storage::ns`). `values/changes` is a bounded (256) per-script log:
`since` older than the log returns `reset: true` (re-read all values). `src` is the writer's
opaque tab id so a tab ignores its own writes. Same-origin tabs also notify each other over
`BroadcastChannel("adblock-gm:<script id>")`; the poll is the cross-origin path and runs
every 2.5 s only while a value-change listener exists.

`@resource` bodies up to `inline_resource_limit` (256 KiB) are embedded in the bundle
(sync `GM_getResourceText/URL`); larger ones are fetched through `resource`.

### 5.1 `xhr` framing

Request body (`Content-Type: application/x-gm-frame`):
`u32 big-endian metaLen | meta JSON (UTF-8) | body bytes (rest)`.
`meta` = `backend::XhrRequest`: `{op: "xhr"|"download", method, url (absolute), headers: [[name,
value],...], anonymous, cookie, user, password, timeout (ms), redirect: "follow"|"error"|"manual"}`.
FormData/Blob/ArrayBuffer/URLSearchParams are serialised by the client; the content type
(with multipart boundary) is in `headers`.

Server steps: authenticate (section 3), `GmBackend::build_outbound(ctx, &meta, body)` (grant,
`@connect`, method allow-list, header sanitising, body cap) -> `OutboundRequest`. Execute it with
the proxy's own HTTP client under the proxy's **destination policy** (SSRF protection: refuse
loopback/private/link-local/the proxy's own listeners unless the policy explicitly allows
them; `@connect` is a script-level allowance, not a substitute). For each redirect response
call `backend::next_hop(ctx, &prev, status, location)` (re-checks `@connect`, strips
`Authorization`/`Cookie` cross-origin, rewrites method for 301/302/303) unless
`redirect != follow`. `use_cookie_jar` (= not `anonymous`) selects the script's own GM cookie jar (one per profile and
script: a script never sees or replays cookies another script obtained; HttpOnly cookies the
script itself stored or received are listed to that script, as Tampermonkey's `GM_cookie` does with
its `httpOnly` field; scoping follows RFC 6265: domain-match, path-match, host-only, `Secure` only
over https, `Domain=` refused for public suffixes and unlisted single-label TLDs)
for send and `Set-Cookie`; the browser's own cookies for third-party sites are not available to
a proxy (a script approved for browser logins gets them through the extension, section 8.4).

Response: `200` + `Content-Type: application/x-gm-frames`, then frames
`u8 type | u32 big-endian len | payload`:

| type | payload |
|---|---|
| 1 head | JSON `{"status", "statusText", "headers": [[name, value],...], "finalUrl", "redirected"?}`; exactly once, first |
| 2 data | raw body bytes; zero or more, as they arrive (drives `onprogress`, streaming) |
| 3 end | `{}`; last frame on success |
| 4 error | JSON `{"kind": "network"\|"timeout"\|"denied"\|"too_large"\|"aborted", "code", "message", "status"?}`; terminal |

If the request is refused before any upstream contact (auth, grants, `@connect`, bad input) the
server answers with the normal JSON error envelope and its status instead of frames; the client
tells the two apart by `Content-Type`. Client abort = the fetch is cancelled; the server must
drop the upstream request when the connection closes. HTTP error statuses (4xx/5xx) are
ordinary `head` frames. Upload progress is emulated by the client (`loadstart`/`progress`/`load`
once the body is sent); true upload streaming is not available through `fetch` everywhere.

`download`: same endpoint with `op:"download"`; the client turns the bytes into a Blob and
clicks an `<a download>` (the proxy cannot write to the user's disk).

## 6. What a hostile page can still do

The runtime shares a world with the page. Mitigations: all built-ins are captured at startup
(`fetch`, `JSON`, `Promise`, `Object.*`, `Function.prototype.call/apply/bind`, DOM
prototype methods, `Response`/`Headers`/stream readers, typed-array methods, timers);
capability tokens live only in closures (never on `window`, the DOM, attributes or
URLs); GM objects handed to scripts are frozen; the injected `<script>`
element is removed after it runs.

Still possible, so **backend checks must never rely on page-side secrecy**:
* a page that runs *before* us in the same frame (inline script ahead of `<head>`'s first
  child, a browser extension, a pre-existing same-origin frame) can poison
  built-ins before they are captured; we cannot detect it;
* it can tamper with prototypes of objects created later (script-visible results such as
  `Promise.prototype.then` on promises we return, `Array.prototype` seen by user code),
  and observe/modify anything user scripts put in the DOM;
* it can read the bundle URL if it is guessable or reusable, and thus steal tokens; a stolen
  token is usable only from that origin (the `Origin` header is checked), for that script, until
  expiry, with that script's server-side grants;
* it can call the endpoints itself with a stolen token, or replace `window.fetch`;
* it can read the document's public `mdoc` (`Server-Timing`) and forge the `ext:` marker of the
  runtime tag or a `menu/wait` answer. That marker only decides whether the in-page button is
  mounted, so a forged `ext:true` (a page script or a service worker that rewrites the markup) hides
  the button and nothing else (a denial of the in-page menu): listing or triggering commands and
  the credentialed relay all need the bridge token and a live session bound to the document (and, for the page's own GM calls and relays, the very connection the document was served to), which
  the page cannot obtain (section 8).

### 6.1 Service workers

A service worker registered for the page's origin is in the path of every same-origin request
the page makes. Nothing the proxy can add changes that: a `fetch` handler sees page-initiated
requests whatever their headers, and it can answer any of them. In particular, with
`service_worker_policy = "allow"` a worker can (a) read the `X-GM-Token` header and body of each
GM backend call and the responses (values, `xhr` payloads, resources), and so act as the script
until the token expires; (b) answer the boot script, the runtime or a bundle URL with code of
its own; (c) `importScripts()` a bundle URL it learned from intercepted markup, which consumes
the single-use URL and runs the bundle inside the worker. It **cannot** read a bundle through
`fetch()`: a bundle is served only when `Sec-Fetch-Dest: script` (the browser sets that header and
page or worker code cannot), and a worker's `fetch()` carries `empty`. Detecting interception from
the page is not possible either: anything the page could check (a header, a timing, a marker in the
response) the worker controls, since it can answer the check itself.

What is done about it, per `userscripts.service_worker_policy`:

* `block_when_privileged` (default): on hosts where an enabled userscript with
  `GM_xmlhttpRequest`, `GM_download` or `GM_cookie` could match (host buckets only, so this
  over-approximates), a service-worker script fetch (`Service-Worker: script` or
  `Sec-Fetch-Dest: serviceworker`) is answered 403 and registration fails; and documents of such
  hosts that get userscripts run `navigator.serviceWorker.getRegistrations()` at document start
  (in the boot script) and unregister every registration.
* `block`: the same on every host with at least one userscript installed.
* `allow`: neither; (a) to (c) above apply.

Still exposed with the default: a worker that was already controlling a page keeps doing so for
the document load that unregisters it; hosts with only non-privileged scripts keep their workers,
which can then see those scripts' calls and values; a worker script served from the HTTP cache
without a request never reaches the proxy, but any update check does; `importScripts` inside an
already-running worker (not a registration) is not distinguishable by the proxy from the worker's
own fetches for `Sec-Fetch-Dest` purposes and is covered only by unregistering. The backend still
checks `Origin`, token, per-script grants and quotas on every call, so a stolen token stays limited
to that script on that origin for its lifetime.

### 6.2 Authority checks

Hence the server enforces everything itself: authority comes from the stored script, not from
the token; `@connect`, `@grant`, quotas and the destination policy are checked per request;
unguessable single-use bundle URLs; short token lifetime; per-profile isolation; scripts the user
has not approved never get tokens. `@grant none` scripts get no token-bearing API at all (the
descriptor still carries one, unused).

## 7. API coverage

Implemented: `GM_getValue/setValue/deleteValue/listValues`, `GM_getValues/setValues/
deleteValues`, `GM_add/removeValueChangeListener`, `GM_addStyle`, `GM_addElement`,
`GM_getResourceText/URL`, `GM_xmlhttpRequest` (text/json/blob/arraybuffer/document/stream,
timeout, abort, anonymous, cookie, user/password, overrideMimeType, binary, readystatechange/
load/error/abort/timeout/progress), `GM_download`, `GM_openInTab`, `GM_setClipboard`,
`GM_notification` (Notification API; console fallback), `GM_registerMenuCommand/
unregisterMenuCommand`, `GM_log`, `GM_getTab/saveTab/getTabs`, `GM_cookie.list/set/delete`,
`GM_info`, `unsafeWindow`, `window.onurlchange`, both `GM_*` and `GM.*` forms.
`GM_openInTab(url, {active:false})` / `loadInBackground` is best effort: a page cannot open a
background tab, so the runtime opens the tab and then refocuses the current window, which browsers
may ignore. The returned handle has `close()` and an `onclose` that is driven by polling the
window's `closed` flag (500 ms, started when a handler is assigned; also fired by `close()`). A
blocked popup yields a handle with `closed: true`. `GM_info.platform` is `{os, arch, browserName,
browserVersion}` from `navigator.userAgentData` when present, else the user agent (`os` is one of
`win`, `mac`, `linux`, `android`, `ios`, `cros`, `openbsd`, `freebsd`, `unknown`).
`@connect` accepts `google.*` and `*.google.*`: the stem followed by any ICANN public suffix
(`google.com`, `www.google.co.uk`); private suffixes such as `github.io` do not count, so
`google.github.io` is not matched. A stem allows its subdomains like a plain domain.
Partial: `upload.onprogress` (emulated), `GM_notification` (no
`highlight`), `@sandbox`/`@inject-into` (always the page world; reported as unsupported).
Unsupported (reported at install): `@run-at context-menu`, `@webRequest`/`GM_webRequest`
(rejects/throws `unsupported`), `@run-in`.

Install plans (`POST /userscripts/plan`) carry `warnings` and `high_warnings` (a subset to show
prominently). `@exclude`/`@exclude-match` rules the engine cannot compile (for example regexes with
look-around; the engine uses the linear-time `regex` crate and has no look-around) are skipped, so
the script would run where its author excluded it. The plan then has a high warning: "N exclude
rules couldn't be compiled; this script will also run on pages its author excluded: <patterns>".

Menu commands live in a registry that is a closure variable of the shared runtime script. It is
not published on `window` (earlier builds exposed `Symbol.for("adblock.userscript.menu")`): page
code can neither list nor invoke commands. The registry is handed once to the menu button, which is
inlined in the same script (`docs/SCRIPT-POLICY.md`); scripts register through `GM_registerMenuCommand`.
`data-m` (`on_demand` | `always`) on the runtime's `<script>` tag selects the button mode; without it
no button is shown.
Commands also reach the extension's popup when the document is bound to a connected extension
session (section 8.3); then the in-page button is not mounted (`data-m="ext:<mode>"`) unless the
proxy answers `{ext:false}`. After a freshly shown or re-attached badge, clicks are ignored for
300 ms (menu items keep their 400 ms guard).

## 8. Extension bridge

The Argus browser extension can connect to the proxy. While it is connected (1) the userscript menu
commands of a page are listed and triggered from the extension's popup, and the in-page button is
not mounted for pages opened in that browser, and (2) `GM_xmlhttpRequest` and `GM_cookie` of scripts
approved for it use the browser's own cookies. Without a connected extension, or for a document the
extension did not bind, everything behaves exactly as described in sections 1 to 7.

Authority never comes from the extension. The proxy decides from the *stored* script (grants,
`@connect`, `browser_cookies`, anonymous flag, method and header rules, destination policy) before
it dispatches anything; the extension can only narrow what it was asked to do (it re-checks the
host against the job's `@connect` and its own host permissions).

### 8.1 Channel

The extension's background script opens a WebSocket `GET /api/v1/ext/channel` on the web API.

* The web API accepts the upgrade only without an `Origin` header or from a `chrome-extension://`,
  `moz-extension://` or `safari-web-extension://` origin. The route is public at the HTTP layer
  (browsers cannot set headers on a WebSocket and the token must not be in the URL): the first frame,
  within 5 seconds, is `{"t":"hello","token":"abk_...","v":1}`. Anything else closes the socket:
  `4408` no hello in time, `4400` malformed hello, `4401` unknown, revoked or expired token (or
  disabled owner), `4403` token without the scope `userscripts:bridge`.
* The server answers `{"t":"welcome","sid":"<32 hex>","v":1}` and then
  `{"t":"proxy","host":<string|null>,"port":<int|null>}`. `sid` is a random 128-bit secret generated
  for this connection (every reconnect gets a new one) and shown to nobody but the extension.
  `proxy` says where the extension listener (8.2) is (`port` null: it is off; `host` null: the host
  of the Argus URL the extension was configured with). The same message is sent again when the
  setting changes.
* Text frames: ext to server `{"t":"ping"}` every 20 seconds (answered `{"t":"pong"}`; the channel is
  closed after 75 seconds of silence) and `{"t":"perms","origins":[...]}` (the extension's per-host
  permissions, sent after welcome and on every change).
* Firefox event pages are suspended: the extension reconnects from an `alarms` tick every 30 seconds.
* A token may hold at most 8 concurrent sessions (the oldest is closed with `4409`). In Chrome the
  incognito instance (manifest `incognito: "split"`) is a second client with its own session.
* Revocation is immediate: revoking a token, or disabling or deleting its owner, closes its live
  channels (`4401`) and ends the proxy connections its sessions authenticated (8.2). The channel
  also re-verifies its token every 3 pings (expiry and anything else that invalidates it end the
  channel within about a minute). When the channel closes the extension stops using the proxy.
* The proxy never waits on the extension's reader: a job whose page reads too slowly (its queue of
  32 answers fills up) is removed, the extension gets a cancel frame and the page gets an error; a
  chunk is never dropped and followed by a normal end.
* Audit: session open and close, every `perms` report and every relayed request are written to the
  audit log (`ext/session_open`, `ext/session_close`, `ext/perms`, `ext/relay`; the relay entry names
  the script, operation, method and host, never URLs, bodies or cookies); changes of the
  `browser_cookies` approval are audited as the approve and confirm calls they are, and each
  relayed request is also logged to the script's security audit.

### 8.2 Binding a document to a browser (proxy authentication)

Nothing about the client's address, and no request header, decides which browser a document
belongs to. The binding is the way enterprise forward proxies do it: **proxy authentication on a
listener of its own**.

1. **The extension listener.** `proxy.ext_port` (web UI: Settings, "Extension listener"; persisted,
   applied live, off by default, bound to `proxy.host`) is an explicit-proxy listener with the same
   switches as the explicit one (MITM, HTTP/2, WebSockets, ad blocking). It answers every request
   and every `CONNECT` that has no valid credentials with
   `407 Proxy Authentication Required`, `Proxy-Authenticate: Basic realm="argus-ext"` and closes
   the connection. The normal ports never answer `407` for this, and nothing in this section
   applies to them. The transparent listener (no proxy configuration on the client) has no
   binding at all.
2. **Credentials.** HTTP: `Proxy-Authorization: Basic base64("ext:" + sid [+ ":" + store])`. The
   listener also speaks **SOCKS5** (it sniffs the first byte, `0x05`): only username/password
   authentication (RFC 1929) is accepted (a client offering no such method is refused), the user
   name is `ext` and the password `sid[:store]`; the `CONNECT` it then asks for goes through the
   same destination policy, bypass, EV and MITM decisions as an HTTP `CONNECT` (a TLS ClientHello
   is intercepted or tunnelled, anything else is plain HTTP to that host). `sid` is the
   channel's session secret and is compared in constant time against every live session; `store`
   is optional and opaque (8.3). Credentials of an unknown, closed or revoked session are
   refused with `407` like missing ones. `Proxy-Authorization` is always removed before a request
   goes upstream (HTTP/1, HTTP/2, WebSocket upgrades, tunnels carry it only in the `CONNECT` head,
   which the proxy consumes).
3. **Binding.** The first valid credentials of a connection (the `CONNECT` head, or the first plain
   request) bind the *whole connection* to the session, and so every request the proxy decrypts
   inside the tunnel. Nothing inside a tunnel can rebind. If the session's token is restricted to
   profiles, the connection is pinned to the first of them; otherwise the usual profile resolution
   applies. A document is bound only when the session's token may serve the document's profile.
4. **Lifetime.** Every request on a bound connection re-checks that the session is live (a plain
   request, a tunnelled request, a new `CONNECT`); a connection whose session ended (channel
   closed, token revoked, user disabled or deleted) is closed within half a second, tunnels
   and upgraded WebSocket splices included. The SOCKS5 handshake (greeting, credentials and
   request) has one deadline (`performance.connection_timeout_secs`), and a destination that
   does not normalise is refused (reply 4), never dialled as written. The extension gets a new `sid` on every reconnect: its existing connections get a
   `407` and re-authenticate.
5. **The extension** (`proxy` and `webRequest` permissions, plus `webRequestAuthProvider` in
   Chrome). The popup has "Use Argus in this browser" (off by default). While it is on and the
   channel is connected and has told the extension where the listener is, Chrome has
   `proxy.settings` (`fixed_servers`, scope `regular`, the Argus host and `<local>` bypassed) and
   Firefox answers `proxy.onRequest` with the listener as a SOCKS5 proxy with per-request
   credentials (Firefox keeps one HTTP proxy-credential cache for all containers, which would
   bind every container to the first one's store, and ignores `proxyAuthorizationHeader` for
   HTTPS tunnels; so in Firefox the identity rides on the proxy connection only and nothing of it
   is in any request, which matters on hosts Argus tunnels without decrypting); off or
   disconnected, Chrome clears the setting and Firefox answers `direct`. In Chrome the `407` is
   answered by `webRequest.onAuthRequired` and only when `isProxy`, the realm is `argus-ext` and the challenger is the listener host and port
   the server announced; each request id is answered once. The host and port come from the server
   over the channel, never from a page. Nothing else (any other proxy, any other realm) is
   ever answered.

A document that is not bound (opened without the extension, through a normal port, before the
extension connected, or by a connection that did not authenticate) behaves exactly as without the
bridge: no `Server-Timing` entry, no id, no record in the proxy, the in-page button as usual.

### 8.3 Documents, `mdoc`, menus, cookie stores

Every HTML document that gets userscripts **and is bound to a live session** has a random 128-bit
public id `mdoc`, separate from the secret bundle id. It is sent as
`Server-Timing: argus;desc="<mdoc>"` (appended to the site's own timing entries), put in each
script's descriptor (`d.mdoc`), and the runtime tag becomes `data-m="ext:<mode>"` (`mode` is the
profile's menu button setting, `off` when it is off). An unbound document gets none of this and
cannot crowd out a bound one. Records are capped at 256 per session; beyond it that session's own
oldest is evicted, never another session's. A page can read the `Server-Timing` value, but the id
alone grants nothing:

* listing and triggering need a bridge token **and** the caller's own live session, and the
  document must be bound to that session and to the caller's cookie store (a document opened by
  another browser, another container or a browser without the extension is refused with `403`);
* the runtime's calls need a script's capability token, and the document must belong to the token's
  profile and origin, list that script, **and have been served to the very connection the call
  arrives on** (same extension session, same cookie store). An `mdoc` and a script token are not
  secrets (the page and the browser's own devtools see them), so a call from another browser, another
  container or an unauthenticated connection that presents them is refused (`menu/sync`,
  `menu/wait`) or served by the script's own jar (relays), never relayed.

**Cookie stores (Firefox containers, private windows).** The extension's credentials carry a store
token, `ext:<sid>:<token>`, for every store except the default one (Chrome has a single store per
extension instance and sends none). The token is an opaque 12-character id the extension generated
for this session and maps back to the real `cookieStoreId` (the proxy never sees `firefox-container-3`
or the like); a new session gets new tokens. A connection and every document on it is bound to
(session, store). The popup names the store of its tab in `X-Argus-Store: <token>` on `GET /ext/menu`
and `POST /ext/menu/trigger`; a document of another store is `403`, exactly like a document of
another browser. Relay jobs (8.4) carry the store token of their document.

Runtime endpoints (`/__adblock__/gm/v1/`, same authentication and fetch metadata rules as section 4):

| route | request | answer |
|---|---|---|
| `menu/sync` | `{mdoc, cmds:[{id,name,accessKey,title,autoClose}]}` (needs `@grant GM_registerMenuCommand`; at most 64 commands, texts clipped to 200 characters) | `{ext:bool}`: a live session serves the document |
| `menu/wait` | `{mdoc}` (long poll, 25 s) | `{ext:true,fire:[{script,cmd}]}` (empty after the poll length or when superseded by a newer poll of the same script) or `{ext:false}` |

The runtime syncs (debounced) after `GM_registerMenuCommand`/`GM_unregisterMenuCommand`, builds the
body by hand from its own closure (a page cannot add or see entries), polls `menu/wait` only while
the script has commands, and runs a fired command from its closure. On `{ext:false}` (or after
three failed polls) it mounts the in-page button as usual, with the mode from `data-m`.

Web API (scope `userscripts:bridge`, header `X-Argus-Session: <sid>` naming a live session of the
calling token; cookie logins cannot use them):

* `GET /ext/menu?mdoc=` returns `{commands:[{script,script_name,cmd,name,access_key,title,auto_close}],
  grants:[{script,script_name,host,patterns}]}`. `grants` lists, for scripts approved for browser
  logins, the `@connect` hosts the extension holds no host permission for (`*://*.host/*` patterns,
  never `@connect *`, TLD wildcards or public suffixes); the popup offers "Grant" for each.
* `POST /ext/menu/trigger` with `{mdoc,script,cmd}` queues the command (it must have been synced)
  and returns `{delivered}`: true when the page's poll was waiting. A queued command expires after
  10 seconds.

The popup reads the `mdoc` from the active tab with `scripting.executeScript` (isolated world, top
frame, `performance.getEntriesByType('navigation')[0].serverTiming`).

### 8.4 Credentialed requests and cookies

A script has the approval flag `browser_cookies` (default off). It can be granted only while the
script is being reviewed: on `POST /userscripts/plan/{id}/confirm`, on `POST /userscripts/{id}/approve`
of an imported script awaiting approval (`409 not_pending_approval` otherwise), and with an update
approval. It needs a network or cookie grant (`GM_xmlhttpRequest`, `GM_cookie`) and is never taken
from a file without `approve`.

A `xhr` (not `download`) or `cookie` call goes to the browser only when all of these hold; otherwise
the script's own jar is used (and the script's page in the dashboard shows "browser logins
unavailable" until a call succeeds through the browser):

1. the script's own checks pass: grant, `@connect`, method and header rules, destination policy;
2. the call is not `anonymous`, the script has `browser_cookies`, and `redirect` is not `manual`
   (a browser fetch cannot expose the redirect response itself);
3. the call names an `mdoc` that belongs to the token's profile and origin, lists the script and
   was served to the connection the call arrives on (see 8.3);
4. that document is bound to a session which is still live;
5. the extension listener is decrypting (global MITM on and the listener's own MITM switch on),
   the target is not Argus itself (its console, the panel and dashboard hosts), and the target is
   not loopback, private or link-local (IP literals, `localhost`, `*.local`), and Argus
   decrypts it (not bypassed or passthrough, the bypass fail-safe is not active, the Extended
   Validation setting does not tunnel it): the relay's per-hop check can only run on traffic the
   proxy decrypts, and a relay token must never travel through a tunnel to a third party;
6. that session reported a host permission covering the target host. Only per-host permissions
   count (`*://host/*`, `*://*.host/*` as the popup grants them): `<all_urls>`, `*://*/*`,
   `https://*/*` and public-suffix patterns never give relay authority, and the extension reports
   only per-host grants (it remembers the ones granted through the popup, because Firefox lists
   just `<all_urls>` for its manifest permission).

The job goes to that session only. Binary frames in both directions are `u8 type | u32 job | payload`
(big endian), reusing the frame types of section 5.1:

| dir | type | payload |
|---|---|---|
| proxy to ext | 0 job | JSON `{op:"xhr"|"cookie", script, relay, store?, connect:{page,list,all}, hasBody, ...}`; `xhr`: `method,url,headers,redirect,timeout`; `cookie`: `cookie:{op:"list"|"set"|"delete",url,...}` |
| proxy to ext | 2 / 3 | request body chunk / end of request body |
| proxy to ext | 5 | cancel (the page aborted, or the proxy gave up) |
| ext to proxy | 1 | head JSON `{status,statusText,headers,finalUrl,redirected}`; for `cookie`: `{result}` |
| ext to proxy | 2 / 3 | response body chunk / end |
| ext to proxy | 4 | error `{kind,code,message}` |

The proxy pipes the answer to the page as a section 5.1 stream (removing `Set-Cookie`), with the
256 MiB cap and the call's deadline. Script-set `Cookie`, `Origin` and `Host` headers are dropped on
this path (the browser supplies its own). A session can only answer jobs it was given.

`xhr` is a `fetch` with the header `X-Argus-Relay: <relay>`, made by the extension and therefore
through the extension listener (8.2) like any request of that browser. The proxy checks every hop
(the browser follows redirects itself): the relay token must belong to a live job **and the hop
must arrive on a connection that authenticated as that job's session** (in the default store); the
session must still hold a permission for the hop's host, the host must not be local, private or
bypassed, and the URL must pass the script's stored `@connect`; the request is then not filtered,
and the header is removed before it goes upstream. A refused hop gets `403` with the note
`relayed request refused`, which the extension turns into an error frame.

Redirects. `fetch(..., {redirect: 'manual'})` returns an opaque response whose `Location` the
extension cannot read, so the extension cannot follow hops itself; the checks run in the proxy
instead, by induction. The first hop is approved by the routing rules above before anything is
dispatched. Every relayed response is decrypted by Argus, so when one is a `3xx` with a `Location`
the proxy resolves it against the request URL and runs the full hop check on the target *before
the browser can follow it*: the job is live and the hop arrives on its session's connection, the
session holds a permission for the host, the host is public (not loopback, private or
link-local) and is not bypassed, the bypass fail-safe is not active, the script's `@connect`
allows it, and Argus will decrypt it (with the Extended Validation setting on, a probe must have
shown the host is not EV; an EV or unprobeable host is tunnelled, so it fails). A response with no
`Location` is passed; one with more than one `Location`, an empty one, or one that does not parse
after a lossy UTF-8 decode (what a browser does) is refused like a failed hop. A hop that fails
is replaced by `502` with `x-adblock-note: relayed redirect refused`, without `Location` or
`Set-Cookie`, which the extension turns into an error frame. Every hop the browser follows was
therefore approved before it was requested, whatever the chain looks like; there is no hop the
proxy cannot see. `redirect: "manual"` calls are never relayed (they use the jar, which returns the
real 3xx); `error` is the browser's own `redirect: 'error'`. The extension also re-checks the
*final* URL against the job's `@connect`, its host permission and the local-target rule before any
byte of the answer is passed on, and refuses loopback and private targets for the first URL.

**Cookie stores.** A background `fetch` always uses the extension's default store. For a job whose
document belongs to another store (`store` in the job, a Firefox container or private window) the
extension (1) fetches with `credentials: 'omit'` and a per-job marker header `X-Argus-Job`; (2) in a
blocking `webRequest.onBeforeSendHeaders` listener, for every hop carrying a registered marker,
replaces `Cookie` with all cookies of that store for the hop's URL (`cookies.getAll({url, storeId})`,
HttpOnly ones included, because the browser would send them) and removes the marker; (3) in a
blocking `webRequest.onHeadersReceived` listener removes `Set-Cookie` from the hop's response and
writes each one to that store (`cookies.set({storeId, ...})`: Domain, Path, Secure, HttpOnly,
SameSite, Expires and Max-Age honoured, an expired or `Max-Age<=0` cookie deletes). The default
store is never read or written for such a job; a marker nobody registered gets no cookies and is
stripped. `GM_cookie` for a store reads and writes with that `storeId`. Chrome has one store per
extension instance: its incognito windows are served by the second (`split`) instance with its own
session, cookie jar and connection, so no cross-store case arises. A browser without blocking
`webRequest` answers a store job with an error (`store`), never with the default store's cookies.

`cookie` operations use the job's store. **HttpOnly cookies are never exposed to scripts**:
the extension filters them out of lists and refuses to set, overwrite or delete one, and the proxy
removes any `http_only` entry from results and refuses `http_only: true` writes itself.

### 8.5 Limits

* A document opened before the extension connected, through a normal port, or before the browser
  switched to the extension listener is not bound: it keeps its in-page button and its scripts use
  the jar until reloaded. The transparent listener never binds.
* `@connect *` is not offered for host grants (no blanket logins); a request to a host the
  extension has no permission for falls back to the jar.
* The extension listener is the single place that binds. A browser that does not use it (toggle
  off, a Firefox container the user switched off) is simply unbound.
* Incognito in Chrome needs the extension to be allowed in incognito windows; without it those
  windows are unbound (the proxy setting applies to regular windows only) and use the jar.

### 6.1.1 Service-worker guard (all filtered sites)

Independently of userscripts, `adblock.guard_service_workers` (default on; web UI: Settings, "Neutralise service workers"; `guard_service_workers` in the config API) keeps service workers from serving documents without Argus's injection. On every filtered host a service-worker script fetch is answered with a no-op worker that takes over, handles no fetches and unregisters itself, so the registration "succeeds" (apps do not error) but pages always load through the proxy; filtered HTML documents also run `getRegistrations()` and unregister existing workers. Full-bypass hosts are never touched. Turning it off restores offline apps and push notifications (their pages are then not filtered while a worker serves them from cache).

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
   per script and inject several bundles if isolation matters more than size (the 40 KB runtime
   is then repeated; keep the file cacheable per script).
6. The runtime removes its own `<script>` element from the DOM at startup and again removes
   any element it injected (`@unwrap`) after execution.

Bundle layout: `(<gm.js>)({base, top, handler, handlerVersion}, [{d: descriptor, f: fn}, ...], window);`
Descriptor `d`: `id, name, runAt, grants (canonical, lowercase), params, token, meta, metaStr,
unwrap, values?, resources?, code?`. `f` is `function(GM_info, GM, <granted GM_*>, unsafeWindow)`
wrapping `@require`s + source in one scope (`this === window`; async function with
`@top-level-await`). `@grant none` gives only `unsafeWindow` (=== `window`). `GM_info`/`GM`
exist whenever any real grant is present. `@unwrap` scripts get no GM API and are injected as a
nonce'd inline `<script>`.

### 2.1 As implemented in `proxy-core` (`src/gm.rs`)

* **One file per script**, as 2.5 suggests: `/__adblock__/us/<doc>.<n>.js`, `n` in injection order
  (run-at group, then install order). The shared 40 KB runtime is repeated in each file (a syntax
  error in one script must not break another; there is no safe way to share one runtime instance
  between separate `<script>` files without a global). Consequence: with several scripts on one
  page only the first runtime instance registers the menu-command registry.
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
* Not implemented: attaching the browser's own cookies for `anonymous: false` (the proxy cannot
  see them; only the GM jar is used), and a shared, cacheable runtime URL.

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
`redirect != follow`. `use_cookie_jar` (= not `anonymous`) selects the profile's GM cookie jar
for send and `Set-Cookie`; the browser's own cookies for third-party sites are not available to
a proxy.

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
URLs, except `resource?t=`); GM objects handed to scripts are frozen; the injected `<script>`
element is removed after it runs.

Still possible, so **backend checks must never rely on page-side secrecy**:
* a page that runs *before* us in the same frame (inline script ahead of `<head>`'s first
  child, a service worker, a browser extension, a pre-existing same-origin frame) can poison
  built-ins before they are captured; we cannot detect it;
* it can tamper with prototypes of objects created later (script-visible results such as
  `Promise.prototype.then` on promises we return, `Array.prototype` seen by user code),
  and observe/modify anything user scripts put in the DOM;
* it can read the bundle URL if it is guessable or reusable, and thus steal tokens; a stolen
  token is usable only from that origin (the `Origin` header is checked), for that script, until
  expiry, with that script's server-side grants;
* it can call the endpoints itself with a stolen token, or replace `window.fetch`.

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
Partial: `upload.onprogress` (emulated), `GM_openInTab` options, `GM_notification` (no
`highlight`), `@sandbox`/`@inject-into` (always the page world; reported as unsupported).
Unsupported (reported at install): `@run-at context-menu`, `@webRequest`/`GM_webRequest`
(rejects/throws `unsupported`), `@run-in`.

Menu commands are exposed to an in-page panel through `window[Symbol.for("adblock.userscript.menu")]`:
a frozen, non-enumerable object `{commands(): [{script, scriptName, id, caption, accessKey}],
invoke(scriptId, id): boolean, subscribe(callback)}`. The panel task consumes it.

# Script policy (NoScript-style)

Per-site control over what a page may run and load, enforced by a proxy. The proxy cannot see script
execution, so it enforces in three layers, strongest first:

1. **A generated `Content-Security-Policy`**, added to each HTML document as an *extra* header. The browser
   enforces it. Browsers intersect multiple policies, so the added header can only restrict; the site's own
   policy is never edited.
2. **HTML rewriting** where CSP cannot express the intent: reveal `<noscript>`, optionally strip blocked
   `<script>` elements so they are never downloaded, optionally drop `<meta http-equiv=refresh>`, drop
   denied `ping` attributes.
3. **Early request blocking** ("network hints"): denied third-party subresources are refused at the proxy,
   but only when the proxy can tell which page made the request.

The logic lives in the pure crate `crates/script-policy` (no I/O, no async). Storage is redb (feature
`store`), the API is `/api/v1/policy/...` (scopes `policy:read`, `policy:write`), the UI page is "Script
policy". Nothing is enforced until the master switch (`settings.enabled`) is turned on.

## Model

**Capabilities** (kebab-case names). *Source-keyed* ones depend on where the thing comes from; *page-level*
ones are a property of the document.

| Kind | Capabilities |
|---|---|
| Source-keyed | `script`, `object`, `media`, `frame`, `font`, `connect`, `ping`, `worker`, `style`, `image`, `form-action` |
| Page-level | `inline-script`, `eval`, `wasm`, `inline-style`, `noscript`, and Permissions-Policy features `camera`, `microphone`, `geolocation`, `payment`, `usb`, `display-capture` |

A **profile** is three capability sets: page-level, first-party sources, third-party sources. First party means
the same registrable domain (public suffix list, including private suffixes such as `github.io`); IPs,
`localhost`, single-label hosts and bare public suffixes are their own site.

**Presets**

| Preset | Meaning |
|---|---|
| `default` | The configurable `default_profile`. Ships as: first-party everything; third-party scripts, plugins (`object`), workers and pings blocked; page-level capabilities allowed. |
| `trusted` | Everything allowed. No CSP is added. |
| `untrusted` | No `script`, `inline-script`, `eval`, `wasm`, `object`, `worker`, `connect`, `ping`, no sensitive browser features. Images, styles, fonts, media and form posts still work; frames only first party. `<noscript>` is revealed. |
| `custom` | An explicit profile. |

**Why this default.** It is NoScript's idea (third-party code is the tracking and malware vector) without its
breakage on the first-party site: a site's own inline scripts, `eval` and API calls keep working, so most
pages still render. Third-party `connect` stays allowed because many sites call APIs on a sibling domain; the
user tightens per site. Third-party scripts block is the one change that visibly breaks CDN-hosted pages, which is
why the feature is opt-in (master switch off) and why source rules ("allow `cdn.example.net` on `example.com`")
are first class. The shipped global default for unlisted sites is `default`.

**Scopes.** `*` (global), `site:example.com` (registrable domain and all subdomains), `host:www.example.com`
(exactly that host), `https://www.example.com` (host and scheme). A bare name parses as `site:`; a non-registrable
name is rejected with a hint. IDN is stored as punycode.

**Rules.**
- *Site rule*: pages in a scope use a preset. One per scope.
- *Source rule*: on pages in `page`, sources in `source` are allowed or denied some source-keyed capabilities
  (the uMatrix-style matrix). `page` may be `*`; `source` may be `*`.
- *Temporary grant*: a site preset or a source allow with an expiry and/or "until restart". `persist` keeps a
  timed grant across restarts; until-restart grants are memory only.

**Precedence.** For a source rule the rank is `(page specificity, source specificity, temporary, deny)`,
compared in that order, specificity being global 0, site 1, host 2, host+scheme 3. The highest rank wins:
more specific page scope first, then more specific source scope, a temporary grant beats a permanent rule of the
same specificity, deny beats allow on a tie. No matching rule means the profile decides (first or third party).
The profile comes from the most specific matching site rule (a temporary site grant beats a permanent rule of the
same scope; a more specific permanent rule beats a less specific temporary grant), else the global preset.

## API in the process (`script-policy`)

`RuleSet` (editable) compiles to `CompiledPolicy` (immutable, `Send + Sync`, one per profile, share in an
`Arc`). Per HTML document call `compiled.decide(scheme, host, port) -> PagePolicy` (a few hash probes and a
public suffix walk, no allocation; the host must be normalised lowercase punycode). Cache per document with
`page.cache_key() = (generation, scheme, host)`. A policy built with temporary grants is valid until
`valid_until()`; `PolicyStore::snapshot` rebuilds it (and bumps the generation) on expiry or edit.

## Capability to CSP mapping

Header is added as a separate `Content-Security-Policy`. "Unrestricted" means the directive is omitted.
`'self'` plus `example.com *.example.com` is what "first party" expands to (the page's registrable domain).

| Capability state | Directive |
|---|---|
| `script` restricted (or `inline-script` / `eval` denied) | `script-src <sources> [data: blob: when sources unrestricted] ['unsafe-inline' if inline-script] ['unsafe-eval' if eval, else 'wasm-unsafe-eval' if wasm]`, plus `'nonce-N'` if inline is blocked and a proxy nonce is given |
| `inline-script` denied | no `'unsafe-inline'`; also `script-src-attr 'none'` (event-handler attributes) |
| `worker` restricted, or `script` restricted while `worker` is not | `worker-src <sources> blob:` (explicit, because `worker-src` otherwise falls back to `script-src`) |
| `style` restricted or `inline-style` denied | `style-src <sources> ['unsafe-inline' if inline-style]`, nonce if inline blocked |
| `image` | `img-src <sources> data: blob:` |
| `font` | `font-src <sources> data:` |
| `media` | `media-src <sources> blob: data:` |
| `object` | `object-src <sources>` (`'none'` when nothing is allowed) |
| `frame` | `frame-src <sources>` |
| `connect` | `connect-src <sources> data: blob:` |
| `form-action` | `form-action <sources>` |
| camera, microphone, geolocation, payment, usb, display-capture denied | separate header `Permissions-Policy: camera=(), ...` |

`<sources>` = surviving allow candidates: first-party tokens if first party is allowed, third-party allow rules as
host sources (`cdn.example.net`, `*.example.net` for a site scope, `https://host` for host+scheme), nothing
(`'none'`) if no source survives. `data:`/`blob:` ride along only when some source is allowed. Third party
allowed means unrestricted (omitted).

**Proxy resources** are passed as `ProxyInject { nonce, path }`. When a directive is restricted: the nonce is
added only where inline is blocked (a nonce makes browsers ignore `'unsafe-inline'`, so it is never added when
inline is allowed), and the `https://page-host[:port]/__adblock__/` path source is added to `script-src`,
`style-src` and `connect-src` only when `'self'` is not already allowed there. Directives that are
unrestricted need nothing.

Not emitted on purpose: `script-src-elem` (it falls back to `script-src`; emitting both only adds a place for
them to disagree), `child-src` (legacy fallback; `frame-src` and `worker-src` are explicit), `default-src`,
`base-uri`, `report-uri`.

## What CSP cannot express

Each is reported in `notes` by `explain` where it applies to the page.

- **Deny carve-outs.** CSP is an allow-list. "Allow third parties except `ads.net`" and "deny `ads.example.com`
  while `*.example.com` is allowed" cannot be written; the deny holds only where the proxy blocks early (see
  below) and is otherwise not enforced. The reverse, first party denied while third party is allowed, is the same.
- **Per-URL allow.** Sources are hosts (and optionally a path); a rule per script URL is not supported. Port
  numbers are not part of a rule; hosts match the default port (`'self'` covers the page's own port).
- **`ping` and `sendBeacon`.** Hyperlink auditing and beacons are governed by `connect-src`, so `ping` cannot be
  denied separately from `connect`. `ping` is enforced by stripping `ping` attributes (HTML action) and by
  blocking requests carrying `Ping-To` (network hint). A script's `sendBeacon` is only stopped if `connect` is.
- **`wasm` denied with `eval` allowed.** `'unsafe-eval'` also permits WebAssembly compilation.
- **Inline blocks vs handlers.** One capability (`inline-script`) covers both. Allowing blocks but not handlers,
  or the reverse, is not offered; `'unsafe-hashes'` is not generated.
- **`javascript:` URLs and `blob:`/`data:` scripts.** Governed by `script-src` only through `'unsafe-inline'`
  (for `javascript:`) and by the scheme list (for `blob:`/`data:`, allowed only when scripts are unrestricted);
  there is no per-origin control. Same-origin `blob:` workers are always allowed with `worker-src` sources.
- **Service workers already installed, and cached pages.** A service worker can serve a page or fetch without
  the proxy seeing it; a response served from the browser or service-worker cache keeps the policy it was stored
  with. Policy changes apply to the next network fetch of the document.
- **Pages the proxy does not rewrite.** Only HTML responses get the header. Frames get their own policy when their
  document is fetched. Non-HTML scripts and workers are not given headers.
- **`WebGL`, canvas, fonts rendering, WebRTC, clipboard.** No CSP directive or Permissions-Policy feature
  corresponds to WebGL, so it is not a capability. WebRTC and clipboard are not modelled.
- **`'self'` on old Safari.** `'self'` may not cover `ws:`/`wss:` there; first-party `connect` uses the host
  tokens as well.
- **Sites using `'strict-dynamic'` or nonces.** Our policy intersects with theirs, so a script our `script-src` does not allow is blocked even if the site's policy would load it. That is the restriction working, not a conflict.
- **Redirects** are checked per hop by the browser for `script-src`; `form-action` redirect handling varies.
- **`<noscript>` in `<head>` containing disallowed elements** is unwrapped as-is.

## HTML actions

`page.html_actions()` returns rules as data for the lol_html stage: `selector`, `op`, and a condition.

| Rule | Condition |
|---|---|
| `noscript` unwrap (keep children) | `noscript` capability allowed, `script` denied for the page's own host, and `inline-script` denied |
| `meta[http-equiv="refresh" i]` remove | setting `strip_meta_refresh` and scripts blocked as above |
| `a[ping], area[ping]` remove attribute `ping` | `ping` can be denied; applied per URL with `allows_url(Ping, url)` |
| `script[src]` remove | strip mode (`strip_blocked_scripts`) and the URL is denied (`allows_url(Script, src)`) |
| `link[rel~=modulepreload][href], link[rel=preload][as=script][href]` remove | strip mode and the URL is denied |
| executable inline `<script>` blocks (selector `INLINE_EXECUTABLE_SCRIPT`) remove | strip mode and `inline-script` denied |

CSP-only mode (default) leaves blocked scripts for the browser to refuse; strip mode saves the download.
The stage must inject the proxy's own elements after (or exempt) these rules. `allows_url` resolves absolute,
protocol-relative and relative URLs (relative is first party); `data:`, `blob:` and `javascript:` are not judged.

## Network hints

`page.network_hints()` lists capabilities worth checking (empty means skip the page); `page.check_request(hints,
&SubRequest)` returns `Allow` or `Block { cap }`. By default `script`, `worker`, `style`, `image`, `font`, `media`,
`object`, `frame` and `ping` are enforceable; `connect` is opt-in (`Sec-Fetch-Dest: empty` also covers
prefetch and service-worker traffic).

**When the proxy knows the page** (`PageContext::from_headers`): the page is the initiating document, taken from
`Referer` (full URL or origin), else `Origin`, else the target itself when `Sec-Fetch-Site: same-origin`. The
request kind comes from `Sec-Fetch-Dest`; a `Ping-To` header marks hyperlink auditing.

**When it does not (fall back to CSP only):**
- no `Referer` and no `Origin` (Referrer-Policy `no-referrer`, or `same-origin` which strips exactly the
  cross-origin requests that matter, or an old client without `Sec-Fetch-*`);
- `Origin: null` (sandboxed or `data:` frames, some redirects);
- `Sec-Fetch-Site: none` (user navigation, not a subresource);
- a `Referer` that is not an http(s) URL.

It can also be wrong: requests made by a worker carry the worker script's URL as referrer, and a page can set
`referrerpolicy` to hide itself. A wrong context can cause a wrong block (one page's rules applied to another page's request), so hints are an optimisation and a carve-out enforcer; CSP is the boundary. Never apply hints to `/__adblock__/` requests or to top-level navigations.

## Reports

`ReportAggregator` (bounded: 256 pages, 64 items per page, evicting the least hit item) merges proxy-side blocks
(`record`, `Via::Network`) and browser `securitypolicyviolation` events (`record_violation`, `Via::Csp`). Each
item is (capability, source host) with count, first/last seen, a sample URL without query, and a suggested one-click
allow (a host-level source rule; none for inline/eval/data/blob). Report-only violations are ignored.
Violations from the site's own policy cannot be told apart by the event alone: the wiring should forward only those
whose `originalPolicy` equals the header the proxy added. `GET /policy/reports` reads it; it is empty until the
proxy records into `PolicyStore::record_block` / `record_violation`.

## Storage, API, import/export

Rules are stored per profile (`DEFAULT_PROFILE = "default"` until profiles land) in redb tables
`policy_site_rules`, `policy_source_rules`, `policy_temp`, `policy_meta`, one immediate transaction per edit,
with a generation counter that bumps on every change (and on grant expiry in memory). Reads never wait for
writes. Writes are audited by the existing audit middleware.

Export is a JSON document (`version`, `settings`, `site_rules`, `source_rules`); temporary grants are not
exported. Import replaces or merges. Importing NoScript's exported JSON is not implemented: its format is an
internal, undocumented structure that changes between versions, so a guessed parser would silently misread
trust lists.

Routes (all under `/api/v1/policy`): `settings` (GET/PUT), `site-rules` (GET/POST), `site-rules/{id}`
(PUT/DELETE), `source-rules` (GET/POST), `source-rules/{id}` (PUT/DELETE), `temp` (GET/POST/DELETE all),
`temp/{id}` (DELETE), `explain` (GET `?url=`), `preview` (POST a proposed change, returns before/after CSP),
`export` (GET), `import` (POST), `reports` (GET).

## What the proxy wiring must provide

- A shared `Arc<PolicyStore>` (or its `snapshot("default")`), refreshed per document; call `decide` once per HTML
  response and cache the rendered header and `HtmlActions` by `cache_key()`.
- The proxy's nonce and resource path for `ProxyInject`, per document.
- The final request URL (scheme, normalised host, port) of each HTML response.
- Per subresource request: `Sec-Fetch-Dest`, `Sec-Fetch-Site`, `Referer`, `Origin`, `Ping-To`, and the request
  target; on a block, record `PolicyStore::record_block` and return the typed block response.
- Forwarding of `securitypolicyviolation` events from the in-page code to `record_violation`.
- The lol_html stage applying `HtmlActions` (selectors are lol_html syntax; `i` flags need lol_html support).

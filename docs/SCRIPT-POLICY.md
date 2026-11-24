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
whose `originalPolicy` equals the header the proxy added (see below). `GET /policy/reports` reads it, per profile.

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

## How the proxy wires it

`crates/proxy-core/src/scriptctl.rs` owns it; the pure crate stays free of I/O.

- **Snapshot.** Each `Profile` carries `Option<Arc<ScriptControl>>`: a lock-free current
  `CompiledPolicy`, rebuilt on the writer's thread after every edit (the store's change hook) and by a
  task that sleeps until `valid_until()` (temporary grants), never by polling. With the master switch
  off every entry point is one relaxed atomic load and nothing else (asserted by tests: the `decide`
  counter stays at zero).
- **Documents.** One `decide` per HTML response, cached per `(generation, scheme, host, port)` in a
  bounded cache. The CSP text is cached with markers for the per-document nonce and report token. It
  is added as a **separate** `Content-Security-Policy` header, after the extended-rule header edits (a
  `$removeheader` rule cannot strip it), never merged into the site's own. `Permissions-Policy` is
  merged with the site's own header by the restrictive merge of the extended rules (never widening).
  `no-transform` pages still get the headers (header-only work). The proxy's own resources stay
  working under the generated policy by construction: its tags carry the per-document nonce, and
  `ProxyInject` adds the nonce and the `/__adblock__/` path where `'self'` is not already allowed.
- **Ports.** Rules carry no port, so the proxy widens every host source to any port
  (`cdn.example.net:*`); CSP would otherwise match the default port only.
- **HTML actions** run in the same streaming `lol_html` stage as the rest (bounded memory):
  `<noscript>` unwrapping when scripts are blocked, optional strip mode (blocked `<script src>`,
  `preload as=script` and `modulepreload` for blocked sources, executable inline blocks when inline is
  denied), meta refresh and `ping` as in the table above. The proxy's own elements are inserted by
  the stage itself and are never subject to these rules.
- **Network hints** run on the request path after the ad-block verdict: `sec-fetch-dest` selects the
  capability, `PageContext::from_headers` the page; unknown context means no decision. Denied
  requests get the typed block response with `x-adblock: policy`, and are recorded with
  `PolicyStore::record_block`. No allocation on the allow path.
- **Reports** are per profile. Browser violations arrive through the CSP's own `report-uri
  /__adblock__/pv?d=<token>` (no script in the page is involved, and it can only ever carry
  violations of *our* header). `POST /__adblock__/pv` accepts a report only if the per-document token
  is ours for that host, the report names that host, and its `original-policy` equals the header we
  generated (nonce and token normalised). The site's own policy is acknowledged (204) and dropped.
  Limits: 8 KiB, 64 reports per document, `application/csp-report`/`json`/`reports+json`, not
  `cross-site`.
- **Per-site ad blocking off** is stored as custom rules: `@@$domain=example.com` (requests) plus the
  sentinel `||adblock.invalid^` that `SharedEngine::site_off` probes to leave cosmetics, scriptlets and
  extended rules out of that site's documents. The API edits the same lines
  (`/rules/site-exceptions`).

### Userscripts and script policy

Userscript managers run their scripts regardless of page restrictions (a NoScript-restricted page
still runs Tampermonkey); this proxy does the same. Our bundles and the shared runtime are covered by
the proxy nonce and path, so they run under `Untrusted`, and their GM requests are covered by the
`/__adblock__/` connect allowance. What the policy still governs is whatever a script *creates*: an
inline event handler, a `<script>` it injects without our nonce, `eval` or `new Function` it calls.
Those are page-world operations and obey the page policy. `@unwrap` scripts (nonce'd inline code) run.

## The in-page panel

A proxy has no toolbar button, so the control surface is a hotkey, **Alt+Shift+A** by default (not a
default shortcut of Chrome, Firefox or Edge on any platform; Alt alone or Ctrl+Shift+A would collide
with menus, the add-ons manager or tab search). It is configurable (`PUT /policy/panel`), per profile,
off by default, and `script_control.panel_enabled = false` removes it everywhere. Only `boot.js`
carries a key listener (about 290 bytes); the panel script (`/__adblock__/panel.<hash>.js`,
immutable) is fetched on the first keypress. Nothing is visible before that. Only trusted
(`isTrusted`) key events open it.

The panel renders in a closed Shadow DOM under `all: initial`, at the top z-index, with focus trap,
`Esc`, ARIA roles, `prefers-color-scheme` colours and a phone-width layout, with no `innerHTML`, no
inline handlers and no `eval` (so it works under strict CSP and Trusted Types). It shows the site's
preset, the sources blocked on the page by registrable domain with a toggle per capability, a TTL
choice for temporary allows, "allow all temporarily", "revoke temporary permissions", the count of
blocked requests, per-site ad blocking, the userscripts matching the page
and a "reload to apply" prompt when the settings change.

### Menu button for userscript commands

`GM_registerMenuCommand` entries are reachable without the panel through a small corner badge. The
per-profile setting `menu_button` (`PUT /policy/panel`; dashboard: Policy, "Userscript menu button")
has three values: `off`, `on_demand` (default: the badge exists only while at least one script on
the page has a registered command) and `always` (on every page where a userscript runs, with "No
commands registered." when empty). It does not depend on `panel.enabled` or on
`script_control.panel_enabled`, and it is never emitted on a page without userscripts, in a
`sandbox`ed document without `allow-scripts`, or when script injection is off.

The button's code is part of the shared runtime script (`data-m` on its tag carries the mode), so it
runs at document start with every command already visible and follows later `register`/`unregister`
through the registry's `subscribe`. A history change (`popstate`, `hashchange`, `pageshow`), a
replaced root, or the page removing the host re-attaches the badge (observing `documentElement`
and the document, at most about 20 times a second). `always` is skipped in frames (`on_demand`
still applies there). The UI is in a closed Shadow DOM under `all: initial`, with no `innerHTML`,
no inline handlers and no network.

**The command registry is not reachable from page code.** It used to be published as a frozen object
under `Symbol.for("adblock.userscript.menu")`, so a page could list captions and invoke commands.
It is now a closure variable of the runtime script and is handed only to the menu button. Scripts
register through their own `GM_registerMenuCommand`. Consequently the in-page panel no longer lists
menu commands: use the badge (`menu_button` other than `off`).

**Clickjacking.** The page can style its own DOM, including our host element, so: the host carries
inline `!important` styles (fixed position, opacity 1, no transform/filter/clip-path, pointer events,
visibility), re-asserted before each click; the badge and the open menu are rendered in the top layer
(`popover="manual"`, falling back to a high z-index); before acting, the click handler checks the
host's and the root's computed style (opacity, transform, filter, visibility, display, clip-path,
pointer-events) and the badge's size and anchor, and ignores the click if anything is off; menu items
ignore clicks in the first 400 ms after the menu opens (a page cannot swap the menu under a click);
and only trusted clicks count. A page can still cover the badge with its own later top-layer element
(a dialog); a click then lands on the page's element, not on ours.

### Authority: why the panel cannot change anything

The panel runs in the page's JavaScript world. A hostile page can synthesise keys (untrusted events
are ignored, but it can load the same script), find our element (a closed root has no
`shadowRoot`, yet the page can hook `attachShadow` before us), and call any endpoint the panel calls.
So **nothing the page's world can do authorises a change**:

1. The panel is read-only. A change is a *proposal* encoded in a link to the reserved host
   (`https://adblock.invalid/confirm?p=…`, `rel=noopener`).
2. That host is answered by the proxy alone and is a top-level page the site cannot script: no
   JavaScript at all, `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy:
   same-origin`, and a request with a `Sec-Fetch-Dest` other than `document` is refused (framing and
   `fetch` get 403). The user reads the changes in plain words before anything happens.
3. `POST /apply` needs a same-origin, user-activated form post (`Sec-Fetch-Site: same-origin`,
   `Sec-Fetch-User: ?1`, `Origin` equal to the reserved origin), an HMAC nonce bound to this profile
   and exactly this proposal (ten minutes), and, by default, the profile's PIN, with a lockout after 5
   wrong tries (30 s doubling to 15 min). Every operation is validated again server-side.
4. `panel.auth` is `pin` (default), `session` (the panel never writes, it links to the dashboard,
   where the logged-in session decides) or `none` (a click on the confirmation page; trusted LAN
   only). With `pin` and no PIN set, changes are refused until one is set in the dashboard.

**Why not an in-page cross-origin iframe?** It would keep the interactive UI out of the page's reach,
but the page controls the iframe's element and its ancestors (opacity, overlays, `pointer-events`), so
a click could be tricked (clickjacking); the site's `frame-src` and our own policy would also have to
allow it, and Intersection Observer v2 visibility checks exist in Chromium only. A top-level page
cannot be overlaid by the site at all.

**Reserved host.** `adblock.invalid` (`script_control.panel_host`; it must end in `.invalid`, which
no real site can claim and which never resolves on the internet). *Explicit proxy:* the browser sends
`CONNECT adblock.invalid:443` (or an absolute-form HTTP request) to the proxy, which intercepts it
like any host: a certificate from the proxy CA, then answered locally. It is never forwarded
upstream, never filtered or rewritten, in both modes (checked in tests). *Transparent mode:* the name
resolves only if the client's DNS points it at the gateway, which is not the default; there, use the
dashboard origin instead (`panel.auth = session`, or edit in the dashboard directly): the panel's
"Open dashboard" link (`script_control.dashboard_url`, derived from `[webui]` when it is a specific
address) is the alternative.

**Residual risks, honestly.** (a) A hostile page can read everything the panel reads: the preset
name, which sources were blocked (it can see its own failed loads anyway), blocked counts, the
userscripts that match the page (these last two it could not otherwise learn). Menu commands are
not readable or invokable by the page: the registry is private to the runtime. (b) It can open the confirmation page with a proposal of its
choosing (a popup or navigation); a user who then reads nothing and types the PIN applies it. The page
shows the change in plain words and says to continue only when the user started it. (c) A page can
spam proposals; they do nothing until confirmed. (d) With `auth = none`, a user clicking through a
page-opened confirmation page applies it: do not use `none` outside a trusted network. (e) The PIN
is hashed with a salted SHA-256 and protected by lockout, not by a slow KDF; a stolen database
allows offline guessing of a short PIN. (f) Anyone using the proxy from the same profile can open
the confirmation page: the profile is the trust boundary, and `session` mode removes writes from it.

## Cost

`cargo bench -p proxy-core --bench script_policy_bench`, 10,000 per-site rules, one core, debug-free
release profile (criterion medians; your machine will differ):

| Operation | Time |
|---|---|
| Master switch off, per HTML response or per request | about 4 ns (one atomic load) |
| HTML response, cached header lookup | about 200 ns |
| HTML response, first time for a host (decide and render the CSP) | about 6.7 µs |
| Subresource check, allowed | about 0.6 to 0.8 µs |
| Subresource check, denied (includes recording the report) | about 0.8 µs |
| Subresource check, page unknown | about 0.17 µs |

A profile whose every preset is `trusted` and that has no deny rule skips the request check entirely.
`boot.js` grew from 7,792 to 8,084 bytes (+292) for the hotkey listener; the panel script (14.3 KB)
is only fetched on the first keypress.

## More limits from the wiring

A violation is reported only if the browser sends the `report-uri` request (a user agent may drop
it); a page served from a service-worker or HTTP cache keeps the policy it was stored with; and the
panel is not injected into a `sandbox`ed document without `allow-scripts`.

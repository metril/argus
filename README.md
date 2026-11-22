# Rust MITM Proxy with Adblocking and Userscript Support

A high-performance, production-ready MITM proxy written in Rust with comprehensive adblocking (AdGuard/uBlock Origin feature parity) and Greasemonkey-compatible userscript execution.

## Features

### Core Proxy (Phase 1 - v0.1.0)
- HTTP/1.1 and HTTP/2 support
- MITM TLS interception with on-the-fly certificate generation
- Certificate caching (30-day TTL, 1-hour idle eviction)
- Connection pooling and graceful shutdown
- Request/response pipeline architecture

### Advanced Protocols (Phase 2 - v0.2.0) ✅
- WebSocket proxying with bidirectional frame forwarding (feature `websockets`, on by default), filtered like other requests
- Transparent-gateway mode (Linux): redirect TCP 80/443 to a second listener, no client proxy settings; see [docs/TRANSPARENT.md](docs/TRANSPARENT.md)
- TLS passthrough list (`proxy.tls_passthrough_hosts`) for certificate-pinned apps, in both entry modes
- HTTP/3 and QUIC are **not** intercepted: `Alt-Svc` is stripped so browsers stay on TCP (reject UDP/443 in transparent mode)

### Adblocking Engine (Phase 3 - v0.3.0) 🚧
- ✅ Core filter engine with adblock-rust integration
- ✅ Network request blocking with AdBlock Plus syntax
- ✅ Filter list management (EasyList, EasyPrivacy, AdGuard Base & Tracking Protection)
- ✅ Auto-downloading filter lists from URLs
- ✅ Statistics tracking (blocked requests, by type, top domains)
- ✅ AdGuard syntax extensions: `$removeparam`, `$removeheader`, `$replace`
  - `$removeparam` - Remove query parameters from URLs (supports regex)
  - `$removeheader` - Remove HTTP headers from requests/responses
  - `$replace` - Content replacement with regex (10MB limit, text only)
- ✅ Cosmetic filtering (element hiding and CSS injection)
  - Element hiding rules (`##`, `#@#`) for standard CSS selectors
  - Extended CSS selectors (`#?#`, `#@?#`) with `:has()`, `:contains()`, `:xpath()`, etc.
  - CSS injection rules (`#$#`, `#@$#`) for style modifications
  - Domain-specific and exception rules
  - Injected into HTML responses via the MITM proxy (streaming, gzip/br aware), with a
    dynamic class/id helper and a procedural-filter evaluator (`:has-text`, `:matches-css`, …)
- ✅ Scriptlet injection (`##+js(...)`): uBlock Origin's scriptlets are fetched at runtime,
  converted to adblock-rust resources (parsed with a real JavaScript parser and validated; a
  resource that fails is dropped and listed in `GET /engine/status`), and cached under
  `data/filters`; the default build also embeds a copy (see below).
  Configurable (or disabled with `""`) via `[adblock] scriptlet_resources_url`.
- ✅ Custom user rules: block/allow (`@@`)/cosmetic rules editable in the Web UI, compiled into
  the engine alongside subscribed lists
- ✅ Filtering across HTTP/1.1, HTTP/2 and WebSocket (HTTP/3/QUIC traffic is not filtered; see above)
- ✅ Scriptlet injection (`#%#`, `#@%#`)
  - JavaScript injection for complex filtering scenarios
  - Built-in scriptlet library (abort-on-property-read, set-constant, remove-class, etc.)
  - AdGuard and uBlock Origin syntax compatibility
  - Exception rules for disabling scriptlets

### Userscript Engine (Phase 4 - v0.4.0)
- Userscripts injected per document (see [Userscripts](#userscripts)), run in the page
- GM_* / GM.* API: values, XHR (under the destination policy and `@connect`), styles, resources
- Capability tokens, same-origin checks and server-side grants (no isolated world: see the hostile-page notes)
- Two-step install with approval, update checks with re-approval, storage view, export/import

### Web Management UI (Phase 5 - v1.0.0)
- Leptos-based WebUI on port 3000
- Authentication with bcrypt + JWT (httpOnly cookies)
- Real-time statistics and request logging
- Filter list and userscript management
- CA certificate download

## Security Features

- **CA Key Encryption**: Private key encrypted at rest (age + Argon2)
- **V8 Sandboxing**: Separate process + seccomp-bpf syscall filtering
- **SSRF Protection**: Blocks RFC1918, link-local, metadata IPs, DNS rebinding
- **ReDoS Protection**: Regex complexity validation + compilation timeouts
- **Circuit Breakers**: Prevent cascading failures (5 failure threshold)
- **Memory Pressure Monitoring**: Load shedding at 2.0GB warning, 2.5GB critical
- **Rate Limiting**: IP + username + global limits
- **TLS Hardening**: TLS 1.3 preferred, AEAD ciphers only

## Performance Targets

- **Latency**: <10ms overhead (basic), <80-100ms (with userscripts)
- **Throughput**: 10,000+ requests/second
- **Memory**: 2.5-3GB with 10,000 connections
- **Startup**: <5 seconds
- **Binary**: <50MB (static)
- **Docker Image**: <100MB (Alpine-based)

## Quick Start

### Prerequisites
- Rust stable (pinned via `rust-toolchain.toml`; MSRV 1.88+)
- Docker (optional, for containerized deployment)

### Build from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/adblocker.git
cd adblocker

# Build release binary (HTTP/1.1, HTTP/2, and WebSockets)
cargo build --release --features websockets

# Build with adblocking support
cargo build --release --features "websockets,adblock"

# Build with every feature (WebSockets, userscripts, Web UI)
cargo build --release --features full

# Run the proxy (the prebuilt binary / Docker image enables the full feature set)
./target/release/adblocker
```

### Docker Deployment

```bash
# Build the image
docker build -t adblocker .

# Run with docker-compose
docker-compose up -d
```

### Security defaults

The proxy only serves private/local client addresses (`proxy.allowed_clients`) and never connects
to loopback, link-local/metadata or its own listeners (`proxy.block_private_destinations`,
`proxy.allowed_destinations`). The check runs on the resolved address that is actually dialled, so
DNS rebinding cannot bypass it. Inside an intercepted TLS connection a request for another host is
answered `421 Misdirected Request` unless the connection's certificate covers that name.
Address-only caveat: names are checked when they resolve, so a name that resolves to one of the
proxy host's own interface addresses is refused on the proxy's own ports only.

### DNS resolution

Every name the proxy dials (intercepted HTTP, CONNECT and transparent tunnels, WebSocket) and
every control-plane fetch (filter lists, resources) is resolved through one caching resolver
(`[dns]`): TTL-clamped, single-flight, and the destination policy is applied to the cached
addresses on every use (control-plane fetches keep their own, stricter policy). Only NXDOMAIN and
"no records" answers are cached negatively (`negative_ttl_secs`); timeouts (retried once),
SERVFAIL and I/O errors never are. When the resolver answers "does not exist", the operating
system resolver is asked once before the lookup fails, so names only the OS knows (mDNS `.local`,
NSS sources) still work; the policy judges those addresses too. This is the same on every path.
Failures (upstream timeouts and errors, DNS failures, refused destinations) are counted in
`GET /api/v1/stats/proxy` (`faults`) and summarized in one warning per 10 s.

### Getting started (end-to-end)

The ports: **8080** (explicit proxy: HTTP and HTTPS via CONNECT), **3000** (Web UI + API), and optionally the transparent-mode port (`proxy.transparent_port`, off by default).

1. **Start it** — `./target/release/adblocker` (or `docker-compose up -d`).
2. **Create your account** — open `http://localhost:3000` and register. The **first** user
   registered automatically becomes the admin.
3. **Install the root CA** — in the Web UI go to **Settings → CA Certificate → Download CA
   Certificate**, or fetch it directly from any device at `http://<server>:3000/api/v1/ca.crt` (this
   endpoint is public so phones and other machines can grab it by URL). Then trust it so MITM'd
   HTTPS pages validate:
   - **macOS**: open the downloaded file → add to the **System** keychain in Keychain Access →
     double-click it → expand **Trust** → set **When using this certificate: Always Trust**.
   - **Chrome/Edge**: Settings > Privacy and security > Security > Manage certificates
   - **Firefox**: Settings > Privacy & Security > Certificates > View Certificates > Authorities > Import
   - **Linux**: `sudo cp adblocker-ca.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates`

   Full per-OS/browser instructions: [docs/CA-INSTALLATION.md](docs/CA-INSTALLATION.md).
4. **Point your device/browser at the proxy** — set **both** the HTTP and HTTPS proxy to the
   server on port **8080** (SOCKS not supported). The proxy binds `0.0.0.0`, so from another
   machine use the server's LAN IP (e.g. `192.168.1.50:8080`), **not** `localhost`.
   - **macOS**: System Settings → Network → (your interface) → Details → Proxies → enable **Web
     Proxy (HTTP)** and **Secure Web Proxy (HTTPS)**, both `Server: <server-ip>`, `Port: 8080`.
5. **Manage blocklists** — the default lists (EasyList, EasyPrivacy, AdGuard Base/Tracking) are
   seeded and downloaded automatically; add your own under **Filters**. Lists are **persisted**
   in the local database and survive restarts, and the engine recompiles automatically when you change them.
6. **Verify it's working**:
   - `curl http://<server>:3000/api/v1/health` returns `{"status":"healthy",...}`.
   - With your device browsing through the proxy, the **Requests Checked / Blocked** counters on
     the **Filters** page climb, and the proxy logs show per-connection lines.
   - **#1 gotcha:** if HTTPS pages error with a certificate warning, the CA from step 3 isn't
     trusted yet — that's almost always why "the proxy doesn't seem to work."

That's it — ad/tracker requests matching your enabled lists are now blocked at the proxy.

## Configuration

Edit `config/default.toml`:

```toml
[proxy]
host = "0.0.0.0"
port = 8080
enable_http2 = true
enable_websockets = true  # Requires building with --features websockets
# Who may use the proxy (CIDRs; others are closed at accept). Default: loopback, RFC 1918,
# CGNAT, link-local and ULA sources. An empty list allows nobody; use ["0.0.0.0/0", "::/0"] to
# open it to everyone (not recommended).
allowed_clients = ["127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "fc00::/7", "fe80::/10"]
# Destinations the proxy refuses to connect to (403, `x-adblock: destination-refused`): loopback,
# link-local/cloud metadata, multicast and the proxy's own listeners, always. Private ranges
# (RFC 1918, ULA, CGNAT) are allowed unless this is set:
block_private_destinations = false
# CIDR exceptions that win over the refusals above (never over the proxy's own listeners):
allowed_destinations = []

[performance]
max_connections = 0          # 0 = derive from the soft RLIMIT_NOFILE (3 fds per connection plus a reserve; the soft limit is raised to the hard limit first)
connection_rate_limit = 10000  # new connections per second; a missing key means 10000, 0 = unlimited

[mitm]
enabled = true
ca_cert_path = "certs/root-ca.crt"
ca_key_path = "certs/root-ca.key"
cert_cache_size = 1000

[adblock]
enabled = true            # Network/cosmetic blocking via the bundled filter engine
data_dir = "data/filters" # Database, cached list files and the compiled engine live here (see Storage layout)
auto_update = true
update_interval_hours = 24
# Control-plane downloads (lists, `!#include`, scriptlet resources) refuse private, loopback and
# link-local destinations by default; allow LAN hosts here (CIDRs, IPs or host names).
allowed_fetch_destinations = []   # e.g. ["192.168.1.0/24", "nas.lan"]
build_threads = 0               # list-build pool threads (parse/compile on a rebuild, low priority); 0 = half the cores
recent_blocked_keep_query = false # strip query strings from the recent-blocked list (they can hold tokens)
respect_no_transform = true # skip body rewriting when the origin sends Cache-Control: no-transform

[userscripts]
enabled = true

[webui]
enabled = true
host = "0.0.0.0"
port = 3000                # Web UI + API
# Binding beyond loopback serves plain HTTP: put a TLS-terminating reverse proxy in front.
cookie_secure = "auto"     # "auto" | "always" | "never": Secure flag on session cookies; auto = when
                           # the request came over HTTPS through a proxy listed in trusted_proxies
trusted_proxies = []       # proxy IPs whose X-Forwarded-For / X-Forwarded-Proto are believed
# Accounts are created by registering in the Web UI; the first user becomes admin.
```

## Blocklist formats and lists

Each list has a **format** (`auto` by default: detected from the content) and an optional
**allowlist** flag (every rule of the list becomes an exception). The list's build report
(`GET /api/v1/lists/{id}/report`, shown on the **Filters** page) says which format was detected and
how many rules were network / cosmetic / handed off / skipped / deduplicated, with the first parse
issues. Pure domain rules (`||host^`, hosts and domain entries) are held in a compact domain set
instead of the engine.

### Supported blocklist formats

| Format | Example line | Maps to | Skipped or handed off |
|---|---|---|---|
| `abp` (Adblock Plus / EasyList) | `\|\|ads.example^$third-party` | engine network and cosmetic rules | options adblock-rust lacks are handed off (see below) |
| `ubo` (uBlock Origin) | `example.com##+js(aeld, click)` | as `abp`, plus scriptlets, `!#include`, `!#if` | as `abp` |
| `adguard` | `\|\|ads.example^$removeparam=id` | as `abp`; AdGuard-only syntax translated where possible | `#%#` JS, `$$` HTML filters, `$denyallow`, `$replace`, ... are handed off |
| `hosts` | `0.0.0.0 ads.example` | blocks the host and its subdomains | `localhost` and local names skipped |
| `domains` | `ads.example` (`*.d`, `.d` also accepted) | blocks the domain and subdomains | local names skipped |
| `dnsmasq` | `address=/ads.example/0.0.0.0` | blocks the domain | other directives skipped |
| `unbound` | `local-zone: "ads.example." always_nxdomain` | blocks the domain | non-blocking zone types skipped |
| `rpz` | `ads.example CNAME .` | blocks the domain; `rpz-passthru` becomes an exception | non-reject policies and custom answers skipped |
| `pihole` | `^ads[0-9]+\.example$` (regex) or `ads.example` | domains and host regex rules | unsupported regex anchors are errors |
| `adguard-home` | `\|\|ads.example^$important` | DNS-style `\|\|host^` rules and exceptions | unsupported modifiers skipped |
| `little-snitch` | `.lsrules` JSON | deny rules for hosts and domains | allow rules, non-host targets skipped |
| `surge` | `DOMAIN-SUFFIX,ads.example,REJECT` | domain, keyword, regex and CIDR rules | non-reject policies skipped |
| `clash` | `payload:` YAML with `+.ads.example` | domain, keyword, regex and CIDR rules | unsupported rule types skipped |
| `ip-list` | `192.0.2.0/24` | IP/CIDR/range block list checked for IP-literal hosts | none |

**Handed off** rules (`$replace`, `$jsonprune`, `$cookie`, `$removeheader`, HTML filters, `#%#`
JavaScript, ...) are parsed and kept, but not enforced yet. `GET /api/v1/rules/ext` lists them (kind,
raw rule, domains) and `GET /api/v1/engine/build` counts them per kind. A rule the engine cannot
parse is *rejected* and appears in the list's issues. `POST /api/v1/rules/validate` runs the same
conversion for a given format and reports each line as translated, accepted, handed off, skipped or
rejected without storing anything.

### List catalogue

A catalogue of well-known hosts, domain and IP lists (StevenBlack, AdAway, HaGeZi, OISD, Phishing
Army, Spamhaus DROP, Feodo, ...) is built in but **disabled by default**; nothing is downloaded until
you add one (Filters, then Catalogue, or `POST /api/v1/lists/catalogue/{id}`). Each entry shows its
licence: check it before use.

### Fetch policy

Lists, `!#include` targets and the scriptlet resource URL are fetched by the control plane under a
stricter destination policy than proxied traffic: only `http`/`https`, and loopback, link-local
(cloud metadata), multicast, unspecified and private ranges (RFC 1918, ULA, CGNAT) are refused,
judged on the address actually connected to (so a name resolving internally is refused, and IPv6
literals and mapped forms are covered). Redirects are followed for at most 3 hops, never from
`https` to `http`, every hop is vetted the same way, and includes must stay on the list's origin.
URLs are checked when saved (`400`, code `fetch_destination_not_allowed` or `invalid_fetch_url`)
and again on every fetch. Hosting lists on your LAN: add its CIDR, IP or host name to
`adblock.allowed_fetch_destinations`. gzip, deflate, br and zstd replies are accepted and decoded as
a stream: `max_list_bytes` is enforced on the *decoded* bytes (all includes of a list share that
budget) and a compression-ratio cap (100:1 beyond the first MiB) stops decompression bombs; other
codings are refused. Lines echoed in build reports are cut to 80 characters.

### Build failures and limits

A failed build (for example a list set that exceeds adblock-rust's flatbuffer limits, roughly a
million non-domain rules; pure domain rules are not counted because they bypass the engine) leaves
the previous engine serving. The failure is logged, shown as `Failed` in the build state
(`GET /api/v1/engine/build`, Filters page) and the next successful build clears it. The limit is
not worked around by sharding: reduce the number of path-style rules, or prefer domain-format lists.

### Storage layout

Everything lives under `adblock.data_dir` (default `data/filters`):

- `adblocker.redb`: one database for list metadata, build reports, users, sessions, tokens, audit
  log and userscripts.
- `lists/`: raw list contents as content-addressed files (`lists/<sha256>`), garbage-collected when
  unreferenced.
- `engine.bin`: the compiled engine, domain set and handed-off rules, so a restart serves the last
  build before touching the network (invalidated when lists or the converter change).

Old sled directories are ignored (and can be deleted). `userscripts.data_dir` and
`webui.session_storage_path` no longer exist; the proxy refuses to start if they are still set.

### `bundled-ubo-resources` feature

Scriptlet rules (`##+js(...)`) need the uBlock Origin resource library. The default build embeds a
pinned copy of it (GPL-3.0; see `docs/LICENSING.md`). At runtime the freshest fetched copy wins,
then the on-disk cache `<data_dir>/resources.json`, then the embedded copy. To build without it:
`cargo build --release --no-default-features --features websockets` (the `full` feature includes it).

## Rule support

Rules the network engine cannot express are handed to the extended-rule index (`crates/ext-rules`),
built in the same off-thread compile step as the engine, persisted with it (same cache key) and
swapped in together with it, so a request never pairs one build's engine with another build's
extended rules. *Enforced* means it changes traffic on the HTTP/1.1 and HTTP/2 forward path
(plain and MITM); WebSocket and HTTP/3 requests see only the network engine.

| Modifier / syntax | Status | Needs a trusted list |
| --- | --- | --- |
| Network rules, `@@`, `$important`, `$badfilter`, `$redirect`, `$csp`, `$removeparam`, `$generichide`, cosmetic `##` | enforced (engine) | no |
| `$replace` (text bodies up to 3 MiB; on HTML it runs first, see below) | enforced | yes |
| `$jsonprune` (up to 4 MiB), `$xmlprune` (up to 4 MiB), `$hls` (up to 2 MiB) | enforced | no |
| `$removeheader` (response and `request:`; forbidden list refused) | enforced | no |
| `$cookie` (removal on requests; removal and attribute edits on `Set-Cookie`) | enforced | no |
| `$permissions` (documents) | enforced | no |
| `$urltransform` (same origin, path and query only, fetched transparently) | enforced | yes |
| `$method`, `$to`, `$denyallow` | enforced | no |
| `$header` (blocks a response whose header matches) | enforced | no |
| HTML filters `##^`, `$$` (`:has-text`, `tag-content`, `min/max-length`) | enforced (`parent-elements` ignored: partial) | no |
| `#%#` JavaScript | enforced (runs before page scripts, after the boot runtime) | yes |
| AdGuard scriptlets without a uBO equivalent, ABP snippets (`#$#`) | partial: `log` and `log-addEventListener` run; every other name is reported once per page as `unsupported scriptlet <name>` | yes |
| Extended CSS the engine rejected (`#?#`, `#$?#`) | partial: in-page evaluator (`:has-text`, `:matches-css*`, `:matches-attr`, `:matches-path`, `:min-text-length`, `:upward`, `:xpath`) | no |
| `$popup` | parsed only (no opener information in request headers) | n/a |
| `$stealth`, `$network`, `$referrerpolicy`, other unknown options | parsed only, listed as `unsupported` in `GET /rules/ext` | n/a |

**Trust.** `$replace`, `$urltransform`, `#%#`, snippets and unknown scriptlets let a list author
rewrite content or run code in every page, so they are dropped (and counted per list in
`GET /api/v1/engine/build`, `ext_stats`) unless the list is *trusted*. Custom rules are always
trusted; downloaded lists are not until you turn on `trusted` (Filters page, or
`PUT /api/v1/lists/{id}` with `lists:write`; the change is audited). Exceptions never need trust.

**Precedence.** An engine block is final. An engine exception (`@@||host^`) does *not* switch off
extended rules: as in uBlock Origin and AdGuard, each modifier is disabled only by an exception
naming it (`@@||host^$replace`), with `$important` beating a plain exception; `$removeparam`
runs before `$urltransform`.

**Apply order for responses.** Header edits and `$header` blocking happen first; then, for a
document, `$replace` runs on the decoded text, and the HTML stages (content-dependent removals,
`##^`, cosmetic and script injection) see its result; non-HTML bodies go decode, transform
(`$replace`, `$jsonprune`, `$xmlprune`, `$hls`, in list order), re-encode. Bodies over a
transform's cap (or documents over 4 MiB when buffering is needed) pass through untouched and are
counted. `Cache-Control: no-transform` skips all body work (header edits still apply) unless
`adblock.respect_no_transform = false`. Documents are recognised from `Sec-Fetch-Dest`, else from
`Sec-Fetch-Mode: navigate`, `Upgrade-Insecure-Requests: 1` or an `Accept` listing `text/html`.

## AdGuard Filter Syntax

The filter engine supports AdGuard's advanced modifiers for fine-grained control over request/response handling:

### $removeparam - URL Parameter Removal

Remove tracking parameters from URLs:

```
# Remove specific parameter
||example.com^$removeparam=utm_source

# Remove multiple parameters (regex)
||example.com^$removeparam=/^(utm_source|utm_medium|utm_term)=/

# Remove all parameters
||tracking.site^$removeparam

# Case-insensitive regex
||example.com^$removeparam=/SESSION/i
```

### $removeheader - HTTP Header Removal

Remove unwanted HTTP headers:

```
# Remove response header (default)
||example.com^$removeheader=refresh

# Remove request header
||example.com^$removeheader=request:user-agent

# Security and framing headers cannot be removed
```

**Forbidden headers** follow AdGuard's published list (the CORS family `Access-Control-*`,
`Cross-Origin-*`, `Origin`, `Content-Security-Policy`, `X-Frame-Options`, `Referrer-Policy`,
`Sec-Fetch-*`, ...) plus the headers that frame the message (`Content-Length`, `Content-Type`,
`Content-Encoding`, `Transfer-Encoding`, `Connection`, `Host`, `Proxy-*`, ...); such a rule is
parsed but never applied. The full list is in `crates/ext-rules/src/headers.rs`.

### $replace - Content Replacement

Replace content in responses using regex:

```
# Basic replacement
||example.com^$replace=/test1/test2/

# Case-insensitive
||example.com^$replace=/ADS/removed/i

# Escape special characters
||example.com^$replace=/price\:\s*\$99/price: \$49/
```

**Limitations**:
- Only applies to text content types (HTML, JS, CSS, JSON)
- Maximum decoded response size: 3 MiB (larger bodies pass through untouched)
- Rules from trusted lists only (see below)

### Exception Rules

Disable modifiers for specific domains:

```
# Disable all removeparam rules for example.com
@@||example.com^$removeparam

# Disable specific removeheader rule
@@||example.com^$removeheader=refresh
```

## Cosmetic Filtering

Cosmetic filtering hides unwanted page elements and injects custom styles without blocking network requests.

### Element Hiding Rules (`##`)

Hide elements matching CSS selectors:

```
# Hide all elements with class .ad-banner
##.ad-banner

# Domain-specific hiding
example.com##.sidebar-ad

# Multiple domains
example.com,test.org##.promo-box

# Complex selectors
##div.ad-container > iframe[src*="ads"]
```

### Element Hiding Exceptions (`#@#`)

Disable hiding rules for specific domains:

```
# Allow .ad-banner on example.com
example.com#@#.ad-banner

# Domain negation - hide everywhere EXCEPT example.com
~example.com##.ad-banner
```

### Extended CSS Selectors (`#?#`)

Use advanced selectors not available in standard CSS:

```
# Hide elements containing specific text
example.com#?#div:contains(Advertisement)

# Case-insensitive text matching
example.com#?#div:contains(/sponsored/i)

# Hide parent elements using :has()
example.com#?#div:has(> .ad-label)

# XPath expressions
example.com#?#:xpath(//div[@class="banner"])

# Move up DOM tree
example.com#?#.ad-marker:nth-ancestor(2)

# Find ancestor matching selector
example.com#?#.inner:upward(div[data-ad])

# Remove elements entirely
example.com#?#.popup:remove()

# Match computed styles
example.com#?#div:matches-css(display: block)
```

### CSS Injection (`#$#`)

Inject custom CSS styles:

```
# Change element appearance
example.com#$#.container { background: transparent !important; }

# Hide with custom styles
example.com#$#.sticky-header { position: static !important; }

# Modify layout
example.com#$#.sidebar { width: 0 !important; }
```

**Security restriction**: Cannot use `url()` values to prevent resource loading.

### CSS Injection Exceptions (`#@$#`)

```
# Disable CSS injection on specific domain
example.com#@$#.container
```

### Cosmetic Filtering Best Practices

1. **Use standard selectors when possible** (`##`) - better performance than extended CSS
2. **Be specific with domains** - reduces false positives
3. **Test exception rules** - verify they don't break website functionality
4. **Prefer element hiding over injection** - simpler and more maintainable
5. **Use `:remove()` carefully** - can break page functionality

## Scriptlet Injection

Scriptlets are JavaScript functions injected into pages to modify behavior that cannot be blocked with network or cosmetic filters.

### Basic Syntax

```
# AdGuard syntax
domain.com#%#//scriptlet('scriptlet-name', 'arg1', 'arg2')

# Exception rule
domain.com#@%#//scriptlet('scriptlet-name')
```

### Built-in Scriptlets

**abort-on-property-read** - Prevents access to object properties:
```
# Block access to window.advert property
example.com#%#//scriptlet('abort-on-property-read', 'advert')

# Throws ReferenceError when accessed
example.com#%#//scriptlet('abort-on-property-read', 'alert')
```

**abort-on-property-write** - Prevents writing to object properties:
```
# Prevent setting window.tracking
example.com#%#//scriptlet('abort-on-property-write', 'tracking')
```

**set-constant** - Override property values with constants:
```
# Set window.isAdBlocker to false
example.com#%#//scriptlet('set-constant', 'isAdBlocker', 'false')

# Set numeric value
example.com#%#//scriptlet('set-constant', 'adsShown', '5')

# Set to undefined
example.com#%#//scriptlet('set-constant', 'adConfig', 'undefined')
```

**remove-attr** - Remove HTML attributes from elements:
```
# Remove data-ad attribute from divs
example.com#%#//scriptlet('remove-attr', 'data-ad', 'div')

# Remove onclick from buttons
example.com#%#//scriptlet('remove-attr', 'onclick', 'button.ad-button')
```

**remove-class** - Remove CSS classes from elements:
```
# Remove 'premium-only' class
example.com#%#//scriptlet('remove-class', 'premium-only', 'div.content')

# Remove multiple classes
example.com#%#//scriptlet('remove-class', 'overlay', 'body')
```

**noopjs** - No-operation scriptlet (placeholder):
```
# Does nothing, useful for testing
example.com#%#//scriptlet('noopjs')
```

### Cross-Browser Compatibility

The implementation supports AdGuard and uBlock Origin syntax:

```
# AdGuard syntax
example.com#%#//scriptlet('abort-on-property-read', 'alert')

# uBlock Origin syntax (aliases supported)
example.com#%#//scriptlet('ubo-abort-on-property-read.js', 'alert')

# Adblock Plus syntax (aliases supported)
example.com#%#//scriptlet('abp-abort-on-property-read', 'alert')
```

### Argument Escaping

Use backslash to escape special characters in arguments:

```
# Escape quotes
example.com#%#//scriptlet('set-constant', 'message', 'it\'s working')

# Escape commas in arguments
example.com#%#//scriptlet('abort-on-property-read', 'config.ads\,trackers')
```

### Exception Rules

Disable scriptlets for specific domains:

```
# Disable all scriptlets
example.com#@%#//scriptlet()

# Disable specific scriptlet
example.com#@%#//scriptlet('abort-on-property-read')
```

### Scriptlet Execution

Scriptlets are:
- Injected before page scripts execute
- Wrapped in IIFE for isolation: `(function() { 'use strict'; /* scriptlet code */ })();`
- Execute in page context (not extension context)
- Can modify page behavior without network blocking

### Security Considerations

1. **Scriptlets execute in page context** - they have full access to the DOM
2. **Use trusted filter lists only** - malicious scriptlets can steal data
3. **Test before deploying** - ensure scriptlets don't break functionality
4. **Monitor for exceptions** - some sites detect and block scriptlet injection

## Auto-Update System

The filter engine includes an automatic update system for keeping filter lists current.

### Basic Usage

```rust
use filter_engine::{FilterEngine, UpdateConfig};

// Create engine
let engine = FilterEngine::new("./data".into())?;

// Enable auto-update with default config (24-hour updates)
engine.enable_auto_update(UpdateConfig::default());

// Start the background updater
engine.start_auto_update().await;
```

### Update Configuration

```rust
use filter_engine::UpdateConfig;

let config = UpdateConfig {
    interval_hours: 12,           // Update every 12 hours
    enabled: true,                // Auto-update enabled
    verify_checksums: true,       // Verify MD5 checksums
    max_retries: 3,               // Retry failed updates 3 times
    retry_delay_secs: 300,        // Wait 5 minutes between retries
};

engine.enable_auto_update(config);
engine.start_auto_update().await;
```

### Manual Updates

Trigger an immediate update manually:

```rust
// Trigger update and get results
let (updated, failed) = engine.trigger_update().await?;
println!("Updated: {}, Failed: {}", updated, failed);
```

### Update Statistics

Monitor update history and per-list statistics:

```rust
// Get update statistics
if let Some(stats) = engine.update_stats() {
    // Get recent update attempts
    let recent = stats.get_attempts(10);
    for attempt in recent {
        println!("Update at {}: {} updated, {} failed",
            attempt.timestamp, attempt.lists_updated, attempt.lists_failed);
    }

    // Get statistics for specific list
    if let Some(list_stats) = stats.get_list_stats("easylist") {
        println!("EasyList: {} successful, {} failed",
            list_stats.success_count, list_stats.failure_count);
        println!("Last checksum: {:?}", list_stats.last_checksum);
    }

    // Get all list statistics
    let all_stats = stats.get_all_list_stats();
    for stat in all_stats {
        println!("{}: success={}, failures={}",
            stat.list_id, stat.success_count, stat.failure_count);
    }
}
```

### Checksum Verification

Filter lists can include MD5 checksums for integrity verification:

```
! Title: EasyList
! Checksum: 8/FRX6I9PqnMzpPRCLwE5Q==
example.com##.ad-banner
```

The update system:
- Automatically extracts checksums from filter list headers
- Calculates MD5 hash of downloaded content (excluding checksum line)
- Compares checksums and rejects corrupted downloads
- Stores last verified checksum for each list

### Atomic Hot Reload

Updates are applied atomically without downtime:

1. **Download Phase**: All filter lists downloaded in parallel
2. **Verification Phase**: Checksums verified if enabled
3. **Compilation Phase**: New filter engine compiled
4. **Atomic Swap**: Old engine replaced via arc-swap
5. **No Downtime**: Requests continue during entire process

### Stopping Auto-Update

```rust
// Stop the background scheduler
engine.stop_auto_update();

// Check if running
if engine.is_auto_update_running() {
    println!("Auto-update is active");
}
```

### Updating Configuration

Change configuration without restarting:

```rust
let new_config = UpdateConfig {
    interval_hours: 6,  // Change to 6-hour updates
    ..engine.get_update_config().unwrap()
};

engine.set_update_config(new_config);
```

### Error Handling

The update system includes comprehensive error handling:

- **Network Errors**: Automatic retries with exponential backoff
- **Checksum Failures**: Lists rejected, errors logged
- **Partial Failures**: Successful lists still loaded
- **Statistics Tracking**: All failures recorded with error messages

```rust
match engine.trigger_update().await {
    Ok((updated, failed)) => {
        println!("Update completed: {} updated, {} failed", updated, failed);

        // Check for failures
        if failed > 0 {
            if let Some(stats) = engine.update_stats() {
                for stat in stats.get_all_list_stats() {
                    if let Some(error) = stat.last_error {
                        eprintln!("List {} failed: {}", stat.list_id, error);
                    }
                }
            }
        }
    }
    Err(e) => {
        eprintln!("Update failed completely: {}", e);
    }
}
```

### Best Practices

1. **Set appropriate intervals**: 12-24 hours for most filter lists
2. **Enable checksum verification**: Protects against corrupted downloads
3. **Monitor statistics**: Track update success rates
4. **Handle failures gracefully**: Don't fail application on update errors
5. **Use conditional requests**: ETags prevent unnecessary downloads (automatic)
6. **Test before production**: Verify update behavior in staging

### Implementation Details

- Uses `tokio::time::interval` for scheduling
- Background task runs in separate spawn
- Thread-safe with `Arc<RwLock<T>>` for shared state
- MD5 checksums follow AdBlock Plus standard
- Base64 encoding for checksum representation
- Supports ETag-based conditional requests

## Userscripts

Tampermonkey/Violentmonkey-style userscripts run in the page, injected by the proxy. There is no
browser extension: the proxy rewrites HTML responses and answers a small backend itself.

### How it works

1. A script is installed through the Web UI or the API in two steps (`plan`, then `confirm`). The
   plan lists the grants, `@connect` hosts, match scope (broad scopes such as `<all_urls>` and
   `@connect *` are flagged) and anything unsupported; nothing runs until you approve it.
2. For each HTML document the proxy asks the profile's script index which scripts match
   (`@match`/`@include`/`@exclude`/`@noframes`; top frame vs. iframe comes from `Sec-Fetch-Dest`).
   With no installed scripts, or no match, nothing is added to the page and no extra request is made.
3. Each matching script becomes one classic `<script src="/__adblock__/us/<doc>.<n>.js">` at the top
   of `<head>` (so `@run-at document-start` runs before page scripts; the runtime stages
   `document-body`/`-end`/`-idle`). A script with a syntax error cannot break another script.
   The bundle URL is per document, unguessable, single use and `no-store`; the page's CSP is
   adapted the same way as for the blocker's own scripts (nonce, `connect-src`, Trusted Types name).
4. The runtime talks to `/__adblock__/gm/v1/*` on the page's own origin. Every call needs a
   capability token (HMAC over profile, script, version, origin, grants and expiry), the matching
   `Origin`, same-origin fetch metadata and a custom header. Authority comes from the stored script:
   `@grant`, `@connect`, quotas and the destination policy are enforced server-side. Protocol:
   `docs/USERSCRIPT-PROTOCOL.md`.

Outbound `GM_xmlhttpRequest`/`GM_download` traffic goes through the proxy's own upstream client under
the same destination policy as proxied traffic (loopback, link-local, the proxy's own listeners and,
if configured, private ranges are refused even for `@connect *`), re-checks `@connect` on every
redirect, and streams both ways in bounded memory. It is not run through the filter engine (script
managers do not filter either). Cookies: the proxy cannot see the browser's cookie store, so
`GM_cookie` and non-anonymous requests use a per-profile jar inside the proxy (in memory, lost on
restart); the browser's own cookies are never attached to a script's request.

### What works

`GM_getValue/setValue/deleteValue/listValues` (+ `GM.*` promise forms, `GM_getValues`...),
`GM_addValueChangeListener` (also across tabs), `GM_addStyle`, `GM_addElement`,
`GM_getResourceText/URL`, `@require`, `GM_xmlhttpRequest` (GET/POST/headers, progress, abort,
timeout, redirects), `GM_download`, `GM_cookie`, `GM_info`, `unsafeWindow`, `GM_openInTab`,
`GM_setClipboard`, `GM_notification`, `GM_registerMenuCommand` (registry only), `@grant none`.
Install, update checks (manual or scheduled; an update that widens `@match`/`@grant`/`@connect`
stays pending until approved), per-script enable/disable, storage view/clear and JSON
export/import are in the Web UI and the API (`docs/API.md`).

### What cannot work through a proxy

- **No isolated world.** Scripts run in the page's JavaScript world. `@sandbox`, `@inject-into
  content` and `@run-in` cannot be honoured (reported at install). `@grant none` scripts and
  `unsafeWindow` are the page's `window`.
- No `@webRequest`/`GM_webRequest`, no `@run-at context-menu`, no toolbar/context-menu UI, no other
  extension-only APIs. Menu commands are collected but there is no panel yet, and with several
  scripts on one page only the first script's commands are registered.
- The proxy cannot write files (`GM_download` saves through the browser) or read the browser's cookies.
- `@unwrap` scripts need an inline script, so they do not run under CSPs or Trusted Types that
  forbid it. Pages sent with CSP `sandbox` (no `allow-scripts`) get no scripts at all.
- The browser must trust the proxy CA and reach the page through the proxy; HTTP/3 is not supported.

### Hostile pages (read this)

A userscript shares its world with the page, so a page is not fully contained. What the design
does: the runtime captures `fetch`, `JSON`, `Promise`, `Function.prototype.call/apply/bind`, DOM
prototypes and stream readers before any page code runs, keeps tokens only in closures (never in
the DOM, an attribute or a URL), serves each bundle once, and deletes its own `<script>` element. A
page that overrides `fetch`, `JSON.parse` or `Function.prototype.call` after load cannot read a
token or hijack a script's calls, and its own calls to the endpoints are refused (browser tests
assert this). What it can still do: poison built-ins before they are captured if it runs before
the proxy's script (not possible for an inline script in the document, but for an extension or an
earlier same-origin frame); tamper with objects it receives later, for example
observe the values a script reads through `Promise.prototype.then` or anything a script writes to
the DOM or exposes on `window`; and, with a token it somehow stole, act as that one script on that
one origin until the token expires (one hour), within that script's approved grants and `@connect`.
Only install scripts you trust with the data of the sites they run on.

**Service workers.** A service worker sees every same-origin request of its pages, so it can read
the `X-GM-Token` header of a script's backend calls and answer any request, including the boot
script and bundle URLs, with its own content. No header or token scheme can stop that: a worker's
`fetch` handler is always in the path. `userscripts.service_worker_policy` therefore acts on the
workers themselves: `block_when_privileged` (default) refuses service-worker script fetches
(registration fails with a 403) and unregisters existing workers, on hosts where a script with
`GM_xmlhttpRequest`, `GM_download` or `GM_cookie` may run; `block` does so for every host the
proxy serves userscripts on; `allow` leaves workers alone, and then they can read those tokens
and GM traffic. Residual exposure with the default: a worker that already controls a page keeps
doing so until the first load that unregisters it, and a worker on a host with only
non-privileged scripts can still see their calls. Bundle URLs are additionally refused unless
fetched by a `<script>` element, which stops a worker from fetching one itself with `fetch()`.

### Configuration

```toml
[userscripts]
enabled = true                 # inject scripts and serve the GM backend
update_check_interval_hours = 0  # scheduled update checks (0 = off)
auto_apply_updates = false     # apply only updates that do not widen grants/@match/@connect
service_worker_policy = "block_when_privileged"  # allow | block_when_privileged | block
```

Stored scripts from before the rewrite (`resources` map format) cannot be read; they are dropped
with a log line when the database is loaded.

## Per-device profiles

A profile is a set of enabled filter lists plus its own custom rules; devices are mapped to
profiles and everything else uses the built-in `default` profile. Explicit-proxy devices are
identified by a token sent as the proxy password, transparent-mode devices by source address
(tokens are the stronger identity). `proxy.require_device_token = true` makes explicit-proxy
connections without a known token fail with `407`. Statistics and the master on/off switch stay
global. Profiles and devices are compiled in the background whenever they change. Details, limits
and delete behaviour: [docs/PROFILES.md](docs/PROFILES.md).

## Script control

NoScript-style control of what a page may run and load, per site, enforced by the proxy. It is
**off until you switch it on** (`PUT /api/v1/policy/settings`, or the dashboard's "Script policy" page).
Full model, tables and limits: [docs/SCRIPT-POLICY.md](docs/SCRIPT-POLICY.md).

- **How it works.** A generated `Content-Security-Policy` is added to each HTML document as an extra
  header (browsers intersect it with the site's own, so it can only restrict). The proxy also rewrites
  the HTML where CSP cannot express the intent (`<noscript>` revealed, optional stripping of blocked
  `<script>` elements, meta refresh, `ping`), and refuses denied third-party subresources early when
  it knows which page asked. Our own injected resources keep working under any policy.
- **Presets.** `default` (first party everything; third-party scripts, plugins, workers and pings
  blocked), `trusted` (nothing added), `untrusted` (no scripts at all, `<noscript>` shown) and
  `custom`. Per-site rules, a per-page source matrix ("allow `cdn.example.net` on `example.com`") and
  temporary permissions (5 minutes, 1 hour, 1 day, until restart) are in the dashboard and API.
- **Userscripts** run regardless of page restrictions (as in every userscript manager); what a script
  creates (inline handlers, `eval`) still obeys the page policy.
- **The panel.** `PUT /api/v1/policy/panel {"enabled": true, "pin": "..."}`, then press
  **Alt+Shift+A** on any page (configurable). A read-only panel opens in a closed shadow root: preset,
  blocked sources by domain with per-capability toggles, temporary allows, per-site ad blocking,
  userscripts and their menu commands. It cannot change anything itself: **changes are confirmed on a
  page only the proxy answers** (`https://adblock.invalid/`), with your PIN, because a hostile page
  can do anything the panel can. Authentication is `pin` (default), `session` (use the dashboard) or
  `none` (trusted LAN only). In transparent mode that name does not resolve unless your DNS points it
  at the gateway; use the dashboard instead. Threat model and residual risks:
  [docs/SCRIPT-POLICY.md](docs/SCRIPT-POLICY.md#the-in-page-panel).
- **What CSP cannot do.** Deny carve-outs ("all third parties except `ads.net`") and per-URL allows
  cannot be written in CSP; `sendBeacon` cannot be separated from `connect`; service-worker and cached
  pages keep the policy they were stored with; only HTML documents get the header. See the list in
  [docs/SCRIPT-POLICY.md](docs/SCRIPT-POLICY.md#what-csp-cannot-express).
- **Config.** `[script_control]` in `config/default.toml`: `panel_enabled` (global switch),
  `panel_host` (must end in `.invalid`), `dashboard_url`.

## Security and Sandboxing (Week 16)

The userscript engine includes comprehensive security hardening to protect against malicious scripts and prevent security vulnerabilities.

### Security Policy

Configure security policies for userscript execution:

```rust
use userscript_engine::{SecurityPolicy, UserscriptRuntime};

// Default policy (recommended for production)
let policy = Arc::new(SecurityPolicy::default());

// Strict policy (maximum security)
let strict_policy = Arc::new(SecurityPolicy::strict());

// Permissive policy (development only)
let dev_policy = Arc::new(SecurityPolicy::permissive());

// Custom policy
let custom_policy = Arc::new(SecurityPolicy {
    max_execution_time_ms: 15_000,
    max_memory_bytes: 75 * 1024 * 1024,
    require_https: true,
    strict_csp: true,
    max_requires: 15,
    max_resources: 30,
    enable_audit_log: true,
    ..Default::default()
});

// Create runtime with security policy
let runtime = UserscriptRuntime::with_security(manager, storage, policy);
```

### Security Features

#### 1. URL Validation

All @require and @resource URLs are validated against the security policy:

```rust
// HTTPS enforcement
policy.require_https = true;  // Block HTTP URLs

// Domain allowlist
policy.allowed_domains.insert("cdn.jsdelivr.net".to_string());
policy.allowed_domains.insert("code.jquery.com".to_string());

// Domain blocklist
policy.blocked_domains.insert("malicious-site.com".to_string());

// Automatic blocking of private IPs
// localhost, 127.0.0.1, 10.x.x.x, 192.168.x.x, 172.16-31.x.x
```

#### 2. Source Code Validation

Scripts are scanned for dangerous patterns before execution:

```javascript
// Blocked patterns:
// - eval()
// - Function() constructor
// - setTimeout/setInterval with string arguments
```

```rust
let validator = ScriptValidator::new(policy.clone());

// Validate script source
validator.validate_source(&script.source)?;

// Validate metadata
validator.validate_requires(&script.metadata.requires)?;
validator.validate_resources(&script.metadata.resources)?;
validator.validate_grants(&script.metadata.grants)?;
```

#### 3. Permission Validation

GM_* API access is controlled by @grant declarations:

```javascript
// ==UserScript==
// @name         Secure Script
// @grant        GM_setValue
// @grant        GM_getValue
// ==/UserScript==

// ✓ Allowed (granted)
GM.setValue('key', 'value');

// ✗ Blocked (not granted)
GM.xmlhttpRequest({ url: "..." });  // Error: Missing @grant GM_xmlhttpRequest
```

```rust
// Check if API is allowed
policy.is_api_allowed("GM_setValue", &grants);

// Block dangerous APIs globally
policy.blocked_gm_apis.insert("unsafeWindow".to_string());
```

#### 4. Security Audit Logging

All security events are logged for monitoring:

```rust
// Get audit log
let auditor = runtime.auditor();

// Recent events
let recent = auditor.get_recent_entries(100);

// Events for specific script
let script_events = auditor.get_script_entries("my-script");

// Audit statistics
let stats = auditor.get_statistics();
println!("Total events: {}", stats.total_events);
println!("Permission denied: {}", stats.permission_denied);
println!("API calls: {}", stats.api_calls);
println!("Network requests: {}", stats.network_requests);
println!("Policy violations: {}", stats.policy_violations);
println!("Suspicious activity: {}", stats.suspicious_activity);

// Clear audit log
auditor.clear();
```

#### 5. Resource Limits

Enforce limits on script resources:

```rust
// Maximum @require dependencies
policy.max_requires = 20;

// Maximum @resource files
policy.max_resources = 50;

// Maximum execution time (milliseconds)
policy.max_execution_time_ms = 30_000;

// Maximum memory usage (bytes)
policy.max_memory_bytes = 100 * 1024 * 1024;
```

### Audit Events

The security auditor tracks these event types:

- `ExecutionStart` - Script execution started
- `ExecutionComplete` - Script executed successfully
- `ExecutionFailed` - Script execution failed
- `ApiCall` - GM_* API function called
- `NetworkRequest` - HTTP request made (@require/@resource)
- `PermissionDenied` - Permission check failed
- `ResourceLoaded` - External resource loaded
- `PolicyViolation` - Security policy violated
- `SuspiciousActivity` - Suspicious behavior detected

### Security Best Practices

1. **Use strict policy in production**:
   ```rust
   let policy = SecurityPolicy::strict();
   ```

2. **Enable HTTPS enforcement**:
   ```rust
   policy.require_https = true;
   ```

3. **Enable audit logging**:
   ```rust
   policy.enable_audit_log = true;
   ```

4. **Review audit logs regularly**:
   ```rust
   let stats = auditor.get_statistics();
   if stats.policy_violations > 0 {
       warn!("Policy violations detected!");
   }
   ```

5. **Validate scripts before installation**:
   ```rust
   let validator = ScriptValidator::new(policy);
   validator.validate_source(&source)?;
   ```

6. **Use domain allowlists**:
   ```rust
   // Only allow trusted CDNs
   policy.allowed_domains.insert("cdn.jsdelivr.net".to_string());
   policy.allowed_domains.insert("cdnjs.cloudflare.com".to_string());
   ```

### Security Example

Complete example with security hardening:

```rust
use userscript_engine::{
    UserscriptManager, UserscriptRuntime, UserscriptStorage,
    SecurityPolicy, RunAt, AuditEvent
};
use std::sync::Arc;

// Create strict security policy
let mut policy = SecurityPolicy::strict();
policy.allowed_domains.insert("cdn.jsdelivr.net".to_string());
policy.allowed_domains.insert("code.jquery.com".to_string());
policy.max_requires = 5;
policy.max_resources = 10;
let policy = Arc::new(policy);

// Create manager and storage
let manager = Arc::new(UserscriptManager::new("./data/userscripts".into())?);
let storage = Arc::new(UserscriptStorage::new("./data/storage".into())?);

// Create runtime with security
let runtime = UserscriptRuntime::with_security(
    manager.clone(),
    storage,
    policy.clone()
);

// Install script (with validation)
let script = r#"
// ==UserScript==
// @name         Secure Script
// @match        *://example.com/*
// @require      https://code.jquery.com/jquery-3.6.0.min.js
// @grant        GM_setValue
// @grant        GM_getValue
// ==/UserScript==

GM.setValue('last_visit', new Date().toString());
console.log('Last visit:', GM.getValue('last_visit', 'Never'));
"#;

manager.install(script.to_string())?;

// Execute with security validation
let results = runtime.execute_for_url(
    "https://example.com/page",
    RunAt::DocumentStart
).await?;

// Check audit log
let auditor = runtime.auditor();
let stats = auditor.get_statistics();
println!("Execution stats:");
println!("  API calls: {}", stats.api_calls);
println!("  Network requests: {}", stats.network_requests);
println!("  Policy violations: {}", stats.policy_violations);

// Review violations
if stats.policy_violations > 0 {
    for entry in auditor.get_recent_entries(10) {
        if matches!(entry.event, AuditEvent::PolicyViolation | AuditEvent::PermissionDenied) {
            eprintln!("Security event: {:?} - {}", entry.event, entry.details);
        }
    }
}
```

### Implementation Notes (Week 15)

- **Week 13**: Metadata parser, storage, basic GM_* APIs
- **Week 14**: Boa JavaScript engine integration, advanced GM_* APIs
- **Week 15**: Execution orchestration, @run-at timing, @require/@resource support
- UserscriptRuntime manages execution lifecycle
- Automatic @require and @resource fetching with caching
- DocumentReadyState determines when scripts execute
- ExecutionResults tracks success/failure
- PageContext for injected CSS management
- MIME type detection for resources
- Base64 data URL generation

### Implementation Notes (Week 16)

- **Week 13**: Metadata parser, storage, basic GM_* APIs
- **Week 14**: Boa JavaScript engine integration, advanced GM_* APIs
- **Week 15**: Execution orchestration, @run-at timing, @require/@resource support
- **Week 16**: Security hardening, sandboxing, audit logging
- SecurityPolicy for configurable security controls
- URL validation with HTTPS enforcement and domain filtering
- Source code validation (blocks eval, Function, etc.)
- Permission validation for GM_* APIs
- Security audit logging for all events
- Resource limits (@require, @resource, execution time, memory)
- Comprehensive test coverage (18 security tests)

### Limitations (Week 16)

These will be addressed in future phases:

- **Async GM_xmlhttpRequest**: Currently synchronous validation only
- **DOM Manipulation**: Scripts execute in Boa context (no real DOM yet)
- **Execution Time Limits**: Policy defined but not yet enforced at runtime
- **Memory Limits**: Policy defined but not yet enforced at runtime
- **System Integration**: Notifications and clipboard are logged/stored, not system-level

## Project Structure

```
adblocker/
├── Cargo.toml                      # Workspace manifest
├── crates/
│   ├── proxy-core/                 # Core proxy server
│   ├── filter-engine/              # Adblocking engine
│   ├── userscript-engine/          # Userscript execution
│   ├── web-api/                    # REST API backend
│   ├── web-ui/                     # Leptos frontend
│   └── common/                     # Shared utilities
├── config/                         # Configuration files
├── certs/                          # Generated certificates
├── data/                           # Filter lists and userscripts
├── logs/                           # Application logs
├── tests/                          # Integration tests
└── benches/                        # Performance benchmarks
```

## Development Roadmap

- **Phase 1 (Weeks 1-4)**: Core proxy with MITM
- **Phase 2 (Weeks 5-7)**: HTTP/3 and WebSocket
- **Phase 3 (Weeks 8-12)**: Adblocking engine
- **Phase 4 (Weeks 13-16)**: Userscript execution
- **Phase 5 (Weeks 17-21)**: WebUI and production features

**Total Timeline**: 21 weeks to v1.0.0 (updated with security hardening: 65-70 weeks)

See [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) for detailed timeline.

## Legal & Compliance

**IMPORTANT**: This software performs TLS interception (MITM). You MUST:

1. Only use on networks you own/administer
2. Obtain informed consent from all affected users
3. Comply with applicable wiretapping laws (ECPA, CFAA in US)
4. Display privacy notices and user consent mechanisms
5. Not use for malicious purposes (unauthorized surveillance, data theft)

See `docs/LEGAL.md` for full compliance requirements.

## Contributing

Contributions are welcome! Please:

1. Read `CONTRIBUTING.md`
2. Open an issue for major changes
3. Follow Rust style guidelines (`cargo fmt`, `cargo clippy`)
4. Add tests for new features
5. Update documentation

## License

Proprietary. All rights reserved. Not licensed for redistribution.

## Security

Report security vulnerabilities to: security@example.com

See `docs/SECURITY.md` for our security policy.

## Acknowledgments

- [Brave's adblock-rust](https://github.com/brave/adblock-rust) - Core adblocking engine
- [Boa](https://github.com/boa-dev/boa) - JavaScript engine
- [Tokio](https://tokio.rs) - Async runtime
- [Hyper](https://hyper.rs) - HTTP implementation
- [tokio-tungstenite](https://github.com/snapview/tokio-tungstenite) - WebSocket implementation

## Status

**Current Version**: v0.3.0 (Alpha)

- ✅ **Phase 1 Complete**: HTTP/1.1, HTTP/2, MITM, Docker deployment
- ✅ **Phase 2 Complete**: WebSocket support (HTTP/3 server removed; `Alt-Svc` stripped instead)
- 🚧 **Phase 3 In Progress**: Adblocking engine (Core filter engine complete, Week 8/12)
- 📅 **Phase 4 Planned**: Userscript execution
- 📅 **Phase 5 Planned**: Web management UI

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
- HTTP/3 and QUIC support (optional feature flag, disabled by default)
- Concurrent UDP (HTTP/3) and TCP (HTTP/1.1, HTTP/2) listeners
- WebSocket proxying with bidirectional frame forwarding (optional feature flag, enabled by default)

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
- ✅ Scriptlet injection (`#%#`, `#@%#`)
  - JavaScript injection for complex filtering scenarios
  - Built-in scriptlet library (abort-on-property-read, set-constant, remove-class, etc.)
  - AdGuard and uBlock Origin syntax compatibility
  - Exception rules for disabling scriptlets

### Userscript Engine (Phase 4 - v0.4.0)
- Greasemonkey-compatible userscript execution
- Boa JavaScript engine with V8-level sandboxing
- GM_* API support (storage, XHR, DOM manipulation)
- Process-level isolation with bubblewrap + seccomp-bpf
- 30-second timeout enforcement

### Web Management UI (Phase 5 - v1.0.0)
- Leptos-based WebUI on port 8081
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
- Rust 1.85+ (2021 edition)
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

# Build with HTTP/3 support
cargo build --release --features http3

# Build with all features (HTTP/3, WebSockets, and Adblocking)
cargo build --release --features "http3,websockets,adblock"

# Run the proxy
./target/release/adblocker
```

### Docker Deployment

```bash
# Build the image
docker build -t adblocker .

# Run with docker-compose
docker-compose up -d
```

### Install Root CA Certificate

1. Start the proxy and navigate to `http://localhost:8081`
2. Download the root CA certificate
3. Install it in your browser/system:
   - **Chrome/Edge**: Settings > Privacy and security > Security > Manage certificates
   - **Firefox**: Settings > Privacy & Security > Certificates > View Certificates > Authorities > Import
   - **macOS**: Keychain Access > System > Import
   - **Linux**: `sudo cp root-ca.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates`

### Configure Browser Proxy

Set your browser to use the proxy:
- **HTTP Proxy**: `localhost:8080`
- **HTTPS Proxy**: `localhost:8080`
- **SOCKS Proxy**: Not supported

## Configuration

Edit `config/default.toml`:

```toml
[proxy]
host = "0.0.0.0"
port = 8080
max_connections = 10000
enable_http2 = true
enable_http3 = false      # Requires building with --features http3
enable_websockets = true  # Requires building with --features websockets

[mitm]
enabled = true  # Required for HTTP/3
ca_cert_path = "certs/root-ca.crt"
ca_key_path = "certs/root-ca.key"
cert_cache_size = 1000

[adblock]
enabled = false           # Requires building with --features adblock
data_dir = "data/filters"
auto_update = true
update_interval_hours = 24

[filters]
enabled = true
auto_update = true
update_interval_hours = 24

[userscripts]
enabled = true
auto_update = true
script_timeout_secs = 30
max_concurrent_isolates = 10

[webui]
enabled = true
port = 8081
username = "admin"
password_hash = "$2b$12$..."  # Generate with: bcrypt-cli hash "your-password"
```

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

# Security headers cannot be removed (Content-Length, Set-Cookie, etc.)
```

**Restricted headers** (cannot be removed for security):
- Content-Length, Content-Encoding, Transfer-Encoding
- Cookie, Set-Cookie, Authorization
- Access-Control-*, Origin, Content-Security-Policy
- And 20+ others (see source code for full list)

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
- Maximum response size: 10 MB
- Rules from trusted filters only

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

## Project Structure

```
adblocker/
├── Cargo.toml                      # Workspace manifest
├── crates/
│   ├── proxy-core/                 # Core proxy server
│   ├── proxy-http3/                # HTTP/3 and WebSocket
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

Dual-licensed under MIT or Apache-2.0. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).

## Security

Report security vulnerabilities to: security@example.com

See `docs/SECURITY.md` for our security policy.

## Acknowledgments

- [Brave's adblock-rust](https://github.com/brave/adblock-rust) - Core adblocking engine
- [Boa](https://github.com/boa-dev/boa) - JavaScript engine
- [Tokio](https://tokio.rs) - Async runtime
- [Hyper](https://hyper.rs) - HTTP implementation
- [Quinn](https://github.com/quinn-rs/quinn) - QUIC implementation
- [h3](https://github.com/hyperium/h3) - HTTP/3 protocol
- [tokio-tungstenite](https://github.com/snapview/tokio-tungstenite) - WebSocket implementation

## Status

**Current Version**: v0.3.0 (Alpha)

- ✅ **Phase 1 Complete**: HTTP/1.1, HTTP/2, MITM, Docker deployment
- ✅ **Phase 2 Complete**: HTTP/3, QUIC, and WebSocket support (optional features)
- 🚧 **Phase 3 In Progress**: Adblocking engine (Core filter engine complete, Week 8/12)
- 📅 **Phase 4 Planned**: Userscript execution
- 📅 **Phase 5 Planned**: Web management UI

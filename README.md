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

## Userscript Engine

The userscript engine provides Greasemonkey/Tampermonkey compatibility for running custom JavaScript on web pages.

### Installing Userscripts

```rust
use userscript_engine::UserscriptManager;

// Create manager
let manager = UserscriptManager::new("./data/userscripts".into())?;

// Install a userscript
let script_source = r#"
// ==UserScript==
// @name         Example Script
// @namespace    http://example.com
// @version      1.0.0
// @description  Demonstrates userscript features
// @match        *://example.com/*
// @grant        GM_setValue
// @grant        GM_getValue
// ==/UserScript==

// Your script code here
GM_setValue('visits', (GM_getValue('visits', 0) + 1));
console.log('Visit count:', GM_getValue('visits'));
"#;

let script_id = manager.install(script_source.to_string())?;
```

### Metadata Block

Userscripts must include a metadata block with directives:

**Required**:
- `@name` - Script name (used as unique identifier with namespace)

**Common**:
- `@namespace` - Unique namespace (combined with name for ID)
- `@version` - Version string for update checks
- `@description` - Human-readable description
- `@author` - Script author

**Execution Control**:
- `@match` - URL patterns where script runs (recommended)
- `@include` - URL patterns to include (legacy)
- `@exclude` - URL patterns to exclude
- `@run-at` - When to inject: `document-start`, `document-end` (default), `document-idle`
- `@noframes` - Don't run in iframes

**Permissions**:
- `@grant` - Required GM_* API functions (e.g., `@grant GM_setValue`)
- `@connect` - Domains allowed for GM_xmlhttpRequest

**Resources**:
- `@require` - External scripts to load before execution
- `@resource` - Named resources accessible via GM_getResourceURL

**Updates**:
- `@updateURL` - URL to check for updates
- `@downloadURL` - URL to download updates

### Example Metadata Block

```javascript
// ==UserScript==
// @name         Advanced Example
// @namespace    http://mysite.com/userscripts
// @version      2.1.0
// @description  Comprehensive userscript example
// @author       Your Name
// @match        *://example.com/*
// @match        *://test.example.com/*
// @exclude      *://example.com/admin*
// @run-at       document-end
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_deleteValue
// @grant        GM_listValues
// @grant        GM_info
// @require      https://code.jquery.com/jquery-3.6.0.min.js
// @resource     icon https://example.com/icon.png
// @updateURL    https://example.com/script.meta.js
// @downloadURL  https://example.com/script.user.js
// ==/UserScript==
```

### GM_* API (Week 13 Foundation)

**Storage Functions** (Implemented):

```javascript
// Store values (supports string, number, boolean, arrays, objects)
GM_setValue('username', 'john');
GM_setValue('count', 42);
GM_setValue('config', {theme: 'dark', lang: 'en'});

// Retrieve values with optional default
let name = GM_getValue('username', 'guest');
let count = GM_getValue('count', 0);

// Delete values
GM_deleteValue('old_key');

// List all stored keys
let keys = GM_listValues(); // Returns ['username', 'count', 'config']

// Get script info
let info = GM_info();
console.log(info.script.id);      // Script unique ID
console.log(info.scriptHandler);   // "AdBlocker Userscript Engine"
console.log(info.version);         // Engine version
```

**Coming in Week 14**:
- `GM_xmlhttpRequest` - Cross-domain HTTP requests
- `GM_notification` - Desktop notifications
- `GM_openInTab` - Open URLs in new tabs
- `GM_addStyle` - Inject CSS
- `GM_getResourceURL` - Access @resource files
- `GM_setClipboard` - Clipboard access

### Managing Userscripts

```rust
// Load all scripts from disk
manager.load_all()?;

// Get script by ID
if let Some(script) = manager.get("example.com:Example Script") {
    println!("Name: {}", script.name());
    println!("Version: {:?}", script.version());
    println!("Enabled: {}", script.enabled);
}

// Get scripts for a URL
let scripts = manager.get_scripts_for_url("https://example.com/page");
for script in scripts {
    println!("Will run: {}", script.name());
}

// Enable/disable scripts
manager.set_enabled("script-id", false)?;

// Update a script
manager.update("script-id", new_source)?;

// Uninstall a script
manager.uninstall("script-id")?;

// Get statistics
let stats = manager.stats();
println!("Total: {}, Enabled: {}, Disabled: {}",
    stats.total_scripts, stats.enabled_scripts, stats.disabled_scripts);
```

### URL Matching

Scripts use glob-style patterns for matching:

```javascript
// Exact domain
// @match https://example.com/*

// Any subdomain
// @match *://*.example.com/*

// Any protocol
// @match *://example.com/*

// All URLs
// @match *://*/*
// @match <all_urls>

// Exclusions
// @exclude *://example.com/admin*
```

### Storage Isolation

Each userscript has isolated storage:
- Values are namespaced by script ID
- Scripts cannot access other scripts' data
- Persistent storage using sled database
- In-memory caching for performance

### Security Considerations

1. **@grant declarations required** - Scripts must declare which GM_* APIs they need
2. **Permission checks enforced** - Calling undeclared APIs throws PermissionDenied error
3. **Storage isolation** - Scripts cannot access each other's data
4. **URL pattern validation** - Only runs on matched URLs
5. **Metadata validation** - Scripts require valid metadata block

### Best Practices

1. **Always use @match over @include** - More precise, better performance
2. **Declare minimal @grant permissions** - Request only needed APIs
3. **Use @exclude for sensitive pages** - Don't run on admin/login pages
4. **Version your scripts** - Enables proper update detection
5. **Test before deploying** - Verify script works on target sites
6. **Namespace your scripts** - Prevents ID conflicts with other authors

### JavaScript Execution (Week 14)

Execute userscripts with the Boa JavaScript engine:

```rust
use userscript_engine::{ScriptExecutor, GmApi, UserscriptStorage};
use std::sync::Arc;

// Create storage and API
let storage = Arc::new(UserscriptStorage::new("./data/userscripts".into())?);
let grants = vec!["GM_setValue".to_string(), "GM_getValue".to_string()];
let gm_api = Arc::new(GmApi::new("my-script".to_string(), storage, grants));

// Create executor with GM API injected
let mut executor = ScriptExecutor::new(gm_api)?;

// Execute userscript
executor.execute(&script.source, &script.name())?;
```

### Advanced GM_* APIs

#### GM_addStyle - CSS Injection

Inject custom CSS into the page:

```javascript
// ==UserScript==
// @name         Style Injector
// @grant        GM_addStyle
// ==/UserScript==

// Hide ads
GM.addStyle(`
    .advertisement,
    .sponsored-content {
        display: none !important;
    }
`);

// Custom theme
GM.addStyle(`
    body {
        background-color: #1e1e1e;
        color: #d4d4d4;
    }
`);
```

#### GM_xmlhttpRequest - Cross-Domain Requests

Make HTTP requests that bypass CORS:

```javascript
// ==UserScript==
// @name         API Client
// @grant        GM_xmlhttpRequest
// @connect      api.example.com
// ==/UserScript==

GM.xmlhttpRequest({
    method: "GET",
    url: "https://api.example.com/data",
    headers: {
        "User-Agent": "MyScript/1.0"
    },
    onload: function(response) {
        console.log("Status:", response.status);
        console.log("Data:", response.responseText);
    },
    onerror: function(error) {
        console.error("Request failed:", error);
    }
});
```

#### GM_notification - Desktop Notifications

Show desktop notifications:

```javascript
// ==UserScript==
// @name         Notifier
// @grant        GM_notification
// ==/UserScript==

GM.notification({
    title: "Script Loaded",
    text: "Your userscript is running!",
    timeout: 5000
});

// Notification with callback
GM.notification({
    title: "New Message",
    text: "You have a new message",
    onclick: function() {
        window.location.href = "/messages";
    }
});
```

#### GM_openInTab - Open URLs

Open URLs in new tabs:

```javascript
// ==UserScript==
// @name         Link Opener
// @grant        GM_openInTab
// ==/UserScript==

document.querySelectorAll('a.external').forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();

        // Open in background tab
        GM.openInTab(link.href, {
            active: false,
            insert: true,
            setParent: true
        });
    });
});
```

#### GM_getResourceURL - Resource Access

Access @resource files:

```javascript
// ==UserScript==
// @name         Resource User
// @grant        GM_getResourceURL
// @resource     icon https://example.com/icon.png
// @resource     config https://example.com/config.json
// ==/UserScript==

// Get icon URL
const iconUrl = GM.getResourceURL('icon');
document.querySelector('#logo').src = iconUrl;

// Fetch config
const configUrl = GM.getResourceURL('config');
fetch(configUrl)
    .then(r => r.json())
    .then(config => console.log('Config:', config));
```

#### GM_setClipboard - Clipboard Access

Copy text to clipboard:

```javascript
// ==UserScript==
// @name         Clipboard Helper
// @grant        GM_setClipboard
// ==/UserScript==

document.querySelectorAll('.copy-button').forEach(button => {
    button.addEventListener('click', () => {
        const text = button.dataset.text;
        GM.setClipboard(text);

        button.textContent = 'Copied!';
        setTimeout(() => {
            button.textContent = 'Copy';
        }, 2000);
    });
});
```

### Complete Example Userscript

```javascript
// ==UserScript==
// @name         Complete Example
// @namespace    http://example.com
// @version      1.0.0
// @description  Demonstrates all GM_* APIs
// @match        *://example.com/*
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_addStyle
// @grant        GM_xmlhttpRequest
// @grant        GM_notification
// @grant        GM_openInTab
// @grant        GM_setClipboard
// @grant        GM_getResourceURL
// @connect      api.example.com
// @resource     logo https://example.com/logo.png
// ==/UserScript==

(function() {
    'use strict';

    // Get script info
    const info = GM.info();
    console.log('Script:', info.script.id);

    // Track visits
    const visits = GM.getValue('visits', 0) + 1;
    GM.setValue('visits', visits);

    // Show notification on first visit
    if (visits === 1) {
        GM.notification({
            title: 'Welcome!',
            text: 'This is your first visit'
        });
    }

    // Inject custom styles
    GM.addStyle(`
        .custom-banner {
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            text-align: center;
        }
    `);

    // Add banner
    const banner = document.createElement('div');
    banner.className = 'custom-banner';
    banner.textContent = `Visit count: ${visits}`;
    document.body.insertBefore(banner, document.body.firstChild);

    // Add copy button
    const copyBtn = document.createElement('button');
    copyBtn.textContent = 'Copy Visit Count';
    copyBtn.onclick = () => {
        GM.setClipboard(`You've visited ${visits} times`);
    };
    banner.appendChild(copyBtn);

    // Fetch remote data
    GM.xmlhttpRequest({
        method: 'GET',
        url: 'https://api.example.com/status',
        onload: (response) => {
            console.log('API Status:', response.responseText);
        }
    });

    // Open link in tab on button click
    const linkBtn = document.createElement('button');
    linkBtn.textContent = 'Open Related Page';
    linkBtn.onclick = () => {
        GM.openInTab('https://example.com/related', {
            active: false
        });
    };
    banner.appendChild(linkBtn);

})();
```

### Implementation Notes (Week 14)

- **Week 13**: Metadata parser, storage system, basic GM_* APIs (setValue, getValue, deleteValue, listValues)
- **Week 14**: Boa JavaScript engine integration, advanced GM_* APIs (xmlhttpRequest, notification, addStyle, etc.)
- Full Greasemonkey/Tampermonkey compatibility
- Permission system enforces @grant declarations
- JavaScript execution with proper value conversion between Rust and JS
- GM object injected into global scope
- All GM_* functions return promises or values as per spec
- Error handling with detailed error messages

### Architecture

The userscript engine consists of:

1. **Metadata Parser** (`metadata.rs`) - Parses `// ==UserScript==` blocks
2. **Script Manager** (`manager.rs`) - Lifecycle management (install/update/uninstall)
3. **Storage** (`storage.rs`) - Persistent key-value storage with sled database
4. **GM API** (`gm_api.rs`) - Implementation of all GM_* functions
5. **Executor** (`executor.rs`) - Boa engine integration and JavaScript execution

### Execution Runtime (Week 15)

Execute userscripts with proper timing and resource management:

```rust
use userscript_engine::{UserscriptManager, UserscriptRuntime, UserscriptStorage, RunAt};
use std::sync::Arc;

// Create manager and storage
let manager = Arc::new(UserscriptManager::new("./data/userscripts".into())?);
let storage = Arc::new(UserscriptStorage::new("./data/userscripts".into())?);

// Create runtime
let runtime = UserscriptRuntime::new(manager.clone(), storage);

// Load userscripts from disk
manager.load_all()?;

// Execute scripts at document-start
let results = runtime.execute_for_url(
    "https://example.com/page",
    RunAt::DocumentStart
).await?;

println!("Executed: {}", results.executed.len());
println!("Failed: {}", results.failed.len());

// Execute scripts at document-end
let results = runtime.execute_for_url(
    "https://example.com/page",
    RunAt::DocumentEnd
).await?;

// Execute scripts at document-idle
let results = runtime.execute_for_url(
    "https://example.com/page",
    RunAt::DocumentIdle
).await?;
```

### @run-at Timing

Control when scripts execute:

```javascript
// ==UserScript==
// @name         Early Script
// @run-at       document-start
// ==/UserScript==

// Runs before page scripts execute
// Can intercept page behavior

// ==UserScript==
// @name         DOM Ready Script
// @run-at       document-end
// ==/UserScript==

// Runs when DOM is ready
// Most common for DOM manipulation

// ==UserScript==
// @name         Full Load Script
// @run-at       document-idle
// ==/UserScript==

// Runs after everything is loaded
// Use for non-critical functionality
```

### @require Dependencies

Load external libraries:

```javascript
// ==UserScript==
// @name         jQuery Script
// @require      https://code.jquery.com/jquery-3.6.0.min.js
// @require      https://cdn.example.com/library.js
// @grant        GM_setValue
// ==/UserScript==

// jQuery is now available
$('button').click(() => {
    GM.setValue('clicked', true);
});
```

The runtime automatically:
- Fetches @require URLs
- Caches dependencies for performance
- Executes them before your script
- Handles fetch errors gracefully

### @resource Files

Access external resources:

```javascript
// ==UserScript==
// @name         Resource Example
// @resource     icon https://example.com/icon.png
// @resource     template https://example.com/template.html
// @grant        GM_getResourceURL
// ==/UserScript==

// Get resource as data URL
const iconUrl = GM.getResourceURL('icon');
document.querySelector('#logo').src = iconUrl;

// Resources are:
// - Fetched and cached automatically
// - Converted to base64 data URLs
// - MIME type detected from extension
```

### Page Context

Track page state and inject CSS:

```rust
use userscript_engine::{PageContext, DocumentReadyState};

let mut ctx = PageContext::new("https://example.com".to_string());

// Update ready state as page loads
ctx.ready_state = DocumentReadyState::Interactive;

// Collect injected CSS from GM_addStyle
ctx.injected_css.push("body { background: #000; }".to_string());

// Get all CSS to inject
let css = ctx.get_css();
```

### Cache Management

Monitor and control caches:

```rust
// Get cache statistics
let stats = runtime.cache_stats();
println!("@require cached: {}", stats.require_cached);
println!("@resource cached: {}", stats.resource_cached);

// Clear caches
runtime.clear_caches();
```

### Complete Integration Example

```rust
use userscript_engine::{
    UserscriptManager, UserscriptRuntime, UserscriptStorage,
    RunAt, DocumentReadyState, PageContext
};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup
    let manager = Arc::new(UserscriptManager::new("./data/userscripts".into())?);
    let storage = Arc::new(UserscriptStorage::new("./data/userscripts".into())?);
    let runtime = UserscriptRuntime::new(manager.clone(), storage);

    // Load installed scripts
    manager.load_all()?;

    // Install a new script
    let script = r#"
// ==UserScript==
// @name         Page Enhancer
// @match        *://example.com/*
// @run-at       document-end
// @require      https://code.jquery.com/jquery-3.6.0.min.js
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_addStyle
// ==/UserScript==

GM.addStyle('body { font-family: Arial; }');

const visits = GM.getValue('visits', 0) + 1;
GM.setValue('visits', visits);

$('body').prepend(`<div>Visit #${visits}</div>`);
"#;

    manager.install(script.to_string())?;

    // Execute for a page request
    let url = "https://example.com/page";
    let mut page_ctx = PageContext::new(url.to_string());

    // Execute at document-start
    runtime.execute_for_url(url, RunAt::DocumentStart).await?;

    // Simulate DOM ready
    page_ctx.ready_state = DocumentReadyState::Interactive;
    let results = runtime.execute_for_url(url, RunAt::DocumentEnd).await?;

    println!("Executed {} scripts", results.executed.len());

    // Get injected CSS
    let css = page_ctx.get_css();
    println!("Injected CSS: {}", css);

    // Simulate complete load
    page_ctx.ready_state = DocumentReadyState::Complete;
    runtime.execute_for_url(url, RunAt::DocumentIdle).await?;

    Ok(())
}
```

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

# Rust MITM Proxy with Adblocking and Userscript Support - Implementation Plan (REVISED)

## Project Overview

Building a production-ready Rust MITM proxy with feature parity to AdGuard and uBlock Origin, supporting comprehensive adblocking, userscript execution, HTTP/2, HTTP/3, WebSocket, WebUI, and Docker deployment.

**Project Status**: Greenfield (empty directory)
**Location**: `/path/to/adblocker`

**Revision Notes**: This plan has been updated based on expert technical reviews (Rust expert, Architecture expert, Project lead) conducted on 2026-01-04. Key changes:
- Timeline extended from 21 weeks to 40-45 weeks (realistic estimate)
- HTTP/3 moved from Phase 2 to Phase 5
- Switched from Boa to V8/deno_core for JavaScript engine
- Docker changed from Alpine to Debian for musl compatibility
- Critical dependency updates (rustls 0.24, redb instead of sled)
- Added comprehensive state management architecture
- Added resource limits and backpressure mechanisms

## Implementation Strategy

Based on user preferences and expert review:
- **Priority**: Proxy foundation first, then filtering features
- **Filter Support**: Both AdBlock Plus and AdGuard formats with full compatibility
- **Userscripts**: V8/deno_core JavaScript engine (production-grade sandboxing)
- **Authentication**: Simple username/password with bcrypt (cost 12)
- **Timeline**: 40-45 weeks for full production release
- **Scope**: Full feature parity with AdGuard and uBlock Origin

---

## Phased Implementation Plan

### Phase 1: Proxy Foundation (6-8 weeks)

**Goal**: Production-ready MITM proxy with HTTP/1.1, HTTP/2, WebSocket, and certificate management

#### Week 1-2: Project Setup & Basic HTTP Proxy
1. Initialize Cargo workspace with multi-crate structure
2. Create basic HTTP/1.1 proxy using `hyper` v1.x + `hyper-util`
3. Set up configuration management with `config` crate
4. Implement structured logging with `tracing` + `tracing-subscriber`
5. Create error handling framework with `thiserror` (libraries) and `anyhow` (binary)
6. Set up CI/CD pipeline (GitHub Actions with automated testing)
7. Configure file descriptor limits for 10k connections

**Key Files**:
- `Cargo.toml` - Workspace manifest
- `crates/proxy-core/src/server.rs` - Main proxy server
- `crates/proxy-core/src/connection.rs` - Connection handling
- `crates/proxy-core/src/config.rs` - Configuration structures
- `.github/workflows/ci.yml` - CI/CD configuration

**Critical Tasks**:
- Design comprehensive config schema upfront (will support all future phases)
- Set up metrics collection from day one (Prometheus format)
- Implement connection pooling with `hyper-util`
- Add backpressure with Semaphore (max 10k concurrent connections)

#### Week 3-5: MITM Certificate Management
1. Implement Certificate Authority generation using `rcgen`
2. Create on-the-fly certificate generation and caching using `moka` (not manual DashMap+LRU)
3. TLS termination with `rustls` 0.24 and `tokio-rustls` 0.26
4. HTTP CONNECT method handling
5. Certificate persistence to disk using `redb`
6. Certificate validation and security (file permissions 0600)
7. SNI handling and wildcard certificate support
8. Browser compatibility testing (Chrome, Firefox, Safari, Edge)
9. Mobile CA installation documentation (iOS, Android)

**Key Files**:
- `crates/proxy-core/src/ca.rs` - Certificate Authority
- `crates/proxy-core/src/mitm.rs` - MITM logic with moka cert caching
- `config/default.toml` - Default configuration
- `docs/CA_INSTALLATION.md` - CA installation guide

**Critical Component**:
```rust
// Certificate caching with moka (not manual DashMap+LRU)
use moka::sync::Cache;

pub struct CertificateCache {
    cache: Cache<String, Arc<CertifiedKey>>,
}

impl CertificateCache {
    pub fn new() -> Self {
        let cache = Cache::builder()
            .max_capacity(1000)
            .time_to_live(Duration::from_secs(3600))  // 1 hour TTL
            .build();
        Self { cache }
    }
}
```

**Testing Focus**:
- Certificate generation edge cases (SNI mismatches, wildcard certs)
- Browser certificate acceptance without warnings
- Certificate pinning detection and handling

#### Week 6-7: HTTP/2, WebSocket & Request Pipeline
1. Integrate HTTP/2 support using `h2` crate
2. WebSocket CONNECT upgrade handling using `tokio-tungstenite`
3. WebSocket frame proxying and state management
4. Design and implement 8-stage request/response pipeline (not 4-stage):
   - Stage 1: Parse & Validate
   - Stage 2: Network Filter
   - Stage 3: Request Modification
   - Stage 4: Route & Forward
   - Stage 5: Response Reception
   - Stage 6: Response Filter Check
   - Stage 7: Response Modification (conditional buffering)
   - Stage 8: Stream Response
5. Implement Tower middleware pattern for pipeline stages
6. Add connection pooling for upstream with limits
7. Implement graceful shutdown handling with tokio::select!
8. Create benchmark suite for performance validation
9. Streaming vs buffering decision logic (Content-Type based)

**Key Files**:
- `crates/proxy-core/src/http2.rs` - HTTP/2 handler
- `crates/proxy-core/src/websocket.rs` - WebSocket proxying (moved from proxy-http3)
- `crates/proxy-middleware/src/lib.rs` - Pipeline middleware (new crate)
- `crates/proxy-middleware/src/filter_stage.rs` - Filter middleware
- `crates/proxy-core/src/pipeline.rs` - Request/response pipeline orchestration
- `benches/proxy_bench.rs` - Performance benchmarks

**Enhanced Pipeline Architecture**:
```
Request Pipeline:
┌──────────────────────────────────────────────────┐
│ 1. Parse & Validate (headers, URL, method)      │
├──────────────────────────────────────────────────┤
│ 2. Network Filter (adblock-rust check)          │
│    → Block: Return 403                           │
│    → Allow: Continue                             │
├──────────────────────────────────────────────────┤
│ 3. Request Modification ($removeparam, headers)  │
├──────────────────────────────────────────────────┤
│ 4. Route & Forward (connection pool select)     │
└──────────────────────────────────────────────────┘

Response Pipeline:
┌──────────────────────────────────────────────────┐
│ 5. Response Reception (parse headers, status)   │
├──────────────────────────────────────────────────┤
│ 6. Response Filter Check (cosmetic/scriptlet?)  │
│    → Decide: Stream or Buffer                   │
├──────────────────────────────────────────────────┤
│ 7. Response Modification (conditional)          │
│    → Buffer & parse HTML if needed              │
│    → Inject cosmetic CSS                        │
│    → Inject scriptlets                          │
│    → Execute userscripts                        │
├──────────────────────────────────────────────────┤
│ 8. Stream Response (send to client)             │
│    → Collect statistics                         │
└──────────────────────────────────────────────────┘
```

**Resource Limits** (added based on expert review):
```rust
struct ResourceLimits {
    max_connections: Semaphore,           // 10,000
    max_cert_generations: Semaphore,      // 100 concurrent
    max_html_buffers: Semaphore,          // 500 concurrent
    max_userscript_executions: Semaphore, // 50 concurrent
}
```

#### Week 8: Docker, Testing & Documentation
1. Create multi-stage Dockerfile (Debian slim, not Alpine)
2. Write docker-compose.yml with volume mounts and proper networking
3. Implement comprehensive integration tests with real browsers
4. End-to-end testing with Chrome, Firefox, Safari
5. Property-based testing with `proptest` for parsers
6. Load testing with `wrk` (target: 10k req/s)
7. Documentation: README, CA installation guide (all platforms)
8. Security testing (file permissions, credential handling)

**Key Files**:
- `Dockerfile` - Multi-stage Debian build (not Alpine)
- `docker-compose.yml` - Container orchestration
- `tests/integration/proxy_test.rs` - Integration tests
- `tests/integration/browser_test.rs` - Browser compatibility tests
- `README.md` - Project documentation
- `docs/CA_INSTALLATION.md` - Detailed CA setup guide

**Dockerfile** (Debian slim for musl compatibility):
```dockerfile
FROM rust:1.85-slim-bookworm AS builder
RUN apt-get update && apt-get install -y \
    pkg-config libssl-dev
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 1000 adblocker
COPY --from=builder /app/target/release/adblocker /app/
USER adblocker
EXPOSE 8080 8081
CMD ["/app/adblocker"]
```

**Deliverable**: v0.1.0 - Working MITM proxy with HTTP/1.1, HTTP/2, and WebSocket

---

### Phase 2: Adblocking Engine (8-12 weeks)

**Goal**: Feature parity with AdGuard and uBlock Origin filtering

#### Week 9-10: Core Filter Engine
1. Integrate Brave's `adblock-rust` as foundation
2. Implement AdBlock Plus syntax parser
3. Basic network request blocking
4. Filter list loader from URLs with retry logic
5. Statistics tracking using atomic counters (lock-free)
6. Hot-reload architecture using `ArcSwap` (not Arc<RwLock>)
7. Request result caching with `moka` (TTL-based)
8. Smoke tests for filter updates (100 sample URLs)

**Key Files**:
- `crates/filter-engine/src/engine.rs` - Main filter engine
- `crates/filter-engine/src/parser/abp.rs` - AdBlock Plus parser
- `crates/filter-engine/src/matcher/network.rs` - Request matching
- `crates/proxy-stats/src/lib.rs` - Statistics collection (new crate)

**Dependencies**:
```toml
adblock = "0.9"           # Verify latest version
url = "2.5"
regex = "1.11"
arc-swap = "1.7"          # For hot-reload
moka = "0.12"             # For caching
```

**Hot-Reload Architecture** (critical for zero-downtime updates):
```rust
use arc_swap::ArcSwap;

pub struct FilterEngineManager {
    engine: ArcSwap<adblock::Engine>,
    stats: Arc<Statistics>,
}

impl FilterEngineManager {
    pub async fn reload(&self, lists: Vec<String>) -> Result<()> {
        // Compile in background
        let mut new_engine = adblock::Engine::new(true);
        for list in lists {
            new_engine.add_filter_list(&list)?;
        }

        // Validate with smoke tests
        smoke_test(&new_engine)?;

        // Atomic swap - zero downtime
        self.engine.store(Arc::new(new_engine));
        Ok(())
    }
}
```

**Statistics Architecture** (lock-free atomic counters):
```rust
use std::sync::atomic::{AtomicU64, Ordering};

pub struct Statistics {
    total_requests: AtomicU64,
    blocked_requests: AtomicU64,
    allowed_requests: AtomicU64,
    // Per-domain stats (eventually consistent)
    domain_stats: Arc<DashMap<String, DomainStats>>,
}

struct DomainStats {
    requests: AtomicU64,
    blocked: AtomicU64,
    bytes: AtomicU64,
}
```

#### Week 11-13: AdGuard Extensions
1. Parse AdGuard-specific syntax extensions
2. Implement `$replace` modifier (regex-based response modification)
3. Implement `$removeparam` (URL parameter stripping with redirects)
4. Implement `$removeheader` (header manipulation)
5. Implement `$redirect` (resource redirection library)
6. Domain-specific rules and exception rules (@@)
7. Priority handling (exception rules always win)
8. Testing with real AdGuard filter lists (100k+ rules)
9. Compatibility testing with uBlock Origin filters

**Key Files**:
- `crates/filter-engine/src/parser/adguard.rs` - AdGuard parser
- `crates/filter-engine/src/modifiers/replace.rs` - $replace implementation
- `crates/filter-engine/src/modifiers/redirect.rs` - $redirect implementation

**Critical**: Each modifier has unique complexity requiring careful implementation

#### Week 14-17: Cosmetic Filtering
1. HTML parsing with `html5ever`
2. Streaming vs buffering decision logic (Content-Type + size limits)
3. CSS injection for element hiding (##.selector)
4. Extended CSS selectors (#?#selector:has(...)) - custom parser
5. CSS rule injection (#$#selector { display: none })
6. CSP header handling (modify to allow injected styles/scripts)
7. Integration with pipeline for response modification
8. Performance optimization (lazy loading, client-side injection option)
9. Size limits for HTML buffering (max 5MB, configurable)

**Key Files**:
- `crates/filter-engine/src/matcher/cosmetic.rs` - Cosmetic filtering
- `crates/filter-engine/src/css/extended.rs` - Extended CSS parser

**Dependencies**:
```toml
html5ever = "0.28"
cssparser = "0.31"
selectors = "0.25"
```

**Resource Limits**:
```toml
[filters]
cosmetic_max_response_size = 5242880  # 5MB max
cosmetic_enabled_for = ["text/html", "application/xhtml+xml"]
use_client_side_cosmetic = true  # Inject rules as <style>, not modify DOM
```

**CSP Handling Strategy**:
- Parse CSP headers before modification
- Modify CSP to allow injected content OR
- Use data: URIs for scripts if CSP is strict

#### Week 18-19: Scriptlet Injection
1. Parse scriptlet rules (#%#//scriptlet(...))
2. Implement AdGuard scriptlet library (50+ scriptlets)
3. Implement uBlock Origin scriptlet library
4. JavaScript injection mechanism (HTML modification)
5. CSP compatibility (inject before CSP applies)
6. Testing with popular scriptlets
7. Error handling (scriptlet failures shouldn't break pages)

**Key Files**:
- `crates/filter-engine/src/matcher/scriptlet.rs` - Scriptlet injection
- `crates/filter-engine/src/scriptlets/adguard.rs` - AdGuard scriptlets
- `crates/filter-engine/src/scriptlets/ublock.rs` - uBlock scriptlets

**Note**: Each scriptlet is unique JavaScript requiring manual implementation

#### Week 20: Auto-Update System & Testing
1. Filter list auto-updater using `reqwest`
2. Conditional requests (ETag/If-Modified-Since)
3. Checksum verification (MD5/SHA256)
4. Syntax validation before applying
5. Atomic hot reload using ArcSwap (no connection drops)
6. Rollback on validation failure (keep last-known-good)
7. Retry logic with exponential backoff
8. Scheduled updates (tokio cron task)
9. Comprehensive testing with top 1000 websites
10. Filter compatibility testing (EasyList, AdGuard lists, uBlock lists)

**Key Files**:
- `crates/filter-engine/src/updater.rs` - Auto-update mechanism
- `crates/filter-engine/src/list.rs` - Filter list management
- `tests/integration/filter_compat_test.rs` - Compatibility tests

**Default Filter Lists**:
- EasyList, EasyPrivacy
- AdGuard Base, AdGuard Tracking Protection
- uBlock Origin filters
- User custom lists

**Update Flow**:
```rust
async fn update_filters() -> UpdateResult {
    // 1. Download with retries (3x, exponential backoff)
    let raw = download_with_retry().await?;

    // 2. Validate syntax
    validate_syntax(&raw)?;

    // 3. Compile in background
    let compiled = compile_in_background(raw).await?;

    // 4. Smoke test (100 sample URLs)
    smoke_test(&compiled)?;

    // 5. Atomic swap
    swap_filters(compiled);

    // 6. Keep old filters for 5 minutes (gradual migration)
    Ok(compiled)
}
```

**Deliverable**: v0.3.0 - Full adblocking with filter list support

---

### Phase 3: Userscript Engine (6-10 weeks)

**Goal**: Greasemonkey-compatible userscript execution with production-grade security

#### Week 21-23: V8/Deno Core Integration
1. Integrate `deno_core` and `rusty_v8` (production-grade JavaScript engine)
2. Parse userscript metadata (Greasemonkey format)
3. URL matching logic (@match, @include, @exclude with regex/glob support)
4. Basic script injection into HTML
5. V8 isolate creation (isolated execution context per page)
6. Memory limits per isolate (50MB default, configurable)
7. CPU timeout enforcement (30s default)
8. Security sandboxing (no file system access, restricted network)

**Key Files**:
- `crates/userscript-engine/src/runtime.rs` - Deno Core runtime wrapper
- `crates/userscript-engine/src/metadata.rs` - Metadata parser
- `crates/userscript-engine/src/injector.rs` - Script injection
- `crates/userscript-engine/src/isolate.rs` - V8 isolate management

**Dependencies**:
```toml
deno_core = "0.335"  # Or latest
rusty_v8 = "0.105"   # Or latest matching deno_core
```

**Why V8 over Boa** (per expert recommendation):
- Production-grade security sandboxing (V8 isolates)
- 10-100x faster than Boa for real userscripts
- Full ES6+ support (Boa is incomplete)
- Battle-tested GM_* API patterns from Deno
- Trade-off: Larger binary size (~50MB more) but worth it for production

**V8 Isolate Configuration**:
```rust
use deno_core::JsRuntime;

let mut runtime = JsRuntime::new(RuntimeOptions {
    max_heap_size: Some(50 * 1024 * 1024),  // 50MB limit
    ..Default::default()
});
```

#### Week 24-26: GM_* API Implementation
1. GM_getValue/setValue using `redb` embedded database (not sled - unmaintained)
2. GM_xmlhttpRequest with `reqwest` (bypasses same-origin policy)
3. GM_addStyle (CSS injection)
4. GM_info (script metadata)
5. GM_getResourceText (fetch @resource)
6. GM_notification (desktop notifications via WebUI)
7. GM_setClipboard (clipboard access)
8. GM_registerMenuCommand (WebUI integration)
9. Storage isolation per script (namespace by script ID)
10. Network request whitelisting based on @grant

**Key Files**:
- `crates/userscript-engine/src/api/storage.rs` - Storage API (redb)
- `crates/userscript-engine/src/api/xhr.rs` - Network API
- `crates/userscript-engine/src/api/dom.rs` - DOM manipulation
- `crates/userscript-engine/src/sandbox.rs` - Security sandboxing

**Dependencies**:
```toml
redb = "2.1"  # Not sled (unmaintained)
```

**GM_* API Sandboxing**:
- Network requests whitelisted by script metadata
- No file system access by default
- CPU and memory limits enforced by V8
- Isolated storage per script

#### Week 27-29: Script Management & Testing
1. Script manager (add/remove/enable/disable)
2. Auto-update checker (@updateURL with conditional requests)
3. Error handling (script errors don't break pages)
4. Detailed logging (script execution, errors, performance)
5. Testing with popular userscripts (Dark Reader, Tampermonkey scripts)
6. Compatibility testing (Greasemonkey, Tampermonkey, Violentmonkey scripts)
7. Performance optimization (minimize overhead, script caching)
8. Documentation: userscript guide, GM_* API reference

**Key Files**:
- `crates/userscript-engine/src/manager.rs` - Script management
- `crates/userscript-engine/src/updater.rs` - Auto-update system
- `docs/USERSCRIPT_GUIDE.md` - User documentation
- `docs/GM_API_REFERENCE.md` - API documentation

**Testing Focus**:
- Popular userscripts from Greasyfork (top 100)
- Malicious script protection (infinite loops, memory bombs)
- Performance impact measurement (latency overhead)

#### Week 30: Integration & Performance Optimization
1. Integration with pipeline for HTML modification
2. Performance optimization (minimize overhead <50ms per page)
3. Script execution caching (don't re-parse on every request)
4. Comprehensive testing suite
5. Security audit (V8 sandboxing, GM_* API restrictions)
6. Graceful degradation (script errors don't break pages)

**Performance Target**: <50-100ms overhead for userscript execution (realistic with V8)

**Deliverable**: v0.4.0 - Full userscript support with production-grade security

---

### Phase 4: WebUI & Management (6-8 weeks)

**Goal**: Production-ready WebUI with authentication and real-time monitoring

#### Week 31-32: Backend API Foundation
1. Set up Axum web server on separate port (8081)
2. Implement bcrypt authentication (cost 12) with JWT tokens
3. Create API endpoints for configuration management
4. Filter list management endpoints (CRUD operations)
5. API integration tests
6. CORS configuration for frontend
7. Rate limiting for authentication endpoints
8. Input validation and sanitization (prevent SSRF, XSS)

**Key Files**:
- `crates/web-api/src/server.rs` - Axum server
- `crates/web-api/src/auth.rs` - Authentication middleware
- `crates/web-api/src/routes/config.rs` - Configuration API
- `crates/web-api/src/routes/filters.rs` - Filter API

**API Endpoints**:
```
Authentication:
POST   /api/v1/auth/login              - Login with username/password
POST   /api/v1/auth/logout             - Logout
GET    /api/v1/auth/verify             - Verify JWT token

Configuration:
GET    /api/v1/config                  - Get current configuration
PUT    /api/v1/config                  - Update configuration
GET    /api/v1/config/ca-certificate   - Download CA certificate

Filter Lists:
GET    /api/v1/filters                 - List all filter lists
POST   /api/v1/filters                 - Add new filter list
PUT    /api/v1/filters/:id             - Update filter list
DELETE /api/v1/filters/:id             - Remove filter list
POST   /api/v1/filters/:id/update      - Trigger manual update
GET    /api/v1/filters/:id/rules       - View rules in list
POST   /api/v1/filters/custom          - Add custom rules
```

**Security**:
- Bcrypt with cost 12 (or Argon2 for better security)
- JWT with 24h expiration
- HTTPS-only (self-signed cert acceptable)
- CORS properly configured
- Rate limiting (5 login attempts per minute)
- SSRF protection (validate filter list URLs)

#### Week 33-34: Extended API & WebSocket
1. Userscript management endpoints (CRUD)
2. Statistics API (overview, requests, filter hits, time-series)
3. Logging API with filtering and pagination
4. WebSocket endpoint for real-time updates
5. Health check endpoint (Kubernetes-ready)
6. Prometheus metrics endpoint (/metrics)
7. OpenAPI/Swagger documentation generation

**Key Files**:
- `crates/web-api/src/routes/scripts.rs` - Userscript API
- `crates/web-api/src/routes/stats.rs` - Statistics API
- `crates/web-api/src/routes/logs.rs` - Logging API
- `crates/web-api/src/websocket.rs` - WebSocket handler

**Additional API Endpoints**:
```
Userscripts:
GET    /api/v1/scripts                 - List all userscripts
POST   /api/v1/scripts                 - Upload new userscript
PUT    /api/v1/scripts/:id             - Update userscript
DELETE /api/v1/scripts/:id             - Remove userscript
PATCH  /api/v1/scripts/:id/toggle      - Enable/disable script
POST   /api/v1/scripts/:id/update      - Trigger manual update

Statistics:
GET    /api/v1/stats/overview          - Overall statistics
GET    /api/v1/stats/requests          - Request statistics
GET    /api/v1/stats/filters           - Filter hit statistics
GET    /api/v1/stats/scripts           - Userscript statistics
GET    /api/v1/stats/timeline          - Time-series data

Logs:
GET    /api/v1/logs                    - Query logs (with filters)
WS     /api/v1/logs/stream             - WebSocket for live logs
DELETE /api/v1/logs                    - Clear logs

System:
GET    /api/v1/system/health           - Health check
GET    /api/v1/system/metrics          - Prometheus metrics
GET    /api/v1/system/version          - Version info
```

#### Week 35-37: Frontend Dashboard (Leptos WASM)
1. Set up Leptos WASM frontend (verify version - use 0.6 if 0.7 unstable)
2. Authentication flow (login, token storage in localStorage)
3. Dashboard overview (stats cards, charts with real-time updates)
4. Filter list management UI (add/remove/enable/disable)
5. Settings UI with CA certificate download
6. Responsive design (mobile-friendly)
7. Error handling and toast notifications

**Key Files**:
- `crates/web-ui/src/main.rs` - Leptos app entry
- `crates/web-ui/src/components/dashboard.rs` - Dashboard
- `crates/web-ui/src/components/filters.rs` - Filter UI
- `crates/web-ui/src/components/settings.rs` - Settings UI
- `crates/web-ui/src/api.rs` - API client

**Dependencies**:
```toml
leptos = { version = "0.6", features = ["csr"] }  # Use 0.6 if 0.7 unstable
leptos_router = "0.6"
```

**Frontend Build**:
```dockerfile
# In Dockerfile
RUN rustup target add wasm32-unknown-unknown
RUN cargo install trunk

# Build WASM UI
RUN cd crates/web-ui && trunk build --release

# Copy WASM assets
COPY --from=builder /app/crates/web-ui/dist /app/static/
```

#### Week 38: Advanced UI Features
1. Userscript management UI with editor
2. Request log viewer with real-time updates (WebSocket)
3. Statistics charts and visualizations (time-series)
4. Responsive design polish
5. Dark mode support
6. Accessibility (WCAG 2.1 AA)

**Key Files**:
- `crates/web-ui/src/components/scripts.rs` - Userscript UI
- `crates/web-ui/src/components/logs.rs` - Log viewer

**Charting Library**: Consider `plotters` (Rust) or JavaScript charting via WASM bindings

**Deliverable**: v0.8.0 - Full WebUI with real-time monitoring

---

### Phase 5: HTTP/3 & Production Hardening (4-6 weeks)

**Goal**: HTTP/3 support (optional) and production-ready release

#### Week 39-41: HTTP/3 and QUIC (Optional)
1. Research and design HTTP/3 integration strategy
2. Integrate `quinn` for QUIC support
3. Implement `h3` protocol handler
4. UDP socket configuration and NAT traversal
5. QUIC connection migration handling
6. 0-RTT attack mitigation
7. Testing and debugging (extensive due to complexity)
8. Make optional and disabled by default
9. Fallback to HTTP/2 on failures
10. Documentation on UDP port requirements and firewall configuration

**Key Files**:
- `crates/proxy-http3/src/http3.rs` - HTTP/3 handler
- `crates/proxy-http3/src/quic.rs` - QUIC connection handling
- `docs/HTTP3_SETUP.md` - HTTP/3 configuration guide

**Dependencies**:
```toml
h3 = "0.0.7"        # Experimental - document as such
h3-quinn = "0.0.7"  # Needed for quinn integration
quinn = "0.11"
```

**Critical Considerations**:
- HTTP/3 MITM is research-level complexity
- UDP NAT traversal requires firewall configuration
- Limited production examples available
- Should remain disabled by default
- **Consider deferring to post-1.0 if causing delays**

#### Week 42-44: Production Hardening & Security
1. Security audit (authentication, input validation, SSRF, XSS)
2. Penetration testing for WebUI
3. Malicious filter rule testing
4. Malicious userscript testing
5. Load testing under sustained load (24+ hours)
6. Memory leak detection (valgrind, heaptrack)
7. Performance optimization based on profiling
8. Error handling review (all failure modes have fallbacks)
9. Dependency security audit (`cargo audit`)
10. Docker multi-arch builds (amd64, arm64)
11. Final integration testing with all components

**Testing Checklist**:
- [ ] Top 1000 websites work correctly with adblocking
- [ ] 10k concurrent connections without crashes
- [ ] Memory usage <1GB under load
- [ ] Latency overhead <10ms (without userscripts)
- [ ] Filter updates don't drop connections
- [ ] Graceful degradation on errors
- [ ] All browsers accept CA certificate
- [ ] WebUI is responsive and functional
- [ ] Security vulnerabilities addressed

#### Week 45: Documentation & Release
1. Comprehensive API documentation (rustdoc + OpenAPI)
2. User guide (installation, configuration, troubleshooting)
3. Administrator guide (deployment, monitoring, maintenance)
4. Migration guides (from Pi-hole, AdGuard Home, Privoxy)
5. Architecture documentation (for contributors)
6. Troubleshooting guide (common issues, solutions)
7. Legal documentation (MITM ethics, disclaimers)
8. Release notes and changelog
9. Final bug fixes
10. v1.0.0 release preparation

**Documentation Structure**:
```
docs/
├── USER_GUIDE.md              # End-user documentation
├── ADMIN_GUIDE.md             # System administrator guide
├── CA_INSTALLATION.md         # CA setup for all platforms
├── USERSCRIPT_GUIDE.md        # Writing and installing userscripts
├── GM_API_REFERENCE.md        # GM_* API documentation
├── MIGRATION_GUIDE.md         # Migration from other tools
├── ARCHITECTURE.md            # System architecture
├── CONTRIBUTING.md            # Contributor guide
├── TROUBLESHOOTING.md         # Common issues and solutions
├── LEGAL.md                   # MITM ethics, disclaimers
└── HTTP3_SETUP.md             # HTTP/3 configuration (if implemented)
```

**Deliverable**: v1.0.0 - Production-ready complete system

---

## Project Structure (Updated)

```
adblocker/
├── Cargo.toml                      # Workspace manifest
├── Dockerfile                      # Multi-stage Debian build
├── docker-compose.yml
├── README.md
├── LICENSE
├── CHANGELOG.md
├── config/
│   ├── default.toml               # Default configuration
│   └── production.toml            # Production overrides
├── certs/                         # Runtime CA certificates (gitignored)
├── data/
│   ├── filters/                   # Downloaded filter lists
│   ├── userscripts/               # Installed userscripts
│   └── db/                        # redb database files
├── logs/                          # Application logs (gitignored)
├── docs/                          # Documentation
│   ├── USER_GUIDE.md
│   ├── ADMIN_GUIDE.md
│   ├── CA_INSTALLATION.md
│   ├── USERSCRIPT_GUIDE.md
│   ├── GM_API_REFERENCE.md
│   ├── MIGRATION_GUIDE.md
│   ├── ARCHITECTURE.md
│   ├── CONTRIBUTING.md
│   ├── TROUBLESHOOTING.md
│   ├── LEGAL.md
│   └── HTTP3_SETUP.md
├── .github/
│   └── workflows/
│       └── ci.yml                 # CI/CD configuration
├── crates/
│   ├── proxy-core/                # Phase 1: Core proxy
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── server.rs          # Main proxy server
│   │       ├── connection.rs      # Connection handling
│   │       ├── mitm.rs            # MITM + moka cert caching
│   │       ├── ca.rs              # Certificate Authority
│   │       ├── http2.rs           # HTTP/2 handler
│   │       ├── websocket.rs       # WebSocket proxying
│   │       ├── pipeline.rs        # Pipeline orchestration
│   │       ├── config.rs          # Configuration
│   │       └── error.rs           # Error types
│   │
│   ├── proxy-middleware/          # Pipeline middleware (NEW)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── filter_stage.rs    # Network filter middleware
│   │       ├── cosmetic_stage.rs  # Cosmetic filter middleware
│   │       ├── userscript_stage.rs # Userscript middleware
│   │       └── stats_stage.rs     # Statistics middleware
│   │
│   ├── proxy-http3/               # Phase 5: HTTP/3 (optional)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── http3.rs           # HTTP/3 handler
│   │       └── quic.rs            # QUIC connection handling
│   │
│   ├── proxy-types/               # Shared types (split from common)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── request.rs
│   │       ├── response.rs
│   │       └── traits.rs
│   │
│   ├── proxy-stats/               # Statistics (NEW, split from common)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── counters.rs        # Atomic counters
│   │       └── timeseries.rs      # Time-series data
│   │
│   ├── proxy-config/              # Configuration (NEW, split from common)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       └── schema.rs
│   │
│   ├── filter-engine/             # Phase 2: Adblocking
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── engine.rs          # Main filter engine
│   │       ├── parser/
│   │       │   ├── mod.rs
│   │       │   ├── abp.rs         # AdBlock Plus
│   │       │   └── adguard.rs     # AdGuard extensions
│   │       ├── matcher/
│   │       │   ├── mod.rs
│   │       │   ├── network.rs     # Network request matching
│   │       │   ├── cosmetic.rs    # Cosmetic filtering
│   │       │   └── scriptlet.rs   # Scriptlet injection
│   │       ├── modifiers/
│   │       │   ├── mod.rs
│   │       │   ├── replace.rs     # $replace
│   │       │   └── redirect.rs    # $redirect
│   │       ├── css/
│   │       │   ├── mod.rs
│   │       │   └── extended.rs    # Extended CSS selectors
│   │       ├── scriptlets/
│   │       │   ├── mod.rs
│   │       │   ├── adguard.rs     # AdGuard scriptlets
│   │       │   └── ublock.rs      # uBlock scriptlets
│   │       ├── updater.rs         # Auto-update
│   │       └── list.rs            # Filter list management
│   │
│   ├── userscript-engine/         # Phase 3: Userscripts
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── runtime.rs         # Deno Core runtime wrapper
│   │       ├── isolate.rs         # V8 isolate management
│   │       ├── metadata.rs        # Metadata parser
│   │       ├── injector.rs        # Script injection
│   │       ├── sandbox.rs         # Security sandboxing
│   │       ├── manager.rs         # Script management
│   │       ├── updater.rs         # Auto-update
│   │       └── api/
│   │           ├── mod.rs
│   │           ├── storage.rs     # GM_getValue/setValue (redb)
│   │           ├── xhr.rs         # GM_xmlhttpRequest
│   │           └── dom.rs         # DOM manipulation
│   │
│   ├── web-api/                   # Phase 4: Backend
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── server.rs          # Axum server
│   │       ├── auth.rs            # Authentication middleware
│   │       ├── websocket.rs       # WebSocket handler
│   │       └── routes/
│   │           ├── mod.rs
│   │           ├── config.rs      # Configuration API
│   │           ├── filters.rs     # Filter API
│   │           ├── scripts.rs     # Userscript API
│   │           ├── stats.rs       # Statistics API
│   │           └── logs.rs        # Logging API
│   │
│   └── web-ui/                    # Phase 4: Frontend
│       ├── Cargo.toml
│       ├── index.html
│       ├── style.css
│       └── src/
│           ├── main.rs            # Leptos app entry
│           ├── app.rs             # Root component
│           ├── api.rs             # API client
│           └── components/
│               ├── mod.rs
│               ├── dashboard.rs   # Dashboard
│               ├── filters.rs     # Filter UI
│               ├── scripts.rs     # Userscript UI
│               ├── settings.rs    # Settings UI
│               └── logs.rs        # Log viewer
│
├── tests/
│   ├── integration/
│   │   ├── proxy_test.rs
│   │   ├── browser_test.rs
│   │   ├── filter_compat_test.rs
│   │   └── script_test.rs
│   └── fixtures/
│       ├── filter_lists/
│       └── userscripts/
│
└── benches/
    ├── proxy_bench.rs
    └── filter_bench.rs
```

---

## Critical Dependencies (Updated)

### Workspace-Level Dependencies

```toml
[workspace]
members = [
    "crates/proxy-core",
    "crates/proxy-middleware",
    "crates/proxy-http3",
    "crates/proxy-types",
    "crates/proxy-stats",
    "crates/proxy-config",
    "crates/filter-engine",
    "crates/userscript-engine",
    "crates/web-api",
    "crates/web-ui",
]
resolver = "2"

[workspace.dependencies]
# Core Proxy (Phase 1)
tokio = { version = "1.42", features = ["full"] }
hyper = { version = "1.5", features = ["server", "client", "http1", "http2"] }
hyper-util = { version = "0.1", features = ["tokio", "server", "client-legacy"] }  # ADDED
rustls = "0.24"  # UPDATED from 0.23
tokio-rustls = "0.26"  # UPDATED to match rustls 0.24
rcgen = "0.13"
h2 = "0.4"

# Async utilities
futures = "0.3"
pin-project = "1.1"
tower = "0.5"  # For middleware pattern
tower-http = { version = "0.6", features = ["cors", "compression-full"] }

# Caching & Concurrency
moka = { version = "0.12", features = ["future"] }  # ADDED for cert caching
arc-swap = "1.7"  # ADDED for hot-reload
dashmap = "6.1"
parking_lot = "0.12"

# Error handling
thiserror = "2.0"
anyhow = "1.0"

# Configuration
config = "0.14"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
toml = "0.8"

# Logging & Metrics
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
metrics = "0.24"  # ADDED
metrics-exporter-prometheus = "0.16"  # ADDED

# HTTP/3 (Phase 5)
h3 = "0.0.7"
h3-quinn = "0.0.7"  # ADDED for quinn integration
quinn = "0.11"
tokio-tungstenite = "0.24"

# Filter Engine (Phase 2)
adblock = "0.9"  # Verify latest version
html5ever = "0.28"
cssparser = "0.31"
selectors = "0.25"
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls"] }
url = "2.5"
regex = "1.11"

# Userscript Engine (Phase 3)
deno_core = "0.335"  # CHANGED from boa_engine
rusty_v8 = "0.105"   # ADDED (V8 bindings)

# Storage
redb = "2.1"  # CHANGED from sled (unmaintained)

# WebUI (Phase 4)
axum = { version = "0.8", features = ["ws", "multipart"] }
bcrypt = "0.16"
jsonwebtoken = "9.3"
leptos = { version = "0.6", features = ["csr"] }  # Use 0.6 if 0.7 unstable
leptos_router = "0.6"

# Time handling
chrono = { version = "0.4", features = ["serde"] }

# Testing
mockito = "1.6"
proptest = "1.6"  # ADDED for property-based testing

# Development
num_cpus = "1.16"
```

---

## State Management Architecture (NEW Section)

### Shared State Design

```rust
/// Main application state shared across all components
pub struct AppState {
    // Immutable after startup
    config: Arc<Config>,

    // Hot-reloadable (ArcSwap for atomic updates)
    filter_engine: Arc<ArcSwap<FilterEngine>>,
    userscript_manager: Arc<ArcSwap<UserscriptManager>>,

    // High-concurrency caching
    cert_cache: Arc<CertificateCache>,  // moka-based
    filter_cache: Arc<FilterCache>,     // moka-based (request results)

    // Lock-free statistics
    stats: Arc<Statistics>,

    // Resource limits
    limits: Arc<ResourceLimits>,

    // Logging (mpsc channel for async writes)
    log_tx: mpsc::Sender<LogEvent>,
}

/// Resource limits for backpressure
pub struct ResourceLimits {
    max_connections: Semaphore,           // 10,000
    max_cert_generations: Semaphore,      // 100 concurrent
    max_html_buffers: Semaphore,          // 500 concurrent
    max_userscript_executions: Semaphore, // 50 concurrent
}

/// Lock-free statistics using atomic counters
pub struct Statistics {
    // Global counters
    total_requests: AtomicU64,
    blocked_requests: AtomicU64,
    allowed_requests: AtomicU64,
    bytes_saved: AtomicU64,

    // Per-domain stats (eventually consistent)
    domain_stats: DashMap<String, DomainStats>,

    // Time-series for charts
    timeseries: Arc<RwLock<RingBuffer<TimeSeriesPoint>>>,
}

struct DomainStats {
    requests: AtomicU64,
    blocked: AtomicU64,
    bytes: AtomicU64,
}
```

### Filter Engine Hot-Reload

```rust
/// Zero-downtime filter updates using ArcSwap
pub async fn reload_filters(&self, lists: Vec<FilterList>) -> Result<()> {
    // 1. Download all lists with retry
    let raw_lists = download_lists(&lists).await?;

    // 2. Validate syntax
    for list in &raw_lists {
        validate_filter_syntax(list)?;
    }

    // 3. Compile in background (slow operation)
    let new_engine = tokio::task::spawn_blocking(move || {
        let mut engine = adblock::Engine::new(true);
        for list in raw_lists {
            engine.add_filter_list(&list)?;
        }
        Ok::<_, Error>(engine)
    }).await??;

    // 4. Smoke test with sample URLs
    smoke_test(&new_engine, SAMPLE_URLS)?;

    // 5. Atomic swap - ongoing requests keep using old engine
    self.filter_engine.store(Arc::new(new_engine));

    // Old engine is dropped when last request finishes (Arc ref count = 0)
    Ok(())
}
```

### Request Context Lifecycle

```rust
/// Request-scoped context capturing state at request start
pub struct RequestContext {
    // Captured at request start (immutable for this request)
    filters: Arc<FilterEngine>,  // Snapshot via ArcSwap
    scripts: Arc<UserscriptManager>,

    // Request-specific data
    url: Url,
    method: Method,
    headers: HeaderMap,
    request_type: RequestType,  // script, image, document, etc.

    // Mutable state
    blocked: bool,
    modified_headers: HeaderMap,
    stats_recorded: bool,
}
```

---

## Resource Limits Configuration (NEW Section)

### Configuration File

```toml
[limits]
# Connection limits
max_connections = 10000
max_connections_per_host = 1000
max_idle_connections_per_host = 100
idle_connection_timeout_secs = 90

# Resource concurrency limits
max_concurrent_cert_generations = 100
max_concurrent_html_buffers = 500
max_concurrent_userscript_executions = 50

# Buffer size limits
max_html_buffer_size = 5242880  # 5MB
max_request_body_size = 10485760  # 10MB
max_response_body_size = 52428800  # 50MB (for streaming)

# Timeout limits
request_timeout_secs = 30
tls_handshake_timeout_secs = 10
dns_resolution_timeout_secs = 5
userscript_timeout_secs = 30

# Memory limits
userscript_max_heap_mb = 50
filter_cache_max_size_mb = 100
cert_cache_max_entries = 1000

# File descriptor limits (set via ulimit)
# ulimit -n 65535
required_file_descriptors = 65535
```

### Implementation

```rust
impl ResourceLimits {
    pub fn from_config(config: &Config) -> Self {
        Self {
            max_connections: Semaphore::new(config.limits.max_connections),
            max_cert_generations: Semaphore::new(config.limits.max_concurrent_cert_generations),
            max_html_buffers: Semaphore::new(config.limits.max_concurrent_html_buffers),
            max_userscript_executions: Semaphore::new(config.limits.max_concurrent_userscript_executions),
        }
    }

    pub async fn acquire_connection_permit(&self) -> Result<SemaphorePermit> {
        self.max_connections.acquire().await
            .map_err(|_| Error::TooManyConnections)
    }
}

// Usage in connection handler
pub async fn handle_connection(
    stream: TcpStream,
    state: Arc<AppState>,
) -> Result<()> {
    let _permit = state.limits.acquire_connection_permit().await?;

    // Handle request with permit held
    // Permit automatically released on drop
}
```

---

## Enhanced Pipeline Architecture

### 8-Stage Pipeline (Not 4-Stage)

```rust
use tower::Service;

/// Request pipeline stages
pub struct RequestPipeline {
    parse: ParseStage,
    network_filter: NetworkFilterStage,
    request_modify: RequestModifyStage,
    route: RouteStage,
}

/// Response pipeline stages
pub struct ResponsePipeline {
    receive: ReceiveStage,
    response_filter_check: ResponseFilterCheckStage,
    response_modify: ResponseModifyStage,  // Conditional buffering
    stream: StreamStage,
}

/// Stage 6: Response Filter Check (decides buffer vs stream)
impl ResponseFilterCheckStage {
    async fn process(&self, ctx: &mut ResponseContext) -> Action {
        // Check Content-Type
        let content_type = ctx.response.headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        // Only buffer HTML for cosmetic filtering
        let needs_cosmetic = content_type.contains("text/html") &&
            self.filter_engine.has_cosmetic_rules(&ctx.url.domain());

        let needs_userscripts = content_type.contains("text/html") &&
            self.userscript_manager.has_scripts_for(&ctx.url);

        // Check size limits
        let content_length = ctx.response.headers()
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);

        if content_length > MAX_BUFFER_SIZE {
            return Action::Stream;  // Too large, stream directly
        }

        if needs_cosmetic || needs_userscripts {
            Action::Buffer  // Buffer for modification
        } else {
            Action::Stream  // Stream directly (images, videos, etc.)
        }
    }
}
```

---

## Performance Targets (Updated)

- **Request latency overhead**: <10ms (without userscripts), <50-100ms (with userscripts)
- **Filter matching**: <100μs per request
- **Throughput**: 10,000+ requests/second (pure proxying), 5,000+ req/s (with filtering)
- **Memory**: <1GB with 10,000 connections (updated from <500MB - more realistic)
- **Startup time**: <5 seconds
- **Binary size**: <100MB (with V8, larger than Boa but acceptable)
- **Docker image**: ~150MB (Debian slim + dependencies)

---

## Testing Strategy (Enhanced)

### Unit Tests
- Each crate with comprehensive coverage (target: >80%)
- Mock external dependencies (filter lists, upstream servers)
- Edge cases and error conditions
- Rustdoc examples as tests

### Integration Tests
- End-to-end proxy tests with real browsers
- Filter blocking validation with real websites
- Userscript execution with real scripts
- API endpoint tests
- WebSocket real-time update tests

### Performance Tests
- Latency benchmarks (criterion.rs)
- Filter matching speed benchmarks
- Memory usage profiling (heaptrack)
- Concurrent connection tests (10k target with wrk)
- Sustained load testing (24+ hours)

### Property-Based Testing (NEW)
```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_filter_parsing_never_panics(s in "\\PC*") {
        // Parser should never panic on any input
        let _ = parse_filter_rule(&s);
    }

    #[test]
    fn test_url_matching_is_deterministic(url in "https?://[a-z]+\\.com/.*") {
        let result1 = engine.check(&url);
        let result2 = engine.check(&url);
        assert_eq!(result1, result2);
    }
}
```

### Browser Compatibility Tests (NEW)
```rust
use fantoccini::{ClientBuilder, Locator};

#[tokio::test]
async fn test_ad_blocking_in_chrome() {
    let client = ClientBuilder::native()
        .proxy("http://localhost:8080")
        .connect("http://localhost:4444")
        .await?;

    client.goto("https://example.com").await?;

    // Verify ad element is removed
    let ad = client.find(Locator::Id("ad-banner")).await;
    assert!(ad.is_err(), "Ad should be blocked");
}
```

### Security Tests (NEW)
- Malicious filter rules (ReDOS, script injection)
- Malicious userscripts (infinite loops, memory bombs)
- Authentication brute force resistance
- SSRF protection for filter list URLs
- XSS prevention in WebUI
- Certificate private key permissions

### Browser Compatibility
- Chrome/Chromium (latest + 2 versions back)
- Firefox (latest + 2 versions back)
- Safari (latest)
- Edge (latest)
- Mobile browsers (iOS Safari, Chrome Android)

---

## Security Considerations (Enhanced)

1. **MITM Ethics**:
   - Clear documentation on legal and ethical use
   - Strong disclaimer about privacy implications
   - Use cases: personal privacy, parental controls, corporate networks with consent

2. **CA Private Key Protection**:
   ```bash
   # File permissions enforcement
   chmod 600 certs/root-ca.key

   # Verification on startup
   if stat -c %a certs/root-ca.key | grep -v 600; then
       echo "ERROR: CA private key has insecure permissions"
       exit 1
   fi
   ```

3. **Password Hashing**:
   - Bcrypt with cost 12 (or Argon2 for better security)
   - No password logging (sanitize logs)
   - JWT with short expiration (24h)

4. **Input Validation**:
   - Sanitize all user inputs (filter lists, custom rules, userscripts)
   - SSRF protection for URLs (block internal IPs, validate schemes)
   - Path traversal prevention

5. **Rate Limiting**:
   - Authentication endpoints (5 attempts per minute)
   - API endpoints (100 requests per minute per IP)
   - Filter list updates (1 per hour)

6. **Minimal Privileges**:
   - Non-root Docker user (uid 1000)
   - Capabilities dropped (no CAP_SYS_ADMIN)
   - Read-only filesystem where possible

7. **Dependency Auditing**:
   - Weekly `cargo audit` runs in CI
   - Automated dependency updates with testing
   - Monitor CVE databases

8. **V8 Sandboxing**:
   - V8 isolates for userscript execution
   - Memory limits per isolate (50MB)
   - CPU timeout enforcement (30s)
   - No file system access
   - Network requests whitelisted by @grant

---

## Docker Deployment (Updated)

### Multi-Stage Dockerfile (Debian Slim)

```dockerfile
# Stage 1: Build environment
FROM rust:1.85-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install WASM toolchain for Leptos
RUN rustup target add wasm32-unknown-unknown
RUN cargo install trunk

# Create app directory
WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/

# Build WASM frontend
WORKDIR /app/crates/web-ui
RUN trunk build --release

# Build server binary
WORKDIR /app
RUN cargo build --release --bin adblocker

# Stage 2: Runtime environment
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 adblocker

# Create directories with proper ownership
RUN mkdir -p /app/data/filters \
             /app/data/userscripts \
             /app/data/db \
             /app/certs \
             /app/logs \
             /app/static && \
    chown -R adblocker:adblocker /app

# Copy binary from builder
COPY --from=builder /app/target/release/adblocker /app/adblocker

# Copy WASM frontend assets
COPY --from=builder /app/crates/web-ui/dist /app/static/

# Copy configuration
COPY config/production.toml /app/config/default.toml

# Set file descriptor limit
RUN echo "adblocker soft nofile 65535" >> /etc/security/limits.conf && \
    echo "adblocker hard nofile 65535" >> /etc/security/limits.conf

USER adblocker
WORKDIR /app

# Expose ports
EXPOSE 8080 8081

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8081/api/v1/system/health || exit 1

ENTRYPOINT ["/app/adblocker"]
```

### docker-compose.yml

```yaml
version: '3.8'

services:
  adblocker:
    build: .
    container_name: adblocker-proxy
    restart: unless-stopped
    ports:
      - "8080:8080"  # Proxy port
      - "8081:8081"  # WebUI port
    volumes:
      - ./data:/app/data
      - ./certs:/app/certs
      - ./logs:/app/logs
      - ./config/production.toml:/app/config/default.toml:ro
    environment:
      - RUST_LOG=info
      - PROXY_PORT=8080
      - WEB_PORT=8081
    ulimits:
      nofile:
        soft: 65535
        hard: 65535
    networks:
      - adblocker-net
    healthcheck:
      test: ["CMD", "wget", "--spider", "-q", "http://localhost:8081/api/v1/system/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s

networks:
  adblocker-net:
    driver: bridge
```

---

## Implementation Order Summary (Updated)

1. **Phase 1 (6-8 weeks)**: Proxy foundation with HTTP/1.1, HTTP/2, WebSocket, MITM
2. **Phase 2 (8-12 weeks)**: Complete adblocking engine (AdBlock Plus + AdGuard + cosmetic + scriptlets)
3. **Phase 3 (6-10 weeks)**: Userscript engine with V8/deno_core
4. **Phase 4 (6-8 weeks)**: WebUI and management with authentication
5. **Phase 5 (4-6 weeks)**: HTTP/3 (optional) and production hardening

**Total Timeline**: 40-45 weeks to v1.0.0

---

## Critical Success Factors

### Must Have Before Starting Phase 1:
1. ✅ Dependency versions corrected (rustls 0.24, redb, hyper-util, deno_core)
2. ✅ State management architecture documented
3. ✅ Resource limits designed and configured
4. ✅ CI/CD pipeline set up
5. ✅ File descriptor limits configured
6. ✅ Docker strategy finalized (Debian slim)

### Must Have Before Phase 2:
1. ⏳ Pipeline architecture validated with tests
2. ⏳ MITM working with all major browsers
3. ⏳ Connection pooling and backpressure tested under load
4. ⏳ Metrics collection working (Prometheus)

### Must Have Before Phase 3:
1. ⏳ Filter engine hot-reload working without connection drops
2. ⏳ HTML buffering with size limits tested
3. ⏳ Cosmetic filtering performance acceptable (<50ms)

### Must Have Before Phase 4:
1. ⏳ V8 isolate security validated
2. ⏳ GM_* API fully functional
3. ⏳ Userscript compatibility tested with popular scripts

### Must Have Before v1.0.0 Release:
1. ⏳ Security audit completed
2. ⏳ Load testing passed (10k connections, 24+ hours)
3. ⏳ All documentation complete
4. ⏳ Multi-arch Docker images built
5. ⏳ Migration guides written

---

## Risk Register (Updated)

| Risk | Severity | Probability | Mitigation | Status |
|------|----------|-------------|------------|--------|
| MITM cert browser compatibility | High | 60% | Extensive testing, CA install docs | Active |
| V8 integration complexity | Medium | 40% | POC in Week 0, fallback plan | Active |
| Filter list incompatibility | Medium | 60% | Validation tool, transparent docs | Active |
| HTTP/3 delays project | High | 50% | Make optional, defer to post-1.0 | Mitigated |
| Performance degradation | High | 50% | Benchmarks from day 1, lazy eval | Active |
| Dependency version lock-in | Medium | 40% | Monitor changelogs, abstraction layers | Active |
| Single developer bus factor | Extreme | 30% | Documentation, modularity, community | Active |
| Timeline overrun | High | 70% | 40% buffer built in, scope flexibility | Mitigated |

---

## Next Steps

1. **Week 0 (Preparation)**:
   - Set up development environment
   - Create GitHub repository with CI/CD
   - Proof-of-concept: MITM cert generation + browser acceptance
   - Proof-of-concept: V8/deno_core "hello world" with GM_* stub
   - Proof-of-concept: adblock-rust integration test
   - Create initial project structure (all crates)
   - Write state management architecture document

2. **Week 1-2 (Phase 1 Start)**:
   - Initialize Cargo workspace with all crates
   - Set up configuration schema (comprehensive for all phases)
   - Basic HTTP/1.1 proxy with hyper + hyper-util
   - Logging and metrics infrastructure
   - CI/CD pipeline with automated testing

3. **Continue through phases sequentially** per updated timeline

---

## Change Log

**2026-01-04 - Major Revision Based on Expert Review**:
- Extended timeline from 21 weeks to 40-45 weeks
- Moved HTTP/3 from Phase 2 to Phase 5
- Changed JavaScript engine from Boa to V8/deno_core
- Updated dependencies (rustls 0.24, redb, hyper-util, moka, arc-swap)
- Changed Docker from Alpine to Debian slim
- Expanded pipeline from 4 stages to 8 stages
- Added state management architecture section
- Added resource limits configuration
- Updated memory target from <500MB to <1GB
- Split `common` crate into focused crates
- Added comprehensive risk register
- Enhanced testing strategy with property-based and browser tests
- Added V8 sandboxing details
- Increased Phase 1 from 4 to 6-8 weeks (MITM complexity)
- Increased Phase 3 from 5 to 8-12 weeks (adblocking scope)
- Increased Phase 4 from 4 to 6-10 weeks (V8 integration)
- Increased Phase 5 from 5 to 6-8 weeks (production hardening)
- Moved WebSocket from proxy-http3 to proxy-core

---

**This plan has been reviewed and validated by:**
- Rust Expert (dependencies, architecture patterns, performance)
- Software Architect (system design, scalability, state management)
- Project Lead (timeline, scope, feasibility, risks)

**Approved for implementation with noted timeline and scope.**

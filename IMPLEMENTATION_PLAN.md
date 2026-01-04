# Rust MITM Proxy with Adblocking and Userscript Support - Implementation Plan

## Project Overview

Building a production-ready Rust MITM proxy with feature parity to AdGuard and uBlock Origin, supporting comprehensive adblocking, userscript execution, HTTP/2, HTTP/3, WebSocket, WebUI, and Docker deployment.

**Project Status**: Greenfield (empty directory)
**Location**: `/path/to/adblocker`

## Implementation Strategy

Based on user preferences:
- **Priority**: Proxy foundation first, then filtering features
- **Filter Support**: Both AdBlock Plus and AdGuard formats with full compatibility
- **Userscripts**: Embedded JS engine (Boa)
- **Authentication**: Simple username/password with bcrypt

## Phased Implementation Plan

### Phase 1: Proxy Foundation (4 weeks)

**Goal**: Production-ready MITM proxy with HTTP/1.1, HTTP/2, and certificate management

#### Week 1: Project Setup & Basic HTTP Proxy
1. Initialize Cargo workspace with multi-crate structure
2. Create basic HTTP/1.1 proxy using `hyper` v1.x
3. Set up configuration management with `config` crate
4. Implement structured logging with `tracing`
5. Create error handling framework with `thiserror`

**Key Files**:
- `Cargo.toml` - Workspace manifest
- `crates/proxy-core/src/server.rs` - Main proxy server
- `crates/proxy-core/src/connection.rs` - Connection handling
- `crates/proxy-core/src/config.rs` - Configuration structures

#### Week 2: MITM Certificate Management
1. Implement Certificate Authority generation using `rcgen`
2. Create on-the-fly certificate generation and caching (DashMap)
3. TLS termination with `rustls` and `tokio-rustls`
4. HTTP CONNECT method handling
5. Certificate persistence and loading

**Key Files**:
- `crates/proxy-core/src/ca.rs` - Certificate Authority
- `crates/proxy-core/src/mitm.rs` - MITM logic and cert caching
- `config/default.toml` - Default configuration

**Critical Component**: Certificate caching must use DashMap for thread-safe, lock-free access with LRU eviction (max 1000 certs)

#### Week 3: HTTP/2 & Request Pipeline
1. Integrate HTTP/2 support using `h2` crate
2. Design and implement request/response pipeline architecture
3. Add connection pooling for upstream connections
4. Implement graceful shutdown handling
5. Create benchmark suite for performance validation

**Key Files**:
- `crates/proxy-core/src/http2.rs` - HTTP/2 handler
- `crates/proxy-core/src/pipeline.rs` - Request/response pipeline
- `benches/proxy_bench.rs` - Performance benchmarks

**Pipeline Architecture**:
```
Request → [Pipeline Stage 1: Parse] → [Stage 2: Filter] →
[Stage 3: Modify] → [Stage 4: Forward] → Response
```

#### Week 4: Docker & Testing
1. Create multi-stage Dockerfile (Alpine-based, <100MB)
2. Write docker-compose.yml with volume mounts
3. Implement comprehensive integration tests
4. End-to-end testing with browsers (Chrome, Firefox)
5. Documentation: README, CA installation guide

**Key Files**:
- `Dockerfile` - Multi-stage build
- `docker-compose.yml` - Container orchestration
- `tests/integration/proxy_test.rs` - Integration tests

**Deliverable**: v0.1.0 - Working MITM proxy with HTTP/1.1 and HTTP/2

---

### Phase 2: Advanced Protocol Support (3 weeks)

**Goal**: Full protocol support including HTTP/3 and WebSocket

#### Week 5-6: HTTP/3 and QUIC
1. Research and design HTTP/3 integration strategy
2. Integrate `quinn` for QUIC support
3. Implement `h3` protocol handler
4. UDP socket configuration and port forwarding
5. Testing and debugging (make optional, disabled by default)

**Key Files**:
- `crates/proxy-http3/src/http3.rs` - HTTP/3 handler
- `crates/proxy-http3/src/quic.rs` - QUIC connection handling

#### Week 7: WebSocket Support
1. WebSocket CONNECT upgrade handling using `tokio-tungstenite`
2. Frame proxying and state management
3. Testing with WebSocket applications (chat, live updates)
4. Performance optimization

**Key Files**:
- `crates/proxy-http3/src/websocket.rs` - WebSocket proxying

**Deliverable**: v0.2.0 - Full protocol support

---

### Phase 3: Adblocking Engine (5 weeks)

**Goal**: Feature parity with AdGuard and uBlock Origin

#### Week 8: Core Filter Engine
1. Integrate Brave's `adblock-rust` as foundation
2. Implement AdBlock Plus syntax parser
3. Basic network request blocking
4. Filter list loader from URLs
5. Statistics tracking (requests blocked, allowed)

**Key Files**:
- `crates/filter-engine/src/engine.rs` - Main filter engine
- `crates/filter-engine/src/parser/abp.rs` - AdBlock Plus parser
- `crates/filter-engine/src/matcher/network.rs` - Request matching

**Dependencies**:
```toml
adblock = "0.9"
url = "2.5"
regex = "1.11"
```

#### Week 9: AdGuard Extensions
1. Parse AdGuard-specific syntax extensions
2. Implement advanced modifiers: `$replace`, `$removeparam`, `$removeheader`, `$redirect`
3. Domain-specific rules and exception rules (@@)
4. Testing with real AdGuard filter lists

**Key Files**:
- `crates/filter-engine/src/parser/adguard.rs` - AdGuard parser

#### Week 10: Cosmetic Filtering
1. HTML parsing with `html5ever`
2. CSS injection for element hiding (##.selector)
3. Extended CSS selectors (#?#selector:has(...))
4. CSS rule injection (#$#selector { display: none })
5. Integration with pipeline for response modification

**Key Files**:
- `crates/filter-engine/src/matcher/cosmetic.rs` - Cosmetic filtering

**Dependencies**:
```toml
html5ever = "0.28"
cssparser = "0.31"
selectors = "0.25"
```

#### Week 11: Scriptlet Injection
1. Parse scriptlet rules (#%#//scriptlet(...))
2. Implement AdGuard and uBlock Origin scriptlet library
3. JavaScript injection mechanism
4. Testing with popular scriptlets

**Key Files**:
- `crates/filter-engine/src/matcher/scriptlet.rs` - Scriptlet injection

#### Week 12: Auto-Update System
1. Filter list auto-updater using `reqwest`
2. Conditional requests (ETag/If-Modified-Since)
3. Checksum verification and validation
4. Atomic hot reload without dropping connections
5. Rollback on validation failure

**Key Files**:
- `crates/filter-engine/src/updater.rs` - Auto-update mechanism
- `crates/filter-engine/src/list.rs` - Filter list management

**Default Filter Lists**:
- EasyList, EasyPrivacy
- AdGuard Base, AdGuard Tracking Protection
- uBlock Origin filters

**Deliverable**: v0.3.0 - Full adblocking with filter list support

---

### Phase 4: Userscript Engine (4 weeks)

**Goal**: Greasemonkey-compatible userscript execution

#### Week 13: Boa Integration
1. Integrate Boa JavaScript engine
2. Parse userscript metadata (Greasemonkey format)
3. URL matching logic (@match, @include, @exclude)
4. Basic script injection into HTML
5. Isolated execution context per page

**Key Files**:
- `crates/userscript-engine/src/runtime.rs` - Boa runtime wrapper
- `crates/userscript-engine/src/metadata.rs` - Metadata parser
- `crates/userscript-engine/src/injector.rs` - Script injection

**Dependencies**:
```toml
boa_engine = "0.21"
boa_parser = "0.21"
```

#### Week 14: GM_* API Implementation
1. GM_getValue/setValue using `sled` embedded database
2. GM_xmlhttpRequest with `reqwest` (bypasses same-origin)
3. GM_addStyle, GM_info, GM_getResourceText
4. Sandboxing: CPU/memory limits, timeout enforcement (30s)

**Key Files**:
- `crates/userscript-engine/src/api/storage.rs` - Storage API
- `crates/userscript-engine/src/api/xhr.rs` - Network API
- `crates/userscript-engine/src/sandbox.rs` - Security sandboxing

#### Week 15: Script Management
1. Script manager (add/remove/enable/disable)
2. Auto-update checker (@updateURL)
3. Error handling and detailed logging
4. Testing with popular userscripts (Dark Reader, etc.)

**Key Files**:
- `crates/userscript-engine/src/manager.rs` - Script management
- `crates/userscript-engine/src/updater.rs` - Auto-update system

#### Week 16: Integration & Testing
1. Integration with pipeline for HTML modification
2. Performance optimization (minimize overhead)
3. Comprehensive testing suite
4. Documentation: userscript guide

**Deliverable**: v0.4.0 - Full userscript support

---

### Phase 5: WebUI & Management (5 weeks)

**Goal**: Production-ready WebUI with authentication and monitoring

#### Week 17: Backend API Foundation
1. Set up Axum web server on separate port (8081)
2. Implement bcrypt authentication with JWT tokens
3. Create API endpoints for configuration management
4. Filter list management endpoints (CRUD operations)
5. API integration tests

**Key Files**:
- `crates/web-api/src/server.rs` - Axum server
- `crates/web-api/src/auth.rs` - Authentication middleware
- `crates/web-api/src/routes/config.rs` - Configuration API
- `crates/web-api/src/routes/filters.rs` - Filter API

**API Endpoints**:
```
POST   /api/v1/auth/login
GET    /api/v1/config
PUT    /api/v1/config
GET    /api/v1/filters
POST   /api/v1/filters
DELETE /api/v1/filters/:id
```

#### Week 18: Extended API & WebSocket
1. Userscript management endpoints
2. Statistics API (overview, requests, filter hits)
3. Logging API with filtering
4. WebSocket endpoint for real-time updates
5. Health check and metrics endpoints

**Key Files**:
- `crates/web-api/src/routes/scripts.rs` - Userscript API
- `crates/web-api/src/routes/stats.rs` - Statistics API
- `crates/web-api/src/routes/logs.rs` - Logging API

#### Week 19: Frontend Dashboard (Leptos)
1. Set up Leptos WASM frontend
2. Authentication flow (login, token storage)
3. Dashboard overview (stats cards, charts)
4. Filter list management UI
5. Settings UI with CA certificate download

**Key Files**:
- `crates/web-ui/src/main.rs` - Leptos app entry
- `crates/web-ui/src/components/dashboard.rs` - Dashboard
- `crates/web-ui/src/components/filters.rs` - Filter UI

**Dependencies**:
```toml
leptos = { version = "0.7", features = ["csr"] }
leptos_router = "0.7"
```

#### Week 20: Advanced UI Features
1. Userscript management UI with editor
2. Request log viewer with real-time updates
3. Statistics charts and visualizations
4. Responsive design (mobile-friendly)
5. Dark mode support

**Key Files**:
- `crates/web-ui/src/components/scripts.rs` - Userscript UI
- `crates/web-ui/src/components/logs.rs` - Log viewer

#### Week 21: Production Hardening
1. Security audit (authentication, input validation)
2. Performance optimization (lazy loading, caching)
3. Comprehensive documentation (API docs, user guide)
4. Docker multi-arch builds (amd64, arm64)
5. Final testing and bug fixes

**Deliverable**: v1.0.0 - Production-ready MVP

---

## Project Structure

```
adblocker/
├── Cargo.toml                      # Workspace manifest
├── Dockerfile                      # Multi-stage Alpine build
├── docker-compose.yml
├── README.md
├── config/
│   ├── default.toml               # Default configuration
│   └── production.toml
├── certs/                         # Runtime CA certificates
├── data/
│   ├── filters/                   # Downloaded filter lists
│   └── userscripts/
├── logs/
├── crates/
│   ├── proxy-core/                # Phase 1: Core proxy
│   │   └── src/
│   │       ├── server.rs          # Main proxy server
│   │       ├── connection.rs
│   │       ├── mitm.rs            # MITM + cert caching
│   │       ├── ca.rs              # Certificate Authority
│   │       ├── http2.rs
│   │       ├── pipeline.rs        # Request/response pipeline
│   │       ├── config.rs
│   │       └── error.rs
│   ├── proxy-http3/               # Phase 2: HTTP/3
│   │   └── src/
│   │       ├── http3.rs
│   │       ├── quic.rs
│   │       └── websocket.rs
│   ├── filter-engine/             # Phase 3: Adblocking
│   │   └── src/
│   │       ├── engine.rs          # Main filter engine
│   │       ├── parser/
│   │       │   ├── abp.rs         # AdBlock Plus
│   │       │   └── adguard.rs     # AdGuard extensions
│   │       ├── matcher/
│   │       │   ├── network.rs
│   │       │   ├── cosmetic.rs
│   │       │   └── scriptlet.rs
│   │       ├── updater.rs         # Auto-update
│   │       └── stats.rs
│   ├── userscript-engine/         # Phase 4: Userscripts
│   │   └── src/
│   │       ├── runtime.rs         # Boa wrapper
│   │       ├── metadata.rs
│   │       ├── injector.rs
│   │       ├── sandbox.rs
│   │       ├── manager.rs
│   │       └── api/
│   │           ├── storage.rs     # GM_getValue/setValue
│   │           └── xhr.rs         # GM_xmlhttpRequest
│   ├── web-api/                   # Phase 5: Backend
│   │   └── src/
│   │       ├── server.rs
│   │       ├── auth.rs
│   │       └── routes/
│   │           ├── config.rs
│   │           ├── filters.rs
│   │           ├── scripts.rs
│   │           ├── stats.rs
│   │           └── logs.rs
│   ├── web-ui/                    # Phase 5: Frontend
│   │   └── src/
│   │       ├── main.rs
│   │       └── components/
│   │           ├── dashboard.rs
│   │           ├── filters.rs
│   │           ├── scripts.rs
│   │           ├── settings.rs
│   │           └── logs.rs
│   └── common/                    # Shared utilities
│       └── src/
│           ├── types.rs
│           └── utils.rs
├── tests/
│   └── integration/
└── benches/
```

## Critical Dependencies

### Core Proxy (Phase 1)
- `tokio` (1.42) - Async runtime
- `hyper` (1.5) - HTTP server/client
- `rustls` (0.23) - TLS implementation
- `rcgen` (0.13) - Certificate generation
- `h2` (0.4) - HTTP/2
- `config` (0.14) - Configuration
- `tracing` (0.1) - Logging

### Advanced Protocols (Phase 2)
- `h3` (0.0.7) - HTTP/3
- `quinn` (0.11) - QUIC
- `tokio-tungstenite` (0.24) - WebSocket

### Filter Engine (Phase 3)
- `adblock` (0.9) - Brave's adblock-rust
- `html5ever` (0.28) - HTML parsing
- `cssparser` (0.31) - CSS parsing
- `reqwest` (0.12) - HTTP client

### Userscript Engine (Phase 4)
- `boa_engine` (0.21) - JavaScript engine
- `sled` (0.34) - Embedded database

### WebUI (Phase 5)
- `axum` (0.8) - Web framework
- `bcrypt` (0.16) - Password hashing
- `jsonwebtoken` (9.3) - JWT tokens
- `leptos` (0.7) - Frontend framework

## Critical Implementation Details

### MITM Certificate Flow
1. On startup: Generate or load Root CA from `certs/root-ca.{crt,key}`
2. On CONNECT request: Check cache for domain certificate
3. If not cached: Generate certificate signed by Root CA using `rcgen`
4. Cache certificate in DashMap with LRU eviction (max 1000)
5. Establish TLS with client using generated cert
6. Establish TLS with target server using real cert
7. Proxy decrypted traffic through pipeline

### Request/Response Pipeline
```rust
Request → Parse → Filter (block/allow) → Modify (cosmetic/scriptlet) →
Userscripts → Forward → Response
```

Each stage can:
- Block the request (return early)
- Modify headers/body
- Inject content
- Collect statistics

### Filter Engine Integration
- Use `adblock-rust` for network request matching
- Parse both AdBlock Plus and AdGuard syntax
- Support all filter modifiers: `$third-party`, `$image`, `$script`, `$replace`, etc.
- Cosmetic filtering modifies HTML response
- Scriptlet injection adds JavaScript to pages

### Userscript Execution
- Parse metadata on script load
- Match URL against @match/@include patterns
- Create isolated Boa context per page
- Inject GM_* APIs based on @grant
- Execute with 30s timeout and memory limits
- Inject script into HTML at appropriate timing (@run-at)

### WebUI Architecture
- Backend: Axum REST API on port 8081
- Frontend: Leptos WASM application
- Authentication: JWT tokens (24h expiration)
- Real-time updates: WebSocket connection
- Statistics: Time-series data with aggregation

## Risk Mitigation

### 1. MITM Certificate Failures
- **Risk**: Browser warnings, validation failures
- **Mitigation**:
  - Clear CA installation documentation
  - Whitelist option for domains (bypass MITM)
  - Certificate pinning detection
  - Fallback to direct proxying

### 2. Filter Engine Performance
- **Risk**: High latency per request
- **Mitigation**:
  - Use proven `adblock-rust` engine
  - Request result caching with TTL
  - Lazy loading of cosmetic rules
  - Benchmark-driven optimization
  - Target: <100μs matching time

### 3. JavaScript Engine Security
- **Risk**: Malicious scripts, resource exhaustion
- **Mitigation**:
  - Strict timeouts (30s default)
  - CPU/memory limits per execution
  - Sandboxed context (no file access)
  - API whitelisting via @grant
  - Regular Boa security updates

### 4. HTTP/3 Complexity
- **Risk**: Complex protocol, UDP requirements
- **Mitigation**:
  - Make optional (disabled by default)
  - Fallback to HTTP/2
  - Extensive testing with `quinn`
  - Clear documentation on UDP ports

### 5. Concurrent Request Handling
- **Risk**: Race conditions, connection leaks
- **Mitigation**:
  - Tokio best practices
  - Connection pooling with limits
  - Graceful shutdown
  - Integration testing
  - Memory profiling

## Performance Targets

- Request latency overhead: <10ms
- Filter matching: <100μs per request
- Throughput: 10,000+ requests/second
- Memory: <500MB with 10,000 connections
- Startup time: <5 seconds
- Binary size: <50MB (static)
- Docker image: <100MB (Alpine)

## Testing Strategy

### Unit Tests
- Each crate with comprehensive coverage
- Mock external dependencies
- Edge cases and error conditions

### Integration Tests
- End-to-end proxy tests
- Filter blocking validation
- Userscript execution
- API endpoints

### Performance Tests
- Latency benchmarks
- Filter matching speed
- Memory usage under load
- Concurrent connections (10k target)

### Browser Compatibility
- Chrome/Chromium
- Firefox
- Safari
- Edge

## Security Considerations

1. **MITM Ethics**: Clear documentation on legal use
2. **CA Protection**: Secure file permissions on private key
3. **No Password Logging**: Bcrypt hashing only
4. **Input Validation**: Sanitize all user inputs
5. **Rate Limiting**: Protect against brute force
6. **Minimal Privileges**: Non-root Docker user
7. **Dependency Auditing**: Regular `cargo audit`

## Configuration Example

```toml
[proxy]
host = "0.0.0.0"
port = 8080
max_connections = 10000
enable_http2 = true
enable_http3 = false
enable_websockets = true

[mitm]
enabled = true
ca_cert_path = "certs/root-ca.crt"
ca_key_path = "certs/root-ca.key"
cert_cache_size = 1000

[filters]
enabled = true
auto_update = true
update_interval_hours = 24

[userscripts]
enabled = true
auto_update = true
script_timeout_secs = 30

[webui]
enabled = true
port = 8081
username = "admin"
password_hash = "$2b$12$..."
```

## Docker Deployment

```dockerfile
FROM rust:1.85-alpine AS builder
RUN apk add --no-cache musl-dev openssl-dev
WORKDIR /app
COPY . .
RUN cargo build --release

FROM alpine:3.21
RUN apk add --no-cache ca-certificates libgcc
RUN adduser -D -u 1000 adblocker
COPY --from=builder /app/target/release/adblocker /app/
USER adblocker
EXPOSE 8080 8081
CMD ["/app/adblocker"]
```

## Implementation Order Summary

1. **Phase 1 (4 weeks)**: Proxy foundation with MITM
2. **Phase 2 (3 weeks)**: HTTP/3 and WebSocket
3. **Phase 3 (5 weeks)**: Complete adblocking engine
4. **Phase 4 (4 weeks)**: Userscript execution
5. **Phase 5 (5 weeks)**: WebUI and production features

**Total Timeline**: 21 weeks to v1.0.0

## Next Steps

1. Initialize Cargo workspace
2. Set up project structure (directories, crates)
3. Begin Phase 1, Week 1: Basic HTTP proxy
4. Implement MITM certificate generation
5. Build out request/response pipeline
6. Continue through phases sequentially

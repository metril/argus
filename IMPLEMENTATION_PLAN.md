# Rust MITM Proxy with Adblocking and Userscript Support - Implementation Plan (REVISED v2)

## Project Overview

Building a production-ready Rust MITM proxy with feature parity to AdGuard and uBlock Origin, supporting comprehensive adblocking, userscript execution, HTTP/2, HTTP/3, WebSocket, WebUI, and Docker deployment.

**Project Status**: Greenfield (empty directory)
**Location**: `/path/to/adblocker`

**Revision Notes - 2026-01-04 (v2)**: Plan updated based on comprehensive expert reviews (Rust expert, Architecture expert, Project lead, Security expert). **CRITICAL CHANGES**:

### Major Timeline & Scope Adjustments
- **Timeline**: Extended from 40-45 weeks to **65-70 weeks** (maintaining full scope with userscripts)
- **Memory Target**: Revised from 1GB to **2.5-3GB** (realistic with V8 isolates)
- **V8 Isolates**: Reduced from 50 to **10 concurrent** (with queuing)
- **Security Hardening**: Extended from 6 weeks to **12-14 weeks** (V8-specific security critical)

### Critical Technical Changes
- **Certificate Caching**: Fixed TTL (30 days + 1 hour idle, not 1 hour), disk persistence added
- **V8 Security**: Separate sandboxed process (not just isolate), seccomp-bpf filtering
- **SSRF Protection**: Comprehensive validation for GM_xmlhttpRequest (blocks RFC1918, metadata IPs)
- **JWT Storage**: httpOnly cookies (not localStorage to prevent XSS)
- **CA Key Storage**: **Must encrypt at rest** with passphrase-derived key
- **ReDoS Protection**: Regex complexity validation, compilation timeouts
- **Circuit Breakers**: Added for upstream failures (prevent cascading failures)
- **Memory Pressure**: Load shedding when approaching limits
- **Client-Side Cosmetic**: Default to `<style>` injection (server-side HTML parsing optional)
- **Domain Stats**: Bounded with moka (10k max, not unbounded DashMap)

### Dependencies Updated
```toml
deno_core = "0.350+"  # Latest (was 0.335)
rusty_v8 = "0.110+"   # Must match deno_core exactly
moka = "0.12"         # Added for bounded caching
arc-swap = "1.7"      # Added for hot-reload
governor = "0.7"      # Added for rate limiting
publicsuffix = "2.2"  # Added for domain parsing
```

### Security-Critical Additions
- Week 0: **V8 security POC** (isolate escape testing) - MANDATORY
- Weeks 52-56: **V8-specific security audit**
- Weeks 57-60: **Penetration testing** focused on userscript sandbox
- **Legal compliance**: User consent mechanism, MITM disclaimers, GDPR compliance

**Expert Assessment Summary**:
- **Rust Expert**: 6.5/10 - Good foundation, critical dependency/architecture fixes needed
- **Architecture Expert**: 6/10 - Solid design, missing circuit breakers and load shedding
- **Project Lead**: 15-25% success probability as-is, 60-70% with adjustments (keeping userscripts adds risk)
- **Security Expert**: 32% security maturity, target 85% - extensive hardening required

---

## Implementation Strategy

Based on user decisions and expert review consensus:
- **Priority**: Proxy foundation first, then filtering features
- **Filter Support**: Both AdBlock Plus and AdGuard formats with full compatibility
- **Userscripts**: **V8/deno_core with MAXIMUM SECURITY** (sandboxed process, not just isolate)
- **Authentication**: bcrypt (cost 12) + **httpOnly JWT cookies** (not localStorage)
- **Timeline**: **65-70 weeks** for production release with comprehensive security
- **Scope**: Full feature parity with AdGuard and uBlock Origin + Tampermonkey
- **Memory**: **2.5-3GB realistic target** with 10 V8 isolates (not 1GB with 50 isolates)

---

## Phased Implementation Plan

### Week 0: Critical Preparation & Security POCs (5 days) - **NEW**

**Goal**: Validate highest-risk components before committing to implementation

#### Mandatory Proof-of-Concepts:

**POC 1: MITM Certificate + Browser Acceptance** (1 day)
```rust
// Test certificate generation and browser compatibility
1. Generate Root CA with rcgen
2. Generate leaf cert for test.local
3. Test with Chrome, Firefox (verify no warnings)
4. Document CA installation procedure
```

**POC 2: V8 Security Sandbox** (2 days) - **CRITICAL**
```rust
// Validate V8 isolate security and process isolation
1. Initialize deno_core runtime with memory/CPU limits
2. Test malicious script scenarios:
   - Infinite loop (must timeout at 30s)
   - Memory bomb (must hit 50MB limit)
   - Prototype pollution attempt
   - File system access attempt (must block)
3. **Test separate process sandboxing** (bubblewrap/firejail)
4. Measure FFI overhead (Rust ↔ V8 boundary)
5. Verify no isolate escape possible
```

**POC 3: adblock-rust Integration** (1 day)
```rust
// Test filter engine performance
1. Load EasyList (100k+ rules)
2. Test 100 sample URLs (ad/non-ad)
3. Measure matching latency (<100μs target)
4. Verify AdGuard modifier support
```

**POC 4: Client-Side Cosmetic Injection** (1 day)
```rust
// Validate low-latency cosmetic filtering
1. Parse cosmetic rules from filter list
2. Generate <style> tag with hide rules
3. Inject before </head> in HTML
4. Measure latency (<5ms target)
5. Compare vs server-side HTML parsing (expected 10-50ms)
```

**Deliverable**: Go/No-Go decision document for each POC. If any POC fails significantly, revise architecture before Phase 1.

---

### Phase 1: Proxy Foundation (10-12 weeks, extended from 6-8)

**Goal**: Production-ready MITM proxy with HTTP/1.1, HTTP/2, WebSocket, and secure certificate management

**Extension Rationale**: MITM browser compatibility testing is time-intensive (2-3 weeks alone). Certificate pinning detection, CSP handling, and mobile browser edge cases require extensive debugging.

#### Week 1-2: Project Setup & Basic HTTP Proxy
1. Initialize Cargo workspace (11 crates - see structure below)
2. Basic HTTP/1.1 proxy using `hyper` 1.5 + `hyper-util` 0.1
3. Configuration management with `config` crate + validation
4. Structured logging: `tracing` + `tracing-subscriber` (JSON format)
5. Error handling: `thiserror` (libraries) + `anyhow` (binary)
6. **CI/CD pipeline** (GitHub Actions):
   - Automated testing
   - `cargo audit` (security)
   - `cargo deny` (license/ban policy)
   - `cargo clippy -- -D warnings`
7. File descriptor limits configured (ulimit 65535)

**Key Files**:
- `Cargo.toml` - Workspace with 11 crates
- `crates/proxy-core/src/server.rs` - Main proxy server
- `crates/proxy-core/src/connection.rs` - Connection handling
- `.github/workflows/ci.yml` - CI/CD with security checks

**Critical Dependencies** (corrected versions):
```toml
tokio = "1.42"
hyper = "1.5"
hyper-util = "0.1"  # CRITICAL - missing from original plan
tower = "0.5"       # Middleware pattern
```

#### Week 3-6: MITM Certificate Management (EXTENDED)

**Why 4 weeks**: Browser compatibility is complex. Each browser (Chrome, Firefox, Safari, Edge, iOS, Android) handles certs differently. Certificate pinning detection, CSP, and security headers require extensive testing.

1. Certificate Authority generation with `rcgen`
2. **On-the-fly cert generation** with **FIXED moka caching**:
   ```rust
   use moka::sync::Cache;

   pub struct CertificateCache {
       cache: Cache<Arc<str>, Arc<CertifiedKey>>,  // NOT String key
       disk_path: PathBuf,  // NEW: Disk persistence
   }

   impl CertificateCache {
       pub fn new() -> Self {
           Cache::builder()
               .max_capacity(1000)
               .time_to_live(Duration::from_secs(86400 * 30))  // 30 days (NOT 1 hour)
               .time_to_idle(Duration::from_secs(3600))        // 1 hour idle eviction
               .build()
       }

       // NEW: Persist to disk, restore on startup
       pub async fn persist_to_disk(&self) -> Result<()> {
           let entries: Vec<_> = self.cache.iter().collect();
           let serialized = bincode::serialize(&entries)?;
           fs::write(&self.disk_path, serialized).await?;
           Ok(())
       }
   }
   ```

3. TLS termination: `rustls` 0.24 + `tokio-rustls` 0.26
4. **TLS Configuration** (security hardened):
   ```rust
   use rustls::version::{TLS12, TLS13};

   let config = ServerConfig::builder()
       .with_protocol_versions(&[&TLS13, &TLS12])  // TLS 1.3 preferred, 1.2 minimum
       .with_cipher_suites(&[
           TLS13_AES_256_GCM_SHA384,
           TLS13_AES_128_GCM_SHA256,
           TLS13_CHACHA20_POLY1305_SHA256,
           // TLS 1.2 fallback (AEAD only)
           TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
       ])
       .build();
   ```

5. HTTP CONNECT method handling
6. **CA Private Key Encryption** (**CRITICAL SECURITY**):
   ```rust
   use age::Encryptor;
   use argon2::{Argon2, PasswordHasher};

   // NEVER store CA key unencrypted
   pub fn encrypt_ca_key(key_pem: &str, passphrase: &str) -> Result<Vec<u8>> {
       // Derive encryption key from passphrase (Argon2id)
       let salt = SystemRandom::new().generate_salt();
       let encryption_key = Argon2::default()
           .hash_password(passphrase.as_bytes(), &salt)?;

       // Encrypt with age (secure, modern encryption)
       let encrypted = age::encrypt(&encryption_key, key_pem.as_bytes())?;
       Ok(encrypted)
   }

   // Require passphrase on startup (NOT in env vars, NOT in config)
   pub fn get_ca_passphrase() -> Result<String> {
       use rpassword::read_password;
       print!("Enter CA passphrase: ");
       let passphrase = read_password()?;
       if passphrase.len() < 16 {
           return Err(anyhow!("Passphrase must be ≥16 characters"));
       }
       Ok(passphrase)
   }
   ```

7. SNI handling and wildcard certificate validation:
   ```rust
   const MAX_WILDCARD_LEVEL: usize = 3;  // *.example.com ok, *.com BLOCKED

   fn validate_wildcard(domain: &str) -> Result<()> {
       if domain.starts_with("*.") {
           let label_count = domain.split('.').count();
           if label_count < MAX_WILDCARD_LEVEL {
               return Err(SecurityError::OverbroadWildcard);
           }
       }
       Ok(())
   }
   ```

8. **Certificate Pinning Detection**:
   ```rust
   pub fn detect_pinning_failure(error: &TlsError, domain: &str) -> bool {
       if matches!(error,
           TlsError::CertificateVerificationFailed |
           TlsError::UnknownCA |
           TlsError::HandshakeTimeout
       ) {
           warn!("⚠️  Certificate pinning detected for {}: SECURITY CONTROL BYPASSED", domain);
           // Optional: add to bypass whitelist
           return true;
       }
       false
   }
   ```

9. Browser compatibility testing (Chrome, Firefox, Safari, Edge, iOS Safari, Chrome Android)
10. CA installation documentation (all platforms)

**Key Files**:
- `crates/proxy-core/src/ca.rs` - CA generation with encryption
- `crates/proxy-core/src/mitm.rs` - MITM logic with moka caching
- `crates/proxy-core/src/tls_config.rs` - Hardened TLS configuration
- `docs/CA_INSTALLATION.md` - Multi-platform CA setup guide
- `docs/LEGAL.md` - MITM legal disclaimers, user consent requirements

**Security Checklist**:
- [ ] CA private key encrypted at rest (age/Argon2)
- [ ] File permissions 0600 verified on startup
- [ ] Certificate pinning detection implemented
- [ ] TLS 1.3 preferred, TLS 1.2 minimum
- [ ] Only AEAD cipher suites enabled
- [ ] Wildcard certificate validation (max *.*.domain.com)

#### Week 7-9: HTTP/2, WebSocket & Request Pipeline (EXTENDED)

**Why 3 weeks**: 8-stage pipeline with Tower middleware is complex. Performance optimization to stay under 10ms latency requires careful tuning.

1. HTTP/2 support with `h2` crate
2. WebSocket proxying: `tokio-tungstenite` (CONNECT upgrade handling)
3. **3-Stage Pipeline** (start simple, expand later):
   ```rust
   // Start with 3 stages, not 8 (expand in Phase 2 if needed)
   Stage 1: Parse & Filter (network blocking)
   Stage 2: Modify & Route (request modification)
   Stage 3: Stream Response (statistics collection)
   ```

4. **Circuit Breaker** (**CRITICAL - prevents cascading failures**):
   ```rust
   use tower::ServiceBuilder;
   use tower_http::timeout::TimeoutLayer;

   let service = ServiceBuilder::new()
       .layer(CircuitBreakerLayer::new(CircuitBreakerConfig {
           failure_threshold: 5,      // Open after 5 failures
           success_threshold: 2,       // Close after 2 successes
           timeout: Duration::from_secs(30),
       }))
       .layer(TimeoutLayer::new(Duration::from_secs(30)))
       .service(proxy_handler);
   ```

5. **Resource Limits** (revised from original):
   ```rust
   pub struct ResourceLimits {
       max_connections: Semaphore,              // 10,000
       max_cert_generations: Semaphore,         // 10 (not 100 - expert recommendation)
       max_html_buffers: Semaphore,             // 200 (not 500 - memory budget)
       max_userscript_executions: Semaphore,    // 10 (not 50 - with queuing)
   }
   ```

6. **Memory Pressure Monitoring** (**NEW - critical for stability**):
   ```rust
   pub struct MemoryMonitor {
       threshold_warning: usize,   // 2.0 GB
       threshold_critical: usize,  // 2.5 GB
   }

   impl MemoryMonitor {
       pub fn should_shed_load(&self) -> LoadSheddingAction {
           let usage = get_process_memory_usage();

           if usage > self.threshold_critical {
               LoadSheddingAction::RejectConnections
           } else if usage > self.threshold_warning {
               LoadSheddingAction::DisableUserscripts
           } else {
               LoadSheddingAction::None
           }
       }
   }
   ```

7. Connection pooling with `hyper-util`
8. Graceful shutdown with `tokio::select!`
9. Benchmark suite (`criterion.rs`)
10. Streaming vs buffering decision logic

**Key Files**:
- `crates/proxy-core/src/http2.rs` - HTTP/2 handler
- `crates/proxy-core/src/websocket.rs` - WebSocket proxying
- `crates/proxy-core/src/pipeline.rs` - 3-stage pipeline
- `crates/proxy-core/src/circuit_breaker.rs` - **NEW**
- `crates/proxy-core/src/memory_monitor.rs` - **NEW**

#### Week 10-12: Docker, Testing & Documentation

1. Multi-stage Dockerfile (Debian bookworm-slim):
   ```dockerfile
   FROM rust:1.85-slim-bookworm AS builder
   # ... (build steps)

   FROM debian:bookworm-slim
   RUN useradd -m -u 64535 -U adblocker  # High UID to avoid collision

   # Drop all capabilities
   USER 64535:64535

   # Read-only root filesystem
   # Writable tmpfs for /tmp, /app/logs
   ```

2. **Docker Security Hardening**:
   ```yaml
   # docker-compose.yml
   services:
     adblocker:
       cap_drop:
         - ALL
       cap_add:
         - NET_BIND_SERVICE  # Only if binding <1024
       security_opt:
         - no-new-privileges:true
       read_only: true
       tmpfs:
         - /tmp
         - /app/logs:uid=64535,gid=64535
   ```

3. Integration tests (real browsers)
4. **Property-based testing** (proptest):
   ```rust
   proptest! {
       #[test]
       fn cert_generation_never_panics(domain in "[a-z]{1,63}(\\.[a-z]{1,63}){1,3}") {
           let _ = generate_certificate(&domain);
       }
   }
   ```

5. Load testing (`wrk` - 10k connections target)
6. Documentation: README, CA installation, legal disclaimers

**Deliverable**: v0.1.0 - MITM proxy with HTTP/1.1, HTTP/2, WebSocket

---

### Phase 2: Adblocking Engine (12-16 weeks, extended from 8-12)

**Goal**: Feature parity with AdGuard and uBlock Origin filtering

**Extension Rationale**: Client-side cosmetic filtering implementation (new approach) + extensive compatibility testing with top 1000 websites requires more time than anticipated.

#### Week 13-15: Core Filter Engine

1. Integrate `adblock-rust` 0.9+
2. AdBlock Plus syntax parser
3. **Hot-reload with ArcSwap** (zero downtime):
   ```rust
   use arc_swap::ArcSwap;

   pub struct FilterEngineManager {
       engine: Arc<ArcSwap<adblock::Engine>>,
   }

   impl FilterEngineManager {
       pub async fn reload(&self, lists: Vec<String>) -> Result<()> {
           // 1. Download with retry
           let raw_lists = download_with_retry(&lists, 3).await?;

           // 2. Validate syntax + ReDoS protection
           for rule in &raw_lists {
               validate_filter_rule_safety(rule)?;
           }

           // 3. Compile in background
           let new_engine = tokio::task::spawn_blocking(move || {
               let mut engine = adblock::Engine::new(true);
               for list in raw_lists {
                   engine.add_filter_list(&list)?;
               }
               Ok::<_, Error>(engine)
           }).await??;

           // 4. Smoke test (100 sample URLs)
           smoke_test(&new_engine, SAMPLE_URLS)?;

           // 5. Atomic swap - zero downtime
           self.engine.store(Arc::new(new_engine));

           Ok(())
       }
   }
   ```

4. **ReDoS Protection** (**CRITICAL SECURITY**):
   ```rust
   fn validate_filter_rule_safety(rule: &str) -> Result<()> {
       // Length limit
       if rule.len() > 4096 {
           return Err(ValidationError::RuleTooLong);
       }

       // Regex complexity validation
       if rule.contains('/') {
           let regex_part = extract_regex(rule)?;

           // Block dangerous patterns
           const DANGEROUS: &[&str] = &[
               r"(\w+)*",    // Nested quantifiers
               r"(\w*)+",
               r"(.*)*",
               r"(.+)+",
               r".*.*.*",    // Multiple wildcards
           ];

           for &pattern in DANGEROUS {
               if regex_part.contains(pattern) {
                   return Err(ValidationError::DangerousRegex);
               }
           }

           // Timeout compilation (1 second max)
           let result = tokio::time::timeout(
               Duration::from_secs(1),
               tokio::task::spawn_blocking(|| Regex::new(&regex_part))
           ).await;

           match result {
               Ok(Ok(Ok(_))) => Ok(()),
               _ => Err(ValidationError::RegexCompilationTimeout),
           }
       } else {
           Ok(())
       }
   }
   ```

5. **Statistics with Bounded Domain Tracking** (**FIXED**):
   ```rust
   pub struct Statistics {
       total_requests: AtomicU64,
       blocked_requests: AtomicU64,

       // FIXED: Bounded domain stats (was unbounded DashMap)
       domain_stats: Arc<moka::sync::Cache<String, Arc<DomainStats>>>,
   }

   impl Statistics {
       pub fn new() -> Self {
           let domain_stats = Cache::builder()
               .max_capacity(10_000)  // Limit to 10k domains (prevent memory exhaustion)
               .time_to_live(Duration::from_secs(3600))
               .build();

           Self { /* ... */ domain_stats }
       }
   }
   ```

6. Filter list loader with SSRF protection:
   ```rust
   fn validate_filter_list_url(url: &Url) -> Result<()> {
       // Block private IPs
       if let Some(host) = url.host() {
           match host {
               Host::Ipv4(ip) if ip.is_private() || ip.is_loopback() => {
                   return Err(ValidationError::PrivateIP);
               }
               Host::Domain(domain) if domain.contains("localhost") => {
                   return Err(ValidationError::PrivateIP);
               }
               _ => {}
           }
       }

       // Scheme whitelist
       if !matches!(url.scheme(), "http" | "https") {
           return Err(ValidationError::InvalidScheme);
       }

       Ok(())
   }
   ```

7. Request result caching with `moka`

**Key Files**:
- `crates/filter-engine/src/engine.rs` - Filter engine with ArcSwap
- `crates/filter-engine/src/parser/abp.rs` - AdBlock Plus parser
- `crates/filter-engine/src/safety.rs` - **NEW** - ReDoS protection
- `crates/proxy-stats/src/lib.rs` - Statistics with bounded tracking

#### Week 16-19: AdGuard Extensions

1. AdGuard syntax parser
2. `$replace` modifier (regex-based response modification)
3. `$removeparam` (URL parameter stripping)
4. `$removeheader` (header manipulation)
5. `$redirect` (resource redirection)
6. Domain-specific rules and exceptions (@@)
7. Testing with AdGuard filter lists (100k+ rules)
8. Compatibility testing with uBlock Origin

**Key Files**:
- `crates/filter-engine/src/parser/adguard.rs` - AdGuard parser
- `crates/filter-engine/src/modifiers/` - Modifier implementations

#### Week 20-24: Cosmetic Filtering (Client-Side Default)

**CRITICAL CHANGE**: Default to **client-side injection** (not server-side HTML parsing)

**Why**: Server-side HTML parsing at 10k req/s is a bottleneck (requires 30-150 CPU cores). Client-side injection has <5ms latency vs 10-50ms for parsing.

1. **Client-Side Cosmetic Injection** (DEFAULT):
   ```rust
   pub fn inject_cosmetic_rules(html: &str, rules: &[CosmeticRule]) -> String {
       let style_tag = format!(
           r#"<style id="adblock-cosmetic">
   {}
   </style>"#,
           rules.iter()
               .map(|r| format!("{} {{ display: none !important; }}", r.selector))
               .collect::<Vec<_>>()
               .join("\n")
       );

       // Inject before </head> - no HTML parsing needed
       html.replace("</head>", &format!("{}</head>", style_tag))
   }
   ```

2. **Server-Side HTML Parsing** (OPTIONAL, for advanced use):
   ```rust
   pub enum CosmeticStrategy {
       ClientSideOnly,        // Default - inject <style>, no parsing
       ServerSideWhenSmall,   // Parse only if <100KB
       ServerSideAlways,      // Always parse (testing only, NOT production)
   }
   ```

3. CSS injection for element hiding (##.selector)
4. **Extended CSS selectors** (limited support):
   - Simple `:has()` via client-side JavaScript
   - Complex selectors deferred to v1.1+

5. **CSP Header Handling**:
   ```rust
   fn modify_csp_for_cosmetic(csp: &str) -> String {
       // Add 'unsafe-inline' to style-src if not present
       // OR use nonce-based CSP
       if !csp.contains("style-src") {
           format!("{} style-src 'unsafe-inline'", csp)
       } else {
           csp.replace("style-src", "style-src 'unsafe-inline'")
       }
   }
   ```

6. Integration with pipeline (Stage 3: conditional buffering)
7. Performance optimization (target: <5ms client-side, <50ms server-side)
8. Size limits (5MB max for buffering)

**Key Files**:
- `crates/filter-engine/src/matcher/cosmetic.rs` - Cosmetic filtering
- `crates/filter-engine/src/css/extended.rs` - Extended CSS (limited)

**Configuration**:
```toml
[filters.cosmetic]
strategy = "client_side_only"  # Default
max_response_size = 5242880    # 5MB
enabled_for = ["text/html", "application/xhtml+xml"]
```

#### Week 25-27: Scriptlet Injection

1. Parse scriptlet rules (#%#//scriptlet(...))
2. Implement **10-15 critical scriptlets** (not 50+):
   - `abort-on-property-read`
   - `abort-on-property-write`
   - `set-constant`
   - `remove-attr`
   - `remove-class`
   - Defer remaining to v1.1+

3. JavaScript injection mechanism
4. CSP compatibility
5. Testing with popular scriptlets
6. Error handling (scriptlet failures don't break pages)

**Key Files**:
- `crates/filter-engine/src/matcher/scriptlet.rs` - Scriptlet injection
- `crates/filter-engine/src/scriptlets/core.rs` - Core scriptlet library (10-15)

#### Week 28: Auto-Update System & Testing

1. Filter list auto-updater with `reqwest`
2. Conditional requests (ETag/If-Modified-Since)
3. Checksum verification (SHA256)
4. **Validation with rollback**:
   ```rust
   pub async fn update_filters(&self) -> Result<()> {
       let old_engine = self.engine.load_full();

       let new_engine = download_and_compile().await?;

       // Validation checks
       smoke_test(&new_engine, SAMPLE_URLS)?;

       // Rule count sanity check
       if new_engine.rule_count() < old_engine.rule_count() / 2 {
           return Err(Error::SuspiciousRuleCount);
       }

       // Performance regression check
       let old_perf = benchmark_engine(&old_engine);
       let new_perf = benchmark_engine(&new_engine);
       if new_perf.avg_latency > old_perf.avg_latency * 2.0 {
           return Err(Error::PerformanceRegression);
       }

       // Atomic swap
       self.engine.store(Arc::new(new_engine));
       Ok(())
   }
   ```

5. Scheduled updates (tokio cron)
6. **Comprehensive testing** (top 1000 websites, not 100)

**Deliverable**: v0.3.0 - Full adblocking with client-side cosmetic filtering

---

### Phase 3: Userscript Engine (14-18 weeks, extended from 6-10)

**Goal**: Greasemonkey-compatible userscript execution with **MAXIMUM SECURITY**

**Extension Rationale**: V8 integration is complex (expert assessment: could add 10-15 weeks if not done carefully). Process-level sandboxing (not just isolate) requires additional implementation and testing.

**CRITICAL**: This is the highest-risk component. All security measures are mandatory.

#### Week 29-31: V8/Deno Core Integration (EXTENDED)

**Week 29**: Dependency Setup & Basic Runtime
1. Integrate latest `deno_core` (0.350+) and matching `rusty_v8` (0.110+)
   ```toml
   # CRITICAL: Versions must match exactly
   deno_core = "0.350"  # or latest
   rusty_v8 = "0.110"   # or version matching deno_core
   ```

2. **V8 Isolate Pool** (10 max, not 50):
   ```rust
   use crossbeam::queue::ArrayQueue;

   pub struct V8IsolatePool {
       idle_isolates: ArrayQueue<JsRuntime>,
       max_size: usize,  // 10
   }

   impl V8IsolatePool {
       pub async fn acquire(&self) -> Result<JsRuntime> {
           // Try to get from pool
           if let Some(isolate) = self.idle_isolates.pop() {
               return Ok(isolate);
           }

           // Pool exhausted - create new (up to max_size)
           if self.current_count() < self.max_size {
               return Ok(Self::create_isolate()?);
           }

           // Wait for available isolate (queuing)
           self.wait_for_isolate().await
       }

       pub fn release(&self, mut isolate: JsRuntime) {
           isolate.run_event_loop(false).unwrap();  // Clear state
           let _ = self.idle_isolates.push(isolate);
       }
   }
   ```

3. **V8 Configuration** (security hardened):
   ```rust
   use deno_core::JsRuntime;

   let mut runtime = JsRuntime::new(RuntimeOptions {
       max_heap_size: Some(50 * 1024 * 1024),  // 50MB hard limit
       v8_flags: vec![
           "--no-expose-wasm".to_string(),        // Disable WebAssembly
           "--jitless".to_string(),               // Disable JIT (maximum safety)
           "--no-flush-bytecode-on-gc".to_string(),
       ],
       create_params: Some(
           v8::CreateParams::default()
               .heap_limits(0, 50 * 1024 * 1024)
               .array_buffer_allocator(
                   v8::new_default_allocator()
                       .set_memory_protection(true)
               )
       ),
       ..Default::default()
   });
   ```

**Week 30**: Userscript Metadata & URL Matching
4. Parse userscript metadata (Greasemonkey format)
5. URL matching logic (@match, @include, @exclude)
6. Basic script injection into HTML

**Week 31**: Isolate Lifecycle & Timeouts
7. **CPU Timeout Enforcement** (not just wall-clock time):
   ```rust
   use std::sync::atomic::{AtomicBool, Ordering};

   struct ExecutionGuard {
       start: Instant,
       terminated: Arc<AtomicBool>,
       max_duration: Duration,  // 30s
       instruction_count: AtomicU64,
       max_instructions: u64,   // 10 million
   }

   impl ExecutionGuard {
       fn check(&self) -> Result<()> {
           // Time-based limit
           if self.start.elapsed() > self.max_duration {
               self.terminated.store(true, Ordering::SeqCst);
               return Err(SecurityError::TimeoutExceeded);
           }

           // Instruction count limit (prevent time-based evasion)
           if self.instruction_count.fetch_add(1, Ordering::Relaxed) > self.max_instructions {
               return Err(SecurityError::InstructionLimitExceeded);
           }

           Ok(())
       }
   }
   ```

8. **Memory Limit Enforcement** (heap + external):
   ```rust
   fn check_memory_limits(isolate: &mut v8::Isolate) -> Result<()> {
       let stats = isolate.get_heap_statistics();
       let total_memory = stats.total_heap_size() + stats.external_memory();

       if total_memory > MAX_TOTAL_MEMORY {
           isolate.terminate_execution();
           return Err(SecurityError::MemoryLimitExceeded);
       }

       Ok(())
   }
   ```

**Key Files**:
- `crates/userscript-engine/src/runtime.rs` - Deno Core runtime
- `crates/userscript-engine/src/isolate_pool.rs` - **NEW** - V8 isolate pooling
- `crates/userscript-engine/src/metadata.rs` - Metadata parser
- `crates/userscript-engine/src/guards.rs` - **NEW** - Timeout/memory guards

#### Week 32-35: Process-Level Sandboxing (**CRITICAL SECURITY**)

**CRITICAL**: V8 isolates alone are insufficient. Must use **process-level sandboxing**.

**Week 32-33**: Bubblewrap/Firejail Integration
1. **Separate Sandboxed Process** (not just isolate):
   ```rust
   use std::process::Command;

   pub fn execute_userscript_sandboxed(script: &str) -> Result<String> {
       // Use bubblewrap (or firejail on systems without bubblewrap)
       let mut child = Command::new("/usr/bin/bwrap")
           .arg("--unshare-all")       // Unshare all namespaces
           .arg("--die-with-parent")   // Kill if parent dies
           .arg("--ro-bind").arg("/usr").arg("/usr")  // Read-only /usr
           .arg("--proc").arg("/proc")
           .arg("--dev").arg("/dev")
           .arg("--tmpfs").arg("/tmp")
           .arg("--seccomp").arg("9")  // Seccomp profile FD
           .arg("--")
           .arg("/app/userscript-runner")  // Dedicated runner binary
           .stdin(Stdio::piped())
           .stdout(Stdio::piped())
           .stderr(Stdio::piped())
           .spawn()?;

       // Write script to stdin
       child.stdin.as_mut().unwrap().write_all(script.as_bytes())?;

       // Wait with timeout
       let output = tokio::time::timeout(
           Duration::from_secs(30),
           child.wait_with_output()
       ).await??;

       Ok(String::from_utf8(output.stdout)?)
   }
   ```

2. **Seccomp-BPF Filter** (syscall filtering):
   ```rust
   // userscript-runner/src/seccomp.rs
   use seccomp_sys::*;

   pub fn apply_seccomp_filter() -> Result<()> {
       let ctx = seccomp_init(SCMP_ACT_KILL)?;

       // Whitelist only essential syscalls
       seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0)?;
       seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0)?;
       seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0)?;
       seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0)?;
       // ... (minimal set)

       // Block dangerous syscalls
       // (execve, open, openat, fork, clone, etc. are blocked by default)

       seccomp_load(ctx)?;
       Ok(())
   }
   ```

**Week 34**: Prototype Pollution Protection
3. **Freeze Critical Prototypes**:
   ```javascript
   // Injected before userscript execution
   Object.freeze(Object.prototype);
   Object.freeze(Array.prototype);
   Object.freeze(Function.prototype);
   Object.freeze(String.prototype);
   ```

4. **Isolate Crash Recovery**:
   ```rust
   pub async fn execute_with_recovery(script: &Script) -> Result<Value> {
       let result = tokio::task::spawn_blocking(move || {
           // If V8 crashes, only this thread dies
           v8_execute(script)
       }).await;

       match result {
           Ok(Ok(value)) => Ok(value),
           Ok(Err(e)) => Err(e),
           Err(join_error) => {
               error!("V8 isolate crashed: {:?}", join_error);
               // Disable this script
               disable_script(script.id);
               Err(Error::V8Crash)
           }
       }
   }
   ```

**Week 35**: Security Testing
5. **Malicious Script Test Suite**:
   ```rust
   #[tokio::test]
   async fn test_infinite_loop_timeout() {
       let script = "while(true) {}";
       let result = execute_userscript(script).await;
       assert!(matches!(result, Err(ScriptError::Timeout)));
   }

   #[tokio::test]
   async fn test_memory_bomb() {
       let script = r#"
           const arrays = [];
           while(true) {
               arrays.push(new Array(1024 * 1024));
           }
       "#;
       let result = execute_userscript(script).await;
       assert!(matches!(result, Err(ScriptError::MemoryLimitExceeded)));
   }

   #[tokio::test]
   async fn test_file_system_access_blocked() {
       let script = r#"
           const fs = require('fs');
           fs.readFileSync('/etc/passwd');
       "#;
       let result = execute_userscript(script).await;
       assert!(matches!(result, Err(ScriptError::SecurityViolation)));
   }
   ```

**Key Files**:
- `crates/userscript-engine/src/sandbox.rs` - Process sandboxing
- `userscript-runner/` - **NEW** - Dedicated sandboxed runner binary
- `userscript-runner/src/seccomp.rs` - **NEW** - Seccomp filter
- `tests/security/malicious_scripts.rs` - **NEW** - Security test suite

#### Week 36-39: GM_* API Implementation

**Week 36**: Storage & Network APIs
1. **GM_getValue/setValue** (storage with `redb`):
   ```rust
   pub struct UserscriptStorage {
       db: Arc<redb::Database>,
   }

   impl UserscriptStorage {
       pub fn get_value(&self, script_id: &str, key: &str) -> Result<Option<String>> {
           let read_txn = self.db.begin_read()?;
           let table = read_txn.open_table(STORAGE_TABLE)?;
           let composite_key = format!("{}:{}", script_id, key);

           Ok(table.get(&composite_key)?.map(|v| v.value().to_string()))
       }
   }
   ```

2. **GM_xmlhttpRequest** with **STRICT SSRF protection**:
   ```rust
   fn validate_xhr_url(url: &Url, script_permissions: &ScriptPermissions) -> Result<()> {
       // 1. Check @connect whitelist
       if !script_permissions.allowed_domains.contains(&url.host_str().unwrap()) {
           return Err(SecurityError::DomainNotWhitelisted);
       }

       // 2. Resolve hostname (DNS rebinding protection)
       let host = url.host_str().ok_or(SecurityError::InvalidURL)?;
       let resolved_ips = tokio::net::lookup_host(format!("{}:443", host)).await?;

       for socket_addr in resolved_ips {
           let ip = socket_addr.ip();

           // 3. Block private IP ranges
           match ip {
               IpAddr::V4(ipv4) => {
                   if ipv4.is_private() ||
                      ipv4.is_loopback() ||
                      ipv4.is_link_local() ||
                      ipv4.octets()[0] == 169 && ipv4.octets()[1] == 254 ||  // AWS metadata
                      ipv4.octets()[0] == 100 && (64..=127).contains(&ipv4.octets()[1])  // CGNAT
                   {
                       return Err(SecurityError::SSRFAttempt(ip.to_string()));
                   }
               }
               IpAddr::V6(ipv6) => {
                   if ipv6.is_loopback() ||
                      ipv6.is_unicast_link_local() ||
                      (ipv6.segments()[0] & 0xfe00) == 0xfc00  // ULA
                   {
                       return Err(SecurityError::SSRFAttempt(ip.to_string()));
                   }
               }
           }
       }

       // 4. Scheme whitelist
       if !matches!(url.scheme(), "http" | "https") {
           return Err(SecurityError::InvalidScheme);
       }

       Ok(())
   }
   ```

**Week 37**: DOM & Styling APIs
3. GM_addStyle (CSS injection)
4. GM_info (script metadata)
5. GM_getResourceText (fetch @resource)

**Week 38**: Advanced APIs
6. GM_notification (desktop notifications via WebUI)
7. GM_setClipboard (clipboard access)
8. GM_registerMenuCommand (WebUI integration)

**Week 39**: Permission System
9. **Strict Permission Model**:
   ```rust
   pub struct ScriptPermissions {
       allowed_apis: HashSet<GMApi>,
       allowed_domains: Vec<String>,  // For GM_xmlhttpRequest
       max_storage_bytes: usize,      // 5MB default
       max_network_requests_per_min: u32,  // 60 default
   }

   enum GMApi {
       GetValue,
       SetValue,
       XmlHttpRequest { domain: String },
       AddStyle,
       Notification,
       Clipboard,  // Requires explicit user consent
   }
   ```

10. Storage isolation per script (namespace by script ID)
11. Network request whitelisting based on @grant

**Key Files**:
- `crates/userscript-engine/src/api/storage.rs` - Storage API
- `crates/userscript-engine/src/api/xhr.rs` - Network API with SSRF protection
- `crates/userscript-engine/src/api/dom.rs` - DOM manipulation
- `crates/userscript-engine/src/permissions.rs` - **NEW** - Permission model

#### Week 40-42: Script Management & Testing

**Week 40**: Script Manager
1. Script manager (add/remove/enable/disable)
2. Auto-update checker (@updateURL)
3. Error handling (graceful degradation)

**Week 41**: Integration Testing
4. Testing with popular userscripts:
   - Dark Reader
   - uBlock Origin Extra
   - AdsBypasser
   - Greasyfork top 100

5. Compatibility testing (Greasemonkey, Tampermonkey, Violentmonkey scripts)

**Week 42**: Performance & Documentation
6. Performance optimization (target: <50-100ms overhead with V8)
7. Script execution caching (compiled bytecode cache)
8. Documentation:
   - User guide (installing, managing scripts)
   - GM_* API reference
   - Security model explanation

**Key Files**:
- `crates/userscript-engine/src/manager.rs` - Script management
- `crates/userscript-engine/src/updater.rs` - Auto-update system
- `docs/USERSCRIPT_GUIDE.md` - User documentation
- `docs/GM_API_REFERENCE.md` - API documentation
- `docs/USERSCRIPT_SECURITY.md` - **NEW** - Security model

**Deliverable**: v0.4.0 - Full userscript support with production-grade security

---

### Phase 4: WebUI & Management (8-10 weeks, extended from 6-8)

**Goal**: Production-ready WebUI with secure authentication and real-time monitoring

**Extension Rationale**: Additional security hardening (httpOnly cookies, CSRF protection, comprehensive input validation) requires more time.

#### Week 43-44: Backend API Foundation

1. Axum web server on port 8081
2. **Secure Authentication**:
   ```rust
   use bcrypt::{hash, verify, DEFAULT_COST};
   use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};

   // Password hashing
   pub fn hash_password(password: &str) -> Result<String> {
       hash(password, DEFAULT_COST)
   }

   // JWT token generation
   pub fn generate_jwt_token(user_id: &str, secret: &[u8]) -> Result<String> {
       let claims = Claims {
           sub: user_id.to_string(),
           exp: Utc::now().timestamp() + 86400,  // 24h expiration
           iat: Utc::now().timestamp(),
       };

       encode(&Header::default(), &claims, &EncodingKey::from_secret(secret))
   }
   ```

3. **httpOnly Cookie-Based Auth** (NOT localStorage):
   ```rust
   use axum::http::header::SET_COOKIE;

   pub fn set_auth_cookie(jwt: &str) -> HeaderValue {
       let cookie = Cookie::build("auth_token", jwt)
           .http_only(true)      // Prevents JavaScript access (XSS protection)
           .secure(true)         // HTTPS only
           .same_site(SameSite::Strict)
           .max_age(time::Duration::hours(24))
           .path("/api")
           .finish();

       HeaderValue::from_str(&cookie.to_string()).unwrap()
   }
   ```

4. **JWT Secret Management** (**CRITICAL**):
   ```rust
   use ring::rand::SystemRandom;

   // Generate cryptographically random 256-bit secret
   fn generate_jwt_secret() -> [u8; 32] {
       let rng = SystemRandom::new();
       let mut secret = [0u8; 32];
       rng.fill(&mut secret).expect("RNG failure");
       secret
   }

   // Store securely (NOT in env vars, NOT in config files)
   fn store_jwt_secret_securely(secret: &[u8]) -> Result<()> {
       // Option 1: Docker secrets
       fs::write("/run/secrets/jwt_secret", secret)?;

       // Option 2: OS keyring
       #[cfg(target_os = "linux")]
       {
           use secret_service::SecretService;
           let keyring = SecretService::new()?;
           keyring.store("adblocker", "jwt_secret", secret)?;
       }

       Ok(())
   }
   ```

5. **Session Revocation**:
   ```rust
   pub struct SessionManager {
       active_tokens: Arc<DashMap<Uuid, SessionData>>,
       revoked_tokens: Arc<DashMap<String, Instant>>,  // JTI -> revocation time
   }

   impl SessionManager {
       pub fn revoke_token(&self, jti: &str) {
           self.revoked_tokens.insert(jti.to_string(), Instant::now());
       }

       pub fn is_revoked(&self, jti: &str) -> bool {
           self.revoked_tokens.contains_key(jti)
       }
   }
   ```

6. **Enhanced Rate Limiting**:
   ```rust
   use governor::{Quota, RateLimiter};

   pub struct RateLimiter {
       per_ip: DashMap<IpAddr, RateLimiter>,
       per_username: DashMap<String, RateLimiter>,
       global: RateLimiter,
   }

   impl AuthRateLimiter {
       pub fn check_login(&self, ip: IpAddr, username: &str) -> Result<()> {
           // All three must pass
           self.global.check()?;                    // 100/min globally
           self.per_ip.entry(ip).check()?;          // 5/min per IP
           self.per_username.entry(username).check()?;  // 5/min per username
           Ok(())
       }
   }
   ```

7. Configuration management API
8. Filter list management API
9. **Input Validation** (all endpoints):
   ```rust
   use validator::Validate;

   #[derive(Deserialize, Validate)]
   pub struct AddFilterListRequest {
       #[validate(url)]
       url: String,

       #[validate(length(min = 1, max = 100))]
       name: String,
   }

   async fn add_filter_list(
       Json(req): Json<AddFilterListRequest>,
   ) -> Result<Json<FilterList>> {
       // Validate
       req.validate()?;

       // SSRF protection
       let url = Url::parse(&req.url)?;
       validate_filter_list_url(&url)?;

       // Add filter list
       // ...
   }
   ```

**Key Files**:
- `crates/web-api/src/server.rs` - Axum server
- `crates/web-api/src/auth.rs` - Authentication with httpOnly cookies
- `crates/web-api/src/session.rs` - **NEW** - Session management with revocation
- `crates/web-api/src/rate_limit.rs` - **NEW** - Enhanced rate limiting
- `crates/web-api/src/routes/config.rs` - Configuration API
- `crates/web-api/src/routes/filters.rs` - Filter API

**API Endpoints**:
```
POST   /api/v1/auth/login       - Login (returns httpOnly cookie)
POST   /api/v1/auth/logout      - Logout (revoke session)
GET    /api/v1/config           - Get config
PUT    /api/v1/config           - Update config
GET    /api/v1/filters          - List filter lists
POST   /api/v1/filters          - Add filter list
DELETE /api/v1/filters/:id      - Remove filter list
```

#### Week 45-46: Extended API & WebSocket

1. Userscript management API (CRUD)
2. Statistics API (overview, time-series)
3. Logging API with filtering
4. **WebSocket for real-time updates**:
   ```rust
   use axum::extract::ws::{WebSocket, Message};

   async fn websocket_handler(
       ws: WebSocket,
       state: Arc<AppState>,
   ) {
       let (mut sender, mut receiver) = ws.split();

       // Subscribe to log events
       let mut log_rx = state.log_tx.subscribe();

       tokio::spawn(async move {
           while let Ok(log_event) = log_rx.recv().await {
               let json = serde_json::to_string(&log_event).unwrap();
               let _ = sender.send(Message::Text(json)).await;
           }
       });
   }
   ```

5. Health check endpoint (Kubernetes-ready)
6. Prometheus metrics endpoint
7. OpenAPI/Swagger documentation

**Key Files**:
- `crates/web-api/src/routes/scripts.rs` - Userscript API
- `crates/web-api/src/routes/stats.rs` - Statistics API
- `crates/web-api/src/routes/logs.rs` - Logging API
- `crates/web-api/src/websocket.rs` - WebSocket handler

#### Week 47-49: Frontend Dashboard (Leptos)

1. Leptos WASM frontend (verify 0.6 stability, use if 0.7 unstable)
2. **Authentication flow** (cookie-based):
   ```rust
   use leptos::*;

   #[component]
   pub fn LoginPage() -> impl IntoView {
       let (username, set_username) = create_signal(String::new());
       let (password, set_password) = create_signal(String::new());

       let login = create_action(move |_: &()| async move {
           let response = reqwest::Client::new()
               .post("/api/v1/auth/login")
               .json(&json!({
                   "username": username.get(),
                   "password": password.get(),
               }))
               .send()
               .await?;

           // Cookie is set automatically by browser
           if response.status().is_success() {
               window().location().set_href("/dashboard");
           }

           Ok::<_, Error>(())
       });

       view! {
           <form on:submit=move |e| {
               e.prevent_default();
               login.dispatch(());
           }>
               <input type="text" on:input=move |e| set_username.set(event_target_value(&e)) />
               <input type="password" on:input=move |e| set_password.set(event_target_value(&e)) />
               <button type="submit">"Login"</button>
           </form>
       }
   }
   ```

3. Dashboard overview (stats, charts)
4. Filter list management UI
5. Settings UI with CA certificate download
6. Responsive design
7. **XSS Protection** (all user input escaped):
   ```rust
   use ammonia::clean;

   fn sanitize_html(input: &str) -> String {
       clean(input)
   }
   ```

**Key Files**:
- `crates/web-ui/src/main.rs` - Leptos app entry
- `crates/web-ui/src/components/dashboard.rs` - Dashboard
- `crates/web-ui/src/components/filters.rs` - Filter UI
- `crates/web-ui/src/components/settings.rs` - Settings UI
- `crates/web-ui/src/api.rs` - API client

#### Week 50: Advanced UI Features

1. Userscript management UI with editor
2. Request log viewer (WebSocket real-time)
3. Statistics charts (time-series with plotters)
4. Dark mode support
5. Accessibility (WCAG 2.1 AA)

**Key Files**:
- `crates/web-ui/src/components/scripts.rs` - Userscript UI
- `crates/web-ui/src/components/logs.rs` - Log viewer

**Deliverable**: v0.8.0 - Full WebUI with secure authentication

---

### Phase 5: HTTP/3 & Production Hardening (18-20 weeks, extended from 4-6)

**Goal**: HTTP/3 support (optional) and **COMPREHENSIVE SECURITY HARDENING**

**Extension Rationale**: V8 security requires extensive testing. Comprehensive penetration testing, security audit, and legal compliance take 12-14 weeks alone.

#### Week 51-54: HTTP/3 and QUIC (Optional)

**RECOMMENDATION**: Consider deferring to v1.1+ if timeline pressure

1. Research HTTP/3 integration
2. Integrate `quinn` 0.11 for QUIC
3. Implement `h3` protocol handler
4. UDP socket configuration
5. Testing (extensive)
6. **Make optional, disabled by default**
7. Fallback to HTTP/2

**Dependencies**:
```toml
h3 = "0.0.7"        # Experimental
h3-quinn = "0.0.7"
quinn = "0.11"
```

**Key Files**:
- `crates/proxy-http3/src/http3.rs` - HTTP/3 handler
- `crates/proxy-http3/src/quic.rs` - QUIC handler

**Configuration**:
```toml
[proxy]
enable_http3 = false  # Disabled by default
```

#### Week 55-60: V8-Specific Security Hardening (**CRITICAL**)

**Week 55-56**: Security Audit
1. **V8 isolate escape testing**:
   - Type confusion attacks
   - Out-of-bounds writes
   - Use-after-free scenarios
   - JIT spray attacks (if JIT enabled)

2. **Process sandbox validation**:
   - Verify bubblewrap/firejail isolation
   - Seccomp filter effectiveness
   - Namespace isolation
   - Capability dropping

3. **SSRF attack testing**:
   - AWS metadata server (169.254.169.254)
   - Google Cloud metadata
   - Private IP ranges
   - DNS rebinding attacks

**Week 57-58**: Penetration Testing
4. **Hire external security firm** (recommended) for:
   - WebUI penetration testing (XSS, CSRF, SQL injection)
   - Authentication bypass attempts
   - Session fixation attacks
   - Privilege escalation testing
   - Filter list injection attacks

5. **Fuzzing** (continuous):
   ```rust
   // Use cargo-fuzz
   #[cfg(fuzzing)]
   use libfuzzer_sys::fuzz_target;

   fuzz_target!(|data: &[u8]| {
       if let Ok(s) = std::str::from_utf8(data) {
           let _ = parse_filter_rule(s);
           let _ = parse_userscript_metadata(s);
       }
   });
   ```

**Week 59**: Security Fix Sprint
6. Fix all findings from security audit
7. Re-test after fixes
8. Document security posture

**Week 60**: Security Documentation
9. Security model documentation
10. Threat model document
11. Security best practices guide

**Key Files**:
- `docs/SECURITY.md` - **NEW** - Security model
- `docs/THREAT_MODEL.md` - **NEW** - Threat analysis
- `docs/SECURITY_BEST_PRACTICES.md` - **NEW** - Deployment security

#### Week 61-64: Production Hardening & Load Testing

**Week 61-62**: Load Testing
1. **Sustained load testing** (48+ hours):
   ```bash
   # 10k concurrent connections
   wrk -t 12 -c 10000 -d 48h --latency http://localhost:8080
   ```

2. Memory leak detection:
   ```bash
   valgrind --leak-check=full --show-leak-kinds=all ./target/release/adblocker
   # OR
   heaptrack ./target/release/adblocker
   ```

3. **CPU profiling**:
   ```bash
   perf record -F 999 -g ./target/release/adblocker
   perf report
   ```

4. **Chaos engineering**:
   ```rust
   #[tokio::test]
   async fn test_upstream_random_failures() {
       let proxy = TestProxy::new()
           .with_chaos(ChaosConfig {
               upstream_failure_rate: 0.1,  // 10% failures
               latency_injection: Duration::from_millis(100),
           })
           .start()
           .await;

       for _ in 0..10000 {
           let resp = proxy.request("/test").await;
           // Should handle gracefully
       }
   }
   ```

**Week 63**: Performance Optimization
5. Profile hot paths (perf, flamegraph)
6. Optimize based on profiling
7. Reduce allocations in hot paths
8. SIMD optimizations (if applicable)

**Week 64**: Final Integration Testing
9. All components working together
10. Browser compatibility (Chrome, Firefox, Safari, Edge, iOS, Android)
11. Top 1000 websites working correctly
12. Graceful degradation on errors

**Key Files**:
- `tests/load/sustained_load.rs` - **NEW** - Load testing
- `tests/chaos/chaos_test.rs` - **NEW** - Chaos engineering

#### Week 65-68: Legal Compliance & Documentation

**Week 65**: Legal Compliance (**CRITICAL**)
1. **User Consent Mechanism**:
   ```rust
   // First-run consent flow
   async fn first_run_setup() -> Result<()> {
       println!("=== MITM Proxy Legal Notice ===");
       println!("This software intercepts TLS traffic (MITM).");
       println!("You MUST obtain consent from all affected users.");
       println!();
       println!("By continuing, you certify that:");
       println!("1. You own/administer this network");
       println!("2. All users have provided informed consent");
       println!("3. You comply with applicable wiretapping laws");
       println!();
       print!("Type 'I AGREE' to continue: ");

       let mut input = String::new();
       std::io::stdin().read_line(&mut input)?;

       if input.trim() != "I AGREE" {
           eprintln!("Setup aborted. Consent required.");
           std::process::exit(1);
       }

       // Log consent acceptance
       audit_log(Event::ConsentAccepted, Utc::now());

       Ok(())
   }
   ```

2. **Privacy Policy** (GDPR compliance):
   ```markdown
   # Privacy Policy

   ## Data Processing
   - URLs visited (for adblocking)
   - Request/response headers (for filtering)
   - Userscripts installed (for execution)
   - Authentication credentials (hashed with bcrypt)

   ## Legal Basis
   - Consent: User installs proxy and configures browser
   - Legitimate Interest: Network security and ad blocking

   ## Data Retention
   - Logs: 30 days (auto-deleted)
   - Statistics: Anonymized, indefinite
   - CA certificates: Until rotation (365 days)

   ## User Rights (GDPR Article 15-20)
   - Access: Export data via /api/v1/export
   - Erasure: Delete account via /api/v1/delete-account
   - Rectification: Update config via /api/v1/config
   - Portability: JSON export available

   ## Data Breach Notification
   - Notification within 72 hours (GDPR Article 33)
   - Contact: security@example.com
   ```

3. **Legal Disclaimers**:
   ```markdown
   # Legal Disclaimer

   ## WARNING: MITM Interception

   This software performs TLS interception (Man-in-the-Middle).

   ### LEGAL USE ONLY
   - Personal devices you own
   - Networks you administer with authorization
   - Users who have provided explicit informed consent

   ### ILLEGAL USE (Criminal Offenses)
   - Intercepting traffic without consent (wiretapping - 18 U.S.C. § 2511)
   - Corporate networks without IT authorization (CFAA violation)
   - Public WiFi hotspots (criminal hacking)

   ### JURISDICTION-SPECIFIC LAWS
   - USA: Wiretap Act (18 U.S.C. § 2511)
   - EU: ePrivacy Directive (2002/58/EC)
   - UK: Investigatory Powers Act 2016

   **DISCLAIMER**: The authors assume NO LIABILITY for misuse.
   Consult a lawyer before deployment.
   ```

4. **Export Control Notice**:
   ```markdown
   ## Export Control Notice

   This software contains cryptographic functionality.
   Export/import may be restricted in some jurisdictions.

   - USA: BIS EAR 742.15(b) - publicly available encryption
   - EU: Dual-use regulation (EU) 2021/821
   ```

**Week 66-67**: Documentation Sprint
5. **User Guide** (installation, configuration, troubleshooting)
6. **Administrator Guide** (deployment, monitoring, maintenance)
7. **Architecture Documentation** (for contributors)
8. **Migration Guides** (from Pi-hole, AdGuard Home, Privoxy)
9. **API Documentation** (OpenAPI/Swagger + rustdoc)
10. **Troubleshooting Guide** (common issues, solutions)

**Documentation Structure**:
```
docs/
├── USER_GUIDE.md              # End-user documentation
├── ADMIN_GUIDE.md             # System administrator guide
├── CA_INSTALLATION.md         # CA setup (all platforms)
├── USERSCRIPT_GUIDE.md        # Writing/installing userscripts
├── GM_API_REFERENCE.md        # GM_* API documentation
├── USERSCRIPT_SECURITY.md     # Security model for userscripts
├── MIGRATION_GUIDE.md         # Migration from other tools
├── ARCHITECTURE.md            # System architecture
├── CONTRIBUTING.md            # Contributor guide
├── TROUBLESHOOTING.md         # Common issues/solutions
├── LEGAL.md                   # MITM disclaimers, consent
├── PRIVACY_POLICY.md          # GDPR compliance
├── SECURITY.md                # Security model
├── THREAT_MODEL.md            # Threat analysis
└── HTTP3_SETUP.md             # HTTP/3 config (if implemented)
```

**Week 68**: Docker Multi-Arch & Release Prep
11. Multi-arch Docker builds (amd64, arm64):
    ```bash
    docker buildx build --platform linux/amd64,linux/arm64 -t adblocker:1.0.0 .
    ```

12. Release notes and changelog
13. Final bug fixes
14. **Security disclosure policy**:
    ```markdown
    # Security Policy

    ## Reporting a Vulnerability

    **DO NOT** open a public issue for security vulnerabilities.

    Email: security@example.com
    PGP Key: [key fingerprint]

    ## Response Timeline
    - Acknowledgment: Within 24 hours
    - Initial assessment: Within 72 hours
    - Fix timeline: Depends on severity
      - Critical: 7 days
      - High: 14 days
      - Medium: 30 days

    ## Disclosure Policy
    - Coordinated disclosure (90 days)
    - CVE assignment if applicable
    - Public advisory after fix
    ```

**Week 69-70**: Final Testing & v1.0.0 Release

15. **Production Readiness Checklist**:
    - [ ] CA private key encrypted at rest
    - [ ] Userscripts sandboxed in separate process
    - [ ] SSRF protection implemented and tested
    - [ ] ReDoS protection in filter parsing
    - [ ] JWT in httpOnly cookies
    - [ ] All secrets in secure storage (NOT env vars)
    - [ ] Docker security hardened (capabilities, read-only, high UID)
    - [ ] Legal disclaimers and consent mechanism
    - [ ] Privacy policy (GDPR compliant)
    - [ ] Security audit completed
    - [ ] Penetration testing completed
    - [ ] Load testing passed (10k connections, 48+ hours)
    - [ ] Memory leaks addressed
    - [ ] All documentation complete
    - [ ] Multi-arch Docker images built
    - [ ] Security disclosure policy published

16. Final smoke tests
17. Release v1.0.0
18. Public announcement

**Deliverable**: **v1.0.0 - Production-Ready Release**

---

## Updated Project Structure

```
adblocker/
├── Cargo.toml                      # Workspace (11 crates)
├── Dockerfile                      # Multi-stage Debian build
├── compose.yaml
├── README.md
├── LICENSE
├── CHANGELOG.md
├── SECURITY.md                     # Security disclosure policy
├── config/
│   ├── default.toml
│   └── production.toml
├── certs/                          # Runtime CA certs (gitignored)
├── data/
│   ├── filters/
│   ├── userscripts/
│   └── db/                         # redb databases
├── logs/                           # Application logs (gitignored)
├── docs/                           # Documentation (14 files)
│   ├── USER_GUIDE.md
│   ├── ADMIN_GUIDE.md
│   ├── CA_INSTALLATION.md
│   ├── USERSCRIPT_GUIDE.md
│   ├── GM_API_REFERENCE.md
│   ├── USERSCRIPT_SECURITY.md      # NEW
│   ├── MIGRATION_GUIDE.md
│   ├── ARCHITECTURE.md
│   ├── CONTRIBUTING.md
│   ├── TROUBLESHOOTING.md
│   ├── LEGAL.md
│   ├── PRIVACY_POLICY.md           # NEW
│   ├── SECURITY.md                 # NEW
│   ├── THREAT_MODEL.md             # NEW
│   └── HTTP3_SETUP.md
├── .github/
│   └── workflows/
│       ├── ci.yml                  # CI/CD with security checks
│       └── security.yml            # Weekly cargo-audit
├── crates/
│   ├── proxy-core/                 # Phase 1
│   │   └── src/
│   │       ├── server.rs
│   │       ├── connection.rs
│   │       ├── mitm.rs
│   │       ├── ca.rs
│   │       ├── tls_config.rs       # NEW
│   │       ├── http2.rs
│   │       ├── websocket.rs
│   │       ├── pipeline.rs
│   │       ├── circuit_breaker.rs  # NEW
│   │       ├── memory_monitor.rs   # NEW
│   │       ├── config.rs
│   │       └── error.rs
│   │
│   ├── proxy-middleware/           # Pipeline middleware
│   │   └── src/
│   │       ├── filter_stage.rs
│   │       ├── cosmetic_stage.rs
│   │       ├── userscript_stage.rs
│   │       └── stats_stage.rs
│   │
│   ├── proxy-http3/                # Phase 5 (optional)
│   │   └── src/
│   │       ├── http3.rs
│   │       └── quic.rs
│   │
│   ├── proxy-types/                # Shared types
│   ├── proxy-stats/                # Statistics (bounded)
│   ├── proxy-config/               # Configuration
│   │
│   ├── filter-engine/              # Phase 2
│   │   └── src/
│   │       ├── engine.rs
│   │       ├── safety.rs           # NEW - ReDoS protection
│   │       ├── parser/
│   │       │   ├── abp.rs
│   │       │   └── adguard.rs
│   │       ├── matcher/
│   │       │   ├── network.rs
│   │       │   ├── cosmetic.rs
│   │       │   └── scriptlet.rs
│   │       ├── modifiers/
│   │       ├── css/
│   │       ├── scriptlets/
│   │       │   └── core.rs         # 10-15 critical scriptlets
│   │       ├── updater.rs
│   │       └── list.rs
│   │
│   ├── userscript-engine/          # Phase 3
│   │   └── src/
│   │       ├── runtime.rs
│   │       ├── isolate_pool.rs     # NEW
│   │       ├── metadata.rs
│   │       ├── injector.rs
│   │       ├── sandbox.rs          # Process sandboxing
│   │       ├── guards.rs           # NEW - Timeout/memory guards
│   │       ├── manager.rs
│   │       ├── updater.rs
│   │       ├── permissions.rs      # NEW
│   │       └── api/
│   │           ├── storage.rs      # redb
│   │           ├── xhr.rs          # With SSRF protection
│   │           └── dom.rs
│   │
│   ├── web-api/                    # Phase 4
│   │   └── src/
│   │       ├── server.rs
│   │       ├── auth.rs             # httpOnly cookies
│   │       ├── session.rs          # NEW - Session revocation
│   │       ├── rate_limit.rs       # NEW - Enhanced rate limiting
│   │       ├── websocket.rs
│   │       └── routes/
│   │           ├── config.rs
│   │           ├── filters.rs
│   │           ├── scripts.rs
│   │           ├── stats.rs
│   │           └── logs.rs
│   │
│   └── web-ui/                     # Phase 4 - Leptos
│       └── src/
│           ├── main.rs
│           ├── api.rs
│           └── components/
│
├── userscript-runner/              # NEW - Sandboxed runner binary
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       └── seccomp.rs              # Seccomp filter
│
├── tests/
│   ├── integration/
│   ├── security/
│   │   └── malicious_scripts.rs    # NEW
│   ├── load/
│   │   └── sustained_load.rs       # NEW
│   └── chaos/
│       └── chaos_test.rs           # NEW
│
└── benches/
    ├── proxy_bench.rs
    └── filter_bench.rs
```

---

## Updated Critical Dependencies

```toml
[workspace.dependencies]
# Core Proxy
tokio = "1.42"
hyper = "1.5"
hyper-util = "0.1"                  # CRITICAL - was missing
rustls = "0.24"                     # Updated from 0.23
tokio-rustls = "0.26"               # Updated to match rustls
rcgen = "0.13"
h2 = "0.4"

# Middleware
tower = "0.5"
tower-http = "0.6"

# Caching & Concurrency
moka = { version = "0.12", features = ["future"] }  # ADDED
arc-swap = "1.7"                                     # ADDED
dashmap = "6.1"

# Error Handling
thiserror = "2.0"
anyhow = "1.0"

# Configuration
config = "0.14"
serde = { version = "1.0", features = ["derive"] }
validator = "0.18"                  # ADDED for input validation

# Logging & Metrics
tracing = "0.1"
tracing-subscriber = "0.3"
metrics = "0.24"

# HTTP/3 (optional)
h3 = "0.0.7"
h3-quinn = "0.0.7"
quinn = "0.11"
tokio-tungstenite = "0.24"

# Filter Engine
adblock = "0.9"
html5ever = "0.28"
cssparser = "0.31"
selectors = "0.25"
reqwest = "0.12"
url = "2.5"
regex = "1.11"
publicsuffix = "2.2"                # ADDED for domain parsing

# Userscript Engine (V8)
deno_core = "0.350"                 # Updated from 0.335
rusty_v8 = "0.110"                  # Updated from 0.105 (must match deno_core)

# Storage
redb = "2.1"

# WebUI
axum = { version = "0.8", features = ["ws", "multipart"] }
bcrypt = "0.16"
jsonwebtoken = "9.3"
leptos = { version = "0.6", features = ["csr"] }
leptos_router = "0.6"

# Security
governor = "0.7"                    # ADDED for rate limiting
age = "0.10"                        # ADDED for CA key encryption
argon2 = "0.5"                      # ADDED for key derivation
ammonia = "4.0"                     # ADDED for HTML sanitization
zeroize = "1.8"                     # ADDED for secure memory clearing

# Sandboxing (Linux)
[target.'cfg(target_os = "linux")'.dependencies]
caps = "0.5"                        # Capability management
nix = { version = "0.29", features = ["process", "sched"] }  # Namespaces

# Testing
mockito = "1.6"
proptest = "1.6"
criterion = "0.5"
```

---

## Updated Performance Targets (REALISTIC)

### Memory
- **Without userscripts**: <1.5GB with 10k connections
- **With userscripts**: **2.5-3GB** with 10k connections (10 V8 isolates)
- **Per V8 isolate**: ~50MB (10 isolates = 500MB baseline)
- **HTML buffers**: 200 max × 5MB = 1GB max
- **Base process**: 200-300MB

### Latency (p50/p99)
- **Proxy only**: 5ms / 15ms
- **+ Network filtering**: 6ms / 20ms
- **+ Cosmetic filtering (client-side)**: 7ms / 25ms
- **+ Cosmetic filtering (server-side)**: 15ms / 60ms
- **+ Userscripts**: **80ms / 200ms** (V8 overhead)

### Throughput
- **Proxy only**: 10,000+ req/s
- **With filtering**: 5,000+ req/s
- **With userscripts**: 2,000-3,000 req/s (V8 bottleneck)

### Other
- **Startup time**: <5 seconds (with cached filters)
- **Binary size**: ~100MB (with V8, larger but acceptable)
- **Docker image**: ~150MB (Debian slim + dependencies)
- **Filter matching**: <100μs per request
- **Certificate generation**: <50ms per cert (cached for 30 days)

---

## Updated Risk Register

| Risk | Severity | Probability | Mitigation | Status |
|------|----------|-------------|------------|--------|
| **V8 integration complexity** | **CRITICAL** | 70% | Week 0 POC, process sandboxing, 18-week Phase 3 | Active |
| **V8 isolate escape** | **CRITICAL** | 40% | Separate process + seccomp, security audit | Active |
| **SSRF via GM_xmlhttpRequest** | HIGH | 60% | Comprehensive URL validation, IP blocking | Active |
| **CA private key theft** | **CRITICAL** | 30% | Encrypt at rest, file permissions, audit | Active |
| **ReDoS in filter lists** | HIGH | 50% | Regex complexity validation, timeouts | Active |
| **Timeline overrun** | HIGH | 60% | 65-70 week timeline (realistic), weekly check-ins | Mitigated |
| **Memory exhaustion** | MEDIUM | 50% | Load shedding, bounded caches, monitoring | Active |
| **MITM cert browser compat** | MEDIUM | 40% | Extensive testing, pinning detection | Active |
| **HTTP/3 delays project** | MEDIUM | 50% | Optional (disabled by default), defer if needed | Mitigated |
| **Security audit failures** | HIGH | 40% | 12-week security hardening, external pentest | Active |
| **Legal compliance issues** | HIGH | 30% | User consent, disclaimers, privacy policy | Active |
| **Single developer burnout** | **CRITICAL** | 70% | 1-week breaks every 6 weeks, realistic timeline | Active |

---

## Implementation Timeline Summary

| Phase | Weeks | Deliverable | Security Focus |
|-------|-------|-------------|----------------|
| **Week 0** | 1 | POCs validated | V8 security POC |
| **Phase 1** | 10-12 | v0.1.0 - MITM Proxy | CA encryption, TLS hardening |
| **Phase 2** | 12-16 | v0.3.0 - Adblocking | ReDoS protection, SSRF prevention |
| **Phase 3** | 14-18 | v0.4.0 - Userscripts | **Process sandboxing, V8 isolation** |
| **Phase 4** | 8-10 | v0.8.0 - WebUI | httpOnly cookies, session security |
| **Phase 5** | 18-20 | **v1.0.0 - Production** | **Security audit, pentesting, legal** |
| **TOTAL** | **65-70** | Full production release | Comprehensive security |

---

## Critical Success Factors (UPDATED)

### Week 0 (Mandatory):
- [ ] MITM cert browser acceptance validated
- [ ] **V8 security POC passed** (isolate escape testing)
- [ ] adblock-rust performance acceptable
- [ ] Client-side cosmetic injection validated

### Before Phase 1:
- [ ] All dependencies pinned (exact versions)
- [ ] CI/CD with security checks configured
- [ ] Docker security hardening designed

### Before Phase 2:
- [ ] MITM working with all major browsers
- [ ] Circuit breakers tested under load
- [ ] Memory pressure monitoring implemented

### Before Phase 3:
- [ ] Filter engine hot-reload zero-downtime
- [ ] ReDoS protection validated
- [ ] Client-side cosmetic filtering performance acceptable

### Before Phase 4:
- [ ] **V8 process sandboxing working** (bubblewrap/seccomp)
- [ ] **SSRF protection tested** (AWS metadata, private IPs)
- [ ] V8 isolate pool with queuing functional
- [ ] All malicious script tests passing

### Before Phase 5:
- [ ] WebUI authentication secure (httpOnly, session revocation)
- [ ] All API endpoints input-validated
- [ ] Rate limiting functional

### Before v1.0.0 Release:
- [ ] **Security audit completed** (V8-specific)
- [ ] **Penetration testing passed**
- [ ] Load testing (10k connections, 48+ hours)
- [ ] Memory leaks addressed
- [ ] **Legal compliance** (consent, disclaimers, privacy policy)
- [ ] All documentation complete
- [ ] Multi-arch Docker images built

---

## Next Steps

### Immediate (Week 0):

1. **Development Environment Setup**:
   - Install Rust 1.85+
   - Install Docker with buildx
   - Install bubblewrap (or firejail)
   - Install security tools (valgrind, heaptrack, perf)

2. **Repository Setup**:
   - Create GitHub repository
   - Set up CI/CD (cargo-audit, cargo-deny, clippy)
   - Configure branch protection

3. **Run Mandatory POCs** (5 days):
   - POC 1: MITM cert + browser acceptance
   - **POC 2: V8 security sandbox** (CRITICAL)
   - POC 3: adblock-rust integration
   - POC 4: Client-side cosmetic injection

4. **Go/No-Go Decision**:
   - If all POCs pass: Proceed to Phase 1
   - If V8 POC fails: Consider alternatives (QuickJS/rquickjs)
   - Document results

### Week 1-2 (Phase 1 Start):

1. Initialize Cargo workspace (11 crates)
2. Set up configuration schema
3. Basic HTTP/1.1 proxy
4. Logging infrastructure
5. Begin MITM cert implementation

---

## Change Log

**2026-01-04 v2 - MAJOR REVISION (Expert Review Integration)**:

### Timeline & Scope
- Extended timeline: 40-45 weeks → **65-70 weeks**
- Added Week 0: Mandatory POCs (V8 security critical)
- Phase 1: 6-8 weeks → 10-12 weeks (MITM complexity)
- Phase 2: 8-12 weeks → 12-16 weeks (cosmetic filtering strategy change)
- Phase 3: 6-10 weeks → **14-18 weeks** (V8 security hardening)
- Phase 4: 6-8 weeks → 8-10 weeks (security hardening)
- Phase 5: 4-6 weeks → **18-20 weeks** (comprehensive security audit)
- **Kept userscripts in v1.0** (user decision, acknowledged high risk)

### Memory & Performance
- Memory target: 1GB → **2.5-3GB** (realistic with 10 V8 isolates)
- V8 isolates: 50 concurrent → **10 concurrent** (with queuing)
- HTML buffers: 500 → **200** (memory budget)
- Cert generation semaphore: 100 → **10**
- Latency with userscripts: <50ms → **<80-100ms** (realistic V8 overhead)

### Critical Architecture Changes
- **Certificate caching**: 1h TTL → 30d TTL + 1h idle eviction, disk persistence
- **V8 sandboxing**: Isolates only → **Separate process + seccomp-bpf**
- **Cosmetic filtering**: Server-side default → **Client-side default** (5ms vs 50ms)
- **Domain stats**: Unbounded DashMap → **Bounded moka Cache** (10k max)
- **JWT storage**: localStorage → **httpOnly cookies** (XSS protection)
- **Added circuit breakers** (prevent cascading failures)
- **Added memory pressure monitoring** (load shedding)

### Security Enhancements
- **CA key encryption**: Unencrypted → **Encrypted at rest** (age/Argon2, passphrase required)
- **SSRF protection**: Basic → **Comprehensive** (RFC1918, metadata IPs, DNS rebinding)
- **ReDoS protection**: None → **Regex complexity validation** + compilation timeout
- **V8 timeout**: Wall-clock only → **Instruction count + wall-clock**
- **V8 memory**: Heap only → **Heap + external memory limits**
- **TLS configuration**: Defaults → **Hardened** (TLS 1.3 preferred, AEAD only)
- **Wildcard certs**: No validation → **Max depth validation** (*.*.domain.com max)
- **Session management**: No revocation → **Session revocation support**
- **Rate limiting**: IP-based → **IP + username + global**

### Dependencies Updated
```toml
# Version bumps
deno_core = "0.335" → "0.350+"
rusty_v8 = "0.105" → "0.110+"
rustls = "0.23" → "0.24"
tokio-rustls = "0.25" → "0.26"

# Added dependencies
hyper-util = "0.1"        # Was missing
moka = "0.12"             # Bounded caching
arc-swap = "1.7"          # Hot-reload
governor = "0.7"          # Rate limiting
publicsuffix = "2.2"      # Domain parsing
age = "0.10"              # CA key encryption
argon2 = "0.5"            # Key derivation
ammonia = "4.0"           # HTML sanitization
zeroize = "1.8"           # Secure memory clearing
validator = "0.18"        # Input validation
```

### New Components
- `crates/proxy-core/src/tls_config.rs` - Hardened TLS
- `crates/proxy-core/src/circuit_breaker.rs` - Circuit breakers
- `crates/proxy-core/src/memory_monitor.rs` - Memory pressure
- `crates/filter-engine/src/safety.rs` - ReDoS protection
- `crates/userscript-engine/src/isolate_pool.rs` - V8 pooling
- `crates/userscript-engine/src/guards.rs` - Timeout/memory guards
- `crates/userscript-engine/src/permissions.rs` - Permission model
- `crates/web-api/src/session.rs` - Session revocation
- `crates/web-api/src/rate_limit.rs` - Enhanced rate limiting
- `userscript-runner/` - **New crate** - Sandboxed runner binary
- `userscript-runner/src/seccomp.rs` - Seccomp filter
- `tests/security/malicious_scripts.rs` - Security tests
- `tests/load/sustained_load.rs` - Load testing
- `tests/chaos/chaos_test.rs` - Chaos engineering

### Documentation Added
- `docs/USERSCRIPT_SECURITY.md` - Security model
- `docs/PRIVACY_POLICY.md` - GDPR compliance
- `docs/SECURITY.md` - Security disclosure
- `docs/THREAT_MODEL.md` - Threat analysis
- `docs/LEGAL.md` - Updated with comprehensive disclaimers
- `SECURITY.md` - Root-level security policy

### Testing Enhancements
- Added property-based testing (proptest)
- Added malicious userscript test suite
- Added sustained load testing (48+ hours)
- Added chaos engineering tests
- Added fuzzing infrastructure (cargo-fuzz)

### Legal & Compliance
- Added user consent mechanism (first-run)
- Added MITM legal disclaimers
- Added privacy policy (GDPR Article 13)
- Added export control notice
- Added security disclosure policy

### Risk Management
- Updated risk register with V8-specific risks
- Added burnout mitigation (1-week breaks every 6 weeks)
- Adjusted timeline to realistic 65-70 weeks
- Acknowledged 60-70% success probability (vs 15-25% at 45 weeks)

---

**Expert Review Summary**:
- **Rust Expert**: Identified critical dependency issues, architecture flaws, V8 complexity risks
- **Architecture Expert**: Identified missing circuit breakers, bounded cache needs, cosmetic filtering bottleneck
- **Project Lead**: Assessed 15-25% success probability without scope/timeline adjustments
- **Security Expert**: Identified 13 critical vulnerabilities requiring immediate attention

**User Decisions**:
1. ❌ Keep userscripts in v1.0 (not removing)
2. ✅ Accept 65-70 week timeline
3. ✅ Accept 2.5-3GB memory target
4. ✅ Commit to comprehensive security hardening

**Approved for implementation with acknowledged high risk due to V8 integration complexity.**


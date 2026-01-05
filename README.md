# Rust MITM Proxy with Adblocking and Userscript Support

A high-performance, production-ready MITM proxy written in Rust with comprehensive adblocking (AdGuard/uBlock Origin feature parity) and Greasemonkey-compatible userscript execution.

## Features

### Core Proxy (Phase 1 - v0.1.0)
- HTTP/1.1 and HTTP/2 support
- MITM TLS interception with on-the-fly certificate generation
- Certificate caching (30-day TTL, 1-hour idle eviction)
- Connection pooling and graceful shutdown
- Request/response pipeline architecture

### Advanced Protocols (Phase 2 - v0.2.0)
- HTTP/3 and QUIC support (optional, disabled by default)
- WebSocket proxying with frame-level control

### Adblocking Engine (Phase 3 - v0.3.0)
- AdBlock Plus and AdGuard syntax support
- Network request blocking (all filter modifiers)
- Cosmetic filtering (element hiding, CSS injection)
- Scriptlet injection
- Auto-updating filter lists (EasyList, AdGuard, uBlock Origin)
- Client-side cosmetic filtering by default (5ms vs 50ms)

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

# Build release binary
cargo build --release

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
max_concurrent_isolates = 10

[webui]
enabled = true
port = 8081
username = "admin"
password_hash = "$2b$12$..."  # Generate with: bcrypt-cli hash "your-password"
```

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

## Status

**Current Version**: v0.0.1 (Pre-alpha)

This project is under active development. Phase 1 (Core proxy) is in progress.

# Multi-stage Dockerfile for Argus MITM Proxy
# Multi-arch: linux/amd64, linux/arm64
# Build:  docker build -t argus .
#         docker buildx build --platform linux/amd64,linux/arm64 -t argus .
#
# Uses cargo-chef for dependency caching - incremental builds are ~10x faster.
# No system TLS libs / OpenSSL: the proxy side uses rustls, the upstream client (vendored wreq)
# uses BoringSSL compiled from source by btls-sys (needs cmake, a C++ compiler, perl and libclang
# for bindgen) and linked statically, with libstdc++ linked statically too. CI fails if
# openssl-sys ever appears in the dependency tree.

# Pinned toolchain version - keep in sync with rust-toolchain.toml
ARG RUST_VERSION=1.92
ARG CARGO_CHEF_VERSION=0.1.77
ARG TRUNK_VERSION=0.21.14
# Must match the wasm-bindgen crate version in Cargo.lock (checked in the webui-builder stage)
ARG WASM_BINDGEN_VERSION=0.2.125

# Stage 1: Chef base - stable Rust on musl + cargo-chef
FROM rust:${RUST_VERSION}-alpine3.21 AS chef

# Build dependencies (ring needs a C toolchain + perl/make; xz unpacks cargo-chef; BoringSSL via
# btls-sys needs cmake + g++ + git (it patches BoringSSL), bindgen needs libclang (clang-dev)
# and the kernel headers).
RUN apk add --no-cache musl-dev gcc g++ make cmake perl pkgconfig curl xz clang-dev linux-headers git

# bindgen locates libclang here (Alpine 3.21 ships LLVM 19); verified to exist at build time.
ENV LIBCLANG_PATH=/usr/lib/llvm19/lib
# Link libstdc++ (needed by BoringSSL's C++ sources) statically so the runtime image stays minimal.
ENV BORING_BSSL_RUST_CPPLIB=static=stdc++
RUN test -e "$LIBCLANG_PATH/libclang.so"
# bindgen (in btls-sys's build script) must dlopen libclang, which a crt-static musl build script
# cannot do. RUSTFLAGS applies to build scripts too, so crt-static is switched off for the whole
# build; the final binary is linked fully static again below. Set once so cook and build share
# fingerprints.
# rustc does not search /usr/lib for `static=` libraries unless told to (libstdc++.a is there).
RUN test -e /usr/lib/libstdc++.a
ENV RUSTFLAGS="-C target-feature=-crt-static -L native=/usr/lib"

# Download the pre-built cargo-chef binary (arch-aware, pinned - much faster than compiling)
ARG CARGO_CHEF_VERSION
ARG TARGETARCH
RUN case "$TARGETARCH" in \
      amd64) CHEF_ARCH=x86_64 ;; \
      arm64) CHEF_ARCH=aarch64 ;; \
      *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac && \
    mkdir -p /tmp/chef && \
    curl -fsSL "https://github.com/LukeMathWalker/cargo-chef/releases/download/v${CARGO_CHEF_VERSION}/cargo-chef-${CHEF_ARCH}-unknown-linux-musl.tar.xz" \
      | tar -xJf - -C /tmp/chef --strip-components=1 && \
    mv /tmp/chef/cargo-chef "$CARGO_HOME/bin/cargo-chef" && \
    chmod +x "$CARGO_HOME/bin/cargo-chef" && \
    rm -rf /tmp/chef

WORKDIR /build

# Stage 2: Planner - analyze dependencies and create recipe
FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY vendor ./vendor
RUN cargo chef prepare --recipe-path recipe.json

# Stage 3: Builder - build dependencies (cached) then source
FROM chef AS builder

# Build dependencies only (this layer is cached until Cargo.toml/lock change).
# `full` compiles in the Web UI, ad blocking, userscripts, WebSocket, and HTTP/3 support so they
# are present in the shipped binary (HTTP/3 still only starts when enabled in config).
COPY --from=planner /build/recipe.json recipe.json
# Vendored wreq/wreq-util are [patch.crates-io] path dependencies; cook needs their sources.
COPY vendor ./vendor
RUN cargo chef cook --release --recipe-path recipe.json -p proxy-core --features full

# Now copy source and build (only our code compiles; deps are cached)
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY vendor ./vendor
# `cargo rustc` passes the extra flags to the final binary only, so build scripts stay dynamic.
RUN cargo rustc --release -p proxy-core --bin argus --features full -- \
      -C link-arg=-s -C target-feature=+crt-static

# Copy binary to a known location and verify
RUN cp /build/target/release/argus /build/argus && \
    ls -lh /build/argus && \
    ! readelf -lW /build/argus | grep -q "INTERP\|Requesting program interpreter"

# Stage 4: WebUI build (WASM is architecture-independent -> always built on the
# build host's platform via $BUILDPLATFORM for speed)
FROM --platform=$BUILDPLATFORM rust:${RUST_VERSION}-alpine3.21 AS webui-builder

ARG TRUNK_VERSION
ARG WASM_BINDGEN_VERSION
ARG BUILDARCH
RUN apk add --no-cache musl-dev gcc curl && \
    case "$BUILDARCH" in \
      amd64) TRUNK_ARCH=x86_64 ;; \
      arm64) TRUNK_ARCH=aarch64 ;; \
      *) echo "unsupported BUILDARCH: $BUILDARCH" >&2; exit 1 ;; \
    esac && \
    curl -fsSL "https://github.com/trunk-rs/trunk/releases/download/v${TRUNK_VERSION}/trunk-${TRUNK_ARCH}-unknown-linux-musl.tar.gz" \
      | tar -xzf - -C /usr/local/bin && \
    curl -fsSL "https://github.com/wasm-bindgen/wasm-bindgen/releases/download/${WASM_BINDGEN_VERSION}/wasm-bindgen-${WASM_BINDGEN_VERSION}-${TRUNK_ARCH}-unknown-linux-musl.tar.gz" \
      | tar -xzf - -C /usr/local/bin --strip-components=1 \
        "wasm-bindgen-${WASM_BINDGEN_VERSION}-${TRUNK_ARCH}-unknown-linux-musl/wasm-bindgen" && \
    rustup target add wasm32-unknown-unknown

WORKDIR /build

# Copy workspace files (full workspace needed for cargo metadata)
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY vendor ./vendor

# trunk would download a glibc wasm-bindgen on arm64 (cannot run on musl), so a musl build is
# installed above and trunk uses it from PATH; fail early if it drifts from Cargo.lock.
RUN grep -A1 '^name = "wasm-bindgen"$' /build/Cargo.lock | grep -q "version = \"${WASM_BINDGEN_VERSION}\"" \
    && wasm-bindgen --version

# Build WebUI (wasm-opt disabled via index.html data-wasm-opt="0")
WORKDIR /build/crates/web-ui
RUN trunk build --release

# Stage 5: Runtime
FROM alpine:3.21

# Pull the latest security patches for base packages, then add runtime deps.
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates libgcc

LABEL org.opencontainers.image.source="https://github.com/metril/argus" \
      org.opencontainers.image.title="argus" \
      org.opencontainers.image.description="Adblocking MITM proxy with Web UI"

# Create non-root user
RUN adduser -D -u 1000 -h /app argus

WORKDIR /app

# Copy binary and WebUI dist
COPY --from=builder /build/argus /app/argus
COPY --from=webui-builder /build/crates/web-ui/dist /app/webui

# Copy default configuration
COPY config/default.toml /app/config/default.toml

# Create necessary directories with proper permissions
RUN mkdir -p /app/certs /app/data /app/logs && \
    chown -R argus:argus /app

USER argus

# Expose ports: 8080 (explicit proxy), 3000 (Web API + WebUI), 3129 (optional transparent
# listener: only active when proxy.transparent_port = 3129; needs host networking, see
# docs/TRANSPARENT.md)
EXPOSE 8080 3000 3129

ENV RUST_LOG=info
ENV CONFIG_PATH=/app/config/default.toml
# Settings saved from the web UI (the shipped config is read-only); on the data volume.
ENV CONFIG_OVERLAY_PATH=/app/data/settings.toml
ENV WEBUI_DIST_PATH=/app/webui

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -q -O /dev/null "http://127.0.0.1:$(cat /app/data/filters/.webui_port 2>/dev/null || echo 3000)/health" || exit 1

ENTRYPOINT ["/app/argus"]

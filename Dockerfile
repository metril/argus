# Multi-stage Dockerfile for Adblocker MITM Proxy
# Multi-arch: linux/amd64, linux/arm64
# Build:  docker build -t adblocker .
#         docker buildx build --platform linux/amd64,linux/arm64 -t adblocker .
#
# Uses cargo-chef for dependency caching - incremental builds are ~10x faster.
# Pure-rustls (no OpenSSL): the build is fully static musl with no system TLS libs.

# Pinned toolchain version - keep in sync with rust-toolchain.toml
ARG RUST_VERSION=1.92
ARG CARGO_CHEF_VERSION=0.1.77
ARG TRUNK_VERSION=0.21.14

# Stage 1: Chef base - stable Rust on musl + cargo-chef
FROM rust:${RUST_VERSION}-alpine3.21 AS chef

# Build dependencies (ring needs a C toolchain + perl/make; xz unpacks cargo-chef)
RUN apk add --no-cache musl-dev gcc make perl pkgconfig curl xz

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
RUN cargo chef prepare --recipe-path recipe.json

# Stage 3: Builder - build dependencies (cached) then source
FROM chef AS builder

# Build dependencies only (this layer is cached until Cargo.toml/lock change).
# `full` compiles in the Web UI, ad blocking, userscripts, WebSocket, and HTTP/3 support so they
# are present in the shipped binary (HTTP/3 still only starts when enabled in config).
COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json --features full

# Now copy source and build (only our code compiles; deps are cached)
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN RUSTFLAGS="-C link-arg=-s" cargo build --release --bin adblocker --features full

# Copy binary to a known location and verify
RUN cp /build/target/release/adblocker /build/adblocker && \
    ls -lh /build/adblocker

# Stage 4: WebUI build (WASM is architecture-independent -> always built on the
# build host's platform via $BUILDPLATFORM for speed)
FROM --platform=$BUILDPLATFORM rust:${RUST_VERSION}-alpine3.21 AS webui-builder

ARG TRUNK_VERSION
ARG BUILDARCH
RUN apk add --no-cache musl-dev gcc curl && \
    case "$BUILDARCH" in \
      amd64) TRUNK_ARCH=x86_64 ;; \
      arm64) TRUNK_ARCH=aarch64 ;; \
      *) echo "unsupported BUILDARCH: $BUILDARCH" >&2; exit 1 ;; \
    esac && \
    curl -fsSL "https://github.com/trunk-rs/trunk/releases/download/v${TRUNK_VERSION}/trunk-${TRUNK_ARCH}-unknown-linux-musl.tar.gz" \
      | tar -xzf - -C /usr/local/bin && \
    rustup target add wasm32-unknown-unknown

WORKDIR /build

# Copy workspace files (full workspace needed for cargo metadata)
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Build WebUI (wasm-opt disabled via index.html data-wasm-opt="0")
WORKDIR /build/crates/web-ui
RUN trunk build --release

# Stage 5: Runtime
FROM alpine:3.21

# Pull the latest security patches for base packages, then add runtime deps.
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates libgcc

# Create non-root user
RUN adduser -D -u 1000 -h /app adblocker

WORKDIR /app

# Copy binary and WebUI dist
COPY --from=builder /build/adblocker /app/adblocker
COPY --from=webui-builder /build/crates/web-ui/dist /app/webui

# Copy default configuration
COPY config/default.toml /app/config/default.toml

# Create necessary directories with proper permissions
RUN mkdir -p /app/certs /app/data /app/logs && \
    chown -R adblocker:adblocker /app

USER adblocker

# Expose ports: 8080 (explicit proxy), 3000 (Web API + WebUI), 3129 (optional transparent
# listener: only active when proxy.transparent_port = 3129; needs host networking, see
# docs/TRANSPARENT.md)
EXPOSE 8080 3000 3129

ENV RUST_LOG=info
ENV CONFIG_PATH=/app/config/default.toml
ENV WEBUI_DIST_PATH=/app/webui

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD nc -z localhost 8080 && nc -z localhost 3000 || exit 1

ENTRYPOINT ["/app/adblocker"]

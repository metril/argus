# Multi-stage Dockerfile for Adblocker MITM Proxy
# Supports multi-arch builds: amd64, arm64
# Build with: docker buildx build --platform linux/amd64,linux/arm64 -t adblocker .
#
# Uses cargo-chef for dependency caching - incremental builds are ~10x faster

# Stage 1: Chef base - install Rust and cargo-chef
FROM alpine:3.21 AS chef

# Install build dependencies
RUN apk add --no-cache \
    musl-dev \
    openssl-dev \
    openssl-libs-static \
    pkgconfig \
    perl \
    make \
    curl \
    libgcc \
    gcc

# Install Rust nightly via rustup (needed for tag_ptr 0.1.0 which requires Rust 1.88+)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly
ENV PATH="/root/.cargo/bin:${PATH}"

# Download pre-built cargo-chef binary (much faster than compiling from source)
ARG TARGETARCH
RUN case "$TARGETARCH" in \
      amd64) CHEF_ARCH="x86_64" ;; \
      arm64) CHEF_ARCH="aarch64" ;; \
      *) CHEF_ARCH="x86_64" ;; \
    esac && \
    curl -sSL "https://github.com/LukeMathWalker/cargo-chef/releases/latest/download/cargo-chef-${CHEF_ARCH}-unknown-linux-musl.tar.gz" | tar -xzf - -C /root/.cargo/bin

WORKDIR /build

# Stage 2: Planner - analyze dependencies and create recipe
FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo chef prepare --recipe-path recipe.json

# Stage 3: Builder - build dependencies (cached) then source
FROM chef AS builder

# Copy recipe and build dependencies only (this layer is cached!)
COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json --features webui

# Now copy source and build (only your code compiles, deps are cached)
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN RUSTFLAGS="-C link-arg=-s" cargo build --release --bin adblocker --features webui

# Copy binary to known location and verify
RUN cp /build/target/release/adblocker /build/adblocker && \
    ls -lh /build/adblocker

# Stage 4: WebUI build (WASM is architecture-independent, use x86_64 for speed)
FROM --platform=$BUILDPLATFORM node:20-alpine AS webui-builder

# Install build dependencies and trunk
RUN apk add --no-cache curl musl-dev gcc && \
    curl -sSL https://github.com/trunk-rs/trunk/releases/download/v0.21.14/trunk-x86_64-unknown-linux-musl.tar.gz | tar -xzf - -C /usr/local/bin

# Install Rust for WASM compilation
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup target add wasm32-unknown-unknown

WORKDIR /build

# Copy workspace files (full workspace needed for cargo metadata)
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Build WebUI (wasm-opt disabled via index.html to avoid compatibility issues)
WORKDIR /build/crates/web-ui
RUN trunk build --release

# Stage 5: Runtime
FROM alpine:3.21

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    libgcc

# Create non-root user
RUN adduser -D -u 1000 -h /app adblocker

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/adblocker /app/adblocker

# Copy WebUI dist from webui-builder
COPY --from=webui-builder /build/crates/web-ui/dist /app/webui

# Copy default configuration
COPY config/default.toml /app/config/default.toml

# Create necessary directories with proper permissions
RUN mkdir -p /app/certs /app/data /app/logs && \
    chown -R adblocker:adblocker /app

# Switch to non-root user
USER adblocker

# Expose ports: 8080 (proxy), 8443 (HTTPS proxy), 3000 (Web API)
EXPOSE 8080 8443 3000

# Set environment variables
ENV RUST_LOG=info
ENV CONFIG_PATH=/app/config/default.toml
ENV WEBUI_DIST_PATH=/app/webui

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD nc -z localhost 8080 && nc -z localhost 3000 || exit 1

# Run the proxy
ENTRYPOINT ["/app/adblocker"]

# Multi-stage Dockerfile for Adblocker MITM Proxy
# Supports multi-arch builds: amd64, arm64
# Build with: docker buildx build --platform linux/amd64,linux/arm64 -t adblocker .

# Build stage
FROM --platform=$BUILDPLATFORM rust:1.85-alpine AS builder

# Target architecture for cross-compilation
ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETARCH

# Install build dependencies
RUN apk add --no-cache \
    musl-dev \
    openssl-dev \
    openssl-libs-static \
    pkgconfig \
    perl \
    make

# Install cross-compilation toolchains if needed
RUN case "$TARGETARCH" in \
        arm64) \
            apk add --no-cache gcc-aarch64-none-elf || true ;; \
    esac

# Set working directory
WORKDIR /build

# Copy workspace files for dependency caching
COPY Cargo.toml Cargo.lock ./

# Copy all crates
COPY crates/common ./crates/common
COPY crates/proxy-core ./crates/proxy-core
COPY crates/proxy-http3 ./crates/proxy-http3
COPY crates/filter-engine ./crates/filter-engine
COPY crates/userscript-engine ./crates/userscript-engine
COPY crates/web-api ./crates/web-api
COPY crates/web-ui ./crates/web-ui

# Set Rust target based on architecture
RUN case "$TARGETARCH" in \
        amd64) echo "x86_64-unknown-linux-musl" > /tmp/target ;; \
        arm64) echo "aarch64-unknown-linux-musl" > /tmp/target ;; \
        *) echo "x86_64-unknown-linux-musl" > /tmp/target ;; \
    esac && \
    rustup target add $(cat /tmp/target)

# Build in release mode with optimizations
ENV RUSTFLAGS="-C target-feature=+crt-static -C link-arg=-s"
RUN cargo build --release --target $(cat /tmp/target) --bin adblocker && \
    cp /build/target/$(cat /tmp/target)/release/adblocker /build/adblocker

# Verify binary was created and show size
RUN ls -lh /build/adblocker

# WebUI build stage
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
COPY crates/common ./crates/common
COPY crates/proxy-core ./crates/proxy-core
COPY crates/proxy-http3 ./crates/proxy-http3
COPY crates/filter-engine ./crates/filter-engine
COPY crates/userscript-engine ./crates/userscript-engine
COPY crates/web-api ./crates/web-api
COPY crates/web-ui ./crates/web-ui

# Build WebUI (wasm-opt disabled via index.html to avoid compatibility issues)
WORKDIR /build/crates/web-ui
RUN trunk build --release

# Runtime stage
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

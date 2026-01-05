# Multi-stage Dockerfile for Adblocker MITM Proxy
# Target: Alpine-based image <100MB

# Build stage
FROM rust:1.85-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    musl-dev \
    openssl-dev \
    openssl-libs-static \
    pkgconfig

# Set working directory
WORKDIR /build

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY crates/common ./crates/common
COPY crates/proxy-core ./crates/proxy-core

# Build in release mode with optimizations
ENV RUSTFLAGS="-C target-feature=+crt-static -C link-arg=-s"
RUN cargo build --release --bin adblocker

# Verify binary was created and show size
RUN ls -lh /build/target/release/adblocker

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
COPY --from=builder /build/target/release/adblocker /app/adblocker

# Copy default configuration
COPY config/default.toml /app/config/default.toml

# Create necessary directories with proper permissions
RUN mkdir -p /app/certs /app/data /app/logs && \
    chown -R adblocker:adblocker /app

# Switch to non-root user
USER adblocker

# Expose proxy port (default 8080)
EXPOSE 8080

# Set environment variables
ENV RUST_LOG=info
ENV CONFIG_PATH=/app/config/default.toml

# Health check (simple TCP check on proxy port)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD nc -z localhost 8080 || exit 1

# Run the proxy
ENTRYPOINT ["/app/adblocker"]

# Multi-stage Dockerfile for Rust MITM Proxy
# Target: Alpine-based image <100MB

# Build stage
FROM rust:1.85-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    musl-dev \
    openssl-dev \
    pkgconfig

# Set working directory
WORKDIR /app

# Copy workspace manifest and dependency files
COPY Cargo.toml ./
COPY crates/common/Cargo.toml ./crates/common/
COPY crates/proxy-core/Cargo.toml ./crates/proxy-core/
COPY crates/proxy-http3/Cargo.toml ./crates/proxy-http3/
COPY crates/filter-engine/Cargo.toml ./crates/filter-engine/
COPY crates/userscript-engine/Cargo.toml ./crates/userscript-engine/
COPY crates/web-api/Cargo.toml ./crates/web-api/
COPY crates/web-ui/Cargo.toml ./crates/web-ui/

# Create dummy source files to cache dependencies
RUN mkdir -p crates/common/src crates/proxy-core/src crates/proxy-http3/src \
    crates/filter-engine/src crates/userscript-engine/src crates/web-api/src \
    crates/web-ui/src && \
    echo "fn main() {}" > crates/common/src/lib.rs && \
    echo "fn main() {}" > crates/proxy-core/src/lib.rs && \
    echo "fn main() {}" > crates/proxy-http3/src/lib.rs && \
    echo "fn main() {}" > crates/filter-engine/src/lib.rs && \
    echo "fn main() {}" > crates/userscript-engine/src/lib.rs && \
    echo "fn main() {}" > crates/web-api/src/lib.rs && \
    echo "fn main() {}" > crates/web-ui/src/lib.rs

# Build dependencies (cached layer)
RUN cargo build --release || true

# Copy actual source code
COPY crates/ ./crates/

# Build the actual application
RUN cargo build --release --bin adblocker

# Runtime stage
FROM alpine:3.21

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    libgcc \
    openssl

# Create non-root user
RUN adduser -D -u 1000 -h /app adblocker

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/adblocker /app/adblocker

# Copy default configuration
COPY config/ /app/config/

# Create necessary directories
RUN mkdir -p /app/certs /app/data/filters /app/data/userscripts /app/logs && \
    chown -R adblocker:adblocker /app

# Switch to non-root user
USER adblocker

# Expose ports
EXPOSE 8080 8081

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8081/health || exit 1

# Run the proxy
CMD ["/app/adblocker"]

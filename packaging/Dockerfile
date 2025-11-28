# R-YARA Docker Image
#
# Multi-stage build for minimal production image
#
# Build: docker build -t r-yara .
# Run:   docker run -p 8080:8080 r-yara server

# ============================================
# Stage 1: Build environment
# ============================================
FROM rust:1.75-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    musl-dev \
    openssl-dev \
    openssl-libs-static \
    pkgconfig \
    git

# Create app directory
WORKDIR /build

# Copy Cargo files first (for dependency caching)
COPY rust/Cargo.toml rust/Cargo.lock ./rust/
COPY rust/r-yara-parser/Cargo.toml ./rust/r-yara-parser/
COPY rust/r-yara-compiler/Cargo.toml ./rust/r-yara-compiler/
COPY rust/r-yara-matcher/Cargo.toml ./rust/r-yara-matcher/
COPY rust/r-yara-vm/Cargo.toml ./rust/r-yara-vm/
COPY rust/r-yara-modules/Cargo.toml ./rust/r-yara-modules/
COPY rust/r-yara-scanner/Cargo.toml ./rust/r-yara-scanner/
COPY rust/r-yara-store/Cargo.toml ./rust/r-yara-store/
COPY rust/r-yara-cli/Cargo.toml ./rust/r-yara-cli/
COPY rust/r-yara-pyro/Cargo.toml ./rust/r-yara-pyro/

# Create stub lib.rs files for dependency compilation
RUN mkdir -p rust/r-yara-parser/src && echo "pub fn stub() {}" > rust/r-yara-parser/src/lib.rs && \
    mkdir -p rust/r-yara-compiler/src && echo "pub fn stub() {}" > rust/r-yara-compiler/src/lib.rs && \
    mkdir -p rust/r-yara-matcher/src && echo "pub fn stub() {}" > rust/r-yara-matcher/src/lib.rs && \
    mkdir -p rust/r-yara-vm/src && echo "pub fn stub() {}" > rust/r-yara-vm/src/lib.rs && \
    mkdir -p rust/r-yara-modules/src && echo "pub fn stub() {}" > rust/r-yara-modules/src/lib.rs && \
    mkdir -p rust/r-yara-scanner/src && echo "pub fn stub() {}" > rust/r-yara-scanner/src/lib.rs && \
    mkdir -p rust/r-yara-store/src && echo "pub fn stub() {}" > rust/r-yara-store/src/lib.rs && \
    mkdir -p rust/r-yara-cli/src && echo "fn main() {}" > rust/r-yara-cli/src/main.rs && \
    mkdir -p rust/r-yara-pyro/src && echo "fn main() {}" > rust/r-yara-pyro/src/main.rs

# Build dependencies (cached layer)
WORKDIR /build/rust
RUN cargo build --release --package r-yara-cli --package r-yara-pyro 2>/dev/null || true

# Now copy actual source
WORKDIR /build
COPY rust/ ./rust/

# Build actual binaries
WORKDIR /build/rust
RUN cargo build --release --package r-yara-cli --package r-yara-pyro

# Strip binaries
RUN strip target/release/r-yara-cli target/release/r-yara-pyro

# ============================================
# Stage 2: Runtime image
# ============================================
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata

# Create non-root user
RUN addgroup -S ryara && adduser -S ryara -G ryara

# Create directories
RUN mkdir -p /rules /data /var/lib/r-yara && \
    chown -R ryara:ryara /rules /data /var/lib/r-yara

# Copy binaries from builder
COPY --from=builder /build/rust/target/release/r-yara-cli /usr/local/bin/r-yara
COPY --from=builder /build/rust/target/release/r-yara-pyro /usr/local/bin/r-yara-server

# Set permissions
RUN chmod +x /usr/local/bin/r-yara /usr/local/bin/r-yara-server

# Switch to non-root user
USER ryara

# Working directory
WORKDIR /data

# Environment variables
ENV RYARA_HOST=0.0.0.0
ENV RYARA_PORT=8080
ENV RYARA_RULES_DIR=/rules
ENV RYARA_DATA_DIR=/var/lib/r-yara
ENV RYARA_LOG_LEVEL=info

# Expose API port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://localhost:8080/api/v2/r-yara/health || exit 1

# Default command - start Fire Hydrant API server
ENTRYPOINT ["/usr/local/bin/r-yara-server"]
CMD ["server"]

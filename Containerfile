# Grob - LLM Routing Proxy
# Containerfile for Podman/Docker (rootless compatible)
# Multi-stage build with cargo-chef for fast rebuilds

# Stage 1: Chef planner — compute dependency recipe
FROM rust:1.85-alpine AS chef
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static && \
    cargo install cargo-chef --locked
WORKDIR /usr/src/grob

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Stage 2: Build dependencies (cached unless Cargo.toml/lock change)
FROM chef AS builder
COPY --from=planner /usr/src/grob/recipe.json recipe.json
RUN cargo chef cook --release --target x86_64-unknown-linux-musl --recipe-path recipe.json

# Copy source and build final binary (only this layer invalidates on code changes)
COPY . .
ENV RUSTFLAGS="-C target-feature=+crt-static -C link-self-contained=yes"
RUN cargo update time@0.3.47 --precise 0.3.35 && \
    cargo build --release --target x86_64-unknown-linux-musl

# Strip symbols for smaller binary
RUN strip target/x86_64-unknown-linux-musl/release/grob

# Stage 3: Runtime (scratch - empty base)
FROM scratch

# Metadata
LABEL org.opencontainers.image.title="grob"
LABEL org.opencontainers.image.description="LLM Routing Proxy with DLP and compliance"
LABEL org.opencontainers.image.source="https://github.com/gelwood/grob"
LABEL org.opencontainers.image.licenses="AGPL-3.0"

# Copy CA certificates for TLS (from builder)
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy binary
COPY --from=builder /usr/src/grob/target/x86_64-unknown-linux-musl/release/grob /grob

# Create non-root user (65534 = nobody)
USER 65534:65534

# Expose port
EXPOSE 8080

# Health check — scratch image has no shell, so use exec form directly.
# /grob status exits 0 when healthy; the || syntax needs a shell, so we
# rely on the orchestrator's httpGet probes instead and skip HEALTHCHECK
# for scratch images (no shell available).

# Default entrypoint: `run` is the container-mode command (foreground, 0.0.0.0, JSON logs)
ENTRYPOINT ["/grob"]
CMD ["run", "--json-logs", "--host", "0.0.0.0", "--port", "8080"]

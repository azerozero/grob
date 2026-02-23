FROM rust:1.84-slim AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY presets/ presets/
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/grob /usr/local/bin/grob
EXPOSE 3456
HEALTHCHECK --interval=30s --timeout=3s CMD ["/usr/local/bin/grob", "status"]
ENTRYPOINT ["grob", "run"]

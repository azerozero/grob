# How to Deploy Grob

## Run in a container

Grob publishes a minimal container image (~6 MB, `FROM scratch`) to GitHub Container Registry.

### Docker / Podman

```bash
docker run -d \
  -e ANTHROPIC_API_KEY=sk-ant-... \
  -e OPENROUTER_API_KEY=sk-or-... \
  -p 8080:8080 \
  ghcr.io/azerozero/grob:latest
```

The container runs `grob run --json-logs --host 0.0.0.0 --port 8080` by default.

### With a config file

Mount your config:

```bash
docker run -d \
  -v ~/.grob/config.toml:/config.toml:ro \
  -e GROB_CONFIG=/config.toml \
  -e ANTHROPIC_API_KEY=sk-ant-... \
  -p 8080:8080 \
  ghcr.io/azerozero/grob:latest
```

### With remote config

```bash
docker run -d \
  -e GROB_CONFIG=https://config.example.com/grob.toml \
  -e ANTHROPIC_API_KEY=sk-ant-... \
  -p 8080:8080 \
  ghcr.io/azerozero/grob:latest
```

## Kubernetes

A sample manifest is provided in `deploy/grob-kube.yml`. Key points:

- Use a Secret for API keys
- Mount config via ConfigMap or use remote config URL
- The health endpoint is `GET /health` (returns 200 with PID)
- Metrics are at `GET /metrics` (Prometheus format)
- The container runs as non-root (UID 65534)

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8080
readinessProbe:
  httpGet:
    path: /health
    port: 8080
```

## Build from source

```bash
# Standard release build
cargo build --release

# Static binary (for container builds)
RUSTFLAGS="-C target-feature=+crt-static" \
  cargo build --release --target x86_64-unknown-linux-musl
```

## Build the container image

```bash
podman build -f Containerfile -t grob:latest .
```

The multi-stage build uses `cargo-chef` for layer caching, so only code changes rebuild the final layer.

## Run as a systemd service

Create `/etc/systemd/system/grob.service`:

```ini
[Unit]
Description=Grob LLM Routing Proxy
After=network.target

[Service]
Type=exec
ExecStart=/usr/local/bin/grob run --json-logs --host 127.0.0.1 --port 13456
Restart=on-failure
RestartSec=5
Environment=ANTHROPIC_API_KEY=sk-ant-...
EnvironmentFile=-/etc/grob/env

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now grob
```

## Monitor with Prometheus

Grob exposes metrics at `/metrics` in Prometheus format:

- `grob_requests_total` -- request count by model, provider, status
- `grob_request_duration_seconds` -- latency histogram
- `grob_spend_usd` -- current month spend
- `grob_input_tokens_total`, `grob_output_tokens_total` -- token counts
- `grob_ratelimit_hits_total` -- upstream rate limit events
- `grob_circuit_breaker_state` -- per-provider circuit breaker state

A Grafana dashboard is provided in `docs/grafana-dashboard.json`.

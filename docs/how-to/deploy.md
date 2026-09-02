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

The container runs `grob run --json-logs --host 0.0.0.0 --port 8080` by default. Use `-p 13456:8080` if you want the native host default on the outside.

### With a config file

Mount your config:

```bash
docker run -d \
  -v ~/.grob/config.toml:/etc/grob/config.toml:ro \
  -e GROB_CONFIG=/etc/grob/config.toml \
  -e GROB_HOME=/var/lib/grob \
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
- Set `GROB_CONFIG=/etc/grob/config.toml` and `GROB_HOME=/var/lib/grob`
- The health endpoint is `GET /health` (returns 200 with PID)
- Metrics are at `GET /metrics` (Prometheus format)
- The container runs as non-root (UID/GID 65534); hostPath volumes must be writable by that user
- Set `GROB_REPLICAS` from the Deployment's replica count if you enforce fleet-wide limits (see below)

```yaml
livenessProbe:
  httpGet:
    path: /live
    port: 8080
readinessProbe:
  httpGet:
    path: /ready
    port: 8080
startupProbe:
  httpGet:
    path: /health
    port: 8080
```

### Fleet-wide limits with more than one pod

Rate-limit buckets and spend counters are **per process**. Each pod enforces the
configured limit on its own, so N pods let the fleet through `N x` the limit.
`rate_limit_replicas` (and `[budget] replicas`) fix that by making each pod
enforce its share — but they are numbers written in a file, and on Kubernetes
the replica count lives in the Deployment and moves under an HPA.

Inject it instead of hardcoding it:

```yaml
spec:
  replicas: 5
  template:
    spec:
      containers:
        - name: grob
          env:
            - name: GROB_REPLICAS
              value: "5"          # keep in sync with spec.replicas
```

`GROB_REPLICAS` overrides the file's replica count. Unset, unparseable, or `0`
leaves the config untouched, so a templating mistake degrades to the previous
behaviour rather than dividing by zero.

With Helm, template it from the same value that sets `spec.replicas` so the two
cannot drift:

```yaml
env:
  - name: GROB_REPLICAS
    value: "{{ .Values.replicaCount }}"
```

**Under an HPA, use `maxReplicas`.** Over-declaring only under-uses the quota;
under-declaring breaks the ceiling. An HPA scaling from 3 to 10 pods against a
declaration of 3 would let the fleet reach 333% of the configured limit.

grob deliberately does **not** query the Kubernetes API to count its own pods:
that would mean a cluster-role, a watch, and a hard dependency on the
orchestrator — for a number the orchestrator can simply hand over. The count
stays a declaration; the environment is just a better place to declare it than
a ConfigMap.

Each pod keeps its own `GROB_HOME` (an `emptyDir` is fine). A shared volume is
**not** required and does not make limits shared: spend counters are in-memory
per process, so a peer's writes are invisible until restart.

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

### Protect `/metrics` with a bearer token

`/metrics` is **public by default** (the Prometheus convention — rely on network
policy / TLS). Because it exposes spend, budget, and tenant labels, you can
require a bearer token instead:

```toml
[metrics]
# Inline token, OR read it from a file (the file wins and is trimmed):
bearer_token = "REPLACE_WITH_A_LONG_RANDOM_TOKEN"
# bearer_token_file = "/etc/grob/metrics-token"
```

With a token set, `/metrics` requires `Authorization: Bearer <token>` (compared
in constant time) and returns `401` otherwise. `/health`, `/live`, and `/ready`
stay public. Point your scraper at the same token:

```yaml
scrape_configs:
  - job_name: grob
    scheme: https            # TLS is handled by grob's TLS/ACME layer or your ingress
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/grob-metrics-token
    static_configs:
      - targets: ["grob:13456"]
```

On Kubernetes, the Helm chart's `serviceMonitor.bearerTokenSecret` wires the
token into a `ServiceMonitor` — see `deploy/helm/grob/README.md`.

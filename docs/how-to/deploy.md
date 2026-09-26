# How to Deploy Grob

## Run in a container

Grob publishes a `FROM scratch` container image to GitHub Container Registry.
Image size depends on the release and target; inspect the tag you deploy.

### Docker / Podman

Prepare a working configuration first with the
[getting-started tutorial](../tutorials/getting-started.md). For these examples,
use provider API keys supplied through environment variables. Export the keys
required by your configuration in the shell that launches the container.

The container runs as UID/GID 65534. Its mounted configuration must be readable
by that identity; bind-mounted data directories must be writable by it. Keep
actual secret values out of a broadly readable configuration file. OAuth tokens
and named secrets in the host's `~/.grob` are not automatically available inside
the container.

The image listens on `0.0.0.0:8080` internally. The examples below publish only
on host loopback. Before sharing the port, configure
[client authentication](../reference/authentication.md) and TLS at your ingress.
Use `127.0.0.1:13456:8080` to expose the native host port instead.

### With a config file

Mount the configuration and a persistent data volume:

```bash
docker volume create grob-data
docker run -d \
  --name grob \
  -v "$HOME/.grob/config.toml:/etc/grob/config.toml:ro" \
  -v grob-data:/var/lib/grob \
  -e GROB_CONFIG=/etc/grob/config.toml \
  -e GROB_HOME=/var/lib/grob \
  -e ANTHROPIC_API_KEY \
  -e OPENROUTER_API_KEY \
  -p 127.0.0.1:8080:8080 \
  ghcr.io/azerozero/grob:latest
```

### With remote config

As an alternative, reuse the data volume and load configuration from a trusted
URL. Forward any additional provider variables required by that configuration.

```bash
docker run -d \
  -e GROB_CONFIG=https://config.example.com/grob.toml \
  -e GROB_HOME=/var/lib/grob \
  -v grob-data:/var/lib/grob \
  -e ANTHROPIC_API_KEY \
  -p 127.0.0.1:8080:8080 \
  ghcr.io/azerozero/grob:latest
```

## Kubernetes

A local Podman-compatible sample is provided in
[`deploy/grob-kube.yml`](../../deploy/grob-kube.yml). It uses a locally built
image, `imagePullPolicy: Never` and host paths. Adapt the image policy, volumes,
credentials and network exposure before deploying it to a cluster. Key points:

- Use a Secret for API keys
- Configure incoming authentication before sharing the service with clients
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

Each pod keeps its own `GROB_HOME`. Use durable per-replica storage when spend
history, keys or OAuth tokens must survive pod replacement. An `emptyDir` loses
them when its pod is removed and cannot preserve a monthly budget history.
A shared volume does not coordinate live limits: spend counters are in-memory
per process, so a peer's writes are invisible until restart. See
[replica consistency](multi-replica-consistency.md) and
[credential backup and key custody](protect-credential-storage.md).

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

## Run as a systemd user service

First install with the shell installer and complete `grob setup` as your normal
user. Verify `~/.local/bin/grob` and `~/.grob/config.toml` exist. For a Homebrew
installation, replace `%h/.local/bin/grob` in `ExecStart` with the absolute path returned by
`command -v grob`, keeping the other arguments.

Create `~/.config/systemd/user/grob.service` (create the directory if needed):

```ini
[Unit]
Description=Grob LLM Routing Proxy
After=network.target

[Service]
Type=exec
ExecStart=%h/.local/bin/grob --config %h/.grob/config.toml run --json-logs --host 127.0.0.1 --port 13456
Restart=on-failure
RestartSec=5
Environment=GROB_HOME=%h/.grob
EnvironmentFile=-%h/.config/grob/env

[Install]
WantedBy=default.target
```

```bash
systemctl --user daemon-reload
systemctl --user enable --now grob
systemctl --user status grob
journalctl --user -u grob
```

If your config references environment variables, put their `NAME=value` assignments
(without `export`) in `~/.config/grob/env` and restrict that file to mode `0600`.
The service does not inherit variables from your terminal. With a custom
`XDG_CONFIG_HOME`, place the unit in that directory's `systemd/user` subdirectory;
the explicit environment-file path above still uses `~/.config/grob/env`.

This service runs with your account's permissions. To keep it running after logout
and start it at boot, an administrator can explicitly enable lingering with
`loginctl enable-linger USERNAME`; undo that with `loginctl disable-linger USERNAME`.
Use `systemctl --user disable --now grob` to stop and disable the service.

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

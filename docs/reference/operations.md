# Operations Reference

## Presets

Grob ships with 7 built-in presets. Apply with `grob preset apply <name>`.

| Preset | Description | Providers |
|--------|-------------|-----------|
| `perf` | Performance max | Anthropic + OpenAI + Gemini, top-tier models |
| `medium` | Best quality/price | Anthropic thinking + OpenRouter defaults |
| `local` | Private, zero API cost for defaults | Ollama local + Anthropic thinking |
| `cheap` | Budget max ($0-5/month) | GLM-5 + DeepSeek + Gemini Flash |
| `fast` | Premium quality, no limit | Opus + GPT-5.2 + Gemini Pro |
| `gdpr` | EU-only GDPR compliant | Mistral, Scaleway, OVH (region=eu) |
| `eu-ai-act` | EU AI Act compliant | EU providers + transparency headers + risk classification |

### Preset management commands

```bash
grob preset list                  # List all presets (built-in + installed)
grob preset info perf             # Show providers, models, env vars, router config
grob preset apply medium          # Apply preset (backs up current config to .toml.backup)
grob preset apply medium --reload # Apply and hot-reload the running server
grob preset export my-custom      # Export current config as a reusable preset
grob preset install https://github.com/org/presets.git  # Install from git repo
grob preset sync                  # Sync presets from configured remote
```

### How presets work

Applying a preset replaces `[router]`, `[[providers]]`, `[[models]]`, `[security]`, `[compliance]`, and `[dlp]` sections in the config. The `[server]` and `[user]` sections are preserved. A `.toml.backup` file is created before any changes.

The compliance presets (`gdpr`, `eu-ai-act`) can be overlaid without replacing the router and provider sections. The setup wizard uses this to add compliance to an existing configuration.

### Installed presets

Custom presets are stored in `~/.grob/presets/` as `.toml` files. Installed presets cannot shadow built-in names.

### Preset sync

Presets can be synced from a configured git repository. The sync interval is configurable with duration suffixes: `30m`, `6h`, `1d`, `90s`.

## Zero-downtime upgrades

The `grob upgrade` command replaces a running instance without dropping requests.

### Unix (Linux/macOS)

Uses `SO_REUSEPORT` to run old and new processes on the same port simultaneously:

1. Spawns a new grob process on the same port.
2. Waits for the new process to pass the `/health` check (up to 35 seconds).
3. Sends `SIGUSR1` to the old process, which begins draining in-flight requests.
4. Waits for the old process to exit (up to 35 seconds drain timeout).

```bash
grob upgrade
```

### Windows

Windows lacks `SO_REUSEPORT`, so there is a brief interruption:

1. Stops the old process via `taskkill`.
2. Waits for the old process to exit (up to 35 seconds).
3. Spawns a new process.
4. Waits for health check.

### Signal handling

| Signal | Behavior |
|--------|----------|
| `SIGINT` (Ctrl+C) | Graceful shutdown |
| `SIGTERM` | Graceful shutdown |
| `SIGUSR1` | Graceful drain (used during upgrade handoff) |

## Container deployment

Grob includes a `Containerfile` for Podman/Docker with a multi-stage build.

### Build

```bash
podman build -t grob .
```

The build uses `cargo-chef` for dependency caching and produces a `scratch`-based image (no shell, no OS) with a statically linked musl binary. The final image contains only the binary and CA certificates.

### Run

```bash
podman run -d \
  --name grob \
  -p 8080:8080 \
  -e ANTHROPIC_API_KEY=sk-ant-xxx \
  -e OPENROUTER_API_KEY=sk-or-xxx \
  -v ~/.grob/config.toml:/config.toml:ro \
  grob run --json-logs --host 0.0.0.0 --port 8080 --config /config.toml
```

The default entrypoint is `grob run --json-logs --host 0.0.0.0 --port 8080`. The container runs as UID 65534 (nobody).

### Container mode (`grob run`)

The `run` command is designed for containers and orchestrators:

- Runs in foreground (no daemonization, no PID file).
- Binds to `::` (all interfaces) by default.
- Supports `SIGINT`, `SIGTERM`, and `SIGUSR1` for graceful shutdown.
- All flags are overridable via environment variables: `GROB_PORT`, `GROB_HOST`, `GROB_LOG_LEVEL`, `GROB_JSON_LOGS`.

### Kubernetes probes

| Probe | Endpoint | Behavior |
|-------|----------|----------|
| Liveness | `GET /live` | Always returns 200 if the process is alive |
| Readiness | `GET /ready` | Returns 200 if providers are configured and at least one circuit breaker is not open; 503 otherwise |
| Startup | `GET /health` | Returns 200 with PID, uptime, spend, and active request count |

```yaml
livenessProbe:
  httpGet:
    path: /live
    port: 8080
  periodSeconds: 10
readinessProbe:
  httpGet:
    path: /ready
    port: 8080
  periodSeconds: 5
```

## TLS / ACME configuration

Native HTTPS with optional automatic certificate provisioning via Let's Encrypt.

### Manual TLS

```toml
[tls]
enabled = true
cert_path = "/etc/ssl/certs/grob.pem"     # PEM certificate (e.g. fullchain.pem)
key_path = "/etc/ssl/private/grob-key.pem" # PEM private key (e.g. privkey.pem)
```

### ACME (Let's Encrypt)

```toml
[tls]
enabled = true

[tls.acme]
enabled = true
domains = ["grob.example.com"]
contacts = ["admin@example.com"]
cache_dir = "~/.grob/certs/"    # Certificate cache directory
staging = false                  # Set to true for Let's Encrypt staging (testing)
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable ACME auto-provisioning |
| `domains` | `[]` | Domain names to obtain certificates for |
| `contacts` | `[]` | Contact email addresses for Let's Encrypt |
| `cache_dir` | `""` | Directory to cache certificates (default: `~/.grob/certs/`) |
| `staging` | `false` | Use Let's Encrypt staging environment |

## Connection warmup

On startup, Grob sends fire-and-forget `HEAD` requests to all configured provider base URLs. This pre-warms TCP and TLS connections so the first real request does not pay the connection setup cost.

Warmup uses a 5-second timeout per provider and runs concurrently in background tasks. Failures are logged at debug level and do not block startup.

## Config hot-reload

The running server can reload configuration without restart:

```bash
# Via API
curl -X POST http://localhost:13456/api/config/reload

# Via preset apply
grob preset apply medium --reload
```

Hot-reload atomically swaps the router, provider registry, and model index. In-flight requests continue on the old snapshot.

## Timeouts

```toml
[timeouts]
api_timeout_ms = 600000       # Total API request timeout (default: 10 minutes)
connect_timeout_ms = 10000    # TCP connection timeout (default: 10 seconds)
```

## Diagnostics

The `grob doctor` command runs 11 diagnostic checks:

1. Config file existence and location
2. Config version
3. Provider credential status (API keys and OAuth)
4. Model configuration count
5. Service running status
6. Port availability
7. DLP enabled/disabled
8. Security configuration (rate limit, circuit breaker)
9. Storage backend (atomic files) accessibility
10. Missing environment variables
11. Podman availability (optional)

# Observability Reference

## Prometheus metrics

Grob exposes Prometheus-compatible metrics at `GET /metrics` in OpenMetrics text format.

### Request metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `grob_requests_total` | counter | `model`, `provider`, `route_type`, `status` | Total requests processed |
| `grob_request_duration_seconds` | histogram | `model`, `provider` | End-to-end request latency |
| `grob_input_tokens_total` | counter | `model`, `provider` | Cumulative input tokens consumed |
| `grob_output_tokens_total` | counter | `model`, `provider` | Cumulative output tokens produced |
| `grob_request_cost_usd` | gauge (monotonic) | `model`, `provider` | Cumulative per-request cost in USD (gauge because cost is fractional; supports `rate()` in PromQL) |
| `grob_active_requests` | gauge | | In-flight requests at scrape time |

### Spend and budget metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `grob_spend_usd` | gauge | | Month-to-date total spend in USD (persistent) |
| `grob_budget_limit_usd` | gauge | | Configured monthly budget cap (only set when > 0) |
| `grob_budget_remaining_usd` | gauge | | Remaining monthly budget in USD |

### Provider health metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `grob_provider_score` | gauge | `provider` | Adaptive provider score (higher = healthier) |
| `grob_provider_latency_ewma_ms` | gauge | `provider` | Exponentially weighted moving average latency |
| `grob_provider_success_rate` | gauge | `provider` | Provider success rate (0.0-1.0) |
| `grob_provider_errors_total` | counter | `provider`, `error_type` | Provider-level error count |
| `grob_circuit_breaker_state` | gauge | `provider` | Circuit breaker state (0=closed, 1=half-open, 2=open) |
| `grob_circuit_breaker_rejected_total` | counter | `provider` | Requests rejected by open circuit breaker |

### Rate limiting metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `grob_ratelimit_rejected_total` | counter | | Requests rejected by rate limiter |

### Cache metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `grob_cache_hits_total` | counter | | Response cache hits |
| `grob_cache_misses_total` | counter | | Response cache misses |
| `grob_cache_skipped_too_large_total` | counter | | Responses too large to cache |

### DLP metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `grob_dlp_detections_total` | counter | `rule`, `action` | DLP rule activations by rule type and action taken |
| `grob_dlp_rules_loaded` | gauge | `type` | Number of loaded DLP rules (labels: `secret`, `name`) |
| `grob_dlp_stream_blocked_total` | counter | | Streaming responses blocked by DLP |
| `grob_dlp_cross_chunk_total` | counter | `rule` | Cross-chunk DLP detections in streaming |
| `grob_dlp_circuit_breaker_total` | counter | | DLP circuit breaker activations |
| `grob_dlp_hot_reload_total` | counter | `result` | DLP config hot-reload attempts |
| `grob_dlp_signature_verified_total` | counter | `result` | DLP signed config verification results |
| `grob_dlp_config_hash_info` | gauge | `hash` | Currently loaded DLP config hash |

### Scrape configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: grob
    scrape_interval: 15s
    static_configs:
      - targets: ["localhost:13456"]
    metrics_path: /metrics
```

A Grafana dashboard is available at `docs/grafana-dashboard.json`.

## OpenTelemetry

Grob exports distributed traces via OTLP/gRPC when the `otel` feature is enabled.

### Configuration

```toml
[otel]
enabled = true
endpoint = "http://localhost:4317"     # OTLP gRPC endpoint
service_name = "grob"                  # Service name in traces
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable OpenTelemetry trace export |
| `endpoint` | `http://localhost:4317` | OTLP exporter endpoint (gRPC) |
| `service_name` | `"grob"` | Service name reported in resource attributes |

### Build requirement

OpenTelemetry requires the `otel` feature flag:

```bash
cargo build --release --features otel
```

The OTel layer is combined with the `tracing` fmt layer into a single subscriber. When `--json-logs` is also set, the fmt layer emits JSON; otherwise it emits human-readable output. Both modes export spans to the OTLP collector.

## Log export

Structured `LogEntry` records are emitted after each completed request to configurable sinks, independent of the tap/webhook system.

### Configuration

```toml
[log_export]
enabled = true

[[log_export.sinks]]
type = "stdout"

[[log_export.sinks]]
type = "file"
path = "/var/log/grob/requests.jsonl"

[[log_export.sinks]]
type = "http"
url = "https://logs.example.com/ingest"
headers = { Authorization = "Bearer tok-xxx" }
```

### Sink types

| Type | Description | Output format |
|------|-------------|---------------|
| `stdout` | Print to stdout (pipe to Fluentd/Vector/Logstash) | Single-line JSON per entry |
| `file` | Append to a file | JSONL (one JSON object per line) |
| `http` | POST to an HTTP endpoint | JSON body per entry |

### LogEntry schema

Each emitted entry contains:

| Field | Type | Description |
|-------|------|-------------|
| `request_id` | string | Unique request identifier |
| `timestamp` | string | ISO-8601 completion time |
| `model` | string | Model name requested by the client |
| `provider` | string | Provider that served the request |
| `input_tokens` | u32 | Input tokens consumed |
| `output_tokens` | u32 | Output tokens produced |
| `latency_ms` | u64 | End-to-end latency in milliseconds |
| `cost_usd` | f64 | Estimated cost in USD |
| `status` | string | `"success"` or `"error"` |
| `dlp_actions` | string[] | DLP actions applied during the request |
| `tenant_id` | string? | Tenant identifier (omitted when null) |

## grob watch

Live traffic inspector TUI. Requires the `watch` feature flag.

```bash
cargo build --release --features watch
grob watch
```

### TUI layout

The terminal UI has three panels:

1. **Providers** (top) -- Color-coded health indicators per provider showing last latency and success rate. Green (>95%), yellow (>80%), red (<=80%).
2. **Live** (center) -- Scrolling event stream showing requests, responses, errors, DLP actions, fallbacks, and circuit breaker state changes. Events are timestamped with `HH:MM:SS`.
3. **Alerts** (bottom) -- Running DLP counters: secrets detected, PII detected, injection attempts.

### Keyboard controls

| Key | Action |
|-----|--------|
| `q` | Quit |
| `p` | Pause/resume the live stream |

### SSE endpoint

The TUI connects to `GET /api/events` (Server-Sent Events). External tools can consume the same SSE stream for custom dashboards or alerting.

### Event types

Events are JSON-tagged unions (`"type"` field):

| Event type | Description | Key fields |
|------------|-------------|------------|
| `request_start` | Request entered dispatch pipeline | `request_id`, `model`, `provider`, `input_tokens`, `route_type` |
| `request_end` | Request completed successfully | `request_id`, `output_tokens`, `latency_ms`, `cost_usd` |
| `request_error` | Request failed at a provider | `request_id`, `provider`, `error` |
| `dlp_action` | DLP engine took action | `request_id`, `direction` (request/response), `action`, `rule_type`, `detail` |
| `fallback` | Provider failover occurred | `request_id`, `from_provider`, `to_provider`, `reason` |
| `circuit_breaker` | Circuit breaker state changed | `provider`, `state` |
| `provider_health` | Periodic health snapshot | `provider`, `latency_ms`, `success_rate`, `requests_total` |

The event bus uses a broadcast channel with a capacity of 1024 events. The TUI keeps a scrollback buffer of 200 events.

## Spend tracking

Monthly spend is tracked persistently in append-only JSONL journals (`~/.grob/spend/YYYY-MM.jsonl`). Data auto-resets on the first request of a new calendar month (new journal file).

### Budget enforcement

Budgets are checked before each request. If any limit is exceeded, the request is rejected with a `BudgetExceeded` error.

```toml
[budget]
monthly_limit_usd = 200.0    # Global monthly cap (0 = unlimited)
warn_at_percent = 80          # Log warning at this threshold (default: 80)
```

Per-provider and per-model budgets are also supported:

```toml
[[providers]]
name = "openrouter"
budget_usd = 50.0             # Provider monthly cap

[[models]]
name = "claude-opus-4-6"
budget_usd = 100.0            # Model monthly cap
```

Budget checking order (most specific wins): model limit, then provider limit, then global limit.

### Pricing

Costs are calculated using a dynamic pricing table fetched from the OpenRouter API on startup (refreshed every 24 hours). If the OpenRouter fetch fails, hardcoded fallback prices are used.

Subscription providers (OAuth auth type) are always costed at $0.

### CLI commands

- `grob spend` -- Show current month spend by provider and model, with budget percentages and warnings.
- `grob status` -- Includes a spend summary line when spend > $0 or a budget is configured.

## Message tracing

Request/response pairs can be traced to a JSONL file for debugging.

```toml
[tracing]
enabled = true
path = "~/.grob/trace.jsonl"    # Default path
omit_system_prompt = true       # Default: true (system prompts are large)
```

## Health endpoints

| Endpoint | Purpose | Response |
|----------|---------|----------|
| `GET /health` | Full health check | `{"status":"ok","pid":...,"spend":...,"active_requests":...}` |
| `GET /live` | Liveness probe (always 200) | `{"status":"alive"}` |
| `GET /ready` | Readiness probe | 200 if providers configured and not all circuit breakers open; 503 otherwise |
| `GET /metrics` | Prometheus metrics | OpenMetrics text format |
| `GET /api/scores` | Adaptive provider scores | Provider scoring details |

# Security Reference

Complete configuration reference for Grob's security middleware: rate limiting, circuit breakers, OWASP headers, audit logging, adaptive scoring, and EU AI Act compliance.

All settings live under the `[security]` section of `config.toml`.

## Master switch

```toml
[security]
enabled = true  # default: true
```

Setting `enabled = false` disables all security middleware (rate limiting, circuit breakers, headers, audit). Not recommended for any deployment beyond local development.

## Rate limiting

Token-bucket rate limiter keyed per tenant (from JWT `sub`/`tenant` claim, virtual key, or API key) with IP-address fallback.

```toml
[security]
rate_limit_rps = 100    # requests per second (default: 100)
rate_limit_burst = 200  # burst capacity (default: 200)
```

### Behavior

- **Algorithm**: Token bucket with milli-token precision. Tokens refill continuously at `rate_limit_rps` per second, capped at `burst`.
- **Keying**: Requests are keyed by tenant ID when authentication is enabled, or by source IP address otherwise (enum `RateLimitKey::Tenant` / `RateLimitKey::Ip`).
- **Rejection**: Returns HTTP `429 Too Many Requests` with a `Retry-After` header indicating the number of seconds until a token becomes available.
- **Cleanup**: Stale buckets (idle > 10 minutes) are evicted every 5 minutes by a background task to prevent memory growth.

### Capacity planning

100 rps sustains roughly 10 concurrent Claude Code sessions (each bursting ~10 req/s during tool-use loops). The 2x burst factor absorbs short spikes without triggering 429s.

### Edge cases

- A new tenant gets a full burst allowance on its first request.
- If `rate_limit_rps` is set to 0, no tokens ever refill and requests are blocked after the initial burst is consumed.

## Circuit breakers

Per-provider circuit breaker prevents cascading failures when an upstream provider degrades.

```toml
[security]
circuit_breaker = true  # default: true
```

### State machine

| State | Entry condition | Behavior | Exit condition |
|-------|----------------|----------|----------------|
| **Closed** | Initial state, or 3 consecutive successes in HalfOpen | Requests pass through normally | 5 consecutive failures |
| **Open** | 5 consecutive failures | Requests fail fast (skip provider) | 30 seconds elapsed |
| **HalfOpen** | 30-second timeout after Open | Allows up to 3 probe requests | 3 successes -> Closed; 1 failure -> Open |

### Default thresholds

| Parameter | Value |
|-----------|-------|
| `failure_threshold` | 5 consecutive failures |
| `success_threshold` | 3 consecutive successes (to close from HalfOpen) |
| `timeout` | 30 seconds |
| `half_open_max_calls` | 3 probe requests |

These are compiled defaults and not currently configurable via TOML (the `circuit_breaker` flag only enables/disables the feature entirely).

### Interaction with routing

When a circuit opens for a provider, requests skip that provider and fall through to the next priority mapping in the model's routing table. Other providers are unaffected.

### Metrics

The gauge `grob_circuit_breaker_state` (with label `provider`) emits:
- `0.0` = Closed
- `1.0` = Open
- `2.0` = HalfOpen

## Security headers

OWASP-recommended headers applied to every response.

```toml
[security]
security_headers = true  # default: true
```

### Headers applied

| Header | Value | Notes |
|--------|-------|-------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | HSTS, 1-year max-age |
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; ...` | Full CSP policy (disabled in API mode) |
| `X-Frame-Options` | `DENY` | Clickjacking protection |
| `X-Content-Type-Options` | `nosniff` | MIME sniffing prevention |
| `Referrer-Policy` | `strict-origin-when-cross-origin` (default) or `no-referrer` (API mode) | Referrer leakage prevention |
| `Permissions-Policy` | `accelerometer=(), camera=(), geolocation=(), ...` | Feature restrictions |
| `Cache-Control` | `no-store, no-cache, must-revalidate, private` | Prevents caching of API responses |

The `X-XSS-Protection` header is disabled by default (deprecated in favor of CSP).

### API mode

When Grob operates as a pure API proxy (the typical deployment), the `SecurityHeadersConfig::api_mode()` variant is used internally. This disables CSP (not needed for JSON APIs) and sets `Referrer-Policy: no-referrer`.

## Request size limits

```toml
[security]
max_body_size = 10485760  # bytes, default: 10 MB (10 * 1024 * 1024)
```

Requests exceeding this limit are rejected with HTTP `413 Payload Too Large` before JSON parsing begins, preventing memory exhaustion from oversized payloads.

## Audit logging

Signed, hash-chained audit log for compliance (HDS, PCI DSS, SecNumCloud, EU AI Act).

```toml
[security]
audit_dir = "/var/lib/grob/audit"  # empty = disabled (default)
audit_signing_algorithm = "ecdsa-p256"  # "ecdsa-p256" | "ed25519" | "hmac-sha256"
audit_hmac_key_path = ""  # only for hmac-sha256; default: <audit_dir>/audit_hmac.key
audit_batch_size = 1  # 1 = per-entry signing, >1 = Merkle batch (default: 1)
audit_flush_interval_ms = 5000  # max ms before flushing incomplete batch (default: 5000)
audit_include_merkle_proof = false  # include proof in each entry (default: false)
```

### Signing algorithms

| Algorithm | Signature size | Key type | Key file |
|-----------|---------------|----------|----------|
| `ecdsa-p256` (default) | 64 bytes | Asymmetric (NIST P-256) | `<audit_dir>/audit.key` or `sign_key_path` |
| `ed25519` | 64 bytes | Asymmetric (Curve25519) | `<audit_dir>/audit.key` or `sign_key_path` |
| `hmac-sha256` | 32 bytes | Symmetric (256-bit) | `<audit_dir>/audit_hmac.key` or `audit_hmac_key_path` |

Key files are generated automatically on first run if they do not exist. Keys are stored with owner-only permissions (`0600` on Unix). If no key path is configured for ECDSA/Ed25519, an ephemeral key is generated (logs cannot be verified across restarts).

### Log format

Entries are written as newline-delimited JSON (JSONL) to `<audit_dir>/current.jsonl`. Each entry contains:

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | RFC 3339 | Event time (UTC) |
| `event_id` | UUID v4 | Unique event identifier |
| `tenant_id` | string | Tenant or user identifier |
| `user_id` | string? | User or service ID (optional) |
| `action` | enum | `REQUEST`, `RESPONSE`, `DLP_BLOCK`, `DLP_WARN`, `AUTH`, `CONFIG_CHANGE`, `ERROR` |
| `classification` | enum | `NC`, `C1`, `C2`, `C3` (data classification) |
| `backend_routed` | string | Provider routed to, or `"BLOCKED"` |
| `request_hash` | string? | SHA-256 of request payload |
| `dlp_rules_triggered` | string[] | DLP rule IDs that fired |
| `ip_source` | string | Source IP (pseudonymized) |
| `duration_ms` | u64 | Processing duration |
| `previous_hash` | string | SHA-256 of previous entry (hash chain) |
| `signature` | hex | Signature bytes |
| `signature_algorithm` | string | Algorithm label |
| `model_name` | string? | Model used (EU AI Act Article 12) |
| `input_tokens` | u32? | Input token count (EU AI Act Article 12) |
| `output_tokens` | u32? | Output token count (EU AI Act Article 12) |
| `risk_level` | enum? | `low`, `medium`, `high`, `critical` (EU AI Act Article 14) |

### Hash chain

Each entry's `previous_hash` is the SHA-256 hash of the preceding entry. The first entry in a new log links to the genesis hash `SHA-256("GROB_AUDIT_GENESIS")`. The hash covers all content fields except `signature`, `signature_algorithm`, and batch metadata.

### Merkle batch signing

When `audit_batch_size > 1`, entries accumulate in memory until the batch is full or `audit_flush_interval_ms` elapses, then:

1. A SHA-256 binary Merkle tree is built over all entry hashes in the batch.
2. The Merkle root is signed once (instead of signing each entry individually).
3. All entries are written with batch metadata:

| Field | Type | Description |
|-------|------|-------------|
| `batch_id` | UUID v4 | Shared batch identifier |
| `batch_index` | u32 | Zero-based position within the batch |
| `merkle_root` | hex | Signed Merkle root hash |
| `merkle_proof` | ProofStep[]? | Inclusion proof (if `audit_include_merkle_proof = true`) |

Each `ProofStep` contains `{ "hash": "<hex>", "side": "left" | "right" }`.

To verify a single entry: recompute its hash, walk the `merkle_proof` steps (prepending left siblings, appending right siblings), and compare the result against the `merkle_root`. Then verify the `signature` over the `merkle_root` using the appropriate key.

### Edge cases

- **Partial batch on shutdown**: Call `AuditLog::flush()` during graceful shutdown to write any buffered entries.
- **Odd-sized batches**: When a Merkle level has an odd node count, the last node is promoted without hashing.
- **Backward compatibility**: Old entries without batch fields deserialize correctly (all batch fields have `#[serde(default)]`).

## Adaptive provider scoring

Ranks providers by a composite quality metric. Opt-in because it changes provider selection order within a priority level.

```toml
[security]
adaptive_scoring = false          # default: false (opt-in)
scoring_latency_alpha = 0.3       # EWMA smoothing factor (default: 0.3)
scoring_window_size = 50          # rolling window for success rate (default: 50)
scoring_decay_rate = 0.001        # score decay per second of inactivity (default: 0.001)
scoring_persist = false           # persist scores across restarts (default: false)
```

### Composite score

```
score = success_rate * latency_factor * confidence
```

| Component | Formula | Description |
|-----------|---------|-------------|
| `success_rate` | `successes / total` over rolling window | Fraction of successful requests |
| `latency_factor` | `1 / (1 + ewma_ms / 1000)` | Penalizes high-latency providers |
| `confidence` | `max(1 - decay_rate * idle_secs, 0.3)` | Decays score during inactivity, floor at 0.3 |

### Circuit breaker integration

When adaptive scoring is enabled alongside circuit breakers:
- **Open** circuit: adaptive factor forced to `0.0` (provider is skipped).
- **HalfOpen** circuit: adaptive factor capped at `0.1`.
- **Closed** circuit: adaptive factor is the raw composite score.

### Mapping sort

Model mappings are sorted by `priority / adaptive_factor`. Providers with factor `0.0` receive infinite effective priority (tried last). A new, unknown provider starts with factor `1.0`.

## Risk classification (EU AI Act)

```toml
[compliance]
enabled = true
risk_classification = true
escalation_threshold = "high"     # "low" | "medium" | "high" | "critical"
escalation_webhook = "https://example.com/webhook"  # optional
```

### Risk levels

| Level | Trigger conditions |
|-------|-------------------|
| **Low** | No DLP triggers, no PII, no blocks |
| **Medium** | PII detected, or more than 2 DLP rules triggered |
| **High** | Request blocked by DLP (without PII) |
| **Critical** | Prompt injection detected, or blocked with PII |

### Escalation

When `risk >= escalation_threshold`, Grob:
1. Increments the `grob_risk_escalation_total` counter (with `level` label).
2. Emits a `WARN`-level log.
3. POSTs a JSON payload to `escalation_webhook` (if configured) with a 5-second timeout.

Webhook payload:
```json
{
  "type": "risk_escalation",
  "risk_level": "Critical",
  "event_id": "...",
  "tenant_id": "...",
  "model": "...",
  "timestamp": "2026-03-18T12:00:00Z"
}
```

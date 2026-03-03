# Security Model

This document explains the security architecture of Grob, the threat assumptions it operates under, and how each security feature works.

## Threat model

Grob is a local or shared proxy that handles sensitive data: API keys, OAuth tokens, and LLM conversation content. The primary threats are:

1. **Credential leakage**: API keys or OAuth tokens exposed in logs, config responses, or error messages
2. **Unauthorized access**: Unauthenticated requests reaching LLM providers via the proxy
3. **Cost abuse**: Runaway spend from misconfigured routing or compromised clients
4. **Data exfiltration**: Sensitive data (secrets, PII) leaving the organization via LLM prompts or responses
5. **Provider cascading failure**: One degraded provider causing request queuing and timeout cascades

## Defense layers

### Authentication

Grob supports three authentication modes for incoming requests:

- **None** (default for local use): No authentication required. Suitable when Grob binds to localhost only.
- **API key**: Set `api_key` in `[server]` config. All requests must include `Authorization: Bearer <token>` or `x-api-key: <token>`. API key comparison uses constant-time equality (`subtle` crate) to prevent timing attacks.
- **JWT**: Validate JWTs against a JWKS endpoint with key rotation support.

Health (`/health`), metrics (`/metrics`), and OAuth endpoints are exempt from authentication.

### Rate limiting

Token-bucket rate limiter per tenant/API-key/IP. Default: 100 requests/second with burst of 200. Returns HTTP 429 with `Retry-After` header when exceeded. Configured via `[security]` section.

### Circuit breakers

Per-provider circuit breaker pattern prevents cascading failures:

| State | Behavior |
|-------|----------|
| Closed | Normal operation. Requests pass through. |
| Open | After 5 consecutive failures. Requests fail-fast for 30 seconds. |
| HalfOpen | After timeout. Allows up to 3 probe requests. 3 successes = Closed, 1 failure = Open. |

When a circuit breaker opens, requests skip that provider and fall through to the next priority mapping. This ensures one degraded provider does not block the entire request pipeline.

### DLP (Data Loss Prevention)

When the `dlp` feature is enabled, Grob scans requests and responses for:

- **Secrets**: 25 builtin rules covering AWS keys, API tokens, private keys, database connection strings, etc.
- **PII**: Names, email addresses, phone numbers
- **Canary tokens**: Watermarks for leak detection
- **URL exfiltration**: Suspicious URLs in responses

Scanning uses Aho-Corasick deterministic finite automata for O(n) performance on streaming chunks. No full-response buffering is needed.

### Credential protection

- API keys in config support `$ENV_VAR` syntax -- resolved at startup, never stored in plaintext in the config file
- The `/api/config` endpoint redacts API keys in responses
- OAuth tokens are stored with `0600` file permissions
- Sensitive data (OAuth codes, PKCE verifiers, token responses, upstream bodies) is excluded from debug logs
- API key comparison uses constant-time equality to prevent timing side-channels

### Security headers

When enabled, Grob applies OWASP-recommended security headers to all responses:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Strict-Transport-Security` (when behind TLS)
- `X-Request-Id` for request tracing

### Request size limits

Requests exceeding `max_body_size` (default: 10 MB) are rejected before parsing. This prevents memory exhaustion from oversized payloads.

### Budget enforcement

Monthly spend limits at three levels (model > provider > global) prevent cost overruns. When a limit is reached, requests return HTTP 402. OAuth/subscription providers are tracked at $0 cost.

### Audit logging

When `audit_dir` is configured, Grob writes signed, hash-chained audit log entries using ECDSA P-256. Each entry is cryptographically linked to the previous one, making tampering detectable. This supports compliance requirements (HDS, PCI, SecNumCloud).

## TLS

Grob supports native TLS via rustls (no OpenSSL dependency):

- **Manual**: Provide certificate and key files via `[tls]` config
- **ACME**: Automatic Let's Encrypt certificates via the `acme` feature flag

For most deployments, running behind a reverse proxy (nginx, Caddy, Traefik) that handles TLS is recommended over native TLS.

## Adaptive provider scoring

When `adaptive_scoring = true`, Grob ranks providers by a composite score combining success rate, latency (EWMA-smoothed), and recency. Scores decay over time to prevent stale rankings from masking degraded providers. The scoring window, decay rate, and latency alpha are configurable. Scores can optionally be persisted across restarts.

This feature is opt-in because it changes the provider selection order within a priority level, which may have cost implications.

## Response cache

When `[cache] enabled = true`, Grob caches responses for deterministic requests (temperature=0). Cache keys are computed from the tenant ID, model, messages, and tools. The cache uses moka (concurrent, TTL-evicting) with configurable capacity and TTL. Cache hits bypass the entire provider pipeline, returning instantly with `x-grob-cache: hit`. Only non-streaming requests are cached.

## EU AI Act compliance

The `[compliance]` section enables features required by the EU AI Act:

- **Transparency headers**: `X-AI-Provider`, `X-AI-Model`, `X-AI-Generated`, `X-Grob-Audit-Id` on every response (Article 50)
- **Audit enrichment**: Model name and token counts recorded in audit entries (Article 12)
- **Risk classification**: Requests scored by DLP trigger count, block status, injection detection, and PII presence (Article 14)
- **Escalation**: High-risk events dispatched to a configured webhook for human review

The `eu-ai-act` preset enables all compliance features in one command.

## Network binding

By default, Grob binds to `[::1]:13456` (IPv6 localhost only). In container mode (`grob run`), it binds to `0.0.0.0`. The bind address should match the deployment scenario:

- **Local workstation**: `::1` (default) -- only local processes can connect (IPv6). Use `127.0.0.1` for IPv4-only environments.
- **Container**: `0.0.0.0` -- accessible from outside the container (use network policies)
- **Shared server**: Use `api_key` or JWT authentication when binding to non-localhost addresses

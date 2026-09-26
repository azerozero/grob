# Error Reference

## HTTP Status Codes

| Code | Meaning | When returned |
|------|---------|---------------|
| 200 | Success | Successful non-streaming response |
| 400 | Bad Request | Invalid request body, missing required fields, schema validation failure, or context window exceeded |
| 401 | Unauthorized | Missing/invalid client credentials, or an upstream credential that needs reauthentication |
| 403 | Forbidden | Valid caller lacks the required role or model/provider permission |
| 402 | Payment Required | Monthly budget exceeded (global, per-provider, or per-model) |
| 404 | Not Found | Unknown endpoint |
| 413 | Payload Too Large | Request body exceeds `max_body_size` when that limit is enabled (`0` / unlimited by default) |
| 429 | Too Many Requests | Local rate limit, policy/tool-spike limit, or upstream throttling. `Retry-After` is present when available. |
| 500 | Internal Server Error | Internal processing, provider construction or transport error |
| 502 | Bad Gateway | Provider protocol failure or an aggregated all-providers failure |
| 503 | Service Unavailable | Readiness failure or an upstream unavailable response |
| 504 | Gateway Timeout | An upstream gateway timeout response |

A failed fallback chain can return its last upstream status instead of `502`. Inspect the error body to distinguish client authentication, upstream authentication, local limits and provider throttling. A local HTTP-client timeout can surface as `500`; the default provider request timeout is 10 minutes.

## Error response format

### Anthropic format (`/v1/messages`)

```json
{
  "type": "error",
  "error": {
    "type": "invalid_request_error",
    "message": "Description of the error"
  }
}
```

### OpenAI format (`/v1/chat/completions`)

```json
{
  "error": {
    "message": "Description of the error",
    "type": "error_type",
    "code": "error_code"
  }
}
```

## Common errors

### `All providers failed for model "..."` (502)

Every provider in the model's fallback chain returned an error. Causes:

- Missing or invalid API keys
- All providers are down or rate-limited
- Circuit breakers are open for all providers

**Diagnostics:**

```bash
grob doctor     # Check local config, credentials and service state
grob validate   # Real provider calls; may consume quota or incur cost
```

### `Budget exceeded` (402)

Monthly spend has reached the configured limit. The response includes which limit was hit (global, provider, or model).

**Check:**

```bash
grob spend
```

### `Rate limit exceeded` (429)

Too many requests per second from the same client. The `Retry-After` header indicates how long to wait.

An upstream `429` can trigger fallback and still reach the client if no eligible alternative succeeds. Policy and tool-spike rejections are terminal local `429`s. Check `error.type`, `error.message` and the provider logs before changing the Grob rate limit.

### `context_length_exceeded` (400)

The input is too close to, or over, the configured context window for the selected logical model. Grob estimates input tokens before provider dispatch so tools see a user-actionable error instead of an opaque upstream 502.

OpenAI-compatible endpoints (`/v1/chat/completions`, `/v1/responses`) return:

```json
{
  "error": {
    "message": "Input exceeds the configured context window. Compact the conversation and retry.",
    "type": "invalid_request_error",
    "param": "input",
    "code": "context_length_exceeded"
  }
}
```

Anthropic-compatible `/v1/messages` returns:

```json
{
  "type": "error",
  "error": {
    "type": "invalid_request_error",
    "message": "Input exceeds the configured context window. Compact the conversation and retry.\n\nSuggested action:\nRun /compact, then retry the last request.",
    "code": "context_length_exceeded",
    "param": "input"
  }
}
```

Responses include compact hints for clients and dashboards:

| Header | Meaning |
|--------|---------|
| `x-grob-action: compact` | Client should compact before retrying |
| `x-grob-context-used` | Estimated context usage ratio |
| `x-grob-context-window` | Context window used for the decision |
| `x-grob-context-estimated-input` | Estimated input tokens |
| `x-grob-context-threshold` | `warn` or `hard` |

### `Circuit breaker open for provider "..."` (502 with fallback)

A provider has accumulated 5+ consecutive failures. Grob skips it for 30 seconds, then probes with limited requests. This is not returned directly to the client unless all providers are in open state.

### `Failed to parse config` (startup)

The TOML config file has a syntax error or an unsupported field. Run `grob doctor`, correct the reported location, and retry. Check for duplicated tables and compare the field with the [Configuration Reference](configuration.md). Applying a preset replaces routing/provider sections; it is a deliberate reset, not the first repair step for a typo.

## Provider-specific errors

Retryable provider failures use the fallback chain when alternatives are configured and eligible. Terminal request or policy errors are returned immediately. If fallback is exhausted, the client may receive the last upstream status and error rather than a generic `502`.

Provider errors include:
- **Authentication failures**: Invalid API key or expired OAuth token
- **Rate limits**: Upstream provider rate limit (tracked in `grob_ratelimit_hits_total` metric)
- **Timeout**: Provider did not respond within `api_timeout_ms`
- **Network errors**: DNS resolution failure, connection refused, TLS handshake failure

## Metrics for error tracking

| Metric | Description |
|--------|-------------|
| `grob_requests_total{status="error"}` | Total failed requests |
| `grob_provider_errors_total` | Errors per provider |
| `grob_ratelimit_hits_total` | Upstream rate limit events |
| `grob_ratelimit_rejected_total` | Grob-level rate limit rejections |
| `grob_circuit_breaker_state` | Per-provider: 0=Closed, 1=Open, 2=HalfOpen |

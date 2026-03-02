# Error Reference

## HTTP Status Codes

| Code | Meaning | When returned |
|------|---------|---------------|
| 200 | Success | Successful non-streaming response |
| 400 | Bad Request | Invalid request body, missing required fields, schema validation failure |
| 401 | Unauthorized | Missing or invalid `Authorization` header when `api_key` is configured |
| 402 | Payment Required | Monthly budget exceeded (global, per-provider, or per-model) |
| 404 | Not Found | Unknown endpoint |
| 413 | Payload Too Large | Request body exceeds `max_body_size` (default: 10 MB) |
| 429 | Too Many Requests | Grob-level rate limit exceeded. Includes `Retry-After` header. |
| 502 | Bad Gateway | All providers failed for the requested model |
| 504 | Gateway Timeout | Provider request timed out (default: 10 minutes) |

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
grob doctor     # Check config and connectivity
grob validate   # Test each provider with a real API call
```

### `Budget exceeded` (402)

Monthly spend has reached the configured limit. The response includes which limit was hit (global, provider, or model).

**Check:**

```bash
grob spend
```

### `Rate limit exceeded` (429)

Too many requests per second from the same client. The `Retry-After` header indicates how long to wait.

This is the Grob-level rate limit, not an upstream provider limit. Upstream 429s trigger fallback to the next provider.

### `Circuit breaker open for provider "..."` (502 with fallback)

A provider has accumulated 5+ consecutive failures. Grob skips it for 30 seconds, then probes with limited requests. This is not returned directly to the client unless all providers are in open state.

### `Failed to parse config` (startup)

The TOML config file has a syntax error. Run `grob doctor` for validation details, or start fresh with `grob preset apply medium`.

## Provider-specific errors

Provider errors are wrapped in the fallback logic. If a provider returns an error, Grob logs it and tries the next provider in the chain. The client only sees an error if all providers fail.

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

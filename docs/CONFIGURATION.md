# Configuration Reference

Grob reads its configuration from `~/.grob/config.toml` by default.

Override with:
- `--config <path>` flag
- `GROB_CONFIG` environment variable (supports file paths and URLs)

## Server

```toml
[server]
port = 13456              # Listen port (default: 13456)
host = "127.0.0.1"        # Bind address (default: 127.0.0.1)
log_level = "info"        # Log level: trace, debug, info, warn, error
api_key = "my-secret"     # Optional: require Bearer token on incoming requests

[server.timeouts]
api_timeout_ms = 600000   # Provider request timeout (default: 10 min)
connect_timeout_ms = 10000 # TCP connect timeout (default: 10s)
```

When `api_key` is set, all requests must include `Authorization: Bearer <token>` or `x-api-key: <token>`. Health and metrics endpoints are exempt.

## Budget

Control monthly spend with global, per-provider, and per-model limits.

```toml
[budget]
monthly_limit_usd = 10.0     # Global hard cap, 0 = unlimited (default: 0)
warn_at_percent = 80          # Log warning at this % of any limit (default: 80)
```

Budget checks follow a priority order: model limit > provider limit > global limit. When a limit is reached, requests return HTTP 402 with a `budget_exceeded` error. OAuth providers cost $0 and never hit caps.

Spend is tracked in `~/.grob/spend.json` and resets automatically each month.

## Providers

```toml
[[providers]]
name = "anthropic"              # Unique name, used in model mappings
provider_type = "anthropic"     # See provider types below
api_key = "$ANTHROPIC_API_KEY"  # API key (supports $ENV_VAR syntax)
base_url = "https://..."        # Override default base URL
auth_type = "oauth"             # "apikey" (default) or "oauth"
oauth_provider = "anthropic-max" # OAuth provider ID (for auth_type = "oauth")
enabled = true                  # Enable/disable without removing config
headers = { "X-Custom" = "v" }  # Custom HTTP headers
budget_usd = 5.0               # Monthly spend limit for this provider (optional)
project_id = "my-gcp-project"  # Google Cloud project ID (for vertex-ai)
location = "us-central1"       # Google Cloud region (for vertex-ai)
```

### Provider types

| Type | Default base URL | Protocol |
|------|-----------------|----------|
| `anthropic` | `https://api.anthropic.com` | Anthropic Messages |
| `openai` | `https://api.openai.com/v1` | OpenAI Chat Completions |
| `openrouter` | `https://openrouter.ai/api/v1` | OpenAI + custom headers |
| `gemini` | Google AI Studio | Gemini |
| `vertex-ai` | Google Cloud | Gemini (ADC auth) |
| `z.ai` | z.ai | Anthropic Messages |
| `minimax` | MiniMax | Anthropic Messages |
| `kimi-coding` | Kimi | Anthropic Messages |

### Environment variable expansion

API keys support `$ENV_VAR` syntax. Grob resolves them at startup:

```toml
api_key = "$OPENROUTER_API_KEY"  # reads from environment
api_key = "sk-ant-..."           # literal value (not recommended)
```

## Models

Models define named routing targets with priority-based fallback chains.

```toml
[[models]]
name = "default"                  # Model name used by the router
budget_usd = 2.0                  # Monthly spend limit for this model (optional)

[[models.mappings]]
provider = "anthropic"            # Provider name (must match a [[providers]] entry)
actual_model = "claude-sonnet-4-6" # Model ID sent to the provider
priority = 1                      # Lower = tried first

[[models.mappings]]
provider = "openrouter"
actual_model = "deepseek/deepseek-v3.2"
priority = 2                      # Fallback if priority 1 fails
inject_continuation_prompt = false # Inject a continuation prompt for non-Anthropic providers (default: false)
```

When a request arrives, Grob tries providers in priority order. If a provider returns an error or times out, Grob moves to the next priority.

## Router

```toml
[router]
default = "default"                    # Default model for unmatched requests
think = "claude-opus-thinking"         # Model for thinking-enabled requests
background = "background"             # Model for background/haiku requests
websearch = "websearch"               # Model for web search tool requests
auto_map_regex = "^claude-"           # Regex: auto-route matching model names to their provider
background_regex = "(?i)claude.*haiku" # Regex: route matching models to background
```

### Routing priority

1. **web_search** -- request contains a `web_search` tool
2. **think** -- request has `thinking` enabled in metadata
3. **background** -- requested model matches `background_regex`
4. **prompt_rules** -- first message matches a prompt rule pattern
5. **auto_map** -- requested model matches `auto_map_regex`
6. **default** -- everything else

### Prompt-based routing

Route requests to specific models based on regex patterns matched against the first user message:

```toml
[[router.prompt_rules]]
pattern = "(?i)translate|翻译"    # Regex pattern to match
model = "translation-model"       # Model to route to
strip_match = false               # Remove matched text from the message (default: false)
```

## Security

Control rate limiting, security headers, body size limits, circuit breakers, and audit logging.

```toml
[security]
enabled = true              # Master switch for all security middleware (default: true)
rate_limit_rps = 100        # Requests per second per tenant/IP (default: 100)
rate_limit_burst = 200      # Burst allowance (default: 200)
max_body_size = 10485760    # Max request body in bytes (default: 10MB)
security_headers = true     # Apply OWASP security headers (default: true)
circuit_breaker = true      # Enable circuit breaker per provider (default: true)
audit_dir = ""              # Audit log directory, empty = disabled (default: "")
```

When `enabled = false`, rate limiting, security headers, and circuit breaker middleware are all skipped. Individual features can also be toggled independently.

The circuit breaker opens after 5 consecutive failures (30s timeout, 3 successes to close). When open, requests skip the provider and fall through to the next mapping.

## Config versioning

Optional schema version for tracking config compatibility:

```toml
version = "0.9.0"
```

## Model deprecation

Mark models as deprecated to emit warnings:

```toml
[[models]]
name = "old-model"
deprecated = "Use new-model instead. Removal planned for v1.0."
```

When a deprecated model is used, Grob logs a warning and adds `X-Model-Deprecated` header to the response.

## Message tracing

Log all requests and responses for debugging:

```toml
[server.tracing]
enabled = false                   # Enable message tracing (default: false)
path = "~/.grob/trace.jsonl"      # Trace file path (default: ~/.grob/trace.jsonl)
omit_system_prompt = true         # Omit system prompts from traces (default: true)
```

## Presets

```toml
[presets]
active = "medium"         # Currently applied preset name
sync_url = "https://..."  # URL to sync presets from (optional)
sync_interval = "24h"     # Auto-sync interval (e.g., "1h", "24h", "7d") (optional)
auto_sync = true          # Enable automatic preset sync (default: true)
```

## Remote configuration

Load config from a URL for Docker/Kubernetes deployments:

```bash
GROB_CONFIG=https://config.example.com/grob.toml grob start
```

When loaded from a URL, config is read-only (save/export commands are disabled). Config is re-fetched on `grob restart`.

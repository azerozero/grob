# Configuration Reference

Grob reads its configuration from `~/.grob/config.toml` by default.

Override with:
- `--config <path>` flag
- `GROB_CONFIG` environment variable (supports file paths and URLs)

## Server

```toml
[server]
port = 13456              # Listen port (default: 13456)
host = "::1"              # Bind address (default: "::1" — IPv6 localhost)
log_level = "info"        # Log level: trace, debug, info, warn, error
api_key = "my-secret"     # Optional: require Bearer token on incoming requests
oauth_callback_port = 1455 # Port for the OAuth callback server (default: 1455)

[server.timeouts]
api_timeout_ms = 600000   # Provider request timeout (default: 10 min)
connect_timeout_ms = 10000 # TCP connect timeout (default: 10s)
```

When `api_key` is set, all requests must include `Authorization: Bearer <token>` or `x-api-key: <token>`. Health, metrics, and OAuth endpoints are exempt.

The default host `::1` is IPv6 localhost. Use `127.0.0.1` for IPv4-only environments, or `0.0.0.0` for container deployments.

## Budget

Control monthly spend with global, per-provider, and per-model limits.

```toml
[budget]
monthly_limit_usd = 10.0     # Global hard cap, 0 = unlimited (default: 0)
warn_at_percent = 80          # Log warning at this % of any limit (default: 80)
```

Budget checks follow a priority order: model limit > provider limit > global limit. When a limit is reached, requests return HTTP 402 with a `budget_exceeded` error. OAuth providers cost $0 and never hit caps.

Spend is tracked in `~/.grob/grob.db` (redb) and resets automatically each month. Legacy `spend.json` data is auto-migrated on first run.

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
region = "eu"                  # Provider region for GDPR filtering (e.g., "eu", "us", "global")
pass_through = true            # Accept any model name not in [[models]] (default: false)
project_id = "my-gcp-project"  # Google Cloud project ID (for vertex-ai)
location = "us-central1"       # Google Cloud region (for vertex-ai)
```

When `pass_through = true`, the provider accepts any model name that does not match a configured `[[models]]` entry, forwarding it as-is to the upstream API. This is useful for providers like OpenRouter that support many models without explicit configuration.

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

### Model strategies

```toml
[[models]]
name = "consensus"
strategy = "fan_out"             # "fallback" (default) or "fan_out"

[models.fan_out]
mode = "fastest"                 # "fastest", "best_quality", or "weighted"
judge_model = "default"          # Model for best_quality judging (optional)
count = 3                        # Number of providers to fan out to (optional, default: all)
```

Fan-out dispatches the request to multiple providers in parallel:
- `fastest`: returns the first successful response
- `best_quality`: sends all responses to a judge model for selection
- `weighted`: scores responses by latency, cost, and length

### Deprecated models

```toml
[[models]]
name = "old-model"
deprecated = "Use new-model instead. Removal planned for v1.0."
```

When a deprecated model is used, Grob logs a warning and adds `X-Model-Deprecated` header to the response.

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

### GDPR mode

```toml
[router]
gdpr = true        # Only route to providers in the allowed region
region = "eu"      # Region filter (only providers with matching "region" field)
```

### Routing priority

Order (highest to lowest):

1. **auto_map** -- model name transformation (runs first, changes model name but not route type)
2. **web_search** -- request contains a `web_search` tool
3. **background** -- original model name matches `background_regex`
4. **subagent** -- system prompt contains `GROB-SUBAGENT-MODEL` tag
5. **prompt_rules** -- user message matches a prompt rule pattern
6. **think** -- request has `thinking` enabled
7. **default** -- everything else

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
enabled = true                  # Master switch for all security middleware (default: true)
rate_limit_rps = 100            # Requests per second per tenant/IP (default: 100)
rate_limit_burst = 200          # Burst allowance (default: 200)
max_body_size = 10485760        # Max request body in bytes (default: 10MB)
security_headers = true         # Apply OWASP security headers (default: true)
circuit_breaker = true          # Enable circuit breaker per provider (default: true)
audit_dir = ""                  # Audit log directory, empty = disabled (default: "")
audit_signing_algorithm = ""    # "ecdsa-p256" (default) or "hmac-sha256"
audit_hmac_key_path = ""        # Path to HMAC key file (for hmac-sha256; default: <audit_dir>/audit_hmac.key)

# Adaptive provider scoring (opt-in)
adaptive_scoring = false        # Enable scoring-based provider ranking (default: false)
scoring_latency_alpha = 0.3     # EWMA alpha for latency smoothing, 0.0-1.0 (default: 0.3)
scoring_window_size = 50        # Rolling window for success rate calculation (default: 50)
scoring_decay_rate = 0.001      # Score decay per second of inactivity (default: 0.001)
scoring_persist = false         # Persist scores across restarts (default: false)
```

When `enabled = false`, rate limiting, security headers, and circuit breaker middleware are all skipped. Individual features can also be toggled independently.

The circuit breaker opens after 5 consecutive failures (30s timeout, 3 successes to close). When open, requests skip the provider and fall through to the next mapping.

When `adaptive_scoring = true`, Grob ranks providers by a composite score (success rate, latency, recency). Higher-scoring providers are tried first within the same priority level. Scores decay over time to prevent stale rankings.

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

## Authentication (JWT)

```toml
[auth]
enabled = false
jwks_url = "https://example.com/.well-known/jwks.json"  # JWKS endpoint for key rotation
issuer = "https://example.com"                           # Expected JWT issuer
audience = "grob"                                        # Expected JWT audience
```

When enabled, incoming requests must include a valid JWT in the `Authorization: Bearer` header. Keys are fetched from the JWKS endpoint and cached with automatic rotation.

## DLP (Data Loss Prevention)

```toml
[dlp]
enabled = true           # Enable DLP scanning (default: true when dlp feature is compiled)
scan_input = true        # Scan outgoing requests for secrets/PII (default: true)
scan_output = true       # Scan incoming responses for secrets/PII (default: true)
block_on_match = false   # Block requests that match DLP rules (default: false)
custom_patterns = []     # Additional regex patterns to scan for
canary_enabled = false   # Enable canary token injection/detection
```

DLP scanning uses Aho-Corasick deterministic finite automata for O(n) performance. 25 builtin rules cover AWS keys, API tokens, private keys, database connection strings, and more.

## Tap (Webhook Events)

```toml
[tap]
enabled = false
url = "https://hooks.example.com/grob"   # Webhook URL to send events to
events = ["request", "response", "error"] # Event types to emit
```

When enabled, Grob sends non-blocking webhook events for request/response/error lifecycle events. Events include model, provider, latency, and token counts.

## Response Cache

```toml
[cache]
enabled = false          # Enable response caching (default: false)
max_capacity = 2000      # Maximum cached entries (default: 2000)
ttl_secs = 3600          # Cache TTL in seconds (default: 1 hour)
max_entry_bytes = 2097152 # Max single entry size in bytes (default: 2 MB)
```

Only deterministic requests (temperature=0) are cached. Cache hits return instantly with an `x-grob-cache: hit` header. The cache uses moka (high-performance concurrent cache with TTL eviction).

## Compliance (EU AI Act)

```toml
[compliance]
enabled = false                    # Enable EU AI Act compliance features
transparency_headers = false       # Add X-AI-Provider, X-AI-Model, X-AI-Generated headers
audit_model_name = false           # Record model name in audit entries (Article 12)
audit_token_counts = false         # Record token counts in audit entries (Article 12)
risk_classification = false        # Enable risk classification (Article 14)
escalation_threshold = "high"      # Minimum risk level to escalate: low, medium, high, critical
escalation_webhook = ""            # Webhook URL for risk escalation notifications
```

The `eu-ai-act` preset enables all compliance features. See [ADR-0005](decisions/0005-anthropic-native-provider-trait.md) for the Anthropic-native design that enables transparent model attribution.

## MCP (Tool Matrix)

```toml
[mcp]
enabled = false                    # Enable MCP tool matrix
matrix_path = "~/.grob/matrix.toml" # Path to tool capability catalogue
```

The MCP tool matrix is a static TOML catalogue of tools with per-provider reliability scores. A bench engine continuously tests tool-calling capabilities. The `/mcp` endpoint exposes a JSON-RPC interface for querying, benchmarking, and calibrating tool scores.

## Per-project overrides

Create a `.grob.toml` file in your project root (or any parent directory up to `$HOME`) to overlay settings:

```toml
# .grob.toml (project root)
[router]
default = "fast-model"
think = "claude-opus-thinking"

[[router.prompt_rules]]
pattern = "(?i)database|migration"
model = "claude-opus-thinking"

[budget]
monthly_limit_usd = 20.0

[presets]
active = "medium"
```

Project config merges with global config. Router settings and prompt rules from the project file take precedence.

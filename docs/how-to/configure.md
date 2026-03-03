# How to Configure Grob

## Set a monthly budget

Add a global spend limit to prevent runaway costs:

```toml
[budget]
monthly_limit_usd = 50.0    # Hard cap, requests return HTTP 402 when exceeded
warn_at_percent = 80         # Log warning at 80% of limit
```

Per-provider and per-model limits are also supported:

```toml
[[providers]]
name = "openrouter"
provider_type = "openrouter"
api_key = "$OPENROUTER_API_KEY"
budget_usd = 20.0            # This provider only

[[models]]
name = "default"
budget_usd = 10.0            # This model only
```

Restart Grob after changing the config:

```bash
grob restart -d
```

## Add a fallback provider

Add a second mapping with a higher priority number (lower priority = tried first):

```toml
[[models]]
name = "default"

[[models.mappings]]
provider = "anthropic"
actual_model = "claude-sonnet-4-6"
priority = 1                  # Tried first

[[models.mappings]]
provider = "openrouter"
actual_model = "deepseek/deepseek-v3.2"
priority = 2                  # Tried if priority 1 fails
```

## Add prompt-based routing

Route specific requests to specialized models using regex patterns:

```toml
[[router.prompt_rules]]
pattern = "(?i)translate|翻译"
model = "translation-model"

[[router.prompt_rules]]
pattern = "(?i)write.*test|unit test"
model = "background"
```

Patterns match against the first user message. Rules are evaluated in order; the first match wins.

## Enable message tracing

Log all requests and responses for debugging:

```toml
[server.tracing]
enabled = true
path = "~/.grob/trace.jsonl"
omit_system_prompt = true     # Don't log system prompts
```

## Configure rate limiting

Adjust the per-tenant rate limit:

```toml
[security]
rate_limit_rps = 200          # Requests per second
rate_limit_burst = 400        # Burst allowance
```

## Use a remote config

Load config from a URL for container deployments:

```bash
GROB_CONFIG=https://config.example.com/grob.toml grob start
```

When loaded from a URL, save/export commands are disabled. Config is re-fetched on `grob restart`.

## Override config per project

Create a `.grob.toml` file in your project root to override router settings:

```toml
# .grob.toml (project root)
[router]
default = "fast-model"

[[router.prompt_rules]]
pattern = "(?i)database|migration"
model = "claude-opus-thinking"
```

Project config merges with the global config, overriding matching keys.

## Enable response caching

Cache deterministic responses (temperature=0) to reduce provider costs and latency:

```toml
[cache]
enabled = true
max_capacity = 2000      # Number of cached entries
ttl_secs = 3600          # Cache TTL (1 hour)
```

Cached responses include an `x-grob-cache: hit` header. Only non-streaming, temperature=0 requests are cached.

## Enable DLP scanning

Scan requests and responses for secrets and PII:

```toml
[dlp]
scan_input = true        # Scan outgoing requests
scan_output = true       # Scan incoming responses
block_on_match = false   # Block (true) or just log (false) matches
```

## Enable pass-through mode

Allow a provider to accept any model name, forwarding it as-is without explicit `[[models]]` configuration:

```toml
[[providers]]
name = "openrouter"
provider_type = "openrouter"
api_key = "$OPENROUTER_API_KEY"
pass_through = true         # Accept any model name
```

With pass-through enabled, you can request any model available on that provider without adding a `[[models.mappings]]` entry.

## Full reference

See [Configuration Reference](../CONFIGURATION.md) for every option with defaults and types.

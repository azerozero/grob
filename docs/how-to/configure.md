# How to Configure Grob

Edit `~/.grob/config.toml`, or the file selected by `--config` / `GROB_CONFIG`. The snippets below are additions to an existing working configuration: replace example model and provider names with your own. Do not append a second copy of a table that already exists.

Run `grob doctor` after editing. `grob validate` additionally makes real provider requests and can consume quota. Use the reload procedure below for routing and budgets; restart for startup-only settings.

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
models = []                  # Required legacy field; mappings select models
budget_usd = 20.0            # This provider only

[[models]]
name = "default"
budget_usd = 10.0            # This model only
```

Restart Grob after changing the config:

```bash
grob restart -d
```

## Reload without restarting

Routing, provider mappings, budgets, policies and the tool layer can be reloaded
through `POST /api/config/reload` with an administrative credential. Existing
requests finish on their original snapshot; subsequent requests use the new one.
Invalid configuration, failed provider construction and changes to startup-only
settings are rejected before the running snapshot changes. An API save rejected
during validation or provider construction also leaves the config file unchanged.

HTTP, JSON-RPC and MCP mutations share the same configuration validation and
rebuild path. RPC `grob/config/set` changes are memory-only and revert on disk
reload. Optional string fields accept a string or explicit `null`; other types
are rejected. RPC `grob/tools/enable` and `grob/tools/disable` update the tool
layer used by subsequent requests, without changing the file on disk.

Changing listener, authentication mode, cache or DLP settings still requires a
restart. For credential replacement without a reload, see
[Manage Secrets](manage-secrets.md#replace-credentials-without-changing-the-agent).

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

Patterns match the user message that starts the current turn, so the choice persists through tool calls. Rules are evaluated in order; the first match wins. The target must be a configured logical model. See [routing priority](../reference/routing.md#priority-order) for cases that take precedence.

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
enabled = true          # Activate the pipeline
```

Restart after changing DLP settings. Built-in secret rules and financial PII use redaction by default. There is no global `block_on_match` setting. Select actions per rule or detector; see [DLP Reference](../reference/dlp.md).

## Enable pass-through mode

Allow a provider to accept any model name, forwarding it as-is without explicit `[[models]]` configuration:

```toml
[[providers]]
name = "openrouter"
provider_type = "openrouter"
api_key = "$OPENROUTER_API_KEY"
models = []                  # Required legacy field; mappings select models
pass_through = true         # Accept any model name
```

With pass-through enabled, you can request any model available on that provider without adding a `[[models.mappings]]` entry.

## Full reference

See [Configuration Reference](../reference/configuration.md) for every option with defaults and types.

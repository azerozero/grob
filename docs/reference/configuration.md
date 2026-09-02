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
warmup_connections = false # Pre-warm provider connections at startup (default: false)
validate_on_start = false  # Probe each router model at startup (default: false)
# expected_config_revision = "sha256:…"  # Multi-replica only: fail /ready when the
                                         # active config revision differs (default: unset)

[server.timeouts]
api_timeout_ms = 600000   # Provider request timeout (default: 10 min)
connect_timeout_ms = 10000 # TCP connect timeout (default: 10s)
```

When `api_key` is set, all requests must include `Authorization: Bearer <token>` or `x-api-key: <token>`. Health, metrics, and OAuth endpoints are exempt.

The default host `::1` is IPv6 localhost. Use `127.0.0.1` for IPv4-only environments, or `0.0.0.0` for container deployments.

### Startup network behavior

By default a fresh `grob start` performs **no outgoing network requests** and the listener binds immediately — startup is offline-safe and air-gap friendly. Two opt-in probes can be enabled:

- `warmup_connections` — fires a background `HEAD` to each provider's base URL so the first real request avoids cold-connection latency.
- `validate_on_start` — sends a minimal `max_tokens=1` test request to every provider mapping and logs a health summary. This consumes a small amount of provider quota per mapping, so it is off by default.

Both run after the listener is already accepting traffic, so neither can stall the bind.

### Multi-replica revision pinning

`expected_config_revision` makes a replica report itself **not ready** while the
configuration it is serving differs from the one the deployment intended, so an
orchestrator drains it instead of letting it enforce a superseded policy. Unset
by default, which is correct for a single daemon. See
[Keep Multiple Replicas Consistent](../how-to/multi-replica-consistency.md).

## Budget

Control monthly spend with global, per-provider, and per-model limits.

```toml
[budget]
monthly_limit_usd = 10.0     # Global hard cap, 0 = unlimited (default: 0)
warn_at_percent = 80          # Log warning at this % of any limit (default: 80)
```

Budget checks follow a priority order: model limit > provider limit > global limit. When a limit is reached, requests return HTTP 402 with a `budget_exceeded` error. OAuth providers cost $0 and never hit caps.

Spend is tracked in append-only JSONL journals (`~/.grob/spend/YYYY-MM.jsonl`) and resets automatically each month.

### Budget across multiple replicas

Spend is tracked **per process**. The in-memory total is seeded once at startup
and updated only by that replica, so a peer writing to the same journal stays
invisible until restart. **Mounting a shared volume does not make the budget
shared** — a natural assumption, and a costly one: N replicas each allow the
full cap, so the fleet can spend `N × monthly_limit_usd`.

If the point of the cap is "do not spend more than this", declare the fleet:

```toml
[budget]
monthly_limit_usd = 100.0   # the FLEET-wide cap
replicas = 5                # each replica enforces its share
margin_percent = 1          # withheld for rounding and restarts
```

Each replica then allows `$19.80`, so five of them cap the fleet at `$99.00`.
Verified on a live replica: with `$19.90` recorded, the next request is refused
with HTTP 402 even though the fleet cap of `$100` is far from reached.

`/health` shows both numbers, so the configured cap can be reconciled with
observed spend:

```json
{
  "spend": {
    "total_usd": 19.9,
    "budget_usd": 100.0,
    "budget_usd_this_replica": 19.8,
    "replicas": 5
  }
}
```

The trade is the same as for [rate limiting](#making-the-limit-a-real-fleet-wide-ceiling):
utilisation for a guarantee, at the cost of **no coordination at all** — no
shared store, no gossip, not a single packet between replicas. A replica cannot
spend an idle peer's share. For a *cost* cap that is usually the right way
round: under-spending is recoverable, an overrun is not.

### Which limits are fleet-aware

Not every limit accumulates across replicas, so not every limit needs dividing.
The distinction is whether the thing being counted is **shared** by the fleet:

| Limit | Fleet-aware | Why |
|---|---|---|
| `[security] rate_limit_rps` / `burst` | ✅ `rate_limit_replicas` | every replica throttles the same caller |
| `[security.rate_limit_clients]` overrides | ✅ same knob | a named client must not escape the ceiling |
| `[[policies]] rate_limit.rps` | ✅ same knob | a policy must not escape it either |
| `[budget] monthly_limit_usd` | ✅ `[budget] replicas` | the money is one pot |
| `[[providers]] budget_usd`, `[[models]] budget_usd` | ✅ same knob | same pot, narrower scope |
| `[[policies]] budget.monthly_usd` | ✅ same knob | same pot again |
| `tool_spike_*_per_min` | ❌ not needed | keyed per **session**, and a session is served by one replica |
| `[cache] max_capacity`, `max_entry_bytes` | ❌ not needed | a per-process memory bound, not a shared quota |
| `max_body_size` | ❌ not needed | a property of a single request |

A limit in the second group is already correct on every replica: dividing it
would shrink a per-process bound for no reason.

`replicas` is a **declaration grob cannot verify** — it never counts its peers,
which is precisely what avoids the coordination. If an autoscaler runs more
replicas than declared, the ceiling scales with them. Declare the autoscaler's
**maximum**, not its nominal size.

## Pricing

Controls where model prices come from and how token usage is accounted.

```toml
[pricing]
fetch_openrouter = false       # Fetch live OpenRouter prices (default: false)
refresh_interval_hours = 24    # Background refresh cadence when fetching (default: 24)
token_counting = "api"         # "api" (default) or "estimate"
```

**Price source.** By default grob uses its built-in hardcoded price table, so startup performs no network I/O. When `fetch_openrouter = true`, the initial OpenRouter fetch runs in a **background task** (it never blocks the listener from binding) and merges live prices over the hardcoded table, refreshing every `refresh_interval_hours`. A failed fetch is logged and leaves the hardcoded table in place.

**Token counting.**

- `api` (default) — trust the provider-reported usage and record spend synchronously, so the next budget check sees it immediately.
- `estimate` — move the spend mutex and journal write off the response hot path into a detached task, so request latency is never gated on disk I/O. Provider-reported usage stays the source of truth; counters consolidate a fraction of a second later, so a concurrent budget check may lag by at most one in-flight request. When a provider omits usage entirely or only returns zero-valued stream usage, input and output tokens are estimated locally (~4 chars/token) so genuinely-consumed tokens aren't billed as `$0`. This local fallback covers **both non-streaming and streaming responses**: for streaming, output tokens are estimated from the accumulated `text_delta` text and spend is recorded when the stream terminates.

**Streaming spend.** Streaming responses (`stream: true`) record spend like non-streaming ones. A passthrough wrapper observes the SSE stream without altering the bytes the client receives — it forwards each chunk immediately (unchanged time-to-first-byte and inter-chunk timing) and does only a cheap substring scan per chunk. On stream termination it records spend in a detached task, so the final chunk is never delayed by the spend mutex or journal write. Provider-reported usage (`message_start` input tokens, `message_delta` output tokens) is authoritative when it contains non-zero token counts; the estimate-mode fallback above applies when a provider omits usage or returns only zero usage. In `api` mode with no reported usage, nothing is billed (matching non-streaming behaviour).

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
| `zenmux` | Zenmux | Anthropic Messages |

### Multi-account key pool

Chain multiple API keys for a single provider. Grob rotates through them automatically.

```toml
[[providers]]
name = "openai"
provider_type = "openai"
api_key = "$OPENAI_API_KEY_1"

[providers.pool]
strategy = "round_robin"   # "sequential" | "round_robin" | "fallback"
keys = ["$OPENAI_API_KEY_2", "$OPENAI_API_KEY_3"]
```

| Strategy | Behavior |
|----------|----------|
| `sequential` | Use keys in order, rotate on rate limit (default) |
| `round_robin` | Distribute requests evenly across all keys |
| `fallback` | Use primary key, switch to pool only on failure |

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
context_window_tokens = 200000     # Optional hard-window hint for compact guard

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

`context_window_tokens` lets Grob reject oversized agent contexts before provider dispatch. At 80% of the window, Grob adds `x-grob-action: compact` warning headers. At 95%, it returns HTTP `400` with `context_length_exceeded` in the endpoint's native error format.

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

1. **web_search** -- request contains a `web_search` tool
2. **background** -- original model name matches `background_regex`
3. **auto_map** -- model name transformation (after background check, changes model name but not route type)
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
rate_limit_rps = 0              # Requests per second per tenant/IP (default: 0 = disabled)
rate_limit_burst = 0            # Burst allowance (default: 0; used only when rate_limit_rps > 0)
rate_limit_by_client = false    # Key the limiter on the OIDC client, not the subject (default: false)
max_body_size = 0               # Max request body in bytes (default: 0 = unlimited)
security_headers = true         # Apply OWASP security headers (default: true)
circuit_breaker = true          # Enable circuit breaker per provider (default: true)
audit_dir = ""                  # Audit log directory, empty = disabled (default: "")
audit_signing_algorithm = ""    # "ecdsa-p256" (default), "hmac-sha256", or "ed25519"
audit_hmac_key_path = ""        # Path to HMAC key file (for hmac-sha256; default: <audit_dir>/audit_hmac.key)

# Adaptive provider scoring (opt-in)
adaptive_scoring = false        # Enable scoring-based provider ranking (default: false)
scoring_latency_alpha = 0.3     # EWMA alpha for latency smoothing, 0.0-1.0 (default: 0.3)
scoring_window_size = 50        # Rolling window for success rate calculation (default: 50)
scoring_decay_rate = 0.001      # Score decay per second of inactivity (default: 0.001)
scoring_persist = false         # Reserved; score persistence is not implemented yet
```

When `enabled = false`, rate limiting, security headers, and circuit breaker middleware are all skipped. Individual features can also be toggled independently.

### Rate limiting by OIDC client

By default the limiter keys on the tenant, which for a user token is the `sub`
claim — the individual **end user**. One application serving a thousand users
therefore gets a thousand independent buckets and is not bounded at all. That is
usually not what an API quota means.

Set `rate_limit_by_client = true` to key client-scoped tokens on the OIDC client
(`azp`, falling back to `client_id`) instead:

```toml
[security]
rate_limit_rps = 10
rate_limit_burst = 20
rate_limit_by_client = true

# Optional per-client overrides. A client absent from this map uses
# rate_limit_rps, so only the exceptions need naming.
[security.rate_limit_clients]
"batch-indexer" = 200   # a trusted job that may push harder
"partner-app"   = 5     # a third-party integration that must not
```

An override scales the burst by the same factor as the rate, so a client granted
10x the throughput also gets 10x the burst rather than inheriting one sized for
the default.

Tokens carrying **no** client claim (a self-signed HMAC token, an API key, an
anonymous request) keep their existing tenant/IP key, so enabling this cannot
merge unrelated callers into one bucket.

Two limits worth knowing: buckets are in-memory and therefore **per replica**
(with N replicas the effective limit is N × `rate_limit_rps`), and the limiter
runs after authentication, so rejected credentials never consume a legitimate
caller's quota.

### Quota headers

Every response carries the current quota, not just the `429`. A client that only
learns its budget from a rejection has already been throttled, which is what
these fields exist to prevent.

```http
RateLimit-Policy: "default";q=20;w=2
RateLimit: "default";r=19;t=2
X-RateLimit-Limit: 20
X-RateLimit-Remaining: 19
X-RateLimit-Reset: 2
```

Both spellings are emitted with identical numbers: the IETF structured fields
(`draft-ietf-httpapi-ratelimit-headers`) because that is where the ecosystem is
heading, and the de-facto `X-RateLimit-*` because that is what clients parse
today.

The advertised quota is the **bucket capacity** (`rate_limit_burst`), not the
refill rate, so `remaining` can never exceed `limit`. The window is how long a
full burst takes to accrue — a token bucket refills continuously and has no
fixed window, so this is the closest honest number to pace against.

### Making the limit a real fleet-wide ceiling

Buckets are per process, so N replicas each enforcing `rate_limit_rps` let the
fleet through `N × rate_limit_rps`. When the limit is a **hard** constraint — a
provider quota that returns 429, a contractual cap — declare the fleet size:

```toml
[security]
rate_limit_rps = 1000          # the FLEET-wide limit
rate_limit_burst = 1000
rate_limit_replicas = 4        # each replica enforces its share
rate_limit_margin_percent = 5  # withhold a little for rounding and restarts
```

Each replica then enforces `(1000 - 5%) / 4 = 237` rps, so the fleet cannot
exceed 950. Measured on three live replicas with a limit of 30: **90 requests
got through without the declaration, 27 with it.**

The trade is utilisation for a guarantee, and it costs **no coordination at
all** — no shared store, no gossip, not a single packet between replicas. A
replica cannot borrow unused capacity from an idle peer, so unbalanced traffic
leaves quota unused: with 3 replicas and all traffic hitting one of them, that
replica is capped at a third of the fleet limit.

Use it when overshooting the limit is worse than under-using it. Leave
`rate_limit_replicas = 1` (the default) when the limit is merely protective —
the behaviour is then bit-for-bit unchanged.

The margin absorbs what division cannot: rounding up on small shares, a replica
restarting with a full bucket, or a scale-up landing before the config catches
up. A share never floors to zero, because a fleet larger than its own limit
would otherwise reject **all** traffic — the limiter becoming the outage it
exists to prevent.

### Checking what is actually enforced

`/health` reports the limiter's scope, because a per-replica limit and a
fleet-wide one are indistinguishable from a response — both just answer `200`:

```json
{
  "rate_limit": {
    "enabled": true,
    "scope": "fleet",
    "rps": 30,
    "burst": 30,
    "effective_rps_this_replica": 9,
    "replicas": 3,
    "margin_percent": 10,
    "keyed_by": "tenant",
    "client_overrides": 0
  }
}
```

`scope` says which guarantee you have. `fleet` means `rps` is a real ceiling
because each replica enforces `effective_rps_this_replica`. `per_replica` means
the fleet can reach `replicas × rps`. This matters: LiteLLM's Redis-backed limiter silently degrades
a configured global limit into a per-pod one when Redis errors
([BerriAI/litellm#35533](https://github.com/BerriAI/litellm/issues/35533)), so
the deployment cannot tell which guarantee it has. grob has no shared store to
lose, but states the scope so the number can be reasoned about.

The circuit breaker opens after 5 consecutive failures (30s timeout, 3 successes to close). When open, requests skip the provider and fall through to the next mapping.

When `adaptive_scoring = true`, Grob ranks providers by a composite score (success rate, latency, recency) and computes `declared_priority / adaptive_factor` before the fallback loop. A degraded provider can move behind a lower-priority healthy provider. Scores are in-memory and decay over time to prevent stale rankings.

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
enabled = true           # Enable DLP scanning (default: false)
scan_input = true        # Scan outgoing requests for secrets/PII (default: true)
scan_output = true       # Scan incoming responses for secrets/PII (default: true)
no_builtins = false      # Disable all 25 built-in secret rules (default: false)
rules_file = ""          # Path to external TOML rules file (optional)
enable_sessions = false  # Per-API-key DLP isolation (default: false)

[[dlp.secrets]]
name = "internal_token"
prefix = "itk_"
pattern = "itk_[A-Za-z0-9]{40}"
action = "canary"        # canary | redact | log

[[dlp.names]]
term = "Thales"
action = "pseudonym"     # pseudonym | redact | log

[dlp.pii]
credit_cards = true      # Luhn-validated (default: true)
iban = true              # mod-97 validated (default: true)
bic = false              # BIC/SWIFT codes (default: false)
action = "redact"        # redact | log

[dlp.entropy]
enabled = false          # SPRT entropy scanner (default: false)
action = "log"           # log | alert

[dlp.url_exfil]
enabled = false          # URL exfiltration detector (default: false)
action = "log"           # redact | log | block
whitelist_domains = []
blacklist_domains = []
domain_match_mode = "suffix"  # exact | suffix | glob

[dlp.prompt_injection]
enabled = false          # Prompt injection detector (default: false)
action = "log"           # redact | log | block
languages = ["all"]      # 28 languages supported

[dlp.signed_config]
enabled = false          # Hot-reload signed config (default: false)
source = ""              # File path or HTTPS URL
poll_interval = "1h"
verify_signature = false
```

DLP scanning uses prefix-gated DFA matching with Aho-Corasick pre-filtering for O(n) performance. 25 built-in rules cover AWS keys, API tokens, private keys, database URIs, and more. See the [DLP Reference](dlp.md) for the complete configuration guide.

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
enabled = false                    # Enable EU AI Act control features
transparency_headers = false       # Add X-AI-Provider, X-AI-Model, X-AI-Generated headers
audit_model_name = false           # Record model name in audit entries (Article 12)
audit_token_counts = false         # Record token counts in audit entries (Article 12)
risk_classification = false        # Enable risk classification (Article 14)
escalation_threshold = "high"      # Minimum risk level to escalate: low, medium, high, critical
escalation_webhook = ""            # Webhook URL for risk escalation notifications
```

The `eu-ai-act` preset enables all compliance features. See [ADR-0005](../decisions/0005-anthropic-native-provider-trait.md) for the Anthropic-native design that enables transparent model attribution.

## MCP (Tool Matrix)

```toml
[mcp]
enabled = false                    # Enable MCP tool matrix
matrix_path = "~/.grob/matrix.toml" # Path to tool capability catalogue
```

The MCP tool matrix is a static TOML catalogue of tools with per-provider reliability scores. A bench engine continuously tests tool-calling capabilities. The `/mcp` endpoint exposes a JSON-RPC interface for querying, benchmarking, and calibrating tool scores.

## Policies

Define per-tenant, per-zone, or per-compliance-framework policy overrides. Policies match requests using glob patterns and apply DLP, rate limit, budget, and log export settings.

```toml
[[policies]]
name = "hospital-eu"

[policies.match]
tenant = "hospital-*"
zone = "eu-*"
compliance = ["gdpr"]

[policies.dlp]
secrets = "block"

[policies.rate_limit]
rps = 50

[policies.budget]
monthly_usd = 500.0

[policies.log_export]
content = "encrypted"
recipients = ["rssi", "dpo"]
```

Multiple `[[policies]]` entries are evaluated in order; the first match wins. Unset fields inherit from the global config.

## Log Export

```toml
[log_export]
content = "encrypted"

[log_export.auditors]
rssi = "age1..."
dpo = "age1..."
```

When `content = "encrypted"`, audit log entries are sealed with age envelope encryption. Each recipient listed in `[log_export.auditors]` receives an age X25519 public key. Only holders of the corresponding private key can decrypt their share of the audit export.

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

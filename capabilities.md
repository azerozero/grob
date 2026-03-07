# Grob Capabilities

> Complete inventory of features and technical capabilities.

## Core Pipeline

### Multi-Provider Dispatch

Seven sequential steps on every request: DLP input scan, MCP tool calibration, cache key computation, routing, cache lookup, fan-out check, provider loop with retry.

- **Provider loop**: re-sorts mappings by adaptive scorer, checks circuit breaker + budget, retries with exponential backoff on retryable errors
- **Streaming**: raw provider bytes → DLP stream → Tap stream (chained wrappers)
- **Continuation injection**: optional per-mapping prompt injection after tool results (for models that stop prematurely)

### Request Routing

Priority-ordered classification (highest to lowest):

| Priority | Route Type | Trigger |
|----------|-----------|---------|
| 1 | WebSearch | Tool name starts with `web_search` |
| 2 | Background | Model matches `background_regex` (default: `(?i)claude.*haiku`) |
| 3 | Subagent | `GROB-SUBAGENT-MODEL` tag in system prompt |
| 4 | PromptRule | User-defined regex on prompt text with capture groups (`$1`, `$name`) |
| 5 | Think | `thinking.type == "enabled"` in request |
| 6 | Default | Model matches `auto_map_regex` (default: `^claude-`) |

- Turn-aware: prompt rules only fire on first message of a turn
- Dynamic model via capture group substitution in prompt rules
- `strip_match: true` removes matched text from the prompt

### Fan-Out (Multi-Provider Racing)

Send the same request to N providers in parallel, configurable per model:

| Mode | Algorithm |
|------|-----------|
| `fastest` | `select_all` race; first success wins, others cancelled |
| `best_quality` | `join_all` + LLM judge (configurable model and criteria) |
| `weighted` | `join_all` + score = `output_tokens / (1 + latency_ms/1000)` |

`fan_out.count` limits how many mappings participate.

### Response Cache

- Caches only deterministic requests (temperature=0 or absent)
- Key: SHA-256 of `tenant_id | model | messages | system | tools | max_tokens` (zero-copy serde into digest)
- Per-tenant isolation via key prefixing
- Synthesizes full SSE sequences from cached JSON (both Anthropic and OpenAI formats)
- Config: `max_capacity` (default 2000), `ttl_secs` (default 3600), `max_entry_bytes` (default 2 MiB)

## Providers

### Supported Provider Types

| Provider | Type | Auth | Protocol |
|----------|------|------|----------|
| Anthropic | `anthropic` | API key, OAuth PKCE | Anthropic Messages API |
| OpenAI | `openai` | API key | OpenAI Chat Completions |
| Gemini | `gemini` | API key, OAuth CodeAssist, Vertex AI ADC | Gemini generateContent |
| Vertex AI | `vertex-ai` | OAuth ADC | Vertex AI |
| OpenRouter | `openrouter` | API key | Anthropic-compatible |
| z.ai | `z.ai` | API key | Anthropic-compatible |
| MiniMax | `minimax` | API key | Anthropic-compatible |
| Kimi Coding | `kimi-coding` | API key | Anthropic-compatible |
| Mistral | `openai` + base_url | API key | OpenAI-compatible |
| Ollama | `openai` + base_url | none | OpenAI-compatible |
| Groq | `openai` + base_url | API key | OpenAI-compatible |
| DeepSeek | `openai` + base_url | API key | OpenAI-compatible |
| Together | `openai` + base_url | API key | OpenAI-compatible |

Any OpenAI-compatible API works with `provider_type = "openai"` and a custom `base_url`.

### Provider Features

- **Rate-limit header forwarding**: 12 Anthropic `anthropic-ratelimit-*` headers passed through
- **Auto-retry on signature error**: strips thinking signatures and resends
- **Gemini rate-limit retry**: 3 retries with `Retry-After` header parsing (supports `Xs` and `Xms`)
- **Connection warmup**: fire-and-forget HEAD requests on startup to pre-warm TLS
- **HTTP/2 adaptive window**: `pool_max_idle=20`, `pool_idle_timeout=90s`
- **Custom headers**: arbitrary per-provider HTTP headers via config
- **Per-provider budget**: independent monthly USD limit per provider

## API Compatibility

### Dual Endpoint

| Endpoint | Format | Streaming | Tool Calling |
|----------|--------|-----------|-------------|
| `/v1/messages` | Anthropic | SSE | Yes |
| `/v1/chat/completions` | OpenAI | SSE | Yes |
| `/v1/models` | OpenAI | N/A | N/A |
| `/v1/messages/count_tokens` | Anthropic | N/A | N/A |

### OpenAI ↔ Anthropic Translation

Bidirectional: system message extraction, tool_calls ↔ tool_use blocks, image URL ↔ base64 source, usage format mapping, streaming SSE event translation on-the-fly.

## Security

### DLP (Data Loss Prevention)

Feature-gated: `dlp`. Eight detection engines:

| Engine | What it detects | Actions |
|--------|----------------|---------|
| SecretScanner | API keys, tokens, credentials (prefix-byte O(1) pre-filter) | Canary, Redact, Log |
| NameAnonymizer | Configured names (HMAC-derived consistent pseudonyms) | Pseudonymize, Redact |
| CanaryGenerator | Replaces secrets with same-length/family fakes | (internal) |
| SprtDetector | High-entropy content (Shannon entropy + SPRT) | Alert |
| PiiScanner | Credit cards (Luhn), IBAN (ISO 7064 mod97), BIC | Redact, Warn, Block |
| UrlExfilScanner | EchoLeak URLs, data URIs, base64 path exfiltration | Block, Warn |
| InjectionDetector | Prompt injection in 28 languages with anti-obfuscation | Block, Log |
| SignedHotConfig | Hot-reload domain lists + patterns (ECDSA P-256 verified) | (config) |

Pipeline: request → injection check (blocks) → name → secret → PII → response → de-anonymize → secret → PII → URL exfil → end-of-stream cross-chunk detection.

Anti-obfuscation: NFKC normalization, 20 zero-width Unicode chars stripped, Cyrillic/Greek/fullwidth/math → ASCII, leet speak decoding, homoglyph mapping. Moka cache (2048 entries, 5 min TTL) for performance.

### Circuit Breakers

Per-provider with three states: Closed → Open → HalfOpen. Config: `failure_threshold=5`, `success_threshold=3`, `timeout=30s`, `half_open_max_calls=3`.

### Adaptive Provider Scoring

Composite score = `success_rate × latency_factor × confidence`:
- EWMA latency smoothing (alpha=0.3)
- Latency factor: `1 / (1 + ewma_ms / 1000)`
- Confidence decay: `(1 - 0.001 × idle_secs).max(0.3)`
- Circuit breaker integration: Open → 0.0, HalfOpen → capped at 0.1
- Re-sorts provider mappings by `priority / adaptive_factor`

### Rate Limiting

Token bucket algorithm per tenant/IP. Config: `rate_limit_rps` (default 100), `rate_limit_burst` (default 200). Returns 429 + `Retry-After` header. Background cleanup of stale buckets every 5 min.

### Signed Audit Log

Append-only JSONL with hash chain (SHA-256, genesis = `SHA256("GROB_AUDIT_GENESIS")`). Two signing algorithms: ECDSA P-256 or HMAC-SHA256. EU AI Act Article 12 fields: model_name, token counts, risk_level. Events: REQUEST, RESPONSE, DLP_BLOCK, DLP_WARN, AUTH, CONFIG_CHANGE, ERROR. Feature-gated: `compliance`.

### Risk Assessment (EU AI Act Article 14)

Automatic classification: injection or (blocked+PII) → Critical; blocked → High; PII or >2 rules → Medium; else Low. Optional webhook escalation when risk ≥ configurable threshold.

### Security Headers

OWASP headers on all responses: HSTS, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Referrer-Policy, Permissions-Policy, Cache-Control: no-store.

### JWT Validation

HMAC-SHA256 and RS256 (JWKS). JWKS background refresh (default 3600s). SHA-256(token) cache (5 min TTL, 10K capacity). Tenant extraction from JWT claims.

## MCP Tool Matrix

Feature-gated: `mcp`. Evaluates which providers handle which tools best.

- **Tool catalogue**: TOML-defined tools with per-provider static reliability scores
- **Score blending**: 40% static + 60% runtime bench results
- **6 metrics**: ToolSelectionAccuracy (0.25), ParamValidity (0.20), ParamCompliance (0.20), ToolChoiceRespect (0.15), ParallelToolSupport (0.10), ToolResultHandling (0.10)
- **Calibration**: filters tools below `min_score` threshold before dispatch
- **Bench engine**: background task testing all (tool, provider) pairs with semaphore concurrency
- **JSON-RPC server**: `/mcp` endpoint, `/api/tool-matrix` report

## Spend Tracking

- Persistent monthly tracking per provider and model (redb or legacy JSON)
- Three-tier budget enforcement: model → provider → global (0.0 = unlimited)
- Warning at configurable percentage (default 80%)
- Subscription detection: OAuth providers → cost=0.0
- Live pricing: fetches from openrouter.ai/api/v1/models, merges with static fallbacks, refreshes every 24h
- Tenant-scoped spend isolation

## Webhook Tap

Feature-gated: `tap`. Streams request bodies + SSE chunks to a webhook URL in real-time. Accumulates chunks per request, assembles full body on stream end, POSTs to configured URL. Config: `webhook_url`, `buffer_size` (default 256), `timeout_ms` (default 5000).

## Record & Replay Harness

Feature-gated: `harness`. HTTP-level recording and replay for sandwich testing.

- **TapeRecorderLayer**: Axum middleware capturing raw HTTP exchanges as JSONL (format-agnostic: works with both Anthropic and OpenAI)
- **MockBackend**: fake provider server with fingerprint matching, configurable latency and error injection (503/429)
- **Driver**: traffic generator with semaphore concurrency, QPS throttling, duration limit
- **Report**: latency percentiles (p50/p90/p95/p99), throughput, error breakdown

## Presets

Seven built-in presets compiled into the binary:

| Preset | Focus | Providers |
|--------|-------|-----------|
| `perf` | Maximum performance | Anthropic + OpenAI + Gemini |
| `medium` | Quality/price balance | Anthropic thinking + OpenRouter |
| `cheap` | Minimum cost | GLM-5 + DeepSeek + Gemini Flash |
| `local` | Local-first | Ollama + Anthropic thinking |
| `fast` | Premium speed | Opus + GPT-5.2 + Gemini Pro |
| `gdpr` | EU data sovereignty | Mistral, Scaleway, OVH (region=eu) |
| `eu-ai-act` | EU AI Act compliance | EU providers + transparency + risk |

Operations: apply (with backup), export (strips secrets), install from git/path, sync from remote, interactive credential wizard.

## Authentication

### OAuth PKCE

Custom implementation (no `oauth2` crate). Three provider configs:
- **Anthropic**: JSON body exchange, public PKCE app
- **OpenAI Codex**: form-encoded, hardcoded redirect
- **Gemini CodeAssist**: form-encoded + client_secret, `loadCodeAssist` API for project_id

### Token Store

Persistent OAuth tokens in redb (or legacy JSON). `SecretString` for credential safety. Auto-refresh when token expires within 5 minutes. File permissions: 0o600 on Unix.

### API Key Auth

Constant-time comparison (subtle crate) against configured key. Supports Bearer token or `x-api-key` header.

## Infrastructure

### TLS + ACME

Native HTTPS via rustls (no OpenSSL). Optional Let's Encrypt auto-certificates with TLS-ALPN-01 challenge on the main port. Background certificate renewal. Feature-gated: `tls`, `acme`.

### Zero-Downtime Upgrades

`SO_REUSEPORT` allows old and new processes to coexist on the same port. New process binds → health check passes → old process receives SIGUSR1 → graceful drain (30s timeout).

### Runtime Config Reload

`POST /api/config/reload` atomically swaps `ReloadableState` (config + router + provider registry) via `RwLock<Arc<...>>`. In-flight requests continue on old snapshot. Background validation after swap.

### Process Management

PID file at `~/.grob/grob.pid` with atomic write (tmp → rename). PID reuse detection on Linux via `/proc/{pid}/cmdline`. Health-based instance detection (HTTP /health, 500ms timeout).

### Prometheus Metrics

`/metrics` endpoint with counters and gauges: active requests, spend, budget, provider scores, latency EWMA, success rates, cache hits/misses, DLP detections, risk escalations, rate limit rejections, circuit breaker states.

### Per-Project Config Overlay

`.grob.toml` in CWD (or parent directories up to home). Overlays router, budget, and preset settings. Project rules prepended (higher priority).

### EU AI Act Compliance

Transparency headers: `x-ai-provider`, `x-ai-model`, `x-grob-audit-id`, `x-ai-generated: true`. Risk classification (Article 14). Audit logging with token counts (Article 12). Feature-gated: `compliance`.

### Container Support

Minimal `FROM scratch` image (~6 MiB). Container mode: `grob run` binds 0.0.0.0, JSON structured logs, graceful SIGTERM shutdown, no PID file. Bundled TLS certificates via rustls.

### Allocator

tikv-jemallocator replaces musl's malloc for ~20% better throughput on Linux.

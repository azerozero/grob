# Grob Architecture

Grob is a multi-provider LLM routing proxy written in Rust. It accepts requests in both Anthropic and OpenAI formats, routes them to the best available provider, and returns responses with streaming support.

## Request flow

```
Client (Claude Code, Aider, curl, ...)
  |
  |  POST /v1/messages           (Anthropic native)
  |  POST /v1/chat/completions   (OpenAI compat)
  v
+------------------------------------------------------------------+
|                        Axum HTTP Server                          |
|                                                                  |
|  Middleware chain (applied outermost-first):                     |
|                                                                  |
|  1. Request ID                                                   |
|     Reads X-Request-Id or generates UUID v4.                     |
|     Echoed back in response header.                              |
|                                                                  |
|  2. Body Size Limit                                              |
|     Rejects payloads over max_body_size (default 10 MB).         |
|                                                                  |
|  3. Security Headers                                             |
|     Applies OWASP response headers (X-Content-Type-Options,      |
|     X-Frame-Options, Strict-Transport-Security, etc).            |
|                                                                  |
|  4. Rate Limiter                                                 |
|     Token-bucket per tenant/API-key/IP.                          |
|     Returns 429 + Retry-After when exceeded.                     |
|                                                                  |
|  5. Auth                                                         |
|     Three modes: none, api_key, jwt.                             |
|     Skips health/metrics/oauth paths.                            |
|                                                                  |
+------------------------------------------------------------------+
  |
  v
+------------------------------------------------------------------+
|                          Handler                                 |
|                                                                  |
|  - Parses request body (Anthropic or OpenAI format)              |
|  - Checks budget (global, per-provider, per-model)               |
|  - Increments active_requests gauge                              |
|  - OpenAI requests are translated to Anthropic internal format   |
|                                                                  |
+------------------------------------------------------------------+
  |
  v
+------------------------------------------------------------------+
|                          Router                                  |
|                                                                  |
|  Determines route type and target model:                         |
|                                                                  |
|  1. Prompt rules     -- regex match on user message content      |
|  2. Auto-map regex   -- maps known model families (e.g. claude-) |
|  3. Task classifier  -- thinking / web_search / background       |
|  4. Default model    -- fallback from [router] config            |
|                                                                  |
|  Output: RouteDecision { model, route_type, provider_mappings }  |
|                                                                  |
+------------------------------------------------------------------+
  |
  v
+------------------------------------------------------------------+
|                    Provider Dispatch                              |
|                                                                  |
|  For each mapping (ordered by priority):                         |
|                                                                  |
|  1. Circuit Breaker check                                        |
|     - Closed:   allow request                                    |
|     - Open:     skip provider, try next (fail-fast)              |
|     - HalfOpen: allow limited probe requests                     |
|                                                                  |
|  2. Provider call                                                |
|     - Anthropic (native passthrough)                             |
|     - OpenAI (translate to OpenAI API format)                    |
|     - Gemini (translate to Gemini API format)                    |
|     - DeepSeek, Ollama, OpenRouter, etc.                         |
|                                                                  |
|  3. On success: record_success on circuit breaker                |
|     On failure: record_failure, try next mapping (fallback)      |
|                                                                  |
|  Strategy modes:                                                 |
|  - fallback: sequential by priority (default)                    |
|  - fan_out:  parallel dispatch, return fastest/best              |
|                                                                  |
+------------------------------------------------------------------+
  |
  v
+------------------------------------------------------------------+
|                     DLP (Data Loss Prevention)                   |
|                                                                  |
|  If enabled, scans response stream for:                          |
|  - Secret patterns (25 builtin rules: AWS keys, tokens, etc.)   |
|  - PII (names, emails, phone numbers)                            |
|  - Canary tokens (watermarks for leak detection)                 |
|                                                                  |
|  Uses Aho-Corasick DFA for O(n) scanning of streaming chunks.   |
|                                                                  |
+------------------------------------------------------------------+
  |
  v
+------------------------------------------------------------------+
|                        Response                                  |
|                                                                  |
|  - Stream SSE events back to client (or buffer for non-stream)  |
|  - Record metrics (latency, tokens, cost, status)                |
|  - Update spend tracker (persistent in redb)                     |
|  - Emit webhook tap event (if configured)                        |
|  - Write audit log entry (if configured)                         |
|                                                                  |
+------------------------------------------------------------------+
  |
  v
Client
```

## Module layout

| Module | Path | Purpose |
|--------|------|---------|
| `server` | `src/server/mod.rs` | Axum HTTP server, middleware stack, request handlers |
| `server::openai_compat` | `src/server/openai_compat.rs` | OpenAI `/v1/chat/completions` request/response translation |
| `server::oauth_handlers` | `src/server/oauth_handlers.rs` | OAuth authorization, token exchange, callback endpoints |
| `server::fan_out` | `src/server/fan_out.rs` | Parallel multi-provider dispatch (fan-out strategy) |
| `providers` | `src/providers/mod.rs` | Provider trait and registry |
| `providers::anthropic_compatible` | `src/providers/anthropic_compatible.rs` | Anthropic API provider (native passthrough) |
| `providers::openai` | `src/providers/openai.rs` | OpenAI API provider |
| `providers::gemini` | `src/providers/gemini.rs` | Gemini API provider |
| `providers::streaming` | `src/providers/streaming.rs` | SSE stream parsing and forwarding |
| `providers::registry` | `src/providers/registry.rs` | Provider registration and model lookup |
| `router` | `src/router/mod.rs` | Request routing engine (regex rules, task classification) |
| `cli` | `src/cli/mod.rs` | Config structs (AppConfig, ServerConfig, etc.) and CLI parsing |
| `preset` | `src/preset.rs` | Preset management (list, apply, export, sync, validate) |
| `auth` | `src/auth/mod.rs` | Auth module aggregator |
| `auth::oauth` | `src/auth/oauth.rs` | OAuth client with PKCE |
| `auth::token_store` | `src/auth/token_store.rs` | Persistent OAuth token storage (redb-backed) |
| `auth::jwt` | `src/auth/jwt.rs` | JWT validation and JWKS refresh |
| `features::token_pricing` | `src/features/token_pricing/mod.rs` | Token counting and dynamic pricing table |
| `features::token_pricing::spend` | `src/features/token_pricing/spend.rs` | Persistent monthly spend tracking and budget enforcement |
| `features::dlp` | `src/features/dlp/mod.rs` | DLP engine (secret scanning, PII detection) |
| `features::dlp::builtins` | `src/features/dlp/builtins.rs` | 25 builtin secret detection rules |
| `features::dlp::pii` | `src/features/dlp/pii.rs` | PII scanner (names, emails, phones) |
| `features::dlp::canary` | `src/features/dlp/canary.rs` | Canary token injection and detection |
| `features::dlp::dfa` | `src/features/dlp/dfa.rs` | Aho-Corasick DFA for stream scanning |
| `features::dlp::stream` | `src/features/dlp/stream.rs` | DLP-aware SSE stream wrapper |
| `features::dlp::session` | `src/features/dlp/session.rs` | Per-session DLP state management |
| `features::tap` | `src/features/tap/mod.rs` | Webhook tap (event emission to external URL) |
| `security` | `src/security/mod.rs` | Security module aggregator |
| `security::circuit_breaker` | `src/security/circuit_breaker.rs` | Circuit breaker pattern (Closed/Open/HalfOpen) |
| `security::rate_limit` | `src/security/rate_limit.rs` | Token-bucket rate limiter per tenant/IP |
| `security::headers` | `src/security/headers.rs` | OWASP security response headers |
| `security::audit_log` | `src/security/audit_log.rs` | Signed audit log with ECDSA P-256 |
| `security::cache` | `src/security/cache.rs` | Response caching (moka) |
| `security::encryption` | `src/security/encryption.rs` | AES-256-GCM encryption for sensitive data |
| `security::schema_validate` | `src/security/schema_validate.rs` | Request schema validation |
| `storage` | `src/storage/mod.rs` | Embedded key-value store (redb) |
| `storage::migrate` | `src/storage/migrate.rs` | Storage migrations |
| `models` | `src/models/mod.rs` | Anthropic request/response types, route types |
| `message_tracing` | `src/message_tracing/mod.rs` | Request/response trace logging (JSONL) |
| `pid` | `src/pid.rs` | PID file management for daemon mode |
| `instance` | `src/instance.rs` | Multi-instance coordination |

## Key design decisions

**Config is static at runtime.** The server loads TOML config on startup. The `/api/config/reload` endpoint atomically swaps the in-memory config (router, provider registry, model index) without restarting the process. In-flight requests continue using the old config snapshot.

**Provider abstraction.** All providers implement the same trait. The proxy normalizes everything to Anthropic's internal message format, then translates outbound to each provider's wire format.

**Fallback with circuit breakers.** Each model maps to one or more providers ordered by priority. If the highest-priority provider fails, the request automatically falls through to the next. Circuit breakers (5 failures = open, 30s timeout, 3 successes to close) prevent repeated calls to degraded providers.

**Streaming-first.** Both SSE streaming and buffered responses are supported. DLP scanning operates on stream chunks using Aho-Corasick automata, so no full-response buffering is needed.

**Persistent state in redb.** OAuth tokens, monthly spend, and storage data are kept in an embedded redb database at `~/.grob/grob.db`. This survives restarts without requiring an external database.

**Security middleware stack.** All security features are toggled via the `[security]` TOML section: `rate_limit_rps`, `rate_limit_burst`, `max_body_size`, `security_headers`, `circuit_breaker`, `audit_dir`. Set `enabled = false` to disable the entire security layer. Each request gets a `X-Request-Id` (UUID v4 if not provided) for tracing across logs.

**jemalloc allocator.** On non-MSVC targets, jemalloc replaces the system allocator for roughly 20% better throughput under load.

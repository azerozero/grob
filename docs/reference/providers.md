# Provider Reference

Reference documentation for the `src/providers/` module. Covers the provider trait, all backend implementations, format translation, streaming, and error handling.

## Provider Trait (`LlmProvider`)

All providers implement the `LlmProvider` trait, defined in `src/providers/mod.rs`. The trait enforces Anthropic Messages API compatibility as the canonical internal format.

| Method | Signature | Purpose |
|--------|-----------|---------|
| `send_message` | `async fn(CanonicalRequest) -> Result<ProviderResponse, ProviderError>` | Non-streaming request |
| `send_message_stream` | `async fn(CanonicalRequest) -> Result<StreamResponse, ProviderError>` | Streaming request (SSE) |
| `count_tokens` | `async fn(CountTokensRequest) -> Result<CountTokensResponse, ProviderError>` | Token counting (provider-specific or heuristic) |
| `supports_model` | `fn(&str) -> bool` | Check if provider serves a given model name |
| `base_url` | `fn() -> Option<&str>` | Return base URL for TLS connection warmup (default: `None`) |

## Provider Implementations

### AnthropicCompatibleProvider

**File**: `src/providers/anthropic_compatible.rs`
**Provider types**: `anthropic`, `z.ai`, `minimax`, `zenmux`, `kimi-coding`

Sends requests natively in Anthropic Messages API format. No format translation needed.

**Capabilities**:
- Native `count_tokens` endpoint (Anthropic backend only; others fall back to character heuristic)
- Automatic thinking block signature sanitization (strips non-Anthropic signatures before sending, retries on signature errors)
- Tool use ID normalization (`^[a-zA-Z0-9_-]+` pattern requirement)
- Anthropic rate-limit header forwarding and Prometheus metrics emission
- Anthropic beta feature merging (server defaults + client-provided, deduplicated)

**Authentication**:
- API key via `x-api-key` header
- OAuth via `Authorization: Bearer` header (auto-refresh on token expiry)

**Request sanitization** (`src/providers/anthropic_sanitize.rs`):

| Function | Trigger | Action |
|----------|---------|--------|
| `strip_non_anthropic_thinking` | Proactive, every request to Anthropic backends | Removes thinking blocks with signatures that fail Anthropic heuristic (< 100 chars or not valid base64) |
| `strip_all_thinking_signatures` | Fallback, on signature error from Anthropic | Removes all `signature` fields from thinking blocks, converting to unsigned |
| `sanitize_tool_use_ids` | Every request to Anthropic backends | Replaces non-alphanumeric characters (except `_`, `-`) with `_` |

### OpenAIProvider

**File**: `src/providers/openai/mod.rs`
**Provider types**: `openai`, `openrouter`

Translates between Anthropic canonical format and OpenAI Chat Completions API. Also supports the Responses API for Codex models.

**Request transformation** (`src/providers/openai/transform.rs`):

| Anthropic concept | OpenAI equivalent |
|-------------------|-------------------|
| `system` | System role message |
| `tool_use` blocks | `tool_calls` array on assistant messages |
| `tool_result` blocks | Separate `tool` role messages |
| `image` blocks | `image_url` content parts (data URI) |
| `thinking` blocks | Dropped (no OpenAI equivalent) |
| `tool_choice.any` | `tool_choice: "required"` |
| `tool_choice.tool` | `tool_choice: { type: "function", function: { name } }` |
| `stop_reason: end_turn` | `finish_reason: stop` |
| `stop_reason: max_tokens` | `finish_reason: length` |
| `stop_reason: tool_use` | `finish_reason: tool_calls` |

**Extension fields**: OpenAI-specific fields (`response_format`, `reasoning_effort`, `seed`, `frequency_penalty`, `presence_penalty`, `parallel_tool_calls`, `user`, `logprobs`, `top_logprobs`, `service_tier`) are preserved in `RequestExtensions` and restored on the outbound request.

**Streaming** (`src/providers/openai/streaming.rs`):
Converts OpenAI SSE chunks to Anthropic SSE format using stateful `StreamTransformState`. Key mappings:
- First chunk triggers `message_start`
- `delta.reasoning` produces `thinking` content blocks
- `delta.content` produces `text` content blocks
- `delta.tool_calls` produces `content_block_start` (tool_use) + `input_json_delta`
- `finish_reason` produces `content_block_stop` + `message_delta` + `message_stop`

**Codex models**: Detected via model name containing "codex". Uses `/v1/responses` endpoint (or `/codex/responses` for OAuth). System prompt injected from `src/providers/openai/codex_instructions.md` (verbatim Codex CLI prompt, embedded via `include_str!`).

**OpenRouter**: Uses `openai` provider type with custom headers (`HTTP-Referer`, `X-Title`).

### GeminiProvider

**File**: `src/providers/gemini/mod.rs`
**Provider types**: `gemini`, `vertex-ai`

Translates between Anthropic canonical format and Google Gemini API. Does **not** use `ProviderBase` due to fundamentally different auth model.

**Three authentication modes**:

| Mode | Base URL | Auth mechanism |
|------|----------|----------------|
| API key (AI Studio) | `generativelanguage.googleapis.com/v1beta` | `?key=` query parameter |
| OAuth (Code Assist) | `cloudcode-pa.googleapis.com/v1internal` | `Authorization: Bearer` |
| Vertex AI | `{location}-aiplatform.googleapis.com/v1` | Application Default Credentials |

**Request transformation** (`src/providers/gemini/transform.rs`):

| Anthropic concept | Gemini equivalent |
|-------------------|-------------------|
| `system` | `system_instruction` |
| `user` / `assistant` roles | `user` / `model` roles |
| `tool_use` blocks | `functionCall` parts |
| `tool_result` blocks | `functionResponse` parts |
| `image` blocks | `inlineData` parts |
| `thinking` blocks | `text` parts (plain text) |
| `WebSearch` tool | `googleSearch` tool type |
| `WebFetch` tool | `urlContext` tool type |
| `tool_choice.auto` | `functionCallingConfig.mode: AUTO` |
| `tool_choice.any` | `functionCallingConfig.mode: ANY` |
| `tool_choice.tool` | `functionCallingConfig.mode: ANY` + `allowed_function_names` |

**Rate-limit retry** (`src/providers/gemini/retry.rs`):
- Parses Google duration format (`"3.020s"`, `"900ms"`)
- Extracts `retryDelay` from `RetryInfo` error details
- Extracts `quotaResetDelay` from `RATE_LIMIT_EXCEEDED` `ErrorInfo` metadata
- Up to 3 retries on 429 errors

**Tool support**: Models containing "lite" or "flash-lite" in their name have tools disabled.

**JSON schema cleaning**: Removes JSON Schema metadata fields (`$schema`, `$id`, `$ref`, `$comment`, `definitions`, `$defs`, `exclusiveMinimum`, `exclusiveMaximum`) that Gemini API rejects.

## Shared Infrastructure

### ProviderBase

**File**: `src/providers/base.rs`

Eliminates field and method duplication across providers. Embedded in `AnthropicCompatibleProvider` and `OpenAIProvider` (not `GeminiProvider`).

| Method | Purpose |
|--------|---------|
| `new(ProviderParams, headers)` | Constructs base with HTTP client |
| `is_oauth()` | Checks if OAuth is configured |
| `supports_model(model)` | Case-insensitive model match or pass-through |
| `resolve_auth(config_fn)` | Resolves OAuth token (with refresh) or API key fallback |
| `apply_headers(builder)` | Appends custom headers to request |

### ProviderRegistry

**File**: `src/providers/registry.rs`

Central registry mapping provider names to `Arc<dyn LlmProvider>` instances and model names to provider names.

| Method | Purpose |
|--------|---------|
| `from_configs_with_models` | Builds registry from TOML config |
| `provider(name)` | Lookup provider by name |
| `provider_for_model(model)` | Lookup provider by model (direct mapping, then scan) |
| `list_models()` | All configured model names |
| `list_providers()` | All configured provider names |
| `warmup_connections()` | Fire-and-forget HEAD requests for TLS pre-warming |

**Provider creation dispatch** (in `create_provider`):

| `provider_type` | Provider class | Default base URL |
|-----------------|----------------|------------------|
| `openai` | `OpenAIProvider` | `https://api.openai.com/v1` |
| `openrouter` | `OpenAIProvider` | `https://openrouter.ai/api/v1` |
| `anthropic` | `AnthropicCompatibleProvider` | `https://api.anthropic.com` |
| `z.ai` | `AnthropicCompatibleProvider` | `https://api.z.ai/api/anthropic` |
| `openai` (with `base_url = api.z.ai/api/paas/v4`) | `OpenAIProvider` | (config-supplied) |
| `minimax` | `AnthropicCompatibleProvider` | `https://api.minimax.io/anthropic` |
| `zenmux` | `AnthropicCompatibleProvider` | `https://zenmux.ai/api/anthropic` |
| `kimi-coding` | `AnthropicCompatibleProvider` | `https://api.kimi.com/coding` |
| `gemini` | `GeminiProvider` | (varies by auth mode) |
| `vertex-ai` | `GeminiProvider` | (varies by location) |

### Streaming

**File**: `src/providers/streaming.rs`

Two stream adapters:

- **`SseStream<S>`**: Parses raw byte stream into `SseEvent` structs. Buffers bytes until `"\n\n"` delimiter found, handles partial chunks from HTTP chunked transfer.
- **`LoggingSseStream<S>`**: Wraps any byte stream to track usage metrics (input/output tokens, cache hit rate, TTFT) and emit Prometheus counters + histograms on stream end.

### Auth Resolution

**File**: `src/providers/auth.rs`

Shared `resolve_access_token` function used by all providers:
1. If OAuth configured: retrieve token from `TokenStore`, refresh if expired, return access token
2. If no OAuth: return API key as-is

### Token Estimation

**File**: `src/providers/helpers.rs`

Character-based heuristic (`total_chars / 4`) used by all providers except Anthropic (which has a native `count_tokens` endpoint). Counts text from system prompt, message text, tool results, and thinking blocks.

### Constants

**File**: `src/providers/constants.rs`

| Constant | Value | Purpose |
|----------|-------|---------|
| `ANTHROPIC_API_VERSION` | `"2023-06-01"` | `anthropic-version` header |
| `ANTHROPIC_BETA_FEATURES` | (comma-separated list) | `anthropic-beta` header defaults |
| `ANTHROPIC_DOMAIN` | `"anthropic.com"` | Backend detection heuristic |
| `MIN_ANTHROPIC_SIGNATURE_LENGTH` | `100` | Thinking block signature validation |
| `RATE_LIMIT_TOKENS_LOW` | `10,000` | Token rate-limit warning threshold |
| `RATE_LIMIT_REQUESTS_LOW` | `10` | Request rate-limit warning threshold |
| `CHARS_PER_TOKEN` | `4` | Heuristic token estimation ratio |

## Error Types

**File**: `src/providers/error.rs`

`ProviderError` is a `thiserror`-derived enum:

| Variant | Cause |
|---------|-------|
| `HttpError` | `reqwest::Error` (network, timeout, TLS) |
| `SerializationError` | `serde_json::Error` (malformed request/response) |
| `ModelNotSupported` | Model not in any provider's config |
| `ApiError { status, message }` | Non-2xx HTTP response from upstream |
| `ConfigError` | Invalid provider configuration |
| `AuthError` | OAuth token missing, expired, or refresh failed |
| `NoProviderAvailable` | No provider configured for the request |
| `AllProvidersFailed` | Every provider in the fallback chain returned an error |

## Configuration Types

**File**: `src/providers/mod.rs`

### `ProviderConfig` (TOML `[[providers]]`)

| Field | Type | Default | Purpose |
|-------|------|---------|---------|
| `name` | `String` | required | Unique provider identifier |
| `provider_type` | `String` | required | Backend type (see registry table) |
| `auth_type` | `AuthType` | `apikey` | `apikey` or `oauth` |
| `api_key` | `Option<SecretString>` | `None` | API key (supports `$ENV_VAR` expansion) |
| `oauth_provider` | `Option<String>` | `None` | OAuth provider ID in TokenStore |
| `project_id` | `Option<String>` | `None` | Google Cloud project (Vertex AI only) |
| `location` | `Option<String>` | `None` | GCP region (Vertex AI only) |
| `base_url` | `Option<String>` | per-type default | Custom endpoint override |
| `headers` | `Option<HashMap>` | `None` | Custom HTTP headers |
| `models` | `Vec<String>` | required | Model identifiers (legacy field) |
| `enabled` | `Option<bool>` | `true` | Enable/disable without removing config |
| `budget_usd` | `Option<BudgetUsd>` | `None` | Per-provider monthly budget |
| `region` | `Option<String>` | `None` | GDPR region filter (`"eu"`, `"us"`, `"global"`) |
| `pass_through` | `Option<bool>` | `false` | Accept any model name |

### `ProviderResponse`

The canonical response type returned by all providers:

| Field | Type | Purpose |
|-------|------|---------|
| `id` | `String` | Unique response identifier |
| `type` | `String` | Always `"message"` |
| `role` | `String` | Always `"assistant"` |
| `content` | `Vec<ContentBlock>` | Ordered content blocks |
| `model` | `String` | Model that generated the response |
| `stop_reason` | `Option<String>` | `"end_turn"`, `"max_tokens"`, `"tool_use"` |
| `stop_sequence` | `Option<String>` | Custom stop sequence if triggered |
| `usage` | `Usage` | Token counts |

### `Usage`

| Field | Type | Purpose |
|-------|------|---------|
| `input_tokens` | `u32` | Tokens in the input prompt |
| `output_tokens` | `u32` | Tokens generated in the output |
| `cache_creation_input_tokens` | `Option<u32>` | Tokens written to prompt cache |
| `cache_read_input_tokens` | `Option<u32>` | Tokens read from prompt cache |

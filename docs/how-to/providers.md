# Provider Setup

Grob supports three categories of providers:

- **Anthropic-native** -- providers that speak the Anthropic Messages API
- **OpenAI-compatible** -- providers that speak the OpenAI Chat Completions API
- **Google** -- Gemini (AI Studio) and Vertex AI

## Use these snippets

The provider blocks below are **configuration fragments**, not standalone
config files. Add the provider you need to your existing Grob configuration,
then connect it to a named `[[models]]` entry through `[[models.mappings]]` and
select that model in `[router]`.

Keep `models = []` in each provider block: the parser requires this legacy
field, but routing uses the mappings. See the
[complete model-mapping example](../examples/models.toml) or the
[local Ollama example](../examples/ollama.toml) for a full configuration.
After editing, `grob model` checks that Grob can load the configuration and lists
its models without calling providers. `grob validate` makes real provider
requests and may incur charges. Restart or
[reload](configure.md#reload-without-restarting) an already-running proxy to
apply changes.

## Provider overview

| Provider | Type | Auth | Base URL |
|----------|------|------|----------|
| Anthropic | `anthropic` | API key / OAuth | `https://api.anthropic.com` |
| OpenAI | `openai` | API key | `https://api.openai.com/v1` |
| Gemini | `gemini` | API key / OAuth | Google AI Studio |
| Vertex AI | `vertex-ai` | ADC | Google Cloud |
| OpenRouter | `openrouter` | API key | `https://openrouter.ai/api/v1` |
| Mistral | `openai` | API key | `https://api.mistral.ai/v1` |
| DeepSeek | `openai` | API key | `https://api.deepseek.com/v1` |
| Groq | `openai` | API key | `https://api.groq.com/openai/v1` |
| Together | `openai` | API key | `https://api.together.xyz/v1` |
| Fireworks | `openai` | API key | `https://api.fireworks.ai/inference/v1` |
| Ollama | `openai` | none | `http://localhost:11434/v1` |
| z.ai (Coding Plan) | `z.ai` | API key | `https://api.z.ai/api/anthropic` (Anthropic) |
| z.ai (PAYG / free tier) | `openai` | API key | `https://api.z.ai/api/paas/v4` (OpenAI) |
| MiniMax | `minimax` | API key | Anthropic-compatible |
| Kimi Coding | `kimi-coding` | API key | Anthropic-compatible |
| Zenmux | `zenmux` | API key | Anthropic-compatible |

---

## Anthropic

Direct access to Claude models. Supports API key and OAuth (Pro/Max subscriptions).

### API key

```toml
[[providers]]
name = "anthropic"
provider_type = "anthropic"
api_key = "$ANTHROPIC_API_KEY"
models = []
```

### OAuth (Pro/Max subscription)

```toml
[[providers]]
name = "anthropic"
provider_type = "anthropic"
auth_type = "oauth"
oauth_provider = "anthropic-max"
models = []
```

On first `grob start`, a browser window opens for OAuth login. Tokens are stored as encrypted files in `~/.grob/tokens/` (AES-256-GCM) and refreshed automatically.

See [OAuth Setup](oauth-setup.md) for details.

---

## OpenRouter

Access 200+ models through a single API key. Models are referenced by their OpenRouter ID (e.g., `deepseek/deepseek-v3.2`, `mistralai/devstral-2512`).

```toml
[[providers]]
name = "openrouter"
provider_type = "openrouter"
api_key = "$OPENROUTER_API_KEY"
models = []
```

Get an API key at [openrouter.ai/keys](https://openrouter.ai/keys).

### Using models via OpenRouter

This named model tries the mappings in ascending priority order. Set your
router target to `openrouter-fallback` to use it, or add the mappings beneath
an existing model instead.

```toml
[[models]]
name = "openrouter-fallback"

[[models.mappings]]
provider = "openrouter"
actual_model = "deepseek/deepseek-v3.2"
priority = 2

[[models.mappings]]
provider = "openrouter"
actual_model = "mistralai/devstral-2512"
priority = 3
```

Browse available models at [openrouter.ai/models](https://openrouter.ai/models).

---

## Mistral / Devstral (direct API)

Use Mistral's API directly instead of going through OpenRouter. Use this path when your credentials and billing belong to Mistral directly.

```toml
[[providers]]
name = "mistral"
provider_type = "openai"
api_key = "$MISTRAL_API_KEY"
base_url = "https://api.mistral.ai/v1"
models = []
```

### Available models

| Model | Use case |
|-------|----------|
| `devstral-small-2505` | Code generation, fast |
| `devstral-2512` | Code generation, stronger |
| `codestral-latest` | Code completion |
| `mistral-large-latest` | General purpose |
| `mistral-medium-latest` | Balanced |

Get an API key at [console.mistral.ai](https://console.mistral.ai/).

---

## OpenAI

```toml
[[providers]]
name = "openai"
provider_type = "openai"
api_key = "$OPENAI_API_KEY"
models = []
```

---

## Fireworks

Fireworks exposes OpenAI-compatible chat completions at `https://api.fireworks.ai/inference/v1`.
Use the full Fireworks model id in mappings.

```toml
[[providers]]
name = "fireworks"
provider_type = "openai"
api_key = "$FIREWORKS_API_KEY"
base_url = "https://api.fireworks.ai/inference/v1"
models = ["accounts/fireworks/models/glm-5p2"]

[[models]]
name = "glm-5.2"
context_window_tokens = 131072

[[models.mappings]]
provider = "fireworks"
actual_model = "accounts/fireworks/models/glm-5p2"
priority = 1
```

See [fireworks-glm52.toml](../examples/fireworks-glm52.toml) for a complete Grob profile.

---

## DeepSeek (direct API)

```toml
[[providers]]
name = "deepseek"
provider_type = "openai"
api_key = "$DEEPSEEK_API_KEY"
base_url = "https://api.deepseek.com/v1"
models = []
```

---

## Groq

```toml
[[providers]]
name = "groq"
provider_type = "openai"
api_key = "$GROQ_API_KEY"
base_url = "https://api.groq.com/openai/v1"
models = []
```

---

## Ollama (local)

No API key needed. Requires [Ollama](https://ollama.com) running locally.

```toml
[[providers]]
name = "ollama"
provider_type = "openai"
api_key = "ollama"
base_url = "http://localhost:11434/v1"
models = []
```

```bash
# Pull models first
ollama pull qwen2.5-coder:32b
ollama pull qwen2.5-coder:7b
```

---

## Gemini

See [Gemini Integration](gemini-integration.md) for full details including Vertex AI.

### API key

```toml
[[providers]]
name = "gemini"
provider_type = "gemini"
api_key = "$GEMINI_API_KEY"
models = []
```

### OAuth (Gemini Pro subscription)

```toml
[[providers]]
name = "gemini"
provider_type = "gemini"
auth_type = "oauth"
oauth_provider = "gemini-pro"
models = []
```

---

## Z.ai / GLM

Z.ai exposes GLM models on **two parallel endpoints** — pick the one that matches your use case.

### When to use which path

| Use case | Path | `provider_type` | `base_url` |
|----------|------|-----------------|------------|
| Anthropic Messages-compatible account | Anthropic-compatible | `z.ai` | `https://api.z.ai/api/anthropic` (default) |
| OpenAI Chat Completions-compatible account | OpenAI-compatible | `openai` | `https://api.z.ai/api/paas/v4` |

Choose the endpoint provisioned for your account and API key. Model access,
free-tier availability and prices are provider decisions; verify them in your
provider account before selecting a model.

### Anthropic-compatible (drop-in for Claude Code)

```toml
[[providers]]
name = "zai-coding"
provider_type = "z.ai"
api_key = "$ZAI_API_KEY"
models = []
```

This routes to `AnthropicCompatibleProvider`, which means: native Anthropic Messages format, full thinking-block support, beta-feature header forwarding, and tool-use-id sanitization. The `base_url` defaults to `https://api.z.ai/api/anthropic` and never needs to be set explicitly.

### OpenAI-compatible

```toml
[[providers]]
name = "zai"
provider_type = "openai"
api_key = "$ZAI_API_KEY"
base_url = "https://api.z.ai/api/paas/v4"
models = ["glm-4.7-flash", "glm-4.5-flash", "glm-4.5-air"]
```

Z.ai's `/api/paas/v4/chat/completions` is OpenAI Chat Completions API-compatible. Grob's standard `OpenAIProvider` translation layer handles the request/response shape. This is the path the `ultra-cheap` preset uses.

#### Quirks ignored by grob

The OpenAI-compat endpoint accepts a few GLM-specific request fields that grob does **not** surface today:

- `thinking: { type: "enabled" | "disabled", clear_thinking: bool }` — chain-of-thought toggle (use `provider_type = "z.ai"` + Anthropic thinking blocks instead).
- `do_sample: bool` — disables temperature/top_p sampling.
- `request_id: string` — user-provided trace ID.
- `tool_stream: bool` — streaming for function calls (GLM-4.6+).

Grob requests pass through without these fields, which is harmless: the server applies its defaults. Error response shape (`{ code, message }` instead of OpenAI's `{ error: { message, type, code } }`) and finish reasons (`sensitive`, `model_context_window_exceeded`, `network_error`) are normalized into grob's standard error envelope at the dispatch layer. Context-window overflows are normalized further to HTTP `400` with `context_length_exceeded` and compact hint headers so clients can retry after `/compact`.

If you need GLM thinking control end-to-end, use the Anthropic-compatible path — `provider_type = "z.ai"` + Anthropic `thinking` blocks map cleanly to GLM's reasoning mode at the upstream.

---

## Custom OpenAI-compatible provider

Any API that follows the OpenAI Chat Completions format works:

```toml
[[providers]]
name = "my-provider"
provider_type = "openai"
api_key = "$MY_API_KEY"
base_url = "https://my-api.example.com/v1"
headers = { "X-Custom-Header" = "value" }
models = []
```

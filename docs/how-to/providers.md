# Provider Setup

Grob supports three categories of providers:

- **Anthropic-native** -- providers that speak the Anthropic Messages API
- **OpenAI-compatible** -- providers that speak the OpenAI Chat Completions API
- **Google** -- Gemini (AI Studio) and Vertex AI

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
```

### OAuth (Pro/Max subscription)

```toml
[[providers]]
name = "anthropic"
provider_type = "anthropic"
auth_type = "oauth"
oauth_provider = "anthropic-max"
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
```

Get an API key at [openrouter.ai/keys](https://openrouter.ai/keys).

### Using models via OpenRouter

```toml
[[models.mappings]]
provider = "openrouter"
actual_model = "deepseek/deepseek-v3.2"     # $0.26/$0.38 per M tokens
priority = 2

[[models.mappings]]
provider = "openrouter"
actual_model = "mistralai/devstral-2512"     # $0.40/$2.00 per M tokens
priority = 3
```

Browse available models at [openrouter.ai/models](https://openrouter.ai/models).

---

## Mistral / Devstral (direct API)

Use Mistral's API directly instead of going through OpenRouter. Useful if you want lower latency or have Mistral credits.

```toml
[[providers]]
name = "mistral"
provider_type = "openai"
api_key = "$MISTRAL_API_KEY"
base_url = "https://api.mistral.ai/v1"
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
```

---

## DeepSeek (direct API)

```toml
[[providers]]
name = "deepseek"
provider_type = "openai"
api_key = "$DEEPSEEK_API_KEY"
base_url = "https://api.deepseek.com/v1"
```

---

## Groq

```toml
[[providers]]
name = "groq"
provider_type = "openai"
api_key = "$GROQ_API_KEY"
base_url = "https://api.groq.com/openai/v1"
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
```

### OAuth (Gemini Pro subscription)

```toml
[[providers]]
name = "gemini"
provider_type = "gemini"
auth_type = "oauth"
oauth_provider = "gemini-pro"
```

---

## Z.ai / GLM

Z.ai exposes GLM models on **two parallel endpoints** — pick the one that matches your use case.

### When to use which path

| Use case | Path | `provider_type` | `base_url` |
|----------|------|-----------------|------------|
| Drop-in for Claude Code (paid Coding Plan or `glm-5.1` as opus replacement) | Anthropic-compatible | `z.ai` | `https://api.z.ai/api/anthropic` (default) |
| Free-tier `glm-4.7-flash` / `glm-4.5-flash` / `glm-4.5-air` (PAYG, ongoing free) | OpenAI-compatible | `openai` | `https://api.z.ai/api/paas/v4` |

The two endpoints are **separate products** at Z.ai. The Anthropic path serves the GLM Coding Plan subscription; the OpenAI path serves the standard PAYG / free-tier access. Use whichever the API key on your account is provisioned for.

### Anthropic-compatible (drop-in for Claude Code)

```toml
[[providers]]
name = "zai-coding"
provider_type = "z.ai"
api_key = "$ZAI_API_KEY"
```

This routes to `AnthropicCompatibleProvider`, which means: native Anthropic Messages format, full thinking-block support, beta-feature header forwarding, and tool-use-id sanitization. The `base_url` defaults to `https://api.z.ai/api/anthropic` and never needs to be set explicitly.

### OpenAI-compatible (free tier, PAYG)

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

Grob requests pass through without these fields, which is harmless: the server applies its defaults. Error response shape (`{ code, message }` instead of OpenAI's `{ error: { message, type, code } }`) and finish reasons (`sensitive`, `model_context_window_exceeded`, `network_error`) are normalized into grob's standard error envelope at the dispatch layer.

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
```

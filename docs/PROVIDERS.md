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
| z.ai | `z.ai` | API key | Anthropic-compatible |
| MiniMax | `minimax` | API key | Anthropic-compatible |
| Kimi Coding | `kimi-coding` | API key | Anthropic-compatible |

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

On first `grob start`, a browser window opens for OAuth login. Tokens are stored in `~/.grob/oauth_tokens.json` and refreshed automatically.

See [OAuth Setup](OAUTH_SETUP.md) for details.

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

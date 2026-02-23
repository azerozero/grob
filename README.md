# Grob

> LLM routing proxy with multi-provider failover

[![CI](https://github.com/azerozero/grob/actions/workflows/ci.yml/badge.svg)](https://github.com/azerozero/grob/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/azerozero/grob)](https://github.com/azerozero/grob/releases)
[![License: ELv2](https://img.shields.io/badge/License-ELv2-blue.svg)](https://www.elastic.co/licensing/elastic-license)

Grob sits between your AI coding assistant and your LLM providers. It routes requests to the right provider, falls back automatically when one is unavailable, and translates between Anthropic and OpenAI API formats.

```
Claude Code ─┐
Aider ───────┼──▶ Grob ──▶ Anthropic (primary)
Cline ───────┘              ├── OpenRouter (fallback)
                            ├── Gemini
                            └── Ollama (local)
```

## Install

```bash
# Pre-built binary (Linux/macOS)
curl -fsSL https://raw.githubusercontent.com/azerozero/grob/main/scripts/install.sh | sh

# Via cargo-binstall
cargo binstall grob

# From source
cargo install --git https://github.com/azerozero/grob
```

## Quick start

```bash
# Apply a preset and start
grob preset apply medium
grob start -d

# Point Claude Code at Grob
ANTHROPIC_BASE_URL=http://127.0.0.1:13456 claude
```

That's it. Grob routes requests to your configured providers with automatic failover.

## How routing works

Every incoming request is classified by task type, then routed to the matching model with its priority-based fallback chain:

```
Request ──▶ Classify ──▶ Model ──▶ Provider (P1) ──fail──▶ Provider (P2) ──fail──▶ Provider (P3)
                │
                ├── thinking enabled?  ──▶ think model
                ├── web_search tool?   ──▶ websearch model
                ├── haiku/background?  ──▶ background model
                ├── regex match?       ──▶ matched model
                └── default            ──▶ default model
```

## Presets

Presets configure providers, models, and fallback chains in one command.

| Preset | Think | Default | Cost |
|--------|-------|---------|------|
| **perf** | Opus 4.6 (Anthropic) | Sonnet 4.6 (Anthropic) | Max subscription |
| **medium** | Opus 4.6 (Anthropic) | Kimi K2.5 (OpenRouter) | Max sub + ~$0.30/M |
| **cheap** | DeepSeek R1 (OpenRouter) | Gemini Flash (OpenRouter) | ~$0.15/M |
| **local** | Opus 4.6 (Anthropic) | Qwen 2.5 Coder (Ollama) | Max sub + free |

```bash
grob preset list                # Show available presets
grob preset apply medium        # Apply a preset
grob preset export my-setup     # Save current config as preset
```

## Configuration

Config lives at `~/.grob/config.toml`. Override with `--config <path>` or `GROB_CONFIG=<path|url>`.

```toml
# Provider
[[providers]]
name = "anthropic"
provider_type = "anthropic"
auth_type = "oauth"
oauth_provider = "anthropic-max"

[[providers]]
name = "openrouter"
provider_type = "openrouter"
api_key = "$OPENROUTER_API_KEY"

# Model with fallback chain
[[models]]
name = "default"

[[models.mappings]]
provider = "anthropic"
actual_model = "claude-sonnet-4-6"
priority = 1

[[models.mappings]]
provider = "openrouter"
actual_model = "deepseek/deepseek-v3.2"
priority = 2

# Routing
[router]
default = "default"
think = "claude-opus-thinking"
background = "background"
websearch = "websearch"

[server]
port = 13456
```

See [Configuration Reference](docs/CONFIGURATION.md) for all options.

## Supported providers

| Provider | Type | Auth | Notes |
|----------|------|------|-------|
| **Anthropic** | `anthropic` | API key or OAuth | Claude models. OAuth works with Pro/Max subscriptions |
| **OpenAI** | `openai` | API key | GPT, o1, o3 models |
| **Gemini** | `gemini` | API key or OAuth | Google AI Studio. OAuth works with Gemini Pro subscriptions |
| **Vertex AI** | `vertex-ai` | ADC | Google Cloud Vertex AI |
| **OpenRouter** | `openrouter` | API key | 200+ models from all providers (DeepSeek, Kimi, Grok, Mistral, etc.) |
| **Mistral** | `openai` | API key | Devstral, Codestral, Mistral Large. Use `base_url = "https://api.mistral.ai/v1"` |
| **Ollama** | `openai` | none | Local models. Use `base_url = "http://localhost:11434/v1"` |
| **Groq** | `openai` | API key | Use `base_url = "https://api.groq.com/openai/v1"` |
| **DeepSeek** | `openai` | API key | Use `base_url = "https://api.deepseek.com/v1"` |
| **Together** | `openai` | API key | Use `base_url = "https://api.together.xyz/v1"` |
| **z.ai** | `z.ai` | API key | Anthropic-compatible provider |
| **MiniMax** | `minimax` | API key | Anthropic-compatible provider |
| **Kimi Coding** | `kimi-coding` | API key | Anthropic-compatible provider |

Any OpenAI-compatible API works with `provider_type = "openai"` and a custom `base_url`.

### Adding a provider

```toml
# Example: Mistral / Devstral direct API
[[providers]]
name = "mistral"
provider_type = "openai"
api_key = "$MISTRAL_API_KEY"
base_url = "https://api.mistral.ai/v1"

# Use it in a model mapping
[[models.mappings]]
provider = "mistral"
actual_model = "devstral-small-2505"
priority = 2
```

Or use any model via OpenRouter without a dedicated provider:

```toml
[[models.mappings]]
provider = "openrouter"
actual_model = "mistralai/devstral-2512"
priority = 2
```

## API compatibility

Grob exposes two endpoints:

| Endpoint | Format | Streaming | Tool calling |
|----------|--------|-----------|-------------|
| `/v1/messages` | Anthropic | Yes | Yes |
| `/v1/chat/completions` | OpenAI | Yes | Yes |

All requests are translated to Anthropic format internally, then routed to the appropriate provider.

## CLI reference

```
grob start [-d]           Start the server (--detach for background)
grob stop                 Stop the server
grob restart [-d]         Restart the server
grob status               Check if the server is running + spend summary
grob spend                Show current month's spend breakdown
grob run                  Run in container mode (0.0.0.0, JSON logs, no PID)
grob model                Show configured models and routing
grob validate             Test all providers with real API calls
grob preset <subcommand>  Manage presets (list, info, apply, export, install, sync)
```

## Container

Grob publishes a minimal container image (~6 MB, `FROM scratch`) to GitHub Container Registry:

```bash
docker run -e ANTHROPIC_API_KEY=sk-... ghcr.io/azerozero/grob:latest
```

The binary bundles TLS certificates via rustls, so no OS layer is needed.

## Documentation

| Document | Description |
|----------|-------------|
| [Configuration Reference](docs/CONFIGURATION.md) | All config options |
| [Provider Setup](docs/PROVIDERS.md) | Per-provider setup guides |
| [OAuth Setup](docs/OAUTH_SETUP.md) | OAuth for Anthropic, Gemini |
| [OpenAI Compatibility](docs/openai-compatibility.md) | `/v1/chat/completions` details |
| [Design Principles](docs/design-principles.md) | Grob's design philosophy |

## License

[AGPL-3.0](LICENSE) -- Commercial licensing available for organizations that cannot comply with AGPL terms. See [LICENSING.md](LICENSING.md) for details.

Originally forked from [claude-code-mux](https://github.com/elidickinson/claude-code-mux) (MIT). Copyright (c) 2025-2026 A00 SASU.

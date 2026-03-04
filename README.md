# Grob

> LLM routing proxy with multi-provider failover

[![CI](https://github.com/azerozero/grob/actions/workflows/ci.yml/badge.svg)](https://github.com/azerozero/grob/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/azerozero/grob)](https://github.com/azerozero/grob/releases)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)

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

## Features

### Multi-provider fallback

Each model maps to a priority-ordered provider chain. If the primary returns a 5xx, 429, or times out, Grob retries the next provider with exponential backoff -- no client-side changes needed. Circuit breakers prevent cascading failures by temporarily removing unhealthy providers.

### DLP (Data Loss Prevention)

Built-in secret scanning (API keys, tokens, credentials), PII detection (emails, phone numbers, names), canary token injection, prompt injection detection, and URL exfiltration blocking. All configurable per-rule with `redact`, `block`, or `warn` actions.

```toml
[dlp]
enabled = true
secrets = "redact"    # Scan for API keys, tokens, credentials
pii = "warn"          # Detect emails, phone numbers
names = "pseudonymize" # Replace real names with consistent pseudonyms
```

### MCP tool matrix

Grob evaluates which LLM providers handle which tools best. A background bench engine periodically probes providers with standardized test cases and builds a scoring matrix. The MCP JSON-RPC server exposes tool routing recommendations.

### Fan-out (multi-provider racing)

Send the same request to multiple providers in parallel and pick the fastest, cheapest, or best-quality response (scored by a judge model).

```toml
[[models]]
name = "best-answer"
strategy = "fan_out"

[models.fan_out]
mode = "fastest"   # or "best_quality", "weighted"
```

### Spend tracking and budgets

Persistent monthly spend tracking per provider and model (stored in redb). Set hard caps to prevent bill shock:

```toml
[budget]
monthly_limit_usd = 100.0
warn_at_percent = 80
```

### OpenAI compatibility

Both `/v1/messages` (Anthropic) and `/v1/chat/completions` (OpenAI) are fully supported with streaming and tool calling. Any OpenAI-compatible client (Aider, OpenCode, Kilo, Continue) works out of the box.

### Record & replay testing (harness)

Capture live HTTP traffic, then replay it through Grob with a mock backend to stress-test the full pipeline. Feature-gated (`--features harness`).

```bash
GROB_HARNESS_RECORD=session.tape.jsonl grob start   # Record
grob harness replay --tape session.tape.jsonl --concurrency 100  # Replay
```

### Also included

- **Rate limiting** -- Per-tenant token bucket with configurable RPS and burst
- **Signed audit log** -- ECDSA-P256 or HMAC-SHA256 signed entries for compliance (EU AI Act Article 12)
- **Adaptive provider scoring** -- EWMA latency + rolling success rate to rank providers dynamically
- **Response caching** -- Automatic dedup for temperature=0 requests (saves tokens and latency)
- **Native TLS + ACME** -- Built-in HTTPS with optional Let's Encrypt auto-certificates
- **Zero-downtime upgrades** -- SO_REUSEPORT + graceful drain for hot restarts
- **OAuth PKCE** -- Browser-based login for Anthropic Max and Gemini Pro subscriptions
- **Prometheus metrics** -- `/metrics` endpoint with request/latency/spend counters
- **Prompt-based routing** -- Regex rules to route specific prompts to specialized models

## API examples

Grob exposes two endpoints:

| Endpoint | Format | Streaming | Tool calling |
|----------|--------|-----------|-------------|
| `/v1/messages` | Anthropic | Yes | Yes |
| `/v1/chat/completions` | OpenAI | Yes | Yes |

### Anthropic format (curl)

```bash
curl -X POST http://127.0.0.1:13456/v1/messages \
  -H "Content-Type: application/json" \
  -H "x-api-key: any-key" \
  -H "anthropic-version: 2023-06-01" \
  -d '{
    "model": "claude-sonnet-4-20250514",
    "max_tokens": 1024,
    "messages": [{"role": "user", "content": "What is 2+2?"}]
  }'
```

### OpenAI format (curl)

```bash
curl -X POST http://127.0.0.1:13456/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer any-key" \
  -d '{
    "model": "claude-sonnet-4-20250514",
    "messages": [{"role": "user", "content": "What is 2+2?"}]
  }'
```

### Streaming

```bash
curl -X POST http://127.0.0.1:13456/v1/messages \
  -H "Content-Type: application/json" \
  -H "x-api-key: any-key" \
  -H "anthropic-version: 2023-06-01" \
  -d '{
    "model": "claude-sonnet-4-20250514",
    "max_tokens": 1024,
    "stream": true,
    "messages": [{"role": "user", "content": "Write a haiku about proxies"}]
  }'
```

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
grob exec -- <cmd>        Launch a command behind the Grob proxy (auto start/stop)
grob preset <subcommand>  Manage presets (list, info, apply, export, install, sync)
grob doctor               Run diagnostic checks on installation
grob connect [provider]   Set up provider credentials interactively
grob env                  Check required environment variables
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
| [Getting Started](docs/tutorials/getting-started.md) | Step-by-step tutorial |
| [Configuration Reference](docs/CONFIGURATION.md) | All config options |
| [Provider Setup](docs/PROVIDERS.md) | Per-provider setup guides |
| [OAuth Setup](docs/OAUTH_SETUP.md) | OAuth for Anthropic, Gemini |
| [OpenAI Compatibility](docs/openai-compatibility.md) | `/v1/chat/completions` details |
| [Security](docs/explanation/security.md) | DLP, rate limiting, audit, circuit breakers |
| [Architecture](docs/ARCHITECTURE.md) | Module layout and design decisions |
| [CLI Reference](docs/reference/cli.md) | Full command documentation |
| [Design Principles](docs/design-principles.md) | Grob's design philosophy |

## License

[AGPL-3.0](LICENSE) -- Commercial licensing available for organizations that cannot comply with AGPL terms. See [LICENSING.md](LICENSING.md) for details.

Originally forked from [claude-code-mux](https://github.com/elidickinson/claude-code-mux) (MIT). Copyright (c) 2025-2026 A00 SASU.

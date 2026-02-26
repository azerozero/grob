# Grob Quick Start

Get up and running in 30 seconds.

## 1. Install

```bash
cargo install grob
# or with binstall:
cargo binstall grob
```

## 2. Apply a preset

```bash
grob preset apply perf
```

This writes `~/.grob/config.toml` with Anthropic + OpenAI + Gemini providers and top-tier models.
Set the required API keys in your environment first:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export OPENAI_API_KEY=sk-...
export GEMINI_API_KEY=AI...
```

Available presets: `perf`, `medium`, `cheap`, `fast`, `local`, `gdpr`.
Run `grob preset list` to see all options.

## 3. Launch your tool

```bash
grob exec -- claude
```

Grob starts in the background, sets `ANTHROPIC_BASE_URL` and `OPENAI_BASE_URL` to point at the proxy, launches your command, and stops when it exits.

Other examples:

```bash
grob exec -- aider
grob exec -- opencode
grob exec -- my-custom-tool --flag
```

## What just happened?

Grob is now proxying all LLM requests. It routes them to the best provider based on the model requested, handles fallback if a provider is down, enforces budgets, and tracks spend. Check the status anytime:

```bash
grob status     # Service status, loaded models, active preset
grob spend      # Current month's spend vs. budget
grob doctor     # Full diagnostic check
```

## Next steps

- [Architecture overview](ARCHITECTURE.md) -- how the request pipeline works
- [Troubleshooting](TROUBLESHOOTING.md) -- common errors and fixes
- [Configuration reference](CONFIGURATION.md) -- all TOML options
- [OpenAPI spec](openapi.yaml) -- full API reference

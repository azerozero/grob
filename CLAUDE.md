# Grob Development Guidelines

## Architecture

Grob is a multi-provider LLM routing proxy written in Rust. It routes requests to Anthropic, OpenAI, Gemini, DeepSeek, Ollama, and other providers with automatic fallback and format translation.

### Key Architectural Decisions

- **Config is static at runtime**: The server loads TOML config on startup and does not reload until restart. The `/api/config` endpoints exist for programmatic access but require a server restart to take effect.
- **Provider abstraction**: All providers implement the `AnthropicProvider` trait (`src/providers/mod.rs`).
- **Routing**: Regex-based prompt rules in `src/router/mod.rs` classify requests into task types (thinking, web_search, background, default).
- **OAuth**: Custom implementation (no `oauth2` crate) with PKCE in `src/auth/oauth.rs`.
- **Spend tracking**: Persistent monthly spend in `~/.grob/spend.json` with budget enforcement.

### Module Layout

| Module | Purpose |
|--------|---------|
| `src/server/mod.rs` | Axum HTTP server, request handlers |
| `src/server/openai_compat.rs` | OpenAI `/v1/chat/completions` translation |
| `src/server/oauth_handlers.rs` | OAuth API endpoints |
| `src/providers/` | Provider implementations (Anthropic, OpenAI, Gemini, etc.) |
| `src/router/mod.rs` | Request routing engine |
| `src/cli/mod.rs` | Config structs and CLI argument parsing |
| `src/auth/` | OAuth client and token store |
| `src/features/token_pricing/` | Pricing, spend tracking, budget enforcement |
| `src/preset.rs` | Preset management system |

# currentDate
Today's date is 2026-02-24.

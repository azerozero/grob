# Grob

Multi-provider LLM routing proxy that sits between AI coding assistants and LLM providers, routing requests with automatic failover, format translation, and spend tracking.

## Stack

- **Language**: Rust 2021 edition (~29K LOC)
- **Runtime**: Tokio async
- **HTTP framework**: Axum 0.7 with Tower middleware
- **HTTP client**: reqwest 0.12 (HTTP/2, rustls)
- **Config**: TOML (serde)
- **Storage**: redb (embedded key-value store for tokens, spend)
- **CLI**: clap 4 (derive mode)
- **Allocator**: jemalloc on non-MSVC targets
- **CI**: GitHub Actions (fmt, clippy, nextest, coverage, cargo-audit, cargo-deny, cargo-hack, cargo-machete)
- **Container**: Multi-stage build, `FROM scratch` (~6 MB image)
- **License**: AGPL-3.0 with commercial dual-licensing

## Architecture

Grob accepts requests in Anthropic (`/v1/messages`) and OpenAI (`/v1/chat/completions`) formats. All requests are normalized to Anthropic's internal message format. A regex-based router classifies each request by task type (thinking, web_search, background, default) and selects a named model. Each model maps to one or more providers ordered by priority. If the highest-priority provider fails, the request falls through to the next. Circuit breakers (5 failures = open, 30s timeout) prevent hammering degraded providers. DLP scanning runs on stream chunks using Aho-Corasick automata. Persistent spend tracking in redb enforces monthly budgets at global, per-provider, and per-model granularity.

## Domain Concepts

- **Provider**: An LLM API backend (Anthropic, OpenAI, Gemini, OpenRouter, Ollama, etc.). Each implements the `LlmProvider` trait.
- **Model**: A named routing target with a priority-ordered fallback chain of provider mappings. Not a single LLM model -- a Grob "model" is a logical slot (e.g., "default", "claude-opus-thinking").
- **Mapping**: A `(provider, actual_model, priority)` tuple. Priority 1 is tried first.
- **Route type**: The classification of a request: `Default`, `Think`, `WebSearch`, `Background`, `PromptRule`, `AutoMap`.
- **Preset**: A pre-built config (providers + models + router) that can be applied in one command.
- **Circuit breaker**: Per-provider state machine (Closed/Open/HalfOpen) that prevents cascading failures.
- **Pass-through**: A provider mode that accepts any model name not explicitly configured, forwarding it as-is.
- **DLP**: Data Loss Prevention -- scans requests/responses for secrets, PII, and canary tokens.
- **Tap**: Webhook event emission for external monitoring.
- **Spend**: Monthly cost tracking per provider/model with budget enforcement (HTTP 402 on exceed).

## Key Patterns

- **Config is static at runtime**: Loaded once from TOML into `Arc`. No hot-reload. Restart to apply changes. `/api/config/reload` swaps the config atomically for in-memory updates.
- **Trait-driven dispatch**: 7 traits in `src/traits.rs` (LlmProvider, RequestRouter, DlpPipeline, SpendTracking, Tracer, AuditWriter, EventTap, ProviderAvailability) enable testing via mock implementations.
- **Feature flags**: `dlp`, `oauth`, `tap`, `compliance` -- all default-on. Disable at compile time for smaller binaries.
- **Error types**: `ProviderError` (thiserror) for provider failures, `AppError` for HTTP responses, `anyhow` for CLI/startup.
- **Streaming-first**: SSE streaming is the primary path. DLP scanning is chunk-based, not buffered.
- **Environment variable expansion**: API keys in TOML support `$ENV_VAR` syntax resolved at startup.
- **All providers normalize to Anthropic format**: OpenAI, Gemini, etc. requests are translated to/from Anthropic Messages internally.

## Commands

```bash
# Build
cargo build
cargo build --release

# Test
cargo nextest run          # Unit + integration tests
cargo test --doc           # Doc tests
cargo clippy -- -D warnings

# Lint
cargo fmt --all -- --check
cargo machete              # Unused deps

# Run locally
cargo run -- start -d      # Start in background (daemon)
cargo run -- stop          # Stop
cargo run -- status        # Health check + spend summary
cargo run -- validate      # Test all providers with real API calls

# Presets
cargo run -- preset list
cargo run -- preset apply medium

# Container
podman build -f Containerfile -t grob .
podman run -e ANTHROPIC_API_KEY=sk-... grob

# Benchmarks
cargo bench --bench routing
cargo bench --bench hotpath
```

## Gotchas

- Default port is **13456**, not 3456. Bind address is `127.0.0.1` by default (IPv4 only in recent versions).
- Config file is `~/.grob/config.toml`. Override with `--config <path>` or `GROB_CONFIG=<path|url>`.
- OAuth tokens stored in `~/.grob/oauth_tokens.json` (not in redb). Token store in redb is for different auth state.
- The `models` field on `ProviderConfig` is a legacy field -- model support is determined by `[[models.mappings]]`, not by listing models on the provider.
- `jemalloc` is not available on MSVC targets -- the `#[cfg(not(target_env = "msvc"))]` guard handles this.
- `cargo chef` is used in the Containerfile for layer caching -- the `time` crate needs a `cargo update --precise` workaround in the build.
- The OpenAI compat endpoint translates everything to Anthropic format internally, so features like `response_format` (JSON mode) are not supported.
- Presets live in `presets/*.toml` (shipped with the binary) and user presets in `~/.grob/presets/`.
- Feature flags are all on by default. To build without DLP: `cargo build --no-default-features --features oauth,tap,compliance`.

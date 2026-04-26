# Grob

Multi-provider LLM routing proxy that sits between AI coding assistants and LLM providers, routing requests with automatic failover, format translation, and spend tracking.

## Stack

- **Language**: Rust 2021 edition (~67K LOC, ~800 public items, 100% doc coverage)
- **Runtime**: Tokio async
- **HTTP framework**: Axum 0.7 with Tower middleware
- **HTTP client**: reqwest 0.12 (HTTP/2, rustls)
- **Config**: TOML (serde)
- **Storage**: Atomic files + append-only JSONL journals (tokens in `~/.grob/tokens/*.json.enc`, spend in `~/.grob/spend/YYYY-MM.jsonl`)
- **CLI**: clap 4 (derive mode)
- **Allocator**: jemalloc on non-MSVC targets
- **CI**: GitHub Actions (fmt, clippy, nextest, coverage, cargo-audit, cargo-deny, cargo-hack, cargo-machete)
- **Container**: Multi-stage build, `FROM scratch` (~6 MB image)
- **License**: AGPL-3.0 with commercial dual-licensing

## Architecture

Grob accepts requests in Anthropic (`/v1/messages`) and OpenAI (`/v1/chat/completions`) formats. All requests are normalized to a canonical internal message format (the `CanonicalRequest` type). OpenAI-specific extension fields (response_format, reasoning_effort, seed, etc.) are captured in `RequestExtensions` for lossless roundtrips. A regex-based router classifies each request by task type (web_search, background, subagent, prompt_rule, think, default) and selects a named model. Each model maps to one or more providers ordered by priority. If the highest-priority provider fails, the request falls through to the next. Circuit breakers (5 failures = open, 30s timeout) prevent hammering degraded providers. DLP scanning runs on stream chunks using Aho-Corasick automata. Persistent spend tracking in append-only JSONL journals (`~/.grob/spend/YYYY-MM.jsonl`) enforces monthly budgets at global, per-provider, and per-model granularity.

## Domain Concepts

- **Provider**: An LLM API backend (Anthropic, OpenAI, Gemini, OpenRouter, Ollama, etc.). Each implements the `LlmProvider` trait.
- **Model**: A named routing target with a priority-ordered fallback chain of provider mappings. Not a single LLM model -- a Grob "model" is a logical slot (e.g., "default", "claude-opus-thinking").
- **Mapping**: A `(provider, actual_model, priority)` tuple. Priority 1 is tried first.
- **Route type**: The classification of a request: `WebSearch`, `Background`, `PromptRule`, `Think`, `Default`. Auto-map is a name transformation step, not a route type.
- **Preset**: A pre-built config (providers + models + router) that can be applied in one command.
- **Circuit breaker**: Per-provider state machine (Closed/Open/HalfOpen) that prevents cascading failures.
- **Pass-through**: A provider mode (`pass_through = true`) that accepts any model name not explicitly configured, forwarding it as-is.
- **Fan-out**: A model strategy that dispatches to multiple providers in parallel (fastest, best_quality, or weighted selection).
- **DLP**: Data Loss Prevention -- scans requests/responses for secrets, PII, and canary tokens.
- **Tap**: Webhook event emission for external monitoring.
- **Spend**: Monthly cost tracking per provider/model with budget enforcement (HTTP 402 on exceed).
- **MCP**: Model Context Protocol tool matrix -- tool-calling capability catalogue with per-provider reliability scoring.
- **Subagent model**: A system prompt tag (`GROB-SUBAGENT-MODEL`) that overrides model selection for nested agent calls.
- **GrobStore**: Persistent storage layer using atomic files and append-only JSONL journals (`~/.grob/`). OAuth tokens stored as individually encrypted files (`tokens/<id>.json.enc`, AES-256-GCM), spend tracked in monthly journals (`spend/YYYY-MM.jsonl`).
- **Harness**: Record & replay sandwich testing. Captures raw HTTP traffic as `.tape.jsonl` files, then replays through grob with a mock backend to exercise the full pipeline (DLP, routing, cache, streaming, etc.).

## Key Patterns

- **Config is static at runtime**: Loaded once from TOML into `Arc`. `/api/config/reload` swaps config atomically without restart. In-flight requests continue on old snapshot.
- **Trait-driven dispatch**: 7+ traits in `src/traits.rs` (LlmProvider, RequestRouter, DlpPipeline, SpendTracking, Tracer, AuditWriter, EventTap, ProviderAvailability) enable testing via mock implementations.
- **Feature flags**: defaults are `dlp`, `oauth`, `tap`, `compliance`, `mcp`, `watch`, `policies`, `socket-opts`, `dirs`, `jemalloc`, `unix-signals` (see `[features].default` in `Cargo.toml`). `harness` is opt-in (compile with `--features harness`). Disable features at compile time for smaller binaries.
- **Error types**: `ProviderError` (thiserror) for provider failures, `AppError` for HTTP responses, `anyhow` for CLI/startup.
- **Streaming-first**: SSE streaming is the primary path. DLP scanning is chunk-based, not buffered.
- **Environment variable expansion**: API keys in TOML support `$ENV_VAR` syntax resolved at startup.
- **All providers normalize to canonical format**: OpenAI, Gemini, etc. requests are translated to/from the `CanonicalRequest` type (structurally Anthropic Messages format). Provider-specific fields are preserved in `RequestExtensions` for lossless roundtrips.
- **Default host is IPv6**: `::1` (not `127.0.0.1`). Container mode uses `0.0.0.0`.
- **Per-project config overlay**: `.grob.toml` in project root merges with global config (router, budget, preset overrides).

## Git Flow

```
feature/* or fix/* ──► PR ──► main ──► (release-plz PR) ──► main ──► tag v*
```

- **Never commit or push directly to `main`**. All changes go through feature branches + PRs.
- `main` is the only long-lived branch (GitHub Flow). release-plz watches `main` and opens a Release PR when releasable commits land.
- **`main` is protected** (GitHub ruleset: no deletion, no force push, PR required).
- **Always work on a feature branch** from `main`: `feat/<topic>` or `fix/<topic>`.
- **Always enable auto-merge** after creating a PR: `gh pr merge <num> --auto --merge`.
- **Conventional commits**: `feat:`, `fix:`, `refactor:`, `perf:` trigger version bumps via release-plz. Use `chore:`, `docs:`, `test:`, `style:` for non-release changes.
- **Pre-commit hooks** via [prek](https://github.com/j178/prek): run `prek install` after cloning. Hooks run `cargo fmt`, `clippy`, `gitleaks` on commit and tests, audit, deny on push.

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
cargo run -- exec -- claude # Launch Claude Code behind proxy (auto-start/stop)
cargo run -- doctor        # Run diagnostic checks
cargo run -- upgrade       # Zero-downtime upgrade via SO_REUSEPORT
cargo run -- setup         # Interactive setup wizard (auth/compliance/budget)
cargo run -- connect       # Interactive credential setup
cargo run -- init          # Create per-project .grob.toml
cargo run -- config-diff   # Compare config against preset
cargo run -- env           # Check required env vars
cargo run -- setup-completions # Install shell completions

# Harness (record & replay testing, requires --features harness)
cargo run --features harness -- harness record -o traffic.tape.jsonl
cargo run --features harness -- harness replay -t traffic.tape.jsonl

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

- Default port is **13456**, not 3456. Default bind address is `::1` (IPv6 localhost).
- Config file is `~/.grob/config.toml`. Override with `--config <path>` or `GROB_CONFIG=<path|url>`.
- OAuth tokens stored in `~/.grob/tokens/<id>.json.enc` (AES-256-GCM encrypted). Spend tracked in `~/.grob/spend/YYYY-MM.jsonl` (append-only journals).
- The `models` field on `ProviderConfig` is a legacy field -- model support is determined by `[[models.mappings]]`, not by listing models on the provider.
- `jemalloc` is not available on MSVC targets -- the `#[cfg(not(target_env = "msvc"))]` guard handles this.
- `cargo chef` is used in the Containerfile for layer caching.
- The OpenAI compat endpoint (`/v1/chat/completions`) translates to canonical format internally. Extension fields (response_format, reasoning_effort, seed, logprobs, etc.) are captured for lossless roundtrip but may not be enforced by Anthropic backends.
- The Responses API endpoint (`/v1/responses`) is used by Codex CLI and OpenAI SDK. It uses named SSE events (`event: response.output_text.delta`) for streaming, flat tool format (no nested `function` wrapper), and `instructions` instead of system messages. Translation logic lives in `src/server/responses_compat/`.
- Presets live in `presets/*.toml` (shipped with the binary) and user presets in `~/.grob/presets/`.
- Feature flags are all on by default. To build without DLP: `cargo build --no-default-features --features oauth,tap,compliance,mcp`.
- Anthropic beta features (`anthropic-beta` header) include prompt-caching-scope, interleaved-thinking, fine-grained-tool-streaming, and oauth. Client-provided beta features are merged with server defaults (no duplicates).
- Routing priority (highest to lowest): WebSearch > Background > AutoMap (name transform) > SubagentTag (model override, returns Default) > PromptRules > Think > Default.
- `grob exec -- <cmd>` is the recommended way to use Grob. It auto-starts, sets env vars, runs your tool, and auto-stops.
- `grob preset apply <name> --reload` applies a preset and hot-reloads the running server in one step.
- Budget exceeded returns HTTP 402, not 429. Rate limit exceeded returns 429.
- `grob -- <cmd>` is shorthand for `grob exec -- <cmd>` (trailing args syntax).
- The `harness` feature flag is opt-in (not in `default`). Build with `cargo build --features harness` to enable `grob harness record/replay`. Set `GROB_HARNESS_RECORD=<path>` to enable the tape recorder middleware at runtime.
- Providers with missing API keys are gracefully disabled at startup (logged as warnings) rather than causing a crash. The server starts with the remaining valid providers.

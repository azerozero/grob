# providers

> `LlmProvider` trait and concrete backends (Anthropic, OpenAI, Gemini, …).

## Purpose

Defines the upstream-LLM abstraction the dispatch pipeline targets and supplies
concrete implementations. Every backend speaks the canonical Anthropic Messages
format on the trait surface; non-Anthropic providers translate to and from
their native wire formats internally (per ADR-0005).

## Public API

| Item | Location | Used by |
|------|----------|---------|
| `LlmProvider` (trait) | `mod.rs` | `server::dispatch`, `server::fan_out` |
| `ProviderResponse`, `Usage`, `StreamResponse` | `mod.rs` | dispatch, openai_compat, responses_compat |
| `ProviderParams` | `mod.rs` | provider constructors |
| `ProviderRegistry` | `registry.rs` | `server::ReloadableState`, dispatch |
| `AnthropicCompatibleProvider` | `anthropic_compatible.rs` | registry |
| `OpenAIProvider` | `openai/mod.rs` | registry |
| `gemini::GeminiProvider` | `gemini/mod.rs` | registry |
| `key_pool::KeyPool` | `key_pool.rs` | provider constructors (multi-account rotation) |
| `build_provider_client` | `mod.rs` | every provider implementation |
| `ProviderError` | `error.rs` | dispatch retry/error mapping |

## Owns

- The `LlmProvider` trait contract and its mock (`mocks::MockLlmProvider`).
- Anthropic, OpenAI (chat completions + Responses bridge), Gemini implementations.
- Authentication helpers (`auth.rs`), shared SSE streaming utilities (`streaming.rs`).
- Multi-account API key pool and rotation logic (`key_pool.rs`).
- Provider registry: model-name lookup, pass-through resolution.
- Anthropic-flavoured request/response sanitization (`anthropic_sanitize.rs`).

## Depends on

- `models` for `CanonicalRequest`, `ContentBlock`, count-tokens types.
- `auth::TokenStore` for OAuth-backed providers (Anthropic Max, ChatGPT, Gemini).
- `cli::{AuthType, ProviderConfig}` (re-exported here) for configuration.

## Non-goals

- Routing or model selection (delegated to `routing::classify`).
- Persistent token storage (delegated to `auth::token_store` + `storage::GrobStore`).
- Cost calculation (delegated to `pricing` + `features::token_pricing`).
- HTTP transport for grob's own surface (delegated to `server/`).

## Adding a provider

Most new backends are OpenAI-compatible and need **no new provider type**: add a
`[[providers]]` entry with `provider_type = "openai"` and a `base_url`. Nothing
in this directory changes. Do that first and stop, unless the backend has a wire
format or auth model that genuinely differs.

If it does need code, the two paths differ sharply in cost:

**OpenAI-compatible with quirks** (the `deepseek` shape, ~8 files):

1. `registry.rs` — a new arm in the `match config.provider_type` at
   `create_provider`. This is the entry point; start here.
2. `pricing.rs` — per-model input/output rates, or spend is undercounted.
3. `routing/classify/inference.rs` and `model_name.rs` — model-name prefix
   inference and canonicalization.
4. `models/mod.rs` — the provider-type enum.
5. `commands/setup/types.rs` and `commands/credential_check.rs` — so the wizard
   and `grob doctor` know the credential.

**Its own wire format or auth model** (the `gemini` shape, ~28 files): all of
the above, plus a `providers/<name>/` module with its own request/response
translation, and `auth/` work if it uses OAuth rather than a bearer key.

Grep an existing provider name across `src/` before starting; that list is the
real checklist, and it is shorter for `deepseek` than for `gemini`.

## Tests

- `tests/unit/provider_test.rs` covers `ProviderRegistry` registration and lookup.
- `tests/unit/inference_test.rs` covers provider-type inference from model names.
- `#[cfg(test)] mod tests` inside `anthropic_compatible.rs`, `openai/transform.rs`, `gemini/transform.rs` cover translation roundtrips.
- `#[cfg(test)] mod tests` inside `key_pool.rs` covers rotation and exhaustion.
- `mocks::MockLlmProvider` (gated on `test` / `test-util`) supplies the stub used by integration harnesses.

## Related ADRs

- [ADR-0005](../../docs/decisions/0005-anthropic-native-provider-trait.md) — Anthropic Messages as the canonical trait format.
- [ADR-0007](../../docs/decisions/0007-openai-compat-dual-surface.md) — OpenAI dual-surface translation lives in `openai/`.
- [ADR-0018](../../docs/decisions/0018-nature-inspired-routing.md) — circuit breaker + health checks consume provider availability signals.

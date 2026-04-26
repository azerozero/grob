# models

> Provider-agnostic request / response types and route-decision shapes.

## Purpose

Defines the canonical data shapes that flow through the dispatch pipeline.
Inbound requests (Anthropic native, OpenAI chat, OpenAI Responses) are
normalised into [`CanonicalRequest`]; outbound responses use Anthropic's
Messages format. Provider-specific fields that don't map cleanly are preserved
in [`extensions::RequestExtensions`] for lossless roundtrips.

## Public API

| Item | Location | Used by |
|------|----------|---------|
| `CanonicalRequest` | `mod.rs` | `server::dispatch`, `providers::LlmProvider`, `routing::classify` |
| `Message`, `MessageContent` | `mod.rs` | dispatch, openai_compat, responses_compat |
| `ContentBlock`, `KnownContentBlock` | `mod.rs` | provider transforms, DLP scanning |
| `ToolResultContent`, `ToolResultBlock`, `KnownToolResultBlock` | `mod.rs` | tool-layer, providers |
| `SystemPrompt`, `SystemBlock` | `mod.rs` | every provider implementation |
| `ImageSource`, `Tool`, `ThinkingConfig` | `mod.rs` | providers, openai_compat |
| `CountTokensRequest`, `CountTokensResponse` | `mod.rs` | `LlmProvider::count_tokens` |
| `RouteDecision`, `RouteType` | `mod.rs` | `routing::classify::Router`, transparency headers |
| `default_max_tokens` | `mod.rs` | `openai_compat::transform` |
| `config::AppConfig` | `config.rs` | `server::ReloadableState`, every CLI command |
| `extensions::RequestExtensions` | `extensions.rs` | provider-specific lossless roundtrips |

## Owns

- The canonical Messages-shaped data model used across the pipeline.
- Untagged `enum` shapes that gracefully passthrough unknown content / tool-result blocks.
- The `default_max_tokens(model)` heuristic table (per-family fallback when clients omit it).
- `RouteDecision` / `RouteType` (populated by `routing::classify::Router`).
- Internal `spend_data` shape shared between `storage` and `features::token_pricing`.

## Depends on

- `serde`, `serde_json`, `chrono` only (no internal slice dependencies for the core types).
- `routing::classify::ComplexityTier` is referenced by `RouteDecision` (forward type reference).

## Non-goals

- Wire-format translation (delegated to `server::openai_compat`, `server::responses_compat`, provider transforms).
- Validation beyond what `serde` enforces structurally.
- Any I/O or async behaviour — this slice is data-only.

## Tests

- `tests/unit/models_test.rs` covers canonical request shapes and serialization.
- `#[cfg(test)] mod tests` inside `mod.rs` covers `default_max_tokens` for Anthropic, OpenAI, Gemini, and fallback families.
- `#[cfg(test)] mod tests` inside `extensions.rs`, `config.rs` cover extension preservation and config defaults.

## Related ADRs

- [ADR-0005](../../docs/decisions/0005-anthropic-native-provider-trait.md) — Anthropic Messages chosen as the canonical shape.
- [ADR-0007](../../docs/decisions/0007-openai-compat-dual-surface.md) — OpenAI translation targets `CanonicalRequest`.
- [ADR-0009](../../docs/decisions/0009-pledge-structural-tool-filtering.md) — tool / content blocks feed pledge filtering.

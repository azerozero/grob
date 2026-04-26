# server

> Axum HTTP server, application state, middleware, and the dispatch pipeline.

## Purpose

Owns the HTTP surface of grob: route table, middleware stack, application state
(`AppState` + `ReloadableState`), and the inbound translation layers (Anthropic
native, OpenAI chat completions, OpenAI Responses API). The dispatch pipeline
orchestrates DLP, cache, routing, and the provider retry loop.

## Public API

| Item | Location | Used by |
|------|----------|---------|
| `start_server` | `mod.rs` | `commands::start` |
| `AppState`, `ReloadableState` | `mod.rs` | every handler, MCP server, RPC |
| `AppError` | `error.rs` | all handlers (HTTP error type) |
| `dispatch::dispatch` (pub(crate)) | `dispatch/mod.rs` | `handlers`, `openai_compat`, `responses_compat` |
| `fan_out::handle_fan_out` | `fan_out.rs` | parallel multi-provider mode |
| `openai_compat::transform_openai_to_canonical` | `openai_compat/transform.rs` | `handlers` |
| `responses_compat::transform_responses_to_canonical` | `responses_compat/transform.rs` | `handlers` |
| `rpc::dispatch` | `rpc/` | JSON-RPC 2.0 control plane |

## Owns

- `/v1/messages`, `/v1/chat/completions`, `/v1/responses`, `/v1/models`.
- `/health`, `/live`, `/ready`, `/metrics`, `/api/config*`, `/api/scores`.
- `/api/oauth/*`, `/api/hit/approve`, `/rpc`, `/api/events` (SSE).
- Middleware: `auth_middleware`, `rate_limit_check_middleware`, `request_id_middleware`,
  security headers, body-size limit, optional tape recorder.
- Graceful shutdown, in-flight drain, OAuth callback listener spawn.

## Depends on

- `providers` for `LlmProvider` dispatch and `ProviderRegistry`.
- `routing::classify` for `Router` and `RouteDecision`.
- `auth` for `TokenStore`, `JwtValidator`, virtual key context.
- `storage` for the shared `GrobStore`.
- `features::dlp`, `features::token_pricing`, `cache`, `security` for middleware concerns.

## Non-goals

- Provider-native HTTP calls (delegated to `providers/`).
- Routing decisions (delegated to `routing::classify::Router`).
- Persistent storage primitives (delegated to `storage/`).
- CLI parsing or process lifecycle outside graceful drain (delegated to `cli/`, `commands/`).

## Tests

- `tests/integration/server_test.rs`, `http_test.rs`, `e2e_test.rs` cover end-to-end HTTP behaviour.
- `tests/integration/cache_test.rs`, `dlp_test.rs`, `compliance_test.rs`, `hit_test.rs` cover middleware-backed concerns.
- `tests/unit/fan_out_test.rs`, `rpc_test.rs` cover the fan-out dispatcher and JSON-RPC plane.
- `#[cfg(test)] mod tests` blocks inside `dispatch/`, `openai_compat/`, `responses_compat/` cover translation invariants.

## Related ADRs

- [ADR-0001](../../docs/decisions/0001-static-config-no-hot-reload.md) — static config, atomic reload of `ReloadableState`.
- [ADR-0007](../../docs/decisions/0007-openai-compat-dual-surface.md) — dual OpenAI surface (chat completions + Responses).
- [ADR-0010](../../docs/decisions/0010-universal-tool-layer.md) — tool-layer middleware sits inside dispatch.
- [ADR-0011](../../docs/decisions/0011-control-engine-mcp-tools.md) — JSON-RPC 2.0 control plane endpoint.
- [ADR-0016](../../docs/decisions/0016-decision-tokens-transparent-routing.md) — transparency headers emitted by middleware.

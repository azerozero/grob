# watch

> Live event bus and TUI traffic inspector for `grob watch`.

## Purpose

`watch` broadcasts dispatch events (request lifecycle, DLP actions, fallbacks,
circuit-breaker transitions, HIT approvals) to subscribers without blocking the
hot path. The same event stream powers the SSE endpoint consumed by the TUI and
external observers. When the `watch` Cargo feature is disabled, [`EventBus`]
collapses to a zero-size no-op so emit sites stay branch-free.

## Public API

| Item | Location | Used by |
|------|----------|---------|
| `EventBus::new`, `emit`, `subscribe` | `mod.rs` | `server/mod.rs` (AppState), `server/dispatch/{mod,provider_loop,retry}`, `features/policies/stream/{mod,approval}` |
| `WatchEvent` (enum: `RequestStart`, `RequestEnd`, `RequestError`, `DlpAction`, `Fallback`, `CircuitBreaker`, `ProviderHealth`, `HitApprovalRequest`, `HitFlaggedContent`, `HitApprovalResponse`) | `events.rs` | `server/watch_sse.rs`, `tui.rs` |
| `DlpDirection` | `events.rs` | `features/dlp` emit sites |
| `tui::run` (feature `watch`) | `tui.rs` | `commands/watch.rs`, `main.rs` |

## Owns

- `mod.rs` — `EventBus` (Tokio broadcast, capacity 1024) and the no-op stub.
- `events.rs` — `WatchEvent` enum, the wire format for SSE and TUI.
- `tui.rs` — Ratatui-based interactive viewer (`watch` feature only).

## Depends on

- `tokio::sync::broadcast` — Lossy fan-out (drops oldest when subscribers lag).
- `chrono`, `serde` — Event timestamps and JSON wire format.
- `ratatui`, `crossterm` — TUI rendering (gated by `watch` feature).
- SSE delivery lives in `server/watch_sse.rs`, which subscribes to `EventBus`.

## Non-goals

- No persistence — events are ephemeral; the JSONL message tracer in
  `shared::message_tracing` covers durable capture.
- No filtering or aggregation — subscribers do that locally.
- No back-pressure on the dispatch path — slow subscribers lose events, by design.
- No HTTP transport here — `server/watch_sse.rs` owns the SSE endpoint.

## Tests

- Inline unit tests in `events.rs` cover `WatchEvent` serde round-trips.
- `EventBus` non-blocking emit/drop semantics are covered in
  `tests/integration_watch.rs`.
- TUI rendering is exercised manually via `grob watch`; no automated UI test.

## Related ADRs

- [ADR-0011 — Control engine and MCP tools](../../../docs/decisions/0011-control-engine-mcp-tools.md) (event surface alignment).
- [ADR-0006 — Policy engine, encrypted audit, HIT gateway](../../../docs/decisions/0006-policy-engine-encrypted-audit-hit-gateway.md) (HIT events emitted on this bus).

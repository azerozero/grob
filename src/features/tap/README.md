# features::tap

> Webhook tap that mirrors request and streaming-response bodies to an external observer URL.

## Purpose

Provides a fire-and-forget observability sink: every request and its assembled SSE response are POSTed to a configured webhook for debugging, replay, and downstream analysis. Uses an mpsc channel with `try_send` semantics so the hot path never blocks; events drop silently when the channel is full. Implements [`crate::traits::EventTap`] under the `tap` cargo feature.

## Public API

| Item | Location | Used by |
|------|----------|---------|
| `TapConfig` | `mod.rs` | `models::config`, server init |
| `TapEvent` (`Request`, `StreamChunk`, `StreamEnd`) | `mod.rs` | dispatch, retry, streaming layer |
| `TapSender` | `mod.rs` | `server::mod`, `server::dispatch::retry` |
| `init_tap` | `mod.rs` | `server::init` |
| `stream::TapStream<S>` | `stream.rs` | streaming response wrapping |

## Owns

- mpsc-backed background worker that accumulates chunks per `request_id`.
- Bounded channel with silent-drop semantics (no back-pressure on dispatch).
- HTTP POST with configurable timeout and optional request-body inclusion.
- Streaming wrapper that taps SSE bytes without buffering the full response in dispatch.

## Depends on

- `crate::traits::EventTap` — trait surface implemented here (under `feature = "tap"`).
- `bytes`, `reqwest`, `serde`, `tokio::sync::mpsc`, `tracing`.

## Non-goals

- Not a reliable event bus: dropped events are not retried or persisted.
- Not an authenticated audit log — see `security::audit` for tamper-evident records.
- Not a fan-out broker: a single webhook URL per instance.
- Does not parse SSE: bytes are forwarded as raw strings.

## Tests

- Unit tests in `mod.rs` (drop-when-full, default config).
- Integration: end-to-end webhook delivery is exercised via the dispatch streaming tests.

## Related ADRs

- None directly. Cross-reference [ADR-0017](../../../docs/decisions/0017-sokolsky-log-backend.md) for the broader observability stack.

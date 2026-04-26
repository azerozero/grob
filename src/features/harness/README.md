# features::harness

> Record-and-replay sandwich testing harness: capture raw HTTP traffic to "tape" files and replay it through grob with a mock backend.

## Purpose

Enables deterministic regression testing of the full dispatch pipeline (DLP, routing, cache, rate limiting, streaming) without live providers. The recorder captures requests and responses as JSONL tape entries; the driver replays them against a running grob instance backed by [`MockBackend`], producing a [`HarnessReport`] with latency stats and per-request diffs. Opt-in behind the `harness` cargo feature.

## Public API

| Item | Location | Used by |
|------|----------|---------|
| `Driver`, `DriverConfig` | `driver.rs` | `commands::harness` |
| `MockBackend`, `MockConfig` | `mock_backend.rs` | `server::mod` (when `harness` enabled) |
| `HarnessReport`, `LatencyStats` | `report.rs` | `commands::harness`, CI |
| `TapeEntry`, `TapeRequest`, `TapeResponse` | `tape.rs` | recorder + driver |
| `TapeWriter` | `tape.rs` | recording session |
| `TapeRecorderLayer`, `TapeRecorderService<S>` | `tape.rs` | tower middleware on the live server |
| `load_tape` | `tape.rs` | replay |

## Owns

- JSONL tape format and serialization.
- Tower middleware that records live traffic into a tape file.
- Mock provider backend that replays scripted responses (text, SSE, error).
- Replay driver that issues recorded requests, captures live output, computes diffs.
- Latency / error-rate aggregation in `HarnessReport`.

## Depends on

- `crate::providers::LlmProvider` — `MockBackend` implements it.
- `crate::models` — request and response types.
- `tower`, `axum`, `reqwest`, `serde`, `tokio`, `tracing`.

## Non-goals

- Not a load generator — see `commands::bench`.
- Not a fuzzer — tapes are deterministic recordings.
- Not redacting tapes at write time — captures must be sanitized manually before sharing (or run through DLP at replay).
- Not enabled by default: gated behind `--features harness`.

## Tests

- Unit tests in each submodule (tape round-trip, mock backend, report aggregation).
- Driver integration tests under `commands::harness`.

## Related ADRs

- None directly. The harness underpins the resilience strategy described in [ADR-0001](../../../docs/decisions/0001-static-config-no-hot-reload.md) (static config makes replay deterministic).

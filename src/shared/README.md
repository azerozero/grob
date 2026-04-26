# shared

> Cross-cutting modules used by multiple slices but not owned by any single feature.

## Purpose

`shared` hosts small, low-coupling utilities that several vertical slices depend on:
process lifecycle (PID, instance probing), networking (SO_REUSEPORT binding),
observability (OpenTelemetry bootstrap, message tracing), and optional ACME TLS.
Modules here have no business logic of their own — they exist so feature slices do
not duplicate plumbing or accidentally re-implement OS-level primitives.

## Public API

| Item | Location | Used by |
|------|----------|---------|
| `pid::write_pid`, `read_pid`, `cleanup_pid`, `pid_file_path` | `pid.rs` | `commands/{start,stop,status,restart}` |
| `pid::is_process_running`, `cleanup_legacy_pid`, `legacy_pid` | `pid.rs` | `server/lifecycle.rs`, `commands/start.rs` |
| `instance::is_instance_running`, `find_instance_pid`, `stop_instance` | `instance.rs` | `commands/{stop,restart,status,start}` |
| `net::bind_reuseport_std` | `net.rs` | `server/init.rs` (zero-downtime upgrade) |
| `otel::init_subscriber_with_otel`, `shutdown_otel` | `otel.rs` | `server/mod.rs`, `commands/start.rs` |
| `message_tracing::MessageTracer` | `message_tracing/mod.rs` | `server/dispatch/{mod,provider_loop,retry}` |
| `acme::resolve_cache_dir`, `build_acme_acceptor` | `acme.rs` (feature `acme`) | `server/init.rs` |

## Owns

- `acme.rs` — Automatic TLS via rustls-acme (feature-gated `acme`).
- `instance.rs` — HTTP `/health` probing for already-running instances.
- `message_tracing/mod.rs` — JSONL request/response trace pipeline with size rotation, optional zstd compression, optional AES-256-GCM encryption.
- `net.rs` — `SO_REUSEPORT` listener binding for graceful binary upgrades.
- `otel.rs` — `tracing_subscriber` + OTLP exporter wiring.
- `pid.rs` — PID file write/read/cleanup with cross-platform `is_process_running`.

## Depends on

- `crate::cli` — `TracingConfig`, `format_base_url`.
- `crate::storage::encrypt::StorageCipher` — Trace file encryption.
- `crate::models`, `crate::providers` — Trace entry shapes.
- `chrono`, `reqwest`, `serde`, `tokio`, `tracing`, `uuid`, `rustls-acme`, `nix`.

## Non-goals

- No business logic — all decisions belong in the calling slice.
- No public re-exports of provider, routing, or dispatch types.
- No persistent state beyond the PID file and trace JSONL.
- Not a place for new feature code: anything domain-specific belongs in `features/`.

## Tests

- Unit tests for `pid` and `net` are colocated in their respective files.
- `message_tracing` is exercised end-to-end in `tests/integration_tracing.rs` (rotation, compression, encryption round-trip).
- `instance` and `otel` are covered indirectly by `tests/server_lifecycle.rs`.

## Related ADRs

- [ADR-0001 — Static config, no hot reload](../../docs/decisions/0001-static-config-no-hot-reload.md) (PID lifecycle on reload).
- [ADR-0013 — Storage in files, no redb](../../docs/decisions/0013-storage-files-no-redb.md) (trace JSONL format).

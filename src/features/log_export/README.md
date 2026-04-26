# log_export

> Structured request/response log export to stdout, JSONL files, and HTTP sinks, with optional age-encrypted content envelopes.

## Purpose

`log_export` emits one `LogEntry` per completed request to every configured sink,
fire-and-forget, alongside the existing tap webhook. Sinks include stdout (for
Fluentd/Vector pipes), append-only JSONL files (per-file mutex), and HTTP POST.
When the operator opts in to content export, request/response bodies are
encrypted with [age] for a set of named auditor public keys; access policies
decide which auditors decrypt which sessions based on tenant, compliance tags,
and DLP signals.

[age]: https://age-encryption.org

## Public API

| Item | Location | Used by |
|------|----------|---------|
| `LogEntry` | `mod.rs` | `server/dispatch/{mod,retry}` |
| `LogExportConfig`, `LogSinkConfig`, `ContentMode` | `mod.rs` | `cli/mod.rs` (TOML) |
| `LogExporter::new`, `emit` | `mod.rs` | `server/mod.rs::AppState`, `server/dispatch/retry.rs` |
| `init_log_exporter` | `mod.rs` | `server/mod.rs` (startup wiring) |
| `encryption::encrypt_for_recipients`, `decrypt_with_identity`, `EncryptError` | `encryption.rs` | `mod.rs` (content envelope) |
| `access_policy::AccessPolicyConfig`, `AccessMatchRules`, `AccessContext`, `resolve_recipients` | `access_policy.rs` | `mod.rs` (recipient resolution) |

## Owns

- `mod.rs` — `LogEntry`, sink dispatch (`Stdout` / `File` / `Http`), exporter init.
- `encryption.rs` — age envelope encryption helpers (multi-recipient).
- `access_policy.rs` — Glob-matched policies that map request context to a
  union of auditor recipients.

## Depends on

- `serde`, `serde_json` — Wire format.
- `reqwest` — HTTP sink (shared client, async fire-and-forget).
- `tokio::fs`, `tokio::sync::Mutex` — Per-file serialized appends.
- `age` — Encryption envelope.
- `tracing` — Sink failure logs (warn level).

## Non-goals

- No durability guarantees — emit is best-effort and never blocks dispatch.
- No retry, queuing, or back-pressure — operators run a sidecar collector for that.
- No log aggregation, search, or rotation — file rotation is the operator's job.
- No PII redaction — that is `features/dlp`'s responsibility before this layer
  sees the entry.
- No spend or billing semantics — see `features/token_pricing`.

## Tests

- `mod.rs::tests` covers config defaults, serde round-trips for all sink kinds,
  init guard rails (disabled / no sinks), and `LogEntry` JSON shape.
- `encryption.rs::tests` covers age round-trip with multiple recipients and the
  empty-recipients error path.
- `access_policy.rs::tests` covers tenant glob matching, compliance OR-matching,
  DLP signal matching, and recipient union semantics.

## Related ADRs

- [ADR-0017 — Sokolsky log backend](../../../docs/decisions/0017-sokolsky-log-backend.md) (target sinks and content envelope strategy).
- [ADR-0006 — Policy engine, encrypted audit, HIT gateway](../../../docs/decisions/0006-policy-engine-encrypted-audit-hit-gateway.md) (encrypted-content posture).
- [ADR-0013 — Storage in files, no redb](../../../docs/decisions/0013-storage-files-no-redb.md) (JSONL as the on-disk shape).

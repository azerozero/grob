# ADR-0004: Persistent monthly spend tracking in local JSON

## Status

Accepted

## Context and Problem Statement

Grob needs to enforce monthly budget limits across server restarts. Where and how should spend data be persisted?

## Decision Drivers

- No external database dependency (grob is a local proxy)
- Must survive server restarts
- Must be human-readable for debugging
- Monthly reset semantics

## Considered Options

- SQLite database
- JSON file in `~/.grob/spend.json`
- In-memory only (reset on restart)

## Decision Outcome

Chosen option: "JSON file in `~/.grob/spend.json`", because it requires zero dependencies, is trivially inspectable, and supports the single-user local proxy use case. Monthly spend resets are handled by comparing the stored month against the current month.

### Consequences

- Good, because zero dependencies — no SQLite, no database driver
- Good, because human-readable — users can inspect and manually reset spend
- Good, because atomic write with temp file + rename prevents corruption
- Bad, because not suitable for multi-instance deployments (single file, no locking between processes)
- Bad, because no historical analytics (only current month is stored)

### Confirmation

Spend tracking is implemented in `src/features/token_pricing/spend.rs`. File writes use write-to-temp-then-rename pattern for atomicity.

---
status: accepted
date: 2026-04-09
deciders: [azerozero, architect]
consulted: []
informed: []
---

> **Status note (2026-04-28)**: status reverted from `done` to `accepted`.
> redb persistence remains the active storage substrate in v0.36.x — `GrobStore`
> in `src/storage/mod.rs` is still the live code path and `~/.grob/spend/*.jsonl`
> has not yet been written. The A-7 storage refactor is deferred to v0.37+.
> The decision recorded here remains binding; only the implementation flag has
> been corrected to reflect that no production code matches the design yet.

# ADR-0013: Storage on Atomic Files + Append-Only Journal — No redb

## Context and Problem Statement

Grob currently persists state (monthly spend, OAuth tokens, virtual keys, policy snapshots) in an embedded `redb` database under `~/.grob/grob.db`. redb was chosen for ACID guarantees and compact on-disk representation. As of v0.34, spend tracking was also moved into redb.

Operational experience over the v0.30–v0.35 window has surfaced three issues that redb does not address well:

1. **Opacity.** A user cannot `less ~/.grob/grob.db`. Debugging a spend discrepancy requires launching Grob with a debug flag or writing a redb inspection tool. Third-party auditors cannot read the state without a custom parser.
2. **Portability to air-gapped / minimal targets.** Several client conversations have raised deployments where the host has *no* local filesystem in the classical sense (ephemeral compute, read-only rootfs, raw block device). redb assumes a real filesystem.
3. **Crash-recovery narrative.** The ACID story is hard to explain to a security reviewer without showing them redb internals. An append-only JSONL journal is trivially auditable: "the last line may be truncated on crash; every prior line is immutable."

Decision D-03 of the 2026-04-08 architect brief explicitly said: "Storage = atomic files + append-only journal. redb out. No legacy migration (few users)."

## Decision Drivers

- **Human-readable format** — `less`, `grep`, `jq` must work on the live state.
- **Third-party auditability** — no binary parser required. Anyone with a shell can verify spend or audit trail.
- **Crash safety without a DB engine** — `open(O_APPEND) + write + fsync` is a well-understood primitive.
- **Cap on disk usage** — D-09 mandates a 50 MB default cap with LRU purge of old snapshots and a stdout fallback when saturated.
- **Minimal-target viability** — must survive on ephemeral / read-only rootfs hosts by falling back to stdout.
- **No migration code** — the current user base is small; a clean break is cheaper than a migration path.

## Considered Options

1. **Keep redb, add an export command** — addresses auditability superficially. Still binary on disk. Still coupled to the filesystem assumption.
2. **Replace with SQLite** — shifts the problem: still binary, still requires a parser, but at least SQLite is ubiquitous. Rejected because the operational complexity is roughly the same for the same opacity.
3. **Atomic files + append-only JSONL journal** — human-readable, trivial crash model, fits air-gapped targets.
4. **Flush-only stdout** — pure streaming, no on-disk state at all. Too radical for the normal laptop/server use case.

## Decision Outcome

**Chosen: option 3, with stdout fallback for saturation (from option 4).**

### Layout

```
~/.grob/
├── spend/
│   ├── 2026-04.jsonl            # month in progress, append-only
│   ├── 2026-03.jsonl.sealed     # prior month, sealed (one kept per D-04)
│   └── index.json               # metadata + sealed-file hashes
├── tokens/
│   ├── anthropic.json.age       # age-encrypted
│   └── openai.json.age
├── config/
│   ├── grob.toml
│   └── presets/
└── audit/
    └── 2026-04.jsonl            # audit trail (goes to Sokolsky in production, see ADR-0017)
```

### Append-only spend journal

Each event is a self-contained JSON object on its own line:

```json
{"ts":"2026-04-09T14:22:31Z","kind":"spend","provider":"anthropic","model":"claude-opus-4-6","input_tok":1234,"output_tok":456,"cost_usd":0.023,"request_id":"req_abc"}
```

Invariants:

1. **Append-only**: `O_APPEND | O_CLOEXEC`, `fsync` on flush. No seek, no rewrite.
2. **One event per line** — newline-delimited JSON. Parsing is `split('\n')`.
3. **Monotonic timestamps** within a file, enforced at write time.
4. **Rollover at month boundary**: `rename(current.jsonl, previous.jsonl.sealed)` + hash (SHA-256) recorded in `index.json`.

### Snapshot policy (D-04)

Only the **current month** and **one sealed previous month** are kept unless `[compliance] retention_months > 1` is set. LRU purge deletes older sealed files first (never the current month).

### Storage cap (D-09)

`[compliance] max_storage_mb = 50` is the default. When `~/.grob/spend/` exceeds the cap:

1. Log a warning.
2. Emit a metric `grob_storage_saturation_total`.
3. Purge the oldest sealed files.
4. If the current month alone exceeds the cap → **fallback to stdout JSON flush**. No corruption, no data loss in the audit sense (stdout is piped to the collector).

### Atomic writes for non-append files (tokens, config)

```
write(tmp) → fsync(tmp) → rename(tmp, final)
```

`rename(2)` is atomic on ext4 / xfs / btrfs. `O_TMPFILE` is used where available.

### No migration

Existing redb users lose their state on upgrade. This is acceptable because:

- The current user base is small (no public release prior to v0.36).
- The only valuable carryover is the current-month spend total. A `grob spend --from-redb` one-shot tool may be shipped as a separate helper if needed, but it is not on the default upgrade path.

## Consequences

### Positive

- Anyone can inspect, grep, and audit the state without tooling.
- Crash safety model is trivially explainable to a security reviewer.
- Air-gapped / minimal-target deployments become viable via stdout fallback.
- Removes one binary-format dependency (`redb`) from the manifest.
- Journal lines are naturally shipable to log aggregators.

### Negative

- O(lines) rebuild at startup vs. O(1) index lookup in redb. Measured at < 10 ms for 10 k events, but will grow with usage. Mitigation: monthly sealing caps the live file.
- JSONL is verbose on disk. Expect ~3× the size of equivalent redb state. Mitigation: sealed files are compressible; LRU + storage cap contain growth.
- Concurrent writers to the same file would corrupt it. Grob is a single-process server so this is not currently a concern, but a future multi-process mode would need a lock or a per-PID file.
- Loss of ACID across files (e.g., updating config + rotating a token in one "transaction"). Grob today does not need cross-file ACID. If it does in the future, this ADR must be revisited.

### Neutral / to watch

- Third-party tooling (log shippers, backup scripts) integrates better with JSONL than with redb. Expected to be a net positive.
- The tokens file remains encrypted — see the token store doc. Encryption stays outside this ADR.

## Follow-ups and related ADRs

- Linked chantier: **A-7 Storage refactor files**, blocked on validation pause after W-1..W-4 merges.
- [ADR-0004](0004-persistent-spend-tracking.md) — superseded in spirit (same goal, different substrate). A cross-reference will be added there once A-7 lands.
- [ADR-0017](0017-sokolsky-log-backend.md) — the production audit path writes to Sokolsky; the local `audit/*.jsonl` file is a fallback for dev.
- Obsidian concept: `50 - Concepts/Storage Files Biomimetique.md`.
- Architect decisions: D-03, D-04, D-09.

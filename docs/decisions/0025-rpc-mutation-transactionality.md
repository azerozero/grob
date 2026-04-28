---
status: proposed
date: 2026-04-28
deciders: [azerozero]
consulted: []
informed: []
supersedes: []
related: [ADR-0001, ADR-0006, ADR-0011, ADR-0017]
---

# ADR-0025: RPC Mutation Transactionality and In-Flight Visibility

## Context and Problem Statement

ADR-0001 established the static-config-with-atomic-reload model: the server
loads TOML on startup, and the `/api/config/reload` endpoint atomically
swaps reloadable state (router, provider registry, model index) without
restart. In-flight requests continue on the old snapshot via a single
`snapshot()` mechanism that captures the configuration version in scope at
the start of dispatch.

A new class of mutation has been growing under issue #228 — RPC calls that
modify server state at runtime *without* going through `config/reload`.
Examples include:

- `config/set` — set a single config key (e.g. enable a feature flag).
- `pledge/set` — narrow the active pledge.
- `tools/enable`, `tools/disable` — toggle a tool in the matrix
  ([ADR-0011](0011-control-engine-mcp-tools.md)).
- `policy/upsert`, `policy/delete` — mutate an entry in the policy engine
  ([ADR-0006](0006-policy-engine-encrypted-audit-hit-gateway.md)).

These mutations work in-memory today; their persistence semantics, ordering
guarantees, and audit footprint have never been recorded as a binding
decision. Operators using them cannot answer the following questions
without reading source code:

1. **Visibility.** A mutation lands while a request is mid-dispatch. Does
   the in-flight request see the pre-mutation state, the post-mutation
   state, or some interleaving of both?
2. **Persistence.** A mutation succeeds and the operator restarts the
   server. Does the mutation survive the restart, or is the next startup
   loaded from disk-only state? Today the answer is "depends on the
   namespace", and is not documented.
3. **Concurrency.** Two mutations land at the same time on different
   namespaces (`config/set` and `pledge/set`). Do they serialize behind a
   single global mutex (slow), or do they interleave (correctness risk)?
4. **Audit.** Does every mutation appear in the Sokolsky audit log
   ([ADR-0017](0017-sokolsky-log-backend.md))? Today some do, some do
   not; the inventory is implicit.

These ambiguities have not produced a known incident, but they will: an
operator writing automation against the RPC surface assumes one set of
semantics, and the next refactor changes them silently.

## Decision Drivers

- **Compatibility with ADR-0001's snapshot model.** Whatever this ADR
  chooses must reuse the existing `snapshot()` machinery. Inventing a
  second consistency primitive doubles the surface to reason about.
- **No surprise to operators.** A mutation that succeeds via RPC must
  either persist or fail loudly; "succeeded but lost on restart" is not
  acceptable.
- **Bounded contention.** A global mutex across all RPC mutations is the
  simplest model but serializes unrelated namespaces unnecessarily.
- **Audit completeness.** Every mutation that changes operator-observable
  state must produce an entry in the audit log. Mutations that *do not*
  change state (e.g. a no-op policy upsert) may emit a tagged event but
  should not flood the log.
- **Bounded blast radius.** A failed mutation must not leave the server
  in a half-mutated state. Either the in-memory swap and the disk write
  both succeed, or neither does.

## Considered Options

1. **Eventually-consistent — in-memory only, write to disk in the
   background.** Cheap, but mutations can be lost on restart. Reject:
   violates the "no surprise" driver.
2. **Restart-required for every mutation.** Treat every RPC mutation as
   "edit a config file and restart". Cleanest semantically but makes the
   RPC surface useless for the live-tuning workflows it was built for.
3. **Atomic in-memory swap + atomic disk persist + per-namespace mutex
   (chosen).** Mutations apply via a critical section that updates the
   in-memory snapshot and writes to disk in a single atomic operation;
   different namespaces can mutate in parallel.
4. **Two-phase commit across namespaces.** Mutations to multiple
   namespaces in one RPC call become a transaction that fully succeeds
   or fully fails. Reject: complexity is not justified by today's
   workload (mutations are single-namespace in 100% of observed RPC
   traffic).

## Decision Outcome

**Chosen: option 3 — atomic in-memory swap + atomic disk persist +
per-namespace mutex.** Visibility reuses ADR-0001's `snapshot()`;
persistence happens before the RPC returns success; per-namespace
serialization permits parallel writes across namespaces while keeping a
single namespace's writes ordered.

### Visibility model

In-flight requests captured a `snapshot()` at dispatch start (per
ADR-0001). They keep that snapshot for the request's lifetime. New
requests entering dispatch *after* the swap point pick up the new
snapshot. Concretely:

```text
                    │
   request A ──────►│   captures snapshot v1
                    │
   RPC mutation ────►│   atomic swap: v1 → v2
                    │
   request B ──────►│   captures snapshot v2
                    │
                    ▼
                   time
```

Request A finishes on v1, even if v2 is the new "live" version. This
matches the existing `/api/config/reload` semantics exactly — the RPC
mutation path is just a smaller-grained variant.

The implementation surface is `ApplicationState::snapshot()` already
in `src/server/mod.rs`. RPC mutations call a private
`apply_mutation(namespace, action)` helper that:

1. Acquires the namespace mutex.
2. Computes the proposed new state.
3. Performs the atomic in-memory swap (pointer update on the
   ApplicationState arc-swap).
4. Writes the proposed state to disk.
5. Releases the mutex.

Failure between steps 3 and 4 (e.g. disk write fails) **rolls back the
in-memory swap** before returning an error. The RPC client either sees
success-with-persistence or failure-with-no-state-change.

### Persistence semantics

Per-namespace persistence destinations:

| Namespace | Disk artifact | Format |
|---|---|---|
| `config/*` | `~/.grob/config.toml` (rewritten atomically via `write_temp + rename`) | TOML |
| `pledge/*` | `~/.grob/pledge/active.toml` | TOML |
| `tools/*` | `~/.grob/tools/matrix.toml` | TOML |
| `policy/*` | `~/.grob/policies/<id>.toml` (one file per policy) | TOML |

All writes use the atomic `write_temp + fsync + rename` pattern from
ADR-0013 (or its successor implementation). The RPC returns success
only when `rename(2)` completes; any earlier failure propagates as an
error, and the in-memory snapshot is rolled back.

A server restart loads from disk and arrives at the same state the
client observed at the last successful mutation. There is no "in-memory
only" state for RPC mutations — by design.

### Concurrency model — per-namespace mutex

A single global mutex would serialize a `config/set` behind a
`pledge/set`, even though they touch unrelated state. This is a
performance cost without a correctness benefit. Instead:

- One `tokio::sync::Mutex` per namespace (`config`, `pledge`, `tools`,
  `policy`).
- A mutation acquires only its namespace's mutex.
- Mutations in different namespaces run in parallel.
- Mutations in the same namespace serialize in arrival order.

Cross-namespace consistency is *not* guaranteed by this ADR. If a
client wants to atomically update a config flag and a policy entry,
the client either accepts an interleaved view or uses
`/api/config/reload` (which already provides a single global swap).

### Audit log entry

Every successful mutation emits one Sokolsky audit event:

```rust
AuditEvent::RpcMutation {
    namespace: String,    // "config", "pledge", "tools", "policy"
    action: String,       // "set", "upsert", "delete", "enable", "disable"
    target: String,       // resource id (key path, policy id, tool id)
    before_hash: [u8; 32], // SHA-256 of pre-mutation namespace state
    after_hash: [u8; 32],  // SHA-256 of post-mutation namespace state
    actor: ActorId,        // who issued the RPC (token id, OAuth subject, etc.)
    timestamp: SystemTime,
}
```

A no-op mutation (e.g. `config/set` with the same value already in
state) emits an event with `before_hash == after_hash`. Auditors can
filter these out; the event log preserves the call attempt for forensic
purposes.

Failed mutations also emit an event (`RpcMutationFailed { namespace,
action, error }`) so that an operator scripting against the RPC can
correlate a 5xx with the audit log without grepping server logs.

### Failure modes and rollback

| Failure point | Behaviour |
|---|---|
| Mutex acquisition (deadlock impossible — single mutex per call) | N/A |
| Validation of new state (e.g. malformed TOML produced by mutation) | Reject before swap; no in-memory or disk change. |
| Atomic in-memory swap | Cannot fail (arc-swap is infallible). |
| Disk write fails (`fsync`, `rename`) | Roll back in-memory swap to the pre-mutation pointer; return 500 to RPC client; emit `RpcMutationFailed` audit event. |
| Audit emission fails | Mutation has succeeded on disk and in memory; audit-emit failure is logged but does not roll back. (Mirrors the existing reload path's audit semantics.) |

The audit-emit failure case is a deliberate carve-out: if Sokolsky is
unreachable, mutations should not be blocked. The local stderr/journal
fallback receives the event and an alert is emitted by the audit
subsystem.

### What this ADR does *not* cover

- **Cross-namespace transactions.** As noted, a multi-namespace mutation
  is not supported; clients should use `/api/config/reload` for that
  use case.
- **Optimistic concurrency / CAS.** Conflicts within a namespace
  serialize; clients are not handed a version token to detect
  concurrent writers. If contention becomes a problem, a future ADR can
  add it.
- **Bulk import.** A client wishing to import a large policy set should
  build a TOML file and call `/api/config/reload`, not script
  thousands of `policy/upsert` RPCs.

## Consequences

### Positive

- **Operator-visible state is consistent across restarts.** A mutation
  that returns success is durable.
- **Audit log is complete.** Every state-changing RPC and every failed
  attempt produces an entry.
- **Bounded contention.** Per-namespace mutexes prevent a slow `policy`
  write from blocking a `config` flag flip.
- **Compatibility with ADR-0001.** The RPC surface reuses the existing
  snapshot model rather than inventing parallel machinery.

### Negative

- **One mutex per namespace** is a small surface to maintain. New
  namespaces must be added to the mutex map at registration time.
- **Disk write happens inside the RPC critical section.** This makes
  RPC latency depend on disk fsync. Acceptable for the workloads RPC
  was built for (live tuning, ~100/min); not acceptable for bulk
  import (which uses `config/reload` instead).
- **No cross-namespace atomicity.** Documented limitation; clients
  needing it use `config/reload`.

### Confirmation

- **Snapshot test** (`tests/rpc_mutation_snapshot.rs`) asserts an
  in-flight request started before a mutation observes the
  pre-mutation namespace state for its full lifetime.
- **Persistence test** (`tests/rpc_mutation_persistence.rs`) starts a
  server, issues a mutation, restarts, and asserts the new state is
  loaded.
- **Concurrency test** (`tests/rpc_mutation_concurrency.rs`) issues
  parallel mutations across namespaces and asserts they complete
  concurrently; same-namespace mutations serialize in arrival order.
- **Audit test** (`tests/rpc_mutation_audit.rs`) asserts every
  successful mutation emits exactly one `RpcMutation` event with
  matching `before_hash` / `after_hash`.
- **Failure test** (`tests/rpc_mutation_disk_failure.rs`) injects a
  disk-write failure, asserts the in-memory state is rolled back and
  the RPC returns 500.

## Pros and Cons of the Options

### Option 1 — Eventually-consistent

**Pros:** lowest RPC latency.
**Cons:** mutations can be lost on restart; violates the "no surprise"
driver.

### Option 2 — Restart required

**Pros:** zero new code; entirely covered by `config/reload`.
**Cons:** RPC surface becomes useless for live tuning.

### Option 3 — Atomic in-memory + disk + per-namespace mutex (chosen)

**Pros:** explicit semantics; reuses ADR-0001 snapshot model; bounded
contention; full audit.
**Cons:** disk fsync inside critical section; one mutex per
namespace.

### Option 4 — Two-phase commit

**Pros:** strong cross-namespace atomicity.
**Cons:** complexity unjustified by current traffic; existing
`config/reload` covers the use case.

## More Information

### Related ADRs

- [ADR-0001](0001-static-config-no-hot-reload.md) — defines the
  snapshot model that this ADR extends.
- [ADR-0006](0006-policy-engine-encrypted-audit-hit-gateway.md) —
  policy engine is one of the namespaces affected.
- [ADR-0011](0011-control-engine-mcp-tools.md) — tool matrix is one of
  the namespaces affected.
- [ADR-0017](0017-sokolsky-log-backend.md) — destination for
  `RpcMutation` audit events.

### Reference issue

- Issue #228 — "RPC mutations: persistence and concurrency". This ADR
  is the formal answer.

### Migration plan

1. Land this ADR (`status: proposed`).
2. Audit existing RPC handlers for namespace coverage; add
   `apply_mutation` wrappers where missing.
3. Add the four `tokio::sync::Mutex` instances to the
   `ApplicationState`.
4. Wire `RpcMutation` audit event into the Sokolsky pipeline.
5. Land tests listed under *Confirmation*.
6. Promote ADR to `accepted` when all tests pass in CI.

---
status: accepted
date: 2026-04-09
deciders: [azerozero, architect]
consulted: []
informed: []
---

# ADR-0017: Sokolsky LogBackend — Cross-Plane Audit with N-of-N Signatures

## Context and Problem Statement

Grob's audit trail must satisfy three requirements that are in tension:

1. **Non-repudiation.** A decision made by Grob (a policy verdict, a tool filter, a mode routing choice, a HIT approval) must be impossible for the operator to silently retract or retroactively edit.
2. **Compromise containment.** If the App plane (the Grob server process) is compromised, the attacker must not be able to forge past audit entries. The audit plane must be isolatable.
3. **Operational simplicity.** The audit sink must not require a specialized infrastructure team to run. It must scale from "a dev on a laptop" to "a 10-node production cluster".

Before this ADR, Grob had only a **single-plane** audit log: the `AuditLog` module in `src/security/audit_log.rs` wrote to a local file (or to stdout, depending on config). This is sufficient for dev but insufficient for any production scenario where Grob itself could be compromised.

A related gap: [ADR-0016](0016-decision-tokens-transparent-routing.md) introduces Decision Tokens as the emission format for every policy decision, but does not specify **where they go**. That gap is closed here.

Sokolsky is the name given to a **multi-plane log collector** with N-of-N cross-plane signatures, developed incrementally across two PRs:

- **PR #90** (`00189a0 feat(server): add LogBackend trait and sokolsky-collector integration`) introduced the `LogBackend` trait and the initial sokolsky-collector integration.
- **PR #94** (`a15cd0e feat(features): add sokolsky advanced scenarios T-SOK-5 to T-SOK-8`) added advanced scenarios (cross-plane replay resistance, backpressure, mTLS wiring, witness quorum).

## Decision Drivers

- **Defense in depth across trust domains.** Separate planes, separate keys, separate operators.
- **Unanimity, not majority.** An N-of-N quorum means a single compromised witness cannot unilaterally commit an audit entry. Majority would let an attacker flip 2 of 3 and win.
- **Standard Grob trait pattern.** Fit into [Architecture Lego](../../README.md) — another brick behind a trait, swappable for stdout or file backends in dev.
- **mTLS between planes.** Each plane has its own certificate chain. Compromise of the App plane does not leak the Audit plane's private key.
- **Replay resistance.** Timestamp + nonce per token, short validity window (default 60 s).
- **Backpressure fail-closed.** If a witness is unreachable, the decision is deferred (HIT) or refused — never silently committed.

## Considered Options

1. **Keep the single-plane local log** — insufficient for production.
2. **Ship audit entries to an external SIEM** — solves durability but does not prevent forgery from within the App plane.
3. **Sign audit entries with a single Grob key** — same issue; the key lives with the compromised plane.
4. **Multi-plane witnesses with N-of-N signatures** — the chosen approach.

## Decision Outcome

**Chosen: option 4 — multi-plane, N-of-N, mTLS.**

### Plane model

Three logical planes:

- **Machine plane** — the physical / VM host. Witness controlled by the infra team.
- **App plane** — the Grob process itself. Witness runs inside the server.
- **Audit plane** — a separate audit process with its own cert chain and storage. Operated by the compliance team (or a third party in the future).

An audit entry (a Decision Token from [ADR-0016](0016-decision-tokens-transparent-routing.md)) is considered **committed** only when **all** required planes have signed it. Default required set: `[Machine, App, Audit]`. Operators can reduce this for dev (e.g., `[App]` only) but must explicitly opt out of the protection.

### Trait and implementations

Defined in `src/features/log_backend/mod.rs`:

```rust
#[async_trait]
pub trait LogBackend: Send + Sync {
    async fn query(&self, q: &LogQuery) -> Result<Vec<LogEntry>, LogBackendError>;
    async fn write(&self, entry: &LogEntry) -> Result<(), LogBackendError>;
}
```

Implementations:

- `StdoutLogBackend` — dev, flushes JSON lines to stdout. No signatures.
- `FileLogBackend` — laptop / small team, writes to a local JSONL file (see [ADR-0013](0013-storage-files-no-redb.md)).
- **`SokolskyLogBackend`** — the production backend. `src/features/log_backend/sokolsky.rs` (~480 LOC). Queries a `sokolsky-collector` endpoint over HTTPS/mTLS, verifies N-of-N cross-plane signatures on read, and fans out writes to all configured witnesses.

### Sokolsky configuration

```rust
pub struct SokolskyConfig {
    pub endpoint: String,              // collector URL
    pub mtls_cert: Option<String>,
    pub mtls_key: Option<String>,
    pub mtls_ca: Option<String>,
    pub required_planes: Vec<Plane>,   // default: [Machine, App, Audit]
}
```

Required-planes defaulting to all three matches the "unanimity, not majority" driver. An operator who sets this to two planes is accepting reduced protection; this is logged as a warning on startup.

### Read path: signature verification

When Grob reads an audit entry (e.g., via the `watch` SSE stream or a compliance query), the `SokolskyLogBackend` re-verifies the cross-plane signatures before returning the entry. An entry with a missing or invalid signature is returned with `SignatureStatus::Invalid` and clearly marked in the response.

### Advanced scenarios (PR #94, T-SOK-5 to T-SOK-8)

- **T-SOK-5** — cross-plane replay resistance: nonce + short validity window.
- **T-SOK-6** — backpressure: if a witness is slow, queue up to a bounded depth, then fail-closed.
- **T-SOK-7** — mTLS rotation: witness certs can rotate without downtime.
- **T-SOK-8** — witness quorum introspection: an operator can query which planes signed each entry.

### Scope: trait + collector integration, not the collector itself

Grob ships the **client** side: the trait, the stdout / file / sokolsky implementations, the configuration. The `sokolsky-collector` daemon is a **separate project**. Grob treats it as an external dependency reached over HTTPS/mTLS. The collector's internals are out of scope for this ADR.

## Consequences

### Positive

- Audit entries cannot be silently modified by a compromise limited to the App plane.
- N-of-N unanimity eliminates the majority-flip attack.
- The trait lets dev, small team, and production share the same emitting code with different sinks.
- Composable with [ADR-0016](0016-decision-tokens-transparent-routing.md): one emits, the other transports.
- The mesh layer ([ADR-0014](0014-mesh-wireguard-kiss.md)) provides the transport substrate.

### Negative

- Production deployment requires running a `sokolsky-collector` daemon — one more moving part.
- N-of-N means a single failing witness blocks progress (fail-closed). This is a deliberate safety choice but has operational impact: witnesses must be watched.
- mTLS rotation on the hot path is non-trivial. T-SOK-7 covers the basics; corner cases will surface in production.

### Neutral / to watch

- The current default of `[Machine, App, Audit]` assumes 3 planes. If a customer wants 5 planes for stronger isolation, the trait supports it but the collector must as well.
- The `sokolsky-collector` interface is versioned. Breaking changes require a coordinated deployment.
- This ADR does not specify a durable storage format for committed entries — that is the collector's responsibility.

## Follow-ups and related ADRs

- [ADR-0016](0016-decision-tokens-transparent-routing.md) — the tokens that flow through this backend.
- [ADR-0014](0014-mesh-wireguard-kiss.md) — the mesh transport substrate.
- [ADR-0013](0013-storage-files-no-redb.md) — local fallback backend for the audit pathway.
- [ADR-0006](0006-policy-engine-encrypted-audit-hit-gateway.md) — the policy engine that emits tokens via this backend.
- Code: `src/features/log_backend/mod.rs` (trait), `src/features/log_backend/sokolsky.rs` (~480 LOC, implementation).
- PRs: azerozero/grob#90 (trait + integration), azerozero/grob#94 (advanced scenarios).
- Obsidian concept: `50 - Concepts/Decision Tokens et Sokolsky.md`.

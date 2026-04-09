---
status: accepted
date: 2026-04-09
deciders: [azerozero, architect]
consulted: []
informed: []
---

# ADR-0016: Decision Tokens — Transparent Agent Routing

## Context and Problem Statement

Grob sits between a "boss" (a human operator or an orchestrating script) and one or more "agents" (LLMs doing the work). As Grob routes requests through its policy layers (DLP, Pledge, HIT), decisions get made: allow, warn, deny, route to training backend vs. real backend, etc.

Two constraints apply:

1. **The agent must not see the routing logic.** The LLM should experience a clean request/response. It must not learn that a decision token exists, which backend it was routed to, or what policy matched. Revealing the routing creates a new attack surface (the LLM can try to reason about the token and bypass it).

2. **Auditability must be preserved.** Every routing decision must leave a trace that the boss and auditors can inspect after the fact. Without this, Grob cannot make compliance claims.

A specific use case made this urgent: the **training vs live** mode. A trading agent (or any agent with real-world consequences) must be testable in "paper" mode before graduating to "live" mode. The mode is a property of the session, not the agent — the agent must behave identically in both modes, unaware of which one is active. The orchestrator decides the mode; Grob routes accordingly.

## Decision Drivers

- **Agent-invisible routing.** The token is never reflected in the response body, headers, or tool-call arguments.
- **Boss-visible audit.** The orchestrator can read the token (or a summary of it) via a separate audit channel.
- **Integrity.** The token is signed / hashed. A compromised agent cannot forge one to change its own routing.
- **Audience scoping.** A token carries a glob pattern describing which plans may read it (`audit/*`, `compliance/*`).
- **Training / live mode.** First-class claim, not an ad-hoc header.
- **Simple on the hot path.** Emitting a token must be fast (no network calls, no HSM round-trip). Verification can be heavier.

## Considered Options

1. **Header on the HTTP request** — simple, but the agent can read HTTP headers if it has tool access.
2. **Environment variable scoped to the agent's subprocess** — leaks into process listings, still readable from within the subprocess.
3. **Opaque MCP-style token** — emitted by the boss agent, verified by Grob, never echoed back to the target agent. Kept out-of-band on the audit channel.

## Decision Outcome

**Chosen: option 3 — opaque, boss-emitted, agent-invisible token.**

### Implementation

Implemented in `src/features/policies/decision_token.rs` (365 LOC). Initial commit: `6fd52fc feat(policies): add decision token type for transparent agent routing` (PR azerozero/grob#88, v0.35.0).

Core types:

```rust
pub enum DecisionMode {
    /// Routes to paper / simulated backend.
    Training,
    /// Routes to real / production backend.
    Live,
}

pub struct DecisionToken {
    pub request_id: String,
    pub policy_id: String,
    pub verdict: Verdict,          // Allow | Warn | Deny
    pub reason_code: String,
    pub audience_glob: String,     // e.g. "audit/*"
    pub mode: DecisionMode,
    pub timestamp: OffsetDateTime,
    pub signature: [u8; 32],       // SHA-256 over canonical serialization
}
```

### Emission points

- **DLP scan** emits a token when it detects (or fails to detect) a pattern.
- **Pledge filter** emits a token for each tool it strips.
- **HIT gateway** emits a token for each approval / denial decision.
- **Mode router** emits a token carrying the training/live selection.

### Invariants enforced in code

1. **Agent-visible view stripping** — `DecisionToken::to_agent_visible()` returns a view with `signature`, `audience_glob`, and `policy_id` zeroed out. Only this view may ever touch the agent's payload.
2. **Integrity verification** — `DecisionToken::verify()` recomputes the SHA-256 hash over the canonical serialization and rejects mismatches.
3. **Audience glob** — `"audit/*"` means plans whose name matches the glob can deserialize the token; others receive an opaque blob.
4. **Mode claim** — `DecisionMode::Training | Live` parsed from the `mode` string, empty/unknown variants rejected.

### Routing use

The mode router is a small function `route_by_mode(request, token) -> Backend` that maps:

- `DecisionMode::Training` → the configured paper backend (e.g., a mock provider).
- `DecisionMode::Live` → the real provider.

The agent sees neither the token nor the routing choice. The response is identical in shape either way.

### Composition with audit

Decision Tokens are the **emission format**; [ADR-0017 Sokolsky LogBackend](0017-sokolsky-log-backend.md) is the **transport and durability layer**. Every token flows into Sokolsky witnesses across the Machine / App / Audit planes. An N-of-N cross-plane signature is required before a token is considered committed.

## Consequences

### Positive

- Clean separation between what the agent experiences (a response) and what the boss/audit sees (a full decision trail).
- Training vs live is a first-class concept — no ad-hoc flags spread across config files.
- Tamper detection is built in (hash verification).
- Composable with any future policy layer: the layer just emits a token.

### Negative

- Every decision emits a token, so high-QPS deployments produce many tokens. Mitigation: batch them for transport to Sokolsky.
- Audience glob adds some complexity for operators. Must be documented in the reference.
- The "invisible to agent" invariant is enforced only by code discipline — a bug that accidentally echoes a token into a response would break the guarantee. Mitigation: targeted insta-snapshot tests that assert tokens never appear in agent-visible output.

### Neutral / to watch

- The signature is SHA-256 over canonical bytes, not a true cryptographic signature. That is sufficient for **integrity** within a trust domain. For cross-domain signing (e.g., federated multisig HIT in the deleted ADR-0007), an Ed25519 signature would be added later as an optional field.
- The `mode` claim is currently binary (training/live). A future "staging" mode is conceivable; the enum is `#[non_exhaustive]` to allow extension.

## Follow-ups and related ADRs

- [ADR-0017](0017-sokolsky-log-backend.md) — cross-plane audit transport.
- [ADR-0015](0015-indirect-prompt-injection-coverage.md) — DLP scans emit decision tokens.
- [ADR-0009](0009-pledge-structural-tool-filtering.md) — Pledge filter emits decision tokens.
- [ADR-0006](0006-policy-engine-encrypted-audit-hit-gateway.md) — HIT gateway is the primary emitter today.
- Code: `src/features/policies/decision_token.rs` (365 LOC).
- PR: azerozero/grob#88 (v0.35.0).
- Obsidian concept: `50 - Concepts/Decision Tokens et Sokolsky.md`.

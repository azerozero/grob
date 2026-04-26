# features::policies

> Unified policy engine, HIT (Human-In-The-Loop) gateway, decision tokens, and quorum/multisig approval.

## Purpose

Evaluates a [`context::RequestContext`] against glob-based [`config::MatchRules`] to produce a [`resolved::ResolvedPolicy`] with overrides for DLP, rate limiting, routing, budget, log export, and HIT authorization. Enforces per-action approval flows (single-approver, multisig, quorum) and binds approved decisions to short-lived signed tokens that route requests transparently to the right backend.

## Public API

| Item | Location | Used by |
|------|----------|---------|
| `PolicyMatcher` | `matcher.rs` | `server::dispatch`, `server::init` |
| `RequestContext` | `context.rs` | dispatch, handlers |
| `ResolvedPolicy` | `resolved.rs` | dispatch, retry |
| `PolicyConfig`, `MatchRules`, `*Override` structs | `config.rs` | `models::config` |
| `HitOverride`, `HitDecision`, `ToolUseInfo`, `evaluate_tool_use*` | `hit.rs` | dispatch, stream approval |
| `HitAuthorization`, `HitAuthParams`, `AuthDecision`, `AuthMethod` | `hit_auth.rs` | HIT gateway handlers |
| `MultiSigCollector`, `MultiSigStatus` | `multisig.rs` | HIT approval flow |
| `QuorumConfig`, `QuorumStrategy`, `QuorumResult`, `tally_votes` | `quorum.rs` | HIT approval flow |
| `RiskScorer`, `RiskScore`, `HitScoringConfig`, `ScoringContext` | `scoring.rs` | dispatch, audit |
| `DecisionToken`, `DecisionClaims`, `BackendTarget`, `route_by_decision_token`, `strip_decision_claims` | `decision_token.rs` | dispatch, retry |
| `stream::HitStream<S>`, `stream::approval::*`, `stream::sse_parser::*` | `stream/` | streaming dispatch |

## Owns

- Glob matching of tenant / zone / model / tool against rule sets.
- Risk scoring with weighted factors and thresholds.
- HIT decision aggregation: single, multisig (M-of-N keys), quorum (K-of-N voters).
- Decision-token issuance and verification (transparent backend routing per ADR-0016).
- SSE parser dedicated to extracting `tool_use` blocks during streaming approval.

## Depends on

- `crate::models` — `CanonicalRequest`, tool blocks.
- `crate::storage` — encrypted persistence for pending approvals.
- `crate::auth` — JWT signing keys for decision tokens.
- `globset`, `serde`, `tokio::sync`, `chrono`, `ed25519-dalek`.

## Non-goals

- Does not perform DLP detection — that is `features::dlp`.
- Does not dispatch HTTP — surface lives in `server::policy_handlers` and `server::mcp_handlers`.
- Does not store audit records — that is `security::audit`.
- Does not implement structural tool filtering — that is `features::pledge`.

## Tests

- Unit tests in each submodule (`matcher.rs`, `quorum.rs`, `multisig.rs`, `decision_token.rs`, `scoring.rs`, `stream/tests.rs`).
- Integration: `tests/integration/hit_test.rs`.
- E2E hurl: `tests/e2e/tests/policies/B*-*.hurl`.
- E2E shell: `tests/e2e/tests/advanced/S5-hit-flow.sh`, `S8-hit-gateway.sh`.
- Cucumber: `tests/cucumber/features/hit_scoring.feature`.

## Related ADRs

- [ADR-0006](../../../docs/decisions/0006-policy-engine-encrypted-audit-hit-gateway.md) — Policy engine, encrypted audit, HIT gateway
- [ADR-0016](../../../docs/decisions/0016-decision-tokens-transparent-routing.md) — Decision tokens for transparent routing
- [ADR-0009](../../../docs/decisions/0009-pledge-structural-tool-filtering.md) — Pledge structural tool filtering (complementary)

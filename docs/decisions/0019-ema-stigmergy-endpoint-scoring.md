---
status: accepted
date: 2026-04-28
deciders: [azerozero]
consulted: []
informed: []
supersedes: []
related: [ADR-0018, ADR-0020, ADR-0022]
---

# ADR-0019: Adaptive Provider Scoring v1 — Provider-Level Score Before `[[endpoints]]`

## Implementation status

Adaptive scoring is implemented as a provider-level scorer in
`src/security/provider_scorer.rs`, initialized from
`[security] adaptive_scoring` and the `scoring_*` fields in
`src/cli/config/security.rs`.

This ADR is **not** a delivered per-endpoint EMA under `[router.ema]`.
There is no `src/routing/ema.rs`, no `[[endpoints]]` top-level schema, and no
`grob_routing_endpoint_*` metric family in the current tree. The live metrics
are:

| Metric | Labels | Meaning |
|---|---|---|
| `grob_provider_score` | `provider` | Composite provider score |
| `grob_provider_latency_ewma_ms` | `provider` | Provider latency EWMA |
| `grob_provider_success_rate` | `provider` | Rolling provider success rate |

The `scoring_persist` config field is parsed but score persistence is not wired
yet; current scores are in-memory process state.

## Context and Problem Statement

Grob routes through logical `[[models]]` entries with priority-ordered provider
mappings. That schema does not yet expose stable endpoint IDs. A full
per-endpoint EMA therefore has no natural key, no migration path, and no clear
operator surface until ADR-0022's `[[endpoints]]` / `[[policies]]` migration is
ready.

The immediate operational need is still real: avoid repeatedly trying a provider
that is failing, slow, or in a half-open circuit-breaker state when another
configured provider can serve the same logical model.

## Decision Drivers

- **Use the schema that exists.** Provider names are stable today; endpoint IDs
  are not.
- **Keep the feature opt-in.** Static priority chains remain the default.
- **Preserve explainability.** The score is a simple formula using success rate,
  latency, and recency, with circuit-breaker overlay.
- **Avoid schema churn.** Do not ship `[router.ema]` or endpoint metrics before
  the endpoint schema exists.
- **Keep hedging separate.** Scoring can improve fallback order without firing
  speculative duplicate requests.

## Considered Options

1. **Per-endpoint EMA under `[router.ema]`.** Rejected for the current branch:
   it depends on ADR-0022's endpoint identity model and would create a second
   routing schema before migration tooling exists.
2. **Provider-level adaptive scorer under `[security]` (chosen).** Fits the
   current config shape, integrates with the existing circuit breaker, and gives
   operators useful self-healing without schema migration.
3. **Thompson sampling / weighted bandit.** Deferred. Probabilistic exploration
   is harder to audit, and there is no endpoint schema or spend/audit protocol
   to constrain exploration safely.
4. **Static priorities only.** Rejected because it leaves transient provider
   degradation entirely on the operator.

## Decision Outcome

Keep the current provider-level scorer as **adaptive provider scoring v1**.

### User-facing configuration

```toml
[security]
adaptive_scoring = false        # opt-in; static priority order by default
scoring_latency_alpha = 0.3     # EWMA alpha for latency smoothing
scoring_window_size = 50        # rolling success-rate window
scoring_decay_rate = 0.001      # confidence decay per second of inactivity
scoring_persist = false         # reserved; not implemented yet
```

### Scoring formula

For each provider:

```text
success_rate = successes / recorded_outcomes
latency_factor = 1 / (1 + latency_ewma_ms / 1000)
confidence = max(1 - decay_rate * seconds_since_last_use, 0.3)
composite = success_rate * latency_factor * confidence
```

The circuit breaker overlays the raw score:

| Circuit state | Adaptive factor |
|---|---|
| Closed | Raw composite score |
| HalfOpen | `min(raw_score, 0.1)` |
| Open | `0.0` |

### Routing integration

When `adaptive_scoring = true`, `dispatch_provider_loop` asks the scorer to
re-sort the selected model mappings before the provider fallback loop starts.
The effective order is:

```text
effective_priority = declared_priority / adaptive_factor
```

Lower effective priority is tried first. A provider with factor `0.0` is pushed
to the end. This can reorder providers across declared priorities; it is not
only a same-priority tie-breaker.

## Non-goals and Deferred Work

- **Per-endpoint scoring.** Useful conceptually, but it should wait for a
  read-only internal endpoint adapter or a realistic ADR-0022 migration plan,
  not a complete cut-over.
- **`[router.ema]`.** Do not add a second operator-facing scoring schema while
  `[security] adaptive_scoring` is the live implementation.
- **Bandit / Thompson sampling.** Deferred until routing decisions have endpoint
  identity, spend constraints, audit records, and an explicit opt-in story for
  probabilistic exploration.
- **Score persistence.** The `scoring_persist` field needs implementation or
  removal; today it is a reserved knob.

## Consequences

### Positive

- Provides self-healing provider ordering without waiting for the endpoint
  schema migration.
- Reuses the existing circuit-breaker state and tests.
- Exposes metrics that match the actual implementation.
- Keeps the default behavior static and predictable.

### Negative

- Provider-level scoring is coarse: two different models behind the same
  provider share one score.
- Reordering by `priority / factor` can override declared priority more strongly
  than a pure gate would. This is intentional for v1 but must stay documented.
- Persistence is not implemented despite the parsed `scoring_persist` field.

## Validation

Current unit tests in `src/security/provider_scorer.rs` cover:

- New providers default to full score.
- Rolling success-rate windows.
- Latency EWMA arithmetic.
- Failure-heavy providers receive low scores.
- Better-scoring providers can move ahead of worse-scoring providers.
- Open circuit breakers force score `0.0`.

Future endpoint-level scoring must add integration tests against the
`[[endpoints]]` migration adapter before replacing this v1 provider scorer.

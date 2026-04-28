---
status: proposed
date: 2026-04-28
deciders: [azerozero]
consulted: []
informed: []
supersedes: []
related: [ADR-0018, ADR-0019]
---

# ADR-0020: Hedged Requests — Tail-Latency Reduction via Speculative Duplication

## Context and Problem Statement

Provider tail latency (P95 / P99) is the silent UX killer for interactive Claude Code sessions. The median DeepSeek V4-Flash response lands at ~700ms; the P99 lands at 8s+ when the provider's queue saturates. From the user's seat, a 8-second pause feels like the agent is stuck.

The classical industrial fix (Cassandra, Google Maglev, BigTable) is **hedged requests**: if the primary provider hasn't responded after a tunable threshold (e.g., 2 seconds), fire a parallel duplicate request to a different provider. Whichever responds first wins; the loser is cancelled.

Cost trade-off: occasionally pay 2× for one logical request. In practice, only ~5-15% of requests trigger the hedge (those landing in the latency tail), so the amortized cost increase is ~5-15% but the P99 perceived latency drops by 60-80%.

## Decision Drivers

- **Sub-3s P99 latency is non-negotiable** for an interactive agent UX — anything above feels like a bug.
- **Don't burn money on the median path.** The hedge fires only when latency tail-detection triggers, not on every request.
- **Operator-controlled.** Hedging on a free tier is foolish (the second request also hits the rate limit). Hedging on a paid tier with abundant capacity is gold. Different presets, different defaults.
- **Idempotency-safe.** LLM completions at `temperature=0` are reproducible enough to discard. Tool-calling responses, audio inputs, side-effecting requests — never hedge.

## Considered Options

1. **Configurable per slot, opt-in (chosen).** Each routed slot (`default-model`, `think-model`, `search-model`, ...) can independently enable hedging via `[<slot>] hedge_after_ms = N`. Default off.
2. **Global `[router] hedge_after_ms = N`.** Rejected: forces a single trade-off across slots that have very different cost/latency profiles. `trivial-model` doesn't need it; `search-model` likely does.
3. **EMA-driven adaptive threshold (built later, on top of ADR-0019).** "Hedge if no response after p95×1.5" — uses ADR-0019's EMA p95 to set the threshold dynamically per endpoint. Listed as a v0.42+ enhancement once ADR-0019 ships.
4. **Always hedge.** Rejected: doubles the bill, hammers free tiers, no benefit on the median path.

## Decision Outcome

**Chosen: opt-in per slot, hard-coded threshold initially, with adaptive variant deferred.**

### User-facing configuration

```toml
# Per-model-slot hedging. Default off.
[models.default-model.hedge]
enabled = false           # opt-in
after_ms = 2000           # fire hedge if primary hasn't responded by this
copies = 2                # 2 = primary + 1 hedge. 3 = primary + 2 hedges (rare)
only_at_temperature_zero = true   # safety: only deterministic completions
skip_if_tools_present = true      # safety: never hedge tool-calling

# Optional: cap concurrent hedges per session to avoid thundering herd
# when many requests pile up at once.
max_concurrent_hedges_per_session = 4

# Optional: hedge target selection
# - "next_priority": fire to the next non-skipped endpoint in the chain
# - "least_loaded": fire to the endpoint with highest EMA score (requires ADR-0019)
target = "next_priority"
```

### Lifecycle of a hedged request

1. Request arrives; router picks primary endpoint (priority chain + EMA gate).
2. Primary call dispatched; timer started for `hedge_after_ms`.
3. **Path A — primary returns first** (~85-95% of the time):
   - Cancel hedge timer if not fired yet.
   - If hedge already in flight, abort it via `tokio::task::JoinHandle::abort()` and best-effort upstream cancellation (HTTP/2 RST_STREAM where supported).
   - Return primary's response to client.
4. **Path B — hedge fires before primary returns** (~5-15%):
   - Pick second endpoint via `target` strategy.
   - Dispatch hedge request in parallel.
   - First response (whichever arrives first) is returned to client.
   - Loser is aborted as in Path A.
5. **Path C — primary errors during the hedge window**:
   - Existing fallback chain logic takes over (no change in behavior).
   - Hedge call, if dispatched, becomes the actual primary.

### Cost & latency model

```
Without hedging:
    p50 = 700ms, p95 = 4s, p99 = 8s+
    cost = 1.0 × per-request

With hedging (after_ms = 2000):
    p50 = 700ms (no change — hedge never fires on median path)
    p95 = 2.5s   (the hedge wins for the slow 5%)
    p99 = 3.0s   (cap at 2000ms + second-provider response)
    cost = 1.0 × per-request × (1 + 0.10 × hedge_fire_rate)
         ≈ 1.10 × per-request
```

### Telemetry

| Metric | Labels | Type | Purpose |
|---|---|---|---|
| `grob_hedge_fired_total` | `slot, primary_provider, hedge_provider` | Counter | Hedge dispatched |
| `grob_hedge_winner` | `slot, winner=primary\|hedge` | Counter | Who returned first |
| `grob_hedge_cancellation_lag_ms` | `slot` | Histogram | Time from winner-known to loser-cancelled (must stay sub-100ms to be honest about cost) |
| `grob_request_hedged_duration` | `slot, winner` | Histogram | End-to-end latency of hedged requests |

### Positive Consequences

- P99 latency drops by ~70% on tail-prone slots.
- Operators see exactly what fraction of requests hedge and how often the hedge wins.
- Free-tier presets (`ultra-cheap`, `eu-eco`) keep `enabled = false` by default — no surprise bills.
- Compatible with ADR-0019 EMA: the hedge target can use EMA score for smart selection.

### Negative Consequences

- **Cost overhead**: ~5-15% on enabled slots. Operators must understand this trade-off.
- **Implementation complexity**: cancellation propagation through the dispatch pipeline must be airtight. A leaked hedge keeps consuming tokens and money.
- **Provider rate-limit burn**: hedging on a near-saturation paid tier accelerates rate-limit hits. ADR-0019's circuit-breaker integration mitigates.
- **Audit log clarity**: every hedged request produces 2 outbound provider calls. The audit log must record both legs (primary+hedge) with a winner flag.

## Implementation Notes

- New `src/routing/hedge.rs` with `HedgeConfig` struct mirroring the TOML.
- Dispatch site: `src/server/dispatch/mod.rs` after the primary endpoint is selected.
- Use `tokio::select!` over (primary_future, hedge_timer_then_dispatch_future).
- Cancellation: `JoinHandle::abort()` for the loser, plus a `Drop` impl on the upstream HTTP request body to terminate streaming early.
- Token-counting must NOT bill the loser (audit log records both, billing pipeline must filter `winner=false` hedge legs from `grob_input_tokens_total`).
- Test: `tests/integration/hedge_test.rs` with mock providers configurable to delay.

## Validation

- Unit: hedge fires after exact threshold, cancels loser within 50ms.
- Property: under random latency distributions, the worst observed P99 with hedging is ≤ unmodified primary's P95.
- Integration: 1k synthetic requests with 1% delayed provider, verify hedge fire rate ≈ 1%, hedge-win rate ≈ 95% of fires, no leaked tokens.
- Production canary: enable on `default-model` of a single test tenant, observe billing & latency for 1 week.

## Migration

- v0.37–0.38: ship `[models.<slot>.hedge]` config field, document, default off everywhere.
- v0.39: enable by default on the (paid) `perf` preset's premium slots only.
- v0.42+: layer adaptive threshold on top of ADR-0019 EMA p95 once that ADR is implemented.

## Cancellation cost handling (operator-declared)

Cancellation behavior is **operator-declared in config**, not hardcoded in the binary. This avoids stale or speculative knowledge about provider billing baked into source. Each operator declares what they have empirically verified for their providers:

```toml
# Per-provider cancellation behavior on RST_STREAM mid-stream.
# Operator MUST verify each value empirically before relying on hedging.
# Test protocol: docs/how-to/verify-hedge-cancellation-billing.md

[hedge.providers.anthropic]
billing_behavior = "full_refund"          # honors cancellation, stops billing
verified_date = "2026-04-28"

[hedge.providers.openai]
billing_behavior = "partial_refund"       # bills until next chunk boundary
verified_date = "2026-04-28"

[hedge.providers.openrouter]
billing_behavior = "no_refund"            # bills full stream regardless
verified_date = "2026-04-28"

[hedge.providers.deepseek]
billing_behavior = "unknown"              # not verified yet
# verified_date intentionally absent
```

Hedging logic uses these declarations:

| `billing_behavior` | Hedging policy |
|---|---|
| `full_refund` | hedge with marginal extra cost in metric |
| `partial_refund` | hedge OK, add ~10% to `grob_hedge_estimated_extra_cost_usd` |
| `no_refund` | **hedging disabled by default**, opt-in via `force_hedge_no_refund_provider = true` |
| `unknown` (or missing) | hedging disabled, fail-closed; operator must verify and declare |

`docs/how-to/verify-hedge-cancellation-billing.md` ships the test protocol: send 5 requests with controlled mid-stream cancellation, compare the resulting bill against a no-cancel baseline, set the appropriate behavior label.

Default file shipped at `presets/hedge-providers.toml.example` lists known providers with `billing_behavior = "unknown"` placeholders and the verification command — operators copy-paste, run the protocol, fill in their findings.

## Open Questions

- **OpenAI Codex compatibility**: OpenAI's OAuth-only client refuses redirected/proxied responses with mismatched request IDs. Hedging produces 2 IDs; we always pick one. Is the response-ID rewriting in the openai_compat translator already idempotent? (TBD pre-impl review.)

## Audience-specific notes

### Trading bots / time-sensitive callers

Hedging is most valuable here. A trading decision delayed by 6s because a provider's queue saturated is a missed trade. Recommended defaults:

- `enabled = true` on `default-model` and `search-model` slots.
- `hedge_after_ms = 1000` (more aggressive than the safe 2000 default).
- `target = "least_loaded"` if ADR-0019 EMA is enabled (best-scoring endpoint takes the hedge).
- Budget impact must be modelled: trading workloads can pay 15-25% extra in absolute USD because the latency floor is a revenue input.

### Security-prevails customers (defense, banks, OIV)

Hedging duplicates the same prompt across two providers — a multi-tenant data-exposure surface. Recommended posture:

- New config field: `[models.<slot>.hedge.compliance_isolation = true]` — when set, the hedge target must share the same `compliance.trust_zone` AND `compliance.jurisdiction` AND have a `compliance.data_classification` greater than or equal to the primary endpoint's. The compliance block is declared per-endpoint in `[endpoints.compliance]` (see ADR-0022). If either endpoint omits the compliance block, hedging is automatically disabled (fail-closed) for that request.
- Audit log entry on every hedged request must record both legs (primary endpoint, hedge endpoint, winner) under the same `request_id` so the compliance team can reconstruct the duplicated dispatch.
- Default off: even with trust-zone isolation, security teams may ban hedging entirely in classified environments. Opt-in only.

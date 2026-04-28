---
status: proposed
date: 2026-04-28
deciders: [azerozero]
consulted: []
informed: []
supersedes: []
related: [ADR-0018]
---

# ADR-0019: EMA Stigmergy — Adaptive Endpoint Health Scoring

## Context and Problem Statement

Grob currently routes via static priority chains in `[[models.mappings]]`. When a high-priority endpoint degrades — slow responses, sporadic 429s, regional outages — grob keeps hammering it on every request until the operator manually edits the config and reloads.

In practice this means:

- A 5-minute DeepSeek hiccup causes ~300 retries-then-fallbacks for an active Claude Code session before any human notices.
- An endpoint that has been struggling for an hour stays at p1 because no one is watching the metrics.
- Conversely, an endpoint that was down yesterday and is fully healthy today stays artificially deprioritized in someone's manually-edited config until they remember to revert the change.

The fix is **adaptive scoring**: each endpoint accumulates a health score from recent observed signals (success rate, latency percentiles, 429 rate) and the score gradually fades back to neutral over time. Inspired by ant pheromone trails — high-traffic-success paths leave stronger trails; failures evaporate without trace.

## Decision Drivers

- **Recovery from transient provider issues without operator intervention** (primary).
- **Predictability for compliance audits** — the routing must remain explainable; "the model picked DeepSeek because its EMA score was 0.85 vs Anthropic's 0.42" is acceptable, "we ran a black-box ML model" is not.
- **Transparent to client** — Claude Code (or any client) should not see the internal switching. It calls `claude-sonnet-4-6` and gets a response; whether the response came from p1 or p3 is not visible in the response shape.
- **Visible in telemetry** — operators need clear metrics to debug routing decisions and audit fallbacks.
- **Backward compatible** — installations that prefer static priorities must continue to work unchanged.

## Considered Options

1. **EMA per-endpoint with configurable α and decay (chosen).** Each endpoint maintains an exponentially-weighted moving average of (success_rate, p95_latency, error_429_rate). On each request, the router picks the highest-scoring endpoint among the eligible ones (within tier filter, within priority chain). Default off; opt-in via `[router] adaptive_scoring = "ema"`.
2. **Median-of-N rolling window.** Keep last N samples per endpoint, take the median. Rejected: more memory (~N×size_of(sample) per endpoint), no smoothing of bursty error rates, harder to tune the recovery curve.
3. **Kalman filter or Bayesian inference.** Rejected: overkill for this signal class, harder to explain in compliance audits, and the parameter tuning effort dwarfs the gain.
4. **Stay static, document the failure mode.** Rejected: the operator burden compounds as the number of endpoints grows. With ultra-cheap preset shipping 7 enabled providers, manual rebalancing is not realistic.

## Decision Outcome

**Chosen: EMA per-endpoint, opt-in, transparent to client, fully observable.**

### User-facing configuration

```toml
[router]
# Default: "static" preserves the existing priority-chain behavior.
# "ema" enables exponentially-weighted health scoring as a tie-breaker
# within the priority chain (does not change the chain itself).
adaptive_scoring = "static"  # or "ema"

[router.ema]
# Smoothing factor 0..1. Higher = faster reaction to changes.
# 0.3 means roughly 3-4 consecutive failures shift the score noticeably.
alpha = 0.3

# Decay half-life. After this duration with no signal, the EMA score
# returns halfway to neutral (1.0). Prevents stale-penalty issues.
decay_half_life = "1h"

# Signals tracked. Each contributes equally to the composite score
# unless `weights` overrides.
signals = ["success_rate", "p95_latency", "error_429_rate"]

# Optional per-signal weights (default: equal).
[router.ema.weights]
success_rate = 1.0
p95_latency = 0.5
error_429_rate = 1.0

# Optional minimum score threshold. Below this, an endpoint is skipped
# entirely (treated as if circuit-breaker tripped). Default: no skip.
# Useful for compliance: "never route to an endpoint scoring below 0.3".
skip_below = 0.3
```

### Scoring formula

```
For each signal s observed in a request:
    score_s_new = α × signal_s + (1 - α) × score_s_prev

Composite endpoint score:
    composite = Σ (weight_s × score_s) / Σ weight_s
    range: [0.0, 1.0], with 1.0 = healthy

Idle decay (every N seconds, no traffic):
    score_s = 1.0 - (1.0 - score_s) × 0.5^(elapsed / decay_half_life)
```

### Routing integration

The chain is unchanged. Within the chain, EMA only acts as a **gate** and a **tie-breaker**:

1. Tier filter applies first (existing logic).
2. Priority chain is walked top-to-bottom (existing logic).
3. For each candidate endpoint, **if `adaptive_scoring = "ema"` and score < `skip_below`**, skip to next.
4. The first acceptable candidate wins (no global score-max search; preserves predictability).

Recovery is automatic: as the EMA score climbs back toward 1.0 (either from positive signal or idle decay), the endpoint re-enters the chain at its declared priority position.

### Transparent client contract

- The HTTP response shape is unchanged. `model: "claude-sonnet-4-6"` in the request returns `model: "claude-sonnet-4-6"` in the response, regardless of which provider actually served it.
- The `provider` and `actual_model` are surfaced only in:
  - Trace log (`~/.grob/trace.jsonl` if tracing enabled)
  - Prometheus metrics (`grob_requests_total{provider, model}`)
  - Optional response header `X-Grob-Routing: provider=anthropic;score=0.85;reason=ema-skip-deepseek`
- Client tools (Claude Code, Cursor, Aider) never need to know switching happened.

### Telemetry

New metrics surface routing decisions:

| Metric | Labels | Type | Purpose |
|---|---|---|---|
| `grob_routing_endpoint_score` | `provider, model` | Gauge | Current composite EMA score 0..1 |
| `grob_routing_endpoint_score_signal` | `provider, model, signal` | Gauge | Per-signal EMA values (debug) |
| `grob_routing_skips_total` | `provider, model, reason` | Counter | When an endpoint is skipped: `ema_below_threshold`, `circuit_open`, `quota_exceeded` |
| `grob_routing_recoveries_total` | `provider, model` | Counter | When a previously-skipped endpoint re-enters the chain |
| `grob_routing_decisions_total` | `from_priority, served_by_priority` | Counter | Histogram of "intended vs actual" priority used |

A Grafana dashboard template `grob-routing-ema.json` ships in `dashboards/` — operators can drop it in their existing instance and see endpoint health curves at a glance.

### Positive Consequences

- **Self-healing**: a 5-minute provider hiccup is absorbed without operator action; recovery is automatic.
- **Operator visibility**: clear metrics, no black box.
- **Backward compatible**: `adaptive_scoring = "static"` (default) preserves byte-for-byte existing behavior.
- **Compliance-friendly**: every routing decision is explainable from the EMA values logged to trace.

### Negative Consequences

- **More state per process**: ~200 bytes per endpoint × ~50 endpoints in a heavy preset ≈ 10KB. Negligible.
- **One extra atomic load per request**: the EMA score lookup. Sub-microsecond.
- **Test surface widens**: deterministic property tests needed to lock the EMA arithmetic and decay.
- **Tuning burden** (mild): operators may want to adjust α and decay for their workload pattern. Defaults are conservative.

## Implementation Notes

- New module `src/routing/ema.rs` exposing `EmaScorer` with `record_signal(endpoint_id, signal, value)` and `score(endpoint_id) -> f32`.
- State stored in `Arc<DashMap<EndpointId, EmaState>>` for lock-free reads on the dispatch hot path.
- Decay applied lazily on `score()` call (read timestamp, apply exponential decay since last update).
- Atomic snapshot via `arc-swap` for hot-reload of weights / alpha / decay.
- Integration point: `src/server/dispatch/mod.rs` between tier filter and provider call. ~50 LoC.

## Validation

- Unit tests with deterministic time injection: alpha=0.5, three failures, verify score falls to expected value.
- Property test: idempotent under no-op time advance.
- Integration test: simulate a 5-minute provider outage, verify ≥80% of subsequent requests bypass the failing endpoint within the first 10 requests.
- Bench: routing decision latency must remain < 100ns p99 (compared to ~50ns static priority).
- Production canary: ship behind `adaptive_scoring = "ema"` opt-in, observe Grafana dashboard for 1 week before recommending the default flip in v0.40+.

## Configurability principle

**Every parameter shipped here is a configurable default, not a hardcoded constant.** Operators override any value via `[router.ema]` in `~/.grob/config.toml`. The defaults below are guidance based on conservative-for-the-median-workload analysis; trading desks and security-prevails deployments are expected to tune their own.

The default flip from `adaptive_scoring = "static"` to `"ema"` is **not a code change** — it is a default value in the config schema. Operators who want EMA earlier set it explicitly; operators who never want it leave it on `"static"` regardless of the project's recommendation.

## Migration

- Initial release shipping ADR-0019 code: `adaptive_scoring` config field added, default `"static"`. No behavior change for existing users.
- Subsequent releases: gather feedback, optionally refine the default. Any shift of the default value is announced in the CHANGELOG one release ahead, never silently.
- Operators are never blocked: they can set `adaptive_scoring = "static"` in their config and stay on the existing routing semantics indefinitely.

## Audience-specific notes

### Trading bots / time-sensitive callers

EMA is most valuable here. The 60s circuit-breaker cooldown is unacceptable in a market-data loop; EMA-driven gating recovers in 5–10 requests after a transient provider issue and avoids hammering a degrading endpoint. Recommended defaults for this audience:

- `alpha = 0.4` (faster reaction)
- `decay_half_life = "15m"` (faster forget)
- `skip_below = 0.5` (more aggressive gating)

### Security-prevails customers (defense, banks, OIV)

EMA decisions must be explainable in a compliance audit. Recommended posture:

- `adaptive_scoring = "ema"` enabled but `skip_below` set to a high threshold (`0.6`+) so endpoints either route normally or get visibly excluded — no fuzzy intermediate cases.
- The Prometheus metric `grob_routing_skips_total{reason="ema_below_threshold"}` becomes the audit signal: any non-zero value means the operator must justify the skip in the post-incident report.
- The optional `X-Grob-Routing` response header MUST be enabled for these deployments — it carries the EMA score that drove the decision into the per-request audit log.

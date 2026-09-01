---
status: accepted
date: 2026-07-28
deciders: [azerozero]
consulted: []
informed: []
supersedes: []
related: [0018]
---

# ADR-0030: Fail-Closed Dependency Contract

## Context and Problem Statement

A gateway that sits in front of provider APIs accumulates security-critical
dependencies on its hot path: budget reservation, policy/HIT authorization,
deterministic DLP, secret resolution, plus best-effort concerns like the audit
sink and metrics export.

The most damaging failure mode across the market is **silent fail-open**: a
dependency becomes unavailable and the gateway lets the request through anyway.
LiteLLM classified this as a P0 in its own "Stability Sprint" — its
`fail_closed_budget_enforcement` did not cover the atomic budget reservation, so
on a Redis outage requests could proceed and overrun the budget even in
"fail closed" mode. For a regulated deployment a budget is an *authorization to
consume*, not a report; "the counter store blinked" must never become "access
granted".

Two things are needed:

1. A single, explicit rule for **which** dependency failures block a request and
   which are allowed to degrade — because both directions are bugs. Blocking on a
   metrics outage destroys availability; continuing on a policy-engine outage
   silently grants access.
2. A record of that rule so a future refactor cannot re-introduce a fail-open by
   accident (exactly how LiteLLM regressed).

## Decision

Every hot-path dependency is classified as **authorizing** (its failure blocks
the request) or **observing** (its failure degrades but proceeds). The request
pipeline enforces this classification; a change that moves a dependency across
the line requires updating this ADR.

| Dependency | On failure | Where enforced (as audited 2026-07-28) |
|---|---|---|
| Config load / validation | **block** — process does not serve | `src/config.rs:204` (`config.validate()?` on load; invalid config never starts) |
| Budget / spend cap | **block** — `BudgetExceeded` before any provider call | `src/server/budget.rs:164,176`; spend read is in-memory (no external store to fail-open on), committed synchronously in `record_spend` |
| Deterministic DLP | **block** — detection returns `DlpBlockError`, propagated by `?` | `src/server/dispatch/mod.rs:331` (`scan_dlp_input(...)?`); engine is in-process and deterministic, so it has no "unavailable" state |
| HIT / tool authorization | **block (deny)** on every non-approval outcome | `src/server/dispatch/retry.rs:794-806`: explicit deny, dropped channel, and timeout all map to `AuthDecision::Deny` |
| Secret resolution (api_key `secret:`/`$ENV`) | **block** — resolved before the registry is built; unresolved never ships | `ProviderRegistry::from_configs_with_models` (see ADR trail of #280/#284) |
| Audit log write | **continue + flag** | audit failure is logged, not fatal |
| Metrics / OpenTelemetry export | **continue** | export is off the decision path |
| Token estimate / pricing | **continue (degrade)** | estimate falls back locally; never blocks |
| Startup provider health probe (`validate_on_start`) | **continue** — opt-in, backgrounded | `src/server/init.rs:84`; never blocks the bind (see the zero-network-startup rule) |

The distinguishing test: *if this dependency is completely unavailable, can a
request that should be denied still reach a provider?* For every **authorizing**
row the answer must be no.

### Audit finding

As of 2026-07-28 the implementation already satisfies this contract on every
row above. Notably grob's budget path carries **no external counter store on the
read side** — the spend is held in memory and reserved synchronously — which
structurally avoids the LiteLLM Redis fail-open rather than patching around it.

This ADR does not change behaviour; it makes the existing contract explicit so it
can be regression-tested and so reviewers have a line to hold.

## Consequences

- Any PR that touches an **authorizing** dependency must preserve `block` on
  failure, or amend this table with justification.
- The one gap is coverage, not correctness: the existing tests assert the
  *decision* outcomes (budget exceeded blocks; HIT times out to deny) but not the
  *dependency-unavailable* variants (e.g. a poisoned spend mutex, a wedged policy
  backend). Closing that with fault-injection property tests is tracked in the
  fail-closed-granularity issue.
- "Observing" dependencies must stay genuinely off the decision path — an audit
  or metrics failure that could block a request would itself be a contract
  violation in the other direction.

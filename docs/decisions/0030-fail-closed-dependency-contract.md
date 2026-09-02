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
| Budget / spend cap | **block** — `BudgetExceeded` before any provider call | `src/server/budget.rs:164,176`; spend read is in-memory, committed synchronously in `record_spend` |
| Spend journal replay (the counter behind the cap) | **block** — a damaged journal refuses startup; an unreadable tenant journal denies the request | `src/storage/journal.rs` (`replay_*` return `Result`), `src/storage/mod.rs` (fatal at `open`), `src/features/token_pricing/spend.rs` (`check_tenant_budget` denies on read failure) |
| Deterministic DLP | **block** — detection returns `DlpBlockError`, propagated by `?` | `src/server/dispatch/mod.rs:331` (`scan_dlp_input(...)?`); engine is in-process and deterministic, so it has no "unavailable" state |
| HIT / tool authorization | **block (deny)** on every non-approval outcome | `src/server/dispatch/retry.rs:794-806`: explicit deny, dropped channel, and timeout all map to `AuthDecision::Deny` |
| Secret resolution (api_key `secret:`/`$ENV`) | **block** — resolved before the registry is built; unresolved never ships | `ProviderRegistry::from_configs_with_models` (see ADR trail of #280/#284) |
| Audit log write | **continue + flag** | audit failure is logged, not fatal |
| Metrics / OpenTelemetry export | **continue** | `src/server/init.rs`: recorder install failure is logged, not propagated (the global recorder is a process one-shot, so a second server in one process must still boot) |
| Token estimate / pricing | **continue (degrade)** | estimate falls back locally; never blocks |
| Startup provider health probe (`validate_on_start`) | **continue** — opt-in, backgrounded | `src/server/init.rs:84`; never blocks the bind (see the zero-network-startup rule) |

The distinguishing test: *if this dependency is completely unavailable, can a
request that should be denied still reach a provider?* For every **authorizing**
row the answer must be no.

### Audit finding

As of 2026-07-28 the implementation satisfied this contract on every row above
at the *decision* level. Notably grob's budget path carries **no external
counter store on the read side** — the spend is held in memory and reserved
synchronously — which structurally avoids the LiteLLM Redis fail-open rather
than patching around it.

The 2026-09-01 fault-injection pass found the one place where that guarantee did
not hold: the in-memory counter is seeded by replaying the JSONL spend journal,
and the replay swallowed every I/O and parse error, returning `SpendData::default()`.
A corrupt, truncated, or unreadable journal therefore started the process at
`$0 spent` and silently reopened an exhausted budget — the LiteLLM failure mode
reached through the file layer instead of Redis. Replay is now fallible:
genuine absence still means "nothing spent", but a journal that exists and
cannot be trusted is fatal at startup and a denial on the per-tenant request
path.

This ADR does not change behaviour; it makes the existing contract explicit so it
can be regression-tested and so reviewers have a line to hold.

## Consequences

- Any PR that touches an **authorizing** dependency must preserve `block` on
  failure, or amend this table with justification.
- The dependency-unavailable variants are covered by
  `src/storage/fault_injection_tests.rs`, which damages the journal (torn write,
  unreadable file) and asserts refusal, while pinning the two boundaries that
  make the guarantee meaningful: a *missing* journal must still start clean, and
  observing dependencies must never block a read.
- "Observing" dependencies must stay genuinely off the decision path — an audit
  or metrics failure that could block a request would itself be a contract
  violation in the other direction.

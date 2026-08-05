# agents

> Agent identity and spend attribution (feature `agents`).

## Purpose

Grob already knows the tenant and the model behind a request. It does not know the *agent*, which is the unit operators reason about when several automated callers share one API key. Without it, cost is attributable to a key rather than to the thing that spent it.

This first slice establishes identity and attribution only. Enforcement (budgets, capabilities, leases) needs a registry to check against, and shipping the observable half first means the enforceable half arrives with real data behind it rather than assumptions.

## Public API

| Item | Location | Used by |
|------|----------|---------|
| `AgentId`, `AgentId::parse` | `mod.rs` | header extraction, journal writes |
| `AgentContext`, `AgentContext::from_headers` | `mod.rs` | request path |
| `AGENT_ID_HEADER`, `PARENT_AGENT_ID_HEADER` | `mod.rs` | clients, documentation |

## Design notes

**Identity is carried, never inferred.** The identifier arrives in `x-grob-agent-id`. Deriving it from traffic shape or prompt content would be guesswork, and a wrong attribution is worse than none: it points an investigation at the wrong agent.

**Identifiers are readable, not generated.** Operators name their agents, and a readable name in a spend report is worth more than a UUID nobody recognises.

**Validation happens at the boundary.** The accepted character set is ASCII alphanumerics plus `-`, `_`, `.` and `:`, bounded at 128 bytes. The value reaches log lines, journal records and metric labels, so refusing a newline once beats escaping it at every use site, where one omission is a corrupted record.

**A malformed header does not fail the request.** Agent identity is metadata for attribution, not authorisation. Enforcement belongs later, against a registry, and that is where a bad identifier should bite.

**Lineage is recorded, not enforced.** `x-grob-parent-agent-id` captures which agent spawned which. That is what later makes hierarchical budgets and recursive termination possible, and it has to exist before it can be relied upon. A parent without a child is discarded, since it would produce a lineage record with no descendant.

## Spend attribution

`SpendEvent` gains an optional `agent` field, written through `record_spend_for_agent`. A separate entry point rather than an extra parameter on the existing one: every current caller keeps working untouched, and the attribution path is visible in a grep rather than hidden behind a `None`.

The field is omitted entirely when absent, so existing journals stay readable and existing exports keep parsing unchanged. A test asserts the key is not even present for an agent-less record, rather than written as `null`.

## Non-goals

- Enforcement of any kind: budgets, capabilities, rate limits, termination.
- A registry of known agents.
- Authorisation. The header is metadata, and trusting it for access control would be a confused-deputy hazard.

## The request path

```
headers -> AgentContext -> DispatchContext::agent_id()
        -> record_spend -> record_attributed -> journal
```

`record_attributed` is a trait method whose default body **drops the agent** and delegates to the pre-existing calls, so every implementor keeps compiling and one that cannot store attribution still records the money. Losing spend is worse than losing a label.

`agent_id()` has two bodies rather than a gated call site, so callers stay feature-agnostic and a build without `agents` attributes to nothing instead of failing to compile.

## Tests

`mod.rs` covers the accepted and refused character sets (including newlines and quotes that would forge a journal line), the length bound, lineage capture, the discarded orphan parent, the dropped self-parented cycle, and a spend round-trip asserting both attribution and backward compatibility.

`agent_attribution_stays_wired_into_the_request_path` reads the source and fails if any of the four connection points above loses its caller. It exists because A1 shipped this slice with nothing calling it, the **fourth** occurrence of that failure in this repository, and the media slice's guard could not see it.

A generic "no slice is orphaned" check was considered and rejected: every slice already has external references, so such a check passes trivially while a slice is half-wired. Naming the specific connection points is what makes the guard able to fail.

## Verified against a live server

Unit tests prove the pieces and the wiring guard proves the connections, but
neither can prove a real request produces a real journal line. Run against a
live `grob` with a mock backend:

| request | journal line |
|---|---|
| `x-grob-agent-id: planner-7` | `"agent":"planner-7"` |
| no header | key absent entirely |
| `x-grob-agent-id: bad id!!` | HTTP 200, key absent |
| streaming, `streamer-1` | `"agent":"streamer-1"` |

The streaming case matters most: it bills through `SpendStreamContext`, a
different code path from the non-streaming one. Attribution that worked only
for non-streaming responses would be **worse than none**, because the gap
would be invisible in the journal. `agent_id` in `dispatch/retry.rs` is in the
wiring guard for exactly that reason.

## What mutation testing found here

Two survivors, both **defects rather than missing tests**: `Display for AgentId` and `is_identified` had no caller outside the tests asserting on them, and `is_self_parented` detected a cyclic lineage then stored it anyway, leaving every consumer to re-check.

The first two were deleted, since a test against otherwise-unused API only proves the API exists. The third became enforcement at the boundary: `from_headers` drops the impossible parent, keeping the identity so spend stays attributable. 16 mutants, 16 caught.

## Related design docs

- [`001-image-dlp-provenance.md`](../../../docs/design/001-image-dlp-provenance.md) — the agent control plane analysis.
- [`002-media-agents-delivery-plan.md`](../../../docs/design/002-media-agents-delivery-plan.md) — this slice is PR A1.

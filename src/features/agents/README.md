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

## Tests

`mod.rs` covers the accepted and refused character sets (including newlines and quotes that would forge a journal line), the length bound, lineage capture, the discarded orphan parent, self-parenting detection, and a spend round-trip asserting both attribution and backward compatibility.

## Related design docs

- [`001-image-dlp-provenance.md`](../../../docs/design/001-image-dlp-provenance.md) — the agent control plane analysis.
- [`002-media-agents-delivery-plan.md`](../../../docs/design/002-media-agents-delivery-plan.md) — this slice is PR A1.

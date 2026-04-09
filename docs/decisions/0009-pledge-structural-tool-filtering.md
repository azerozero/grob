---
status: accepted
date: 2026-04-09
deciders: [azerozero, architect]
consulted: []
informed: []
---

# ADR-0009: Pledge — Structural Tool Filtering for LLM Payloads

## Context and Problem Statement

LLM tool-calling frameworks typically enforce tool restrictions at **execution time**: the LLM asks to run `bash`, the runtime checks a deny list, and refuses. This is a reactive control. The LLM still *sees* the tool definition, may retry with variations, and wastes tokens arguing with the filter.

Grob needs a model where a caller can declare "for this session, the LLM operates under `read_only` capabilities — it can never touch `bash`, `write_file`, or `web_fetch`". The restriction must be **structural** (the tool does not exist in the payload sent to the provider) rather than **behavioral** (the tool exists but is refused on invocation).

Inspired by OpenBSD's `pledge(2)` syscall, which restricts a process to a declared set of capabilities and terminates it on violation.

## Decision Drivers

- **Zero-retry guarantee** — the LLM cannot "discover" a blocked tool and retry with obfuscation.
- **Lower token cost** — removed tools save input tokens, especially with Claude's verbose tool schemas.
- **Auditability** — every pledge resolution is logged (which profile, why).
- **Composition with HIT** — a pledged session still uses HIT for tools that are allowed but high-risk.
- **Zero overhead when disabled** — `config.enabled = false` is a no-op; the filter must not pay allocation cost.

## Considered Options

1. **Execution-time deny list** (status quo before this ADR).
2. **Structural filtering at request preparation** — strip tools from `CanonicalRequest.tools` before dispatch.
3. **Delegate to provider** — ask Anthropic / OpenAI to apply server-side filtering.

## Decision Outcome

**Chosen: option 2 — structural filtering at request preparation.**

Pledge is implemented as a small module (`src/features/pledge/`, ~360 LOC total) with:

- **`PledgeConfig`** (`config.rs`) — TOML-driven declaration: `enabled`, `default_profile`, rule list (`source` / `token_prefix` matches), profile table.
- **`PledgeProfile`** — named set of allowed tool names, plus an `allow_all` escape hatch for operator bypass.
- **`PledgeFilter`** (`mod.rs`) — the stateful filter: `apply(&mut CanonicalRequest, source, token)` strips `request.tools` in place.
- **Built-in profiles** (`profiles.rs`) — `read_only`, `inspect`, `sandbox`, etc.

### Pipeline position

```
DLP scan input → Tool Layer (injection/aliasing) → Pledge filter → HIT gateway → Provider dispatch
```

Pledge runs **after** the Tool Layer (so aliasing has already normalized names) and **before** HIT (so HIT scores only tools the LLM could actually call).

### Invariants enforced in code

1. When `config.enabled == false`, `apply()` returns early with zero allocation — verified by `#[cfg(test)]` assertion.
2. A profile with `allow_all = true` short-circuits the loop.
3. The filter is deterministic: same request + same config → same output, always.
4. Profile resolution order: rule match > default profile > `allow_all` (fail-open only if operator explicitly declared).

## Consequences

### Positive

- The LLM **cannot retry** a blocked tool because it was never offered. Closes the obfuscation attack vector.
- Token savings measurable (removed tool schemas often 200–500 tokens each).
- A single TOML edit + `/api/config/reload` atomically tightens the session policy without process restart.
- Trivial to extend: adding a new profile is a config change, not a code change.

### Negative

- The LLM **does not know why** a tool is absent. If a user's prompt assumes `bash` exists and it doesn't, the LLM will invent workarounds. Mitigation: document the active profile in the system prompt (caller's responsibility).
- Pledge is **not a sandbox**: it assumes the provider honors the submitted tool list. A malicious provider could inject tools; Grob does not yet detect that.
- Changing the default profile silently affects all untagged sessions. Recommended: always set rules explicitly in production.

### Neutral / to watch

- Pledge ↔ HIT composition must remain **structural-before-behavioral**. Reordering the pipeline would change semantics.
- A future CLI (`grob pledge set/clear/status`, tracked as A-4 / T-A4) will expose runtime control. The config path must remain the source of truth on restart — the CLI only writes to the config.

## Follow-ups and related ADRs

- [ADR-0010](0010-universal-tool-layer.md) — Tool Layer runs immediately before Pledge and performs aliasing that Pledge relies on.
- [ADR-0011](0011-control-engine-mcp-tools.md) — future MCP wizard tools will expose pledge profile selection.
- [ADR-0015](0015-indirect-prompt-injection-coverage.md) — Pledge mitigates some injection vectors but does not replace input/output DLP.
- `src/features/pledge/` — implementation (3 files, ~360 LOC).
- Initial commit: `5634544 feat(pledge): add structural tool filtering for LLM payloads (ADR-005)` (rescue ADR-005, officialized here).

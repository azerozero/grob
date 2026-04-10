---
status: accepted
date: 2026-04-09
deciders: [azerozero, architect]
consulted: []
informed: []
---

# ADR-0010: Universal Tool Layer — Injection, Aliasing, Capability Gating

## Context and Problem Statement

LLM providers disagree on tool support in incompatible ways:

- **Anthropic** natively supports function-calling with its own schema.
- **OpenAI** uses a different schema with slightly different semantics around `parameters` and `tool_choice`.
- **Gemini** uses `tools.functionDeclarations` with a third variant.
- **DeepSeek, Ollama, Mistral** inherit OpenAI's schema but some older models ignore tool blocks entirely.

An agent framework calling Grob expects tools to "just work" regardless of the target model. Without a translation layer, a caller must know which provider it is hitting, and either:

1. send a provider-specific payload (leaking topology to clients), or
2. omit tools and lose functionality on capable models.

Additionally, some callers send **alternative tool names** (`read`, `write`, `exec`) expecting Grob to map them to a canonical set (`read_file`, `write_file`, `bash`). And some sessions need tools *injected* that the caller forgot to declare (e.g., always include `grob_configure` when routing through the MCP server).

## Decision Drivers

- **Transparent abstraction** — callers declare intent; Grob handles provider-specific translation.
- **Composability** — injection, aliasing, and capability gating must be independent stages that can each be disabled.
- **Zero-cost when off** — `config.enabled = false` is a no-op: no allocation, no branching cost.
- **Embedded catalog** — Grob ships with a curated set of tool schemas (bash, read_file, write_file, web_search, grep) so that injection doesn't require external files at runtime.
- **Deterministic order** — the output of the layer is a pure function of the input + config.

## Considered Options

1. **Per-provider adapters** — each provider module handles its own tool translation. Leads to duplication and drift.
2. **External tool manifest** — load tool schemas from disk at startup. Adds operational burden.
3. **Universal Tool Layer with embedded catalog** — a single module applies injection, aliasing, and capability gating in a fixed order.

## Decision Outcome

**Chosen: option 3.**

Implemented in `src/features/tool_layer/` as five submodules composing a three-stage pipeline:

```
request
  │
  ▼
[1. Capability gate]  → if target model lacks tool support, strip all tools
  │
  ▼
[2. Aliasing]         → rewrite alternative names to canonical (`read` → `read_file`)
  │
  ▼
[3. Injection]        → add missing tools from embedded catalog
  │
  ▼
request (normalized)
```

### Submodules

| File | Responsibility | LOC |
|---|---|---|
| `mod.rs` | `ToolLayer` orchestrator, `process()` entry point | 287 |
| `capability.rs` | Per-model capability map (tool support yes/no) | 73 |
| `aliasing.rs` | Canonical name rewrite table | 100 |
| `catalog.rs` | Embedded tool schemas (bash, read_file, write_file, web_search, grep) | 63 |
| `injection.rs` | Adds missing tools from catalog based on rules | 112 |
| `config.rs` | `ToolLayerConfig` (TOML-driven) | 55 |
| `schemas/` | JSON schema fixtures, loaded at compile time via `include_str!` | — |

### Pipeline position

Runs **after DLP scan input** (so scans see the original tool list) and **before the Pledge filter** (so Pledge operates on canonical names). Position enforced in `src/server/dispatch/mod.rs`.

### Invariants

1. `enabled = false` → instant return, zero allocation (same contract as Pledge).
2. Capability gating is **destructive but reversible**: the stripped tools are not restored downstream. If a capable model is later added to a request, tools must be re-injected.
3. Aliasing is **idempotent**: running it twice is a no-op.
4. Injection never overwrites an existing tool definition — user-supplied schemas win.

## Consequences

### Positive

- Callers target a canonical tool vocabulary; Grob handles the rest.
- Adding a new tool to the catalog is a single-file change (`catalog.rs` + a schema).
- Multiple providers can be swapped mid-flight via `/api/config/reload` without breaking clients.
- The embedded catalog means no runtime filesystem dependency — the binary is self-sufficient.

### Negative

- The catalog is **coupled to the binary version**. Updating a tool schema requires a release. Mitigation: infrequent changes, MCP-based dynamic tools for experimental surfaces.
- Capability gating may hide failures: a model that *claims* tool support but misbehaves is not detected. Mitigation: integration tests per model.
- Aliasing table must be kept in sync with documentation. Drift risk.

### Neutral / to watch

- The Tool Layer does not enforce authorization — that's Pledge's job ([ADR-0009](0009-pledge-structural-tool-filtering.md)).
- The 5-tool embedded catalog is the v0.31 baseline. Future additions will be reviewed against scope creep.

## Follow-ups and related ADRs

- [ADR-0009](0009-pledge-structural-tool-filtering.md) — Pledge filter runs immediately after the Tool Layer.
- [ADR-0011](0011-control-engine-mcp-tools.md) — future MCP wizard tools will share the catalog's schema loading path.
- `src/features/tool_layer/` — implementation (6 files, ~690 LOC + schemas).
- Initial commit: `41959dd feat: add universal tool layer v1 (injection, aliasing, capability gating)` (rescue ADR-004, officialized here).

# tool_layer

> Universal tool layer: capability gating, name aliasing, and catalog injection on the canonical request.

## Purpose

`tool_layer` mutates `CanonicalRequest.tools` after DLP and before cache lookup
in the dispatch pipeline. It removes tools for models that lack tool support,
rewrites alternative tool names to canonical form (`execute_command` → `bash`),
and injects missing tools (e.g. `web_search`) from an embedded catalog so any
client gets a consistent tool palette regardless of which surface it speaks.
The layer is fully config-driven and a zero-cost no-op when `enabled = false`.

## Public API

| Item | Location | Used by |
|------|----------|---------|
| `ToolLayer::new`, `process` | `mod.rs` | `server/mod.rs`, `server/dispatch/mod.rs` |
| `ToolLayerConfig`, `CapabilityEntry`, `InjectRule`, `AliasRule` | `config.rs` | `cli/mod.rs` (TOML deserialization) |
| `capability::should_block_tools` | `capability.rs` | `mod.rs::process` |
| `aliasing::apply_aliases` | `aliasing.rs` | `mod.rs::process` |
| `injection::inject_tools` | `injection.rs` | `mod.rs::process` |
| `catalog::lookup`, `catalog::CatalogEntry` | `catalog.rs` | `injection.rs` |
| Embedded JSON schemas | `schemas/{bash,grep,read_file,web_search,write_file}.json` | `catalog.rs` (compile-time `include_str!`) |

## Owns

- `mod.rs` — `ToolLayer` orchestrator and the three-step pipeline.
- `config.rs` — TOML config types (`[tool_layer]` section).
- `capability.rs` — Provider/model capability check (`tools_supported`, `no_tool_models`).
- `aliasing.rs` — In-place rename of tool names.
- `injection.rs` — Adds catalog tools when absent from the request.
- `catalog.rs` — Static lookup table of canonical tool definitions.
- `schemas/*.json` — JSON Schemas for each canonical tool (compiled in).

## Depends on

- `crate::models::{CanonicalRequest, Tool}` — The mutation target.
- `serde`, `serde_json` — Config and schema deserialization.
- `tracing` — Info-level log when tools are stripped.

## Non-goals

- No tool execution — this layer only shapes the request payload.
- No DLP, no policy decisions, no per-tool authorization — those live in
  `features/{dlp,policies,pledge}`.
- No runtime catalog mutation — tool definitions are compile-time embedded.
- No transport-specific translation — the layer operates on `CanonicalRequest`.

## Tests

- `mod.rs::tests` covers alias resolution, injection idempotency, capability
  blocking, schema preservation, and pass-through of unknown tools.
- Submodules colocate unit tests for `aliasing`, `injection`, `catalog::lookup`,
  and `capability::should_block_tools`.

## Related ADRs

- [ADR-0010 — Universal tool layer](../../../docs/decisions/0010-universal-tool-layer.md) (the foundational design).
- [ADR-0009 — Pledge structural tool filtering](../../../docs/decisions/0009-pledge-structural-tool-filtering.md) (sibling layer that runs after this one).
- [ADR-0011 — Control engine and MCP tools](../../../docs/decisions/0011-control-engine-mcp-tools.md) (catalog parity with MCP surface).

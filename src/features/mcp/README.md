# features::mcp

> MCP (Model Context Protocol) tool matrix, JSON-RPC server, and self-tuning scorer.

## Purpose

Exposes grob's control plane as MCP tools (query, bench, calibrate, hint, configure, report) and maintains a per-provider tool-calling capability matrix. Continuous benchmarks update a rolling [`scorer::ToolScorer`] window to feed the router with empirical reliability data per `(tool, provider)` pair. The wizard tools satisfy ADR-0008's "ask once, defaults, recap, config-as-code" laws.

## Public API

| Item | Location | Used by |
|------|----------|---------|
| `McpState` | `mod.rs` | `server::mod`, `server::mcp_handlers` |
| `McpConfig`, `McpServerConfig`, `BenchConfig`, `ToolRoutingConfig`, `ToolChain` | `config.rs` | `models::config` |
| `ToolMatrix`, `ToolEntry`, `ToolSchema`, `ProviderToolCapability`, `ToolScore`, `RuntimeScores` | `matrix.rs` | router, MCP server |
| `ToolScorer`, `ToolMetric` | `scorer.rs` | bench engine |
| `calibration::calibrate_tools` | `calibration.rs` | dispatch — per-request tool gating |
| `bench::spawn_bench_engine`, `bench::evaluator::evaluate`, `bench::test_cases::*` | `bench/` | startup, periodic recalibration |
| `server::types::{JsonRpcRequest, JsonRpcResponse, RpcError, *Params}` | `server/types.rs` | `server::mcp_handlers` |
| `server::methods::*` | `server/methods.rs` | JSON-RPC method dispatch |

## Owns

- Static TOML tool capability catalogue (per provider).
- Rolling-window scorer (default 50 samples) with success-rate and latency metrics.
- Bench engine: scenario runner, evaluator, test-case fixtures.
- MCP JSON-RPC types and methods.
- Per-request tool calibration that strips unsupported tools before dispatch.

## Depends on

- `crate::models` — `CanonicalRequest`, `Message`, `ProviderResponse`.
- `crate::providers` — to issue bench requests.
- `crate::security::provider_scorer` — shared rolling-window pattern.
- `serde`, `tokio::sync::RwLock`, `tracing`, `metrics`.

## Non-goals

- Not the universal tool layer (`features::tool_layer`) that adapts tool dialects.
- Not the structural pledge filter (`features::pledge`).
- HTTP / SSE transport lives in `server::mcp_handlers`, not here.
- No persistence: scorer state is in-memory and rebuilt on restart.

## Tests

- Unit tests in `matrix.rs`, `scorer.rs`, `calibration.rs`, `bench/evaluator.rs`, `server/methods.rs`.
- Integration tests via the MCP HTTP surface (see `server::mcp_handlers`).
- Wizard E2E: `tests/e2e/tests/wizard/`.

## Related ADRs

- [ADR-0011](../../../docs/decisions/0011-control-engine-mcp-tools.md) — Control engine via MCP tools
- [ADR-0008](../../../docs/decisions/0008-wizard-lifecycle.md) — Wizard lifecycle (config-as-code)
- [ADR-0010](../../../docs/decisions/0010-universal-tool-layer.md) — Universal tool layer (adjacent)

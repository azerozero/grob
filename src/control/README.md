# control

> Generic `(role, action) → response` engine shared by CLI, JSON-RPC, MCP, and future UI adapters.

## Purpose
Centralises the action catalog and RBAC checks so every operator surface speaks the same vocabulary. Adapters translate transport-specific input (CLI flags, JSON-RPC method names, MCP tool calls, HTTP routes) into an `Action` variant, the engine resolves the required `Role`, and the result comes back as a uniform `ControlResponse` or `ControlError`.

## Public API
| Item | Location | Used by |
|------|----------|---------|
| `Action` (top-level enum, 9 namespaces) | `engine.rs` | every adapter |
| `ServerAction`, `ModelAction`, `ProviderAction`, `BudgetAction`, `KeysAction`, `ConfigAction`, `ToolsAction`, `HitAction`, `PledgeAction` | `engine.rs` | adapter dispatch |
| `Role` (`Observer`, `Operator`, `Admin`, `Superadmin`), `Role::has_at_least` | `engine.rs` | server auth, MCP auth |
| `required_role(action)` | `engine.rs` | adapter authorization |
| `parse_method(method, params)` | `engine.rs` | JSON-RPC adapter |
| `ControlResponse::ok`, `ok_message` | `engine.rs` | adapter encoders |
| `ControlError`, `ControlErrorCode` (`Unauthorized`, `Forbidden`, `NotFound`, `Internal`, `BudgetExceeded`, `InvalidParams`) | `engine.rs` | adapter encoders |
| `ALL_METHODS` | `engine.rs` | discovery, MCP listing |

## Owns
- The single canonical action catalog (`Action` and its nine sub-enums).
- The four-level role hierarchy with monotonic privilege ordering (`Observer < Operator < Admin < Superadmin`).
- The action → required-role mapping (`required_role`).
- The JSON-RPC method-string parser (`parse_method`) and the discoverable method list (`ALL_METHODS`).
- A uniform success/error envelope serialisable to JSON for any transport.

## Depends on
- `serde`, `serde_json` only. Pure data and dispatch logic — no I/O, no async.

## Non-goals
- Executing actions. The engine encodes shape and authorization; servers/CLIs/MCP servers wire it to actual state mutators.
- Transport framing (HTTP, JSON-RPC, MCP, stdio). Adapters own that.
- Persistence. Stateless by design.
- Streaming responses. Single-shot envelope only.

## Tests
- `tests/unit/rpc_test.rs` exercises `parse_method` and the JSON-RPC adapter end-to-end.
- Inline tests cover `Role::has_at_least`, `required_role`, and method discovery completeness.

## Related ADRs
- [ADR-0011](../../docs/decisions/0011-control-engine-mcp-tools.md) — ControlEngine generic + MCP-tools-first configuration surface.
- [ADR-0008](../../docs/decisions/0008-wizard-lifecycle.md) — Wizard actions exposed via this engine.

# pledge

> Pledge filter: structurally strips tool definitions before dispatch so the LLM never sees forbidden tools.

## Purpose

`pledge` resolves a session profile from the request source (`mcp`, `cli`, `api`)
or a bearer-token prefix and removes every tool whose name is not in the
profile's allowlist. Unlike a runtime blacklist (which blocks at execution time
and forces retries), a pledged session simply cannot emit a `tool_use` block for
a forbidden tool because that tool literally does not appear in the request the
provider receives. Built-in profiles are `read_only`, `execute`, `full`, and
`none`; the system is a no-op when `enabled = false`.

## Public API

| Item | Location | Used by |
|------|----------|---------|
| `PledgeFilter::new`, `apply` | `mod.rs` | `server/dispatch/mod.rs` |
| `PledgeConfig`, `PledgeRule` | `config.rs` | `cli/mod.rs`, `models/config.rs`, `server/rpc/pledge_ns.rs` |
| `PledgeProfile` (struct) | `config.rs` | `profiles.rs` |
| `profiles::resolve`, `READ_ONLY`, `EXECUTE`, `FULL`, `NONE` | `profiles.rs` | `mod.rs::resolve_profile`, `cli.rs` |
| `cli::cmd_list_profiles`, `cmd_status`, `validate_profile`, `format_set_message`, `format_clear_message` | `cli.rs` | `commands/pledge.rs`, `server/rpc/pledge_ns.rs` |

## Owns

- `mod.rs` — `PledgeFilter` and the source/token rule resolver.
- `config.rs` — TOML config types (`[pledge]` section).
- `profiles.rs` — Built-in profile constants and name-based lookup.
- `cli.rs` — Helpers for the `grob pledge` subcommands and the JSON-RPC namespace.

## Depends on

- `crate::models::CanonicalRequest` — The request whose `tools` field is filtered.
- `serde` — Config deserialization.

## Non-goals

- No execution-time enforcement — that belongs to `features/policies` and the
  HIT gateway.
- No tool injection or aliasing — those live in `features/tool_layer` and run
  before this filter.
- No DLP on tool inputs — `features/dlp` handles content scanning.
- No dynamic profile authoring at runtime — profiles are compile-time constants
  on purpose (auditability).

## Tests

- `mod.rs::tests` covers `read_only`, `execute`, `full`, `none` semantics, MCP
  source override, CLI fall-through to default, token-prefix matching, and the
  disabled no-op path.
- Profile lookup is exercised indirectly through every test in `mod.rs`.

## Related ADRs

- [ADR-0009 — Pledge structural tool filtering](../../../docs/decisions/0009-pledge-structural-tool-filtering.md) (the foundational design).
- [ADR-0010 — Universal tool layer](../../../docs/decisions/0010-universal-tool-layer.md) (sibling layer that runs before pledge).
- [ADR-0006 — Policy engine, encrypted audit, HIT gateway](../../../docs/decisions/0006-policy-engine-encrypted-audit-hit-gateway.md) (defense in depth at execution time).

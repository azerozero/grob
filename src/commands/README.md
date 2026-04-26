# commands

> Implements every grob CLI subcommand: server lifecycle, diagnostics, secrets, presets, bench.

## Purpose
Hosts the imperative entry points dispatched from `main.rs` after clap parses the argv. Each module corresponds to a single subcommand or family (`start`, `stop`, `doctor`, `secrets`, `bench`, `setup`, …) and stays self-contained so the binary stays small and the surface stays reviewable.

## Public API
| Item | Location | Used by |
|------|----------|---------|
| `cmd_init`, `cmd_env`, `cmd_completions`, `cmd_setup_completions` | `init.rs`, `env.rs`, `completions.rs`, `setup_completions.rs` | `main.rs` |
| `cmd_secrets_{add,list,show,rm}` | `secrets.rs` | `main.rs` |
| `cmd_logs_decrypt` | `logs.rs` | `main.rs` |
| `cmd_preset_info`, `cmd_preset_export` | `preset.rs` | `main.rs` |
| `cmd_config_diff` | `config_diff.rs` | `main.rs` |
| `setup::SetupFlags` (interactive wizard entry) | `setup/mod.rs` | `main.rs` |
| `bench` engine (`mock`, `scenarios`, `stats`, `output`, `payloads`) | `bench/` | `main.rs` |
| `common::spawn_background_service`, polling constants | `common.rs` | `start`, `restart` |
| `rpc_client` (JSON-RPC 2.0 client) | `rpc_client.rs` | `connect`, `status`, `stop` |
| `custom_validation_request` | `credential_check.rs` | `doctor`, `setup` |

## Owns
- Server lifecycle: `start` (daemonize), `stop` (graceful), `restart`, `run` (foreground), `status`.
- Operator UX: `init`, `setup` wizard (8 screens, recap, atomic write), `doctor`, `validate`, `env`.
- Data ops: `spend`, `key`, `secrets`, `logs decrypt`, `model`, `preset`.
- Config lifecycle: `config-diff`, `config_promote`, `config_rollback`.
- `bench/`: self-contained throughput + latency harness with mock backend.
- `harness/`: record-and-replay sandwich tests (opt-in feature flag).

## Depends on
- `crate::cli` (argument types, config structs).
- `crate::server`, `crate::providers`, `crate::auth`, `crate::storage` for actual behaviour.
- `crate::control` engine (CLI is one adapter, see ADR-0011).
- `crate::preset` for `setup` and `preset` subcommands.

## Non-goals
- Defining argument shapes (lives in `cli::args`).
- Long-running server logic (lives in `server/`).
- Provider HTTP clients (lives in `providers/`).
- Holding shared mutable state. Each command runs to completion and exits.

## Tests
- `tests/unit/setup_wizard_test.rs` covers wizard recap + atomic write.
- `tests/unit/rpc_test.rs` exercises the JSON-RPC client against an in-process server.
- `tests/enterprise/preset_snapshot_test.rs` snapshots `apply_preset` outputs.
- Bench, doctor, init are exercised by integration smoke tests in `tests/integration/`.

## Related ADRs
- [ADR-0001](../../docs/decisions/0001-static-config-no-hot-reload.md) — Static config (drives `restart` semantics).
- [ADR-0008](../../docs/decisions/0008-wizard-lifecycle.md) — Wizard lifecycle (setup, doctor, edit, migrate).
- [ADR-0011](../../docs/decisions/0011-control-engine-mcp-tools.md) — CLI as ControlEngine adapter.
- [ADR-0013](../../docs/decisions/0013-storage-files-no-redb.md) — Storage choice surfaced via `secrets` and `logs` commands.

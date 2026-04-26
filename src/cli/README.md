# cli

> Defines the clap argument tree, the static TOML schema, and validated newtypes.

## Purpose
Owns the user-facing surface of grob: every CLI flag, every subcommand declaration, and the strongly-typed config structs that the TOML loader deserializes into. Stays a leaf module so the rest of the crate depends on it without forming a cycle. Re-exports `AppConfig` from `models::config` for backwards compatibility.

## Public API
| Item | Location | Used by |
|------|----------|---------|
| `Cli`, `Commands` (clap derive) | `args.rs` | `main.rs`, `commands/*` |
| `detect_bare_trailing_cmd` | `args.rs` | `main.rs` (UX guard) |
| `*Action` enums (`KeyAction`, `SecretsAction`, `PresetAction`, `LogsAction`, `HarnessAction`) | `args.rs` | `commands/*` dispatchers |
| `ServerConfig`, `RouterConfig`, `ProviderConfig`, `ModelConfig` | `config/{server,routing,providers}.rs` | `models::config`, providers |
| `SecurityConfig`, `ComplianceConfig`, `TeeConfig`, `FipsConfig` | `config/security.rs` | `security/*` |
| `BudgetConfig`, `CacheConfig`, `TracingConfig`, `OtelConfig` | `config/{budget,cache,telemetry}.rs` | features layer |
| `SecretsConfig`, `SecretsBackend`, `SecretsFileConfig` | `config/secrets.rs` | `auth::secrets` |
| `BudgetUsd`, `Port`, `BodySizeLimit`, `ConfigSource` | `newtypes.rs` | server, budget |
| `parse_duration` | `config/reliability.rs` | TOML parsing |
| `format_bind_addr`, `format_base_url` | `mod.rs` | server bind, status |

## Owns
- The clap derive tree (single source of truth for `--help`).
- The TOML schema for every section: `[server]`, `[router]`, `[[providers]]`, `[[models]]`, `[security]`, `[compliance]`, `[budget]`, `[cache]`, `[secrets]`, `[tracing]`, `[otel]`, `[user]`, `[harness]`.
- Validated newtypes that reject invalid ports, budgets, and body-size limits at deserialization time.
- IPv6-aware bind/URL formatting helpers.

## Depends on
- `clap`, `clap_complete`, `serde`, `toml` for derive plumbing.
- `crate::features::log_export::LogExportConfig` and `crate::features::tool_layer::config::ToolLayerConfig` (re-exported).
- `crate::models::config::AppConfig` (re-exported to break the historical cycle).

## Non-goals
- Reading or writing config files (`models::config` and `commands::*` handle I/O).
- Implementing subcommand logic (lives in `commands/*`).
- Runtime configuration mutation. Config is static once loaded; see ADR-0001.
- Provider behaviour or routing logic.

## Tests
- Inline unit tests in `mod.rs` cover IPv4/IPv6 bind formatting.
- `tests/unit/config_test.rs` exercises round-trip TOML parsing of every config struct.
- `tests/unit/tier_config_test.rs` covers tier matching deserialization edge cases.

## Related ADRs
- [ADR-0001](../../docs/decisions/0001-static-config-no-hot-reload.md) — Static config, no hot reload.
- [ADR-0011](../../docs/decisions/0011-control-engine-mcp-tools.md) — Control engine and MCP-tools-first surface (CLI is one of three adapters).

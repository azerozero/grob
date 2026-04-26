# preset

> Manages builtin and installed config presets: load, apply, overlay, export, validate, sync, credentials.

## Purpose
Provides curated TOML config bundles (`perf`, `medium`, `local`, `cheap`, `fast`, `gdpr`, `eu-ai-act`) plus user-installed presets in `~/.grob/presets/`. Merges a preset into an existing config while preserving `[server]` and `[user]`, validates that every routing target resolves to a real provider+model, and orchestrates the credential wizard for providers a preset requires.

## Public API
| Item | Location | Used by |
|------|----------|---------|
| `PresetInfo`, `list_presets`, `preset_dir`, `preset_content` | `mod.rs` | `commands::preset`, `setup` |
| `apply_preset`, `preview_preset`, `overlay_compliance`, `export_preset` | `mod.rs` | `commands::preset`, `setup` |
| `print_preset_info` | `mod.rs` | `commands::preset` |
| `MappingResult`, `ModelValidation`, `validate_config`, `build_registry`, `print_validation_results`, `log_validation_results` | `validation.rs` | `commands::validate`, `doctor`, server startup |
| `CredentialStatus`, `check_credentials`, `setup_credentials_interactive`, `setup_credentials_interactive_filtered`, `load_oauth_provider_list_pub` | `credentials.rs` | `setup` wizard, `doctor` |
| `parse_interval`, `spawn_background_sync`, `sync_presets`, `install_from_source` | `sync.rs` | `start`, `commands::preset` |

## Owns
- Seven builtin presets shipped via `include_str!` from `presets/*.toml`.
- TOML merge logic: replaces `[router]`, `[[providers]]`, `[[models]]`, `[security]`, `[compliance]`, `[dlp]` while keeping `[server]` and `[user]` intact, sets `presets.active`.
- Compliance overlay path: merges only `[security]`, `[compliance]`, `[dlp]`, plus `router.gdpr`/`router.region`.
- Backup-before-write (`config.toml.backup`) on every apply.
- Validation: checks every routing target resolves to a registered provider+model, surfaces missing OAuth/api-key credentials.
- Background sync from a Git source URL, periodic refresh, install-from-source.

## Depends on
- `crate::cli` (config structs), `crate::models::config::AppConfig`.
- `crate::providers::registry::ProviderRegistry`, `crate::auth::TokenStore`.
- `toml`, `anyhow`, `tempfile` (tests).

## Non-goals
- Editing presets in place. Users export, edit by hand, then re-apply.
- Provider HTTP behaviour (lives in `providers/`).
- Wizard UX (lives in `commands::setup`; this module supplies primitives).
- Hot-reload. Apply rewrites the file; the user calls `grob restart` or `/api/config/reload`.

## Tests
- Inline tests in `mod.rs` cover apply round-trip, builtin TOML parsing, interval parsing, list-with-builtins.
- `tests/enterprise/preset_snapshot_test.rs` snapshots merged config for every builtin preset.

## Related ADRs
- [ADR-0001](../../docs/decisions/0001-static-config-no-hot-reload.md) — Apply rewrites file; reload is atomic.
- [ADR-0008](../../docs/decisions/0008-wizard-lifecycle.md) — Setup wizard drives `apply_preset` + `setup_credentials_interactive`.

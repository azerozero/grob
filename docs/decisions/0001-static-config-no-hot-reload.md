# ADR-0001: Explicit API reload — no filesystem hot-reload

## Status

Accepted

## Context and Problem Statement

Grob loads configuration from a TOML file at startup. Should the server watch the config file and reload on changes, or require a restart?

## Decision Drivers

- Simplicity of implementation and reasoning about state
- Avoiding race conditions between in-flight requests and config changes
- Provider credentials and routing rules changing mid-request could cause silent failures
- Operator predictability — config changes take effect at a known point in time

## Considered Options

- Hot reload with file watcher (notify crate)
- Signal-based reload (SIGHUP)
- Static config, restart to apply changes
- Explicit API-triggered reload (chosen)

## Decision Outcome

Chosen option: "Explicit API-triggered reload", because it eliminates filesystem-watching complexity while giving operators a controlled, intentional mechanism to apply changes without a restart. Config is not file-watched; changes only take effect when the operator explicitly calls `/api/config/reload` or restarts the server.

### Design

`AppState` splits state into two tiers:

**Reloadable** — wrapped in `RwLock<Arc<ReloadableState>>` and swapped atomically by `/api/config/reload`:

| Field | Type |
|-------|------|
| `config` | Full `AppConfig` |
| `router` | Compiled routing engine |
| `provider_registry` | Provider registry with API keys |
| `model_index` | `HashMap<String, usize>` for O(1) model lookup |
| `policy_matcher` | Compiled glob policy engine (from `[[policies]]`) |

**Stable** — created once at startup, never reloaded:

| Field | Why stable |
|-------|-----------|
| `spend_tracker` | Cross-reload spend continuity |
| `grob_store` | File-based storage backend |
| `token_store` | OAuth token cache |
| `audit_log` | Hash chain must be continuous |
| `rate_limiter` | Token bucket state must persist |
| `circuit_breakers` | Failure state must survive reloads |
| `response_cache` | Cache hits across reloads are valuable |
| `event_bus` | Live subscribers must not be disconnected |
| `MCP` state | Tool matrix state is session-scoped |

In-flight requests call `state.snapshot()` at entry, which clones the `Arc<ReloadableState>`. The swap only updates the `RwLock` inner value — in-flight requests hold their own `Arc` clone and are unaffected.

### Consequences

- Good, because no race conditions — in-flight requests always see a consistent snapshot
- Good, because operator controls exactly when config takes effect (explicit API call)
- Good, because no watcher thread, no inotify dependency, no race between FS events and request timing
- Good, because reload atomically rebuilds router + registry + model index together (no partial state)
- Bad, because a config file edit is not applied until `/api/config/reload` is called (by design)

### Confirmation

`src/server/mod.rs`: `AppState.inner: RwLock<Arc<ReloadableState>>` and `snapshot()` accessor.
`src/server/config_api.rs`: `reload_config` handler performs the atomic swap.

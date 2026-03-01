# ADR-0001: Static config — no hot reload

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

## Decision Outcome

Chosen option: "Static config, restart to apply changes", because it eliminates an entire class of concurrency bugs and makes the server behavior fully deterministic. Config is loaded once into an `Arc` and shared immutably across all request handlers.

### Consequences

- Good, because no race conditions between config changes and in-flight requests
- Good, because simpler implementation — no watcher thread, no locking, no config versioning
- Good, because operator always knows which config is active (the one loaded at startup)
- Bad, because config changes require a server restart (mitigated by fast startup time)

### Confirmation

The `AppState` struct holds config in an `Arc<Config>` with no interior mutability. Any attempt to mutate config at runtime would be a compile error.

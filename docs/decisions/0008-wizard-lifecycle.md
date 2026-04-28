---
status: accepted
date: 2026-04-03
accepted: 2026-04-28
---

> **Promotion note (2026-04-28)**: Status flipped from `proposed` to `accepted`.
> Trigger: ADR-0011 (ControlEngine + MCP-tools-first) is already `accepted` and
> formally depends on this ADR — keeping ADR-0008 `proposed` was a status inversion.
> Implementation work (chantier A-1: ControlEngine, A-2: CLI thin wrapper) is
> unblocked. No code changes ship in this PR — implementation tracked separately.

# ADR-0008: Wizard Lifecycle Architecture

**Status:** Accepted
**Date:** 2026-04-03
**Accepted:** 2026-04-28
**Context:** The current `grob setup` wizard is a one-shot interactive flow that doesn't re-examine existing config, doesn't validate after generation, and has broken OAuth auto-start promises.

## Decision

Unify `setup`, `doctor`, `connect`, and `auto_flow` into a single config lifecycle engine following the OpenBSD/step-ca pattern.

### Core Principles

1. **Ask once, derive the rest** — if a value can be computed from another, don't prompt for it
2. **Defaults are decisions** — every default is an opinionated choice, never empty
3. **Recap before apply** — show diff before touching the filesystem
4. **Config-as-code output** — wizard generates a committable TOML file, never hidden state

### State Machine

```
grob start / grob exec
     │
     ├── config absent → setup mode (questions)
     ├── config present + all creds OK → start immediately (zero prompts)
     └── config present + missing creds → auto_flow (per-provider skip)
           ├── OAuth → print URL, paste code
           └── API key → enter or skip

grob doctor
     ├── lint config (schema, deprecated fields)
     ├── test connectivity (probe each backend)
     ├── compare against current schema (migration needed?)
     └── propose diff → confirm → apply

grob setup (explicit re-run)
     └── reads existing config → shows current values as defaults → diff → apply
```

### Three Surfaces, One Engine

```
CLI (stdin/stderr)  ─┐
MCP tool calls      ─┼──→ wizard engine ──→ grob.toml ──→ grob reload
Web UI (future)     ─┘
```

The wizard engine is a pure function: `(current_config, answers) → new_config_toml`.
Each surface collects answers differently but produces the same input.

### MCP Tools

```
wizard_get_config()          → read current TOML, return as struct
wizard_set_value(path, val)  → modify config, return diff
wizard_run_doctor()          → return pass/warn/fail per check
wizard_apply()               → write TOML + reload grob
wizard_diff()                → show pending changes before apply
```

### Doctor Checks

| Check | What | Severity |
|-------|------|----------|
| Schema | config.toml valid against current schema | error |
| Backends | HTTP probe on each configured backend | error |
| DLP rules | regexes compile, no conflicts | error |
| Credentials | OAuth tokens valid, API keys set | warn |
| Audit log | path writable, signing key valid | warn |
| Versions | config version vs binary version | info |

### Server Mode vs Client Mode

**Server mode** (remote grob + reverse proxy):
```
wizard → generates:
  grob.toml       (backends, routing, DLP)
  Caddyfile       (TLS, reverse proxy to grob)
  compose.yaml    (orchestration)
```

**Client mode** (local grob):
```
wizard → generates:
  ~/.grob/config.toml (providers, routing, budget)
```

### What Gets Removed

- `grob connect` becomes `grob setup --credentials-only` (alias kept for compat)
- Duplicate validation at startup (init + post-init) collapses to one pass
- "OAuth will trigger on first start" promise replaced by actual auto_flow
- JSON config format: TOML is the only user-facing format

## Consequences

- Users always have a single committable TOML file as source of truth
- Agents (MCP) configure grob the same way humans do
- Doctor replaces ad-hoc validation scattered across start/connect/status
- E2E testable via piped stdin or MCP tool calls

## Test Plan

See `tests/e2e/tests/wizard/run-wizard-tests.sh` for the lifecycle chain:
W0 (no config) → W1 (setup) → W2 (parse) → W3-W6 (functional) → W7 (reload) → W8 (stop) → W9 (re-setup)

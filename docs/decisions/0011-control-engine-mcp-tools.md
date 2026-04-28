---
status: accepted
date: 2026-04-09
deciders: [azerozero, architect]
consulted: []
informed: []
---

# ADR-0011: ControlEngine Generic + MCP-Tools-First Configuration Surface

## Context and Problem Statement

Grob exposes configuration and lifecycle actions (setup, connect, pledge, doctor, spend, key rotation) across three surfaces that will soon grow to four:

1. **CLI** — `grob setup`, `grob exec`, `grob pledge`, `grob doctor`.
2. **Control Plane JSON-RPC** — four namespaces shipped in v0.31 (`server`, `model`, `provider`, `budget`).
3. **MCP tools** — a wizard MCP server exposing `wizard_*` functions that an AI agent can call.
4. **Future embedded UI** (B-1) — the browser surface.

Each surface currently implements its own command dispatch logic. The CLI embeds the setup wizard logic directly in `src/commands/setup.rs`. The JSON-RPC server re-implements lookups over the same state. The MCP wizard tools (introduced by [ADR-0008](0008-wizard-lifecycle.md)) are a third, partial implementation.

This duplication has already caused drift:

- A fix to preset resolution in the CLI was not applied to the JSON-RPC path.
- The MCP wizard tool for budget display shows a different format than `grob spend`.
- Adding a new wizard step means editing three files and remembering to keep them aligned.

[ADR-0008](0008-wizard-lifecycle.md) proposed a wizard lifecycle engine but scoped it to the setup/doctor/connect/auto_flow triad. The scope needs to expand.

## Decision Drivers

- **Single source of behavior** — one module decides what each action does; the surfaces are thin adapters.
- **Testable in isolation** — the engine must be a pure function `(state, action) -> (new_state, effects)` with no I/O, so it can be property-tested and fuzzed.
- **MCP-tools-first** — instead of extending the JSON-RPC namespace map indefinitely, new control surfaces are exposed as MCP tools. The JSON-RPC namespaces stay frozen at v1.
- **Surface parity by construction** — adding an action to the engine automatically makes it reachable from all surfaces once each adapter routes the new action variant.
- **No extension of JSON-RPC** — deliberately constrain the RPC namespace surface area. MCP covers the growth path.

## Considered Options

1. **Extend the JSON-RPC namespace map** — add `keys`, `config`, `tools`, `hit`, `pledge` namespaces (rescue ADR-001's original plan). Rejected because MCP tools give the same reach without growing the schema, and because agents prefer tools over raw RPC.
2. **Keep three parallel implementations, wire them to a shared helper module** — insufficient; the helper grows into a de-facto engine without the discipline of pure functions.
3. **Introduce a pure `ControlEngine`** — `(state, action) -> new_state` module with **three** thin adapters (CLI, MCP, UI). Drop the RPC namespace expansion plan.

## Decision Outcome

**Chosen: option 3.**

### Architecture

```
                          ┌──────────────┐
                          │ ControlEngine│
                          │  (pure fn)   │
                          └──────┬───────┘
               ┌─────────────────┼─────────────────┐
               ▼                 ▼                 ▼
        ┌────────────┐    ┌────────────┐    ┌────────────┐
        │ CLI adapter│    │ MCP adapter│    │ UI adapter │
        │ commands/* │    │ features/  │    │ server/ui  │
        │            │    │ mcp/       │    │ (future)   │
        └────────────┘    └────────────┘    └────────────┘
```

- **`ControlEngine`** (planned `src/control/engine.rs`) — pure state machine. Inputs: current `AppState` snapshot + `Action` enum. Outputs: new `AppState` + a list of `SideEffect` values describing what the adapter must actually do (spawn OAuth flow, write config file, call provider API).
- **CLI adapter** (`src/commands/`) — interprets side effects, shows progress to humans, returns exit codes.
- **MCP adapter** (`src/features/mcp/`) — exposes the action variants as MCP tools (`wizard_setup_start`, `wizard_select_preset`, `grob_configure`, …). The MCP surface grows with the engine, not with the JSON-RPC namespace map.
- **UI adapter** (future, B-1) — HTML + SSE + JWT embedded via `rust-embed`, consuming the same engine.

### JSON-RPC namespaces: frozen

The four v0.31 namespaces (`server`, `model`, `provider`, `budget`) remain. No new namespace will be added. The five namespaces originally planned in rescue ADR-001 (`keys`, `config`, `tools`, `hit`, `pledge`) are **not** implemented as RPC — they become MCP tools instead.

### Migration order

1. **A-1** — extract a `ControlEngine` skeleton with two actions (`SetupStart`, `SetupConfirm`) as proof of concept.
2. **A-2** — refactor the CLI commands one by one to go through the engine.
3. **A-3** — extend the MCP wizard tools to cover the engine's full action set.
4. **B-1** — implement the UI adapter on top of the same engine.

Sequenced: A-1 blocks A-2 / A-3 / B-1 (structural refactor, conflict risk).

## Consequences

### Positive

- **One source of truth** for what each action does. Tests run against the engine in isolation.
- Adding a new action once exposes it on all surfaces.
- MCP-first gives AI agents a natural path to drive Grob without needing raw RPC access.
- Reduces the incentive to grow the JSON-RPC schema, which is already frozen at v1 per [ADR-0001](0001-static-config-no-hot-reload.md).

### Negative

- The refactor is **structurally invasive**. Everything that currently touches `commands/*.rs`, `server/rpc/`, and `features/mcp/` is impacted. Expected ~2 days of work with conflicts.
- A pure engine plus side-effect list is a pattern unfamiliar to contributors used to direct I/O. Onboarding cost.
- MCP tools are less discoverable than RPC namespaces for non-AI consumers. Mitigation: each tool is listed with a description and example in `grob doctor`.

### Neutral / to watch

- The `self-tuning MCP tool` (`grob_configure`, shipped in PR #100 / v0.35.0) is the first production-ready MCP control surface. It is the canonical example of the MCP-tools-first pattern.
- Once the engine lands, the "command duplication" anti-pattern in `commands/` must be audited to confirm it has been eliminated.

## Follow-ups and related ADRs

- Extends [ADR-0008: Wizard Lifecycle Architecture](0008-wizard-lifecycle.md) — ADR-0008's state machine becomes a special case of the ControlEngine's action set. ADR-0008 was promoted to `accepted` on 2026-04-28; this dependency is now satisfied and chantiers A-1/A-2 are unblocked.
- [ADR-0009](0009-pledge-structural-tool-filtering.md), [ADR-0010](0010-universal-tool-layer.md) — modules that the engine orchestrates.
- [ADR-0013](0013-storage-files-no-redb.md) — engine state persistence lands on the files backend.
- Chantiers: A-1 (engine), A-2 (CLI thin), A-3 (MCP wizard extend) in the sprint menu.
- Current code: `src/server/rpc/` (JSON-RPC namespaces), `src/features/mcp/` (MCP tools including `grob_configure` from PR #100).

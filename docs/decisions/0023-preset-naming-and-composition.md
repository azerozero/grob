---
status: proposed
date: 2026-04-28
deciders: [azerozero]
consulted: []
informed: []
supersedes: []
related: [ADR-0008, ADR-0022, ADR-0024]
---

# ADR-0023: Preset Naming and Composition Strategy

## Context and Problem Statement

Grob ships five built-in presets today (`perf`, `ultra-cheap`, `eu-eco`,
`eu-pro`, `eu-max`) plus two compliance overlays (`gdpr`, `eu-ai-act`) under
`presets/*.toml`. The set has been growing organically: each new audience has
been served by adding a preset, sometimes by splitting an existing one
(`eu` → `eu-eco`/`eu-pro`/`eu-max` in a recent release; see CHANGELOG),
sometimes by adding an overlay alongside (`gdpr.toml`, `eu-ai-act.toml`).

Two structural questions have never been settled:

1. **What makes a preset shippable as a built-in?** The current heuristic is
   "the maintainer thinks a meaningful audience exists". This produces
   inconsistencies — for example, `optimal` shipped briefly in a recent
   release then was retired before users adopted it (see CHANGELOG).
   There is no checklist a candidate must pass.
2. **How do presets compose?** `gdpr.toml` and `eu-ai-act.toml` look like
   presets but are actually meant to be applied **on top of** another preset.
   Nothing in the file format distinguishes the two roles. A user reading
   `presets/index.toml` cannot tell that `gdpr` is an overlay and `eu-pro`
   is a base.

These ambiguities surface in three operational pain points:

- **Discovery.** `grob preset list` flattens overlays and bases into one
  list, so first-time users get confused about which one to pick.
- **Configuration drift.** When a base preset (e.g. `eu-pro`) is updated
  with a new provider, the overlay (`gdpr`) does not automatically reflect
  the change because the relationship is implicit, not declared.
- **Naming sprawl.** Without a convention, future presets risk landing
  with inconsistent names — `eu-strict-2026`, `cheap-no-anthropic`,
  `experimental-bandit-routing` — making the catalogue hard to navigate.

ADR-0022 introduces structured `[endpoints.compliance]` blocks. This makes
the overlay-vs-base distinction tractable in code: an overlay is a config
fragment that targets `[endpoints.compliance]` keys, a base is a full
routing configuration. The schema is now expressive enough to formalise
the strategy that has been operating informally.

## Decision Drivers

- **Single source of truth for "is this preset shippable?"** A candidate
  must pass an explicit gate, not rely on maintainer intuition.
- **Predictable user experience.** Users should be able to read the preset
  catalogue and immediately know which entries are starting points, which
  are tunings, and which are experimental.
- **Compatible with the ADR-0022 schema rebuild.** The strategy chosen here
  must survive the `[[endpoints]]` / `[[policies]]` migration without
  needing a second redesign.
- **Backward compatible.** Existing preset names (`perf`, `ultra-cheap`,
  `eu-eco`, `eu-pro`, `eu-max`, `gdpr`, `eu-ai-act`) must keep working;
  no rename forces user config rewrites.
- **Auditability for security-prevails customers.** Compliance overlays
  are a documented surface; they must not silently merge into base
  presets in a way that hides which compliance decisions apply.

## Considered Options

1. **Status quo — informal convention.** Keep adding presets as needed; let
   the maintainer eyeball "is this generally useful". Reject: produces the
   sprawl described above and offers no answer to the overlay-vs-base
   question.
2. **Folder-based separation.** Put base presets in `presets/base/`,
   overlays in `presets/overlay/`, experimental in `presets/experimental/`.
   Simple but invisible to anyone who does not run `tree`.
3. **Frontmatter `tier` field.** Add a typed `[meta] tier = "base"` to
   every preset's `[meta]` block; gate `grob preset list` formatting on
   it; reject loading a preset whose tier value is not in a fixed set.
   Composition rules become explicit in the data model, not just in
   maintainer custom.
4. **Dedicated TOML namespaces.** Rename overlays to `overlay-gdpr.toml`,
   experimental to `experimental-bandit.toml`. Encodes the role in the
   filename, but breaks any user who has scripted `grob preset apply
   gdpr` and similar.

## Decision Outcome

**Chosen: option 3 — frontmatter `tier` field.** Each preset declares its
role inside its own `[meta]` block. `grob preset info <name>` reads the
field, `grob preset list` groups by it, and the loader rejects unknown
values. Filenames stay unchanged; the existing names keep working.

### Tier taxonomy

Three tiers, fixed by this ADR:

| Tier | Purpose | Examples (today) |
|---|---|---|
| `base` | Standalone routing config — pick one. Never overlaid on another base. | `perf`, `ultra-cheap` |
| `audience-specific` | Standalone routing config tuned to a specific audience constraint (sovereignty, jurisdiction, vertical). | `eu-eco`, `eu-pro`, `eu-max` |
| `experimental` | Opt-in beta. Not shipped as a built-in unless the user enables a feature flag. | (none today; reserved for new primitives) |

A separate concept, **overlay**, is *not* a preset tier. Overlays are
documented in ADR-0024 and identified by a different frontmatter field
(`[meta] kind = "overlay"`).

### Naming convention

`{audience-or-cost}-{tier-or-grade}` lower-case kebab-case.

Concrete patterns:

- Cost-driven: `ultra-cheap`, `cheap-eu`, `mid-tier`.
- Audience-driven (sovereignty / jurisdiction / vertical):
  `eu-{eco|pro|max}`, `us-{eco|pro|max}`, `apac-{eco|pro|max}`.
- Performance-driven: `perf`, `perf-anthropic`, `perf-multi`.
- Experimental: `experimental-{primitive-name}` (`experimental-bandit`,
  `experimental-hedged`).

The convention is descriptive, not prescriptive: a preset with a clearly
distinct audience (e.g. a healthcare-vertical preset) can pick the most
recognisable name without contortion.

### Composition rules

1. **Presets do not nest.** A base or audience-specific preset is a
   complete routing configuration. It does not inherit from, extend, or
   reference another preset. This matches the existing TOML structure:
   each preset file is self-contained, and merging two of them is the
   user's responsibility.
2. **Compliance overlays are not presets.** `gdpr.toml` and
   `eu-ai-act.toml` carry `[meta] kind = "overlay"` and only declare
   `[endpoints.compliance]` blocks (per ADR-0022) plus optional
   `[policies]` filters. They are applied on top of a base preset by
   `grob preset apply <base> --with <overlay>`.
3. **Experimental presets ship in-tree but not built-in.** Files live in
   `presets/experimental/` and are gated behind `[features]
   experimental_presets = true` at runtime. `grob preset list` shows
   them only when the feature is enabled, with an `(experimental)` tag.
4. **Composition is one-way.** A base preset does not reach into an
   overlay; an overlay does not redefine endpoints declared in the base.
   If a user needs a base modified, they fork the preset file rather
   than overlay it. This keeps the merge order trivial: base first,
   overlay second, no diamond conflicts.

### Lifecycle gate — `grob preset info` as the shippability check

Every preset must satisfy three conditions before shipping in-tree as
built-in:

1. `[meta] description = "..."` is non-empty and ≤ 80 characters
   (matches the format used by `presets/index.toml`).
2. `[meta] tier` is one of `base`, `audience-specific`, or
   `experimental`. The loader rejects any other value.
3. `grob preset info <name>` runs to completion and emits no warning.
   This validates that providers referenced exist, that auto-map regexes
   compile, and that compliance metadata (when present, see ADR-0024)
   parses.

These three checks are wired into CI as `cargo test
preset_validation_built_in`. Adding a new preset to the in-tree set is a
documentation event: the test fails until the preset passes the gate.

### What this ADR does *not* cover

- **Preset versioning** — when an existing preset bumps to a new
  provider list, what is the user-visible signal? Deferred to ADR-0024,
  which handles this for compliance presets specifically (cert
  expiry, sub-processor change, etc.).
- **User-authored presets in `~/.grob/presets/`** — the convention
  documented here is for in-tree built-ins; user-authored presets are
  free to ignore it. The loader will continue to accept any well-formed
  TOML.
- **Auto-translation of legacy preset names** — every name that ships at
  the time this ADR is accepted keeps working. No rename pressure.

## Consequences

### Positive

- **`grob preset list` becomes navigable.** Output groups bases first,
  then audience-specific, with overlays in a separate section. Users
  reading the output for the first time can identify a starting point in
  one screen.
- **CI gates new presets.** Adding a preset is a single documented
  operation; the gate ensures every shipped preset has a description, a
  tier, and validates cleanly.
- **Composition is structural, not implicit.** ADR-0024's compliance
  overlays plug into a documented hook rather than relying on naming
  conventions.
- **Experimental presets get a home.** Bench results from new primitives
  (e.g. early Thompson-sampling experiments) can land in-tree without
  promising end-user stability.

### Negative

- **One more required field per preset file.** Every existing preset
  needs a `[meta] tier = "..."` line. Mechanical change, but a change.
- **The taxonomy is finite.** If a future preset does not fit into
  `base` / `audience-specific` / `experimental`, this ADR has to be
  revisited. The taxonomy was sized for the current catalogue plus
  expected growth (~12 presets), not for an unbounded set.
- **`experimental_presets` feature flag is a new surface.** Adds one
  more configuration knob and one more test path.

### Confirmation

- **Linter test** (`tests/preset_metadata.rs`) asserts every file in
  `presets/*.toml` declares `[meta] tier = "..."` from the allowed set
  and that `[meta] description` is non-empty.
- **Validation test** (`tests/preset_validation_built_in.rs`) calls
  `grob preset info <name>` against every shipped preset and asserts
  zero warnings.
- **Naming-convention test** (`tests/preset_naming.rs`) asserts every
  shipped filename matches `[a-z0-9]+(-[a-z0-9]+)*` (lower-case
  kebab-case).
- **CI gate** runs all three on every PR; CHANGELOG `[Unreleased]`
  block records the expected additions for the next release.

## Pros and Cons of the Options

### Option 1 — Informal convention (status quo)

**Pros:** zero work; no schema change.
**Cons:** the sprawl described in *Context*; new contributors have no
guidance; overlays remain invisible in tooling.

### Option 2 — Folder-based separation

**Pros:** simple; no TOML schema change.
**Cons:** invisible to most users (who use `grob preset list`, not
`tree presets/`); breaks file-name-based scripts; cannot encode richer
metadata (description length, validation status).

### Option 3 — Frontmatter `tier` field (chosen)

**Pros:** explicit, machine-readable, backward compatible (only adds a
field), composes with ADR-0024's `kind = "overlay"`.
**Cons:** adds one required field per preset; one more lint to
maintain.

### Option 4 — Dedicated TOML namespaces

**Pros:** the role is visible in the filename.
**Cons:** breaks every user who has typed `grob preset apply gdpr` —
the rename cost is large for limited gain over option 3.

## More Information

### Related ADRs

- [ADR-0008](0008-wizard-lifecycle.md) — wizard exposes preset selection
  during first-run; `grob preset list` formatting changes here will
  reflect there.
- [ADR-0022](0022-declarative-endpoints-policies-schema.md) —
  `[endpoints.compliance]` is the schema hook compliance overlays
  declare against.
- [ADR-0024](0024-preset-as-compliance-template.md) — formalises
  compliance overlays as packaged decisions.

### Migration plan

1. Land this ADR (`status: proposed`).
2. Add `[meta] tier = "..."` to every shipped preset file in a
   follow-up PR (mechanical change, no behaviour delta).
3. Implement `grob preset info` validation gate.
4. Promote ADR to `accepted` when the gate is enforced in CI.

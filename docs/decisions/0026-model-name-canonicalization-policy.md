---
status: proposed
date: 2026-04-28
deciders: [azerozero]
consulted: []
informed: []
supersedes: []
related: [ADR-0003, ADR-0018, ADR-0022]
---

# ADR-0026: Model Name Canonicalization Policy

## Context and Problem Statement

Pull request #307 (commit `b8b86b3`) introduced
`canonicalize_model_name()` in `src/routing/classify/model_name.rs`. The
function applies a small set of deterministic, idempotent rewrites so
that user-typed model names map onto the canonical keys used in
`[[models]]` config entries and `presets/*.toml`. The most common
ambiguities it resolves:

- Trailing date suffix: `claude-3-5-sonnet-20241022` →
  `claude-3-5-sonnet`.
- Trailing `-latest`: `claude-sonnet-4-5-latest` → `claude-sonnet-4-5`.
- Dot-vs-dash version: `gemini-2.5-flash` → `gemini-2-5-flash`.
- Anthropic family-version reorder: `claude-3-5-sonnet` →
  `claude-sonnet-3-5`.
- Mixed casing: lowercase ASCII.

Without canonicalization, an explicit `[[models]]` entry named
`claude-sonnet-3-5` would not match a request for
`Claude-3-5-Sonnet-20241022`, even though both refer to the same model.
The function unblocks a real user pain (the same model has multiple
spellings in vendor docs and SDKs) but landed without a recorded
decision. Three structural questions are unanswered in writing:

1. **Are the rules canonical?** Today they are hardcoded in the source.
   When a vendor publishes a sixth dot-versioned family, who decides
   whether the new prefix gets added, and on what test? The current
   code has tests for the rules that exist; the *policy* governing
   addition of new rules is not documented.
2. **Are operators allowed to override?** A power user routing to a
   custom model whose name happens to match a canonicalization pattern
   has no escape hatch documented anywhere.
3. **What happens when a vendor renames a model?** Today an alias would
   need a manual migration; the lifecycle is not documented.

ADR-0018 introduced the topology-vs-policy split with `[[endpoints]]`,
and ADR-0022 commits to the schema rebuild. Canonicalization must
survive that schema migration without further ambiguity. The policy
this ADR records governs the *rules* in
`src/routing/classify/model_name.rs`, the *escape hatch* for operators,
and the *deprecation cadence* for renamed models.

## Decision Drivers

- **Idempotence is non-negotiable.** Whatever rule set ships, applying
  the canonicalizer twice must equal applying it once. This is a
  property tested via proptest already; new rules must preserve it.
- **Vendor-prefix gating prevents collisions.** A naive
  dot-replacement rule would corrupt unrelated model names like
  `glm-4.6`. Rules that rewrite version separators must be gated on a
  known family prefix.
- **Predictability beats expressiveness.** A small fixed rule set the
  operator can read in 30 lines is preferable to a config-driven DSL
  for 99% of users.
- **Escape hatch for the 1%.** An operator running a custom proxy with
  a model name colliding with the canonicalization rules must have a
  documented way out.
- **Stable upgrade story.** When a vendor renames a model (e.g.
  `claude-3-7-opus` → `claude-opus-3-7-r1`), users must not silently
  fall through into a "model not found" path on the next grob upgrade.

## Considered Options

1. **Config-driven canonicalization.** Operators declare rules in TOML.
   Reject: 99% of users would have to write rules that match what we
   ship anyway; the schema and validation cost is large.
2. **Hardcoded rules with documented escape hatches (chosen).** Rules
   live in source, gated by family prefix; operators with collisions
   patch the table or use the per-endpoint `actual_model` mapping
   already in `[[endpoints]]`.
3. **Skip canonicalization, force users to write all spellings.**
   Reject: this was the pre-PR-307 behaviour and it produced the bug
   that the canonicalizer fixes. Reverting it would relitigate that
   debate.
4. **External alias service.** A network call resolves user input to
   a canonical name. Reject: violates ADR-0014's single-binary
   constraint and adds a new failure mode.

## Decision Outcome

**Chosen: option 2 — hardcoded rules with documented escape hatches.**
The rules in `src/routing/classify/model_name.rs` are canonical; this
ADR commits to their shape and lifecycle; operators with collisions
have two documented escape paths (table patch or per-endpoint
override).

### Canonical form — fixed rule set

The canonical form is produced by the following rules, applied in
order. Each rule short-circuits when its pattern is absent, which
guarantees idempotence.

1. **Lowercase.** ASCII-only; non-ASCII bytes pass through unchanged.
2. **Strip trailing `-latest`** (`claude-sonnet-4-5-latest` →
   `claude-sonnet-4-5`).
3. **Strip trailing 8-digit date suffix** `-YYYYMMDD`
   (`claude-3-5-sonnet-20241022` → `claude-3-5-sonnet`). Must be
   exactly 8 digits to avoid clobbering version segments such as
   `gpt-5-2`.
4. **Dot-versions to dashed-versions** for the family prefix set
   (`gemini-2.5-flash` → `gemini-2-5-flash`). Gated on the family
   prefix so unrelated IDs (e.g. `glm-4.6`) survive untouched.
5. **Anthropic family-version reorder** (`claude-{N}-{M}-{family}` →
   `claude-{family}-{N}-{M}` for `family ∈ {sonnet, opus, haiku}`).
   Both Anthropic-published spellings collapse onto the modern
   spelling used in `presets/*.toml`.

### Family-prefix gate

The dot-version replacement rule is gated on a known prefix set:

```text
claude-      gpt-      gemini-      grok-      deepseek-
```

A request whose model name starts with any other prefix bypasses rule
4. This is the structural protection against collisions with custom
model names. The gate is a constant in
`src/routing/classify/model_name.rs`; adding a vendor prefix is a
two-line change with a unit test.

### Idempotence is a load-bearing property

The proptest in `model_name.rs` asserts:

```rust
prop_assert_eq!(
    canonicalize(canonicalize(x)),
    canonicalize(x),
);
```

over arbitrary alphanumeric strings. This is a release gate. Any new
rule that breaks idempotence must be rejected at PR review.

### Operator escape hatches

Two paths, both documented:

1. **Per-endpoint `actual_model` mapping.** ADR-0022's
   `[[endpoints]]` schema already supports
   `backend = { provider, model = "<exact string>" }`. The string is
   passed to the provider verbatim, bypassing the canonicalizer for
   the *outbound* leg. An operator hosting `my-claude-3.5-fork` on a
   custom endpoint declares it once in the endpoint config and grob
   never rewrites it.
2. **Table patch.** An operator who needs the canonicalizer itself
   to behave differently (e.g. a private fork of grob serving a
   non-public vendor) patches the constant table and rebuilds. This
   is explicitly *not* a config-driven path. It is the supported way
   for operators outside the public vendor set to extend the
   canonicalizer.

These two cover the observed needs. A third path (config-driven
rules) is rejected because the maintenance cost outweighs the value
for the user count it would serve.

### Deprecation lifecycle for renamed models

When a vendor renames a model (or grob's canonical key changes for any
other reason), the old name remains a recognised alias for **two
minor releases** — the same cadence used for command-line argument
deprecations elsewhere in grob.

Concrete steps:

1. **Release N (announcement).** Add the new canonical form. Add a
   one-way alias from the old form to the new form (the canonicalizer
   gains a new entry in rule 5 or an equivalent rule). Existing users
   continue to resolve via the alias.
2. **Releases N..N+1 (deprecation).** Each request resolved via an
   alias logs a one-time WARN per session: "model name `<old>`
   resolves to `<new>`; please update your config; alias removed in
   v<N+2>".
3. **Release N+2 (removal).** Alias removed; old name no longer
   resolves; request returns the standard "model not found" error.

The 2-minor-release window matches ADR-0022's deprecation cadence
philosophy at a faster scale (the surface here is much smaller than
the schema rebuild). For high-impact renames (e.g. an entire family
rebrand), a future ADR may extend the window.

### What this ADR does *not* cover

- **Provider-side normalisation.** Some providers accept multiple
  spellings; grob does not assume so. The canonicalizer fixes the
  inbound side; the outbound model string is what the operator has
  declared in `[[endpoints]]` or `[[models]]`.
- **Capability tagging.** Mapping `claude-sonnet-4-5` to a
  capability set (coding, vision, etc.) is governed by ADR-0018's
  endpoint capability inference, not this ADR.
- **Auto-completion in the wizard.** The wizard
  ([ADR-0008](0008-wizard-lifecycle.md)) may suggest canonical names;
  the suggestions come from the same table this ADR commits to.

## Consequences

### Positive

- **Predictable behaviour.** Operators can read 30 lines of source
  and know exactly what the canonicalizer does. No DSL to learn.
- **Collision-safe.** The family-prefix gate prevents accidental
  rewrites of unrelated model names.
- **Escape hatch is honest.** Two documented paths cover the rare
  cases without polluting the common case with config schema.
- **Renames are loud.** The 2-release deprecation window with WARN
  logging gives users time to update configs before silent failure.

### Negative

- **Hardcoded means new vendors require a release.** When a sixth
  dot-versioned family appears, an operator cannot self-serve; they
  open a PR or use the per-endpoint escape hatch.
- **The rule set has an arbitrary stop point.** A future contributor
  may want to add a sixth rule (e.g. underscore-vs-dash); this ADR
  does not pre-approve such additions, but the property tests must
  catch idempotence regressions.
- **Aliases live in source.** Each rename adds a small amount of
  permanent code surface (until removal at N+2).

### Confirmation

- **Idempotence proptest** (`model_name.rs::prop_canonicalize_is_idempotent`)
  is a release gate.
- **Family-prefix gate test** (`tests/canonicalize_unrelated.rs`)
  asserts model names like `glm-4.6`, `mistral-large-2402`,
  `qwen-3.5-72b` survive unchanged.
- **Date-suffix length test** asserts strings ending in fewer than 8
  digits do not get the date stripper.
- **Alias deprecation test** is added per rename: WARN log emitted
  exactly once per session, alias resolved correctly during the
  deprecation window, error returned after removal.
- **CI gate**: any change to the family-prefix set or the rule list
  requires a corresponding test addition; reviewers reject PRs that
  add a rule without a proptest update.

## Pros and Cons of the Options

### Option 1 — Config-driven canonicalization

**Pros:** infinite flexibility.
**Cons:** schema cost, validation cost, every operator writes rules
that match what we ship anyway.

### Option 2 — Hardcoded rules + escape hatches (chosen)

**Pros:** simple, idempotent, fast; escape hatches cover the rare
cases; family-prefix gate prevents collisions.
**Cons:** new vendors require a release.

### Option 3 — Skip canonicalization

**Pros:** zero code.
**Cons:** users hit the bug PR-307 fixed.

### Option 4 — External alias service

**Pros:** centralised aliases.
**Cons:** violates the single-binary constraint; new failure mode.

## More Information

### Related ADRs

- [ADR-0003](0003-regex-routing-engine.md) — the classification engine
  that consumes the canonicalized name.
- [ADR-0018](0018-nature-inspired-routing.md) — topology-vs-policy
  split; the per-endpoint `actual_model` field is the operator escape
  hatch this ADR points to.
- [ADR-0022](0022-declarative-endpoints-policies-schema.md) —
  `[[endpoints]]` schema where the per-endpoint override lives in
  the new schema.

### Reference

- PR #307, commit `b8b86b3` — the implementation that landed the
  rules this ADR formalises.
- `src/routing/classify/model_name.rs` — module-level docs cover the
  per-rule details; this ADR covers the *policy* governing the rules.

### Migration plan

1. Land this ADR (`status: proposed`).
2. Cross-link the ADR from
   `src/routing/classify/model_name.rs` module-level docs.
3. Promote ADR to `accepted` when the family-prefix gate test is
   in place and idempotence proptest is enforced as a release gate.

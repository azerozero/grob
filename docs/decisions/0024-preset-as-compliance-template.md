---
status: proposed
date: 2026-04-28
deciders: [azerozero]
consulted: []
informed: []
supersedes: []
related: [ADR-0006, ADR-0022, ADR-0023]
---

# ADR-0024: Preset-as-Compliance-Template — Packaged Compliance Decisions

## Context and Problem Statement

The `eu-pro` and `eu-max` presets ship today carrying compliance metadata
**implicitly** in TOML comments and provider selection: "this preset uses
Scaleway (FR datacenters) and Nebius (eu-north1, FI), excludes US
providers, and is intended for GDPR-strict EU sovereign routing." The
intent is documented in the preset header; the *machine-readable* form
of that intent does not exist anywhere — neither the policy engine nor
the audit log knows that `eu-pro` makes specific compliance claims.

ADR-0022 introduces a structured `[endpoints.compliance]` block with six
typed fields (`trust_zone`, `jurisdiction`, `data_classification`,
`certifications`, `provider_risk_score`, `sub_processors`). With this
schema, presets can encode compliance decisions in a typed form rather
than in prose. But three structural questions remain:

1. **Authority.** When an `eu-pro` preset declares
   `jurisdiction = "EU"` for every endpoint, who guarantees that this
   declaration is correct as of the release date? Today the answer is
   "the preset maintainer reviewed the provider's docs"; tomorrow this
   needs to be a documented commitment with a review cadence.
2. **Evolution.** When a sub-processor changes (e.g. Scaleway adds a new
   partner data centre outside FR) or a certification expires (e.g. the
   provider drops SecNumCloud), what is the user-facing signal?
   Currently a preset would silently still claim the old compliance
   posture until the next release.
3. **Customer extension.** A security-prevails customer may want to
   *narrow* a shipped preset (add more requirements) without forking
   the entire preset. How does grob support that without making the
   merge order ambiguous?

ADR-0023 establishes the tier taxonomy and recognises *overlay* as a
distinct concept, but leaves the **content** of compliance overlays
unspecified. This ADR fills that gap.

The strategic question is: do we treat compliance presets as
documentation (informal claims, soft guarantees, no machine
verification), or as *packaged decisions* — a typed bundle of routing
topology, policy choices, and compliance metadata, versioned and
auditable?

## Decision Drivers

- **Security-prevails customers cannot adopt informal claims.** Defense,
  banks, and OIV change-management processes require evidence that a
  declared posture is current, traceable, and reviewable. A TOML comment
  does not pass that bar.
- **Compliance changes outside grob's release cycle.** Provider
  certifications expire on the provider's calendar, not on grob's.
  The signalling mechanism must surface drift even when grob itself
  has not changed.
- **Composition with the ADR-0023 overlay model.** Compliance overlays
  must plug cleanly into the tier taxonomy without introducing a fourth
  tier or breaking the "presets do not nest" rule.
- **No silent merges.** When an overlay tightens a base preset, the user
  must see the diff before applying — both the new value and the
  rationale.
- **Audit trail.** Each preset application emits an event readable by
  ADR-0017's Sokolsky log backend, capturing which preset, which
  overlay, and which compliance commitments were active at apply time.

## Considered Options

1. **Documentation-only compliance.** Keep the TOML-comment status quo;
   add a `docs/compliance/` page describing each preset's claims. No
   schema, no audit, no enforcement. Reject: does not solve the
   security-prevails adoption blocker.
2. **External compliance registry.** Maintain a separate JSON/YAML file
   under `compliance/registry.json` that maps preset names to their
   compliance metadata. Reject: introduces a second source of truth that
   can drift from the preset itself.
3. **Compliance metadata embedded in the preset (chosen).** Each preset
   declares `[endpoints.compliance]` per ADR-0022 directly inline. A
   preset is a packaged decision: topology + policy + compliance, all
   versioned together.
4. **Formal certification authority.** Grob ships compliance presets
   only after an external auditor signs off. Reject: out of scope; the
   maintainer can document review without claiming an external audit.

## Decision Outcome

**Chosen: option 3 — compliance metadata embedded inline as part of the
preset.** A compliance preset is a *packaged decision*: it bundles
topology (`[[endpoints]]`), policies (`[[policies]]`), and compliance
declarations (`[endpoints.compliance]`) in a single TOML file, versioned
in lockstep, reviewable as a unit.

### What "packaged decision" means

A compliance preset (e.g. `eu-pro`, `eu-max`) commits to four things,
all visible in the preset file and inspectable via `grob preset info`:

1. **Routing topology.** Which endpoints exist (`[[endpoints]]`).
2. **Policy choices.** How requests select among them (`[[policies]]`).
3. **Compliance posture.** What every endpoint declares
   (`[endpoints.compliance]` per ADR-0022).
4. **Review metadata.** When the preset was last reviewed against the
   sub-processor lists and certifications it claims (`[meta]
   compliance_reviewed = "YYYY-MM-DD"`).

These four are inseparable. A preset that declares
`jurisdiction = "EU"` but routes to a US endpoint is rejected by
`grob preset info`. A preset whose `compliance_reviewed` date is more
than 12 months old emits a warning at apply time.

### Customer extension via overlays

A security-prevails customer can extend a shipped preset with their
own `[endpoints.compliance]` overrides through an overlay file (per
ADR-0023's `[meta] kind = "overlay"`):

```toml
# /etc/grob/overlays/customer-extra.toml
[meta]
kind = "overlay"
description = "Additional internal classification for customer X"
applies_to = ["eu-pro", "eu-max"]

[endpoints.compliance]
data_classification = "restricted"
certifications = ["customer-internal-baseline-2026-q2"]
```

Apply: `grob preset apply eu-pro --with /etc/grob/overlays/customer-extra.toml`.

The overlay **adds** to the base's compliance metadata; it does not
silently *relax* a base's declared posture. If a customer needs to
weaken a base (e.g. allow `data_classification = "internal"` where the
base demands `restricted`), the loader rejects the overlay with a
clear error. Tightening is allowed; loosening requires forking.

### Update lifecycle — versioning compliance presets

Compliance presets are versioned with the rest of grob. When the
preset's compliance posture changes:

1. **Sub-processor added or removed.** Bump the preset's
   `[meta] compliance_reviewed` date and emit a CHANGELOG entry under
   the *Compliance* heading. The preset filename does not change.
2. **Certification expires.** If a certification listed in
   `[endpoints.compliance].certifications` is renewed in time, bump
   `compliance_reviewed`. If it lapses, **bump the preset filename** to
   `<preset>-v2.toml` and keep the v1 file shippable until the next
   minor release for compatibility (mirrors ADR-0023's
   audience-specific tier policy on backward compatibility).
3. **Major posture change.** A change that removes a jurisdiction or
   trust zone (e.g. dropping FR data centres) is a major bump:
   `<preset>-v2.toml` ships, the v1 file gets a deprecation note in
   `[meta]`, and the deprecation appears in the CHANGELOG and at every
   `grob preset apply <name>` until the v1 file is removed.

This mirrors the ADR-0022 deprecation cadence (10 minor releases) for
the highest-impact case (major posture change). For the common case
(routine review), nothing visibly changes for the user beyond an updated
review date.

### Schema additions to `[meta]`

Compliance presets add three optional `[meta]` fields on top of the
existing `[meta] description` from ADR-0023:

| Field | Type | Default | Meaning |
|---|---|---|---|
| `compliance_reviewed` | date `YYYY-MM-DD` | — | Last review against sub-processors and certifications. |
| `compliance_summary` | string ≤ 200 chars | — | One-paragraph user-facing summary of the posture. |
| `replaces` | string (preset name) | — | Older preset this one supersedes. Triggers deprecation banner on the named preset. |

`grob preset info <name>` renders these alongside the routing summary.
`grob preset list --compliance` filters to the subset of presets that
declare `compliance_summary`.

### Audit trail at apply time

When a user runs `grob preset apply <preset> [--with <overlay>]`, grob
emits a structured event to the Sokolsky log backend (ADR-0017):

```json
{
  "kind": "preset.apply",
  "preset": "eu-pro",
  "preset_compliance_reviewed": "2026-04-28",
  "overlay": "/etc/grob/overlays/customer-extra.toml",
  "overlay_compliance_summary": "Additional internal classification for customer X",
  "endpoints_compliance_digest": "<sha256 of merged compliance blocks>"
}
```

The digest gives a stable identifier for the **applied** posture (base
+ overlay) without leaking the full TOML to the audit log. Auditors
querying Sokolsky can correlate the digest with a preset version known
at the time of application.

### What this ADR does *not* cover

- **Provider-side certification verification.** Grob does not query
  provider APIs to confirm certifications are current. The
  `compliance_reviewed` date is a maintainer attestation, not a live
  check.
- **Cryptographic signing of presets.** Presets are reviewed in git;
  no PGP/Sigstore signature is required at this stage. Future work,
  separate ADR.
- **Auto-update of the review date.** A preset whose last review is
  stale must be hand-bumped by the maintainer; no nightly job rewrites
  it.

## Consequences

### Positive

- **Compliance posture is machine-readable.** ADR-0022's typed schema
  combined with the `[meta] compliance_*` fields gives every shipped
  preset an inspectable, auditable shape.
- **Customer extensibility without forking.** Overlays cover the common
  case (tighten, do not relax). Forking remains the escape hatch for
  the uncommon case.
- **Deprecation is loud.** The `replaces` field and CHANGELOG entry
  ensure users on a stale preset see a banner at every apply, not
  silently inherit lapsed claims.
- **Sokolsky digest** gives forensic auditors a stable handle for the
  posture in effect at any given application time.

### Negative

- **More work for the preset maintainer.** Each compliance preset must
  carry a review date and a summary; the maintainer must keep the
  review fresh.
- **Lifecycle rules add complexity.** Three categories (routine
  review / certification renew / major posture change) each have a
  different signalling cost. The rules must be documented in the
  contributor guide.
- **No external audit.** A preset still represents a maintainer
  judgement, not a third-party attestation. Customers who need an
  audited posture must run their own due diligence.

### Confirmation

- **Schema test** (`tests/preset_compliance_schema.rs`) asserts that
  every preset declaring at least one `[endpoints.compliance]` block
  also declares `[meta] compliance_reviewed` and
  `[meta] compliance_summary`.
- **Apply-time test** (`tests/preset_compliance_apply.rs`) verifies the
  Sokolsky `preset.apply` event is emitted with the correct digest for
  a fixture preset + overlay pair.
- **Stale-review warning test** asserts that
  `compliance_reviewed > 12 months ago` emits a warning to stderr at
  apply time (not blocking, surfacing).
- **Overlay tightening test** asserts that an overlay attempting to
  loosen `data_classification` is rejected with a clear error.

## Pros and Cons of the Options

### Option 1 — Documentation-only compliance

**Pros:** zero schema cost.
**Cons:** does not pass security-prevails change-management; informal
claims drift silently; no machine verification.

### Option 2 — External compliance registry

**Pros:** clean separation of concerns.
**Cons:** two sources of truth; preset and registry can drift; review
cadence is not enforceable.

### Option 3 — Embedded compliance metadata (chosen)

**Pros:** single source of truth (the preset file); reviewable in git;
composes with ADR-0022 and ADR-0023.
**Cons:** more work per preset; more rules in the lifecycle.

### Option 4 — Formal certification authority

**Pros:** strongest claim possible.
**Cons:** out of scope for grob's resourcing; entangles release
cadence with auditor schedule.

## More Information

### Related ADRs

- [ADR-0006](0006-policy-engine-encrypted-audit-hit-gateway.md) —
  policy engine and audit pipeline; preset-apply events flow through
  the same path.
- [ADR-0017](0017-sokolsky-log-backend.md) — production audit sink for
  the `preset.apply` digest.
- [ADR-0022](0022-declarative-endpoints-policies-schema.md) — defines
  the `[endpoints.compliance]` schema this ADR commits to embedding in
  presets.
- [ADR-0023](0023-preset-naming-and-composition.md) — establishes the
  overlay-vs-base separation that this ADR populates with content.

### Worked example — `eu-pro` after this ADR

```toml
[meta]
description = "Strict-EU sovereign, balanced — Hermes-4-405B + Qwen3.5-397B"
tier = "audience-specific"
compliance_reviewed = "2026-04-28"
compliance_summary = "EU sovereign routing through Scaleway (FR) and Nebius (eu-north1, FI). All endpoints declare jurisdiction = EU and trust_zone = sovereign-eu. SecNumCloud and ISO 27001 listed where the provider has them."

# topology + policy + compliance follow, per ADR-0022
```

### Migration plan

1. Land this ADR (`status: proposed`).
2. Backfill `[meta] compliance_reviewed` and `compliance_summary` on
   shipped EU presets in a follow-up PR.
3. Add tests listed under *Confirmation*.
4. Promote ADR to `accepted` once tests are enforced and Sokolsky
   wiring lands.

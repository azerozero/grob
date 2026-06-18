---
status: superseded
date: 2026-06-14
deciders: [azerozero]
consulted: []
informed: []
supersedes: []
superseded_by: [0029-relicense-core-apache]
related: [0024-preset-as-compliance-template]
---

# ADR-0028: Open-Core Boundary — AGPL Core vs Commercial Modules

> Superseded by [ADR-0029](0029-relicense-core-apache.md), which relicenses
> Grob Core to Apache-2.0 while keeping the open-core product boundary.

## Context and Problem Statement

grob-core ships under AGPL-3.0. A commercial layer is planned in two
separate, private products:

- **grob-enterprise** — HA/clustering, multi-region, SIEM connectors,
  turnkey regulatory packs, advanced RBAC, fleet/tenant management, etc.
- **grob-admin** — a web console (policy builder, audit explorer, compliance
  dashboard, provisioning, GitOps manifest generation, license management,
  multi-instance health).

Without a written boundary, two failures are likely: contributors build
commercial-shaped features into the AGPL repo by accident, and the
dual-licensing strategy that funds the project drifts out of reach.

A code audit on 2026-06-14 found that **three features earmarked as
"commercial" already exist in the open core**:

- **Approval workflows** — the HIT (human-in-the-loop) gateway
  (`/api/hit/approve`, `src/features/policies/hit_auth.rs`).
- **RBAC** — a fixed role hierarchy (Observer/Operator/Admin/Superadmin) with
  Action→Role checks across every operator surface (`src/control/engine.rs`).
- **Compliance foundations** — EU AI Act audit fields (Art. 12/14), risk
  classification (Art. 14), `gdpr`/`region` router flags, and Standard/DLP/
  GDPR/Enterprise compliance profiles (`src/security/audit_log.rs`,
  `src/security/risk.rs`).

A decision is needed: gate these three behind a commercial feature flag, or
accept them as part of the AGPL core.

## Decision Drivers

- The open core must be genuinely useful and self-contained — a credible OSS
  product, not a crippled teaser.
- The commercial layer must stay viable — paid features must not be
  cannibalized by the open core.
- The licensing boundary must remain clean enough for **dual-licensing**.
- Contributors must not be able to blur the line by accident.
- Minimize maintenance overhead (conditional compilation, feature-flag matrices).

## Considered Options

1. **Gate the three borderline features** behind `feature = "enterprise"` and
   remove them from the default OSS build.
2. **Accept the three in AGPL**; draw the commercial line *above* them (advanced
   variants only) and at everything currently absent.
3. **Relicense the whole core** under a source-available license (BSL / Elastic
   License) instead of AGPL.

## Decision Outcome

Chosen: **Option 2 — accept the three borderline features as AGPL.** The
commercial line is drawn at the *advanced* tier of each, plus everything not yet
implemented. No feature gating or refactor is required today, because the
commercial features are greenfield and will live in separate private repos.

### The boundary

**🟢 grob-core (AGPL-3.0) — everything in the repo today**

- LLM gateway / routing, OpenAI-compatible API (`/v1/chat/completions`,
  `/v1/responses`, `/v1/models`, `/v1/messages`), cache-aware multi-format
  translation (see ADR-0007).
- Providers (Anthropic, OpenAI, Gemini; DeepSeek/Mistral/Ollama/Groq via the
  OpenAI-compatible type).
- DLP / PII redaction, policy engine, signed audit log, rate limiting,
  per-tenant budget enforcement.
- **HIT approval (single-level)**, **basic RBAC** (Observer/Operator/Admin/
  Superadmin), **compliance foundations** (EU AI Act audit, GDPR/region flags,
  risk classification, compliance profiles).
- Helm chart, metrics/health, local and server modes, CLI.

**🔒 grob-enterprise + grob-admin (commercial) — everything currently absent**

- HA / clustering / active-active, multi-region.
- SIEM connectors (Splunk, Sentinel, Elastic, QRadar), Vault/OpenBao secret
  backend, SSO multi-org / SAML, air-gap bundle, offline update channel.
- **Turnkey regulatory packs** (NIS2, DORA, ISO 27001), RSSI PDF/HTML reporting,
  long-term audit retention tooling.
- **Advanced RBAC** (custom roles, per-resource / fine-grained, org scoping),
  **multi-level / delegated approval chains**.
- Fleet / tenant management.
- **All of grob-admin (web UI)**: policy builder, audit explorer, compliance
  dashboard, tenant provisioning, GitOps manifest generation, license
  management, multi-instance health.

### The three borderline features — explicit split

| Feature | AGPL core (kept) | Commercial (advanced) |
|---------|------------------|-----------------------|
| Approval | HIT gateway, single-level approve/deny | Multi-level & delegated approval chains, SLAs |
| RBAC | Fixed roles Observer/Operator/Admin/Superadmin | Custom roles, per-resource/fine-grained, org scoping |
| Compliance | EU AI Act audit, risk classification, GDPR/region flags, profiles | Turnkey NIS2/DORA/ISO 27001 packs, RSSI reporting, retention tooling |

### Default rule for future ambiguous features

Foundations / primitives / single-level → **AGPL core**. Turnkey, packaged,
multi-level, fine-grained, or web-UI → **commercial**.

### Licensing strategy (dual-license)

- grob-core stays **AGPL-3.0**; copyright is held by azerozero, and external
  contributions are taken under a **CLA** (enforced by the `cla-check` job in
  CI). The CLA is the linchpin: it lets azerozero **relicense** the core.
- Commercial modules live **outside this repo** (private `grob-enterprise` /
  `grob-admin`). They are never merged here.
- AGPL §13 (network clause): SaaS users of grob-core must be offered the source.
  Enterprise customers who cannot accept AGPL obtain a **commercial license** to
  the core (made possible by the CLA + sole copyright).

### Guardrail

Commercial-shaped work **must not be merged into this (AGPL) repo**. New
enterprise/admin features go to `grob-enterprise` / `grob-admin`. When in doubt,
apply the default rule above and consult this ADR.

## Consequences

### Positive

- A self-contained, credible OSS core that includes real approval, RBAC, and
  compliance foundations — not a teaser.
- The dual-licensing path stays open and is already backed by the CI `cla-check`.
- Zero conditional-compilation / feature-flag maintenance for the three features.

### Negative

- The three features are **permanently AGPL** — they cannot be pulled back into
  a paid-only tier later.
- Competitors may use approval / basic RBAC / compliance foundations under AGPL
  (mitigated: the *advanced* tiers and the web console remain commercial).
- Keeping the line clean now depends on contributor discipline (mitigated by
  this ADR + the guardrail + periodic audit).

### Confirmation

- The boundary tables in this ADR are the canonical reference.
- The CI `cla-check` job ensures every contribution is relicensable.
- A periodic grep audit (enterprise-shaped keywords) confirms no commercial code
  has leaked into the AGPL repo.

## Pros and Cons of the Options

### Option 1 — Gate behind `feature = "enterprise"`

- Good: maximizes the paid surface.
- Bad: cripples the OSS core (no approval/RBAC/compliance out of the box),
  hurts adoption and credibility; adds a feature-flag matrix to maintain;
  these features are already public, so gating them now is a takeback.

### Option 2 — Accept in AGPL, sell the advanced tier (chosen)

- Good: credible OSS core; clean dual-license; no gating overhead; honest about
  what is already public.
- Bad: the three features stay AGPL forever; the advanced line must be
  enforced by discipline.

### Option 3 — Relicense core to BSL/Elastic

- Good: simplest commercial protection.
- Bad: not OSI-approved/“open source”; community and trust cost; large,
  disruptive change; the project’s identity is AGPL open core.

## More Information

- Source of the boundary: code audit on 2026-06-14 (this conversation).
- Related: [ADR-0024](0024-preset-as-compliance-template.md) — packaged
  compliance decisions via presets, which the commercial regulatory packs build
  on.

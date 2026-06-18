---
status: accepted
date: 2026-06-18
deciders: [azerozero]
consulted: []
informed: []
supersedes: [0028-open-core-boundary]
related: [0024-preset-as-compliance-template]
---

# ADR-0029: Relicense Grob Core to Apache-2.0

## Context and Problem Statement

Grob is infrastructure software: it sits in the request path between coding
agents and LLM providers. The core adoption goal is broad deployment by
individual developers, platform teams, regulated teams, integrators, and
vendors who may embed the gateway in their own systems.

The previous public core license was AGPL-3.0 with a commercial alternative.
That protected against private SaaS modifications, but it also created legal
friction for the exact enterprise and platform users Grob needs to reach.

The strongest moat for Grob is not the network copyleft clause. It is the Rust
single binary, provider compatibility, DLP-first request path, signed audit
evidence, air-gap friendliness, deployment quality, trust, and commercial
control-plane products.

## Decision Drivers

- Maximize adoption of the public gateway and CLI.
- Make the core acceptable for enterprise infrastructure review.
- Keep an explicit patent grant for contributors and users.
- Preserve a clear open-core product boundary.
- Avoid claiming that historical AGPL releases were never AGPL.
- Keep commercial value in advanced packaged products, managed operations, and
  support, not in blocking core gateway use.

## Considered Options

1. **Keep AGPL-3.0 + commercial license.**
2. **Relicense Grob Core to MIT.**
3. **Relicense Grob Core to Apache-2.0 and keep advanced products commercial.**
4. **Move to a source-available license.**

## Decision Outcome

Chosen: **Option 3 — Grob Core is Apache-2.0**.

From this decision forward, the public repository is licensed under
Apache-2.0. Historical releases keep their original published license. Older
AGPL-3.0 / commercial releases remain historical artifacts; they are not
retroactively rewritten.

### Public core

The following remain in the open-source Apache-2.0 core:

- Gateway and routing data plane.
- CLI and local daemon workflows.
- OpenAI, Anthropic, and Responses API compatibility layers.
- Provider adapters and OpenAI-compatible provider support.
- DLP primitives, request/response scanning, and redaction/blocking actions.
- Signed audit foundations, hash chains, Merkle batching, and JSONL export.
- Policy engine primitives, HIT approval primitives, fixed RBAC primitives.
- Presets, SDK examples, MCP adapters, Helm and deployment manifests.
- Documentation and compliance-control mappings.

### Commercial products

Commercial products may include:

- Grob Admin web console.
- HA / clustering / active-active and multi-region operations.
- Advanced SIEM connectors and long-term signed audit retention.
- Turnkey policy packs and compliance evidence packs.
- Advanced RBAC, multi-level approval, fleet and tenant management.
- Air-gap appliance, managed deployments, support, warranty, and indemnity.
- Trace-to-automation products.

### Compliance wording

Grob must not claim that installing the core makes an organization compliant.
The correct public wording is:

> Grob provides compliance controls and audit evidence mapping for EU AI Act,
> GDPR/RGPD, NIS2/DORA, and HDS/PCI-style audit requirements. Grob is not
> certified by default.

Operators must enable the relevant controls, configure providers and regions,
and validate the full deployment against their obligations.

### Contributor licensing

The CLA remains in place. It lets A00 SASU distribute contributions under
Apache-2.0 and, when needed, under commercial or proprietary licenses for paid
products. Contributors retain copyright in their contributions.

The `origin/cla-signatures` branch stores CLA evidence and is not a routine
stale branch.

## Consequences

### Positive

- Lower legal friction for platform teams and integrators.
- Explicit Apache patent grant for infrastructure users.
- Easier commercial embedding of the public gateway.
- Clearer distinction between the open data plane and paid control plane.

### Negative

- Private SaaS modifications no longer trigger AGPL source obligations.
- Competitors can reuse the public data plane under a permissive license.
- The commercial boundary must be maintained by product discipline and private
  repositories, not by core copyleft.

## Guardrail

Primitives and interfaces belong in the Apache-2.0 core. Turnkey packaged
workflows, managed operations, advanced UI, multi-level enterprise governance,
and long-term compliance evidence products may live in commercial repositories.

When a feature is ambiguous, default to:

- **Core**: protocol compatibility, security primitives, audit primitives,
  policy primitives, local CLI ergonomics, deployment manifests.
- **Commercial**: hosted/admin UI, fleet management, packaged compliance
  reports, advanced integrations, managed operations, support commitments.

## Confirmation

- `LICENSE` contains Apache-2.0.
- `Cargo.toml` declares `license = "Apache-2.0"`.
- OCI and Homebrew metadata declare Apache-2.0.
- Public docs avoid "Grob is GDPR/HDS/PCI compliant" claims.
- The CLA bot still enforces contribution licensing.

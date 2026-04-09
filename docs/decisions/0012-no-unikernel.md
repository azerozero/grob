---
status: accepted
date: 2026-04-09
deciders: [azerozero, architect]
consulted: []
informed: []
---

# ADR-0012: No Unikernel — Prefer Secure-by-Design + seccomp + scratch Image

## Context and Problem Statement

During the pre-v0.30 exploration, Grob gained a `unikernel` feature flag and an accompanying build pipeline targeting Unikraft (and optionally RustyHermit / OSv). The idea was to compile Grob as a single-address-space unikernel bootable directly on a hypervisor, claiming:

- Minimal attack surface (no Linux kernel).
- Fast boot (< 100 ms).
- Confidential computing alignment with TEE backends.

By v0.33, every claimed benefit had eroded or was achievable with a far lighter approach:

- **Attack surface** — already minimized by the scratch-image container (~6 MB), `unsafe` denial at crate level, `zeroize` on secrets, and seccomp filtering.
- **Boot time** — irrelevant vs. round-trip LLM latency (hundreds of ms per call). Unikernel boot shaves 200 ms off a request path that spends 800 ms in HTTPS and 4 s in inference.
- **Confidential computing** — TEE detection (AMD SEV-SNP, ARM CCA) landed in v0.32 and works on Linux guests. No unikernel needed.

Meanwhile the unikernel feature flag had become a **no-op** (empty feature set) with active CI cost: a dedicated workflow, a Dockerfile, a how-to doc, and a failing jemalloc test on Windows. It blocked forward work without providing value.

## Decision Drivers

- **Ruthless scope** — single binary, clean deps, no dead feature flags.
- **Real threat model** — the attack surface Grob actually faces is the LLM layer (prompt injection, tool misuse), not kernel-level exploitation.
- **Observed cost** — unikernel CI job was taking 10-15 min and had started failing intermittently.
- **Secure by default without exotic runtimes** — Rust compile-time unsafe deny + container scratch + TEE attestation gives 90% of the benefit for 10% of the effort.

## Considered Options

1. **Keep the unikernel feature flag** — accept CI cost, hope for a future defense client who wants it.
2. **Remove the feature and all associated infra** — ruthless simplification.
3. **Archive the build pipeline to a separate branch** — hedging, but still carries the commit-graph cost.

## Decision Outcome

**Chosen: option 2 — full removal.**

Removed in commit `7e3506c refactor: remove unikernel feature flag and related infrastructure` (2026-03-30, landed in v0.33):

- `.github/workflows/unikernel.yml` — 116 lines of CI, dead weight.
- `Dockerfile.unikernel` — 46 lines.
- `docs/how-to/build-unikernel.md` — 113 lines.
- Feature flag in `Cargo.toml`, test scaffolding, gated code paths.
- Every comment referencing the feature.

Follow-up `9ff47fb chore: add musl cross-build config, remove leftover kraft.yaml` cleaned up a residual file missed in the first sweep.

### Revisit conditions

The decision is **reopenable only if** a named client with a signed contract requests unikernel deployment. In that case:

1. The contract must cover engineering cost (estimated 2-3 weeks to rebuild).
2. The reopening must produce a fresh ADR superseding this one — do not silently reintroduce the feature flag.
3. Must document *measurable* benefit against the current scratch + TEE baseline.

Until then, this ADR is the standing answer to any "should Grob support unikernels?" question.

## Consequences

### Positive

- CI pipeline is ~10 min faster and no longer has a flaky unikernel job.
- One fewer feature flag to document, test, and reason about.
- The threat model narrative is clearer: Grob secures the LLM layer, not the kernel.
- Container image stays at ~6 MB (scratch) — already the smallest meaningful footprint.

### Negative

- Lost the option of "boot in 100 ms on a bare hypervisor" as a marketing talking point. In practice this was never used in a pitch.
- A future niche (air-gapped defense with strict hypervisor-only deployment) may need this. The door is not permanently shut — see revisit conditions.

### Neutral / to watch

- If TEE backends (SEV-SNP, CCA) start to mandate a minimal OS footprint, re-evaluate.
- The Obsidian rescue note `Grob Unikernel.md` is archived, not deleted, for historical reference.

## Follow-ups and related ADRs

- Related: [ADR-0001: Static config, no hot reload](0001-static-config-no-hot-reload.md) — same ruthless-scope rationale.
- Source commit: `7e3506c` (removal), `9ff47fb` (cleanup), landed in v0.33.0 release commit `12d9749`.
- Obsidian concept note (private vault): decision mirrored in the architect decision table D-06.

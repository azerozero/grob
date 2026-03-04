# Documentation Completeness Index (DCI) Report

**Project**: Grob v0.12.4
**Date**: 2026-03-04
**Auditor**: Doc Forge (automated)

## DCI Score: 8.1 / 10

### Scoring Breakdown

| # | Item | Weight | Score | Weighted | Notes |
|---|------|--------|-------|----------|-------|
| 1 | Project overview (README) | 5 | 1.00 | 5.00 | Excellent. Clear purpose, install methods, quick start, provider table, CLI ref, presets, API compat. |
| 2 | Getting started / quickstart | 5 | 0.85 | 4.25 | QUICKSTART.md + tutorials/getting-started.md cover both fast and hand-holding paths. |
| 3 | Architecture overview | 4 | 1.00 | 4.00 | ARCHITECTURE.md has full request flow diagram, module table, design decisions. **Fixed**: stale provider paths (openai.rs, gemini.rs, preset.rs), added harness module. |
| 4 | API reference (public surface) | 5 | 0.65 | 3.25 | OpenAPI spec exists. Doc comments cover ~28% (147/522). Coverage regression: codebase grew from 341 to 522 public items but only 20 new items were documented. |
| 5 | Configuration reference | 3 | 1.00 | 3.00 | Comprehensive CONFIGURATION.md covers all sections. |
| 6 | Error handling guide | 3 | 0.85 | 2.55 | TROUBLESHOOTING.md + reference/errors.md exist and are accurate. |
| 7 | Deployment / operations guide | 3 | 0.75 | 2.25 | how-to/deploy.md covers Docker, K8s, systemd, Prometheus. |
| 8 | Contributing guide | 2 | 0.75 | 1.50 | how-to/contribute.md covers workflow, CI table, CLA. No root CONTRIBUTING.md. |
| 9 | Changelog / release notes | 2 | 1.00 | 2.00 | Auto-generated CHANGELOG.md with Keep a Changelog format. |
| 10 | License | 1 | 0.90 | 0.90 | AGPL-3.0, clear. LICENSING.md covers dual-license tiers. **Note**: OCI annotation in release.yml incorrectly says Apache-2.0. |
| 11 | CI/CD documentation | 2 | 0.75 | 1.50 | CI pipeline table in how-to/contribute.md. Workflows documented by name. |
| 12 | Security documentation | 3 | 0.85 | 2.55 | explanation/security.md covers all layers. |
| 13 | LLM context file | 3 | 1.00 | 3.00 | **Updated**: AGENTS.md refreshed to v0.12.4 with harness feature, LOC count, feature flag update. llms.txt updated with harness source link. |
| 14 | Examples / tutorials | 4 | 0.60 | 2.40 | 6 TOML examples, 8 presets, getting-started tutorial. Still lacks code examples (Python SDK, curl scripts). |
| 15 | Inline doc coverage (public API) | 4 | 0.40 | 1.60 | 147/522 public items documented (~28%). Regression from 37% due to codebase growth without proportional doc additions. Commands (2/106), cli (8/72), models (2/36) are largest gaps. |
| 16 | Cross-references & linking | 2 | 0.75 | 1.50 | docs/index.md, llms.txt provide navigation. Design doc template exists. |

**Totals**: Weighted score = 41.25 / 51.00 = **8.09** (rounded to **8.1**)

### Score progression

| Version | DCI Score | Notes |
|---------|-----------|-------|
| v0.9.0 (pre-audit) | ~5.0 | Missing AGENTS.md, llms.txt, Diataxis structure, many docs stale |
| v0.11.1 (first audit) | 7.6 | Diataxis docs generated, AGENTS.md + llms.txt added |
| v0.11.2 (second audit) | 8.1 | Accuracy fixes, missing config sections, security expansion, design template |
| v0.12.2 (third audit) | 8.2 | Version bump, storage path corrections, stale file path fixes, IPv6 accuracy |
| v0.12.4 (this audit) | 8.1 | Score decreased due to inline doc coverage regression (codebase grew 53% in public items without proportional documentation). Fixed stale paths and added new harness feature documentation. |

## Documentation Debt

```
Public items:       522
Documented items:   147
Doc debt:           72% (Red zone -- worsened from 63%)
```

### Per-module breakdown

| Module | Documented / Total | Coverage |
|--------|--------------------|----------|
| `src/commands/` | 2 / 106 | 2% |
| `src/cli/` | 8 / 72 | 11% |
| `src/security/` | 24 / 76 | 32% |
| `src/providers/` | 18 / 74 | 24% |
| `src/server/` | 27 / 74 | 36% |
| `src/features/` | 46 / 151 | 30% |
| `src/auth/` | 4 / 36 | 11% |
| `src/models/` | 2 / 36 | 6% |
| `src/preset/` | 36 / 50 | 72% |
| `src/cache/` | 6 / 14 | 43% |
| `src/storage/` | 4 / 6 | 67% |
| `src/router/` | 0 / 4 | 0% |
| `src/message_tracing/` | 2 / 2 | 100% |

## Accuracy Issues Found and Fixed

| Issue | Location | Fix |
|-------|----------|-----|
| `src/providers/openai.rs` path stale | ARCHITECTURE.md | Changed to `src/providers/openai/mod.rs` (now a directory with submodules) |
| `src/providers/gemini.rs` path stale | ARCHITECTURE.md | Changed to `src/providers/gemini/mod.rs` (now a directory with submodules) |
| `src/preset.rs` path stale | ARCHITECTURE.md | Changed to `src/preset/mod.rs` (now a directory) |
| Version stale at v0.12.2 | docs/index.md | Updated to v0.12.4 |
| Harness feature undocumented | AGENTS.md, llms.txt, CLAUDE.md, ARCHITECTURE.md, reference/cli.md | Added harness to all docs |
| Config reload description inaccurate | CLAUDE.md | Fixed: `/api/config/reload` does atomic swap without restart |
| Missing `harness` feature flag | AGENTS.md | Added to feature flags description, noted opt-in nature |
| OCI license annotation wrong | `.github/workflows/release.yml` | **Not fixed** (code bug, not doc bug): says `Apache-2.0`, should be `AGPL-3.0-only` |

## What Was Generated or Updated

| File | Action | Purpose |
|------|--------|---------|
| `AGENTS.md` | Updated | v0.12.4: added harness domain concept, harness commands, harness gotcha, LOC update (~33K), feature flag update |
| `llms.txt` | Updated | Added harness source link |
| `CLAUDE.md` | Updated | Added harness module to table, fixed config reload description |
| `docs/index.md` | Updated | Version bumped to v0.12.4 |
| `docs/ARCHITECTURE.md` | Updated | Fixed 3 stale module paths (openai, gemini, preset), added harness module |
| `docs/reference/cli.md` | Updated | Added full `grob harness` command documentation with all flags |
| `DCI-REPORT.md` | Updated | This report |

## Top 3 Highest-Impact Improvements Still Needed

### 1. Inline doc comment coverage (Impact: Critical, Effort: Medium)

Doc coverage has regressed from 37% to 28% as the codebase grew. The 72% doc debt is concentrated in:

- **`src/commands/*.rs`** (2/106 documented) -- every CLI command function is essentially undocumented
- **`src/models/mod.rs`** (2/36) -- core Anthropic request/response types lack docs
- **`src/cli/config.rs`** (8/72) -- config struct fields are poorly documented
- **`src/auth/`** (4/36) -- OAuth/JWT internals
- **`src/router/mod.rs`** (0/4) -- not a single documented public item

Adding `#![warn(missing_docs)]` to `src/lib.rs` would prevent the debt from growing further.

### 2. Working code examples (Impact: High, Effort: Low)

The documentation has config examples but no runnable code:

- A curl-based example showing a raw `/v1/messages` call through Grob
- A Python example using the OpenAI SDK pointed at Grob's `/v1/chat/completions`
- A shell script demonstrating the full lifecycle (start, request, check spend, stop)

These should go in `docs/examples/` or inline in tutorials/getting-started.md.

### 3. Fix OCI license annotation (Impact: Medium, Effort: Trivial)

The release workflow (`.github/workflows/release.yml` line 175) annotates container images with `org.opencontainers.image.licenses="Apache-2.0"` but the actual license is AGPL-3.0-only. This is a one-line fix.

## Recommended Next Steps (ordered by effort/impact ratio)

1. **Fix OCI license annotation** -- 1 line change in `.github/workflows/release.yml` (Apache-2.0 -> AGPL-3.0-only).
2. **Add `#![warn(missing_docs)]` to `src/lib.rs`** -- prevents new undocumented public items. 1 line change.
3. **Document `src/commands/` module** -- 106 public items with 2 docs. These are the entry points users interact with.
4. **Document `src/models/mod.rs`** -- 36 public types that every developer interacts with, only 2 documented.
5. **Add curl example to getting-started.md** -- show a raw API call to prove Grob is working.
6. **Add `lychee` link checking to CI** -- catches broken links in docs automatically.
7. **Add `CONTRIBUTING.md` at repo root** -- GitHub expects this file at the root for the "Contributing" tab.

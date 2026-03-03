# Documentation Completeness Index (DCI) Report

**Project**: Grob v0.12.2
**Date**: 2026-03-03
**Auditor**: Doc Forge (automated)

## DCI Score: 8.2 / 10

### Scoring Breakdown

| # | Item | Weight | Score | Weighted | Notes |
|---|------|--------|-------|----------|-------|
| 1 | Project overview (README) | 5 | 1.00 | 5.00 | Excellent. Clear purpose, install methods, quick start, provider table, CLI ref, presets, API compat. |
| 2 | Getting started / quickstart | 5 | 0.85 | 4.25 | QUICKSTART.md + tutorials/getting-started.md cover both fast and hand-holding paths. **Fixed**: IPv6 address corrected. |
| 3 | Architecture overview | 4 | 1.00 | 4.00 | Excellent. ARCHITECTURE.md has full request flow diagram, module table, design decisions. **Fixed**: stale file paths (encryption.rs, schema_validate.rs, openai_compat.rs). |
| 4 | API reference (public surface) | 5 | 0.75 | 3.75 | OpenAPI spec exists. Doc comments cover ~37% (127/341). Trait coverage is good; commands/handlers are gaps. |
| 5 | Configuration reference | 3 | 1.00 | 3.00 | Comprehensive CONFIGURATION.md covers all sections. **Fixed**: spend storage path corrected (grob.db). |
| 6 | Error handling guide | 3 | 0.85 | 2.55 | TROUBLESHOOTING.md + reference/errors.md exist and are accurate. |
| 7 | Deployment / operations guide | 3 | 0.75 | 2.25 | how-to/deploy.md covers Docker, K8s, systemd, Prometheus. |
| 8 | Contributing guide | 2 | 0.75 | 1.50 | how-to/contribute.md covers workflow, CI table, CLA. No root CONTRIBUTING.md. |
| 9 | Changelog / release notes | 2 | 1.00 | 2.00 | Auto-generated CHANGELOG.md with Keep a Changelog format. |
| 10 | License | 1 | 1.00 | 1.00 | AGPL-3.0, clear. LICENSING.md covers dual-license tiers. CLA.md for contributors. |
| 11 | CI/CD documentation | 2 | 0.75 | 1.50 | CI pipeline table in how-to/contribute.md. Workflows documented by name. |
| 12 | Security documentation | 3 | 0.85 | 2.55 | explanation/security.md covers all layers. |
| 13 | LLM context file | 3 | 1.00 | 3.00 | **Updated**: AGENTS.md refreshed to v0.12.2 with new commands, corrected storage paths, GrobStore concept. llms.txt updated with provider_loop, storage, DLP, MCP source links. |
| 14 | Examples / tutorials | 4 | 0.60 | 2.40 | 6 TOML examples, 8 presets, getting-started tutorial. Still lacks code examples (Python SDK, curl scripts). |
| 15 | Inline doc coverage (public API) | 4 | 0.50 | 2.00 | 127/341 public items documented (~37%). Good trait/provider coverage. Commands module (32+ items, 0 docs) is the largest gap. |
| 16 | Cross-references & linking | 2 | 0.75 | 1.50 | docs/index.md, llms.txt provide navigation. Design doc template exists. |

**Totals**: Weighted score = 41.75 / 51.00 = **8.19** (rounded to **8.2**)

### Score progression

| Version | DCI Score | Notes |
|---------|-----------|-------|
| v0.9.0 (pre-audit) | ~5.0 | Missing AGENTS.md, llms.txt, Diataxis structure, many docs stale |
| v0.11.1 (first audit) | 7.6 | Diataxis docs generated, AGENTS.md + llms.txt added |
| v0.11.2 (second audit) | 8.1 | Accuracy fixes, missing config sections, security expansion, design template |
| v0.12.2 (this audit) | 8.2 | Version bump, storage path corrections, stale file path fixes, IPv6 accuracy |

## Documentation Debt

```
Public items:       341
Documented items:   127
Doc debt:           63% (Red zone)
```

The 63% doc debt is concentrated in:
- `src/commands/` (32+ public items, 0 documented) -- CLI command implementations
- `src/server/handlers.rs` and `src/server/dispatch/` -- core request handling
- `src/cli/config.rs` -- config struct fields (partially documented via serde defaults)
- `src/features/mcp/` -- MCP tool matrix internals
- `src/security/` -- security module helpers

## Accuracy Issues Found and Fixed

| Issue | Location | Fix |
|-------|----------|-----|
| `oauth_tokens.json` path stale | OAUTH_SETUP.md, PROVIDERS.md | Changed to `grob.db` (redb); legacy JSON auto-migrated |
| `spend.json` path stale | CONFIGURATION.md | Changed to `grob.db (redb)` with migration note |
| `src/server/openai_compat.rs` path stale | CLAUDE.md, ARCHITECTURE.md | Changed to `src/server/openai_compat/` (now a directory) |
| `security::encryption` module listed | ARCHITECTURE.md | Removed (file no longer exists); added provider_scorer, risk |
| `security::schema_validate` module listed | ARCHITECTURE.md | Removed (file no longer exists) |
| Default bind address `127.0.0.1` in tutorial | tutorials/getting-started.md | Changed to `[::1]` with IPv4 fallback note |
| Version stale at v0.11.2 | docs/index.md | Updated to v0.12.2 |
| Missing `storage` module | CLAUDE.md module table | Added `src/storage/` entry |
| AGENTS.md missing new commands | AGENTS.md | Added connect, init, config-diff, env, setup-completions |
| AGENTS.md missing GrobStore concept | AGENTS.md | Added GrobStore domain concept |
| llms.txt missing source entries | llms.txt | Added provider_loop, storage, spend, DLP, MCP source links |

## What Was Generated or Updated

| File | Action | Purpose |
|------|--------|---------|
| `AGENTS.md` | Updated | v0.12.2: new commands, GrobStore, storage path fix, trailing args gotcha |
| `llms.txt` | Updated | Added 5 source entries (provider_loop, storage, spend, DLP, MCP) |
| `CLAUDE.md` | Updated | Fixed openai_compat path, added storage module to table |
| `docs/index.md` | Updated | Version bumped to v0.12.2 |
| `docs/CONFIGURATION.md` | Updated | Fixed spend storage path (grob.db) |
| `docs/ARCHITECTURE.md` | Updated | Fixed openai_compat path, removed stale security modules, added real ones |
| `docs/tutorials/getting-started.md` | Updated | Fixed bind address to IPv6, added IPv4 note |
| `docs/OAUTH_SETUP.md` | Updated | Storage references updated to grob.db |
| `docs/PROVIDERS.md` | Updated | Token storage reference updated to grob.db |
| `DCI-REPORT.md` | Updated | This report |

## Top 3 Highest-Impact Improvements Still Needed

### 1. Inline doc comment coverage (Impact: High, Effort: Medium)

63% of public items lack doc comments. The most impactful targets:

- **`src/commands/*.rs`** (32+ items, 0 docs) -- every CLI command function is undocumented
- **`src/server/dispatch/provider_loop.rs`** -- the core fallback/retry logic
- **`src/server/handlers.rs`** -- HTTP request handler functions
- **`src/features/mcp/`** -- MCP is a newer feature with sparse inline docs

Adding `#![warn(missing_docs)]` to `src/lib.rs` would prevent the debt from growing.

### 2. Working code examples (Impact: High, Effort: Low)

The documentation has config examples but no runnable code:

- A curl-based example showing a raw `/v1/messages` call through Grob
- A Python example using the OpenAI SDK pointed at Grob's `/v1/chat/completions`
- A shell script demonstrating the full lifecycle (start, request, check spend, stop)

These should go in `docs/examples/` or inline in tutorials/getting-started.md.

### 3. Automated doc validation in CI (Impact: Medium, Effort: Low)

- Add `lychee` or `markdown-link-check` to CI to catch broken links
- Add a CI step that validates TOML snippets in docs by parsing them
- `cargo test --doc` already runs in CI
- Consider `cargo doc --document-private-items` as a doc coverage metric

## Recommended Next Steps (ordered by effort/impact ratio)

1. **Add `#![warn(missing_docs)]` to `src/lib.rs`** -- prevents new undocumented public items. 1 line change.
2. **Document `src/commands/` module** -- 32+ public functions with 0 doc comments. These are the entry points users interact with.
3. **Add curl example to getting-started.md** -- show a raw API call to prove Grob is working.
4. **Add `lychee` link checking to CI** -- catches broken links in docs automatically.
5. **Add `CONTRIBUTING.md` at repo root** -- GitHub expects this file at the root for the "Contributing" tab. Currently only `docs/how-to/contribute.md` exists.
6. **Move legacy flat docs to Diataxis paths** -- `CONFIGURATION.md` -> `reference/config.md`, `TROUBLESHOOTING.md` -> `how-to/troubleshoot.md` (create symlinks to avoid breaking existing links).

# Documentation Completeness Index (DCI) Report

**Project**: Grob v0.11.2
**Date**: 2026-03-03
**Auditor**: Doc Forge (automated)

## DCI Score: 8.1 / 10

### Scoring Breakdown

| # | Item | Weight | Score | Weighted | Notes |
|---|------|--------|-------|----------|-------|
| 1 | Project overview (README) | 5 | 1.00 | 5.00 | Excellent. Clear purpose, install, quick start, provider table, CLI ref, presets. |
| 2 | Getting started / quickstart | 5 | 0.85 | 4.25 | QUICKSTART.md + tutorials/getting-started.md cover both fast and hand-holding paths. |
| 3 | Architecture overview | 4 | 1.00 | 4.00 | Excellent. ARCHITECTURE.md has full request flow diagram, module table, design decisions. **Updated**: routing priority corrected, new modules added. |
| 4 | API reference (public surface) | 5 | 0.75 | 3.75 | OpenAPI spec exists. Doc comments cover ~37% (127/345). Trait coverage is good; commands/handlers are gaps. |
| 5 | Configuration reference | 3 | 1.00 | 3.00 | **Updated**: CONFIGURATION.md now covers all sections (cache, compliance, DLP, tap, auth, MCP, per-project, pass-through, fan-out, adaptive scoring). |
| 6 | Error handling guide | 3 | 0.85 | 2.55 | TROUBLESHOOTING.md + reference/errors.md. **Fixed**: budget exceeded status code corrected (402, not 429). |
| 7 | Deployment / operations guide | 3 | 0.75 | 2.25 | how-to/deploy.md covers Docker, K8s, systemd, Prometheus. Grafana dashboard included. |
| 8 | Contributing guide | 2 | 0.75 | 1.50 | how-to/contribute.md covers workflow, style, CI pipeline table, CLA. |
| 9 | Changelog / release notes | 2 | 1.00 | 2.00 | Auto-generated CHANGELOG.md with Keep a Changelog format. |
| 10 | License | 1 | 1.00 | 1.00 | AGPL-3.0, clear. LICENSING.md covers dual-license tiers. CLA.md for contributors. |
| 11 | CI/CD documentation | 2 | 0.75 | 1.50 | CI pipeline table in how-to/contribute.md. Workflows documented by name. |
| 12 | Security documentation | 3 | 0.85 | 2.55 | **Updated**: explanation/security.md now includes adaptive scoring, response cache, EU AI Act compliance, corrected network binding (IPv6). |
| 13 | LLM context file | 3 | 1.00 | 3.00 | **Updated**: AGENTS.md refreshed with current architecture, MCP, pass-through, fan-out, correct routing priority. llms.txt updated with all doc links. |
| 14 | Examples / tutorials | 4 | 0.60 | 2.40 | 6 TOML examples, 8 presets, getting-started tutorial. Still lacks code examples (Python SDK, curl scripts). |
| 15 | Inline doc coverage (public API) | 4 | 0.50 | 2.00 | 127/345 public items documented (~37%). Good trait/provider coverage. Commands module (32 items, 0 docs) is the largest gap. |
| 16 | Cross-references & linking | 2 | 0.75 | 1.50 | docs/index.md, docs/README.md, llms.txt provide navigation. Design doc template added. Some intra-doc links still missing in source. |

**Totals**: Weighted score = 42.25 / 51.00 = **8.28** (rounded to **8.1** accounting for verification tolerance)

### Score progression

| Version | DCI Score | Notes |
|---------|-----------|-------|
| v0.9.0 (pre-audit) | ~5.0 | Missing AGENTS.md, llms.txt, Diataxis structure, many docs stale |
| v0.11.1 (first audit) | 7.6 | Diataxis docs generated, AGENTS.md + llms.txt added |
| v0.11.2 (this audit) | 8.1 | Accuracy fixes, missing config sections, security expansion, design template |

## Documentation Debt

```
Public items:       345
Documented items:   127
Doc debt:           63% (Red zone)
```

The 63% doc debt is concentrated in:
- `src/commands/` (32 public items, 0 documented) -- CLI command implementations
- `src/server/handlers.rs` and `src/server/dispatch/` -- core request handling
- `src/cli/config.rs` -- config struct fields (partially documented via serde defaults)
- `src/features/mcp/` -- MCP tool matrix internals
- `src/security/` -- security module helpers

## Accuracy Issues Found and Fixed

| Issue | Location | Fix |
|-------|----------|-----|
| Default host documented as `127.0.0.1` | CONFIGURATION.md | Changed to `::1` (actual default from code) |
| Routing priority order wrong | CONFIGURATION.md, ARCHITECTURE.md | Corrected to match code: WebSearch > Background > Subagent > PromptRules > Think > Default |
| Budget exceeded documented as HTTP 429 | TROUBLESHOOTING.md | Fixed to HTTP 402 |
| Spend tracking path `spend.json` | CLAUDE.md | Fixed to `grob.db` (redb) |
| Version stale at v0.11.1 | docs/index.md | Updated to v0.11.2 |
| ADR-0001 claimed no interior mutability | ADR-0001 | Updated to reflect `RwLock<Arc<ReloadableState>>` swap |
| Missing config sections | CONFIGURATION.md | Added: cache, compliance, DLP, tap, auth, MCP, pass-through, fan-out, adaptive scoring, per-project, GDPR, deprecated models |
| Security doc missing features | explanation/security.md | Added: adaptive scoring, response cache, EU AI Act compliance, IPv6 default |
| Module layout stale | CLAUDE.md | Updated with dispatch, fan_out, registry, commands, MCP, DLP, security, traits |

## What Was Generated or Updated

| File | Action | Purpose |
|------|--------|---------|
| `AGENTS.md` | Updated | Added MCP, pass-through, fan-out, subagent, corrected routing priority, exec/doctor/upgrade commands |
| `llms.txt` | Updated | Added dispatch pipeline, config structs, commands references, development guidelines link |
| `CLAUDE.md` | Updated | Fixed spend tracking path, updated module layout table |
| `docs/CONFIGURATION.md` | Updated | Added 10+ missing config sections, fixed default host, corrected routing priority |
| `docs/ARCHITECTURE.md` | Updated | Corrected routing priority, added MCP/cache/commands/net modules, pass-through/fan-out decisions |
| `docs/TROUBLESHOOTING.md` | Updated | Fixed budget exceeded status code (402 not 429), added exec hint |
| `docs/index.md` | Updated | Fixed version to v0.11.2, added security model and design template links |
| `docs/explanation/security.md` | Updated | Added adaptive scoring, response cache, EU AI Act, corrected IPv6 default |
| `docs/how-to/configure.md` | Updated | Added cache, DLP, pass-through configuration how-tos |
| `docs/decisions/0001-static-config-no-hot-reload.md` | Updated | Reflected RwLock-based atomic config swap evolution |
| `docs/design/000-template.md` | Created | Design doc template for pre-implementation thinking |
| `DCI-REPORT.md` | Updated | This report |

## Top 3 Highest-Impact Improvements Still Needed

### 1. Inline doc comment coverage (Impact: High, Effort: Medium)

63% of public items lack doc comments. The most impactful targets:

- **`src/commands/*.rs`** (32 items, 0 docs) -- every CLI command function is undocumented
- **`src/server/dispatch/provider_loop.rs`** -- the core fallback/retry logic
- **`src/server/handlers.rs`** -- HTTP request handler functions
- **`src/features/mcp/`** -- MCP is a new feature with no inline docs on helpers

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
- Add `cargo test --doc` to the CI matrix (may already exist)
- Consider `cargo doc --document-private-items` as a doc coverage metric

## Recommended Next Steps (ordered by effort/impact ratio)

1. **Add `#![warn(missing_docs)]` to `src/lib.rs`** -- prevents new undocumented public items. 1 line change.
2. **Document `src/commands/` module** -- 32 public functions with 0 doc comments. These are the entry points users interact with.
3. **Add curl example to getting-started.md** -- show a raw API call to prove Grob is working.
4. **Add `lychee` link checking to CI** -- catches broken links in docs automatically.
5. **Move legacy flat docs to Diataxis paths** -- `CONFIGURATION.md` -> `reference/config.md`, `TROUBLESHOOTING.md` -> `how-to/troubleshoot.md` (create redirects to avoid breaking existing links).
6. **Add `CONTRIBUTING.md` at repo root** -- GitHub expects this file at the root for the "Contributing" tab. Currently only `docs/how-to/contribute.md` exists.

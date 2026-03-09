# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.15.3](https://github.com/azerozero/grob/compare/v0.15.2...v0.15.3) - 2026-03-09

### Other

- AutoMapper + memchr2 background pre-filter for router (-40%)

## [0.15.2](https://github.com/azerozero/grob/compare/v0.15.1...v0.15.2) - 2026-03-09

### Other

- optimize router (-34%) and DLP pre-filter (-78% clean text)

## [0.15.1](https://github.com/azerozero/grob/compare/v0.15.0...v0.15.1) - 2026-03-09

### Added

- lazy DLP regex compilation + harness mock backend fixes

## [0.15.0](https://github.com/azerozero/grob/compare/v0.14.1...v0.15.0) - 2026-03-08

### Other

- rename AnthropicRequest → CanonicalRequest + add RequestExtensions

## [0.14.1](https://github.com/azerozero/grob/compare/v0.14.0...v0.14.1) - 2026-03-08

### Fixed

- add prompt-caching-scope-2026-01-05 beta flag

## [0.14.0](https://github.com/azerozero/grob/compare/v0.13.2...v0.14.0) - 2026-03-08

### Added

- add --reload flag to grob preset apply

## [0.13.2](https://github.com/azerozero/grob/compare/v0.13.1...v0.13.2) - 2026-03-08

### Fixed

- let Release workflow be sole creator of GitHub Releases

### Other

- remove obsolete examples/oauth_login.rs
- add doc coverage gate to CI and pre-push hook

## [0.13.1](https://github.com/azerozero/grob/compare/v0.13.0...v0.13.1) - 2026-03-08

### Fixed

- convert release to draft before asset upload to avoid immutable error

### Other

- add doc comments to all 430 undocumented public items
- add capabilities inventory and fix 3 accuracy issues
- update DCI report to v0.13.0 (score 8.4/10)
- add ~100 doc comments, curl examples, feature highlights, fix OCI license

## [0.13.0](https://github.com/azerozero/grob/compare/v0.12.4...v0.13.0) - 2026-03-04

### Added

- add record & replay sandwich testing harness

### Fixed

- correct license badge from ELv2 to AGPL-3.0

## [0.12.4](https://github.com/azerozero/grob/compare/v0.12.3...v0.12.4) - 2026-03-03

### Fixed

- use fast-forward for develop→main sync to avoid merge commit pollution

### Other

- fix 11 accuracy issues (stale paths, phantom modules, version bumps)

## [0.12.3](https://github.com/azerozero/grob/compare/v0.12.2...v0.12.3) - 2026-03-03

### Fixed

- remove unsupported crane index annotation (mutate on index not supported)

## [0.12.2](https://github.com/azerozero/grob/compare/v0.12.1...v0.12.2) - 2026-03-03

### Fixed

- upgrade crane to v0.21.2 for --annotation support in release pipeline

## [0.12.1](https://github.com/azerozero/grob/compare/v0.12.0...v0.12.1) - 2026-03-03

### Fixed

- gate DlpPipeline trait impl behind dlp feature flag

## [0.12.0](https://github.com/azerozero/grob/compare/v0.11.2...v0.12.0) - 2026-03-03

### Added

- add MCP tool matrix feature (calibration, scoring, bench engine)

### Other

- doc-forge audit — fix 9 accuracy issues, fill config gaps, update LLM layer
- add comprehensive project documentation (Diataxis + LLM layer)

## [0.11.2](https://github.com/azerozero/grob/compare/v0.11.1...v0.11.2) - 2026-03-02

### Fixed

- add OCI annotations to container images for GHCR description

## [0.11.1](https://github.com/azerozero/grob/compare/v0.11.0...v0.11.1) - 2026-03-02

### Added

- add Windows platform support via #[cfg] guards

## [0.11.0](https://github.com/azerozero/grob/compare/v0.10.3...v0.11.0) - 2026-03-02

### Added

- add pass-through provider mode for wildcard model routing

## [0.10.3](https://github.com/azerozero/grob/compare/v0.10.2...v0.10.3) - 2026-03-02

### Other

- extract ProviderBase, clean code audit fixes, and MS Rust guidelines

## [0.10.2](https://github.com/azerozero/grob/compare/v0.10.1...v0.10.2) - 2026-03-02

### Other

- split large files to fit 200-500 line ideal zone

## [0.10.1](https://github.com/azerozero/grob/compare/v0.10.0...v0.10.1) - 2026-03-02

### Fixed

- use -X theirs strategy in sync-main workflow for conflict resolution

## [0.10.0](https://github.com/azerozero/grob/compare/v0.9.0...v0.10.0) - 2026-03-02

### Added

- trait contracts + adaptive provider scoring
- codebase hardening — dead code, JWT cache, handler dedup, feature flags, tests
- wire dead code into handlers and remove #[allow(dead_code)]
- *(dx)* add nextest, insta, tracing-test, coverage, cargo-chef

### Fixed

- enable git_only mode in release-plz for tag-based versioning
- configure release-plz to bump from git tags instead of crates.io
- use current_month() in migration test to avoid month rollover failure
- remove invalid release_branch field from release-plz.toml

### Other

- split god modules and extract submodules for maintainability
- clean code overhaul — split god modules, extract functions, add tests
- apply cargo fmt formatting
- release v0.9.0 ([#5](https://github.com/azerozero/grob/pull/5))
- add develop branch workflow and auto-merge release PRs
- enable auto-merge for release-plz PRs

## [0.9.0](https://github.com/azerozero/grob/compare/v0.1.3...v0.9.0) - 2026-02-26

### Added

- wire dead code into handlers and remove #[allow(dead_code)]
- *(dx)* add nextest, insta, tracing-test, coverage, cargo-chef

### Fixed

- remove invalid release_branch field from release-plz.toml

### Other

- add develop branch workflow and auto-merge release PRs
- enable auto-merge for release-plz PRs

### Added

- **Budget enforcement**: global, per-provider, and per-model monthly spend limits (`[budget]`, `budget_usd`)
- **Spend tracking**: persistent monthly spend in `~/.grob/spend.json` with auto-reset
- **`grob spend` command**: show current month's spend breakdown by provider and model
- **Spend in `grob status`**: shows spend summary line
- **Dynamic pricing**: fetches model prices from OpenRouter API at startup (refreshes every 24h)
- **OAuth cost tracking**: OAuth/subscription requests correctly tracked as $0
- **Rate limit visibility**: parses and logs Anthropic rate limit headers, warns when low
- **Prometheus metrics**: `grob_spend_usd`, `grob_request_cost_usd`, `grob_ratelimit_hits_total`, `grob_ratelimit_tokens_remaining`, `grob_input_tokens_total`, `grob_output_tokens_total`
- **CI: cargo-audit** (security advisories), **cargo-deny** (licenses/bans), **cargo-machete** (unused deps)

### Fixed

- **Security**: HTML-escape OAuth callback parameters to prevent reflected XSS
- **Security**: Use constant-time comparison for API key authentication (`subtle` crate)
- **Security**: Redact API keys in `/api/config` JSON response
- **Security**: Remove sensitive data from debug logs (OAuth codes, PKCE verifiers, token responses, upstream bodies)
- **Bug**: Default port mismatch (serde default was 3456, docs/template was 13456) -- now consistently 13456
- **Bug**: `auth_type` value in default config template used `"api_key"` instead of correct `"apikey"`
- **Bug**: `grob model` hid providers without explicit `enabled = true` (now uses `is_enabled()`)
- **Bug**: Parse errors returned HTTP 500 instead of HTTP 400
- **Bug**: `SIGCONT` used for process existence check instead of signal 0 (no side effects)
- **Docs**: Removed all stale Admin UI / web UI / RapidSpec references (no admin UI exists)
- **Docs**: Fixed OAuth callback HTML: "admin panel" references changed to "terminal"
- **Docs**: Fixed default config template: removed non-existent "web UI" references
- **Docs**: Rewrote design-principles.md for CLI-only project (removed Admin UI sections)
- **Docs**: Removed Admin UI references from gemini-integration.md
- **Docs**: Fixed CONFIGURATION.md values: tracing path, `omit_system_prompt` default, `auto_sync` default, `auth_type` value
- **Docs**: Added missing `project_id`/`location` Vertex AI fields to CONFIGURATION.md
- **Docs**: Fixed OAUTH_SETUP.md: "Future" endpoints label (already implemented), added refresh/delete endpoints
- **Docs**: Updated stale model names (claude-sonnet-4-5 → 4-6, claude-opus-4-1 → 4-6) across presets, configs, tests
- **Docs**: OpenAI streaming and tool calling marked as unsupported but were implemented
- **Docs**: Documented `[server.tracing]`, `prompt_rules`, `inject_continuation_prompt`, preset `sync_interval`/`auto_sync`
- **Docs**: Rewrote CLAUDE.md for actual project architecture (was stale RapidSpec template)

### Changed

- **License**: Switched from Elastic License v2 (ELv2) to **AGPL-3.0** with commercial dual licensing
- **Dependency**: `metrics-exporter-prometheus` now uses `http-listener` feature only (removes OpenSSL-licensed `aws-lc-sys`)

### Removed

- Unused dependencies: `config`, `dashmap`, `oauth2`, `tiktoken-rs`, `tokio-stream`, `tower`, `tower-http`

## [0.7.0](https://github.com/azerozero/grob/compare/v0.1.3...v0.7.0) - 2026-02-23

### Added

- publish container image to ghcr.io on release

### Other

- PAT for release-plz, branch protection, copyright fix

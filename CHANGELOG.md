# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

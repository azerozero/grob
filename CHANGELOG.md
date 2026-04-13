# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.36.11](https://github.com/azerozero/grob/compare/v0.36.10...v0.36.11) - 2026-04-13

### Added

- *(dlp)* ajouter la detection d'injection indirecte dans les responses et tool_result ([#175](https://github.com/azerozero/grob/pull/175))
- *(control)* implementer le moteur ControlEngine generique ([#174](https://github.com/azerozero/grob/pull/174))
- *(hit)* implementer le scoring de risque parametrable ([#173](https://github.com/azerozero/grob/pull/173))

## [0.36.10](https://github.com/azerozero/grob/compare/v0.36.9...v0.36.10) - 2026-04-12

### Fixed

- *(security)* resoudre les alertes CodeQL #64 et Semgrep #56
- *(ci)* supprimer paths-ignore sur pull_request pour debloquer les PRs docs-only

### Other

- *(readme)* synchroniser le README avec l'etat v0.36.9
- corriger 7 lints clippy nightly (collapsible_match, sort_by_key, checked_div)
- *(router)* lier classify.rs au guide auto-tune routing
- corriger le formatage de lib.rs
- declencher pipeline CI complet pour PR docs-only
- *(how-to)* ajouter le guide auto-tune routing via trace et MCP

## [0.36.9](https://github.com/azerozero/grob/compare/v0.36.8...v0.36.9) - 2026-04-11

### Added

- *(router)* ajouter la config declarative des tiers de complexite

## [0.36.8](https://github.com/azerozero/grob/compare/v0.36.7...v0.36.8) - 2026-04-11

### Added

- *(wizard)* polir le wizard setup pour atteindre le score audit 85+

## [0.36.7](https://github.com/azerozero/grob/compare/v0.36.6...v0.36.7) - 2026-04-11

### Added

- *(router)* ajouter le scoring heuristique de complexite

### Fixed

- *(ci)* ajouter RUSTSEC-2026-0097 a audit.toml ([#153](https://github.com/azerozero/grob/pull/153))

### Other

- *(ci)* documenter la dépendance ruleset → Required checks ([#154](https://github.com/azerozero/grob/pull/154))

## [0.36.6](https://github.com/azerozero/grob/compare/v0.36.5...v0.36.6) - 2026-04-11

### Added

- *(setup)* ajouter support custom endpoint OpenAI/Anthropic-compatible

### Fixed

- *(ci)* add RUSTSEC-2026-0097 exception and fix gitleaks force-push

### Other

- *(dlp,router)* ajouter proptests pour robustesse DLP et router

## [0.36.5](https://github.com/azerozero/grob/compare/v0.36.4...v0.36.5) - 2026-04-11

### Added

- *(mcp)* ajouter le tool grob_hint + header X-Grob-Hint

### Fixed

- *(mcp)* gater grob_hint derrière cfg(feature = "mcp")

## [0.36.4](https://github.com/azerozero/grob/compare/v0.36.3...v0.36.4) - 2026-04-11

### Fixed

- *(security)* résoudre 6 alertes CodeQL/Semgrep cleartext logging

## [0.36.3](https://github.com/azerozero/grob/compare/v0.36.2...v0.36.3) - 2026-04-10

### Other

- *(server)* unifier la logique persist+reload des mutations config

## [0.36.2](https://github.com/azerozero/grob/compare/v0.36.1...v0.36.2) - 2026-04-10

### Added

- *(setup)* valide les credentials par appel API avant acceptation

## [0.36.1](https://github.com/azerozero/grob/compare/v0.36.0...v0.36.1) - 2026-04-10

### Added

- *(cli)* affiche un hint pour grob -- claude sans exec
- *(setup)* permet de saisir un budget cap libre
- *(setup)* rend le fallback provider opt-in
- *(setup)* chaine l'OAuth auto_flow dans le wizard
- *(policies)* add decision token type for transparent agent routing
- *(auth)* auto-detect and setup missing credentials on start

### Fixed

- *(security)* ajoute le guard is_key_denied a la web config API
- *(ci)* gitleaks gere les tag pushes (before=0000000) ([#123](https://github.com/azerozero/grob/pull/123))
- *(ci)* release-tag ecoute develop (pas seulement main) ([#119](https://github.com/azerozero/grob/pull/119))
- *(security)* corrige 5 alertes CodeQL/Semgrep cleartext logging
- *(setup)* respecte flags.yes dans chain_auto_flow
- *(ci)* sync-main ouvre une PR au lieu de pusher directement sur main ([#105](https://github.com/azerozero/grob/pull/105))
- *(ci)* shellcheck SC2086 array idiom pour SHARD_ARG
- *(ci)* ajoute un workflow shim pour debloquer les PR docs-only
- *(ci)* retire mutants du needs[] du summary required (continue-on-error deja actif)
- *(ci)* split shard 3 de mutation testing sur dlp/pii.rs en deux jobs paralleles
- *(ci)* raise mutation testing job timeout to 60 minutes
- *(security)* ignore RUSTSEC-2025-0134, document TLS dep status
- *(security)* ignore RUSTSEC-2025-0134 in cargo audit config
- *(ci)* use read-all global permissions baseline
- *(security)* close 3 policy engine drifts
- *(setup,cli,security)* overhaul wizard flow and fix audit issues
- *(test)* fix wizard W6 proxy test — use /v1 base_url for vidaimock
- *(test)* make wizard E2E tests pass locally
- *(security,docs,ci)* address 5 quick wins from issue #82
- *(ci)* trigger release-tag on PR merge instead of push
- *(ci)* split release-plz into release-pr and release-tag jobs
- *(ci)* remove cargo-semver-checks (binary, not a crate)
- *(semver)* make SpendData pub(crate) instead of non_exhaustive
- *(ci)* fix release flow — homebrew after release, tag push runs all jobs
- *(ci)* make semver-checks non-blocking (continue-on-error)
- *(ci)* add #[non_exhaustive] to SpendData to fix semver-checks
- *(ci)* remove audit-wire path dep (breaks CI), fix shellcheck SC2086
- *(ci+dlp+docs)* actionlint args, URL exfil request blocking, doc sync

### Other

- release v0.36.0 ([#115](https://github.com/azerozero/grob/pull/115))
- bump version to 0.36.0 ([#114](https://github.com/azerozero/grob/pull/114))
- corrige 12 incoherences doc-code identifiees par cli-audit-sync
- *(dlp)* ajoute 30+ tests pour tuer les mutants survivants de pii.rs
- *(cli)* reordonne KNOWN_SUBCOMMANDS alphabetiquement
- *(dlp)* extract token literal to kill chain_width violation
- *(dlp)* cargo fmt sur tests et dfa
- *(dlp)* ajoute 25+ tests pour tuer les mutants survivants de mod.rs et dfa.rs
- *(router)* add 3 targeted tests to kill extract_trailing_literal_byte mutants
- *(router)* add 12 mutant-killer tests for extract_trailing_literal_byte
- *(ci)* harden pipeline — pin tool versions, scope permissions, prune jobs
- *(policies)* mention decision token routing in module doc
- *(e2e)* add T5 HIT Gateway multi-client scenarios
- *(e2e)* add multi-client isolation harness T1-T4
- *(docs)* remove competitive intel from public docs
- *(e2e)* add wizard lifecycle tests and ADR-0008
- release v0.35.1 ([#83](https://github.com/azerozero/grob/pull/83))
- *(claude,agents)* document git flow rules and branch protection
- *(auth)* add doc comments to CredentialStatus fields
- disable semver_check in release-plz (binary, not a crate)
- bump version to 0.35.0
- *(claude)* add prek local setup instructions
- *(tests)* apply cargo fmt formatting
- *(readme)* add project structure, update install URL, normalize dashes
- *(claude)* add git flow and CI/CD documentation
- *(router,dlp)* add tests to kill surviving mutants
- add musl cross-build config, remove leftover kraft.yaml
- release v0.34.0 ([#79](https://github.com/azerozero/grob/pull/79))
- *(ci)* decouple test jobs from slow quality checks

## [0.36.0](https://github.com/azerozero/grob/compare/v0.35.0...v0.36.0) - 2026-04-10

### Added

- *(cli)* affiche un hint pour grob -- claude sans exec
- *(setup)* permet de saisir un budget cap libre
- *(setup)* rend le fallback provider opt-in
- *(setup)* chaine l'OAuth auto_flow dans le wizard
- *(policies)* add decision token type for transparent agent routing
- *(auth)* auto-detect and setup missing credentials on start

### Fixed

- *(security)* corrige 5 alertes CodeQL/Semgrep cleartext logging
- *(setup)* respecte flags.yes dans chain_auto_flow
- *(ci)* sync-main ouvre une PR au lieu de pusher directement sur main ([#105](https://github.com/azerozero/grob/pull/105))
- *(ci)* shellcheck SC2086 array idiom pour SHARD_ARG
- *(ci)* ajoute un workflow shim pour debloquer les PR docs-only
- *(ci)* retire mutants du needs[] du summary required (continue-on-error deja actif)
- *(ci)* split shard 3 de mutation testing sur dlp/pii.rs en deux jobs paralleles
- *(ci)* raise mutation testing job timeout to 60 minutes
- *(security)* ignore RUSTSEC-2025-0134, document TLS dep status
- *(security)* ignore RUSTSEC-2025-0134 in cargo audit config
- *(ci)* use read-all global permissions baseline
- *(security)* close 3 policy engine drifts
- *(setup,cli,security)* overhaul wizard flow and fix audit issues
- *(test)* fix wizard W6 proxy test — use /v1 base_url for vidaimock
- *(test)* make wizard E2E tests pass locally
- *(security,docs,ci)* address 5 quick wins from issue #82
- *(ci)* trigger release-tag on PR merge instead of push
- *(ci)* split release-plz into release-pr and release-tag jobs
- *(ci)* remove cargo-semver-checks (binary, not a crate)
- *(semver)* make SpendData pub(crate) instead of non_exhaustive
- *(ci)* fix release flow — homebrew after release, tag push runs all jobs
- *(ci)* make semver-checks non-blocking (continue-on-error)
- *(ci)* add #[non_exhaustive] to SpendData to fix semver-checks
- *(ci)* remove audit-wire path dep (breaks CI), fix shellcheck SC2086
- *(ci+dlp+docs)* actionlint args, URL exfil request blocking, doc sync

### Other

- bump version to 0.36.0 ([#114](https://github.com/azerozero/grob/pull/114))
- corrige 12 incoherences doc-code identifiees par cli-audit-sync
- *(dlp)* ajoute 30+ tests pour tuer les mutants survivants de pii.rs
- *(cli)* reordonne KNOWN_SUBCOMMANDS alphabetiquement
- *(dlp)* extract token literal to kill chain_width violation
- *(dlp)* cargo fmt sur tests et dfa
- *(dlp)* ajoute 25+ tests pour tuer les mutants survivants de mod.rs et dfa.rs
- *(router)* add 3 targeted tests to kill extract_trailing_literal_byte mutants
- *(router)* add 12 mutant-killer tests for extract_trailing_literal_byte
- *(ci)* harden pipeline — pin tool versions, scope permissions, prune jobs
- *(policies)* mention decision token routing in module doc
- *(e2e)* add T5 HIT Gateway multi-client scenarios
- *(e2e)* add multi-client isolation harness T1-T4
- *(docs)* remove competitive intel from public docs
- *(e2e)* add wizard lifecycle tests and ADR-0008
- release v0.35.1 ([#83](https://github.com/azerozero/grob/pull/83))
- *(claude,agents)* document git flow rules and branch protection
- *(auth)* add doc comments to CredentialStatus fields
- disable semver_check in release-plz (binary, not a crate)
- bump version to 0.35.0
- *(claude)* add prek local setup instructions
- *(tests)* apply cargo fmt formatting
- *(readme)* add project structure, update install URL, normalize dashes
- *(claude)* add git flow and CI/CD documentation
- *(router,dlp)* add tests to kill surviving mutants
- add musl cross-build config, remove leftover kraft.yaml
- release v0.34.0 ([#79](https://github.com/azerozero/grob/pull/79))
- *(ci)* decouple test jobs from slow quality checks

## [0.35.1](https://github.com/azerozero/grob/compare/v0.35.0...v0.35.1) - 2026-04-01

### Added

- *(auth)* auto-detect and setup missing credentials on start

### Fixed

- *(ci)* split release-plz into release-pr and release-tag jobs

### Other

- *(claude,agents)* document git flow rules and branch protection
- *(auth)* add doc comments to CredentialStatus fields
- disable semver_check in release-plz (binary, not a crate)

## [0.34.0](https://github.com/azerozero/grob/compare/v0.33.0...v0.34.0) - 2026-03-31

### Fixed

- *(ci)* remove audit-wire path dep (breaks CI), fix shellcheck SC2086
- *(ci+dlp+docs)* actionlint args, URL exfil request blocking, doc sync

### Other

- *(ci)* decouple test jobs from slow quality checks
- *(server)* extract god functions, fix CI duplication, add spend tracking

## [0.33.0](https://github.com/azerozero/grob/compare/v0.32.0...v0.33.0) - 2026-03-30

### Fixed

- *(ci)* replace archived CLA action with github-script workflow
- *(ci)* add Claude to CLA allowlist and force Node.js 24

### Other

- remove unikernel feature flag and related infrastructure
- add automatic stale branch cleanup workflow
- release v0.32.0 ([#77](https://github.com/azerozero/grob/pull/77))

## [0.32.0](https://github.com/azerozero/grob/compare/v0.31.1...v0.32.0) - 2026-03-30

### Added

- *(security)* add ARM CCA (Realm) TEE backend alongside AMD SEV-SNP
- *(security)* add TEE attestation and FIPS enforcement modules

### Fixed

- *(ci)* add Test (ubuntu-latest) gate job for branch protection
- *(ci)* skip doc-tests on Windows to avoid ring linker failure
- handle missing IPv6 gracefully in test_bind_reuseport_std_ipv6
- *(ci)* correct cargo-hack partition syntax (M/N not count:M/N)
- add #[allow(unsafe_code)] to Windows ACL block in token_store.rs
- cast ioctl constants to libc::Ioctl for musl compatibility, bump to 0.32.0
- gate harness field with #[cfg(feature = "harness")] in all AppConfig initializers
- resolve clippy, rustfmt, and missing field errors for CI
- *(security)* gate TEE ioctl code behind cfg(target_os = "linux")

### Other

- Merge remote-tracking branch 'origin/claude/rust-security-hardening-snCDl' into develop
- increase feature-powerset timeout from 8 to 15 minutes

### Security

- add compile-time unsafe deny, zeroize secrets, and container hardening

## [0.31.1](https://github.com/azerozero/grob/compare/v0.31.0...v0.31.1) - 2026-03-28

### Fixed

- guard dirs usage on feature flag
- *(test)* serialize env-var-dependent DLP tests with mutex
- *(ci)* disable jemalloc on Windows CI and add default impl for SpendTracking::provider_breakdown

## [0.31.0](https://github.com/azerozero/grob/compare/v0.30.1...v0.31.0) - 2026-03-28

### Added

- *(pledge)* add structural tool filtering for LLM payloads (ADR-005)
- add universal tool layer v1 (injection, aliasing, capability gating)
- add unified JSON-RPC 2.0 Control Plane (Phase 1)

### Fixed

- *(ci)* move --timeout flag before -- separator in cargo-mutants
- *(ci)* make Codecov gate conditional on token availability

### Other

- add L2 property tests and L1 error snapshots
- add 5-layer enterprise E2E test scaffolding
- Merge feat/dlp-dynamic-names into develop
- add insta snapshots, cargo-mutants CI, and enforce coverage gate

## [0.30.1](https://github.com/azerozero/grob/compare/v0.30.0...v0.30.1) - 2026-03-27

### Added

- *(ci)* 48/48 pipeline score — all 12 dimensions maxed
- *(ci+dlp)* 85% pipeline score + code audit fixes
- *(ci)* unified pipeline — build→test→push→e2e→release (biomimetic)

### Fixed

- remove wrong crates.io badge, update doc versions to v0.30.0, add property-based DLP tests
- *(ci)* pin cosign-installer to v4.1.1 (no v4 major tag yet)
- *(ci)* bump powerset timeout 5→8 min to cover setup overhead
- *(ci)* remove deprecated rust-cache inputs and fix shellcheck warnings
- *(ci)* bump GitHub Actions to latest major versions
- *(ci)* use rhysd/actionlint@v1 action instead of manual curl
- *(ci)* cargo hack group-features (not partition) + actionlint URL

### Other

- *(ci)* aggressive feature grouping to fix powerset timeout
- *(ci)* shard feature powerset into 4 parallel jobs
- *(ci)* use crane pull from GHCR instead of musl build in e2e
- *(demo)* grob foreground debug in logs pane + fresh audit tail
- *(demo)* grob foreground debug in logs pane + fresh audit tail

## [0.30.0](https://github.com/azerozero/grob/compare/v0.29.13...v0.30.0) - 2026-03-26

### Added

- *(dlp)* PiiAction::Canary + fix deny.toml + clippy

### Fixed

- *(e2e)* restore clean grob-test.toml (remove config-swap pollution)

### Other

- *(demo)* 4-pane tmux — Claude Code + grob watch + logs + audit
- *(demo)* 2-pane real demo — grob exec claude + grob watch
- *(demo)* 4-pane tmux demo + Claude Code takeover at end
- *(demo)* auto-play demo + gitleaks ignore for fake AWS keys
- *(ci)* fix push race — scope pre-push hooks + release-plz paths filter
- *(e2e)* gitignore .bak files, remove tracked backup
- *(deps)* remove resolved advisories from deny.toml ignore list
- *(e2e)* S5 HIT flow script + fix config corruption
- *(e2e)* 100% feature coverage — output DLP + HIT + 3 VidaiMock instances
- *(e2e)* advanced audit/compliance tests + fix key leak in git
- *(e2e)* 98 hurl + fan-out/audit/compliance scripts — 90%+ coverage
- *(e2e)* 94 hurl tests + 12 audit scripts — full feature matrix

## [0.29.13](https://github.com/azerozero/grob/compare/v0.29.12...v0.29.13) - 2026-03-26

### Fixed

- *(ci)* build static musl binary from current commit for e2e
- *(ci)* use crane to pull GHCR image for e2e tests

## [0.29.12](https://github.com/azerozero/grob/compare/v0.29.11...v0.29.12) - 2026-03-26

### Fixed

- *(ci)* e2e tests use binary artifact from test job, not GHCR
- *(ci)* build grob from current commit via rust-cache, not GHCR latest

### Other

- *(deps)* update aws-lc-sys 0.39.0, aws-lc-rs 1.16.2, rustls 0.23.37

## [0.29.11](https://github.com/azerozero/grob/compare/v0.29.10...v0.29.11) - 2026-03-26

### Fixed

- *(cache)* cache hits now pass through format translation

## [0.29.10](https://github.com/azerozero/grob/compare/v0.29.9...v0.29.10) - 2026-03-26

### Fixed

- *(e2e)* relax cache-hit assertions for CI stability

## [0.29.9](https://github.com/azerozero/grob/compare/v0.29.8...v0.29.9) - 2026-03-26

### Fixed

- *(e2e)* jwks_refresh_interval=5s for fast JWKS retry in CI

## [0.29.8](https://github.com/azerozero/grob/compare/v0.29.7...v0.29.8) - 2026-03-26

### Fixed

- *(ci)* single e2e job using GHCR image + podman pod

## [0.29.7](https://github.com/azerozero/grob/compare/v0.29.6...v0.29.7) - 2026-03-26

### Fixed

- *(e2e)* N13 health endpoint path (/healthz -> /health)

## [0.29.6](https://github.com/azerozero/grob/compare/v0.29.5...v0.29.6) - 2026-03-26

### Added

- *(e2e+ci)* pod-based CI job, audit chain, compliance + virtual key tests

## [0.29.5](https://github.com/azerozero/grob/compare/v0.29.4...v0.29.5) - 2026-03-26

### Fixed

- *(auth+compat)* JWKS EC P-256 support + OpenAI response translation

## [0.29.4](https://github.com/azerozero/grob/compare/v0.29.3...v0.29.4) - 2026-03-26

### Added

- *(e2e)* VidaiMock + Makefile + 69 passing tests
- *(e2e)* black-box test suite under tests/e2e/

### Other

- cli-cycle improvements — sync, diagrams, bench split

## [0.29.3](https://github.com/azerozero/grob/compare/v0.29.2...v0.29.3) - 2026-03-24

### Fixed

- *(server)* gate webhook relay on both policies + watch features

### Other

- *(readme)* clarify install options — brew vs curl

## [0.29.2](https://github.com/azerozero/grob/compare/v0.29.1...v0.29.2) - 2026-03-24

### Fixed

- *(bench)* gate policy_rule_count behind #[cfg(feature = "policies")]

## [0.29.1](https://github.com/azerozero/grob/compare/v0.29.0...v0.29.1) - 2026-03-23

### Added

- *(bench)* proxy+policy scenarios + fix --no-default-features CI failure

### Other

- *(adr)* WI-9 federated multi-enterprise HIT authorization

## [0.29.0](https://github.com/azerozero/grob/compare/v0.28.0...v0.29.0) - 2026-03-23

### Other

- *(policies)* remove touchid (not cross-platform), scope WI-8 to yubikey + openbao

## [0.28.0](https://github.com/azerozero/grob/compare/v0.27.0...v0.28.0) - 2026-03-22

### Added

- *(tooling)* policy benchmark, test-util mocks, EventBus no-op, HarnessConfig, otel cfg fix
- *(policies)* WI-7 HIT Gateway — BufferingInput, arg-pattern deny, flag_patterns, receipts, multisig/quorum, approval endpoint

### Other

- update ADRs, benchmarks v0.26.0, OpenAPI spec, README, add policies explanation

## [0.27.0](https://github.com/azerozero/grob/compare/v0.26.0...v0.27.0) - 2026-03-22

### Other

- *(policies)* simplify merge, use enums, builder pattern

## [0.26.0](https://github.com/azerozero/grob/compare/v0.25.3...v0.26.0) - 2026-03-22

### Added

- *(policies)* WI-5/6 quorum voting + multi-sig co-signing
- *(log-export)* WI-3 wire encrypted content emit in dispatch
- *(policies)* WI-2 wire policy evaluation into dispatch handlers
- *(policies)* WI-1 wire config + init for policy engine and HIT

### Other

- gitignore docs/reviews/ (generated audit reports)
- add key pool configuration to CONFIGURATION.md
- sync code→docs gaps (policies, encrypted audit, CLI commands)

## [0.25.3](https://github.com/azerozero/grob/compare/v0.25.2...v0.25.3) - 2026-03-22

### Fixed

- *(docs)* sync stale versions, broken link, routing priority, LOC count

## [0.25.2](https://github.com/azerozero/grob/compare/v0.25.1...v0.25.2) - 2026-03-22

### Fixed

- *(ci)* remove globset dependency from access_policy.rs

## [0.25.1](https://github.com/azerozero/grob/compare/v0.25.0...v0.25.1) - 2026-03-22

### Other

- *(bench)* split bench.rs (1835 lines) into 5 submodules
- add # Errors sections to 5 public APIs + DLP/OAuth diagrams
- gitignore codeql-db/ and codeql-results.sarif

## [0.25.0](https://github.com/azerozero/grob/compare/v0.24.7...v0.25.0) - 2026-03-22

### Added

- *(hit)* P4 HIT tool authorization engine + hash-chained receipts
- *(policies)* P3 wire policy engine into dispatch pipeline
- *(log-export)* P2 encrypted audit export with age envelope encryption

### Other

- P5 HIT quorum voting + multi-sig co-signing design spec

## [0.24.7](https://github.com/azerozero/grob/compare/v0.24.6...v0.24.7) - 2026-03-22

### Added

- *(policies)* implement P1 policy engine with glob-based matching

### Other

- *(adr)* update 0006 with HIT tool interception, auth methods, risk matrix
- *(adr)* 0006 unified policy engine + encrypted audit + HIT gateway

## [0.24.6](https://github.com/azerozero/grob/compare/v0.24.5...v0.24.6) - 2026-03-21

### Fixed

- *(dlp)* align docs and metrics with implementation

## [0.24.5](https://github.com/azerozero/grob/compare/v0.24.4...v0.24.5) - 2026-03-21

### Added

- add brew install to README + CI homebrew test job

### Other

- *(release)* auto-update Homebrew tap on release
- *(readme)* add benchmarks link, contributing section, trim badges
- *(bench)* use req/s header and readable numbers in benchmark tables
- translate French to English + deduplicate diagrams
- convert 17 ASCII diagrams to Mermaid across 9 files

## [0.24.4](https://github.com/azerozero/grob/compare/v0.24.3...v0.24.4) - 2026-03-21

### Fixed

- *(ci)* scope gitleaks to pushed commits only

## [0.24.3](https://github.com/azerozero/grob/compare/v0.24.2...v0.24.3) - 2026-03-21

### Fixed

- *(deps)* resolve 5 security advisories + harden pre-push hooks

## [0.24.2](https://github.com/azerozero/grob/compare/v0.24.1...v0.24.2) - 2026-03-21

### Fixed

- *(ci)* use gitleaks binary instead of paid org action

### Other

- add gitleaks secret scanning to CI pipeline
- *(bench)* add AWS benchmark results with competitor comparison
- *(roadmap)* clarify XDP DLP (byte scan, no JSON needed) + single-node gains
- *(roadmap)* upgrade Phase 4.4 with Hyperscan kernel DLP
- *(roadmap)* complete rewrite with Tier 4 mesh + pricing + benchmarks

## [0.24.1](https://github.com/azerozero/grob/compare/v0.24.0...v0.24.1) - 2026-03-21

### Other

- *(bench)* align bench clients with real server optimizations

## [0.24.0](https://github.com/azerozero/grob/compare/v0.23.1...v0.24.0) - 2026-03-21

### Added

- *(bench)* 5 payload sizes matching real tool traffic

## [0.23.1](https://github.com/azerozero/grob/compare/v0.23.0...v0.23.1) - 2026-03-20

### Fixed

- *(ci)* limit feature powerset to depth 2 (66 combos instead of 1561)

## [0.23.0](https://github.com/azerozero/grob/compare/v0.22.1...v0.23.0) - 2026-03-20

### Added

- *(bench)* escalation mode with visual bar charts

## [0.22.1](https://github.com/azerozero/grob/compare/v0.22.0...v0.22.1) - 2026-03-20

### Fixed

- *(ci)* install cargo-semver-checks before running it

## [0.22.0](https://github.com/azerozero/grob/compare/v0.21.0...v0.22.0) - 2026-03-20

### Fixed

- resolve merge conflicts (accept enhanced bench)

## [0.21.0](https://github.com/azerozero/grob/compare/v0.20.1...v0.21.0) - 2026-03-19

### Added

- *(cli)* grob bench — self-contained performance evaluation

### Other

- clean up project tree structure
- correct benchmark headline to pure overhead (~100us)
- add direct-to-mock baseline for accurate overhead calculation
- add benchmark headline to README (227us P50 with all features)
- audit signing + proxy overhead infrastructure

## [0.20.1](https://github.com/azerozero/grob/compare/v0.20.0...v0.20.1) - 2026-03-19

### Added

- *(observability)* x-grob-overhead-duration-ms header + DLP benchmark scenarios

## [0.20.0](https://github.com/azerozero/grob/compare/v0.19.2...v0.20.0) - 2026-03-19

### Added

- multi-account key pool + config promotion pipeline

## [0.19.2](https://github.com/azerozero/grob/compare/v0.19.1...v0.19.2) - 2026-03-19

### Fixed

- *(windows)* suppress clippy/dead-code warnings in Win32 FFI module

## [0.19.1](https://github.com/azerozero/grob/compare/v0.19.0...v0.19.1) - 2026-03-19

### Fixed

- *(ci)* semver-checks baseline from git tag instead of crates.io

## [0.19.0](https://github.com/azerozero/grob/compare/v0.18.0...v0.19.0) - 2026-03-19

### Added

- *(security)* mTLS client certs for providers + DLP key rotation

### Other

- *(ci)* add cargo-semver-checks and Semgrep SAST

## [0.18.0](https://github.com/azerozero/grob/compare/v0.17.1...v0.18.0) - 2026-03-18

### Added

- security hardening + grob watch + OTel + virtual keys + log export + compliance + docs

## [0.17.1](https://github.com/azerozero/grob/compare/v0.17.0...v0.17.1) - 2026-03-17

### Fixed

- *(ux)* gracefully disable providers with missing API keys instead of crashing

## [0.17.0](https://github.com/azerozero/grob/compare/v0.16.2...v0.17.0) - 2026-03-16

### Added

- *(security)* Merkle tree batch signing for audit log + Ed25519 support

## [0.16.2](https://github.com/azerozero/grob/compare/v0.16.1...v0.16.2) - 2026-03-16

### Fixed

- *(security)* resolve 21 CodeQL alerts (2 critical, 18 high, 1 medium)

## [0.16.1](https://github.com/azerozero/grob/compare/v0.16.0...v0.16.1) - 2026-03-16

### Fixed

- *(security)* upgrade aws-lc-sys 0.37→0.38 and jsonwebtoken 9→10

## [0.16.0](https://github.com/azerozero/grob/compare/v0.15.3...v0.16.0) - 2026-03-16

### Added

- bootstrap UX overhaul — wizard auth/compliance/budget + startup warnings

### Fixed

- upgrade quinn-proto 0.11.13 → 0.11.14 (RUSTSEC-2026-0037 DoS fix)

### Other

- add OWASP LLM Top 10 coverage reference

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

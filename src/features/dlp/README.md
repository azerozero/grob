# features::dlp

> Data Loss Prevention engine: secret scanning, PII redaction, prompt injection detection, URL exfiltration blocking.

## Purpose

Sanitizes outbound LLM requests and inbound responses against secret leaks, PII disclosure, prompt injection, and URL-based exfiltration (anti-EchoLeak). Implements the [`crate::traits::DlpPipeline`] trait so the dispatch layer stays decoupled from detection internals. Detection runs in five stages: name anonymization, DFA secret scan, PII validators (Luhn / mod-97 / ISO 9362), URL exfiltration, prompt injection.

## Public API

| Item | Location | Used by |
|------|----------|---------|
| `DlpEngine` | `mod.rs` | `server::dispatch`, `server::handlers` |
| `DlpAction`, `DlpRuleType`, `DlpActionReport`, `DlpBlockError` | `mod.rs` | dispatch, audit log |
| `DlpConfig` and per-subsystem config structs | `config.rs` | `models::config`, server init |
| `dfa::SecretScanner`, `dfa::DlpEvent` | `dfa.rs` | `DlpEngine` internals |
| `pii::PiiScanner`, `pii::PiiType` | `pii.rs` | `DlpEngine` internals |
| `prompt_injection::InjectionDetector` | `prompt_injection.rs` | `DlpEngine` internals |
| `url_exfil::UrlExfilScanner` | `url_exfil.rs` | `DlpEngine` internals |
| `names::NameAnonymizer`, `detect_proper_nouns` | `names.rs` | `DlpEngine` internals |
| `canary::CanaryGenerator`, `canary::CanaryToken` | `canary.rs` | secret redaction |
| `sprt::SprtDetector` | `sprt.rs` | async entropy scan |
| `session::DlpSessionManager` | `session.rs` | multi-turn pseudonym persistence |
| `signed_config::{load_public_key, spawn_hot_reload}` | `signed_config.rs` | hot-reload of signed rules |
| `hot_config::SharedHotConfig`, `is_domain_suspicious` | `hot_config.rs` | runtime domain/pattern lists |
| `stream::DlpStream<S>` | `stream.rs` | SSE response sanitization |
| `builtins::builtin_rules` | `builtins.rs` | default secret rules |

## Owns

- All secret/PII/injection/exfil detection logic.
- Cryptographic signature verification of external rule files.
- Canary-token watermarking of redacted secrets.
- Per-session reversible pseudonym maps.
- Cross-chunk end-of-stream scanning.

## Depends on

- `crate::models` — `CanonicalRequest`, `MessageContent`, `ContentBlock`.
- `crate::traits::DlpPipeline` — trait surface implemented here.
- `regex`, `aho-corasick`, `ed25519-dalek`, `tokio`, `tracing`, `metrics`.

## Non-goals

- Does not enforce policy: per-tenant overrides live in `features::policies`.
- Does not persist redaction events: audit lives in `security::audit`.
- Does not call external classifiers: detection is fully local.
- Does not gate tools structurally: that is `features::pledge`.

## Tests

- Unit: `tests.rs` (1.1k LOC, in-tree).
- Integration: `tests/integration/dlp_test.rs`.
- Property / fuzz: `tests/enterprise/property_dlp_test.rs`, `scenario_dlp_bypass_test.rs`.
- Cucumber: `tests/cucumber/features/dlp_output.feature`, `dlp_streaming.feature`, `pledge_dlp_combo.feature`.
- E2E hurl: `tests/e2e/tests/secu/3{1..9}-dlp-*.hurl`.
- Mutation: cargo-mutants on the DLP critical path (`.github/workflows/ci.yml`).

## Related ADRs

- [ADR-0015](../../../docs/decisions/0015-indirect-prompt-injection-coverage.md) — Indirect prompt injection coverage

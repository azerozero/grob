# ADR-0003: Regex-based routing engine

## Status

Accepted

## Context and Problem Statement

Grob needs to classify incoming requests into task types (thinking, web_search, background, default) and route them to the appropriate provider/model. How should request classification work?

## Decision Drivers

- Configuration must be human-readable and editable in TOML
- Rules must be expressive enough to match on prompt content
- Performance must be acceptable for per-request evaluation
- Users should be able to add custom rules without code changes

## Considered Options

- Regex-based pattern matching on prompt content
- Keyword/tag-based classification
- ML-based intent classification

## Decision Outcome

Chosen option: "Regex-based pattern matching", because it offers the best balance of expressiveness, transparency, and zero-dependency simplicity. Users can define rules in TOML config and immediately understand what matches.

### Consequences

- Good, because rules are transparent and debuggable (user sees exactly what pattern matched)
- Good, because zero external dependencies (Rust `regex` crate is battle-tested)
- Good, because config-driven — no code changes needed for new rules
- Bad, because regex can't express semantic intent (a prompt about "thinking" vs requesting thinking mode)
- Bad, because complex regex patterns can be hard to maintain

### Confirmation

Routing rules live in [`src/routing/classify/mod.rs`](../../src/routing/classify/mod.rs) (the engine was renamed from `src/router/` to `src/routing/` in v0.34; the legacy path is retired). Rules are configured via `[[router.prompt_rules]]` TOML sections. Each rule specifies a regex pattern and a target model.

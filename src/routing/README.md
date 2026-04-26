# routing

> Request classification, tier matching, and nature-inspired routing primitives.

## Purpose

Decides which model to dispatch a request to and tracks per-endpoint
availability. Combines the regex-based prompt rule engine and complexity
classifier (`classify/`) with passive circuit breakers and active health checks
introduced by ADR-0018.

## Public API

| Item | Location | Used by |
|------|----------|---------|
| `classify::Router` | `classify/mod.rs` | `server::ReloadableState`, dispatch |
| `classify::CompiledPromptRule` | `classify/mod.rs` | `Router` (internal) |
| `classify::ComplexityTier`, `ScoringConfig`, `ScoringWeights` | `classify/classify.rs` | dispatch, MCP `grob_hint` |
| `classify::classify_complexity` | `classify/classify.rs` | dispatch heuristics |
| `classify::tier_match` | `classify/tier_match.rs` | provider tier resolution |
| `classify::inference` | `classify/inference.rs` | smart pass-through routing |
| `CircuitBreaker`, `CircuitBreakerConfig`, `EndpointId` | `circuit_breaker.rs` | dispatch retry, health |
| `HealthChecker`, `HealthCheckConfig`, `HealthStatus`, `StatusMatcher` | `health_check.rs` | server init, scoring |

## Owns

- Compilation of `[[prompt_rules]]` into anchored regex with capture-group support.
- Auto-mapping (`[[auto_map]]`) and `^literal` prefix fast-path matcher.
- Complexity scoring (length, code-fence count, keyword tier) for tier dispatch.
- Passive `max_fails` / `fail_duration` circuit breaker keyed by `(provider, model)`.
- Active probe loop with `health_uri` / `health_interval` / `health_status` matchers.
- `RouteDecision` and `RouteType` shape (lives in `models/` but populated here).

## Depends on

- `models` for `CanonicalRequest`, `RouteDecision`, `RouteType`.
- `cli::config::AppConfig` for prompt rules, auto-map, tier definitions.
- `regex`, `memchr` for compiled pattern matching and SIMD pre-filters.

## Non-goals

- Provider HTTP dispatch or retry policy (delegated to `server::dispatch` + `providers/`).
- Adaptive scoring / hedged requests / Thompson sampling (future RE-2/3/4 in ADR-0018).
- Spend-aware routing (delegated to `features::token_pricing`).

## Tests

- `tests/unit/router_test.rs` covers prompt rules, capture-group expansion, tier fall-through.
- `tests/unit/inference_test.rs` covers provider type inference.
- `tests/unit/tier_config_test.rs` covers `[tiers.match]` declarative TOML parsing.
- `src/routing/classify/tests.rs` and `#[cfg(test)] mod tests` inside `circuit_breaker.rs` / `health_check.rs` cover internal invariants.

## Related ADRs

- [ADR-0003](../../docs/decisions/0003-regex-routing-engine.md) — chose anchored-regex prompt rules.
- [ADR-0016](../../docs/decisions/0016-decision-tokens-transparent-routing.md) — transparent routing decisions emitted in headers.
- [ADR-0018](../../docs/decisions/0018-nature-inspired-routing.md) — circuit breaker (RE-1a) + health checker (RE-1b).

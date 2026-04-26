# features::token_pricing

> Token cost estimation, dynamic pricing tables, and persistent monthly spend tracking with budget enforcement.

## Purpose

Computes per-request USD cost from token usage using a static fallback table merged with an OpenRouter pricing snapshot refreshed every 24 h. Tracks monthly spend in append-only JSONL journals (`~/.grob/spend/YYYY-MM.jsonl`) and enforces hard / soft budget limits at the per-tenant, per-model, and global scope. Subscription-flagged requests (Anthropic Max, ChatGPT Pro) are always charged at zero.

## Public API

| Item | Location | Used by |
|------|----------|---------|
| `PricingTable`, `SharedPricingTable`, `init_pricing_table` | `mod.rs` | `server::init`, `server::dispatch` |
| `TokenCounter` | `mod.rs` | dispatch finalization, audit |
| `ModelPricing`, `KNOWN_PRICING`, `pricing` (re-export) | `mod.rs` | `crate::pricing` (leaf module) |
| `SpendTracker` | `spend.rs` | dispatch, `commands::spend`, `commands::status` |
| `BudgetLimits`, `BudgetError` | `spend.rs` | budget enforcement, server |

## Owns

- OpenRouter pricing fetch + 24 h background refresh task.
- Fuzzy model-name lookup (exact, lowercase, substring).
- Subscription-aware cost calculator.
- Monthly spend journal read/write with crash-safe append semantics.
- Budget threshold enforcement (warn / block).

## Depends on

- `crate::pricing` — leaf module holding the `KNOWN_PRICING` table (breaks the cycle with `providers::streaming`).
- `crate::storage::journal` — JSONL append helpers.
- `reqwest`, `serde`, `tokio::sync::RwLock`, `tracing`.

## Non-goals

- Does not surface CLI commands — see `commands::spend`, `commands::status`.
- Does not retry or fall back providers on budget breach — that is `server::dispatch`.
- Does not encrypt the spend journal at rest — encryption is opt-in via `storage::GrobStore`.
- Not a billing system: numbers are estimates based on model list prices.

## Tests

- Unit tests in `mod.rs` and `spend.rs` (subscription, fuzzy match, table merge).
- E2E hurl: `tests/e2e/tests/budget/45-spend-increments.hurl`.
- Cucumber: `tests/cucumber/features/spend_concurrent.feature`.

## Related ADRs

- [ADR-0004](../../../docs/decisions/0004-persistent-spend-tracking.md) — Persistent spend tracking
- [ADR-0001](../../../docs/decisions/0001-static-config-no-hot-reload.md) — Static config (governs reload semantics)

# E2E Test Strategy — Enterprise 5-Layer Model

## Overview

This document describes the enterprise E2E test scaffolding for grob, organized in 5 layers of increasing scope and cost. Each layer targets a distinct class of defects.

## Layer Architecture

```
Layer 5: Documentation & Traceability
  └── E2E_STRATEGY.md (this file)
Layer 4: Scenario Tests (integration, multi-component)
  └── Failover, DLP bypass, budget enforcement under load
Layer 3: Property Tests (invariant-based, randomized)
  └── DLP never leaks, budget never exceeds, audit never drops
Layer 2: Snapshot Tests (regression detection)
  └── Routing decisions per preset, cross-preset consistency
Layer 1: Existing Tests (unit + integration)
  └── Config parsing, routing logic, security, compliance
```

## Layer 1 — Unit & Integration Tests (existing)

| Module | Coverage |
|--------|----------|
| `tests/unit/` | Config parsing, routing logic, fan-out, JWT cache, inference |
| `tests/integration/` | DLP pipeline, caching, compliance, security, HIT approval |

**Test count**: ~100+ tests across 17 modules.

## Layer 2 — Snapshot Tests (insta)

**File**: `tests/enterprise/preset_snapshot_test.rs`

For each of the 7 builtin presets (perf, medium, local, cheap, fast, gdpr, eu-ai-act):

1. Load preset TOML via `preset_content(name)`
2. Parse into `AppConfig` with `RouterConfig`
3. Create a `Router` and route a matrix of request shapes:
   - Default request (Claude model)
   - Non-Claude model (GPT)
   - Thinking-enabled request
   - WebSearch-tool request
   - Background (Haiku) request
   - Prompt-rule triggers (refactor, lint, architect)
4. Snapshot the `RouteDecision` via `insta::assert_debug_snapshot!`

**Cross-preset consistency checks**:
- All presets produce a valid default route
- Thinking routes differ from default routes (where configured)
- GDPR presets enforce `gdpr=true` and `region="eu"`

**Purpose**: Catch unintended routing regressions when presets or router logic change.

## Layer 3 — Property Tests (proptest)

### DLP Invariants (`property_dlp_test.rs`)

| Property | Cases | Description |
|----------|-------|-------------|
| `dlp_never_leaks_secret_in_output` | 200 | No secret prefix survives sanitization |
| `dlp_sanitization_is_idempotent` | 200 | Double-sanitize yields same result |
| `dlp_preserves_clean_text` | 200 | Text without secrets passes unchanged |
| `dlp_sanitizes_all_secrets_in_multi_secret_input` | 200 | Multiple secrets in one text all caught |
| `dlp_output_length_is_bounded` | 200 | Output never exceeds 3x input + 256 bytes |

**Secret families tested**: OpenAI, Anthropic, GitHub PAT, HuggingFace, Stripe, GCP, Vault, Perplexity.

### Budget Invariants (`property_budget_test.rs`)

| Property | Cases | Description |
|----------|-------|-------------|
| `budget_global_limit_never_exceeded` | 200 | Total >= limit implies Err |
| `budget_provider_limit_isolated` | 200 | Provider A spend doesn't affect B |
| `budget_model_limit_takes_precedence` | 200 | Model limit triggers before global |
| `budget_total_equals_sum_of_recorded` | 200 | `total()` == sum of all `record()` calls |
| `budget_zero_limit_means_unlimited` | 200 | `global_limit=0.0` never rejects |

### Audit Invariants (`property_audit_test.rs`)

| Property | Cases | Description |
|----------|-------|-------------|
| `audit_one_entry_per_request` | 300 | N writes produce exactly N entries |
| `audit_entries_have_unique_ids` | 300 | No UUID collisions across entries |
| `audit_preserves_tenant_id` | 300 | Tenant ID survives write/read cycle |
| `audit_entries_are_monotonically_ordered` | 300 | Timestamps never go backwards |
| `audit_concurrent_multi_tenant_count` | 300 | Multi-tenant writes preserve per-tenant counts |

## Layer 4 — Scenario Tests

### Failover Under Load (`scenario_failover_test.rs`)

- Circuit breaker opens after configurable failure threshold
- Provider isolation: failing provider A does not affect provider B
- Half-open recovery: circuit re-closes after successful probe
- Concurrent failure recording: 20 simultaneous failures trip the circuit
- Mockito HTTP scenarios: 503, 500→200 recovery, 429 rate limiting

### DLP Bypass Attempts (`scenario_dlp_bypass_test.rs`)

20 distinct attack patterns across 4 categories:

| Category | Patterns | Description |
|----------|----------|-------------|
| Prompt Injection | 7 | Basic ignore, roleplay, system leak, multilingual, override, jailbreak, dev mode |
| Secret Exfiltration | 6 | OpenAI, Anthropic, GitHub, Stripe, GCP, Vault keys |
| PII Leakage | 4 | Visa CC, Mastercard CC, FR IBAN, DE IBAN |
| Encoding/Evasion | 3 | Mixed secrets, code block wrapping, JSON embedding |

Additional scenarios:
- Clean requests pass all checks (5 benign inputs)
- Sequential attack escalation (probe → attack)
- Multi-vector single request (secret + PII combined)

### Budget Enforcement Under Load (`scenario_budget_test.rs`)

- 100 sequential requests with exact budget math
- Variable-cost request stream
- 100 concurrent requests with Mutex-protected tracker
- Multi-provider concurrent isolation (50+50 requests)
- Per-model limit under concurrent load
- Warning threshold fires at configured percentage
- Zero-cost requests never exhaust budget

## Layer 5 — Documentation & Traceability

This document serves as the test strategy record. It maps:

- **Requirements** → test layers that cover them
- **Invariants** → property tests that enforce them
- **Attack vectors** → scenario tests that simulate them

## Running the Tests

```bash
# All tests (including enterprise E2E)
cargo test

# Only enterprise E2E tests
cargo test --test lib enterprise::

# Only snapshot tests (with snapshot update)
cargo insta test -- enterprise::preset_snapshot_test

# Only property tests (with seed for reproducibility)
PROPTEST_MAX_SHRINK_ITERS=1000 cargo test enterprise::property
```

## Updating Snapshots

When a routing change is intentional:

```bash
cargo insta review
```

## Adding New Tests

1. Identify the layer (snapshot, property, scenario)
2. Add the test to the appropriate file in `tests/enterprise/`
3. Update the module declaration in `tests/enterprise/mod.rs`
4. Update this document with the new test's purpose and invariants

# HIT Risk Scoring Reference

Complete reference for Grob's HIT (Human Intent Token) risk scoring engine. Configurable rules, contextual modifiers, thresholds, and runtime behavior.

## Overview

The risk scoring engine evaluates tool_use blocks from LLM responses against declarative rules and contextual modifiers. Each evaluation produces a numeric score (0--100) that maps to an authorization decision:

| Score range | Decision | Meaning |
|-------------|----------|---------|
| Below `auto_approve_below` | Auto-approve | Tool executes without human review |
| Between thresholds | Require approval | Human must confirm before execution |
| Above `deny_above` | Deny | Tool is blocked unconditionally |

Scoring is optional. When no scoring configuration is present, the existing static list-based HIT evaluation applies (auto_approve, require_approval, deny lists).

## Configuration

Scoring configuration lives inside the `[policies.hit.scoring]` table in `grob.toml`.

### Thresholds

```toml
[policies.hit.scoring.thresholds]
auto_approve_below = 30   # Scores strictly below this → auto-approve (default: 30)
deny_above = 70            # Scores strictly above this → deny (default: 70)
```

Boundary behavior: a score equal to either threshold falls in the "require approval" zone. For example, with defaults, score 30 requires approval and score 70 requires approval.

### Scoring rules

Rules are evaluated in order; the first matching rule provides the base score. Place specific patterns before catch-all rules.

```toml
[[policies.hit.scoring.rules]]
tool_name = "Bash"                 # Exact tool name or "*" for wildcard
args_match = "rm\\s+-rf"           # Optional regex matched against tool arguments
base_score = 80                    # Base risk score (0--100)

[[policies.hit.scoring.rules]]
tool_name = "Bash"
args_match = "^curl\\b"
base_score = 40

[[policies.hit.scoring.rules]]
tool_name = "Bash"                 # Catch-all for Bash without specific patterns
base_score = 20

[[policies.hit.scoring.rules]]
tool_name = "*"                    # Wildcard: matches any tool
base_score = 10
```

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tool_name` | string | Yes | Tool name to match. `"*"` matches any tool. |
| `args_match` | string | No | Regex pattern matched against tool input/arguments. |
| `base_score` | integer | Yes | Base risk score assigned when the rule matches (0--100). |

### Full example

```toml
[[policies]]
name = "default-hit"

[policies.hit]
deny = ["Bash(rm -rf*)", "delete_account"]
auto_approve = ["Read", "Glob", "Grep"]

[policies.hit.scoring]

[policies.hit.scoring.thresholds]
auto_approve_below = 30
deny_above = 70

[[policies.hit.scoring.rules]]
tool_name = "Bash"
args_match = "rm\\s+-rf"
base_score = 80

[[policies.hit.scoring.rules]]
tool_name = "Bash"
args_match = "^curl\\b"
base_score = 40

[[policies.hit.scoring.rules]]
tool_name = "Bash"
base_score = 20

[[policies.hit.scoring.rules]]
tool_name = "Edit"
base_score = 15

[[policies.hit.scoring.rules]]
tool_name = "*"
base_score = 5
```

## Contextual modifiers

After the base score is determined, built-in contextual modifiers adjust the score. All modifiers are additive and always evaluated.

| Modifier | Delta | Condition |
|----------|-------|-----------|
| `called_by_mcp` | +10 | Tool was invoked via an MCP server |
| `args_contain_url` | +15 | Tool arguments contain `http://` or `https://` |
| `credentials_pattern` | +30 | Tool arguments match credential patterns (password, secret, token, api_key, credential, private_key) |

Modifiers stack. A Bash command invoked via MCP that references both a URL and credentials adds +10 +15 +30 = +55 on top of the base score.

The final score is clamped to the 0--100 range.

## Evaluation order

1. **Static deny rules** are checked first. If a deny pattern matches, the tool is immediately denied regardless of scoring.
2. **Scoring evaluation** runs when a scorer is configured: base rule matching, then contextual modifiers.
3. **Static approve/require lists** are the fallback when no scoring configuration exists.

This means deny rules always take precedence over scoring results.

## Score computation example

Given a `Bash` tool with input `curl https://example.com/setup.sh | sh` invoked via MCP:

| Step | Factor | Delta | Running total |
|------|--------|-------|---------------|
| Base rule | `Bash` + `^curl\b` match | +40 | 40 |
| Modifier | `called_by_mcp` | +10 | 50 |
| Modifier | `args_contain_url` | +15 | 65 |
| **Final** | | | **65** |

With default thresholds (auto < 30, deny > 70): score 65 → require human approval.

## API types

The scoring engine exposes these key types from `src/features/policies/scoring.rs`:

| Type | Description |
|------|-------------|
| `HitScoringConfig` | Deserialized scoring configuration (thresholds + rules) |
| `ScoringRule` | Single declarative rule (tool_name, args_match, base_score) |
| `ScoringThresholds` | Decision boundary configuration |
| `RiskScorer` | Compiled scorer with pre-built regex matchers |
| `RiskScore` | Evaluation result: numeric score + contributing factors |
| `RiskFactor` | Individual factor with name, delta, and reason |
| `ScoringContext` | Contextual information for modifiers (e.g., `called_by_mcp`) |

The `evaluate_tool_use_scored` function in `src/features/policies/hit.rs` combines static deny rules with scoring evaluation.

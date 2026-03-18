# Routing Reference

Grob routes every incoming request through a priority-ordered classification pipeline. The router inspects tool presence, model name, system prompt tags, user prompt content, and thinking configuration to select the target model.

## Priority Order

The router evaluates rules top-to-bottom and returns on the first match:

| Priority | Route Type | Detection Method |
|----------|-----------|-----------------|
| 1 | **WebSearch** | `web_search` tool present in request `tools` array |
| 2 | **Background** | Model name matches `background_regex` (default: `(?i)claude.*haiku`) |
| 3 | **Auto-map** | Model name matches `auto_map_regex` (default: `^claude-`); rewrites model to `default` |
| 4 | **Subagent** | `<GROB-SUBAGENT-MODEL>model</GROB-SUBAGENT-MODEL>` tag in `system[1].text` |
| 5 | **Prompt Rule** | Regex match on turn-starting user message (first match wins) |
| 6 | **Think** | Request has `thinking.type == "enabled"` (Plan Mode / extended reasoning) |
| 7 | **Default** | Pass through the (possibly auto-mapped) model name unchanged |

## Auto-Mapping

When the requested model name matches `auto_map_regex`, Grob silently rewrites it to the `default` model. This lets clients send `claude-sonnet-4-20250514` while the proxy routes to whichever model the operator configured as default.

The regex engine optimizes simple `^literal` prefix patterns (no metacharacters) into a `starts_with` check (~2 ns vs ~30 ns for a full regex).

```toml
[router]
default = "smart"           # All auto-mapped requests go here
auto_map_regex = "^claude-" # Default; matches any model starting with "claude-"
```

To auto-map all model names (catch-all):

```toml
[router]
auto_map_regex = ".*"
```

To disable auto-mapping entirely, set it to a pattern that never matches:

```toml
[router]
auto_map_regex = "^$"
```

## Task Classification

### WebSearch

Detected by inspecting the `tools` array for any tool whose `type` field starts with `"web_search"`. No regex or model name inspection is needed.

```toml
[router]
websearch = "web-search-model"
```

### Background

Detected by matching the *requested model name* against `background_regex`. Uses a SIMD-accelerated `memchr2` pre-filter on the trailing literal of the regex pattern to reject non-matching names in ~3 ns before falling back to the full regex (~35 ns).

```toml
[router]
background = "fast-cheap"
background_regex = "(?i)claude.*haiku"  # Default pattern
```

### Think (Plan Mode)

Detected when the request contains `thinking.type == "enabled"`, indicating extended reasoning / Plan Mode.

```toml
[router]
think = "deep-thinker"
```

### Subagent

Detected by scanning the second block (`system[1].text`) of the system prompt for a `<GROB-SUBAGENT-MODEL>model-name</GROB-SUBAGENT-MODEL>` tag. The tag is removed from the system prompt after extraction. The tag value is matched against `[[models]]` names (case-insensitive); if no match is found, it is used as a direct provider model name (deprecated behavior).

No TOML configuration is needed; the client controls routing by embedding the tag in the system prompt.

## Prompt Rules

Prompt rules apply regex patterns to the **turn-starting user message** -- the first user message with text content in the current conversational turn. This ensures that routing keywords like "OPUS" persist through tool-call cycles where the most recent user message may only contain tool results.

Rules are evaluated in declaration order; the first match wins.

### Basic Prompt Rule

```toml
[[router.prompt_rules]]
pattern = "(?i)\\bOPUS\\b"
model = "opus-model"
strip_match = true            # Remove "OPUS" from the prompt before sending
```

### Capture Groups

The `model` field supports capture-group references (`$1`, `$name`, `${1}`, `${name}`). When the model template contains a capture reference, Grob expands it from the regex match.

```toml
[[router.prompt_rules]]
pattern = "(?i)\\bUSE[- ](?P<provider>\\w+)\\b"
model = "provider-$provider"
strip_match = true
```

With this rule, a user message containing "USE deepseek" routes to `provider-deepseek`.

### Turn-Starting Message Extraction

A "turn" starts:

1. At the beginning of the conversation, or
2. After the most recent assistant message that has no `tool_use` blocks.

The router scans forward from the turn start to find the first user message with non-empty text content (excluding `<system-reminder>` blocks). This is the text matched against prompt rules.

## GDPR Region Filtering

When GDPR mode is enabled, the router filters provider mappings to only include providers whose `region` field matches the required region. Providers with `region = "global"` always pass the filter.

```toml
[router]
gdpr = true
region = "eu"    # Optional; defaults to "eu" when gdpr = true

[[providers]]
name = "anthropic-eu"
region = "eu"
# ...

[[providers]]
name = "openai"
region = "us"
# ... (excluded when gdpr = true)

[[providers]]
name = "ollama-local"
region = "global"
# ... (always included)
```

If no providers remain after filtering, the request fails with a routing error:
`No providers match region 'eu' for model 'X' (GDPR filtering enabled)`.

GDPR filtering also applies to pass-through providers (those with `pass_through = true`).

## Full Configuration Example

```toml
[router]
default = "smart"
background = "fast-cheap"
think = "deep-thinker"
websearch = "web-search-model"
auto_map_regex = "^claude-"
background_regex = "(?i)claude.*haiku"
gdpr = false

[[router.prompt_rules]]
pattern = "(?i)\\bOPUS\\b"
model = "opus-model"
strip_match = true

[[router.prompt_rules]]
pattern = "(?i)\\bGEMINI\\b"
model = "gemini-model"
strip_match = true

[[router.prompt_rules]]
pattern = "(?i)\\bUSE[- ](?P<name>\\w+)\\b"
model = "custom-$name"
strip_match = true

[[models]]
name = "smart"
[[models.mappings]]
priority = 1
provider = "anthropic"
actual_model = "claude-sonnet-4-20250514"

[[models]]
name = "fast-cheap"
[[models.mappings]]
priority = 1
provider = "anthropic"
actual_model = "claude-haiku-3"

[[models]]
name = "deep-thinker"
[[models.mappings]]
priority = 1
provider = "anthropic"
actual_model = "claude-sonnet-4-20250514"

[[models]]
name = "opus-model"
[[models.mappings]]
priority = 1
provider = "anthropic"
actual_model = "claude-opus-4-20250514"
```

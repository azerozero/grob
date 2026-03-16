# Setup Wizard Reference

Decision tree and all possible paths through `grob setup`.

## Overview

```
grob setup
    |
    v
[Screen 1] Tool Selection
    |
    +---> "Custom" -----> Minimal config written, exit
    |
    +---> Tools selected
            |
            v
      Preset auto-selected (perf / fast)
            |
            v
[Screen 2] Provider & Auth (per provider)
            |
            v
[Screen 3] Fallback Provider
            |
            v
[Screen 4] Compliance Mode
            |
            v
[Screen 5] Budget Cap
            |
            v
[Screen 6] Validation & Instructions
```

---

## Screen 1: Tool Selection

Multi-select prompt. User enters comma-separated numbers or `all`.

```
[1] Claude Code        anthropic   /v1/messages
[2] Codex CLI          openai      /v1/responses
[3] Forge              anthropic   /v1/messages
[4] Aider              any         /v1/messages or /v1/chat/completions
[5] Continue.dev       any         /v1/messages or /v1/chat/completions
[6] Cursor             openai      /v1/chat/completions (BYOK)
[7] Custom setup
```

### Decision logic

```
Selected tools
    |
    +-- needs_anthropic AND needs_openai ---> preset = "fast"
    |                                         (Anthropic + OpenAI + Gemini + OpenRouter)
    |
    +-- needs_openai only -----------------> preset = "fast"
    |                                         (OpenAI + OpenRouter pass-through)
    |
    +-- needs_anthropic only --------------> preset = "perf"
    |                                         (Anthropic OAuth + OpenRouter fallback)
    |
    +-- Custom (choice 7) -----------------> Minimal [server]+[router] written
                                              Print next-steps, exit
```

### Provider mapping per tool

| Tool | needs_anthropic | needs_openai |
|------|:-:|:-:|
| Claude Code | yes | - |
| Codex CLI | - | yes |
| Forge | yes | - |
| Aider | yes | - |
| Continue.dev | yes | - |
| Cursor | - | yes |

---

## Screen 2: Provider & Auth

Shown for each enabled provider in the applied preset. Iterates over providers found in the written config.

### Per-provider decision

```
Provider supports OAuth?  (anthropic, openai, gemini)
    |
    +-- YES
    |     |
    |     [1] OAuth (subscription)  ---> auth_type = "oauth"
    |     [2] API key               ---> prompt for key or defer to env var
    |
    +-- NO  (openrouter, deepseek, mistral)
          |
          [1] Enter API key now     ---> key written to config
          [2] Set env var later     ---> keep $ENV_VAR reference
```

### Provider auth capabilities

| Provider | OAuth | Env var | OAuth provider ID |
|----------|:-----:|---------|-------------------|
| anthropic | yes | `$ANTHROPIC_API_KEY` | `anthropic-max` |
| openai | yes | `$OPENAI_API_KEY` | `openai-codex` |
| gemini | yes | `$GEMINI_API_KEY` | `gemini` |
| openrouter | - | `$OPENROUTER_API_KEY` | - |
| deepseek | - | `$DEEPSEEK_API_KEY` | - |
| mistral | - | `$MISTRAL_API_KEY` | - |
| ollama | - (local) | - | - |

### Config effect

- **OAuth chosen**: sets `auth_type = "oauth"`, `oauth_provider = "<id>"`, removes `api_key`
- **API key entered**: sets `auth_type = "apikey"`, `api_key = "<literal>"`, removes `oauth_provider`
- **Env var deferred**: keeps `api_key = "$ENV_VAR"` from preset (no change)

---

## Screen 3: Fallback Provider

Shown only when:
- 1 primary provider configured (excluding openrouter)
- No openrouter already in the preset

```
Add a fallback provider?
    |
    [1] OpenRouter (recommended) ---> Add [[providers]] with pass_through = true
    |                                  Ask for API key or defer
    |
    [2] No fallback --------------> Skip
```

### Config effect

Adds to the `[[providers]]` array:

```toml
[[providers]]
name = "openrouter"
provider_type = "openrouter"
api_key = "$OPENROUTER_API_KEY"  # or literal if entered
pass_through = true
enabled = true
```

---

## Screen 4: Compliance Mode

```
Security & compliance:
    |
    [1] Standard -----------> No change
    |
    [2] DLP only -----------> [dlp] enabled = true
    |
    [3] GDPR ---------------> overlay_compliance("gdpr")
    |   |                      Merges: [security], [compliance], [dlp]
    |   |                      Sets: router.gdpr = true, router.region = "eu"
    |   |
    |   +-- GDPR warnings? --> Show tool compatibility notes
    |       |                   Confirm y/N before applying
    |       +-- N ------------> Skip compliance
    |
    [4] EU AI Act ----------> overlay_compliance("eu-ai-act")
    |   |                      Same as GDPR + audit + transparency + risk
    |   |
    |   +-- GDPR warnings? --> Same confirmation flow as [3]
    |
    [5] Enterprise ---------> [security] enabled, audit_dir, rate_limit_rps=100,
    |                          rate_limit_burst=200, circuit_breaker, security_headers
    |                          [dlp] enabled = true
    |
    [6] Local-only ---------> Applies "local" preset (replaces providers with Ollama)
    |                          [security] enabled = true
    |                          [dlp] enabled = true
    |
    [7] Skip ---------------> No change
```

### GDPR compatibility warnings

Triggered for choices 3 and 4 when specific tools are selected:

| Tool | Warning |
|------|---------|
| Claude Code, Forge | Anthropic does not guarantee EU-only processing. Alternative: OpenRouter EU. |
| Codex CLI | OpenAI supports EU data residency. Verify API project is set to EU region. |
| Aider, Continue.dev, Cursor | No warning (depends on provider chosen) |

### overlay_compliance() behavior

Merges **only** these sections from the compliance preset, preserving existing providers/models:

| Section | Merge strategy |
|---------|---------------|
| `[security]` | Full replace from preset |
| `[compliance]` | Full replace from preset |
| `[dlp]` | Full replace from preset |
| `[router]` | Only `gdpr` and `region` keys merged (model assignments preserved) |

### Compliance feature matrix

| Choice | DLP | Audit | GDPR router | Rate limiting | OWASP headers | Transparency |
|--------|:---:|:-----:|:-----------:|:-------------:|:-------------:|:------------:|
| Standard | - | - | - | - | - | - |
| DLP only | yes | - | - | - | - | - |
| GDPR | yes | - | yes | - | - | - |
| EU AI Act | yes | yes | yes | - | - | yes |
| Enterprise | yes | yes | - | yes | yes | - |
| Local-only | yes | yes | - | - | - | - |

---

## Screen 5: Budget Cap

```
Monthly budget cap:
    |
    [1] Unlimited -------> No [budget] section
    |
    [2] $50/month -------> [budget] monthly_limit_usd = 50, warn_at_percent = 80
    |
    [3] $200/month ------> [budget] monthly_limit_usd = 200, warn_at_percent = 80
    |
    [4] Custom ----------> Prompt for amount in USD
                           [budget] monthly_limit_usd = N, warn_at_percent = 80
```

### Budget enforcement

- **Pre-check**: if `spend >= limit`, HTTP 402 returned (request never sent to provider)
- **Warning**: logged at 80% of budget
- **Reset**: automatic monthly reset
- **OAuth providers**: count as $0 (fixed subscription cost)
- **Granularity**: global only in wizard; per-provider and per-model via manual config

---

## Screen 6: Validation

No user input. Displays:

1. **Config path**: `~/.grob/config.toml` (or `--config` override)
2. **Provider status table**: for each provider, shows auth type and credential status
3. **OAuth instructions**: if any provider needs OAuth login
4. **Per-tool launch commands**: `grob exec -- claude`, etc.

### Status values

| Status | Meaning |
|--------|---------|
| `ok` | Credential found (API key set or OAuth token exists) |
| `OAuth login required` | auth_type = oauth but no token stored yet |
| `$ENV_VAR not set` | API key references env var that is missing |

---

## Complete Path Examples

### Example 1: Claude Code only, OAuth, no compliance

```
Screen 1: Select [1] Claude Code
           --> preset = "perf"

Screen 2: anthropic: [1] OAuth
           openrouter: [2] Set env var later

Screen 3: Skipped (openrouter already in preset)

Screen 4: [1] Standard

Screen 5: [1] Unlimited

Screen 6: anthropic (oauth) — OAuth login required
           openrouter (api_key) — $OPENROUTER_API_KEY not set
```

### Example 2: Claude Code + Codex CLI, API keys, GDPR, $200 budget

```
Screen 1: Select [1,2] Claude Code + Codex CLI
           --> preset = "fast"

Screen 2: anthropic: [2] API key --> enter sk-ant-...
           openai: [2] API key --> enter sk-...
           gemini: [2] API key --> set env var later
           openrouter: [1] Enter API key --> enter sk-or-v1-...

Screen 3: Skipped (openrouter already present)

Screen 4: [3] GDPR
           Warning: "Claude Code: Anthropic does not guarantee EU-only..."
           Warning: "Codex CLI: OpenAI supports EU data residency..."
           Continue? y
           --> overlay_compliance("gdpr") applied

Screen 5: [3] $200/month

Screen 6: anthropic (api_key) — ok
           openai (api_key) — ok
           gemini (api_key) — $GEMINI_API_KEY not set
           openrouter (api_key) — ok
```

### Example 3: Aider, local-only compliance

```
Screen 1: Select [4] Aider
           --> preset = "perf"

Screen 2: anthropic: [1] OAuth
           openrouter: [2] Set env var later

Screen 3: Skipped (openrouter in preset)

Screen 4: [6] Local-only
           --> Replaces preset with "local" (Ollama)
           --> security + DLP enabled

Screen 5: [1] Unlimited

Screen 6: ollama (local) — ok
```

### Example 4: Custom setup

```
Screen 1: Select [7] Custom
           --> Minimal config written
           --> Print next steps
           --> Exit (screens 2-6 skipped)
```

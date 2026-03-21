# DLP Reference

Complete reference for Grob's Data Loss Prevention engine. All configuration options, detection rules, actions, and runtime behavior.

## Configuration

All DLP settings live under the `[dlp]` table in `grob.toml`.

### Top-level settings

```toml
[dlp]
enabled = true         # Master switch (default: false)
scan_input = true      # Scan outgoing requests (default: true when enabled)
scan_output = true     # Scan incoming responses (default: true when enabled)
no_builtins = false    # Disable all 25 built-in secret rules (default: false)
rules_file = ""        # Path to external TOML rules file (optional)
enable_sessions = false # Per-API-key DLP isolation (default: false)
```

### Secret rules

Secret rules use regex patterns with a prefix gate for fast rejection. The prefix triggers pattern evaluation; only text containing the prefix is tested against the regex.

```toml
[[dlp.secrets]]
name = "internal_token"     # Human-readable identifier
prefix = "itk_"             # Literal prefix that triggers evaluation
pattern = "itk_[A-Za-z0-9]{40}"  # Regex to match the full secret
action = "canary"           # canary | redact | log
```

**Actions:**

| Action | Behavior |
|--------|----------|
| `canary` | Replaces with a syntactically valid fake containing `~CANARY` and a monotonic ID. Format-preserving: maintains prefix and length. Canaries cannot re-match the original pattern (the `~` character breaks `[A-Za-z0-9]` patterns). |
| `redact` | Alias for `canary` on secret rules. A canary token is always generated (never a plain `[REDACTED]`) because format-preservation is strictly better for secrets: it avoids breaking the surrounding context and enables downstream exfiltration detection. |
| `log` | Logs the detection without modifying the text. |

### Custom prefix rules

For vendor-specific tokens where you know the prefix and total length but do not need a full regex.

```toml
[[dlp.custom_prefixes]]
name = "vault_token"
prefix = "v1.AA"
length = 32           # Expected total length including prefix
action = "canary"
```

The engine auto-generates a regex: `{escaped_prefix}[A-Za-z0-9]{remaining_length}`.

### Name anonymization

```toml
[[dlp.names]]
term = "Thales"        # Exact term to detect (case-insensitive)
action = "pseudonym"   # pseudonym | redact | log
```

**Actions:**

| Action | Behavior |
|--------|----------|
| `pseudonym` | Replaces with an HMAC-derived pseudonym (e.g. `Cobalt-Falcon-a3f2`). The mapping is reversed on the response path. Set `GROB_DLP_SECRET` env var for stable pseudonyms across restarts. |
| `redact` | Replaces with `[NAME]`. |
| `log` | Logs the detection without modification. |

Pseudonyms are generated from 64 adjectives and 64 nouns (4096 combinations) plus a hex suffix for collision resistance. The forward mapping uses Aho-Corasick for O(n) multi-pattern matching.

### PII detection

```toml
[dlp.pii]
credit_cards = true    # Luhn-validated card numbers (default: true)
iban = true            # ISO 13616 mod-97 validated IBANs (default: true)
bic = false            # BIC/SWIFT codes (default: false, higher false-positive rate)
action = "redact"      # redact | log
```

Redaction labels: `[CARD REDACTED]`, `[IBAN REDACTED]`, `[BIC REDACTED]`.

### Entropy analysis

```toml
[dlp.entropy]
enabled = false        # Default: disabled
action = "log"         # log | alert
```

Uses a Sequential Probability Ratio Test (SPRT) on Shannon entropy. Thresholds:
- Natural English: ~3.5-4.5 bits/byte
- Base64: ~5.5-6.0 bits/byte
- Random: ~7.5-8.0 bits/byte
- Detection threshold: 5.5 bits/byte

Runs asynchronously after stream completion. Never blocks the response path.

### URL exfiltration detection

```toml
[dlp.url_exfil]
enabled = false                     # Default: disabled
action = "log"                      # redact | log | block
scan_markdown_images = true         # ![](url) patterns
scan_markdown_links = true          # [text](url) patterns
scan_raw_urls = true                # Bare http/https URLs
flag_long_query_params = true       # Query strings > max_query_length
flag_base64_in_path = true          # Base64 segments in URL paths
flag_data_uris = true               # data: URI scheme
max_query_length = 200              # Byte threshold for long query flagging
whitelist_domains = []              # Allowed domains (if set, only these pass)
blacklist_domains = []              # Blocked domains
domain_match_mode = "suffix"        # exact | suffix | glob
```

**Domain matching modes:**

| Mode | Behavior | Example |
|------|----------|---------|
| `exact` | Hostname must equal the entry | `github.com` matches only `github.com` |
| `suffix` | Hostname ends with the entry | `github.com` matches `api.github.com` |
| `glob` | Wildcard patterns | `*.github.com` matches `api.github.com` but not `github.com` |

When `whitelist_domains` is non-empty, any domain NOT in the whitelist is flagged. Whitelist takes precedence over blacklist.

### Prompt injection detection

```toml
[dlp.prompt_injection]
enabled = false                     # Default: disabled
action = "log"                      # redact | log | block
no_builtins = false                 # Disable built-in patterns
custom_patterns = []                # User-defined regex patterns
languages = ["all"]                 # Language filter: ["all"] or ["en", "fr", "zh", ...]
```

28 languages supported: English, French, German, Spanish, Italian, Portuguese, Dutch, Polish, Russian, Chinese, Japanese, Korean, Turkish, Arabic, Hindi, Vietnamese, Thai, Indonesian, Malay, Swedish, Norwegian, Danish, Finnish, Czech, Romanian, Hungarian, Greek, Esperanto.

Anti-obfuscation pipeline (applied before pattern matching):
1. Strip invisible Unicode characters (zero-width spaces, joiners, directional marks, BOM)
2. NFKC normalization
3. Homoglyph mapping (Cyrillic, Greek, fullwidth, mathematical variants to Latin)
4. Whitespace collapse
5. Leet speak decoding (aggressive pass, only if standard pass found nothing)

Text normalization is cached with moka (2048 entries, 5-minute TTL).

### Signed config hot-reload

```toml
[dlp.signed_config]
enabled = false
source = "~/.grob/dlp-rules.toml"  # File path or HTTPS URL
poll_interval = "1h"               # Polling interval (e.g. "30m", "6h")
verify_signature = false           # Require ECDSA P-256 signature
public_key_path = ""               # Path to PEM or raw SEC1 public key
detached_sig_suffix = ".sig"       # Suffix for detached signature files
```

Hot-reloadable fields: `url_exfil.whitelist_domains`, `url_exfil.blacklist_domains`, `prompt_injection.custom_patterns`. Changes are SHA-256 checksummed; unchanged content is skipped.

### External rules file

```toml
[dlp]
rules_file = "~/.grob/dlp-rules.toml"
```

External file format (no `[dlp]` wrapper):

```toml
[[secrets]]
name = "custom_token"
prefix = "ctk_"
pattern = "ctk_[A-Za-z0-9]{32}"
action = "redact"

[[names]]
term = "Acme Corp"
action = "pseudonym"
```

### Session isolation

```toml
[dlp]
enable_sessions = true
```

When enabled, each unique API key (or JWT `tenant_id`) gets its own `NameAnonymizer` with different pseudonyms and an independent `CanaryGenerator` counter. API keys are SHA-256 hashed for session identification. Session engines are created lazily and cached.

## Built-in rules

25 rules ship by default (disable with `no_builtins = true`):

| Rule | Prefix | Family |
|------|--------|--------|
| `openai_api_key` | `sk-proj-` | llm |
| `anthropic_api_key` | `sk-ant-api03-` | llm |
| `huggingface_token` | `hf_` | llm |
| `perplexity_api_key` | `pplx-` | llm |
| `gcp_api_key` | `AIza` | generic |
| `vault_token` | `hvs.` | generic |
| `stripe_secret_key` | `sk_` | stripe |
| `stripe_restricted_key` | `rk_live_` | stripe |
| `sendgrid_api_key` | `SG.` | stripe |
| `github_pat_v2` | `github_pat_` | github |
| `github_pat` | `ghp_` | github |
| `github_oauth` | `gho_` | github |
| `github_app` | `ghs_` | github |
| `gitlab_pat` | `glpat-` | gitlab |
| `npm_token` | `npm_` | generic |
| `slack_bot_token` | `xoxb-` | generic |
| `slack_user_token` | `xoxp-` | generic |
| `aws_access_key` | `AKIA` | aws |
| `jwt_token` | `eyJ` | jwt |
| `rsa_private_key` | `-----BEGIN RSA PRIVATE KEY-----` | pem |
| `openssh_private_key` | `-----BEGIN OPENSSH PRIVATE KEY-----` | pem |
| `ec_private_key` | `-----BEGIN EC PRIVATE KEY-----` | pem |
| `generic_private_key` | `-----BEGIN PRIVATE KEY-----` | pem |
| `postgres_uri` | `postgres://` | database |
| `mongodb_uri` | `mongodb://` | database |

All built-in rules use the `redact` action.

## Scanning pipeline

### Request path (input)

1. **Prompt injection detection** (if enabled, `action = block` short-circuits)
2. **Name anonymization** (real names to pseudonyms)
3. **Secret scanning** (DFA prefix gate, then regex)
4. **PII scanning** (credit cards, IBAN, BIC with mathematical validation)

### Response path (output)

1. **Name de-anonymization** (pseudonyms back to real names)
2. **Secret scanning** (catches LLM-generated secrets)
3. **PII scanning** (catches LLM-generated PII)
4. **URL exfiltration scanning** (Markdown images/links, data URIs)

### Streaming path

SSE stream chunks are intercepted by the `DlpStream` adapter:

- **Zero-copy passthrough**: Chunks without `content_block_delta` events are forwarded unchanged (SIMD-accelerated `memchr::memmem` check).
- **Token-length EMA pre-filter**: An exponential moving average of per-delta text lengths skips DFA scanning when tokens are long (normal prose). Short BPE fragments trigger scanning.
- **Canary circuit breaker**: After 20 secret detections in one stream, canary generation switches to `[REDACTED]` to prevent canary flooding.
- **Cross-chunk detection**: The full response is accumulated and scanned at end-of-stream to catch secrets split across SSE deltas.
- **SPRT buffer**: Bounded at 4 KB; accumulated per-stream. The SPRT scanner operates token-by-token (whitespace-split) rather than a raw byte sliding window.
- **URL exfil block**: If a block-action URL exfiltration is detected, the stream is terminated with an `event: error` SSE event.

## Performance

- **Prefix byte filter**: O(n) single-byte lookup rejects text without any known prefix start byte (~90% rejection rate on clean text).
- **Aho-Corasick confirmation**: For short texts (<=512 bytes), a multi-pattern AC automaton confirms a full prefix string exists before running regexes (~99% rejection).
- **Lazy regex compilation**: Pattern syntax is validated at startup via `regex_syntax::parse` (cheap). Full DFA compilation is deferred to the first scan via `OnceLock`.
- **Name matching**: Aho-Corasick automaton for both forward (anonymize) and reverse (de-anonymize) directions.
- **PII pre-filter**: Byte-level scan for digit/uppercase runs before invoking regex.

## Metrics

All metrics use the `grob_dlp_` prefix:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `grob_dlp_rules_loaded` | gauge | `type` | Number of loaded rules by type (`secret`, `name`) |
| `grob_dlp_detections_total` | counter | `type`, `rule`, `action` | Detection events |
| `grob_dlp_cross_chunk_total` | counter | `rule` | Cross-chunk detections at end-of-stream |
| `grob_dlp_stream_blocked_total` | counter | — | Streams terminated by URL exfil block |
| `grob_dlp_circuit_breaker_total` | counter | — | Canary circuit breaker activations |
| `grob_dlp_hot_reload_total` | counter | `status` | Hot-reload outcomes (`success`, `unchanged`, `failed`, `sig_failed`) |
| `grob_dlp_signature_verified_total` | counter | `result` | Signature verification results |
| `grob_dlp_config_hash_info` | gauge | `hash` | Current config hash (first 16 hex chars) |

## Environment variables

| Variable | Purpose |
|----------|---------|
| `GROB_DLP_SECRET` | HMAC key for deterministic pseudonym generation. When unset, a random key is generated per process (pseudonyms differ across restarts). |

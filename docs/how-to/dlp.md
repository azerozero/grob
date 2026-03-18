# How to Configure DLP

## How to enable basic secret scanning

Add to `grob.toml`:

```toml
[dlp]
enabled = true
```

This activates the 25 built-in rules covering GitHub tokens, AWS keys, OpenAI/Anthropic keys, JWTs, PEM private keys, Stripe keys, database URIs, and more. All built-in rules use `redact` action (replaces with `[REDACTED]`).

## How to add custom secret rules

Define rules with a prefix (for fast rejection) and a regex pattern:

```toml
[[dlp.secrets]]
name = "vault_token"
prefix = "hvs."
pattern = "hvs\\.[A-Za-z0-9_-]{24,}"
action = "canary"
```

The `canary` action replaces the secret with a syntactically valid fake containing `~CANARY` and a monotonic ID. If the canary appears downstream, the leak source is identifiable.

For tokens with a known prefix and fixed length (no regex needed):

```toml
[[dlp.custom_prefixes]]
name = "internal_api_key"
prefix = "iak_"
length = 44
action = "redact"
```

## How to manage rules in an external file

Keep rules separate from your main config:

```toml
[dlp]
enabled = true
rules_file = "~/.grob/dlp-rules.toml"
```

The external file uses the same `[[secrets]]`, `[[custom_prefixes]]`, and `[[names]]` arrays without a `[dlp]` wrapper. Rules are merged with inline rules.

## How to anonymize names

```toml
[[dlp.names]]
term = "Acme Corp"
action = "pseudonym"

[[dlp.names]]
term = "Jane Doe"
action = "pseudonym"
```

On the request path, `Acme Corp` becomes a pseudonym like `Cobalt-Falcon-a3f2`. On the response path, the pseudonym is reversed back to `Acme Corp`.

For stable pseudonyms across restarts, set the `GROB_DLP_SECRET` environment variable:

```bash
export GROB_DLP_SECRET="your-stable-secret-key"
```

## How to detect PII in financial data

PII detection is enabled by default when DLP is active. To customize:

```toml
[dlp.pii]
credit_cards = true    # Luhn-validated
iban = true            # ISO 13616 mod-97 validated
bic = true             # BIC/SWIFT codes (more false positives)
action = "redact"
```

Set `action = "log"` to detect without modifying the text.

## How to block prompt injection

```toml
[dlp.prompt_injection]
enabled = true
action = "block"
languages = ["all"]
```

Blocked requests return HTTP 400 with a DLP error. For monitoring before enforcement, use `action = "log"`.

To restrict scanning to specific languages:

```toml
languages = ["en", "fr", "de", "zh"]
```

Add custom patterns to supplement the 28-language built-in set:

```toml
custom_patterns = ["(?i)corporate\\s+override", "(?i)bypass\\s+safety"]
```

## How to prevent URL exfiltration

Protects against attacks where the LLM embeds secrets in outbound URLs (e.g., EchoLeak):

```toml
[dlp.url_exfil]
enabled = true
action = "block"
whitelist_domains = ["cdn.example.com", "docs.rs", "github.com"]
domain_match_mode = "suffix"
```

When `whitelist_domains` is set, any URL with a domain NOT in the list is flagged. For a blacklist approach instead:

```toml
whitelist_domains = []
blacklist_domains = ["evil.com", "exfil.io"]
```

## How to enable session isolation

Different API keys get different pseudonyms and independent canary counters:

```toml
[dlp]
enabled = true
enable_sessions = true
```

Each API key (or JWT `tenant_id`) gets its own DLP engine with unique name mappings. Session engines are created lazily and cached.

## How to hot-reload domain lists

Update domain lists and injection patterns without restarting:

```toml
[dlp.signed_config]
enabled = true
source = "~/.grob/dlp-hot.toml"
poll_interval = "30m"
```

The hot-reload file format:

```toml
[url_exfil]
whitelist_domains = ["cdn.example.com"]
blacklist_domains = ["new-threat.com"]

[prompt_injection]
custom_patterns = ["(?i)new\\s+attack\\s+pattern"]
```

For cryptographic verification of updates:

```toml
[dlp.signed_config]
verify_signature = true
public_key_path = "~/.grob/dlp-signing-key.pub"
```

## How to enable all DLP protections

```toml
[dlp]
enabled = true
scan_input = true
scan_output = true

[dlp.prompt_injection]
enabled = true
action = "block"

[dlp.url_exfil]
enabled = true
action = "block"
whitelist_domains = ["cdn.example.com"]

[dlp.pii]
credit_cards = true
iban = true
action = "redact"

[dlp.entropy]
enabled = true
action = "log"
```

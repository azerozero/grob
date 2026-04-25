# Manage upstream provider secrets

Store API keys for upstream providers (MiniMax, Mercury, OpenRouter,
DeepInfra, Groq, Z.ai, Gemini, ...) **encrypted at rest** with the same
AES-256-GCM master key as OAuth tokens. The cleartext value never lives
in your `config.toml`, your shell history, or your dotfiles.

## When to use this vs alternatives

| Storage | Sensitivity | Reload-friendly | Backup-friendly |
|---------|-------------|------------------|------------------|
| `api_key = "secret:<name>"` (this guide) | ✅ encrypted at rest | yes — read on startup | yes — encrypted blob in `~/.grob/secrets/` |
| `api_key = "$ENV_VAR"` | 🟡 visible to any process via `/proc/<pid>/environ`, shell history, dotfiles | yes (re-export + restart) | depends on env management |
| `api_key = "sk-..."` plain string | ❌ cleartext on disk, in backups, in version control if `.grob/config.toml` is checked in | yes | dangerous |
| OAuth via `grob connect` | ✅ encrypted at rest | yes | yes — refresh token blob |

OAuth (Anthropic Max, Gemini Pro) remains the preferred path when the
provider supports it. Use `grob secrets` for everything else.

## Where the data lives

- Master key: `~/.grob/encryption.key` (32 random bytes, chmod 600)
- Encrypted secrets: `~/.grob/secrets/<name>.enc`

The master key is generated automatically the first time `grob` opens
its storage. Back it up — losing the file means every encrypted blob
(OAuth tokens, virtual keys, secrets) becomes unreadable.

## Add a secret

```sh
grob secrets add minimax
# Enter value for 'minimax' (one line, will be encrypted): <paste>
```

To keep the value out of your shell history, pipe instead:

```sh
printf '%s' "$YOUR_KEY" | grob secrets add minimax
```

The trailing newline is stripped. Empty values are rejected.

## Reference the secret in your provider config

Use `secret:<name>` as the `api_key` value:

```toml
[[providers]]
name = "minimax"
provider_type = "openai"
base_url = "https://api.minimax.chat/v1"
api_key = "secret:minimax"
models = ["MiniMax-M2.5"]
```

On startup, grob resolves the placeholder by looking up `minimax` in the
encrypted store and substitutes the cleartext into the in-memory provider
config. The TOML on disk stays clean.

A log line confirms the resolution:

```
🔐 Resolved api_key for provider 'minimax' from grob secret 'minimax'
```

If the secret is missing the provider falls back to the unresolved
placeholder (and the registry warns).

## List

```sh
grob secrets list
# Secrets (3 total):
#   • groq
#   • minimax
#   • openrouter

grob secrets list --json
```

`list` prints names only — never values.

## Show

Default is redacted (`first 4 + last 4` chars):

```sh
grob secrets show minimax
# sk-a...XJ7Q
# (redacted; pass --unsafe-show to reveal)
```

To reveal the full value (keep it on a private terminal only):

```sh
grob secrets show minimax --unsafe-show
```

## Remove

```sh
grob secrets rm minimax
# Remove secret 'minimax'? [y/N] y
# ✅ Removed 'minimax'

grob secrets rm minimax --force        # skip prompt
```

## Migrate from env vars

Replace each `api_key = "$X_API_KEY"` line with `api_key = "secret:x"`,
then move the value:

```sh
printf '%s' "$MINIMAX_API_KEY"  | grob secrets add minimax
printf '%s' "$DEEPINFRA_API_KEY" | grob secrets add deepinfra
printf '%s' "$MERCURY_API_KEY"   | grob secrets add mercury
printf '%s' "$GLM_API_KEY"       | grob secrets add glm
printf '%s' "$GROQ_API_KEY"      | grob secrets add groq
printf '%s' "$OPENROUTER_API_KEY" | grob secrets add openrouter
printf '%s' "$GEMINI_API_KEY"    | grob secrets add gemini

# Then unset the env vars and remove them from your shell rc.
```

Restart `grob` and confirm the resolution lines in the logs.

## What is **not** here yet (tracked)

- **Master key backup/restore CLI**: `grob secrets export-key --to <file> --password <prompt>` and `import-key`. Today the master key is a raw file — back it up manually.
- **Pluggable backend** (Vault, Kubernetes Secret, AWS Secrets Manager). Coming via the `SecretBackend` trait — see [PR #276](https://github.com/azerozero/grob/pull/276) (Vault Agent strategy will work via a `File` backend reading from a mounted directory).

## Trade-offs

- The encrypted store is **single-user, single-host**. If you need
  multi-host or multi-user, prefer a real secret manager (Vault,
  cloud KMS) and surface it via the upcoming File backend.
- A compromised local user account can read both the master key
  (chmod 600) and the encrypted blobs. The store protects against
  *backups* and *casual disk inspection*, not against an attacker who
  already has your shell.

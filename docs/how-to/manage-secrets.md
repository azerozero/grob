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

## Choose a backend (`[secrets]`)

Three backends ship today, selected via the top-level `[secrets]` section:

```toml
[secrets]
backend = "local_encrypted"   # default — ~/.grob/secrets/<name>.enc (AES-GCM)
# backend = "env"             # std::env::var(NAME) — for 12-factor apps
# backend = "file"            # cleartext file at <path>/<name> — Vault/K8s mount

[secrets.file]
path = "/etc/grob/secrets"     # only read when backend = "file"
```

Whatever the backend, the placeholder syntax in `[[providers]]` stays the
same: `api_key = "secret:<name>"`. Only the resolution layer changes.

### `env` backend

`secret:minimax-api-key` resolves to `std::env::var("MINIMAX_API_KEY")`.
The lookup name is uppercased and dashes become underscores. Nothing is
encrypted at rest — use this only when the env is itself secured (CI
vault, systemd `LoadCredential=`, container runtime injection).

### `file` backend (Vault Agent / Kubernetes Secret)

`secret:minimax` reads the cleartext value from `<path>/minimax`.
Path-traversal names (`../`, `/`, leading dot) are rejected. A trailing
`\n` is stripped (common when written by `echo` or Vault).

#### Vault Agent on Kubernetes (recommended pattern)

Annotate the pod so Vault Agent renders templates into a shared volume:

```yaml
metadata:
  annotations:
    vault.hashicorp.com/agent-inject: "true"
    vault.hashicorp.com/agent-inject-secret-minimax: "secret/data/grob/minimax"
    vault.hashicorp.com/agent-inject-template-minimax: |
      {{- with secret "secret/data/grob/minimax" -}}
      {{ .Data.data.value }}
      {{- end -}}
    vault.hashicorp.com/agent-inject-secret-groq:    "secret/data/grob/groq"
    vault.hashicorp.com/role: "grob"
```

Configure grob to read from the injected directory:

```toml
[secrets]
backend = "file"
[secrets.file]
path = "/vault/secrets"
```

Vault Agent handles lease renewal, reload notifications, and rotation —
grob never sees the Vault address, token, or AppRole. To pick up rotated
secrets without restart, configure Vault Agent's `template.exec` to send
SIGHUP (or wire a sidecar that re-issues `grob restart`).

#### Kubernetes Secret directly

Mount a Secret as a volume and point the file backend at it:

```yaml
volumeMounts:
  - name: grob-secrets
    mountPath: /etc/grob/secrets
    readOnly: true
volumes:
  - name: grob-secrets
    secret:
      secretName: grob-provider-keys
      items:
        - { key: minimax,    path: minimax }
        - { key: groq,       path: groq }
        - { key: openrouter, path: openrouter }
```

```toml
[secrets]
backend = "file"
[secrets.file]
path = "/etc/grob/secrets"
```

Trade-off: rotating the Kubernetes Secret needs a pod restart (or `kubectl
rollout restart`). Use the Vault Agent path above for live rotation.

## What is **not** here yet (tracked)

- **Master key backup/restore CLI**: `grob secrets export-key --to <file> --password <prompt>` and `import-key`. Today the master key is a raw file — back it up manually.
- **Native Vault backend** (direct API calls, dynamic refresh without restart). The File backend covers 95 % of cases via Vault Agent — open an issue if you need the native path.

## Trade-offs

- The encrypted store is **single-user, single-host**. If you need
  multi-host or multi-user, prefer a real secret manager (Vault,
  cloud KMS) and surface it via the upcoming File backend.
- A compromised local user account can read both the master key
  (chmod 600) and the encrypted blobs. The store protects against
  *backups* and *casual disk inspection*, not against an attacker who
  already has your shell.

# Manage upstream provider secrets

Store API keys for upstream providers (MiniMax, Mercury, OpenRouter,
DeepInfra, Groq, Z.ai, Gemini, ...) **encrypted at rest** with the same
AES-256-GCM master key as OAuth tokens. The cleartext value never lives
in your `config.toml`, your shell history, or your dotfiles.

## When to use this vs alternatives

| Storage | Sensitivity | Reload-friendly | Backup-friendly |
|---------|-------------|------------------|------------------|
| `api_key = "secret:<name>"` (this guide) | ✅ encrypted at rest | yes — read on each request | yes — encrypted blob in `~/.grob/secrets/` |
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

Grob verifies the reference at startup and retains its name in the provider
configuration. It decrypts the current value immediately before each upstream
request. A missing primary secret disables the provider at startup. Deleting or
corrupting a secret while running causes authentication resolution to fail; the
literal `secret:` placeholder and old plaintext are never used as fallbacks.

## Replace credentials without changing the agent

Give each agent a Grob virtual key. Keep the administrative credential separate:

```toml
[auth]
mode = "api_key"
api_key = "secret:grob-admin"
adopt_from_system = false  # keep explicitly supplied OAuth credentials authoritative
```

```sh
grob secrets add grob-admin
grob key create --name coding-agent --allowed-providers minimax
```

Configure the agent once with the emitted `grob_...` key and the Grob endpoint.
Grob authenticates that key, applies its restrictions, then supplies the upstream
provider credential. It does not forward the agent's Authorization header.
The administrative credential permits configuration, OAuth and key management;
virtual keys and tenant JWTs do not. An explicit `auth.api_key` can also serve as
the administrative credential when `auth.mode = "jwt"`.

To replace the upstream credential, write a new value under the same name:

```sh
printf '%s' "$NEW_MINIMAX_KEY" | grob secrets add minimax
```

The next upstream dispatch reads the replacement. No agent update, config reload
or daemon restart is needed. An already dispatched request continues with its
captured credential; a streaming response is not interrupted. Replacing
`grob-admin` similarly changes administrative access without changing agent keys.

Named references also work in `providers.pool.keys` and custom header values:

```toml
[[providers]]
name = "gateway"
provider_type = "openai"
base_url = "https://gateway.example.com/v1"
api_key = "secret:gateway-primary"
models = ["default"]
headers = { X-Gateway-Key = "secret:gateway-header" }
[providers.pool]
keys = ["secret:gateway-secondary"]
```

An OAuth token saved through `grob connect` is visible to the running daemon on
its next read. A late refresh result cannot overwrite a newer stored credential
or recreate a deleted token. Virtual-key rotation preserves expiration, tenant,
budget, rate limit, model and provider restrictions. CLI key operations use the
same encrypted store whether the daemon is running or stopped; select the same
`GROB_HOME` for both processes.

Encrypted-store OAuth refreshes take a per-provider kernel file lock shared by
all Grob processes. Waiting is limited to 30 seconds; the issuer request has a
20-second deadline. Lock files remain in place and must not be deleted while
Grob is running. Explicit credential replacement and deletion do not wait for
the issuer request and remain authoritative over a late response.

A durable refresh intent is written before contacting the issuer. If a process
dies, is cancelled, or receives an ambiguous failure after the issuer may have
rotated its token, Grob refuses to reuse that uncertain refresh token. Authenticate again
with `grob connect --force-reauth`, or supply a new credential through the administrative OAuth
flow. Do not delete the `.refresh.pending` file to force a retry. Supplying a new
refresh token supersedes the old intent; editing expiration or reauthentication
metadata does not. Legacy JSON stores only coordinate within one process; use
the encrypted store when sharing credentials between processes.

## Memory and disk protection

Authenticated upstream requests require HTTPS outside loopback. Provider clients
do not follow redirects, so a remote endpoint cannot redirect an API key or
custom credential header to another server. Authentication header values are
marked sensitive to keep them out of HTTP request debug formatting.

The local backend uses the existing AES-256-GCM implementation, fresh nonces,
authenticated ciphertext and atomic file replacement. Temporary files are private
before data is written, synchronized before rename, and the parent directory is
synchronized on Unix. Concurrent first starts cannot overwrite the master key.

Named provider credentials and stored OAuth tokens are not held in a persistent
plaintext cache. Decrypted serialization buffers and transient token strings use
zeroizing containers. AES-GCM also enables its `zeroize` feature so AES and GHASH
state is erased when the cipher is dropped. Literal credentials in TOML and
environment variables do not gain these properties: migrate them to named encrypted secrets and remove
old copies from configuration backups and shell setup after verifying the change.

Use [process memory hardening](harden-memory.md) to disable dumps and, on Linux,
optionally lock process memory against swap. These controls are opt-in and fail
startup if a requested protection cannot be enabled. They do not encrypt RAM.

An in-process RAM-encryption library would still need a decryption key in the
same process. This implementation minimizes plaintext lifetime; it does not
promise protection against a compromised process, root access, or every
copy made by HTTP/TLS libraries. Filesystem snapshots, SSD wear levelling and old
backups also prevent a guarantee of physical erasure. Replace or revoke the old
credential with its issuer when retiring it.

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

Reload the provider configuration after changing references. Subsequent value replacements need no reload.

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

### Operate without Vault

The local encrypted backend is the default and requires no Vault service:

```toml
[secrets]
backend = "local_encrypted"
```

Provision the named credentials with `grob secrets add <name>` and keep the
provider's `api_key = "secret:<name>"` reference. The agent retains its virtual
Grob key. Replacing the local value takes effect on the next upstream dispatch;
the running daemon and agent do not need to restart. Provision all references
before deliberately changing the backend of an existing deployment.

This is supported standalone operation for the current LLM-provider path.
Automatic Vault-to-local recovery and general HTTP credential routing are planned
in [ADR-0031](../decisions/0031-optional-vault-credential-routing.md). That design
requires equal routing, injection and rotation functions with local storage, plus
opt-in bounded recovery for Vault outages. It does not make expired, revoked or
unreadable secrets usable, and an offline copy cannot detect a new remote
revocation until communication resumes. The current file backend has no lease or
freshness enforcement; do not treat a stale Vault Agent file as validated recovery.

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

Vault Agent handles lease renewal and replaces the mounted files. Grob reads the
current file on each request; no signal or restart is required. Publish file
updates atomically so a request cannot observe a partially written credential.

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

Grob picks up replacement values once Kubernetes updates the mounted files.
A `subPath` mount does not receive Secret updates; use the directory mount shown
above. Environment-based injection still requires restarting the process.

## What is **not** here yet (tracked)

- **Master key backup/restore CLI**: `grob secrets export-key --to <file> --password <prompt>` and `import-key`. Today the master key is a raw file — back it up manually.
- **Native Vault backend and bounded offline recovery**: planned in [ADR-0031](../decisions/0031-optional-vault-credential-routing.md). File injection via Vault Agent is available today; it does not implement that recovery policy.

## Trade-offs

- The encrypted store is **single-user, single-host**. If you need
  multi-host or multi-user, prefer a real secret manager (Vault,
  cloud KMS) and surface it via the File backend.
- A compromised local user account can read both the master key
  (chmod 600) and the encrypted blobs. Keep the master key separate from ciphertext backups; a backup containing both
  can be decrypted. Encryption does not protect against an attacker who already
  has access to this account.

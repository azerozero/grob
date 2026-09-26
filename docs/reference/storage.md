# Storage Reference

Complete reference for Grob's persistent storage layer: atomic files, append-only JSONL journals, and AES-256-GCM encryption at rest.

## Overview

Grob uses file-based storage with atomic writes and append-only journals (see [ADR-0013](../decisions/0013-storage-files-no-redb.md)). Spend journals are readable JSONL; credential files contain authenticated ciphertext. Atomic replacement protects credential publication, while spend uses batched durability. See [crash-test boundaries](../how-to/harden-memory.md#reproduce-the-checks).

**Default path**: `~/.grob/`

## Directory layout

```
~/.grob/
├── spend/
│   ├── 2026-04.jsonl            # current month, append-only
│   └── 2026-03.jsonl.sealed     # prior month, sealed
├── tokens/
│   ├── anthropic.json.enc       # AES-256-GCM encrypted OAuth token
│   └── openai.json.enc
├── vkeys/
│   └── <sha256_hex>.json.enc    # encrypted virtual key (by hash)
├── secrets/
│   └── <name>.enc              # named provider secret
├── credentials/
│   └── <scope_hash>.enc        # service bundle and validity metadata
├── encryption.check           # authenticated association with the storage key
└── encryption.key             # local key, absent with external-only custody
```

## Spend journal

Spend data is stored as an append-only JSONL journal, one file per month.

### Journal line format

Each event is a self-contained JSON object on its own line:

```json
{"ts":"2026-04-09T14:22:31Z","kind":"spend","provider":"anthropic","model":"claude-opus-4-6","cost_usd":0.023}
```

Tenant-scoped events include a `"tenant"` field:

```json
{"ts":"2026-04-09T14:22:31Z","kind":"spend","provider":"anthropic","model":"claude-opus-4-6","cost_usd":0.023,"tenant":"org-456"}
```

### Invariants

- **Append-only**: writes use `O_APPEND`, `fsync` on flush. No seek, no rewrite.
- **One event per line**: newline-delimited JSON. Parsing is `split('\n')`.
- **Rollover at month boundary**: current file is sealed (renamed to `.jsonl.sealed`) when the month changes.

### Startup replay

On startup, the current month's journal is replayed into an in-memory `SpendData` cache. Global events (no `"tenant"` field) populate the cache; tenant events are replayed on demand.

**Auto-reset**: When a new month is detected, spend data resets to zero.

**Batched fsync**: Spend data is cached in memory and fsynced to the journal every 10 `record_spend` calls. Call `flush_spend()` during graceful shutdown.

## OAuth tokens

One encrypted file per provider: `tokens/<provider_id>.json.enc`.

Decrypted payload (JSON):

```json
{
  "provider_id": "claude-max",
  "access_token": "sk-ant-...",
  "refresh_token": "rt-...",
  "expires_at": "2026-03-18T13:00:00Z",
  "enterprise_url": null,
  "project_id": null
}
```

The `enterprise_url` field is used by GitHub Copilot Enterprise. The `project_id` field stores the Google Cloud project ID for Gemini Code Assist.

**Atomic writes**: token files are written via `write(tmp) → fsync(tmp) → rename(tmp, final)`. On Unix, the parent directory is also synced after publication. Validate the target filesystem and storage stack; process-kill tests alone do not prove physical power-loss behavior.

## Virtual keys

One hash-keyed file is authoritative for authentication and administration:
`vkeys/<sha256_hex>.json.enc`. Legacy `id_<uuid>.json.enc` index files are ignored.
Rotation and revocation use the shared credential lock. See
[Authentication Reference](authentication.md) for record fields.

## Service credential records

`credentials/<scope_hash>.enc` holds one encrypted bundle and its tenant, service,
binding revision, generation, authority, expiry and revocation state. The hash
covers the exact tenant/service tuple; records are checked against both values
on read. Publication uses generation fencing to reject stale refreshes.

Record format 2 separates administrative expiry from the current Vault version's
expiry. Format 1 remains readable with its old deadline preserved conservatively.
See the [upgrade procedure](../how-to/route-service-credentials.md#upgrade-records-with-an-old-combined-expiry)
before republishing affected Vault bindings. The record format is independent of
the outer encryption-envelope version.

## Encryption at rest

OAuth tokens, virtual keys, named secrets and service records are encrypted with AES-256-GCM before storage. Spend journals are stored as plaintext JSON (they contain no secrets).

### Key management

A fresh local store generates a random 32-byte key using the OS CSPRNG and
publishes it without overwriting another process's key. Alternatively,
`GROB_ENCRYPTION_KEY_FILE` selects an external protected 32-byte file outside the
store. A local copy, if present, must agree with it. Existing encrypted data or
`encryption.check` prevents silent replacement of a missing key. Missing, wrong,
corrupt or conflicting key material fails initialization.

Keep `encryption.check` with the data and protect backups of the key separately.
See [key custody, migration and recovery](../how-to/protect-credential-storage.md)
for the operational procedure. Changing the bytes is not supported key rotation;
a data-key rotation needs coordinated re-encryption and recovery testing.

### Encryption format

Encrypted values are stored as:

```
[ASCII GRB1][version byte 1][12-byte nonce][ciphertext + 16-byte GCM tag]
```

- **Nonce**: 96-bit random nonce generated per encryption operation using `OsRng`.
- **Ciphertext**: AES-256-GCM authenticated encryption of the plaintext JSON.
- **Tag**: 128-bit GCM authentication tag (appended by the AEAD implementation).

### Transparent migration from unencrypted data

For OAuth tokens, named provider secrets and virtual keys,
`decrypt_or_plaintext()` first authenticates the current envelope. A damaged,
truncated or unknown-version envelope is rejected, never treated as plaintext.
Pre-envelope ciphertext is also read when authentication succeeds. Only bytes
without an envelope that cannot be decrypted take the legacy plaintext path,
with a warning; callers still parse JSON records or UTF-8 named secrets. A subsequent write uses
the current encrypted envelope.

Service credential records accept authenticated encryption only and never use
that plaintext fallback. Do not manually rewrite encrypted files or remove the
key/check to work around corruption. Restore a consistent tested backup instead.

## Legacy redb detection

If a `grob.db` file (from the former redb backend) exists in `~/.grob/`, a warning is logged at startup. No automatic migration is performed (see ADR-0013). Spend and token data in the old `grob.db` will not be read.

## File permissions

All sensitive files created by the storage layer have restricted permissions:

| File | Unix | Windows |
|------|------|---------|
| `encryption.key` | `0600` | Owner-only DACL (`GENERIC_ALL` for current user, no inherited ACEs) |
| Atomically written token, virtual-key, secret and service records | `0600` | Owner-only DACL |
| `encryption.check` | `0600` | Owner-only DACL |
| Audit signing keys | `0600` | Same |

## Configuration

No TOML configuration is needed for the storage layer. The storage directory is `~/.grob/` by default and is determined internally. The local key is derived from that directory unless `GROB_ENCRYPTION_KEY_FILE` selects an external key.

For custom storage placement (e.g., in containers), set `GROB_HOME` to the desired base directory. The container examples use `GROB_HOME=/var/lib/grob`.

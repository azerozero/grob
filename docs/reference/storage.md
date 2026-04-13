# Storage Reference

Complete reference for Grob's persistent storage layer: atomic files, append-only JSONL journals, and AES-256-GCM encryption at rest.

## Overview

Grob uses file-based storage with atomic writes and append-only journals (see [ADR-0013](../decisions/0013-storage-files-no-redb.md)). All state is human-readable (JSONL or encrypted JSON files), crash-safe, and inspectable with standard tools (`less`, `grep`, `jq`).

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
│   ├── <sha256_hex>.json.enc    # encrypted virtual key (by hash)
│   └── id_<uuid>.json.enc       # encrypted virtual key (by UUID)
└── encryption.key               # 256-bit AES key (32 bytes, binary)
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

**Atomic writes**: token files are written via `write(tmp) → fsync(tmp) → rename(tmp, final)`. `rename(2)` is atomic on ext4/xfs/btrfs.

## Virtual keys

Two encrypted files per key:

| File pattern | Purpose |
|-------------|---------|
| `vkeys/<sha256_hex>.json.enc` | Primary lookup during authentication |
| `vkeys/id_<uuid>.json.enc` | Management operations (list, revoke, delete) |

Values: AES-256-GCM encrypted JSON of `VirtualKeyRecord`. See [Authentication Reference](authentication.md) for the full field list.

The `list_virtual_keys()` method scans the `vkeys/` directory and skips `id_` prefixed files to avoid returning duplicates.

## Encryption at rest

All OAuth tokens and virtual key records are encrypted with AES-256-GCM before storage. Spend journals are stored as plaintext JSON (they contain no secrets).

### Key management

**Key generation**: On first storage open, a random 256-bit key is generated using the OS CSPRNG (`OsRng`) and written to `encryption.key`. The key file is set to owner-only permissions (`0600` on Unix, restricted DACL on Windows).

**Key loading**: On subsequent opens, the key is loaded from `encryption.key`. If the file exists but is not exactly 32 bytes, initialization fails with an error.

**Key path**: Always `<base_dir>/encryption.key`.

### Encryption format

Encrypted values are stored as:

```
[12-byte nonce][ciphertext + 16-byte GCM tag]
```

- **Nonce**: 96-bit random nonce generated per encryption operation using `OsRng`.
- **Ciphertext**: AES-256-GCM authenticated encryption of the plaintext JSON.
- **Tag**: 128-bit GCM authentication tag (appended by the AEAD implementation).

### Transparent migration from unencrypted data

The `decrypt_or_plaintext()` method handles the transition from unencrypted to encrypted storage. If decryption fails (e.g., the data is legacy unencrypted JSON), the raw bytes are returned as-is. On the next write, the data is re-encrypted.

### Edge cases

- **Key rotation**: Not currently supported. Changing `encryption.key` invalidates all encrypted data.
- **Tampered ciphertext**: AES-GCM authentication fails, returning an error. The `decrypt_or_plaintext` fallback treats corrupted data as potential legacy plaintext.
- **Missing key file**: A new key is generated, but existing encrypted data becomes unreadable.

## Legacy redb detection

If a `grob.db` file (from the former redb backend) exists in `~/.grob/`, a warning is logged at startup. No automatic migration is performed (see ADR-0013). Spend and token data in the old `grob.db` will not be read.

## File permissions

All sensitive files created by the storage layer have restricted permissions:

| File | Unix | Windows |
|------|------|---------|
| `encryption.key` | `0600` | Owner-only DACL (`GENERIC_ALL` for current user, no inherited ACEs) |
| `tokens/*.json.enc` | inherited | inherited |
| `vkeys/*.json.enc` | inherited | inherited |
| Audit signing keys | `0600` | Same |

## Configuration

No TOML configuration is needed for the storage layer. The storage directory is `~/.grob/` by default and is determined internally. The encryption key path is always derived from the base directory.

For custom storage placement (e.g., in containers), the path is resolved from the `--data-dir` CLI flag or the `GROB_DATA_DIR` environment variable when available.

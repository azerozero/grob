# Storage Reference

Complete reference for Grob's persistent storage layer: the redb database, AES-256-GCM encryption at rest, and migration from legacy JSON files.

## Overview

Grob uses [redb](https://github.com/cberner/redb), an embedded ACID key-value store, as its single persistent storage backend. The database file replaces the legacy `spend.json` and `oauth_tokens.json` files with a unified, encrypted, crash-safe store.

**Default path**: `~/.grob/grob.db`

## Database tables

| Table name | Key type | Value type | Purpose |
|------------|----------|------------|---------|
| `spend` | `&str` | `&[u8]` (JSON) | Monthly spend tracking (global + per-tenant) |
| `oauth_tokens` | `&str` | `&[u8]` (encrypted JSON) | OAuth access/refresh tokens |
| `virtual_keys` | `&str` | `&[u8]` (encrypted JSON) | Virtual API key records |
| `meta` | `&str` | `&str` | Migration state, schema version |

### spend table

Keys:
- `"global"` -- aggregate spend across all tenants.
- `"tenant:<id>"` -- per-tenant spend (e.g., `"tenant:org-456"`).

Value: JSON-serialized `SpendData`:

```json
{
  "month": "2026-03",
  "total": 42.50,
  "by_provider": { "anthropic": 30.00, "openai": 12.50 },
  "by_model": { "claude-sonnet": 30.00, "gpt-4o": 12.50 },
  "by_provider_count": { "anthropic": 15, "openai": 8 }
}
```

**Auto-reset**: When a new month is detected (comparing `data.month` to the current `YYYY-MM`), the spend data resets to zero.

**Batched writes**: Spend data is cached in memory and flushed to disk every 10 `record_spend` calls. Call `flush_spend()` during graceful shutdown to avoid losing the last few records.

### oauth_tokens table

Keys: provider ID string (e.g., `"claude-max"`, `"openai-codex"`).

Values: AES-256-GCM encrypted JSON of `OAuthToken`:

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

### virtual_keys table

Two index entries per key:

| Key pattern | Purpose |
|-------------|---------|
| `<sha256_hex>` | Primary lookup during authentication (hash of the full `grob_...` key) |
| `id:<uuid>` | Secondary index for management operations (list, revoke, delete) |

Values: AES-256-GCM encrypted JSON of `VirtualKeyRecord`. See [Authentication Reference](authentication.md) for the full field list.

The `list_virtual_keys()` method filters out `id:` entries to avoid returning duplicates.

### meta table

| Key | Value | Description |
|-----|-------|-------------|
| `migrated_from_json` | `"true"` | Set after JSON migration completes |
| `schema_version` | `"1"` | Current database schema version |

## Encryption at rest

All OAuth tokens and virtual key records are encrypted with AES-256-GCM before storage. Spend data is stored as plaintext JSON (it contains no secrets).

### Key management

```
~/.grob/
  grob.db           # redb database
  encryption.key    # 256-bit AES key (32 bytes, binary)
```

**Key generation**: On first database open, a random 256-bit key is generated using the OS CSPRNG (`OsRng`) and written to `encryption.key`. The key file is set to owner-only permissions (`0600` on Unix, restricted DACL on Windows).

**Key loading**: On subsequent opens, the key is loaded from `encryption.key`. If the file exists but is not exactly 32 bytes, initialization fails with an error.

**Key path**: Always `<db_parent_dir>/encryption.key` (sibling of the database file).

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

- **Key rotation**: Not currently supported. Changing `encryption.key` invalidates all encrypted data in the database.
- **Tampered ciphertext**: AES-GCM authentication fails, returning an error. The `decrypt_or_plaintext` fallback treats corrupted data as potential legacy plaintext (a warning should be logged if it does not parse as valid JSON).
- **Missing key file**: A new key is generated, but existing encrypted data becomes unreadable.

## Migration from JSON

On first database open, Grob checks for legacy JSON files and migrates them automatically.

### Migration sources

| Legacy file | Target table | Key |
|-------------|-------------|-----|
| `~/.grob/spend.json` | `spend` | `"global"` |
| `~/.grob/oauth_tokens.json` | `oauth_tokens` | one entry per provider ID |

### Migration behavior

1. Check `meta.migrated_from_json`. If `"true"`, skip migration.
2. If `spend.json` exists, parse it and insert into the `spend` table under key `"global"`.
3. If `oauth_tokens.json` exists, parse the `HashMap<String, OAuthToken>` and insert each token into the `oauth_tokens` table. (Note: tokens migrated from JSON are stored as plaintext initially; they are re-encrypted on next write.)
4. Set `meta.migrated_from_json = "true"` and `meta.schema_version = "1"`.
5. Delete the legacy JSON files after successful migration.

### Edge cases

- **Parse failure**: If a legacy file exists but cannot be parsed, a warning is logged and migration continues. The `migrated_from_json` flag is still set to prevent repeated attempts.
- **Partial migration**: If `spend.json` exists but `oauth_tokens.json` does not (or vice versa), only the existing file is migrated.
- **Idempotent**: Running migration again after completion is a no-op (guarded by the meta flag).
- **No legacy files**: If neither JSON file exists, the meta flag is set immediately with no data changes.

## File permissions

All sensitive files created by the storage layer have restricted permissions:

| File | Unix | Windows |
|------|------|---------|
| `grob.db` | `0600` | Owner-only DACL (`GENERIC_ALL` for current user, no inherited ACEs) |
| `encryption.key` | `0600` | Same |
| `oauth_tokens.json` (legacy) | `0600` | Same |
| Audit signing keys | `0600` | Same |

## Configuration

No TOML configuration is needed for the storage layer. The database path is `~/.grob/grob.db` by default and is determined internally. The encryption key path is always derived from the database path.

For custom database placement (e.g., in containers), the path is resolved from the `--data-dir` CLI flag or the `GROB_DATA_DIR` environment variable when available.

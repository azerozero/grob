# storage

> Atomic file writes, append-only JSONL journals, AES-256-GCM at rest.

## Purpose

Persistence layer for grob: append-only spend journals, encrypted OAuth tokens,
encrypted virtual key records, and pluggable secret backends. Replaces the
former `redb` backend with crash-safe primitives (per ADR-0013): journals use
`O_APPEND`, other files use atomic write-fsync-rename.

## Public API

| Item | Location | Used by |
|------|----------|---------|
| `GrobStore` | `mod.rs` | `server::AppState`, every credential consumer |
| `GrobStore::open`, `default_path` | `mod.rs` | `server::init`, `commands::*` |
| `GrobStore::{save,get,delete,list}_oauth_token(s)` | `mod.rs` | `auth::TokenStore` |
| `GrobStore::{store,lookup,list,revoke,delete}_virtual_key` | `mod.rs` | auth middleware, `commands::vkey` |
| `GrobStore::{set,get,list,remove}_secret` | `mod.rs` | provider api-key resolution |
| `secrets::SecretBackend` (trait) | `secrets.rs` | provider auth, config loader |
| `secrets::{LocalEncryptedBackend, EnvBackend, FileBackend}` | `secrets.rs` | `secrets::build_backend` |
| `secrets::build_backend` | `secrets.rs` | `server::init` |
| `migrate::warn_legacy_redb` | `migrate.rs` | `GrobStore::open` |

## Owns

- `~/.grob/` directory layout: `spend/YYYY-MM.jsonl`, `tokens/<id>.json.enc`, `vkeys/<hash>.json.enc`, `secrets/<name>.enc`.
- Atomic write helper (write → fsync → rename) in `atomic.rs`.
- AES-256-GCM cipher with `decrypt_or_plaintext` migration path in `encrypt.rs`.
- Append-only spend journal with monthly rotation and tenant-scoped replay (`journal.rs`).
- Pluggable `SecretBackend` trait with three built-in implementations.

## Depends on

- `auth::token_store::OAuthToken` and `auth::virtual_keys::VirtualKeyRecord` (data shapes).
- `features::token_pricing::spend::SpendData` (in-memory spend cache).
- `aes-gcm`, `secrecy::SecretString`, `chrono`, `uuid`, `serde_json`.

## Non-goals

- Cost calculation or budget enforcement (delegated to `features::token_pricing`).
- OAuth flow logic (delegated to `auth::oauth`).
- A general key/value database — this slice is purpose-built for grob's three persistence shapes.

## Tests

- `#[cfg(test)] mod tests` inside `mod.rs` covers spend cycle, OAuth CRUD, per-tenant spend, persistence across reopen, virtual key store/lookup/revoke/delete, secret roundtrip / list / remove / overwrite, and filename sanitization.
- `#[cfg(test)] mod tests` inside `secrets.rs`, `journal.rs`, `encrypt.rs`, `atomic.rs` cover their internal invariants.

## Related ADRs

- [ADR-0004](../../docs/decisions/0004-persistent-spend-tracking.md) — append-only journal design and replay semantics.
- [ADR-0013](../../docs/decisions/0013-storage-files-no-redb.md) — chose atomic files over `redb`; no migration path.

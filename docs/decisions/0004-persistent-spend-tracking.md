# ADR-0004: Persistent spend tracking in redb (GrobStore)

## Status

Accepted

## Context and Problem Statement

Grob needs to enforce monthly budget limits across server restarts. Where and how should spend data be persisted?

## Decision Drivers

- No external database dependency (grob is a local proxy)
- Must survive server restarts
- Monthly reset semantics
- Must coexist with OAuth tokens and virtual keys (avoid N separate files)

## Considered Options

- SQLite database
- JSON file in `~/.grob/spend.json`
- In-memory only (reset on restart)
- Embedded redb database (chosen)

## Decision Outcome

Chosen option: "Embedded redb database at `~/.grob/grob.db`", because it provides ACID transactions, colocates all persistent state (spend, OAuth, virtual keys) in a single file, and supports the single-user local proxy use case. A hot-path in-memory cache avoids redb read transactions on every request.

### Design

`GrobStore` (`src/storage/mod.rs`) is the single redb-backed store:

| redb table | Content |
|------------|---------|
| `SPEND_TABLE` | `SpendData` rows keyed by tenant ID (JSON-serialized) |
| `OAUTH_TABLE` | Encrypted OAuth tokens |
| `VKEYS_TABLE` | Virtual key records |
| `META_TABLE` | Key-value metadata |

**Hot-path cache**: `SpendTracker` keeps a `Mutex<SpendData>` in-memory cache for global spend, flushed to redb every N writes via a `AtomicU32` counter. This eliminates a redb read transaction on every token-counted request.

**Tenant spend** is tracked separately — writes go directly to redb keyed by tenant ID, not through the in-memory cache.

**Legacy path** (`SpendTracker::load(path)` / `~/.grob/spend.json`) is retained for CLI commands (`grob spend`, `grob doctor`) and tests. On first open of a new redb database, `migrate::migrate_from_json()` auto-migrates any existing `spend.json` and `oauth_tokens.json` into the new database.

### Consequences

- Good, because ACID transactions prevent corruption on crashes
- Good, because single file (`~/.grob/grob.db`) holds all persistent state
- Good, because in-memory cache keeps the request hot path free of I/O
- Good, because redb is pure Rust, zero native library dependencies
- Bad, because not human-readable (use `grob spend` CLI to inspect)
- Bad, because not suitable for multi-instance deployments (embedded DB, single writer)
- Bad, because no historical analytics (current month only, same as before)

### Confirmation

`src/storage/mod.rs`: `GrobStore` with `record_spend`, `flush_spend`, `store_virtual_key`, etc.
`src/features/token_pricing/spend.rs`: `SpendTracker::with_store()` (redb path) and `SpendTracker::load()` (legacy JSON path).
`src/storage/migrate.rs`: `migrate_from_json()` for first-open migration.

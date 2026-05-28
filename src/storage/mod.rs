//! Persistent storage layer using atomic files and append-only journals.
//!
//! Replaces the former `redb` backend (see ADR-0013). Layout:
//!
//! ```text
//! ~/.grob/
//! ├── spend/YYYY-MM.jsonl   # append-only spend journal
//! ├── tokens/<id>.json.enc  # AES-256-GCM encrypted OAuth tokens
//! └── vkeys/<hash>.json.enc # AES-256-GCM encrypted virtual keys
//! ```
//!
//! [`GrobStore`] owns one struct with four concerns, each split into its own
//! submodule of cross-file `impl GrobStore` blocks: [`spend`], [`oauth`],
//! [`secrets_store`], and [`vkeys`]. This module holds the struct, lifecycle
//! (`open`), and shared helpers.

/// Atomic file write (write → fsync → rename).
pub(crate) mod atomic;
/// AES-256-GCM encryption for credential storage at rest.
pub(crate) mod encrypt;
/// Append-only JSONL spend journal.
pub(crate) mod journal;
/// Legacy storage detection and warning.
pub mod migrate;
/// OAuth-token persistence (`impl GrobStore`).
mod oauth;
/// Pluggable secret backends (local encrypted, env, file).
pub mod secrets;
/// Named-secret persistence (`impl GrobStore`).
mod secrets_store;
/// Spend-journal persistence (`impl GrobStore`).
mod spend;
/// Virtual-key persistence (`impl GrobStore`).
mod vkeys;

use crate::features::token_pricing::spend::SpendData;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU32;
use std::sync::Mutex;

/// Default tenant id used when a request carries no tenant context.
///
/// Per-tenant budget enforcement requires every record/check call to be
/// keyed on a tenant; legacy callers that have no tenant fall back to this
/// reserved id so isolation logic still works without conditionals.
pub const DEFAULT_TENANT: &str = "_default";

/// Unified storage backend using atomic files and append-only journals.
///
/// Stores spend data as JSONL journals, OAuth tokens and virtual keys
/// as individually encrypted JSON files. All writes are crash-safe:
/// journals use `O_APPEND`, other files use atomic rename.
pub struct GrobStore {
    /// Root directory (e.g. `~/.grob`).
    base_dir: PathBuf,
    /// Append-only spend journal (global, also receives tenant-tagged events
    /// for backward compatibility with the legacy single-journal layout).
    journal: Mutex<journal::SpendJournal>,
    /// Per-tenant append-only spend journals: written to in addition to the
    /// global journal so per-tenant budget recovery does not have to scan
    /// every other tenant's events on startup.
    tenant_journals: Mutex<HashMap<String, journal::SpendJournal>>,
    /// Hot-path in-memory spend cache (global, kept for the legacy
    /// `total()`/`provider_breakdown()` accessors and Prometheus exposition).
    spend_cache: Mutex<SpendData>,
    /// Per-tenant in-memory spend caches keyed by tenant id. The
    /// [`DEFAULT_TENANT`] entry is used for un-tagged requests.
    tenant_caches: Mutex<HashMap<String, SpendData>>,
    /// Batch writes: fsync every N record_spend calls.
    save_counter: AtomicU32,
    /// AES-256-GCM cipher for encrypting tokens and keys at rest.
    cipher: encrypt::StorageCipher,
}

impl std::fmt::Debug for GrobStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrobStore")
            .field("path", &self.base_dir)
            .finish_non_exhaustive()
    }
}

impl GrobStore {
    /// Opens or creates the storage directory.
    ///
    /// Replays the current-month spend journal into memory.
    /// Warns if a legacy `grob.db` (redb) file is detected.
    ///
    /// # Errors
    ///
    /// - Returns an error if the storage directory cannot be created.
    /// - Returns an error if storage encryption initialization fails.
    /// - Returns an error if the spend journal cannot be opened.
    pub fn open(path: &Path) -> Result<Self> {
        // `path` was formerly the DB file path (e.g. ~/.grob/grob.db).
        // Derive the base directory from it for backward compat with callers.
        let base_dir = path
            .parent()
            .unwrap_or_else(|| Path::new(".grob"))
            .to_path_buf();

        std::fs::create_dir_all(&base_dir).with_context(|| {
            format!("failed to create storage directory: {}", base_dir.display())
        })?;

        // Warn about legacy redb file (ADR-0013: no migration).
        migrate::warn_legacy_redb(&base_dir);

        // Ensure sub-directories exist.
        let tokens_dir = base_dir.join("tokens");
        let vkeys_dir = base_dir.join("vkeys");
        std::fs::create_dir_all(&tokens_dir)?;
        std::fs::create_dir_all(&vkeys_dir)?;

        // Initialize encryption cipher.
        let cipher = encrypt::StorageCipher::load_or_generate(path)
            .context("failed to initialize storage encryption")?;

        // Open spend journal and replay current month.
        let journal =
            journal::SpendJournal::open(&base_dir).context("failed to open spend journal")?;
        let spend_cache = journal.replay_current();

        // Replay per-tenant caches from the global journal so per-tenant
        // budget enforcement survives a restart.
        let tenant_caches = journal.replay_all_tenants();

        Ok(Self {
            base_dir,
            journal: Mutex::new(journal),
            tenant_journals: Mutex::new(HashMap::new()),
            spend_cache: Mutex::new(spend_cache),
            tenant_caches: Mutex::new(tenant_caches),
            save_counter: AtomicU32::new(0),
            cipher,
        })
    }

    /// Default path: `~/.grob/grob.db` (kept for caller compatibility).
    pub fn default_path() -> PathBuf {
        crate::grob_home()
            .unwrap_or_else(|| PathBuf::from(".grob"))
            .join("grob.db")
    }

    /// Gets the storage base directory path (for diagnostics).
    pub fn path(&self) -> &Path {
        &self.base_dir
    }
}

/// Sanitizes a string for use as a filename.
///
/// Shared by every persistence submodule so that ids reaching the filesystem
/// (provider ids, tenant ids, secret names, key hashes) cannot escape their
/// directory. Visible to the `storage` submodules via `super::sanitize_filename`.
fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::token_store::OAuthToken;
    use crate::auth::virtual_keys::VirtualKeyRecord;
    use chrono::Utc;
    use secrecy::{ExposeSecret, SecretString};

    #[test]
    fn test_open_and_spend_cycle() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("grob.db");
        let store = GrobStore::open(&db_path).unwrap();

        let spend = store.load_spend(None);
        assert_eq!(spend.total, 0.0);

        store.record_spend(None, 0.05, "openrouter", "claude-sonnet");
        store.record_spend(None, 0.10, "anthropic", "claude-opus");
        store.flush_spend();

        let spend = store.load_spend(None);
        assert!((spend.total - 0.15).abs() < 0.001);
        assert!((spend.by_provider["openrouter"] - 0.05).abs() < 0.001);
        assert!((spend.by_provider["anthropic"] - 0.10).abs() < 0.001);
    }

    #[test]
    fn test_oauth_crud() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("grob.db");
        let store = GrobStore::open(&db_path).unwrap();

        let token = OAuthToken {
            provider_id: "test-provider".to_string(),
            access_token: SecretString::new("access-123".to_string()),
            refresh_token: SecretString::new("refresh-456".to_string()),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            enterprise_url: None,
            project_id: None,
            needs_reauth: None,
        };

        store.save_oauth_token(&token).unwrap();

        let retrieved = store.get_oauth_token("test-provider").unwrap();
        assert_eq!(retrieved.provider_id, "test-provider");

        let providers = store.list_oauth_providers();
        assert_eq!(providers, vec!["test-provider"]);

        store.delete_oauth_token("test-provider").unwrap();
        assert!(store.get_oauth_token("test-provider").is_none());
    }

    #[test]
    fn test_per_tenant_spend() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("grob.db");
        let store = GrobStore::open(&db_path).unwrap();

        store.record_spend(Some("tenant-a"), 1.0, "provider", "model");
        store.record_spend(Some("tenant-b"), 2.0, "provider", "model");
        store.record_spend(None, 3.0, "provider", "model");

        let global = store.load_spend(None);
        assert!((global.total - 3.0).abs() < 0.001);

        let tenant_a = store.load_spend(Some("tenant-a"));
        assert!((tenant_a.total - 1.0).abs() < 0.001);

        let tenant_b = store.load_spend(Some("tenant-b"));
        assert!((tenant_b.total - 2.0).abs() < 0.001);
    }

    #[test]
    fn test_persistence_across_open() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("grob.db");

        {
            let store = GrobStore::open(&db_path).unwrap();
            store.record_spend(None, 5.0, "provider", "model");
            store.flush_spend();
        }

        let store = GrobStore::open(&db_path).unwrap();
        let spend = store.load_spend(None);
        assert!((spend.total - 5.0).abs() < 0.001);
    }

    #[test]
    fn test_virtual_key_store_and_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("grob.db");
        let store = GrobStore::open(&db_path).unwrap();

        let (full_key, hash) = crate::auth::virtual_keys::generate_key();
        let record = VirtualKeyRecord {
            id: uuid::Uuid::new_v4(),
            name: "test-key".to_string(),
            prefix: full_key[..12].to_string(),
            key_hash: hash.clone(),
            tenant_id: "tenant-1".to_string(),
            budget_usd: Some(50.0),
            rate_limit_rps: Some(10),
            allowed_models: Some(vec!["claude-sonnet".to_string()]),
            created_at: Utc::now(),
            expires_at: None,
            revoked: false,
            last_used_at: None,
        };

        store.store_virtual_key(&record).unwrap();

        let retrieved = store.lookup_virtual_key(&hash).unwrap();
        assert_eq!(retrieved.id, record.id);
        assert_eq!(retrieved.name, "test-key");
        assert_eq!(retrieved.tenant_id, "tenant-1");
        assert_eq!(retrieved.budget_usd, Some(50.0));
    }

    #[test]
    fn test_virtual_key_list() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("grob.db");
        let store = GrobStore::open(&db_path).unwrap();

        for i in 0..3 {
            let (full_key, hash) = crate::auth::virtual_keys::generate_key();
            let record = VirtualKeyRecord {
                id: uuid::Uuid::new_v4(),
                name: format!("key-{i}"),
                prefix: full_key[..12].to_string(),
                key_hash: hash,
                tenant_id: "tenant-1".to_string(),
                budget_usd: None,
                rate_limit_rps: None,
                allowed_models: None,
                created_at: Utc::now(),
                expires_at: None,
                revoked: false,
                last_used_at: None,
            };
            store.store_virtual_key(&record).unwrap();
        }

        let keys = store.list_virtual_keys();
        assert_eq!(keys.len(), 3);
    }

    #[test]
    fn test_virtual_key_revoke() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("grob.db");
        let store = GrobStore::open(&db_path).unwrap();

        let (full_key, hash) = crate::auth::virtual_keys::generate_key();
        let id = uuid::Uuid::new_v4();
        let record = VirtualKeyRecord {
            id,
            name: "revocable".to_string(),
            prefix: full_key[..12].to_string(),
            key_hash: hash.clone(),
            tenant_id: "tenant-1".to_string(),
            budget_usd: None,
            rate_limit_rps: None,
            allowed_models: None,
            created_at: Utc::now(),
            expires_at: None,
            revoked: false,
            last_used_at: None,
        };

        store.store_virtual_key(&record).unwrap();
        assert!(!store.lookup_virtual_key(&hash).unwrap().revoked);

        let revoked = store.revoke_virtual_key(&id).unwrap();
        assert!(revoked);
        assert!(store.lookup_virtual_key(&hash).unwrap().revoked);

        let missing = store.revoke_virtual_key(&uuid::Uuid::new_v4()).unwrap();
        assert!(!missing);
    }

    #[test]
    fn test_virtual_key_delete() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("grob.db");
        let store = GrobStore::open(&db_path).unwrap();

        let (full_key, hash) = crate::auth::virtual_keys::generate_key();
        let id = uuid::Uuid::new_v4();
        let record = VirtualKeyRecord {
            id,
            name: "deletable".to_string(),
            prefix: full_key[..12].to_string(),
            key_hash: hash.clone(),
            tenant_id: "tenant-1".to_string(),
            budget_usd: None,
            rate_limit_rps: None,
            allowed_models: None,
            created_at: Utc::now(),
            expires_at: None,
            revoked: false,
            last_used_at: None,
        };

        store.store_virtual_key(&record).unwrap();
        assert!(store.lookup_virtual_key(&hash).is_some());

        let deleted = store.delete_virtual_key(&id).unwrap();
        assert!(deleted);
        assert!(store.lookup_virtual_key(&hash).is_none());

        let again = store.delete_virtual_key(&id).unwrap();
        assert!(!again);
    }

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("claude-max"), "claude-max");
        assert_eq!(sanitize_filename("tenant/evil"), "tenant_evil");
        assert_eq!(sanitize_filename("a:b"), "a_b");
    }

    #[test]
    fn test_secret_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = GrobStore::open(&dir.path().join("grob.db")).unwrap();

        store.set_secret("minimax", "sk-minimax-test-123").unwrap();

        let got = store.get_secret("minimax").unwrap();
        assert_eq!(got.expose_secret(), "sk-minimax-test-123");
    }

    #[test]
    fn test_secret_list_does_not_leak_values() {
        let dir = tempfile::tempdir().unwrap();
        let store = GrobStore::open(&dir.path().join("grob.db")).unwrap();

        store.set_secret("minimax", "sk-secret-value").unwrap();
        store.set_secret("groq", "gsk-other-secret").unwrap();

        let names = store.list_secrets();
        assert_eq!(names, vec!["groq", "minimax"]);
        for n in &names {
            assert!(!n.contains("sk-"), "list must not leak values");
        }
    }

    #[test]
    fn test_secret_remove() {
        let dir = tempfile::tempdir().unwrap();
        let store = GrobStore::open(&dir.path().join("grob.db")).unwrap();

        store.set_secret("ephemeral", "x").unwrap();
        assert!(store.get_secret("ephemeral").is_some());

        let removed = store.remove_secret("ephemeral").unwrap();
        assert!(removed);
        assert!(store.get_secret("ephemeral").is_none());

        let again = store.remove_secret("ephemeral").unwrap();
        assert!(!again, "remove on absent must return Ok(false)");
    }

    #[test]
    fn test_secret_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let store = GrobStore::open(&dir.path().join("grob.db")).unwrap();

        store.set_secret("rotating", "v1").unwrap();
        store.set_secret("rotating", "v2").unwrap();

        assert_eq!(store.get_secret("rotating").unwrap().expose_secret(), "v2");
    }
}

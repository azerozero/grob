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

/// Atomic file write (write → fsync → rename).
pub(crate) mod atomic;
/// AES-256-GCM encryption for credential storage at rest.
pub(crate) mod encrypt;
/// Append-only JSONL spend journal.
pub(crate) mod journal;
/// Legacy storage detection and warning.
pub mod migrate;

use crate::auth::token_store::OAuthToken;
use crate::auth::virtual_keys::VirtualKeyRecord;
use crate::features::token_pricing::spend::SpendData;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

/// Unified storage backend using atomic files and append-only journals.
///
/// Stores spend data as JSONL journals, OAuth tokens and virtual keys
/// as individually encrypted JSON files. All writes are crash-safe:
/// journals use `O_APPEND`, other files use atomic rename.
pub struct GrobStore {
    /// Root directory (e.g. `~/.grob`).
    base_dir: PathBuf,
    /// Append-only spend journal.
    journal: Mutex<journal::SpendJournal>,
    /// Hot-path in-memory spend cache.
    spend_cache: Mutex<SpendData>,
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

        Ok(Self {
            base_dir,
            journal: Mutex::new(journal),
            spend_cache: Mutex::new(spend_cache),
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

    /// Loads spend data (from cache for global, from journal for tenants).
    pub(crate) fn load_spend(&self, tenant: Option<&str>) -> SpendData {
        if tenant.is_none() {
            return self
                .spend_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
        }
        let journal = self.journal.lock().unwrap_or_else(|e| e.into_inner());
        journal.replay_for_tenant(tenant.unwrap_or(""))
    }

    /// Records spend for a request. Uses in-memory cache + batched fsync.
    pub(crate) fn record_spend(
        &self,
        tenant: Option<&str>,
        amount: f64,
        provider: &str,
        model: &str,
    ) {
        let ts = chrono::Utc::now().to_rfc3339();

        // Update in-memory cache (global).
        if tenant.is_none() {
            let mut cache = self.spend_cache.lock().unwrap_or_else(|e| e.into_inner());
            let now = crate::features::token_pricing::spend::current_month();
            if cache.month != now {
                *cache = SpendData::default();
            }
            cache.total += amount;
            *cache.by_provider.entry(provider.to_string()).or_default() += amount;
            *cache.by_model.entry(model.to_string()).or_default() += amount;
            *cache
                .by_provider_count
                .entry(provider.to_string())
                .or_default() += 1;
        }

        // Append to journal.
        let event = journal::SpendEvent {
            ts,
            kind: "spend".to_string(),
            provider: provider.to_string(),
            model: model.to_string(),
            cost_usd: amount,
            tenant: tenant.map(String::from),
        };
        if let Ok(mut j) = self.journal.lock() {
            if let Err(e) = j.append(&event) {
                tracing::warn!("failed to append spend event to journal: {e}");
            }
        }

        // Batch fsync every 10 calls.
        let count = self.save_counter.fetch_add(1, Ordering::Relaxed);
        if count.is_multiple_of(10) {
            self.flush_spend();
        }
    }

    /// Forces journal fsync to disk.
    pub(crate) fn flush_spend(&self) {
        if let Ok(mut j) = self.journal.lock() {
            if let Err(e) = j.fsync() {
                tracing::warn!("failed to fsync spend journal: {e}");
            }
        }
    }

    // ── OAuth token storage ─────────────────────────────────────────

    fn token_path(&self, provider_id: &str) -> PathBuf {
        self.base_dir
            .join("tokens")
            .join(format!("{}.json.enc", sanitize_filename(provider_id)))
    }

    /// Saves an OAuth token (encrypted with AES-256-GCM).
    ///
    /// # Errors
    ///
    /// Returns an error if serialization, encryption, or the
    /// atomic file write fails.
    pub fn save_oauth_token(&self, token: &OAuthToken) -> Result<()> {
        let plaintext = serde_json::to_vec(token)?;
        let encrypted = self.cipher.encrypt(&plaintext)?;
        let path = self.token_path(&token.provider_id);
        atomic::write_atomic(&path, &encrypted)?;
        Ok(())
    }

    /// Gets an OAuth token by provider ID (decrypts from AES-256-GCM).
    pub fn get_oauth_token(&self, provider_id: &str) -> Option<OAuthToken> {
        let path = self.token_path(provider_id);
        let encrypted = std::fs::read(&path).ok()?;
        let decrypted = self.cipher.decrypt_or_plaintext(&encrypted);
        serde_json::from_slice(&decrypted).ok()
    }

    /// Deletes an OAuth token by provider ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be removed.
    pub fn delete_oauth_token(&self, provider_id: &str) -> Result<()> {
        let path = self.token_path(provider_id);
        if path.exists() {
            std::fs::remove_file(&path)
                .with_context(|| format!("failed to delete token: {}", path.display()))?;
        }
        Ok(())
    }

    /// Lists all provider IDs that have tokens.
    pub fn list_oauth_providers(&self) -> Vec<String> {
        let tokens_dir = self.base_dir.join("tokens");
        Self::list_enc_files(&tokens_dir)
    }

    /// Gets all OAuth tokens (decrypts each from AES-256-GCM).
    pub fn all_oauth_tokens(&self) -> std::collections::HashMap<String, OAuthToken> {
        let mut map = std::collections::HashMap::new();
        for provider_id in self.list_oauth_providers() {
            if let Some(token) = self.get_oauth_token(&provider_id) {
                map.insert(provider_id, token);
            }
        }
        map
    }

    /// Gets the storage base directory path (for diagnostics).
    pub fn path(&self) -> &Path {
        &self.base_dir
    }

    // ── Virtual key storage ─────────────────────────────────────────

    fn vkey_hash_path(&self, key_hash: &str) -> PathBuf {
        self.base_dir
            .join("vkeys")
            .join(format!("{}.json.enc", sanitize_filename(key_hash)))
    }

    fn vkey_id_path(&self, id: &uuid::Uuid) -> PathBuf {
        self.base_dir
            .join("vkeys")
            .join(format!("id_{id}.json.enc"))
    }

    /// Stores a virtual key record (encrypted with AES-256-GCM).
    ///
    /// Creates two files: one keyed by hash (for O(1) auth lookup) and
    /// one keyed by UUID (for management operations).
    ///
    /// # Errors
    ///
    /// Returns an error if serialization, encryption, or the
    /// atomic file write fails.
    pub fn store_virtual_key(&self, record: &VirtualKeyRecord) -> Result<()> {
        let plaintext = serde_json::to_vec(record)?;
        let encrypted = self.cipher.encrypt(&plaintext)?;

        // Primary: by hash.
        atomic::write_atomic(&self.vkey_hash_path(&record.key_hash), &encrypted)?;
        // Secondary: by UUID.
        let encrypted2 = self.cipher.encrypt(&plaintext)?;
        atomic::write_atomic(&self.vkey_id_path(&record.id), &encrypted2)?;

        Ok(())
    }

    /// Looks up a virtual key record by its SHA-256 hash.
    pub fn lookup_virtual_key(&self, key_hash: &str) -> Option<VirtualKeyRecord> {
        let path = self.vkey_hash_path(key_hash);
        let encrypted = std::fs::read(&path).ok()?;
        let decrypted = self.cipher.decrypt_or_plaintext(&encrypted);
        serde_json::from_slice(&decrypted).ok()
    }

    /// Lists all virtual key records.
    pub fn list_virtual_keys(&self) -> Vec<VirtualKeyRecord> {
        let vkeys_dir = self.base_dir.join("vkeys");
        let entries = match std::fs::read_dir(&vkeys_dir) {
            Ok(e) => e,
            Err(_) => return vec![],
        };

        let mut records = vec![];
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            // Skip id_ files to avoid duplicates.
            if name_str.starts_with("id_") {
                continue;
            }
            if !name_str.ends_with(".json.enc") {
                continue;
            }
            if let Ok(data) = std::fs::read(entry.path()) {
                let decrypted = self.cipher.decrypt_or_plaintext(&data);
                if let Ok(record) = serde_json::from_slice::<VirtualKeyRecord>(&decrypted) {
                    records.push(record);
                }
            }
        }
        records
    }

    /// Revokes a virtual key by UUID (sets `revoked = true`).
    ///
    /// # Errors
    ///
    /// Returns an error if the record cannot be read, deserialized,
    /// or re-encrypted.
    pub fn revoke_virtual_key(&self, id: &uuid::Uuid) -> Result<bool> {
        let id_path = self.vkey_id_path(id);
        let data = match std::fs::read(&id_path) {
            Ok(d) => d,
            Err(_) => return Ok(false),
        };
        let decrypted = self.cipher.decrypt_or_plaintext(&data);
        let mut record: VirtualKeyRecord = serde_json::from_slice(&decrypted)?;
        record.revoked = true;
        self.store_virtual_key(&record)?;
        Ok(true)
    }

    /// Deletes a virtual key by UUID (removes both hash and id files).
    ///
    /// # Errors
    ///
    /// Returns an error if the files cannot be removed.
    pub fn delete_virtual_key(&self, id: &uuid::Uuid) -> Result<bool> {
        let id_path = self.vkey_id_path(id);
        let data = match std::fs::read(&id_path) {
            Ok(d) => d,
            Err(_) => return Ok(false),
        };
        let decrypted = self.cipher.decrypt_or_plaintext(&data);
        let record: VirtualKeyRecord = serde_json::from_slice(&decrypted)?;

        // Remove both files.
        let hash_path = self.vkey_hash_path(&record.key_hash);
        let _ = std::fs::remove_file(&hash_path);
        let _ = std::fs::remove_file(&id_path);
        Ok(true)
    }

    // ── Helpers ──────────────────────────────────────────────────────

    /// Lists entity IDs from `*.json.enc` files in a directory.
    fn list_enc_files(dir: &Path) -> Vec<String> {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return vec![],
        };
        let mut ids = vec![];
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if let Some(id) = name_str.strip_suffix(".json.enc") {
                ids.push(id.to_string());
            }
        }
        ids
    }
}

/// Sanitizes a string for use as a filename.
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
    use chrono::Utc;
    use secrecy::SecretString;

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
}

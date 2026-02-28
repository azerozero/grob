pub mod migrate;

use crate::auth::token_store::OAuthToken;
use crate::features::token_pricing::spend::SpendData;
use anyhow::{Context, Result};
use redb::{Database, ReadableTable, TableDefinition};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

const SPEND_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("spend");
const OAUTH_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("oauth_tokens");
const META_TABLE: TableDefinition<&str, &str> = TableDefinition::new("meta");

/// Unified storage backend using redb (embedded key-value store).
/// Replaces spend.json and oauth_tokens.json with a single ACID database.
pub struct GrobStore {
    db: Database,
    /// Hot-path in-memory spend cache (avoids read txn on every request)
    spend_cache: Mutex<SpendData>,
    /// Batch writes: flush to disk every N record_spend calls
    save_counter: AtomicU32,
    path: PathBuf,
}

impl std::fmt::Debug for GrobStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrobStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl GrobStore {
    /// Open or create the database at the given path.
    /// Runs JSON migration on first open if legacy files exist.
    pub fn open(path: &Path) -> Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create storage directory: {}", parent.display())
            })?;
        }

        let db = Database::create(path)
            .with_context(|| format!("Failed to open redb database: {}", path.display()))?;

        // Ensure tables exist
        {
            let write_txn = db.begin_write()?;
            {
                let _ = write_txn.open_table(SPEND_TABLE)?;
                let _ = write_txn.open_table(OAUTH_TABLE)?;
                let _ = write_txn.open_table(META_TABLE)?;
            }
            write_txn.commit()?;
        }

        // Run migration if needed
        migrate::migrate_from_json(&db, path)?;

        // Load spend cache from db
        let spend_cache = Self::load_spend_from_db(&db, None)?;

        Ok(Self {
            db,
            spend_cache: Mutex::new(spend_cache),
            save_counter: AtomicU32::new(0),
            path: path.to_path_buf(),
        })
    }

    /// Default path: ~/.grob/grob.db
    pub fn default_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".grob")
            .join("grob.db")
    }

    /// Load spend data from the database for a given tenant (None = global).
    fn load_spend_from_db(db: &Database, tenant: Option<&str>) -> Result<SpendData> {
        let key = Self::spend_key(tenant);
        let read_txn = db.begin_read()?;
        let table = read_txn.open_table(SPEND_TABLE)?;

        match table.get(key.as_str())? {
            Some(value) => {
                let bytes = value.value();
                let mut data: SpendData = serde_json::from_slice(bytes).unwrap_or_default();
                // Auto-reset if new month
                let now = crate::features::token_pricing::spend::current_month();
                if data.month != now {
                    tracing::info!(
                        "New month detected ({} -> {}), resetting spend",
                        data.month,
                        now
                    );
                    data = SpendData::default();
                }
                Ok(data)
            }
            None => Ok(SpendData::default()),
        }
    }

    fn spend_key(tenant: Option<&str>) -> String {
        match tenant {
            Some(t) => format!("tenant:{}", t),
            None => "global".to_string(),
        }
    }

    /// Load spend data (from in-memory cache for global, from db for tenants).
    pub fn load_spend(&self, tenant: Option<&str>) -> SpendData {
        if tenant.is_none() {
            return self
                .spend_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
        }
        Self::load_spend_from_db(&self.db, tenant).unwrap_or_default()
    }

    /// Record spend for a request. Uses in-memory cache + batched writes.
    pub fn record_spend(&self, tenant: Option<&str>, amount: f64, provider: &str, model: &str) {
        // Update in-memory cache (always for global)
        if tenant.is_none() {
            let mut cache = self.spend_cache.lock().unwrap_or_else(|e| e.into_inner());
            let now = crate::features::token_pricing::spend::current_month();
            if cache.month != now {
                *cache = SpendData::default();
            }
            cache.total += amount;
            *cache.by_provider.entry(provider.to_string()).or_default() += amount;
            *cache.by_model.entry(model.to_string()).or_default() += amount;
        }

        // Batch writes: persist every 10 calls
        let count = self.save_counter.fetch_add(1, Ordering::Relaxed);
        if count.is_multiple_of(10) {
            self.flush_spend_for(tenant);
        }

        // Also record per-tenant if specified
        if let Some(t) = tenant {
            let mut data = Self::load_spend_from_db(&self.db, Some(t)).unwrap_or_default();
            data.total += amount;
            *data.by_provider.entry(provider.to_string()).or_default() += amount;
            *data.by_model.entry(model.to_string()).or_default() += amount;
            let _ = self.write_spend_data(Some(t), &data);
        }
    }

    /// Force write spend data to disk.
    pub fn flush_spend(&self) {
        self.flush_spend_for(None);
    }

    fn flush_spend_for(&self, tenant: Option<&str>) {
        let data = if tenant.is_none() {
            self.spend_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        } else {
            Self::load_spend_from_db(&self.db, tenant).unwrap_or_default()
        };
        let _ = self.write_spend_data(tenant, &data);
    }

    fn write_spend_data(&self, tenant: Option<&str>, data: &SpendData) -> Result<()> {
        let key = Self::spend_key(tenant);
        let bytes = serde_json::to_vec(data)?;
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(SPEND_TABLE)?;
            table.insert(key.as_str(), bytes.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Save an OAuth token to the database.
    pub fn save_oauth_token(&self, token: &OAuthToken) -> Result<()> {
        let bytes = serde_json::to_vec(token)?;
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(OAUTH_TABLE)?;
            table.insert(token.provider_id.as_str(), bytes.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Get an OAuth token by provider ID.
    pub fn get_oauth_token(&self, provider_id: &str) -> Option<OAuthToken> {
        let read_txn = self.db.begin_read().ok()?;
        let table = read_txn.open_table(OAUTH_TABLE).ok()?;
        let value = table.get(provider_id).ok()??;
        serde_json::from_slice(value.value()).ok()
    }

    /// Delete an OAuth token by provider ID.
    pub fn delete_oauth_token(&self, provider_id: &str) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(OAUTH_TABLE)?;
            table.remove(provider_id)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// List all provider IDs that have tokens.
    pub fn list_oauth_providers(&self) -> Vec<String> {
        let read_txn = match self.db.begin_read() {
            Ok(t) => t,
            Err(_) => return vec![],
        };
        let table = match read_txn.open_table(OAUTH_TABLE) {
            Ok(t) => t,
            Err(_) => return vec![],
        };
        let mut providers = vec![];
        if let Ok(iter) = table.iter() {
            for entry in iter.flatten() {
                let (key, _) = entry;
                providers.push(key.value().to_string());
            }
        }
        providers
    }

    /// Get all OAuth tokens.
    pub fn all_oauth_tokens(&self) -> std::collections::HashMap<String, OAuthToken> {
        let mut map = std::collections::HashMap::new();
        let read_txn = match self.db.begin_read() {
            Ok(t) => t,
            Err(_) => return map,
        };
        let table = match read_txn.open_table(OAUTH_TABLE) {
            Ok(t) => t,
            Err(_) => return map,
        };
        if let Ok(iter) = table.iter() {
            for (key, value) in iter.flatten() {
                if let Ok(token) = serde_json::from_slice::<OAuthToken>(value.value()) {
                    map.insert(key.value().to_string(), token);
                }
            }
        }
        map
    }

    /// Get database file path (for diagnostics).
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use secrecy::SecretString;

    #[test]
    fn test_open_and_spend_cycle() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = GrobStore::open(&db_path).unwrap();

        // Initial spend should be zero
        let spend = store.load_spend(None);
        assert_eq!(spend.total, 0.0);

        // Record spend
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
        let db_path = dir.path().join("test.db");
        let store = GrobStore::open(&db_path).unwrap();

        let token = OAuthToken {
            provider_id: "test-provider".to_string(),
            access_token: SecretString::new("access-123".to_string()),
            refresh_token: SecretString::new("refresh-456".to_string()),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            enterprise_url: None,
            project_id: None,
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
        let db_path = dir.path().join("test.db");
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
        let db_path = dir.path().join("test.db");

        {
            let store = GrobStore::open(&db_path).unwrap();
            store.record_spend(None, 5.0, "provider", "model");
            store.flush_spend();
        }

        // Reopen
        let store = GrobStore::open(&db_path).unwrap();
        let spend = store.load_spend(None);
        assert!((spend.total - 5.0).abs() < 0.001);
    }
}

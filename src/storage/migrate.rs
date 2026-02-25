use anyhow::Result;
use redb::{Database, TableDefinition};
use std::path::Path;

const SPEND_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("spend");
const OAUTH_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("oauth_tokens");
const META_TABLE: TableDefinition<&str, &str> = TableDefinition::new("meta");

/// Migrate legacy JSON files (spend.json, oauth_tokens.json) into redb.
/// Only runs once — sets `migrated_from_json = "true"` in META_TABLE.
/// Does NOT delete the original JSON files (natural backup).
pub fn migrate_from_json(db: &Database, db_path: &Path) -> Result<()> {
    // Check if already migrated
    {
        let read_txn = db.begin_read()?;
        let table = read_txn.open_table(META_TABLE)?;
        if let Some(val) = table.get("migrated_from_json")? {
            if val.value() == "true" {
                return Ok(());
            }
        }
    }

    let grob_dir = db_path
        .parent()
        .unwrap_or_else(|| Path::new("."));

    let mut migrated_anything = false;

    // Migrate spend.json
    let spend_path = grob_dir.join("spend.json");
    if spend_path.exists() {
        match std::fs::read_to_string(&spend_path) {
            Ok(content) => {
                match serde_json::from_str::<crate::features::token_pricing::spend::SpendData>(
                    &content,
                ) {
                    Ok(data) => {
                        let bytes = serde_json::to_vec(&data)?;
                        let write_txn = db.begin_write()?;
                        {
                            let mut table = write_txn.open_table(SPEND_TABLE)?;
                            table.insert("global", bytes.as_slice())?;
                        }
                        write_txn.commit()?;
                        tracing::info!(
                            "Migrated spend.json → redb (${:.2} total)",
                            data.total
                        );
                        migrated_anything = true;
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse spend.json during migration: {}", e);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to read spend.json during migration: {}", e);
            }
        }
    }

    // Migrate oauth_tokens.json
    let oauth_path = grob_dir.join("oauth_tokens.json");
    if oauth_path.exists() {
        match std::fs::read_to_string(&oauth_path) {
            Ok(content) => {
                match serde_json::from_str::<
                    std::collections::HashMap<String, crate::auth::token_store::OAuthToken>,
                >(&content)
                {
                    Ok(tokens) => {
                        let write_txn = db.begin_write()?;
                        {
                            let mut table = write_txn.open_table(OAUTH_TABLE)?;
                            for (provider_id, token) in &tokens {
                                if let Ok(bytes) = serde_json::to_vec(token) {
                                    table.insert(provider_id.as_str(), bytes.as_slice())?;
                                }
                            }
                        }
                        write_txn.commit()?;
                        tracing::info!(
                            "Migrated oauth_tokens.json → redb ({} tokens)",
                            tokens.len()
                        );
                        migrated_anything = true;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to parse oauth_tokens.json during migration: {}",
                            e
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to read oauth_tokens.json during migration: {}", e);
            }
        }
    }

    // Mark as migrated (even if no files existed — so we don't check again)
    let write_txn = db.begin_write()?;
    {
        let mut table = write_txn.open_table(META_TABLE)?;
        table.insert("migrated_from_json", "true")?;
        table.insert("schema_version", "1")?;
    }
    write_txn.commit()?;

    if migrated_anything {
        tracing::info!("JSON → redb migration complete (original files preserved as backup)");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::auth::token_store::OAuthToken;
    use crate::features::token_pricing::spend::SpendData;
    use chrono::Utc;
    use secrecy::SecretString;
    use std::collections::HashMap;

    #[test]
    fn test_migration_from_json() {
        let dir = tempfile::tempdir().unwrap();
        let grob_dir = dir.path();

        // Write legacy spend.json
        let spend = SpendData {
            month: "2026-02".to_string(),
            total: 42.50,
            by_provider: {
                let mut m = HashMap::new();
                m.insert("openrouter".to_string(), 42.50);
                m
            },
            by_model: {
                let mut m = HashMap::new();
                m.insert("claude-sonnet".to_string(), 42.50);
                m
            },
        };
        std::fs::write(
            grob_dir.join("spend.json"),
            serde_json::to_string_pretty(&spend).unwrap(),
        )
        .unwrap();

        // Write legacy oauth_tokens.json
        let mut tokens = HashMap::new();
        tokens.insert(
            "test-provider".to_string(),
            OAuthToken {
                provider_id: "test-provider".to_string(),
                access_token: SecretString::new("access-abc".to_string()),
                refresh_token: SecretString::new("refresh-xyz".to_string()),
                expires_at: Utc::now() + chrono::Duration::hours(1),
                enterprise_url: None,
                project_id: None,
            },
        );
        std::fs::write(
            grob_dir.join("oauth_tokens.json"),
            serde_json::to_string_pretty(&tokens).unwrap(),
        )
        .unwrap();

        // Open database (triggers migration)
        let db_path = grob_dir.join("grob.db");
        let store = crate::storage::GrobStore::open(&db_path).unwrap();

        // Verify spend was migrated
        let loaded_spend = store.load_spend(None);
        assert!((loaded_spend.total - 42.50).abs() < 0.01);

        // Verify OAuth token was migrated
        let token = store.get_oauth_token("test-provider").unwrap();
        assert_eq!(token.provider_id, "test-provider");

        // Verify JSON files still exist (not deleted)
        assert!(grob_dir.join("spend.json").exists());
        assert!(grob_dir.join("oauth_tokens.json").exists());

        // Verify migration doesn't run again
        drop(store);
        let _store2 = crate::storage::GrobStore::open(&db_path).unwrap();
        // No errors or panics means idempotent
    }
}

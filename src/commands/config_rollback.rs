use crate::cli;
use anyhow::{Context, Result};
use std::path::Path;

/// Restores config.toml from its backup file.
///
/// Copies `config.toml.backup` over the active `config.toml`, then
/// triggers a hot-reload on the running server if reachable.
pub async fn cmd_config_rollback(
    config: &cli::AppConfig,
    config_source: &cli::ConfigSource,
) -> Result<()> {
    let config_path = match config_source {
        cli::ConfigSource::File(p) => p.clone(),
        cli::ConfigSource::Url(_) => {
            anyhow::bail!("Cannot rollback a remote URL config");
        }
    };

    let backup_path = config_path.with_extension("toml.backup");

    if !backup_path.exists() {
        anyhow::bail!(
            "No backup found at {}. Nothing to rollback.",
            backup_path.display()
        );
    }

    rollback_from_backup(&backup_path, &config_path)?;

    // Attempt hot-reload if grob is running.
    let host = &config.server.host;
    let port: u16 = config.server.port.into();
    if crate::shared::instance::is_instance_running(host, port).await {
        let url = format!("{}/api/config/reload", cli::format_base_url(host, port));
        match reqwest::Client::new()
            .post(&url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                println!("Config reloaded on running server");
            }
            Ok(resp) => {
                eprintln!("Reload returned HTTP {}", resp.status());
            }
            Err(e) => {
                eprintln!("Reload failed: {} — restart grob to apply", e);
            }
        }
    } else {
        println!("No running instance detected. Start grob to use the restored config.");
    }

    Ok(())
}

/// Copies the backup file over the active config file.
fn rollback_from_backup(backup_path: &Path, config_path: &Path) -> Result<()> {
    std::fs::copy(backup_path, config_path).with_context(|| {
        format!(
            "Failed to copy {} -> {}",
            backup_path.display(),
            config_path.display()
        )
    })?;

    println!("Rolled back to previous config ({})", backup_path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rollback_from_backup() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let backup_path = config_path.with_extension("toml.backup");

        // Write current config and backup with different content.
        std::fs::write(&config_path, "current = true\n").unwrap();
        std::fs::write(&backup_path, "previous = true\n").unwrap();

        rollback_from_backup(&backup_path, &config_path).unwrap();

        let restored = std::fs::read_to_string(&config_path).unwrap();
        assert_eq!(restored, "previous = true\n");
    }

    #[test]
    fn test_rollback_missing_backup_fails() {
        let dir = tempfile::tempdir().unwrap();
        let backup_path = dir.path().join("config.toml.backup");
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, "current = true\n").unwrap();

        let result = rollback_from_backup(&backup_path, &config_path);
        assert!(result.is_err());
    }
}

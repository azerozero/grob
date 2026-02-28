//! Remote preset sync: HTTP fetch, git fallback, and background sync.

use super::preset_dir;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

/// Index file format for a remote preset repository.
#[derive(Deserialize)]
struct PresetIndex {
    files: Vec<String>,
}

/// Fetch text content from a URL.
async fn fetch_text(client: &reqwest::Client, url: &str) -> Result<String> {
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("Failed to fetch {}", url))?;

    if !response.status().is_success() {
        anyhow::bail!("HTTP {} for {}", response.status(), url);
    }

    response
        .text()
        .await
        .with_context(|| format!("Failed to read response from {}", url))
}

/// Sync presets from any URL source.
/// - URL ending in `.toml` (not `index.toml`) → download single preset file
/// - URL ending in `/` or `index.toml` → download index, then fetch each listed file
/// - URL ending in `.git` or `git@` prefix → fallback to git clone (requires git)
pub async fn sync_presets(source: &str) -> Result<()> {
    if source.ends_with(".git") || source.starts_with("git@") || source.starts_with("git://") {
        // Git fallback (requires git installed)
        tracing::warn!("Using git for sync — consider using an HTTP URL instead");
        sync_from_git(source)
    } else {
        sync_from_url(source).await
    }
}

/// Sync presets via HTTP (no git required).
async fn sync_from_url(url: &str) -> Result<()> {
    let dest_dir = preset_dir()?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("Failed to create HTTP client")?;

    // Single .toml file download
    if url.ends_with(".toml") && !url.ends_with("/index.toml") {
        let filename = url.rsplit('/').next().unwrap_or("preset.toml");
        let content = fetch_text(&client, url).await?;
        // Validate it's parseable TOML
        let _: toml::Value = toml::from_str(&content)
            .with_context(|| format!("Downloaded file is not valid TOML: {}", url))?;
        let dest = dest_dir.join(filename);
        std::fs::write(&dest, &content)?;
        println!("  Downloaded: {}", filename);
        return Ok(());
    }

    // Directory-style: fetch index.toml then each listed file
    let base_url = if url.ends_with('/') {
        url.to_string()
    } else if url.ends_with("/index.toml") {
        url.trim_end_matches("index.toml").to_string()
    } else {
        format!("{}/", url)
    };

    let index_url = format!("{}index.toml", base_url);
    let index_content = fetch_text(&client, &index_url).await
        .with_context(|| format!("Failed to fetch index at {}. Either point to a single .toml file or provide a directory with index.toml", index_url))?;

    let index: PresetIndex = toml::from_str(&index_content)
        .context("Failed to parse index.toml (expected: files = [\"a.toml\", \"b.toml\"])")?;

    let mut count = 0;
    for file in &index.files {
        let file_url = format!("{}{}", base_url, file);
        match fetch_text(&client, &file_url).await {
            Ok(content) => {
                // Validate TOML before saving
                if toml::from_str::<toml::Value>(&content).is_err() {
                    eprintln!("  Warning: {} is not valid TOML, skipping", file);
                    continue;
                }
                let dest = dest_dir.join(file);
                std::fs::write(&dest, &content)?;
                println!("  Downloaded: {}", file);
                count += 1;
            }
            Err(e) => {
                eprintln!("  Warning: Failed to download {}: {}", file, e);
            }
        }
    }

    println!("  Synced {} preset(s) from {}", count, base_url);
    Ok(())
}

/// Install presets from a source (HTTP URL or local file/directory)
pub async fn install_from_source(source: &str) -> Result<()> {
    if source.starts_with("http://") || source.starts_with("https://") {
        sync_presets(source).await
    } else {
        install_from_local(source)
    }
}

/// Install from a local file or directory.
fn install_from_local(source: &str) -> Result<()> {
    let dest_dir = preset_dir()?;
    let source_path = Path::new(source);

    if source_path.is_dir() {
        let mut count = 0;
        for entry in std::fs::read_dir(source_path)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("toml") {
                let dest = dest_dir.join(path.file_name().unwrap());
                std::fs::copy(&path, &dest)?;
                println!("  Installed: {}", dest.display());
                count += 1;
            }
        }
        println!("  {} preset(s) installed from {}", count, source);
    } else if source_path.is_file() {
        let dest = dest_dir.join(source_path.file_name().unwrap());
        std::fs::copy(source_path, &dest)?;
        println!("  Installed: {}", dest.display());
    } else {
        anyhow::bail!("Source not found: {}", source);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Git fallback (kept for git:// and .git URLs)
// ---------------------------------------------------------------------------

/// Sync presets from a git repository (requires git installed).
fn sync_from_git(repo_url: &str) -> Result<()> {
    let home = dirs::home_dir().context("Failed to get home directory")?;
    let repo_dir = home.join(".grob").join("presets-repo");
    let dest_dir = preset_dir()?;

    if repo_dir.exists() {
        println!("  Pulling latest presets...");
        let output = std::process::Command::new("git")
            .args(["pull", "--ff-only"])
            .current_dir(&repo_dir)
            .output()
            .context("Failed to run git — is git installed?")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!(
                "  Warning: git pull failed ({}), re-cloning...",
                stderr.trim()
            );
            std::fs::remove_dir_all(&repo_dir)?;
            clone_repo(repo_url, &repo_dir)?;
        }
    } else {
        clone_repo(repo_url, &repo_dir)?;
    }

    // Copy all .toml files from repo to presets dir
    let mut count = 0;
    for entry in std::fs::read_dir(&repo_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("toml") {
            let dest = dest_dir.join(path.file_name().unwrap());
            std::fs::copy(&path, &dest)?;
            count += 1;
        }
    }

    // Also check a presets/ subdirectory
    let repo_presets_subdir = repo_dir.join("presets");
    if repo_presets_subdir.is_dir() {
        for entry in std::fs::read_dir(&repo_presets_subdir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("toml") {
                let dest = dest_dir.join(path.file_name().unwrap());
                std::fs::copy(&path, &dest)?;
                count += 1;
            }
        }
    }

    println!("  Synced {} preset(s) from {}", count, repo_url);
    Ok(())
}

fn clone_repo(url: &str, dest: &Path) -> Result<()> {
    println!("  Cloning {}...", url);
    let output = std::process::Command::new("git")
        .args(["clone", "--depth", "1", url])
        .arg(dest)
        .output()
        .context("Failed to run git — is git installed?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("git clone failed: {}", stderr.trim());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Background sync
// ---------------------------------------------------------------------------

/// Parse a human-readable interval string to seconds.
/// Supports: "30m", "6h", "1d", "12h", etc.
pub fn parse_interval(input: &str) -> Result<u64> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        anyhow::bail!("Empty interval string");
    }

    let (num_str, unit) = trimmed.split_at(trimmed.len() - 1);
    let num: u64 = num_str
        .parse()
        .with_context(|| format!("Invalid interval number: '{}'", num_str))?;

    match unit {
        "s" => Ok(num),
        "m" => Ok(num * 60),
        "h" => Ok(num * 3600),
        "d" => Ok(num * 86400),
        _ => anyhow::bail!("Unknown interval unit '{}'. Use s/m/h/d.", unit),
    }
}

/// Spawn a background sync loop that fetches presets at the given interval.
pub fn spawn_background_sync(source: String, interval_str: String) {
    let interval_secs = match parse_interval(&interval_str) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Invalid sync_interval '{}': {}", interval_str, e);
            return;
        }
    };

    tracing::info!(
        "Preset background sync: every {} ({}s) from {}",
        interval_str,
        interval_secs,
        source
    );

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;

            tracing::info!("Syncing presets from {}...", source);
            match sync_presets(&source).await {
                Ok(_) => tracing::info!("Preset sync complete"),
                Err(e) => tracing::error!("Preset sync failed: {}", e),
            }
        }
    });
}

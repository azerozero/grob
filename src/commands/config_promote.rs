use crate::preset;
use anyhow::{Context, Result};
use std::io::Write;

/// Pushes a local preset to a remote grob instance.
///
/// Loads the preset, fetches the remote config for diffing, optionally
/// prompts for confirmation, then uploads and triggers a reload.
///
/// # Errors
///
/// Returns an error if the preset cannot be loaded, the remote
/// instance is unreachable, or the config push/reload fails.
pub async fn cmd_config_push(name: &str, target_url: &str, skip_confirm: bool) -> Result<()> {
    let preset_toml = preset::preset_content(name)
        .with_context(|| format!("Failed to load preset '{}'", name))?;

    let preset_val: toml::Value = toml::from_str(&preset_toml)
        .with_context(|| format!("Failed to parse preset '{}'", name))?;

    let client = reqwest::Client::new();
    let timeout = std::time::Duration::from_secs(10);

    // Fetch remote config for comparison.
    let remote_url = format!("{}/api/config", target_url.trim_end_matches('/'));
    println!("Fetching remote config from {}...", remote_url);
    let remote_resp = client
        .get(&remote_url)
        .timeout(timeout)
        .send()
        .await
        .with_context(|| format!("Failed to connect to {}", remote_url))?;

    if !remote_resp.status().is_success() {
        anyhow::bail!(
            "Remote returned HTTP {}: {}",
            remote_resp.status(),
            remote_resp.text().await.unwrap_or_default()
        );
    }

    let remote_json: serde_json::Value = remote_resp
        .json()
        .await
        .context("Failed to parse remote config JSON")?;

    // Show section-level diff between remote and preset.
    println!();
    println!("Config diff: preset '{}' vs remote ({})", name, target_url);
    println!();
    for section in &["router", "providers", "models"] {
        let local_val = preset_val.get(section);
        let remote_val = remote_json.get(section);
        match (local_val, remote_val) {
            (Some(_), Some(_)) => println!("  [{}]: will be updated", section),
            (Some(_), None) => println!("  [{}]: will be added", section),
            (None, Some(_)) => println!("  [{}]: unchanged (not in preset)", section),
            (None, None) => {}
        }
    }
    println!();

    if !skip_confirm {
        print!("Push preset '{}' to {}? [y/N] ", name, target_url);
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    // Build JSON payload from preset TOML sections.
    let mut payload = serde_json::Map::new();
    for section in &["router", "providers", "models"] {
        if let Some(val) = preset_val.get(section) {
            let json_val: serde_json::Value = serde_json::from_str(
                &serde_json::to_string(&val).context("Failed to convert TOML to JSON")?,
            )
            .context("Failed to re-parse as JSON")?;
            payload.insert(section.to_string(), json_val);
        }
    }

    // POST config to remote.
    let post_url = format!("{}/api/config", target_url.trim_end_matches('/'));
    println!("Pushing config to {}...", post_url);
    let post_resp = client
        .post(&post_url)
        .timeout(timeout)
        .json(&payload)
        .send()
        .await
        .with_context(|| format!("Failed to push config to {}", post_url))?;

    if !post_resp.status().is_success() {
        anyhow::bail!(
            "Push failed with HTTP {}: {}",
            post_resp.status(),
            post_resp.text().await.unwrap_or_default()
        );
    }

    // Trigger reload on the remote.
    let reload_url = format!("{}/api/config/reload", target_url.trim_end_matches('/'));
    println!("Triggering config reload...");
    let reload_resp = client
        .post(&reload_url)
        .timeout(timeout)
        .send()
        .await
        .with_context(|| format!("Failed to reload config at {}", reload_url))?;

    if reload_resp.status().is_success() {
        println!("Preset '{}' pushed and reloaded on {}", name, target_url);
    } else {
        eprintln!(
            "Config pushed but reload returned HTTP {}",
            reload_resp.status()
        );
    }

    Ok(())
}

/// Pulls config from a remote grob instance and saves as a local preset.
///
/// Fetches the remote `/api/config` JSON, strips the `server` section
/// (host/port are not portable), and saves as a TOML preset file.
///
/// # Errors
///
/// Returns an error if the remote instance is unreachable, the
/// response cannot be parsed, or the preset file cannot be written.
pub async fn cmd_config_pull(from_url: &str, save_name: &str) -> Result<()> {
    let client = reqwest::Client::new();
    let timeout = std::time::Duration::from_secs(10);

    let remote_url = format!("{}/api/config", from_url.trim_end_matches('/'));
    println!("Pulling config from {}...", remote_url);

    let resp = client
        .get(&remote_url)
        .timeout(timeout)
        .send()
        .await
        .with_context(|| format!("Failed to connect to {}", remote_url))?;

    if !resp.status().is_success() {
        anyhow::bail!(
            "Remote returned HTTP {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }

    let remote_json: serde_json::Value = resp
        .json()
        .await
        .context("Failed to parse remote config JSON")?;

    // Convert JSON to TOML, stripping the server section.
    let mut toml_val: toml::Value = serde_json::from_str(
        &serde_json::to_string(&remote_json).context("Failed to serialize JSON")?,
    )
    .context("Failed to convert JSON to TOML value")?;

    if let Some(table) = toml_val.as_table_mut() {
        table.remove("server");
        table.remove("presets");
    }

    let toml_str = toml::to_string_pretty(&toml_val).context("Failed to serialize as TOML")?;

    let dir = preset::preset_dir()?;
    let output_path = dir.join(format!("{}.toml", save_name));
    std::fs::write(&output_path, &toml_str)
        .with_context(|| format!("Failed to write preset: {}", output_path.display()))?;

    println!(
        "Saved remote config as preset '{}' at {}",
        save_name,
        output_path.display()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preset_content_loads_for_push() {
        // Verify that built-in presets can be loaded (used by push).
        let content = preset::preset_content("perf");
        assert!(content.is_ok());
        let val: Result<toml::Value, _> = toml::from_str(&content.unwrap());
        assert!(val.is_ok());
    }
}

use crate::{cli, preset};

/// Lists all available presets with their source and active status.
pub async fn cmd_preset_list(config: &cli::AppConfig) {
    println!("📦 Available Presets");
    println!();
    match preset::list_presets() {
        Ok(presets) => {
            for p in &presets {
                let tag = if p.is_builtin { "builtin" } else { "installed" };
                let active = if config.presets.active.as_deref() == Some(&p.name) {
                    " (active)"
                } else {
                    ""
                };
                println!("  {} [{}]{}", p.name, tag, active);
                println!("    {}", p.description);
            }
        }
        Err(e) => eprintln!("Error listing presets: {}", e),
    }
}

/// Prints detailed information about a named preset.
pub fn cmd_preset_info(name: &str) {
    if let Err(e) = preset::print_preset_info(name) {
        eprintln!("❌ {}", e);
    }
}

/// Installs presets from a local path or remote URL source.
pub async fn cmd_preset_install(source: &str) {
    println!("📥 Installing presets from {}...", source);
    match preset::install_from_source(source).await {
        Ok(_) => println!("✅ Installation complete"),
        Err(e) => eprintln!("❌ Installation failed: {}", e),
    }
}

/// Applies a named preset to the local config file with credential setup.
pub async fn cmd_preset_apply(
    name: &str,
    config_source: &cli::ConfigSource,
    config: &cli::AppConfig,
    reload: bool,
) -> anyhow::Result<()> {
    let file_path = match config_source {
        cli::ConfigSource::File(p) => p.clone(),
        cli::ConfigSource::Url(_) => {
            eprintln!("❌ Cannot apply presets to a remote URL config");
            eprintln!("   Use a local config file instead");
            return Ok(());
        }
    };
    println!("🔧 Applying preset '{}'...", name);
    match preset::apply_preset(name, &file_path) {
        Ok(_) => {
            if let Err(e) = preset::setup_credentials_interactive(&file_path) {
                eprintln!("Warning: credential check failed: {}", e);
            }
            println!();
            println!("✅ Preset '{}' applied successfully", name);

            if reload {
                reload_running_server(config).await;
            } else {
                println!("   Run: grob start -d");
            }
        }
        Err(e) => eprintln!("❌ Failed to apply preset: {}", e),
    }
    Ok(())
}

/// Sends a config reload request to a running grob server.
async fn reload_running_server(config: &cli::AppConfig) {
    let host = &config.server.host;
    let port: u16 = config.server.port.into();

    if !crate::instance::is_instance_running(host, port).await {
        println!("   No running instance found, skipping reload");
        println!("   Run: grob start -d");
        return;
    }

    let url = format!("{}/api/config/reload", cli::format_base_url(host, port));

    match reqwest::Client::new()
        .post(&url)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            println!("🔄 Config reloaded on running server");
        }
        Ok(resp) => {
            eprintln!("⚠️  Reload returned {}", resp.status());
        }
        Err(e) => {
            eprintln!("⚠️  Reload failed: {}", e);
        }
    }
}

/// Exports the current config file as a reusable named preset.
///
/// When `env` is set, the preset file is saved as `{name}.{env}.toml`
/// instead of `{name}.toml`, enabling per-environment presets.
pub fn cmd_preset_export(
    name: &str,
    config_source: &cli::ConfigSource,
    env: Option<&str>,
) -> anyhow::Result<()> {
    let file_path = match config_source {
        cli::ConfigSource::File(p) => p.clone(),
        cli::ConfigSource::Url(_) => {
            eprintln!("❌ Cannot export presets from a remote URL config");
            return Ok(());
        }
    };
    let export_name = match env {
        Some(e) => format!("{}.{}", name, e),
        None => name.to_string(),
    };
    println!("📤 Exporting current config as preset '{}'...", export_name);
    match preset::export_preset(&export_name, &file_path) {
        Ok(_) => println!("✅ Export complete"),
        Err(e) => eprintln!("❌ Export failed: {}", e),
    }
    Ok(())
}

/// Synchronizes presets from the configured remote sync URL.
pub async fn cmd_preset_sync(config: &cli::AppConfig) {
    if let Some(ref url) = config.presets.sync_url {
        println!("🔄 Syncing presets from {}...", url);
        match preset::sync_presets(url).await {
            Ok(_) => println!("✅ Sync complete"),
            Err(e) => eprintln!("❌ Sync failed: {}", e),
        }
    } else {
        eprintln!("❌ No sync_url configured in [presets] section");
        eprintln!("   Add to config.toml:");
        eprintln!("   [presets]");
        eprintln!(
            "   sync_url = \"https://raw.githubusercontent.com/azerozero/grob/main/presets/\""
        );
    }
}

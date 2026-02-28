use crate::{cli, preset};

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

pub fn cmd_preset_info(name: &str) {
    if let Err(e) = preset::print_preset_info(name) {
        eprintln!("❌ {}", e);
    }
}

pub async fn cmd_preset_install(source: &str) {
    println!("📥 Installing presets from {}...", source);
    match preset::install_from_source(source).await {
        Ok(_) => println!("✅ Installation complete"),
        Err(e) => eprintln!("❌ Installation failed: {}", e),
    }
}

pub fn cmd_preset_apply(name: &str, config_source: &cli::ConfigSource) -> anyhow::Result<()> {
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
            println!("   Run: grob start -d");
        }
        Err(e) => eprintln!("❌ Failed to apply preset: {}", e),
    }
    Ok(())
}

pub fn cmd_preset_export(name: &str, config_source: &cli::ConfigSource) -> anyhow::Result<()> {
    let file_path = match config_source {
        cli::ConfigSource::File(p) => p.clone(),
        cli::ConfigSource::Url(_) => {
            eprintln!("❌ Cannot export presets from a remote URL config");
            return Ok(());
        }
    };
    println!("📤 Exporting current config as preset '{}'...", name);
    match preset::export_preset(name, &file_path) {
        Ok(_) => println!("✅ Export complete"),
        Err(e) => eprintln!("❌ Export failed: {}", e),
    }
    Ok(())
}

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

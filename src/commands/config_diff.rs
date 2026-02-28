use crate::{cli, preset};

pub fn cmd_config_diff(
    config: &cli::AppConfig,
    config_source: &cli::ConfigSource,
    target: Option<String>,
) -> anyhow::Result<()> {
    let target_name = target
        .as_deref()
        .unwrap_or_else(|| config.presets.active.as_deref().unwrap_or("medium"));

    let preset_content = match preset::get_preset_content(target_name) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("❌ Failed to load target '{}': {}", target_name, e);
            return Ok(());
        }
    };

    let current_toml = match config_source {
        cli::ConfigSource::File(p) => std::fs::read_to_string(p).unwrap_or_default(),
        cli::ConfigSource::Url(_) => {
            eprintln!("❌ Cannot diff remote URL config");
            return Ok(());
        }
    };

    let current: toml::Value =
        toml::from_str(&current_toml).unwrap_or(toml::Value::Table(toml::map::Map::new()));
    let preset_val: toml::Value =
        toml::from_str(&preset_content).unwrap_or(toml::Value::Table(toml::map::Map::new()));

    println!("📋 Config diff: local vs '{}'", target_name);
    println!();

    for section in &["router", "providers", "models"] {
        let local_val = current.get(section);
        let preset_v = preset_val.get(section);
        match (local_val, preset_v) {
            (Some(l), Some(p)) if l == p => {
                println!("  [{}]: identical", section);
            }
            (Some(_), Some(_)) => {
                println!("  [{}]: differs", section);
            }
            (Some(_), None) => {
                println!("  [{}]: only in local", section);
            }
            (None, Some(_)) => {
                println!("  [{}]: only in preset", section);
            }
            (None, None) => {}
        }
    }
    Ok(())
}

use crate::{cli, preset};

pub fn cmd_connect(
    config: &cli::AppConfig,
    config_source: &cli::ConfigSource,
    provider: Option<String>,
) -> anyhow::Result<()> {
    let file_path = match config_source {
        cli::ConfigSource::File(p) => p.clone(),
        cli::ConfigSource::Url(_) => {
            eprintln!("❌ Cannot manage credentials for a remote URL config");
            return Ok(());
        }
    };

    if let Some(ref provider_name) = provider {
        let found = config.providers.iter().any(|p| p.name == *provider_name);
        if !found {
            eprintln!("❌ Provider '{}' not found in config", provider_name);
            eprintln!(
                "   Available: {}",
                config
                    .providers
                    .iter()
                    .map(|p| p.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            return Ok(());
        }
        println!("🔑 Setting up credentials for '{}'...", provider_name);
        if let Err(e) =
            preset::setup_credentials_interactive_filtered(&file_path, Some(provider_name))
        {
            eprintln!("❌ Credential setup failed: {}", e);
        }
    } else {
        println!("🔑 Setting up credentials for all providers...");
        if let Err(e) = preset::setup_credentials_interactive(&file_path) {
            eprintln!("❌ Credential setup failed: {}", e);
        }
    }
    Ok(())
}

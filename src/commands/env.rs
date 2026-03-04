use crate::{cli, providers};

/// Lists environment variable status for each configured provider.
pub fn cmd_env(config: &cli::AppConfig) {
    println!("🔑 Environment Variables");
    println!();

    let mut any_missing = false;
    for provider in &config.providers {
        if !provider.is_enabled() {
            continue;
        }
        let raw_key = provider.api_key.as_deref().unwrap_or("");
        let env_var_name = format!("{}_API_KEY", provider.name.to_uppercase().replace('-', "_"));

        match provider.auth_type {
            providers::AuthType::OAuth => {
                println!("  {:<25} OAuth (no env var needed)", provider.name);
            }
            providers::AuthType::ApiKey => {
                if raw_key.is_empty() {
                    println!("  {:<25} ⚠️  {} MISSING", provider.name, env_var_name);
                    any_missing = true;
                } else {
                    println!("  {:<25} ✅ API key configured", provider.name);
                }
            }
        }
    }
    if any_missing {
        println!();
        println!("  Hint: export MISSING_VAR=your-key-here");
        println!("  Or:   grob connect <provider>");
    }
}

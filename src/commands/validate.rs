use crate::{cli, preset};

/// Validates the configuration by testing each model with real API calls.
pub async fn cmd_validate(config: &cli::AppConfig) -> anyhow::Result<()> {
    println!("🔍 Validating configuration...");
    println!();

    let (registry, _token_store) = match preset::build_registry(config) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("❌ Failed to initialize providers: {}", e);
            eprintln!("   Fix your config and try again.");
            return Ok(());
        }
    };

    println!(
        "  Testing {} model(s) with real API calls...",
        config.models.len()
    );
    println!();

    let results = preset::validate_config(config, &registry).await;
    preset::print_validation_results(&results);
    Ok(())
}

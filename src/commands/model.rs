use crate::cli;

pub fn cmd_model(config: &cli::AppConfig) {
    println!("📊 Model Configuration");
    println!();
    println!("Configured Models:");
    println!("  • Default: {}", config.router.default);
    if let Some(ref think) = config.router.think {
        println!("  • Think: {}", think);
    }
    if let Some(ref ws) = config.router.websearch {
        println!("  • WebSearch: {}", ws);
    }
    if let Some(ref bg) = config.router.background {
        println!("  • Background: {}", bg);
    }
    println!();
    println!("Providers:");
    for provider in &config.providers {
        if provider.is_enabled() {
            println!("  • {} ({})", provider.name, provider.provider_type);
        }
    }
}

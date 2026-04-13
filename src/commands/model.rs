use crate::{cli, instance};

/// Prints the configured router models and enabled providers.
pub async fn cmd_model(config: &cli::AppConfig) {
    let host = &config.server.host;
    let port = config.server.port.value();

    if instance::is_instance_running(host, port).await {
        let base_url = cli::format_base_url(host, port);
        print_model_from_rpc(&base_url, config).await;
    } else {
        print_model_from_config(config);
    }
}

/// Prints model info by querying the running server via RPC.
async fn print_model_from_rpc(base_url: &str, config: &cli::AppConfig) {
    use super::rpc_client::try_rpc_call;

    println!("\u{1f4ca} Model Configuration (live)");
    println!();

    if let Some(routing) = try_rpc_call(base_url, "grob/model/routing", None).await {
        println!("Configured Models:");
        if let Some(d) = routing["default"].as_str() {
            println!("  \u{2022} Default: {}", d);
        }
        if let Some(t) = routing["think"].as_str() {
            println!("  \u{2022} Think: {}", t);
        }
        if let Some(w) = routing["websearch"].as_str() {
            println!("  \u{2022} WebSearch: {}", w);
        }
        if let Some(b) = routing["background"].as_str() {
            println!("  \u{2022} Background: {}", b);
        }
    } else {
        print_configured_models(config);
    }

    println!();

    if let Some(providers) = try_rpc_call(base_url, "grob/provider/list", None).await {
        println!("Providers:");
        if let Some(arr) = providers.as_array() {
            for p in arr {
                let name = p["name"].as_str().unwrap_or("?");
                let models = p["models"]
                    .as_array()
                    .map(|m| {
                        m.iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                if models.is_empty() {
                    println!("  \u{2022} {}", name);
                } else {
                    println!("  \u{2022} {} ({})", name, models);
                }
            }
        }
    } else {
        print_enabled_providers(config);
    }
}

/// Prints model info from local config (server not running).
fn print_model_from_config(config: &cli::AppConfig) {
    println!("\u{1f4ca} Model Configuration");
    println!();
    print_configured_models(config);
    println!();
    print_enabled_providers(config);
}

fn print_configured_models(config: &cli::AppConfig) {
    println!("Configured Models:");
    println!("  \u{2022} Default: {}", config.router.default);
    if let Some(ref think) = config.router.think {
        println!("  \u{2022} Think: {}", think);
    }
    if let Some(ref ws) = config.router.websearch {
        println!("  \u{2022} WebSearch: {}", ws);
    }
    if let Some(ref bg) = config.router.background {
        println!("  \u{2022} Background: {}", bg);
    }
}

fn print_enabled_providers(config: &cli::AppConfig) {
    println!("Providers:");
    for provider in &config.providers {
        if provider.is_enabled() {
            println!("  \u{2022} {} ({})", provider.name, provider.provider_type);
        }
    }
}

use crate::shared::instance;
use crate::{cli, features, preset, providers};

/// Prints service status, router config, providers, models, and spend.
pub async fn cmd_status(config: &cli::AppConfig) -> anyhow::Result<()> {
    let host = &config.server.host;
    let port = config.server.port.value();
    let base_url = cli::format_base_url(host, port);

    let (running, pid_info) = resolve_running_state(host, port).await;

    if running {
        println!("  Service:   \u{2705} running{}", pid_info);
    } else {
        println!("  Service:   \u{274c} stopped");
    }

    println!("  Address:   {}", cli::format_bind_addr(host, port));

    if let Some(ref active) = config.presets.active {
        println!("  Preset:    {}", active);
    }

    if let Some(project_path) = cli::find_project_config() {
        println!("  Project:   {}", project_path.display());
    }

    println!();

    if running {
        print_status_from_rpc(&base_url, config).await;
    } else {
        print_status_from_config(config);
    }

    Ok(())
}

/// Resolves whether the server is running and extracts PID info.
async fn resolve_running_state(host: &str, port: u16) -> (bool, String) {
    if let Some(pid) = instance::find_instance_pid(host, port).await {
        (true, format!(" (PID: {})", pid))
    } else if instance::is_instance_running(host, port).await {
        (true, String::new())
    } else if let Some(pid) = instance::legacy_pid() {
        if instance::is_process_running(pid) {
            (true, format!(" (PID: {}, legacy)", pid))
        } else {
            instance::cleanup_legacy_pid();
            (false, String::new())
        }
    } else {
        (false, String::new())
    }
}

/// Prints status by querying the running server via RPC.
async fn print_status_from_rpc(base_url: &str, config: &cli::AppConfig) {
    use super::rpc_client::try_rpc_call;

    if let Some(routing) = try_rpc_call(base_url, "grob/model/routing", None).await {
        print_routing_from_json(&routing);
    } else {
        print_routing_from_config(config);
    }

    println!();

    if let Some(providers) = try_rpc_call(base_url, "grob/provider/list", None).await {
        print_providers_from_json(&providers);
    } else {
        print_providers_from_config(config);
    }

    println!();

    if let Some(models) = try_rpc_call(base_url, "grob/model/list", None).await {
        print_models_from_json(&models);
    } else {
        print_models_from_config(config);
    }

    if let Some(budget) = try_rpc_call(base_url, "grob/budget/current", None).await {
        let total = budget["total_usd"].as_f64().unwrap_or(0.0);
        let limit = budget["budget_usd"].as_f64().unwrap_or(0.0);
        if total > 0.0 || limit > 0.0 {
            println!();
            print_spend_line(total, limit);
        }
    } else {
        print_spend_from_local(config);
    }
}

/// Prints status from local config when server is not running.
fn print_status_from_config(config: &cli::AppConfig) {
    print_routing_from_config(config);
    println!();
    print_providers_from_config(config);
    println!();
    print_models_from_config(config);
    print_spend_from_local(config);
}

fn print_routing_from_config(config: &cli::AppConfig) {
    println!("  Router:");
    println!("    Default:    {}", config.router.default);
    if let Some(ref m) = config.router.think {
        println!("    Think:      {}", m);
    }
    if let Some(ref m) = config.router.background {
        println!("    Background: {}", m);
    }
    if let Some(ref m) = config.router.websearch {
        println!("    WebSearch:  {}", m);
    }
    if config.router.gdpr {
        let region = config.router.region.as_deref().unwrap_or("eu");
        println!("    GDPR:       on (region: {})", region);
    }
}

fn print_routing_from_json(routing: &serde_json::Value) {
    println!("  Router:");
    if let Some(d) = routing["default"].as_str() {
        println!("    Default:    {}", d);
    }
    if let Some(t) = routing["think"].as_str() {
        println!("    Think:      {}", t);
    }
    if let Some(b) = routing["background"].as_str() {
        println!("    Background: {}", b);
    }
    if let Some(w) = routing["websearch"].as_str() {
        println!("    WebSearch:  {}", w);
    }
}

fn print_providers_from_config(config: &cli::AppConfig) {
    println!("  Providers:");
    for provider in &config.providers {
        let status = if !provider.is_enabled() {
            "disabled".to_string()
        } else {
            let auth_status = match provider.auth_type {
                providers::AuthType::OAuth => {
                    if let Some(ref oauth_id) = provider.oauth_provider {
                        let oauth_providers = preset::load_oauth_provider_list_pub();
                        if oauth_providers.contains(oauth_id) {
                            "oauth ok"
                        } else {
                            "needs auth"
                        }
                    } else {
                        "needs auth"
                    }
                }
                providers::AuthType::ApiKey => {
                    if provider.api_key.is_some() {
                        "key set"
                    } else {
                        "no key"
                    }
                }
            };
            let region_tag = provider
                .region
                .as_deref()
                .map(|r| format!(" [{}]", r))
                .unwrap_or_default();
            format!("{}{}", auth_status, region_tag)
        };
        println!(
            "    {:<20} ({}) {}",
            provider.name, provider.provider_type, status
        );
    }
}

fn print_providers_from_json(providers: &serde_json::Value) {
    println!("  Providers:");
    if let Some(arr) = providers.as_array() {
        for p in arr {
            let name = p["name"].as_str().unwrap_or("?");
            let models = p["models"].as_array().map(|m| m.len()).unwrap_or(0);
            println!("    {:<20} ({} models)", name, models);
        }
    }
}

fn print_models_from_config(config: &cli::AppConfig) {
    println!("  Models ({}):", config.models.len());
    for model in &config.models {
        let providers: Vec<String> = model
            .mappings
            .iter()
            .map(|m| format!("{}/{}", m.provider, m.actual_model))
            .collect();
        let strategy = model.strategy.label();
        let strategy_tag = if strategy != "fallback" {
            format!(" [{}]", strategy)
        } else {
            String::new()
        };
        println!(
            "    {:<25} \u{2192} {}{}",
            model.name,
            providers.join(", "),
            strategy_tag
        );
    }
}

fn print_models_from_json(models: &serde_json::Value) {
    if let Some(arr) = models["models"].as_array() {
        println!("  Models ({}):", arr.len());
        for m in arr {
            let name = m["name"].as_str().unwrap_or("?");
            let providers = m["providers"]
                .as_array()
                .map(|p| {
                    p.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            let strategy = m["strategy"].as_str().unwrap_or("Fallback");
            let strategy_tag = if strategy != "Fallback" {
                format!(" [{}]", strategy)
            } else {
                String::new()
            };
            println!("    {:<25} \u{2192} {}{}", name, providers, strategy_tag);
        }
    }
}

fn print_spend_from_local(config: &cli::AppConfig) {
    let spend = features::token_pricing::spend::load_spend_data();
    if spend.total > 0.0 || config.budget.monthly_limit_usd.value() > 0.0 {
        println!();
        print_spend_line(spend.total, config.budget.monthly_limit_usd.value());
    }
}

fn print_spend_line(total: f64, budget_limit: f64) {
    if budget_limit > 0.0 {
        let pct = (total / budget_limit) * 100.0;
        println!(
            "  Spend:     ${:.2} / ${:.2} ({:.0}%)",
            total, budget_limit, pct
        );
    } else {
        println!("  Spend:     ${:.2} (no budget limit)", total);
    }
}

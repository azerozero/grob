use crate::{cli, features, instance, preset, providers};

pub async fn cmd_status(config: &cli::AppConfig) -> anyhow::Result<()> {
    let (running, pid_info) = if let Some(pid) =
        instance::find_instance_pid(&config.server.host, config.server.port).await
    {
        (true, format!(" (PID: {})", pid))
    } else if instance::is_instance_running(&config.server.host, config.server.port).await {
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
    };

    if running {
        println!("  Service:   ✅ running{}", pid_info);
    } else {
        println!("  Service:   ❌ stopped");
    }

    println!(
        "  Address:   {}",
        cli::format_bind_addr(&config.server.host, config.server.port)
    );

    if let Some(ref active) = config.presets.active {
        println!("  Preset:    {}", active);
    }

    if let Some(project_path) = cli::find_project_config() {
        println!("  Project:   {}", project_path.display());
    }

    println!();

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
        let region_info = config.router.region.as_deref().unwrap_or("eu");
        println!("    GDPR:       on (region: {})", region_info);
    }

    println!();

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

    println!();

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
            "    {:<25} → {}{}",
            model.name,
            providers.join(", "),
            strategy_tag
        );
    }

    let spend = features::token_pricing::spend::load_spend_data();
    if spend.total > 0.0 || config.budget.monthly_limit_usd > 0.0 {
        println!();
        let budget_limit = config.budget.monthly_limit_usd;
        if budget_limit > 0.0 {
            let pct = (spend.total / budget_limit) * 100.0;
            println!(
                "  Spend:     ${:.2} / ${:.2} ({:.0}%)",
                spend.total, budget_limit, pct
            );
        } else {
            println!("  Spend:     ${:.2} (no budget limit)", spend.total);
        }
    }
    Ok(())
}

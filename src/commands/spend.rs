use crate::{cli, features, instance, providers};

/// Displays current month spend breakdown by provider and model.
pub async fn cmd_spend(config: &cli::AppConfig) {
    let host = &config.server.host;
    let port = config.server.port.value();

    if instance::is_instance_running(host, port).await {
        let base_url = cli::format_base_url(host, port);
        print_spend_from_rpc(&base_url, config).await;
    } else {
        print_spend_from_local(config);
    }
}

/// Prints spend data by querying the running server via RPC.
async fn print_spend_from_rpc(base_url: &str, config: &cli::AppConfig) {
    use super::rpc_client::try_rpc_call;

    let current = try_rpc_call(base_url, "grob/budget/current", None).await;
    let breakdown = try_rpc_call(base_url, "grob/budget/breakdown", None).await;

    let (total, budget_usd) = match &current {
        Some(c) => (
            c["total_usd"].as_f64().unwrap_or(0.0),
            c["budget_usd"].as_f64().unwrap_or(0.0),
        ),
        None => {
            eprintln!("  (RPC unavailable, falling back to local data)");
            print_spend_from_local(config);
            return;
        }
    };

    println!("\u{1f4b0} Spend (live from server)");
    println!();

    if budget_usd > 0.0 {
        let pct = (total / budget_usd) * 100.0;
        println!(
            "  Total:       ${:.2} / ${:.2} ({:.0}%)",
            total, budget_usd, pct
        );
    } else {
        println!("  Total:       ${:.2} (no limit)", total);
    }
    println!();

    if let Some(bd) = &breakdown {
        if let Some(arr) = bd.as_array() {
            if !arr.is_empty() {
                println!("  By provider:");
                for entry in arr {
                    let name = entry["provider"].as_str().unwrap_or("?");
                    let spent = entry["spent_usd"].as_f64().unwrap_or(0.0);
                    let reqs = entry["request_count"].as_u64().unwrap_or(0);
                    println!("    {:<20} ${:.2} ({} reqs)", name, spent, reqs);
                }
                println!();
            }
        }
    }

    if budget_usd > 0.0 {
        let remaining = (budget_usd - total).max(0.0);
        println!("  Budget remaining: ${:.2} (global)", remaining);
    }
}

/// Prints spend data from local spend file (server not running).
fn print_spend_from_local(config: &cli::AppConfig) {
    let spend = features::token_pricing::spend::load_spend_data();
    let budget = &config.budget;

    let month_display = if let Ok(date) =
        chrono::NaiveDate::parse_from_str(&format!("{}-01", spend.month), "%Y-%m-%d")
    {
        date.format("%B %Y").to_string()
    } else {
        spend.month.clone()
    };

    println!("\u{1f4b0} Spend for {}", month_display);
    println!();

    if budget.monthly_limit_usd.value() > 0.0 {
        let pct = (spend.total / budget.monthly_limit_usd.value()) * 100.0;
        println!(
            "  Total:       ${:.2} / ${:.2} ({:.0}%)",
            spend.total,
            budget.monthly_limit_usd.value(),
            pct
        );
    } else {
        println!("  Total:       ${:.2} (no limit)", spend.total);
    }
    println!();

    if !spend.by_provider.is_empty() {
        println!("  By provider:");
        let mut provider_list: Vec<_> = spend.by_provider.iter().collect();
        provider_list.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));

        for (provider_name, amount) in &provider_list {
            let is_sub = config
                .providers
                .iter()
                .find(|p| &p.name == *provider_name)
                .map(|p| p.auth_type == providers::AuthType::OAuth)
                .unwrap_or(false);

            let provider_budget = config
                .providers
                .iter()
                .find(|p| &p.name == *provider_name)
                .and_then(|p| p.budget_usd.map(|b| b.value()));

            if is_sub {
                println!("    {:<20} ${:.2} (subscription)", provider_name, amount);
            } else if let Some(limit) = provider_budget {
                let pct = (*amount / limit) * 100.0;
                let flag = if **amount >= limit {
                    " EXCEEDED"
                } else if pct >= budget.warn_at_percent as f64 {
                    " \u{26a0}\u{fe0f}"
                } else {
                    ""
                };
                println!(
                    "    {:<20} ${:.2} / ${:.2} ({:.0}%){}",
                    provider_name, amount, limit, pct, flag
                );
            } else {
                println!("    {:<20} ${:.2}", provider_name, amount);
            }
        }
        println!();
    }

    if !spend.by_model.is_empty() {
        println!("  By model:");
        let mut models: Vec<_> = spend.by_model.iter().collect();
        models.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));

        for (model_name, amount) in &models {
            let model_budget = config
                .models
                .iter()
                .find(|m| &m.name == *model_name)
                .and_then(|m| m.budget_usd.map(|b| b.value()));

            if let Some(limit) = model_budget {
                let pct = (*amount / limit) * 100.0;
                let flag = if **amount >= limit {
                    " EXCEEDED"
                } else if pct >= budget.warn_at_percent as f64 {
                    " \u{26a0}\u{fe0f}"
                } else {
                    ""
                };
                println!(
                    "    {:<30} ${:.2} / ${:.2} ({:.0}%){}",
                    model_name, amount, limit, pct, flag
                );
            } else {
                println!("    {:<30} ${:.2}", model_name, amount);
            }
        }
        println!();
    }

    if budget.monthly_limit_usd.value() > 0.0 {
        let remaining = (budget.monthly_limit_usd.value() - spend.total).max(0.0);
        println!("  Budget remaining: ${:.2} (global)", remaining);
    }
}

use crate::{cli, features, providers};

pub fn cmd_spend(config: &cli::AppConfig) {
    let spend = features::token_pricing::spend::load_spend_data();
    let budget = &config.budget;

    let month_display = if let Ok(date) =
        chrono::NaiveDate::parse_from_str(&format!("{}-01", spend.month), "%Y-%m-%d")
    {
        date.format("%B %Y").to_string()
    } else {
        spend.month.clone()
    };

    println!("💰 Spend for {}", month_display);
    println!();

    if budget.monthly_limit_usd > 0.0 {
        let pct = (spend.total / budget.monthly_limit_usd) * 100.0;
        println!(
            "  Total:       ${:.2} / ${:.2} ({:.0}%)",
            spend.total, budget.monthly_limit_usd, pct
        );
    } else {
        println!("  Total:       ${:.2} (no limit)", spend.total);
    }
    println!();

    if !spend.by_provider.is_empty() {
        println!("  By provider:");
        let mut provider_list: Vec<_> = spend.by_provider.iter().collect();
        provider_list.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap());

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
                .and_then(|p| p.budget_usd);

            if is_sub {
                println!("    {:<20} ${:.2} (subscription)", provider_name, amount);
            } else if let Some(limit) = provider_budget {
                let pct = (*amount / limit) * 100.0;
                let flag = if **amount >= limit {
                    " EXCEEDED"
                } else if pct >= budget.warn_at_percent as f64 {
                    " ⚠️"
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
        models.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap());

        for (model_name, amount) in &models {
            let model_budget = config
                .models
                .iter()
                .find(|m| &m.name == *model_name)
                .and_then(|m| m.budget_usd);

            if let Some(limit) = model_budget {
                let pct = (*amount / limit) * 100.0;
                let flag = if **amount >= limit {
                    " EXCEEDED"
                } else if pct >= budget.warn_at_percent as f64 {
                    " ⚠️"
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

    if budget.monthly_limit_usd > 0.0 {
        let remaining = (budget.monthly_limit_usd - spend.total).max(0.0);
        println!("  Budget remaining: ${:.2} (global)", remaining);
    }
}

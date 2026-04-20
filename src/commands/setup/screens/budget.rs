//! Screen 6: monthly budget cap (USD/EUR/GBP cosmetic label).

use std::io::{self, Write};

use crate::commands::setup::input::{prompt_choice, read_line};
use crate::commands::setup::types::BudgetChoice;

/// Prompts the user for a monthly budget.
///
/// Passing the previous budget as `existing_budget` lets the user keep it
/// by pressing enter at the amount prompt.
pub(in crate::commands::setup) fn screen_budget(
    existing_budget: Option<i64>,
) -> Option<BudgetChoice> {
    println!();
    println!("  Monthly budget cap:");
    if let Some(current) = existing_budget {
        println!("    Current: {} USD/month", current);
    }
    println!("    [1] Unlimited");
    println!("    [2] Set a limit");

    match prompt_choice(2) {
        2 => {
            if let Some(current) = existing_budget {
                print!("    Amount [{}]: ", current);
            } else {
                print!("    Amount: ");
            }
            io::stdout().flush().ok();
            let input = read_line();
            let amount = if input.is_empty() {
                existing_budget?
            } else {
                input.parse::<i64>().ok()?
            };
            print!("    Currency [USD]: ");
            io::stdout().flush().ok();
            let currency_input = read_line();
            let currency = parse_currency(&currency_input);
            Some(BudgetChoice { amount, currency })
        }
        _ => None,
    }
}

/// Parses a free-form currency input, defaulting to USD when empty or invalid.
///
/// Accepted values : `USD`, `EUR`, `GBP` (case-insensitive). The config schema
/// only stores amounts in USD, so non-USD values are still displayed in the
/// recap for transparency but the persisted value goes into
/// `[budget] monthly_limit_usd` unchanged.
fn parse_currency(input: &str) -> &'static str {
    match input.trim().to_ascii_uppercase().as_str() {
        "" | "USD" => "USD",
        "EUR" => "EUR",
        "GBP" => "GBP",
        _ => "USD",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// W-3 : `parse_currency` reconnait USD/EUR/GBP, ignore la casse, et
    /// tombe sur USD quand l'entree est vide ou inconnue. Ce helper est le
    /// seul morceau pur du nouveau screen_budget libre, donc c'est le bon
    /// endroit pour le verrouiller.
    #[test]
    fn test_w3_parse_currency_defaults_and_variants() {
        assert_eq!(parse_currency(""), "USD");
        assert_eq!(parse_currency("usd"), "USD");
        assert_eq!(parse_currency("USD"), "USD");
        assert_eq!(parse_currency("  eur "), "EUR");
        assert_eq!(parse_currency("GBP"), "GBP");
        assert_eq!(parse_currency("bitcoin"), "USD");
    }
}

// Grob - Token Pricing Feature
// Copyright (c) 2025 a00 SAS
// License: Elastic License v2.0
// See LICENSE for details

//! Token pricing module
//! Provides cost estimation for different models with dynamic pricing from OpenRouter

pub mod spend;

use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Pricing for a single model (USD per 1M tokens)
#[derive(Debug, Clone, Serialize)]
pub struct ModelPricing {
    /// Model identifier
    pub model: &'static str,
    /// Input price per 1M tokens (USD)
    pub input_per_million: f64,
    /// Output price per 1M tokens (USD)
    pub output_per_million: f64,
}

impl ModelPricing {
    /// Calculate cost for a given number of tokens
    pub fn calculate(&self, input_tokens: u32, output_tokens: u32) -> f64 {
        (input_tokens as f64 * self.input_per_million
            + output_tokens as f64 * self.output_per_million)
            / 1_000_000.0
    }
}

/// Known model pricing (USD) - fallback for models not available on OpenRouter
pub static KNOWN_PRICING: &[ModelPricing] = &[
    // Anthropic
    ModelPricing {
        model: "claude-opus-4-6",
        input_per_million: 15.0,
        output_per_million: 75.0,
    },
    ModelPricing {
        model: "claude-opus-4-5",
        input_per_million: 15.0,
        output_per_million: 75.0,
    },
    ModelPricing {
        model: "claude-opus-4-1",
        input_per_million: 15.0,
        output_per_million: 75.0,
    },
    ModelPricing {
        model: "claude-sonnet-4-6",
        input_per_million: 3.0,
        output_per_million: 15.0,
    },
    ModelPricing {
        model: "claude-sonnet-4-5",
        input_per_million: 3.0,
        output_per_million: 15.0,
    },
    ModelPricing {
        model: "claude-sonnet-4-0",
        input_per_million: 3.0,
        output_per_million: 15.0,
    },
    ModelPricing {
        model: "claude-haiku-4-5",
        input_per_million: 0.8,
        output_per_million: 4.0,
    },
    ModelPricing {
        model: "claude-haiku-3-5",
        input_per_million: 0.8,
        output_per_million: 4.0,
    },
    // OpenAI
    ModelPricing {
        model: "gpt-4o",
        input_per_million: 2.5,
        output_per_million: 10.0,
    },
    ModelPricing {
        model: "gpt-4-turbo",
        input_per_million: 10.0,
        output_per_million: 30.0,
    },
    ModelPricing {
        model: "gpt-4",
        input_per_million: 30.0,
        output_per_million: 60.0,
    },
    ModelPricing {
        model: "gpt-3.5-turbo",
        input_per_million: 0.5,
        output_per_million: 1.5,
    },
    // DeepSeek
    ModelPricing {
        model: "deepseek-chat",
        input_per_million: 0.27,
        output_per_million: 1.10,
    },
    ModelPricing {
        model: "deepseek-reasoner",
        input_per_million: 0.55,
        output_per_million: 2.19,
    },
    // Devstral
    ModelPricing {
        model: "devstral-small",
        input_per_million: 0.10,
        output_per_million: 0.30,
    },
    // Chinese Models
    ModelPricing {
        model: "glm-4",
        input_per_million: 0.14,
        output_per_million: 0.14,
    },
    ModelPricing {
        model: "glm-4-flash",
        input_per_million: 0.14,
        output_per_million: 0.14,
    },
    ModelPricing {
        model: "glm-4-plus",
        input_per_million: 0.14,
        output_per_million: 0.14,
    },
    ModelPricing {
        model: "MiniMax-M2",
        input_per_million: 0.30,
        output_per_million: 1.20,
    },
    ModelPricing {
        model: "minimax-m2",
        input_per_million: 0.30,
        output_per_million: 1.20,
    },
    ModelPricing {
        model: "kimi-k2",
        input_per_million: 2.00,
        output_per_million: 8.00,
    },
    ModelPricing {
        model: "kimi-k2-thinking",
        input_per_million: 2.00,
        output_per_million: 8.00,
    },
    // Groq
    ModelPricing {
        model: "llama-3.1-70b",
        input_per_million: 0.59,
        output_per_million: 0.79,
    },
    ModelPricing {
        model: "llama-3.1-8b",
        input_per_million: 0.05,
        output_per_million: 0.08,
    },
];

/// Dynamic pricing table with model -> (input_per_million, output_per_million) in USD
#[derive(Debug, Clone)]
pub struct PricingTable {
    /// model_id -> (input_per_million, output_per_million) in USD
    prices: HashMap<String, (f64, f64)>,
}

impl PricingTable {
    /// Create from hardcoded fallbacks only
    pub fn from_known() -> Self {
        let mut prices = HashMap::new();
        for p in KNOWN_PRICING {
            prices.insert(
                p.model.to_lowercase(),
                (p.input_per_million, p.output_per_million),
            );
        }
        Self { prices }
    }

    /// Fetch pricing from OpenRouter API and merge with hardcoded fallbacks
    pub async fn fetch_and_merge() -> Self {
        let mut table = Self::from_known();

        match Self::fetch_openrouter().await {
            Ok(openrouter_prices) => {
                let count = openrouter_prices.len();
                for (model, prices) in openrouter_prices {
                    table.prices.insert(model.to_lowercase(), prices);
                }
                tracing::info!("Fetched {} model prices from OpenRouter", count);
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to fetch OpenRouter pricing, using hardcoded fallbacks: {}",
                    e
                );
            }
        }

        table
    }

    /// Fetch pricing from OpenRouter API (no auth required)
    /// Returns model_id -> (input_per_million, output_per_million) in USD
    async fn fetch_openrouter() -> anyhow::Result<HashMap<String, (f64, f64)>> {
        let client = reqwest::Client::new();
        let resp = client
            .get("https://openrouter.ai/api/v1/models")
            .timeout(std::time::Duration::from_secs(15))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("OpenRouter API returned status {}", resp.status());
        }

        let body: serde_json::Value = resp.json().await?;
        let mut prices = HashMap::new();

        if let Some(data) = body.get("data").and_then(|d| d.as_array()) {
            for model in data {
                let id = match model.get("id").and_then(|v| v.as_str()) {
                    Some(id) => id,
                    None => continue,
                };

                let pricing = match model.get("pricing") {
                    Some(p) => p,
                    None => continue,
                };

                // OpenRouter returns per-token prices as strings
                let prompt_price = pricing
                    .get("prompt")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<f64>().ok())
                    .unwrap_or(0.0);

                let completion_price = pricing
                    .get("completion")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<f64>().ok())
                    .unwrap_or(0.0);

                // Convert per-token to per-million-tokens
                let input_per_million = prompt_price * 1_000_000.0;
                let output_per_million = completion_price * 1_000_000.0;

                if input_per_million > 0.0 || output_per_million > 0.0 {
                    prices.insert(id.to_string(), (input_per_million, output_per_million));
                }
            }
        }

        Ok(prices)
    }

    /// Get price per million tokens for a model (case-insensitive, fuzzy match)
    pub fn get(&self, model: &str) -> Option<(f64, f64)> {
        // Try exact (case-sensitive) first - zero allocation
        if let Some(prices) = self.prices.get(model) {
            return Some(*prices);
        }
        // Then lowercase exact match
        let model_lower = model.to_lowercase();
        if let Some(prices) = self.prices.get(&model_lower) {
            return Some(*prices);
        }
        // Fuzzy match: check if any key contains the model or vice versa
        for (key, prices) in &self.prices {
            if model_lower.contains(key) || key.contains(&model_lower) {
                return Some(*prices);
            }
        }
        None
    }

    /// Whether the pricing table is empty
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.prices.is_empty()
    }
}

/// Shared pricing table accessible across the application
pub type SharedPricingTable = Arc<RwLock<PricingTable>>;

/// Create a shared pricing table and spawn background refresh every 24h
pub async fn init_pricing_table() -> SharedPricingTable {
    let table = PricingTable::fetch_and_merge().await;
    let shared = Arc::new(RwLock::new(table));

    // Spawn background refresh every 24 hours
    let shared_clone = shared.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(24 * 60 * 60));
        interval.tick().await; // Skip first immediate tick
        loop {
            interval.tick().await;
            tracing::info!("Refreshing OpenRouter pricing table...");
            let new_table = PricingTable::fetch_and_merge().await;
            *shared_clone.write().await = new_table;
        }
    });

    shared
}

/// Static pricing lookup map for O(1) exact match.
static PRICING_MAP: std::sync::LazyLock<
    std::collections::HashMap<&'static str, &'static ModelPricing>,
> = std::sync::LazyLock::new(|| KNOWN_PRICING.iter().map(|p| (p.model, p)).collect());

/// Get pricing for a model from the static fallback table (case-insensitive)
pub fn get_pricing(model: &str) -> Option<&'static ModelPricing> {
    // Try exact match first (O(1), no allocation)
    PRICING_MAP.get(model).copied().or_else(|| {
        let lower = model.to_lowercase();
        KNOWN_PRICING.iter().find(|p| lower.contains(p.model))
    })
}

/// Token cost calculator
pub struct TokenCounter {
    pub estimated_cost_usd: f64,
}

impl TokenCounter {
    /// Create from usage and calculate cost (uses static fallback table)
    #[cfg(test)]
    pub fn new(model: &str, input_tokens: u32, output_tokens: u32) -> Self {
        let cost = get_pricing(model)
            .map(|p| p.calculate(input_tokens, output_tokens))
            .unwrap_or(0.0);

        Self {
            estimated_cost_usd: cost,
        }
    }

    /// Create from usage with subscription flag and dynamic pricing table
    pub fn with_pricing(
        model: &str,
        input_tokens: u32,
        output_tokens: u32,
        is_subscription: bool,
        pricing_table: Option<&PricingTable>,
    ) -> Self {
        let cost = if is_subscription {
            0.0 // Included in subscription (Max, Pro, etc.)
        } else if let Some(table) = pricing_table {
            table
                .get(model)
                .map(|(inp, out)| {
                    (input_tokens as f64 / 1_000_000.0) * inp
                        + (output_tokens as f64 / 1_000_000.0) * out
                })
                .unwrap_or_else(|| {
                    // Fall back to static table
                    get_pricing(model)
                        .map(|p| p.calculate(input_tokens, output_tokens))
                        .unwrap_or(0.0)
                })
        } else {
            get_pricing(model)
                .map(|p| p.calculate(input_tokens, output_tokens))
                .unwrap_or(0.0)
        };

        Self {
            estimated_cost_usd: cost,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claude_pricing() {
        let pricing = get_pricing("claude-sonnet-4-6").unwrap();
        assert_eq!(pricing.input_per_million, 3.0);

        let cost = pricing.calculate(1000, 500);
        assert!((cost - 0.0105).abs() < 0.001);
    }

    #[test]
    fn test_token_counter() {
        let counter = TokenCounter::new("claude-sonnet-4-6", 1000, 500);
        assert!(counter.estimated_cost_usd > 0.0);
    }

    #[test]
    fn test_unknown_model() {
        let counter = TokenCounter::new("unknown-model", 1000, 500);
        assert_eq!(counter.estimated_cost_usd, 0.0);
    }

    #[test]
    fn test_pricing_table_from_known() {
        let table = PricingTable::from_known();
        assert!(!table.is_empty());

        // Exact match
        let (inp, out) = table.get("claude-opus-4-6").unwrap();
        assert_eq!(inp, 15.0);
        assert_eq!(out, 75.0);
    }

    #[test]
    fn test_pricing_table_fuzzy_match() {
        let table = PricingTable::from_known();
        // Fuzzy: model ID contains a known key
        let result = table.get("anthropic/claude-sonnet-4-6:beta");
        assert!(result.is_some());
    }

    #[test]
    fn test_subscription_zero_cost() {
        let counter = TokenCounter::with_pricing("claude-opus-4-6", 10000, 5000, true, None);
        assert_eq!(counter.estimated_cost_usd, 0.0);
    }

    #[test]
    fn test_with_pricing_table() {
        let table = PricingTable::from_known();
        let counter =
            TokenCounter::with_pricing("claude-sonnet-4-6", 1000, 500, false, Some(&table));
        assert!(counter.estimated_cost_usd > 0.0);
    }
}

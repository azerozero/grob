// Claude Code Mux - Token Pricing Feature
// Copyright (c) 2024 [Ton Nom]
// License: Elastic License v2.0
// See LICENSE for details

//! Token pricing module
//! Provides cost estimation for different models

use serde::Serialize;

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
        let input_cost = (input_tokens as f64 / 1_000_000.0) * self.input_per_million;
        let output_cost = (output_tokens as f64 / 1_000_000.0) * self.output_per_million;
        input_cost + output_cost
    }
}

/// Known model pricing (USD)
pub static KNOWN_PRICING: &[ModelPricing] = &[
    // Anthropic
    ModelPricing {
        model: "claude-opus-4-1",
        input_per_million: 15.0,
        output_per_million: 75.0,
    },
    ModelPricing {
        model: "claude-opus-4-5",
        input_per_million: 15.0,
        output_per_million: 75.0,
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
        input_per_million: 5.0,
        output_per_million: 15.0,
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

/// Get pricing for a model (case-insensitive)
pub fn get_pricing(model: &str) -> Option<&'static ModelPricing> {
    let model_lower = model.to_lowercase();
    KNOWN_PRICING
        .iter()
        .find(|p| model_lower.contains(&p.model.to_ascii_lowercase()))
}

/// Token cost calculator
#[allow(dead_code)]
pub struct TokenCounter {
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub estimated_cost_usd: f64,
    pub model: String,
}

impl TokenCounter {
    /// Create from usage and calculate cost
    pub fn new(model: &str, input_tokens: u32, output_tokens: u32) -> Self {
        let cost = get_pricing(model)
            .map(|p| p.calculate(input_tokens, output_tokens))
            .unwrap_or(0.0);

        Self {
            input_tokens,
            output_tokens,
            estimated_cost_usd: cost,
            model: model.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claude_pricing() {
        let pricing = get_pricing("claude-sonnet-4-5").unwrap();
        assert_eq!(pricing.input_per_million, 3.0);

        let cost = pricing.calculate(1000, 500);
        assert!((cost - 0.0105).abs() < 0.001);
    }

    #[test]
    fn test_token_counter() {
        let counter = TokenCounter::new("claude-sonnet-4-5", 1000, 500);
        assert_eq!(counter.input_tokens, 1000);
        assert_eq!(counter.output_tokens, 500);
    }

    #[test]
    fn test_unknown_model() {
        let counter = TokenCounter::new("unknown-model", 1000, 500);
        assert_eq!(counter.estimated_cost_usd, 0.0);
    }
}

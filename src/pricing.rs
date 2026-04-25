//! Static model pricing lookup (leaf module, no internal dependencies).
//!
//! Provides per-model cost estimates from a hardcoded fallback table.
//! Both `providers::streaming` and `features::token_pricing` import from
//! here, avoiding a circular dependency between those two modules.

use serde::Serialize;

/// Pricing for a single model (USD per 1M tokens).
#[derive(Debug, Clone, Serialize)]
pub struct ModelPricing {
    /// Model identifier.
    pub model: &'static str,
    /// Input price per 1M tokens (USD).
    pub input_per_million: f64,
    /// Output price per 1M tokens (USD).
    pub output_per_million: f64,
}

impl ModelPricing {
    /// Calculates cost for a given number of tokens.
    ///
    /// # Examples
    ///
    /// ```
    /// use grob::pricing::ModelPricing;
    /// let p = ModelPricing { model: "test", input_per_million: 3.0, output_per_million: 15.0 };
    /// let cost = p.calculate(1_000_000, 0);
    /// assert!((cost - 3.0).abs() < 1e-9);
    /// ```
    pub fn calculate(&self, input_tokens: u32, output_tokens: u32) -> f64 {
        (input_tokens as f64 * self.input_per_million
            + output_tokens as f64 * self.output_per_million)
            / 1_000_000.0
    }
}

/// Known model pricing (USD) - fallback for models not available on OpenRouter.
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
    // GLM-4.7-Flash (Z.ai, released 2026-01-19) — free tier per Z.ai pricing
    ModelPricing {
        model: "glm-4.7-flash",
        input_per_million: 0.0,
        output_per_million: 0.0,
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
    // MiniMax M2.5 (released 2026-02-12) — same input price as M2, same output
    ModelPricing {
        model: "MiniMax-M2.5",
        input_per_million: 0.30,
        output_per_million: 1.20,
    },
    ModelPricing {
        model: "minimax-m2.5",
        input_per_million: 0.30,
        output_per_million: 1.20,
    },
    // M2.5-Lightning: identical capability, 2x throughput, 2x output cost
    ModelPricing {
        model: "MiniMax-M2.5-Lightning",
        input_per_million: 0.30,
        output_per_million: 2.40,
    },
    ModelPricing {
        model: "minimax-m2.5-lightning",
        input_per_million: 0.30,
        output_per_million: 2.40,
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
    // Llama 3.3 70B (Groq versatile endpoint)
    ModelPricing {
        model: "llama-3.3-70b-versatile",
        input_per_million: 0.59,
        output_per_million: 0.79,
    },
    // Inception Labs (diffusion LLM, fast)
    ModelPricing {
        model: "mercury-coder-small",
        input_per_million: 0.25,
        output_per_million: 1.25,
    },
    // Google Gemini
    ModelPricing {
        model: "gemini-2.5-pro",
        input_per_million: 1.25,
        output_per_million: 5.00,
    },
];

/// Static pricing lookup map for O(1) exact match.
static PRICING_MAP: std::sync::LazyLock<
    std::collections::HashMap<&'static str, &'static ModelPricing>,
> = std::sync::LazyLock::new(|| KNOWN_PRICING.iter().map(|p| (p.model, p)).collect());

/// Looks up static pricing for a model (case-insensitive, fuzzy).
/// # Examples
///
/// ```
/// use grob::pricing::pricing;
/// let p = pricing("claude-opus-4-6").unwrap();
/// assert!(p.input_per_million > 0.0);
/// assert!(pricing("unknown-model-xyz").is_none());
/// ```
pub fn pricing(model: &str) -> Option<&'static ModelPricing> {
    // Try exact match first (O(1), no allocation)
    PRICING_MAP.get(model).copied().or_else(|| {
        let lower = model.to_lowercase();
        KNOWN_PRICING.iter().find(|p| lower.contains(p.model))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimax_m25_lookup() {
        let p = pricing("MiniMax-M2.5").expect("M2.5 listed");
        assert_eq!(p.input_per_million, 0.30);
        assert_eq!(p.output_per_million, 1.20);
    }

    #[test]
    fn minimax_m25_lightning_double_output_cost() {
        let p = pricing("MiniMax-M2.5-Lightning").expect("Lightning listed");
        assert_eq!(p.input_per_million, 0.30);
        assert_eq!(p.output_per_million, 2.40);
    }

    #[test]
    fn glm_47_flash_is_free_tier() {
        let p = pricing("glm-4.7-flash").expect("glm-4.7-flash listed");
        assert_eq!(p.input_per_million, 0.0);
        assert_eq!(p.output_per_million, 0.0);
    }

    #[test]
    fn llama_33_70b_versatile_uses_groq_pricing() {
        let p = pricing("llama-3.3-70b-versatile").expect("listed");
        assert_eq!(p.input_per_million, 0.59);
        assert_eq!(p.output_per_million, 0.79);
    }

    #[test]
    fn mercury_coder_small_listed() {
        let p = pricing("mercury-coder-small").expect("listed");
        assert_eq!(p.input_per_million, 0.25);
        assert_eq!(p.output_per_million, 1.25);
    }

    #[test]
    fn gemini_25_pro_listed() {
        let p = pricing("gemini-2.5-pro").expect("listed");
        assert_eq!(p.input_per_million, 1.25);
        assert_eq!(p.output_per_million, 5.00);
    }

    #[test]
    fn calculate_one_million_input() {
        let p = pricing("MiniMax-M2.5").unwrap();
        let cost = p.calculate(1_000_000, 0);
        assert!((cost - 0.30).abs() < 1e-9);
    }
}

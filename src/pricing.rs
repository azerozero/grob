//! Static model pricing lookup (leaf module, no internal dependencies).
//!
//! Provides per-model cost estimates from a hardcoded fallback table.
//! Both `providers::streaming` and `features::token_pricing` import from
//! here, avoiding a circular dependency between those two modules.
//!
//! Prices reflect publicly listed rates as of 2026-04-30 (USD per 1M tokens).
//! Update this file when providers publish price changes; the upstream
//! OpenRouter feed in [`crate::features::token_pricing`] takes precedence
//! at runtime so this is the cold-start fallback.

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

/// Known model pricing (USD) — fallback for models not available on OpenRouter.
pub static KNOWN_PRICING: &[ModelPricing] = &[
    // -----------------------------------------------------------------
    // Anthropic — Opus 4.6+ moved to $5/$25 (was $15/$75 on 4.5 and earlier).
    // -----------------------------------------------------------------
    ModelPricing {
        model: "claude-opus-4-7",
        input_per_million: 5.0,
        output_per_million: 25.0,
    },
    ModelPricing {
        model: "claude-opus-4-6",
        input_per_million: 5.0,
        output_per_million: 25.0,
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
        model: "claude-sonnet-4-7",
        input_per_million: 3.0,
        output_per_million: 15.0,
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
    // Haiku 4.5 raised to $1/$5 in early 2026.
    ModelPricing {
        model: "claude-haiku-4-5",
        input_per_million: 1.0,
        output_per_million: 5.0,
    },
    ModelPricing {
        model: "claude-haiku-3-5",
        input_per_million: 0.8,
        output_per_million: 4.0,
    },
    // -----------------------------------------------------------------
    // OpenAI — GPT-5 family added April 2026.
    // -----------------------------------------------------------------
    ModelPricing {
        model: "gpt-5",
        input_per_million: 0.625,
        output_per_million: 5.0,
    },
    ModelPricing {
        model: "gpt-5.5",
        input_per_million: 5.0,
        output_per_million: 30.0,
    },
    ModelPricing {
        model: "gpt-5.5-pro",
        input_per_million: 30.0,
        output_per_million: 180.0,
    },
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
    // OpenAI reasoning models (o-series). Listed price excludes the
    // reasoning-token surcharge — token billing infra (PR #TODO) adds the 3×
    // multiplier on `reasoning_tokens` for accurate cost.
    ModelPricing {
        model: "o1",
        input_per_million: 15.0,
        output_per_million: 60.0,
    },
    ModelPricing {
        model: "o1-mini",
        input_per_million: 3.0,
        output_per_million: 12.0,
    },
    ModelPricing {
        model: "o3",
        input_per_million: 15.0,
        output_per_million: 60.0,
    },
    ModelPricing {
        model: "o3-mini",
        input_per_million: 3.0,
        output_per_million: 12.0,
    },
    // OpenAI open-source weights served on Groq free tier (gpt-oss).
    ModelPricing {
        model: "gpt-oss-20b",
        input_per_million: 0.0,
        output_per_million: 0.0,
    },
    ModelPricing {
        model: "gpt-oss-120b",
        input_per_million: 0.0,
        output_per_million: 0.0,
    },
    // -----------------------------------------------------------------
    // DeepSeek — V4 family. Legacy endpoints retire 2026-07-24.
    // V4-Pro promo ($0.435/$0.87) ended 2026-05-05 → list price.
    // -----------------------------------------------------------------
    ModelPricing {
        model: "deepseek-v4-flash",
        input_per_million: 0.14,
        output_per_million: 0.28,
    },
    ModelPricing {
        model: "deepseek-v4-pro",
        input_per_million: 1.74,
        output_per_million: 3.48,
    },
    // Legacy endpoints reroute to V4-Flash since 2026-Q1.
    ModelPricing {
        model: "deepseek-chat",
        input_per_million: 0.14,
        output_per_million: 0.28,
    },
    ModelPricing {
        model: "deepseek-reasoner",
        input_per_million: 0.14,
        output_per_million: 0.28,
    },
    // -----------------------------------------------------------------
    // Devstral (Mistral AI coding model).
    // -----------------------------------------------------------------
    ModelPricing {
        model: "devstral-small",
        input_per_million: 0.10,
        output_per_million: 0.30,
    },
    // -----------------------------------------------------------------
    // Z.ai / GLM family.
    // -----------------------------------------------------------------
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
    // GLM-4.5-Flash and 4.7-Flash are free tier on Z.ai for registered users.
    ModelPricing {
        model: "glm-4.5-flash",
        input_per_million: 0.0,
        output_per_million: 0.0,
    },
    ModelPricing {
        model: "glm-4.7-flash",
        input_per_million: 0.0,
        output_per_million: 0.0,
    },
    // -----------------------------------------------------------------
    // MiniMax — M2.5 list price corrected to $0.15/$0.95 (was billed at
    // $0.30/$1.20 — 2× over).
    // -----------------------------------------------------------------
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
        model: "MiniMax-M2.5",
        input_per_million: 0.15,
        output_per_million: 0.95,
    },
    ModelPricing {
        model: "minimax-m2.5",
        input_per_million: 0.15,
        output_per_million: 0.95,
    },
    // M2.5-Lightning tier prices unverified — keep historical rate as
    // best-effort until Anthropic-compat endpoint publishes a list.
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
    // M2.7 released March 2026; assumes M2.5 rates pending official table.
    ModelPricing {
        model: "MiniMax-M2.7",
        input_per_million: 0.15,
        output_per_million: 0.95,
    },
    ModelPricing {
        model: "minimax-m2.7",
        input_per_million: 0.15,
        output_per_million: 0.95,
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
    // -----------------------------------------------------------------
    // Groq (Llama family on dedicated inference).
    // -----------------------------------------------------------------
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
    ModelPricing {
        model: "llama-3.3-70b-versatile",
        input_per_million: 0.59,
        output_per_million: 0.79,
    },
    // Llama 4 Scout 17B on Groq — free tier with 30K TPM cap.
    ModelPricing {
        model: "llama-4-scout-17b",
        input_per_million: 0.0,
        output_per_million: 0.0,
    },
    // -----------------------------------------------------------------
    // Inception Labs (diffusion LLM). Mercury 2 supersedes mercury-coder-small.
    // -----------------------------------------------------------------
    ModelPricing {
        model: "mercury-2",
        input_per_million: 0.25,
        output_per_million: 0.75,
    },
    ModelPricing {
        model: "mercury-coder-small",
        input_per_million: 0.25,
        output_per_million: 1.25,
    },
    // -----------------------------------------------------------------
    // xAI Grok.
    // -----------------------------------------------------------------
    ModelPricing {
        model: "grok-4.1-fast",
        input_per_million: 0.20,
        output_per_million: 0.50,
    },
    // -----------------------------------------------------------------
    // Google Gemini — 2.5 Pro output is $10/M (was billed $5/M — 2× under).
    // Prices apply to the ≤200K-context tier; >200K tier is $2.50/$15.
    // -----------------------------------------------------------------
    ModelPricing {
        model: "gemini-2.5-pro",
        input_per_million: 1.25,
        output_per_million: 10.00,
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
/// let p = pricing("claude-opus-4-7").unwrap();
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
    fn opus_47_listed_at_new_price() {
        let p = pricing("claude-opus-4-7").expect("opus 4.7 listed");
        assert_eq!(p.input_per_million, 5.0);
        assert_eq!(p.output_per_million, 25.0);
    }

    #[test]
    fn opus_46_corrected_to_new_price() {
        // Regression: was $15/$75 (legacy 4.5-era rate) — 3× over-billing.
        let p = pricing("claude-opus-4-6").expect("opus 4.6 listed");
        assert_eq!(p.input_per_million, 5.0);
        assert_eq!(p.output_per_million, 25.0);
    }

    #[test]
    fn haiku_45_corrected() {
        // Regression: was $0.80/$4 — raised to $1/$5.
        let p = pricing("claude-haiku-4-5").expect("haiku 4.5 listed");
        assert_eq!(p.input_per_million, 1.0);
        assert_eq!(p.output_per_million, 5.0);
    }

    #[test]
    fn gpt_5_listed() {
        let p = pricing("gpt-5").expect("gpt-5 listed");
        assert_eq!(p.input_per_million, 0.625);
        assert_eq!(p.output_per_million, 5.0);
    }

    #[test]
    fn gpt_55_listed() {
        let p = pricing("gpt-5.5").expect("gpt-5.5 listed");
        assert_eq!(p.input_per_million, 5.0);
        assert_eq!(p.output_per_million, 30.0);
    }

    #[test]
    fn deepseek_v4_flash_listed() {
        let p = pricing("deepseek-v4-flash").expect("V4-Flash listed");
        assert_eq!(p.input_per_million, 0.14);
        assert_eq!(p.output_per_million, 0.28);
    }

    #[test]
    fn deepseek_legacy_rerouted_to_v4_rates() {
        // Legacy deepseek-chat endpoint reroutes to V4-Flash since 2026-Q1.
        let p = pricing("deepseek-chat").expect("legacy chat listed");
        assert_eq!(p.input_per_million, 0.14);
        assert_eq!(p.output_per_million, 0.28);
    }

    #[test]
    fn minimax_m25_corrected() {
        // Regression: was $0.30/$1.20 — 2× over-billing.
        let p = pricing("MiniMax-M2.5").expect("M2.5 listed");
        assert_eq!(p.input_per_million, 0.15);
        assert_eq!(p.output_per_million, 0.95);
    }

    #[test]
    fn minimax_m25_lightning_unchanged() {
        // Lightning tier list unverified; kept as historical rate.
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
    fn mercury_2_listed() {
        let p = pricing("mercury-2").expect("mercury 2 listed");
        assert_eq!(p.input_per_million, 0.25);
        assert_eq!(p.output_per_million, 0.75);
    }

    #[test]
    fn mercury_coder_small_kept_for_backcompat() {
        let p = pricing("mercury-coder-small").expect("legacy mercury listed");
        assert_eq!(p.input_per_million, 0.25);
        assert_eq!(p.output_per_million, 1.25);
    }

    #[test]
    fn grok_41_fast_listed() {
        let p = pricing("grok-4.1-fast").expect("grok 4.1 fast listed");
        assert_eq!(p.input_per_million, 0.20);
        assert_eq!(p.output_per_million, 0.50);
    }

    #[test]
    fn gemini_25_pro_output_corrected() {
        // Regression: output was $5/M — actually $10/M on ≤200k tier (2× under).
        let p = pricing("gemini-2.5-pro").expect("listed");
        assert_eq!(p.input_per_million, 1.25);
        assert_eq!(p.output_per_million, 10.00);
    }

    #[test]
    fn calculate_one_million_input() {
        let p = pricing("MiniMax-M2.5").unwrap();
        let cost = p.calculate(1_000_000, 0);
        assert!((cost - 0.15).abs() < 1e-9);
    }
}

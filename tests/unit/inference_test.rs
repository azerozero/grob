//! Tests for provider type inference and smart pass-through routing.

mod tests {
    use grob::router::inference::infer_provider_type;

    // ── Codex CLI models ──

    #[test]
    fn codex_default_model() {
        assert_eq!(infer_provider_type("gpt-5.3-codex"), Some("openai"));
    }

    #[test]
    fn codex_recommended_model() {
        assert_eq!(infer_provider_type("gpt-5.4"), Some("openai"));
    }

    #[test]
    fn codex_legacy_models() {
        assert_eq!(infer_provider_type("gpt-5.2-codex"), Some("openai"));
        assert_eq!(infer_provider_type("gpt-5.1-codex-max"), Some("openai"));
    }

    // ── Claude Code models ──

    #[test]
    fn claude_code_sonnet() {
        assert_eq!(infer_provider_type("claude-sonnet-4-6"), Some("anthropic"));
    }

    #[test]
    fn claude_code_opus() {
        assert_eq!(infer_provider_type("claude-opus-4-6"), Some("anthropic"));
    }

    #[test]
    fn claude_code_haiku() {
        assert_eq!(
            infer_provider_type("claude-3-5-haiku-20241022"),
            Some("anthropic")
        );
    }

    // ── Aider default models ──

    #[test]
    fn aider_default_model() {
        // Aider works best with Claude Sonnet
        assert_eq!(
            infer_provider_type("claude-sonnet-4-20250514"),
            Some("anthropic")
        );
    }

    #[test]
    fn aider_deepseek() {
        assert_eq!(infer_provider_type("deepseek-r1"), Some("openai"));
        assert_eq!(infer_provider_type("deepseek-chat"), Some("openai"));
    }

    // ── OpenRouter slash format ──

    #[test]
    fn openrouter_anthropic_slash() {
        assert_eq!(
            infer_provider_type("anthropic/claude-opus-4-6"),
            Some("openrouter")
        );
    }

    #[test]
    fn openrouter_openai_slash() {
        assert_eq!(infer_provider_type("openai/gpt-4o"), Some("openrouter"));
    }

    #[test]
    fn openrouter_google_slash() {
        assert_eq!(
            infer_provider_type("google/gemini-3-pro"),
            Some("openrouter")
        );
    }

    #[test]
    fn openrouter_deepseek_slash() {
        assert_eq!(
            infer_provider_type("deepseek/deepseek-r1"),
            Some("openrouter")
        );
    }

    // ── Google Gemini models ──

    #[test]
    fn gemini_pro() {
        assert_eq!(infer_provider_type("gemini-2.5-pro"), Some("gemini"));
        assert_eq!(infer_provider_type("gemini-3-pro"), Some("gemini"));
    }

    #[test]
    fn gemini_flash() {
        assert_eq!(infer_provider_type("gemini-3-flash"), Some("gemini"));
    }

    // ── OpenAI o-series models ──

    #[test]
    fn openai_o_series() {
        assert_eq!(infer_provider_type("o1-preview"), Some("openai"));
        assert_eq!(infer_provider_type("o3-mini"), Some("openai"));
        assert_eq!(infer_provider_type("o4-mini"), Some("openai"));
    }

    // ── OpenAI-compatible providers ──

    #[test]
    fn grok_models() {
        assert_eq!(infer_provider_type("grok-4.1-fast"), Some("openai"));
    }

    #[test]
    fn mistral_models() {
        assert_eq!(infer_provider_type("mistral-large-latest"), Some("openai"));
    }

    #[test]
    fn llama_models() {
        assert_eq!(infer_provider_type("llama-3.1-405b"), Some("openai"));
    }

    // ── Unknown models ──

    #[test]
    fn unknown_model_returns_none() {
        assert_eq!(infer_provider_type("custom-model-v1"), None);
        assert_eq!(infer_provider_type("my-local-model"), None);
        assert_eq!(infer_provider_type("glm-5"), None);
    }
}

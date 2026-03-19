//! Provider type inference from model name prefixes.
//!
//! Enables smart pass-through routing: when a model is not explicitly
//! configured, grob infers the correct provider backend from the model
//! name prefix (e.g. `gpt-5.4` → `"openai"`, `claude-sonnet-4-6` → `"anthropic"`).

/// Infers the provider backend type from a model name.
///
/// Returns the canonical `provider_type` string that matches
/// `provider_type` values used in TOML `[[providers]]` configuration.
///
/// # Examples
///
/// ```
/// use grob::router::inference::infer_provider_type;
/// assert_eq!(infer_provider_type("gpt-5.4"), Some("openai"));
/// assert_eq!(infer_provider_type("claude-sonnet-4-6"), Some("anthropic"));
/// assert_eq!(infer_provider_type("anthropic/claude-opus-4-6"), Some("openrouter"));
/// ```
pub fn infer_provider_type(model: &str) -> Option<&'static str> {
    // "provider/model" format → OpenRouter
    if model.contains('/') {
        return Some("openrouter");
    }

    // Prefix matching against known provider families
    if model.starts_with("claude-") {
        return Some("anthropic");
    }
    if model.starts_with("gpt-")
        || model.starts_with("o1-")
        || model.starts_with("o3-")
        || model.starts_with("o4-")
    {
        return Some("openai");
    }
    if model.starts_with("gemini-") {
        return Some("gemini");
    }

    // OpenAI-compatible providers (all use the OpenAI chat/completions wire format)
    if model.starts_with("deepseek")
        || model.starts_with("grok-")
        || model.starts_with("mistral-")
        || model.starts_with("llama-")
    {
        return Some("openai");
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anthropic_models() {
        assert_eq!(infer_provider_type("claude-sonnet-4-6"), Some("anthropic"));
        assert_eq!(infer_provider_type("claude-opus-4-6"), Some("anthropic"));
        assert_eq!(
            infer_provider_type("claude-3-5-haiku-20241022"),
            Some("anthropic")
        );
    }

    #[test]
    fn openai_models() {
        assert_eq!(infer_provider_type("gpt-5.4"), Some("openai"));
        assert_eq!(infer_provider_type("gpt-5.3-codex"), Some("openai"));
        assert_eq!(infer_provider_type("gpt-4o"), Some("openai"));
        assert_eq!(infer_provider_type("o1-preview"), Some("openai"));
        assert_eq!(infer_provider_type("o3-mini"), Some("openai"));
        assert_eq!(infer_provider_type("o4-mini"), Some("openai"));
    }

    #[test]
    fn gemini_models() {
        assert_eq!(infer_provider_type("gemini-3-pro"), Some("gemini"));
        assert_eq!(infer_provider_type("gemini-3-flash"), Some("gemini"));
    }

    #[test]
    fn openai_compatible_models() {
        assert_eq!(infer_provider_type("deepseek-r1"), Some("openai"));
        assert_eq!(infer_provider_type("deepseek-chat"), Some("openai"));
        assert_eq!(infer_provider_type("grok-4.1-fast"), Some("openai"));
        assert_eq!(infer_provider_type("mistral-large-latest"), Some("openai"));
        assert_eq!(infer_provider_type("llama-3.1-405b"), Some("openai"));
    }

    #[test]
    fn openrouter_slash_format() {
        assert_eq!(
            infer_provider_type("anthropic/claude-opus-4-6"),
            Some("openrouter")
        );
        assert_eq!(infer_provider_type("openai/gpt-4o"), Some("openrouter"));
        assert_eq!(
            infer_provider_type("google/gemini-3-pro"),
            Some("openrouter")
        );
    }

    #[test]
    fn unknown_models() {
        assert_eq!(infer_provider_type("custom-model-v1"), None);
        assert_eq!(infer_provider_type("my-local-model"), None);
    }
}

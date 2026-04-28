//! TDD Tests - Provider Registry
//!
//! Tests for provider registration and selection.

#[cfg(test)]
mod tests {
    use grob::providers::{AuthType, ProviderConfig};
    use secrecy::SecretString;

    /// Test: Provider config enables by default
    #[test]
    fn test_provider_enabled_by_default() {
        let config = ProviderConfig {
            name: "test".to_string(),
            provider_type: "openai".to_string(),
            auth_type: AuthType::ApiKey,
            api_key: Some(SecretString::new("test-key".to_string())),
            oauth_provider: None,
            project_id: None,
            location: None,
            base_url: None,
            headers: None,
            models: vec![],
            enabled: None,
            budget_usd: None,
            region: None,
            pass_through: None,
            tls_cert: None,
            tls_key: None,
            tls_ca: None,
            pool: None,
            circuit_breaker: None,

            health_check: None,
        };

        assert!(config.is_enabled());
    }

    /// Test: Provider can be explicitly disabled
    #[test]
    fn test_provider_can_be_disabled() {
        let config = ProviderConfig {
            name: "test".to_string(),
            provider_type: "openai".to_string(),
            auth_type: AuthType::ApiKey,
            api_key: Some(SecretString::new("test-key".to_string())),
            oauth_provider: None,
            project_id: None,
            location: None,
            base_url: None,
            headers: None,
            models: vec![],
            enabled: Some(false),
            budget_usd: None,
            region: None,
            pass_through: None,
            tls_cert: None,
            tls_key: None,
            tls_ca: None,
            pool: None,
            circuit_breaker: None,

            health_check: None,
        };

        assert!(!config.is_enabled());
    }

    /// Regression: Z.ai PAYG / free-tier endpoint must be reachable through
    /// the standard `openai` provider type.
    ///
    /// Z.ai exposes two parallel endpoints:
    ///
    /// - `https://api.z.ai/api/anthropic` — Anthropic-compatible (Coding Plan), reached via `provider_type = "z.ai"`.
    /// - `https://api.z.ai/api/paas/v4`   — OpenAI-compatible (free tier / PAYG), reached via `provider_type = "openai"` + explicit `base_url`.
    ///
    /// The `ultra-cheap` preset uses the second path. This test parses the
    /// shipped TOML, asserts the `zai` provider entry survives parsing, and
    /// verifies the OpenAI-compat fingerprint (provider_type, base_url, GLM
    /// model list). It guards against accidental removal of the fields that
    /// route the request to `OpenAIProvider` — if someone refactored the
    /// registry to require a dedicated `glm`/`zai` provider type, this test
    /// would still expect the openai-compat path to keep working since the
    /// roadmap verdict (B-01) was: don't add a GLM-specific impl.
    #[test]
    fn ultra_cheap_preset_zai_uses_openai_compat() {
        // The preset ships in the source tree at `presets/ultra-cheap.toml`.
        // `CARGO_MANIFEST_DIR` is set to the package root by Cargo at build
        // time and is stable across `cargo test` / `cargo nextest run` /
        // workspace invocations.
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let preset_path = std::path::Path::new(manifest_dir).join("presets/ultra-cheap.toml");
        let toml_str = std::fs::read_to_string(&preset_path).unwrap_or_else(|e| {
            panic!(
                "presets/ultra-cheap.toml is shipped with the source tree (read {:?}): {}",
                preset_path, e
            )
        });

        let value: toml::Value = toml::from_str(&toml_str).expect("ultra-cheap.toml is valid TOML");

        let providers = value
            .get("providers")
            .and_then(|p| p.as_array())
            .expect("preset has [[providers]] entries");

        let zai = providers
            .iter()
            .find(|p| p.get("name").and_then(|n| n.as_str()) == Some("zai"))
            .expect("ultra-cheap preset declares a `zai` provider");

        assert_eq!(
            zai.get("provider_type").and_then(|t| t.as_str()),
            Some("openai"),
            "Z.ai free-tier path must use openai_compat — not a dedicated `z.ai` provider type"
        );
        assert_eq!(
            zai.get("base_url").and_then(|u| u.as_str()),
            Some("https://api.z.ai/api/paas/v4"),
            "Z.ai OpenAI-compat endpoint base URL is the canonical paas/v4 path"
        );

        let models: Vec<&str> = zai
            .get("models")
            .and_then(|m| m.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        assert!(
            models.iter().any(|m| m.starts_with("glm-")),
            "zai provider must list at least one GLM model (got: {:?})",
            models
        );
    }
}

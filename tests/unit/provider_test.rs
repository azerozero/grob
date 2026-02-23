//! TDD Tests - Provider Registry
//!
//! Tests for provider registration and selection.

#[cfg(test)]
mod tests {
    use grob::providers::{AuthType, ProviderConfig};

    /// Test: Provider config enables by default
    #[test]
    fn test_provider_enabled_by_default() {
        let config = ProviderConfig {
            name: "test".to_string(),
            provider_type: "openai".to_string(),
            auth_type: AuthType::ApiKey,
            api_key: Some("test-key".to_string()),
            oauth_provider: None,
            project_id: None,
            location: None,
            base_url: None,
            headers: None,
            models: vec![],
            enabled: None,
            budget_usd: None,
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
            api_key: Some("test-key".to_string()),
            oauth_provider: None,
            project_id: None,
            location: None,
            base_url: None,
            headers: None,
            models: vec![],
            enabled: Some(false),
            budget_usd: None,
        };

        assert!(!config.is_enabled());
    }
}

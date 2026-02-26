//! TDD Tests - Configuration parsing
//!
//! These tests demonstrate Test-Driven Development for config features.

#[cfg(test)]
mod tests {
    use grob::cli::{AppConfig, RouterConfig, ServerConfig};

    /// Test: Config parsing with default values
    /// RED: This test should fail initially (no default port defined)
    /// GREEN: Implement default port in ServerConfig
    #[test]
    fn test_default_server_config() {
        let config = ServerConfig::default();
        assert_eq!(config.port, 13456); // Expected default port
    }

    /// Test: Router config serialization
    #[test]
    fn test_router_config_serialization() {
        let config = RouterConfig {
            default: "test-model".to_string(),
            background: Some("bg-model".to_string()),
            think: Some("think-model".to_string()),
            websearch: Some("web-model".to_string()),
            auto_map_regex: Some("^claude-".to_string()),
            background_regex: Some("(?i)haiku".to_string()),
            prompt_rules: vec![],
            gdpr: false,
            region: None,
        };

        // Should serialize to TOML without panic
        let toml = toml::to_string(&config).unwrap();
        assert!(toml.contains("default = \"test-model\""));
    }

    /// Test: AppConfig creates default path
    #[test]
    fn test_app_config_default_path() {
        let path = AppConfig::default_path().expect("Should create default path");
        assert!(path.to_string_lossy().contains(".grob"));
    }

    /// Test: validate rejects invalid auth mode
    #[test]
    fn test_validate_rejects_invalid_auth_mode() {
        let toml = r#"
[server]
port = 8080

[router]
default = "test"

[auth]
mode = "kerberos"
"#;
        let result = AppConfig::from_content(toml, "test");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Invalid auth.mode"),
            "Expected auth mode error, got: {}",
            err
        );
    }

    /// Test: validate rejects fan_out strategy without fan_out config block
    #[test]
    fn test_validate_rejects_fan_out_without_config() {
        use grob::cli::{ModelConfig, ModelMapping, ModelStrategy};

        // Build config programmatically to avoid TOML parsing issues with nested arrays
        let config = AppConfig {
            server: ServerConfig::default(),
            router: RouterConfig {
                default: "my-model".to_string(),
                background: None,
                think: None,
                websearch: None,
                auto_map_regex: None,
                background_regex: None,
                prompt_rules: vec![],
                gdpr: false,
                region: None,
            },
            providers: vec![grob::providers::ProviderConfig {
                name: "prov1".to_string(),
                provider_type: "anthropic".to_string(),
                auth_type: grob::providers::AuthType::ApiKey,
                api_key: Some("sk-test".to_string()),
                base_url: None,
                models: vec![],
                enabled: Some(true),
                oauth_provider: None,
                project_id: None,
                location: None,
                headers: None,
                budget_usd: None,
                region: None,
            }],
            models: vec![ModelConfig {
                name: "my-model".to_string(),
                mappings: vec![ModelMapping {
                    priority: 1,
                    provider: "prov1".to_string(),
                    actual_model: "claude-3".to_string(),
                    inject_continuation_prompt: false,
                }],
                budget_usd: None,
                strategy: ModelStrategy::FanOut,
                fan_out: None, // Missing fan_out config!
                deprecated: None,
            }],
            presets: Default::default(),
            budget: Default::default(),
            dlp: Default::default(),
            auth: Default::default(),
            tap: Default::default(),
            security: Default::default(),
            cache: Default::default(),
            compliance: Default::default(),
            version: None,
            user: Default::default(),
        };

        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("fan_out"),
            "Expected fan_out config error, got: {}",
            err
        );
    }

    /// Test: validate passes valid config with fan_out config block present
    #[test]
    fn test_validate_passes_valid_fan_out_config() {
        use grob::cli::{FanOutConfig, FanOutMode, ModelConfig, ModelMapping, ModelStrategy};

        let config = AppConfig {
            server: ServerConfig::default(),
            router: RouterConfig {
                default: "my-model".to_string(),
                background: None,
                think: None,
                websearch: None,
                auto_map_regex: None,
                background_regex: None,
                prompt_rules: vec![],
                gdpr: false,
                region: None,
            },
            providers: vec![
                grob::providers::ProviderConfig {
                    name: "prov1".to_string(),
                    provider_type: "anthropic".to_string(),
                    auth_type: grob::providers::AuthType::ApiKey,
                    api_key: Some("sk-test".to_string()),
                    base_url: None,
                    models: vec![],
                    enabled: Some(true),
                    oauth_provider: None,
                    project_id: None,
                    location: None,
                    headers: None,
                    budget_usd: None,
                    region: None,
                },
                grob::providers::ProviderConfig {
                    name: "prov2".to_string(),
                    provider_type: "anthropic".to_string(),
                    auth_type: grob::providers::AuthType::ApiKey,
                    api_key: Some("sk-test2".to_string()),
                    base_url: None,
                    models: vec![],
                    enabled: Some(true),
                    oauth_provider: None,
                    project_id: None,
                    location: None,
                    headers: None,
                    budget_usd: None,
                    region: None,
                },
            ],
            models: vec![ModelConfig {
                name: "my-model".to_string(),
                mappings: vec![
                    ModelMapping {
                        priority: 1,
                        provider: "prov1".to_string(),
                        actual_model: "claude-3".to_string(),
                        inject_continuation_prompt: false,
                    },
                    ModelMapping {
                        priority: 2,
                        provider: "prov2".to_string(),
                        actual_model: "claude-3".to_string(),
                        inject_continuation_prompt: false,
                    },
                ],
                budget_usd: None,
                strategy: ModelStrategy::FanOut,
                fan_out: Some(FanOutConfig {
                    mode: FanOutMode::Fastest,
                    judge_model: None,
                    judge_criteria: None,
                    count: None,
                }),
                deprecated: None,
            }],
            presets: Default::default(),
            budget: Default::default(),
            dlp: Default::default(),
            auth: Default::default(),
            tap: Default::default(),
            security: Default::default(),
            cache: Default::default(),
            compliance: Default::default(),
            version: None,
            user: Default::default(),
        };

        let result = config.validate();
        assert!(
            result.is_ok(),
            "Expected valid config, got: {:?}",
            result.err()
        );
    }

    /// Test: validate passes a fully valid config
    #[test]
    fn test_validate_passes_valid_config() {
        let config = AppConfig {
            server: ServerConfig {
                port: 8080,
                ..Default::default()
            },
            router: RouterConfig {
                default: "my-model".to_string(),
                background: None,
                think: None,
                websearch: None,
                auto_map_regex: None,
                background_regex: None,
                prompt_rules: vec![],
                gdpr: false,
                region: None,
            },
            providers: vec![grob::providers::ProviderConfig {
                name: "prov1".to_string(),
                provider_type: "anthropic".to_string(),
                auth_type: grob::providers::AuthType::ApiKey,
                api_key: Some("sk-test".to_string()),
                base_url: None,
                models: vec![],
                enabled: Some(true),
                oauth_provider: None,
                project_id: None,
                location: None,
                headers: None,
                budget_usd: None,
                region: None,
            }],
            models: vec![],
            presets: Default::default(),
            budget: Default::default(),
            dlp: Default::default(),
            auth: Default::default(),
            tap: Default::default(),
            security: Default::default(),
            cache: Default::default(),
            compliance: Default::default(),
            version: None,
            user: Default::default(),
        };

        let result = config.validate();
        assert!(
            result.is_ok(),
            "Expected valid config, got: {:?}",
            result.err()
        );
    }
}

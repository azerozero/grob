//! TDD Tests - Configuration parsing
//!
//! These tests demonstrate Test-Driven Development for config features.

#[cfg(test)]
mod tests {
    use grob::cli::{AppConfig, Port, RouterConfig, ServerConfig};

    /// Test: Config parsing with default values
    /// RED: This test should fail initially (no default port defined)
    /// GREEN: Implement default port in ServerConfig
    #[test]
    fn test_default_server_config() {
        let config = ServerConfig::default();
        assert_eq!(config.port.value(), 13456); // Expected default port
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
        use crate::helpers::fixtures::{base_provider_config, test_app_config};
        use grob::cli::{ModelConfig, ModelMapping, ModelStrategy};

        let config = AppConfig {
            router: RouterConfig {
                default: "my-model".to_string(),
                ..test_app_config().router
            },
            providers: vec![base_provider_config("prov1")],
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
            #[cfg(feature = "mcp")]
            mcp: Default::default(),
            ..test_app_config()
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
        use crate::helpers::fixtures::{base_provider_config, test_app_config};
        use grob::cli::{FanOutConfig, FanOutMode, ModelConfig, ModelMapping, ModelStrategy};

        let mut prov2 = base_provider_config("prov2");
        prov2.api_key = Some(secrecy::SecretString::new("sk-test2".to_string()));

        let config = AppConfig {
            router: RouterConfig {
                default: "my-model".to_string(),
                ..test_app_config().router
            },
            providers: vec![base_provider_config("prov1"), prov2],
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
            #[cfg(feature = "mcp")]
            mcp: Default::default(),
            ..test_app_config()
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
        use crate::helpers::fixtures::{base_provider_config, test_app_config};

        let config = AppConfig {
            server: ServerConfig {
                port: Port::new(8080).unwrap(),
                ..Default::default()
            },
            router: RouterConfig {
                default: "my-model".to_string(),
                ..test_app_config().router
            },
            providers: vec![base_provider_config("prov1")],
            #[cfg(feature = "mcp")]
            mcp: Default::default(),
            ..test_app_config()
        };

        let result = config.validate();
        assert!(
            result.is_ok(),
            "Expected valid config, got: {:?}",
            result.err()
        );
    }
}

#[cfg(test)]
mod tier_tests {
    use grob::cli::{AppConfig, TierConfig};

    #[test]
    fn test_tier_config_toml_round_trip() {
        let toml_input = r#"
[server]
port = 8080

[router]
default = "test-model"

[[tiers]]
name = "trivial"
providers = ["fast-prov"]

[[tiers]]
name = "medium"
providers = ["balanced-prov"]

[[tiers]]
name = "complex"
providers = ["strong-prov", "backup-prov"]
fanout = true
"#;
        let config = AppConfig::from_content(toml_input, "test").unwrap();
        assert_eq!(config.tiers.len(), 3);
        assert_eq!(config.tiers[0].name, "trivial");
        assert_eq!(config.tiers[0].providers, vec!["fast-prov"]);
        assert!(!config.tiers[0].fanout);
        assert_eq!(config.tiers[2].name, "complex");
        assert!(config.tiers[2].fanout);
    }

    #[test]
    fn test_tier_config_empty_is_default() {
        let toml_input = r#"
[server]
port = 8080

[router]
default = "test-model"
"#;
        let config = AppConfig::from_content(toml_input, "test").unwrap();
        assert!(
            config.tiers.is_empty(),
            "No [[tiers]] should yield empty vec"
        );
    }

    #[test]
    fn test_tier_config_single_tier() {
        let toml_input = r#"
[server]
port = 8080

[router]
default = "test-model"

[[tiers]]
name = "trivial"
providers = ["cheap-provider"]
"#;
        let config = AppConfig::from_content(toml_input, "test").unwrap();
        assert_eq!(config.tiers.len(), 1);
        assert_eq!(config.tiers[0].name, "trivial");
    }

    #[test]
    fn test_tier_config_serialization() {
        let tier = TierConfig {
            name: "complex".to_string(),
            providers: vec!["prov-a".to_string(), "prov-b".to_string()],
            fanout: true,
            match_conditions: None,
        };
        let toml = toml::to_string(&tier).unwrap();
        assert!(toml.contains("name = \"complex\""));
        assert!(toml.contains("fanout = true"));
    }

    #[test]
    fn test_classifier_config_toml_round_trip() {
        let toml_str = r#"
[server]
port = 8080

[router]
default = "my-model"

[classifier]
[classifier.weights]
max_tokens = 2.0
tools = 0.5
context_size = 1.0
keywords = 1.5
system_prompt = 0.0

[classifier.thresholds]
medium_threshold = 3.0
complex_threshold = 7.0
        "#;

        let config = AppConfig::from_content(toml_str, "test").unwrap();
        let c = config.classifier.expect("classifier must be present");
        assert!((c.weights.max_tokens - 2.0).abs() < f32::EPSILON);
        assert!((c.weights.tools - 0.5).abs() < f32::EPSILON);
        assert!((c.weights.system_prompt).abs() < f32::EPSILON);
        assert!((c.thresholds.medium_threshold - 3.0).abs() < f32::EPSILON);
        assert!((c.thresholds.complex_threshold - 7.0).abs() < f32::EPSILON);
    }

    #[test]
    fn test_classifier_absent_uses_defaults() {
        let toml_str = r#"
[server]
port = 8080

[router]
default = "my-model"
        "#;

        let config = AppConfig::from_content(toml_str, "test").unwrap();
        assert!(config.classifier.is_none());
    }
}

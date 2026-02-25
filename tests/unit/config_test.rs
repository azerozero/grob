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
}

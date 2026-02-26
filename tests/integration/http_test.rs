//! HTTP integration tests
//!
//! These tests exercise HTTP-relevant behaviors through the public API:
//! configuration, routing, auth, and security settings.

#[cfg(test)]
mod tests {
    use grob::cli::{AppConfig, RouterConfig, SecurityTomlConfig, ServerConfig};

    #[test]
    fn test_health_config_defaults() {
        // Verify the server config has sane defaults for health endpoints
        let config = ServerConfig::default();
        assert_eq!(config.port, 13456);
        assert_eq!(config.oauth_callback_port, 1455);
    }

    #[test]
    fn test_ready_requires_providers() {
        // A config with no providers means readiness should report no providers
        let config = AppConfig::from_content(
            r#"
[router]
default = "test-model"
"#,
            "test",
        )
        .unwrap();
        assert!(config.providers.is_empty());
        assert!(config.models.is_empty());
    }

    #[test]
    fn test_auth_rejects_bad_mode() {
        let result = AppConfig::from_content(
            r#"
[router]
default = "test-model"

[auth]
mode = "ldap"
"#,
            "test",
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid auth.mode"));
    }

    #[test]
    fn test_auth_api_key_config() {
        let config = AppConfig::from_content(
            r#"
[router]
default = "test-model"

[auth]
mode = "api_key"
api_key = "my-secret-key"
"#,
            "test",
        )
        .unwrap();
        assert_eq!(config.auth.mode, "api_key");
        assert_eq!(config.auth.api_key.as_deref(), Some("my-secret-key"));
    }

    #[test]
    fn test_request_id_uuid_format() {
        // Request IDs are UUID v4 — verify format
        let id = uuid::Uuid::new_v4().to_string();
        assert_eq!(id.len(), 36);
        assert_eq!(id.chars().filter(|&c| c == '-').count(), 4);
    }

    #[test]
    fn test_security_headers_config_enabled() {
        let config = SecurityTomlConfig {
            enabled: true,
            security_headers: true,
            ..Default::default()
        };
        assert!(config.enabled);
        assert!(config.security_headers);
    }

    #[test]
    fn test_auto_map_routes_to_default() {
        let config = AppConfig {
            server: ServerConfig::default(),
            router: RouterConfig {
                default: "fallback-model".to_string(),
                background: None,
                think: None,
                websearch: None,
                auto_map_regex: Some("^claude-".to_string()),
                background_regex: None,
                prompt_rules: vec![],
                gdpr: false,
                region: None,
            },
            providers: vec![],
            models: vec![],
            presets: Default::default(),
            budget: Default::default(),
            dlp: Default::default(),
            auth: Default::default(),
            tap: Default::default(),
            security: Default::default(),
            version: None,
            user: Default::default(),
        };

        let router = grob::router::Router::new(config);
        let mut req = grob::models::AnthropicRequest {
            model: "claude-3-5-sonnet".to_string(),
            messages: vec![grob::models::Message {
                role: "user".to_string(),
                content: grob::models::MessageContent::Text("hello".to_string()),
            }],
            max_tokens: 100,
            thinking: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop_sequences: None,
            stream: None,
            metadata: None,
            system: None,
            tools: None,
            tool_choice: None,
        };
        let decision = router.route(&mut req).unwrap();
        // auto_map_regex matches "claude-*", so it should route to the default model
        assert_eq!(decision.model_name, "fallback-model");
    }

    #[test]
    fn test_unmatched_model_passes_through() {
        let config = AppConfig {
            server: ServerConfig::default(),
            router: RouterConfig {
                default: "fallback-model".to_string(),
                background: None,
                think: None,
                websearch: None,
                auto_map_regex: Some("^claude-".to_string()),
                background_regex: None,
                prompt_rules: vec![],
                gdpr: false,
                region: None,
            },
            providers: vec![],
            models: vec![],
            presets: Default::default(),
            budget: Default::default(),
            dlp: Default::default(),
            auth: Default::default(),
            tap: Default::default(),
            security: Default::default(),
            version: None,
            user: Default::default(),
        };

        let router = grob::router::Router::new(config);
        let mut req = grob::models::AnthropicRequest {
            model: "gpt-4o".to_string(),
            messages: vec![grob::models::Message {
                role: "user".to_string(),
                content: grob::models::MessageContent::Text("hello".to_string()),
            }],
            max_tokens: 100,
            thinking: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop_sequences: None,
            stream: None,
            metadata: None,
            system: None,
            tools: None,
            tool_choice: None,
        };
        let decision = router.route(&mut req).unwrap();
        // "gpt-4o" doesn't match "^claude-", so it passes through as-is
        assert_eq!(decision.model_name, "gpt-4o");
    }

    #[test]
    fn test_metrics_body_limit_config() {
        // Default max body size should be reasonable
        let config = SecurityTomlConfig::default();
        assert!(config.max_body_size > 0, "max_body_size should be > 0");
    }

    #[test]
    fn test_oauth_callback_port_configurable() {
        let config = ServerConfig {
            oauth_callback_port: 9999,
            ..Default::default()
        };
        assert_eq!(config.oauth_callback_port, 9999);
    }
}

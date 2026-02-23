//! Unit tests for the Router module

mod tests {
    use grob::cli::{AppConfig, RouterConfig, ServerConfig};
    use grob::models::{AnthropicRequest, Message, MessageContent, RouteType, ThinkingConfig};
    use grob::router::Router;

    fn create_test_config() -> AppConfig {
        AppConfig {
            server: ServerConfig::default(),
            router: RouterConfig {
                default: "default.model".to_string(),
                background: Some("background.model".to_string()),
                think: Some("think.model".to_string()),
                websearch: Some("websearch.model".to_string()),
                auto_map_regex: Some("^claude-".to_string()),
                background_regex: Some("(?i)claude.*haiku".to_string()),
                prompt_rules: vec![],
            },
            providers: vec![],
            models: vec![],
            presets: Default::default(),
        }
    }

    fn create_simple_request(text: &str) -> AnthropicRequest {
        AnthropicRequest {
            model: "claude-opus-4".to_string(),
            messages: vec![Message {
                role: "user".to_string(),
                content: MessageContent::Text(text.to_string()),
            }],
            max_tokens: 1024,
            thinking: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop_sequences: None,
            stream: None,
            metadata: None,
            system: None,
            tools: None,
        }
    }

    #[test]
    fn test_default_routing() {
        let config = create_test_config();
        let router = Router::new(config);

        let mut request = create_simple_request("Write a function to sort an array");
        let decision = router.route(&mut request).unwrap();

        assert_eq!(decision.route_type, RouteType::Default);
        assert_eq!(decision.model_name, "default.model");
    }

    #[test]
    fn test_plan_mode_detection() {
        let config = create_test_config();
        let router = Router::new(config);

        let mut request = create_simple_request("Explain quantum computing");
        request.thinking = Some(ThinkingConfig {
            r#type: "enabled".to_string(),
            budget_tokens: Some(10_000),
        });

        let decision = router.route(&mut request).unwrap();
        assert_eq!(decision.route_type, RouteType::Think);
        assert_eq!(decision.model_name, "think.model");
    }

    #[test]
    fn test_background_task_detection() {
        let config = create_test_config();
        let router = Router::new(config);

        // Create request with haiku model
        let mut request = create_simple_request("Hello");
        request.model = "claude-3-5-haiku-20241022".to_string();

        let decision = router.route(&mut request).unwrap();
        assert_eq!(decision.route_type, RouteType::Background);
        assert_eq!(decision.model_name, "background.model");
    }

    #[test]
    fn test_websearch_tool_detection() {
        use grob::models::Tool;

        let config = create_test_config();
        let router = Router::new(config);

        let mut request = create_simple_request("Search the web for latest news");
        request.tools = Some(vec![Tool {
            r#type: Some("web_search_2025_04".to_string()),
            name: Some("web_search".to_string()),
            description: Some("Search the web".to_string()),
            input_schema: Some(serde_json::json!({
                "type": "object",
                "properties": {}
            })),
        }]);

        let decision = router.route(&mut request).unwrap();
        assert_eq!(decision.route_type, RouteType::WebSearch);
        assert_eq!(decision.model_name, "websearch.model");
    }

    #[test]
    fn test_websearch_has_highest_priority() {
        use grob::models::Tool;

        let config = create_test_config();
        let router = Router::new(config);

        // WebSearch should win even if thinking is enabled
        let mut request = create_simple_request("Search and explain");
        request.thinking = Some(ThinkingConfig {
            r#type: "enabled".to_string(),
            budget_tokens: Some(10_000),
        });
        request.tools = Some(vec![Tool {
            r#type: Some("web_search".to_string()),
            name: None,
            description: None,
            input_schema: None,
        }]);

        let decision = router.route(&mut request).unwrap();
        assert_eq!(decision.route_type, RouteType::WebSearch);
        assert_eq!(decision.model_name, "websearch.model");
    }

    #[test]
    fn test_auto_map_claude_models() {
        let config = create_test_config();
        let router = Router::new(config);

        // Test Claude model auto-mapping (default pattern)
        let mut request = create_simple_request("Hello");
        request.model = "claude-3-5-sonnet-20241022".to_string();

        let decision = router.route(&mut request).unwrap();
        assert_eq!(decision.route_type, RouteType::Default);
        assert_eq!(decision.model_name, "default.model");
    }

    #[test]
    fn test_auto_map_custom_regex() {
        let mut config = create_test_config();
        config.router.auto_map_regex = Some("^(claude-|gpt-)".to_string());
        let router = Router::new(config);

        // Test GPT model auto-mapping with custom regex
        let mut request = create_simple_request("Hello");
        request.model = "gpt-4".to_string();

        let decision = router.route(&mut request).unwrap();
        assert_eq!(decision.route_type, RouteType::Default);
        assert_eq!(decision.model_name, "default.model");
    }

    #[test]
    fn test_no_auto_map_non_matching() {
        let config = create_test_config();
        let router = Router::new(config);

        // Test non-Claude model (should not auto-map, use model name as-is)
        let mut request = create_simple_request("Hello");
        request.model = "glm-4.6".to_string();

        let decision = router.route(&mut request).unwrap();
        assert_eq!(decision.route_type, RouteType::Default);
        assert_eq!(decision.model_name, "glm-4.6");
    }

    #[test]
    fn test_routing_priority() {
        let config = create_test_config();
        let router = Router::new(config);

        // Think has highest priority
        let mut request = create_simple_request("Explain complex topic");
        request.thinking = Some(ThinkingConfig {
            r#type: "enabled".to_string(),
            budget_tokens: Some(10_000),
        });

        let decision = router.route(&mut request).unwrap();
        assert_eq!(decision.route_type, RouteType::Think);
    }

    #[test]
    fn test_disabled_background_routing() {
        let mut config = create_test_config();
        config.router.background = None;
        let router = Router::new(config);

        let mut request = create_simple_request("Hello");
        request.model = "claude-3-5-haiku-20241022".to_string();

        let decision = router.route(&mut request).unwrap();
        // Should use default model since background is disabled
        assert_eq!(decision.route_type, RouteType::Default);
    }
}

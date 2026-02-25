//! Test fixtures for Claude Code Mux

use grob::models::{AnthropicRequest, Message, MessageContent, ThinkingConfig};

/// Creates a simple Anthropic request for testing
pub fn create_test_request(model: &str, text: &str) -> AnthropicRequest {
    AnthropicRequest {
        model: model.to_string(),
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

/// Creates an Anthropic request with thinking enabled (Plan Mode)
pub fn create_thinking_request(model: &str, text: &str) -> AnthropicRequest {
    AnthropicRequest {
        model: model.to_string(),
        messages: vec![Message {
            role: "user".to_string(),
            content: MessageContent::Text(text.to_string()),
        }],
        max_tokens: 1024,
        thinking: Some(ThinkingConfig {
            r#type: "enabled".to_string(),
            budget_tokens: Some(10_000),
        }),
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

/// Creates a request with web_search tool
pub fn create_websearch_request(model: &str, text: &str) -> AnthropicRequest {
    use grob::models::Tool;

    AnthropicRequest {
        model: model.to_string(),
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
        tools: Some(vec![Tool {
            r#type: Some("web_search_2025_04".to_string()),
            name: Some("web_search".to_string()),
            description: Some("Search the web".to_string()),
            input_schema: Some(serde_json::json!({
                "type": "object",
                "properties": {}
            })),
        }]),
    }
}

/// Test configuration for router
pub fn test_router_config() -> grob::cli::RouterConfig {
    use grob::cli::RouterConfig;

    RouterConfig {
        default: "default-model".to_string(),
        background: Some("background-model".to_string()),
        think: Some("think-model".to_string()),
        websearch: Some("websearch-model".to_string()),
        auto_map_regex: Some("^claude-".to_string()),
        background_regex: Some("(?i)claude.*haiku".to_string()),
        prompt_rules: vec![],
    }
}

/// Creates test AppConfig
pub fn test_app_config() -> grob::cli::AppConfig {
    use grob::cli::{AppConfig, ServerConfig};

    AppConfig {
        server: ServerConfig::default(),
        router: test_router_config(),
        providers: vec![],
        models: vec![],
        presets: Default::default(),
        budget: Default::default(),
        dlp: Default::default(),
        auth: Default::default(),
        tap: Default::default(),
    }
}

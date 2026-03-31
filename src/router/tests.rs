use super::*;
use crate::cli::{RouterConfig, ServerConfig};
use crate::models::{Message, MessageContent, ThinkingConfig};

fn create_test_config() -> AppConfig {
    AppConfig {
        server: ServerConfig::default(),
        router: RouterConfig {
            default: "default.model".to_string(),
            background: Some("background.model".to_string()),
            think: Some("think.model".to_string()),
            websearch: Some("websearch.model".to_string()),
            auto_map_regex: None,   // Use default Claude pattern
            background_regex: None, // Use default claude-haiku pattern
            prompt_rules: vec![],   // No prompt rules by default
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
        user: Default::default(),
        version: None,
        security: Default::default(),
        cache: Default::default(),
        compliance: Default::default(),
        otel: Default::default(),
        log_export: Default::default(),
        pledge: Default::default(),
        policies: vec![],
        #[cfg(feature = "mcp")]
        mcp: Default::default(),
        tool_layer: Default::default(),
        tee: Default::default(),
        fips: Default::default(),
        #[cfg(feature = "harness")]
        harness: Default::default(),
    }
}

fn create_simple_request(text: &str) -> CanonicalRequest {
    CanonicalRequest {
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
        tool_choice: None,
        extensions: Default::default(),
    }
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
fn test_default_routing() {
    let mut config = create_test_config();
    config.router.background = None; // Disable background routing
    let router = Router::new(config);

    let mut request = create_simple_request("Write a function to sort an array");

    let decision = router.route(&mut request).unwrap();
    assert_eq!(decision.route_type, RouteType::Default);
    assert_eq!(decision.model_name, "default.model");
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
    assert_eq!(decision.route_type, RouteType::Think); // Think wins
}

#[test]
fn test_websearch_tool_detection() {
    let config = create_test_config();
    let router = Router::new(config);

    let mut request = create_simple_request("Search the web for latest news");
    request.tools = Some(vec![crate::models::Tool {
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
    let config = create_test_config();
    let router = Router::new(config);

    // WebSearch should win even if thinking is enabled
    let mut request = create_simple_request("Search and explain");
    request.thinking = Some(ThinkingConfig {
        r#type: "enabled".to_string(),
        budget_tokens: Some(10_000),
    });
    request.tools = Some(vec![crate::models::Tool {
        r#type: Some("web_search".to_string()),
        name: None,
        description: None,
        input_schema: None,
    }]);

    let decision = router.route(&mut request).unwrap();
    assert_eq!(decision.route_type, RouteType::WebSearch); // WebSearch wins over Think
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
    assert_eq!(decision.model_name, "default.model"); // Auto-mapped to default
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
    assert_eq!(decision.model_name, "default.model"); // Auto-mapped to default
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
    assert_eq!(decision.model_name, "glm-4.6"); // Uses original model name (no auto-mapping)
}

#[test]
fn test_prompt_rule_matching() {
    use crate::cli::PromptRule;
    let mut config = create_test_config();
    config.router.prompt_rules = vec![PromptRule {
        pattern: "(?i)commit.*changes".to_string(),
        model: "fast-model".to_string(),
        strip_match: false,
    }];
    let router = Router::new(config);

    let mut request = create_simple_request("Please commit these changes");
    let decision = router.route(&mut request).unwrap();
    assert_eq!(decision.route_type, RouteType::PromptRule);
    assert_eq!(decision.model_name, "fast-model");
}

#[test]
fn test_prompt_rule_strip_match() {
    use crate::cli::PromptRule;
    let mut config = create_test_config();
    config.router.prompt_rules = vec![PromptRule {
        pattern: r"\[fast\]".to_string(),
        model: "fast-model".to_string(),
        strip_match: true,
    }];
    let router = Router::new(config);

    let mut request = create_simple_request("[fast] Write a function to sort an array");
    let decision = router.route(&mut request).unwrap();
    assert_eq!(decision.route_type, RouteType::PromptRule);
    assert_eq!(decision.model_name, "fast-model");

    // Verify the matched phrase was stripped from the prompt
    if let MessageContent::Text(text) = &request.messages[0].content {
        assert_eq!(text, " Write a function to sort an array");
        assert!(!text.contains("[fast]"));
    } else {
        panic!("Expected text content");
    }
}

#[test]
fn test_prompt_rule_no_strip_match() {
    use crate::cli::PromptRule;
    let mut config = create_test_config();
    config.router.prompt_rules = vec![PromptRule {
        pattern: r"\[fast\]".to_string(),
        model: "fast-model".to_string(),
        strip_match: false,
    }];
    let router = Router::new(config);

    let mut request = create_simple_request("[fast] Write a function to sort an array");
    let decision = router.route(&mut request).unwrap();
    assert_eq!(decision.route_type, RouteType::PromptRule);
    assert_eq!(decision.model_name, "fast-model");

    // Verify the matched phrase was NOT stripped (strip_match = false)
    if let MessageContent::Text(text) = &request.messages[0].content {
        assert!(text.contains("[fast]"));
    } else {
        panic!("Expected text content");
    }
}

#[test]
fn test_prompt_rule_dynamic_model_numeric() {
    use crate::cli::PromptRule;
    let mut config = create_test_config();
    config.router.prompt_rules = vec![PromptRule {
        pattern: r"(?i)GROB-MODEL:([a-zA-Z0-9._-]+)".to_string(),
        model: "$1".to_string(),
        strip_match: true,
    }];
    let router = Router::new(config);

    let mut request = create_simple_request("GROB-MODEL:deepseek-v3 Write a function");
    let decision = router.route(&mut request).unwrap();
    assert_eq!(decision.route_type, RouteType::PromptRule);
    assert_eq!(decision.model_name, "deepseek-v3");

    // Verify strip worked
    if let MessageContent::Text(text) = &request.messages[0].content {
        assert!(!text.contains("GROB-MODEL"));
        assert!(text.contains("Write a function"));
    } else {
        panic!("Expected text content");
    }
}

#[test]
fn test_prompt_rule_dynamic_model_named() {
    use crate::cli::PromptRule;
    let mut config = create_test_config();
    config.router.prompt_rules = vec![PromptRule {
        pattern: r"(?i)USE-MODEL:(?P<model>[a-zA-Z0-9._-]+)".to_string(),
        model: "$model".to_string(),
        strip_match: true,
    }];
    let router = Router::new(config);

    let mut request = create_simple_request("USE-MODEL:gpt-4o please help");
    let decision = router.route(&mut request).unwrap();
    assert_eq!(decision.route_type, RouteType::PromptRule);
    assert_eq!(decision.model_name, "gpt-4o");
}

#[test]
fn test_prompt_rule_dynamic_model_with_prefix() {
    use crate::cli::PromptRule;
    let mut config = create_test_config();
    config.router.prompt_rules = vec![PromptRule {
        pattern: r"@(\w+)-mode".to_string(),
        model: "provider-$1".to_string(),
        strip_match: false,
    }];
    let router = Router::new(config);

    let mut request = create_simple_request("@fast-mode explain this");
    let decision = router.route(&mut request).unwrap();
    assert_eq!(decision.route_type, RouteType::PromptRule);
    assert_eq!(decision.model_name, "provider-fast");
}

#[test]
fn test_prompt_rule_static_model_unchanged() {
    // Ensure existing static behavior is preserved (no $ references)
    use crate::cli::PromptRule;
    let mut config = create_test_config();
    config.router.prompt_rules = vec![PromptRule {
        pattern: r"\[static\]".to_string(),
        model: "static-model".to_string(), // No $ references
        strip_match: true,
    }];
    let router = Router::new(config);

    let mut request = create_simple_request("[static] do something");
    let decision = router.route(&mut request).unwrap();
    assert_eq!(decision.route_type, RouteType::PromptRule);
    assert_eq!(decision.model_name, "static-model");
}

#[test]
fn test_contains_capture_reference() {
    assert!(super::rules::contains_capture_reference("$1"));
    assert!(super::rules::contains_capture_reference("$model"));
    assert!(super::rules::contains_capture_reference("${1}"));
    assert!(super::rules::contains_capture_reference("${name}"));
    assert!(super::rules::contains_capture_reference("prefix-$1-suffix"));
    assert!(!super::rules::contains_capture_reference("static-model"));
    assert!(!super::rules::contains_capture_reference("no-refs-here"));
}

#[test]
fn test_prompt_rule_persists_through_tool_calls() {
    // Test that prompt phrases "stick" for the entire turn, even after tool calls
    use crate::cli::PromptRule;
    use crate::models::{ContentBlock, KnownContentBlock, ToolResultContent};

    let mut config = create_test_config();
    config.router.prompt_rules = vec![PromptRule {
        pattern: r"(?i)OPUS".to_string(),
        model: "opus-model".to_string(),
        strip_match: false,
    }];
    let router = Router::new(config);

    // Simulate a turn with tool calls:
    // 1. User: "OPUS write me a test suite"
    // 2. Assistant: [tool_use: Read]
    // 3. User: [tool_result: file contents]
    let mut request = CanonicalRequest {
        model: "claude-opus-4".to_string(),
        messages: vec![
            // Turn-starting user message with prompt phrase
            Message {
                role: "user".to_string(),
                content: MessageContent::Text("OPUS write me a test suite".to_string()),
            },
            // Assistant response with tool_use
            Message {
                role: "assistant".to_string(),
                content: MessageContent::Blocks(vec![ContentBlock::Known(
                    KnownContentBlock::ToolUse {
                        id: "tool_1".to_string(),
                        name: "Read".to_string(),
                        input: serde_json::json!({"file_path": "/src/main.rs"}),
                    },
                )]),
            },
            // User message with only tool_result (no text)
            Message {
                role: "user".to_string(),
                content: MessageContent::Blocks(vec![ContentBlock::Known(
                    KnownContentBlock::ToolResult {
                        tool_use_id: "tool_1".to_string(),
                        content: ToolResultContent::Text("fn main() {}".to_string()),
                        is_error: false,
                        cache_control: None,
                    },
                )]),
            },
        ],
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
        tool_choice: None,
        extensions: Default::default(),
    };

    let decision = router.route(&mut request).unwrap();
    // Should match the "OPUS" from the turn-starting message, not the tool_result
    assert_eq!(decision.route_type, RouteType::PromptRule);
    assert_eq!(decision.model_name, "opus-model");
}

#[test]
fn test_prompt_rule_resets_after_turn_ends() {
    // Test that prompt phrases reset when a new turn starts
    // (after an assistant message without tool_use)
    use crate::cli::PromptRule;

    let mut config = create_test_config();
    config.router.prompt_rules = vec![PromptRule {
        pattern: r"(?i)OPUS".to_string(),
        model: "opus-model".to_string(),
        strip_match: false,
    }];
    let router = Router::new(config);

    // Simulate two turns:
    // Turn 1: User: "OPUS write me tests" -> Assistant: "Here are the tests..."
    // Turn 2: User: "Now add documentation" (no OPUS)
    let mut request = CanonicalRequest {
        model: "claude-opus-4".to_string(),
        messages: vec![
            // Turn 1: User with OPUS
            Message {
                role: "user".to_string(),
                content: MessageContent::Text("OPUS write me tests".to_string()),
            },
            // Turn 1: Assistant response (text only, no tool_use - ends the turn)
            Message {
                role: "assistant".to_string(),
                content: MessageContent::Text("Here are the tests...".to_string()),
            },
            // Turn 2: User without OPUS (new turn)
            Message {
                role: "user".to_string(),
                content: MessageContent::Text("Now add documentation".to_string()),
            },
        ],
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
        tool_choice: None,
        extensions: Default::default(),
    };

    let decision = router.route(&mut request).unwrap();
    // Should NOT match "OPUS" because it was in the previous turn
    // The current turn started with "Now add documentation"
    assert_eq!(decision.route_type, RouteType::Default);
    assert_eq!(decision.model_name, "default.model");
}

#[test]
fn test_prompt_rule_strip_match_in_multi_turn() {
    // Test that strip_match works on the turn-starting message in a multi-message turn
    use crate::cli::PromptRule;
    use crate::models::{ContentBlock, KnownContentBlock, ToolResultContent};

    let mut config = create_test_config();
    config.router.prompt_rules = vec![PromptRule {
        pattern: r"\[OPUS\]".to_string(),
        model: "opus-model".to_string(),
        strip_match: true,
    }];
    let router = Router::new(config);

    let mut request = CanonicalRequest {
        model: "claude-opus-4".to_string(),
        messages: vec![
            // Turn-starting message with [OPUS] tag
            Message {
                role: "user".to_string(),
                content: MessageContent::Text("[OPUS] write me tests".to_string()),
            },
            // Assistant with tool_use
            Message {
                role: "assistant".to_string(),
                content: MessageContent::Blocks(vec![ContentBlock::Known(
                    KnownContentBlock::ToolUse {
                        id: "tool_1".to_string(),
                        name: "Read".to_string(),
                        input: serde_json::json!({}),
                    },
                )]),
            },
            // User with tool_result
            Message {
                role: "user".to_string(),
                content: MessageContent::Blocks(vec![ContentBlock::Known(
                    KnownContentBlock::ToolResult {
                        tool_use_id: "tool_1".to_string(),
                        content: ToolResultContent::Text("content".to_string()),
                        is_error: false,
                        cache_control: None,
                    },
                )]),
            },
        ],
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
        tool_choice: None,
        extensions: Default::default(),
    };

    let decision = router.route(&mut request).unwrap();
    assert_eq!(decision.route_type, RouteType::PromptRule);
    assert_eq!(decision.model_name, "opus-model");

    // Verify [OPUS] was stripped from the first (turn-starting) message
    if let MessageContent::Text(text) = &request.messages[0].content {
        assert!(!text.contains("[OPUS]"));
        assert!(text.contains("write me tests"));
    } else {
        panic!("Expected text content in first message");
    }
}

// ---------- extract_trailing_literal_byte ----------

#[test]
fn trailing_literal_basic_extraction() {
    // "haiku" is ≥ 3 alpha chars at end → first byte lowered = b'h'
    assert_eq!(
        extract_trailing_literal_byte("(?i)claude.*haiku"),
        Some(b'h')
    );
}

#[test]
fn trailing_literal_with_dollar_anchor() {
    // Trailing '$' should be stripped, then "haiku" extracted.
    assert_eq!(extract_trailing_literal_byte("(?i)haiku$"), Some(b'h'));
    assert_eq!(extract_trailing_literal_byte("(?i)haiku$$"), Some(b'h'));
}

#[test]
fn trailing_literal_only_dollars() {
    // Pattern is just "$" — after stripping, end == 0 → None.
    assert_eq!(extract_trailing_literal_byte("$"), None);
    assert_eq!(extract_trailing_literal_byte("$$"), None);
}

#[test]
fn trailing_literal_non_alpha_last_char() {
    // Last char before anchor is not alphabetic → None.
    assert_eq!(extract_trailing_literal_byte("foo.*[0-9]"), None);
    assert_eq!(extract_trailing_literal_byte("abc123"), None);
}

#[test]
fn trailing_literal_too_short() {
    // Alphabetic run < 3 chars → None.
    assert_eq!(extract_trailing_literal_byte(".*ab"), None);
    assert_eq!(extract_trailing_literal_byte("x"), None);
    assert_eq!(extract_trailing_literal_byte("xy"), None);
}

#[test]
fn trailing_literal_exactly_three() {
    // Exactly 3 alpha chars at end → extracted.
    assert_eq!(extract_trailing_literal_byte(".*abc"), Some(b'a'));
}

#[test]
fn trailing_literal_alternation_bails() {
    // Pipe means alternation → None.
    assert_eq!(extract_trailing_literal_byte("haiku|sonnet"), None);
}

#[test]
fn trailing_literal_uppercase_lowered() {
    // Uppercase should be lowered.
    assert_eq!(extract_trailing_literal_byte(".*HAIKU"), Some(b'h'));
}

#[test]
fn trailing_literal_empty_pattern() {
    assert_eq!(extract_trailing_literal_byte(""), None);
}

#[test]
fn trailing_literal_alpha_run_with_digit_boundary() {
    // "foo123bar" — last alpha run is "bar" (3 chars), first byte = b'b'.
    assert_eq!(extract_trailing_literal_byte("foo123bar"), Some(b'b'));
    // "foo1ab" — last alpha run is "ab" (2 chars) → None.
    assert_eq!(extract_trailing_literal_byte("foo1ab"), None);
}

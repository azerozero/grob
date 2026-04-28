use super::*;
use crate::cli::{RouterConfig, ServerConfig};
use crate::models::{Message, MessageContent, ThinkingConfig};
use proptest::prelude::*;

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
        tiers: vec![],
        classifier: None,
        presets: Default::default(),
        budget: Default::default(),
        dlp: Default::default(),
        auth: Default::default(),
        tap: Default::default(),
        user: Default::default(),
        version: None,
        security: Default::default(),
        cache: Default::default(),
        secrets: Default::default(),
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
fn test_auto_map_skips_explicit_virtual_model() {
    // Regression: a request that matches the auto_map regex must NOT be
    // rewritten to `router.default` when the user has an explicit
    // `[[models]]` entry with the same name. Without this guard the
    // virtual entry's fallback chain would be bypassed entirely and the
    // virtual name would leak to a pass-through provider downstream.
    use crate::cli::ModelConfig;

    let mut config = create_test_config();
    // Add a virtual model entry with the same name as the incoming model.
    config.models.push(ModelConfig {
        name: "claude-sonnet-4-6".to_string(),
        mappings: vec![],
        budget_usd: None,
        strategy: Default::default(),
        fan_out: None,
        deprecated: None,
    });
    let router = Router::new(config);

    let mut request = create_simple_request("Hello");
    request.model = "claude-sonnet-4-6".to_string();

    let decision = router.route(&mut request).unwrap();
    assert_eq!(decision.route_type, RouteType::Default);
    // Must use the explicit virtual name, NOT the auto-mapped default.
    assert_eq!(decision.model_name, "claude-sonnet-4-6");
}

#[test]
fn test_auto_map_still_rewrites_unmapped_claude() {
    // Counter-test: when the user has no `[[models]]` entry for the
    // incoming claude-* name, auto-map continues to rewrite as before.
    let config = create_test_config();
    let router = Router::new(config);

    let mut request = create_simple_request("Hello");
    request.model = "claude-some-unmapped-variant".to_string();

    let decision = router.route(&mut request).unwrap();
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

// --- Mutant-killing tests for extract_trailing_literal_byte ---
// Targets: >= 3 boundary, to_ascii_lowercase, alternation, escape sequences.

#[test]
fn trailing_literal_boundary_two_vs_three() {
    // Exactly 2 alpha chars → None (boundary: < 3).
    assert_eq!(extract_trailing_literal_byte(".*ab"), None);
    // Exactly 3 alpha chars → Some (boundary: >= 3).
    assert_eq!(extract_trailing_literal_byte(".*abc"), Some(b'a'));
    // Exactly 4 alpha chars → Some (first byte of run).
    assert_eq!(extract_trailing_literal_byte(".*abcd"), Some(b'a'));
}

#[test]
fn trailing_literal_lowercase_identity() {
    // Already lowercase — result must equal the byte itself.
    assert_eq!(extract_trailing_literal_byte(".*hello"), Some(b'h'));
    // Mixed case — result is always lowercased first byte of the run.
    assert_eq!(extract_trailing_literal_byte(".*Hello"), Some(b'h'));
    assert_eq!(extract_trailing_literal_byte(".*HELLO"), Some(b'h'));
    // Verify the returned byte is specifically lowercase, not the original.
    let result = extract_trailing_literal_byte(".*ZZZ");
    assert_eq!(result, Some(b'z'));
    assert_ne!(result, Some(b'Z'));
}

#[test]
fn trailing_literal_first_byte_of_run_not_last() {
    // Must return first byte of the alphabetic run, not the last.
    assert_eq!(extract_trailing_literal_byte(".*xyz"), Some(b'x'));
    assert_ne!(extract_trailing_literal_byte(".*xyz"), Some(b'z'));
}

#[test]
fn trailing_literal_quantifiers_before_alpha() {
    // Quantifier before the alpha run does not affect extraction.
    assert_eq!(extract_trailing_literal_byte(".*foo+bar"), Some(b'b'));
    assert_eq!(extract_trailing_literal_byte(".*foo?baz"), Some(b'b'));
    assert_eq!(extract_trailing_literal_byte(".*foo*qux"), Some(b'q'));
}

#[test]
fn trailing_literal_trailing_quantifier() {
    // Quantifier as last character → not alphabetic → None.
    assert_eq!(extract_trailing_literal_byte(".*abc+"), None);
    assert_eq!(extract_trailing_literal_byte(".*abc*"), None);
    assert_eq!(extract_trailing_literal_byte(".*abc?"), None);
}

#[test]
fn trailing_literal_dollar_after_short_alpha() {
    // "ab$" → strip $, alpha run is "ab" (2) → None.
    assert_eq!(extract_trailing_literal_byte("ab$"), None);
    // "abc$" → strip $, alpha run is "abc" (3) → Some(b'a').
    assert_eq!(extract_trailing_literal_byte("abc$"), Some(b'a'));
}

#[test]
fn trailing_literal_pipe_anywhere() {
    // Pipe at start, middle, end — all bail.
    assert_eq!(extract_trailing_literal_byte("|abc"), None);
    assert_eq!(extract_trailing_literal_byte("abc|def"), None);
    assert_eq!(extract_trailing_literal_byte("abc|"), None);
}

#[test]
fn trailing_literal_backslash_escape() {
    // 'd' after backslash is still an ASCII alpha byte — the function does not
    // parse regex escapes, it only looks at raw bytes.
    assert_eq!(extract_trailing_literal_byte(".*abc\\d"), None);
    // "\\wabc" → backslash (0x5C) breaks alpha run, "wabc" is 4 alpha → Some(b'w').
    assert_eq!(extract_trailing_literal_byte(".*\\wabc"), Some(b'w'));
}

#[test]
fn trailing_literal_unicode_non_ascii() {
    // "café" ends with UTF-8 bytes for 'é' (0xC3 0xA9) which are not ASCII alpha,
    // but the byte before them is 'f' — so the function sees the raw bytes.
    // Actually "café" = [99, 97, 102, 195, 169] — last non-alpha, alpha run before
    // is "caf" wait no — let's just verify actual behavior.
    // "über" = [195, 188, 98, 101, 114] — "ber" is 3 alpha → Some(b'b').
    assert_eq!(extract_trailing_literal_byte(".*über"), Some(b'b'));
    // Pure non-ASCII at end → None.
    assert_eq!(extract_trailing_literal_byte(".*ÉÉÉ"), None);
}

#[test]
fn trailing_literal_long_alpha_run() {
    // Long run → returns first byte.
    assert_eq!(
        extract_trailing_literal_byte(".*abcdefghijklmnop"),
        Some(b'a')
    );
}

#[test]
fn trailing_literal_digit_then_three_alpha() {
    // Digit breaks the run, then 3 alpha → extracted.
    assert_eq!(extract_trailing_literal_byte("9abc"), Some(b'a'));
    assert_eq!(extract_trailing_literal_byte("99abc"), Some(b'a'));
    // Digit breaks, only 2 alpha → None.
    assert_eq!(extract_trailing_literal_byte("9ab"), None);
}

#[test]
fn trailing_literal_triple_dollar() {
    // Kills: `end -= 1` → no-op (infinite loop / timeout) in dollar-stripping loop.
    // All three dollars stripped → end == 0 → None.
    assert_eq!(extract_trailing_literal_byte("$$$"), None);
}

#[test]
fn trailing_literal_pure_alpha_pattern() {
    // Kills: `i > 0` → `false` in backward walk (walk would not execute at all).
    // Entire pattern is alpha → i walks to 0, run = full length.
    assert_eq!(extract_trailing_literal_byte("hello"), Some(b'h'));
    assert_eq!(extract_trailing_literal_byte("abc"), Some(b'a'));
    // Only 2 alpha chars (full pattern) → None.
    assert_eq!(extract_trailing_literal_byte("ab"), None);
}

#[test]
fn trailing_literal_single_char() {
    // Kills: `end == 0` → off-by-one mutations after dollar strip.
    // Single alpha char → run is 1 < 3 → None.
    assert_eq!(extract_trailing_literal_byte("x"), None);
    // Single non-alpha → None (early return on non-alpha check).
    assert_eq!(extract_trailing_literal_byte("9"), None);
    // Single dollar → end == 0 → None.
    assert_eq!(extract_trailing_literal_byte("$"), None);
}

// ── Property-based tests ─────────────────────────────────────

proptest! {
    /// extract_trailing_literal_byte never panics on arbitrary input.
    #[test]
    fn prop_extract_trailing_never_panics(pattern in ".{0,200}") {
        let _ = extract_trailing_literal_byte(&pattern);
    }

    /// Result is deterministic: same input always produces same output.
    #[test]
    fn prop_extract_trailing_deterministic(pattern in ".{0,100}") {
        let a = extract_trailing_literal_byte(&pattern);
        let b = extract_trailing_literal_byte(&pattern);
        prop_assert_eq!(a, b);
    }

    /// If a result is returned, it must be a lowercase ASCII alphabetic byte.
    #[test]
    fn prop_extract_trailing_result_is_lowercase_alpha(pattern in ".{0,200}") {
        if let Some(byte) = extract_trailing_literal_byte(&pattern) {
            prop_assert!(byte.is_ascii_lowercase(),
                "Returned byte {:?} is not lowercase ASCII alpha", byte as char);
        }
    }

    /// Patterns containing '|' always return None (alternation bail).
    #[test]
    fn prop_alternation_always_none(
        left in "[a-z]{3,10}",
        right in "[a-z]{3,10}"
    ) {
        let pattern = format!("{left}|{right}");
        prop_assert_eq!(extract_trailing_literal_byte(&pattern), None);
    }

    /// Router::new + route never panics on arbitrary model names.
    #[test]
    fn prop_router_classify_no_panic(model_name in "[a-zA-Z0-9._-]{0,80}") {
        let config = create_test_config();
        let router = Router::new(config);
        let mut request = create_simple_request("hello world");
        request.model = model_name;
        let result = router.route(&mut request);
        prop_assert!(result.is_ok(), "route() must not panic or error");
    }

    /// Route with arbitrary user text never panics.
    #[test]
    fn prop_route_arbitrary_text_no_panic(text in "\\PC{0,200}") {
        let config = create_test_config();
        let router = Router::new(config);
        let mut request = create_simple_request(&text);
        let result = router.route(&mut request);
        prop_assert!(result.is_ok(), "route() must not panic on arbitrary text");
    }
}

// ── Tier integration tests ──────────────────────────────────────────────────

#[test]
fn test_default_routing_has_complexity_tier() {
    let config = create_test_config();
    let router = Router::new(config);
    let mut request = create_simple_request("hello");
    let decision = router.route(&mut request).unwrap();
    assert!(
        decision.complexity_tier.is_some(),
        "Default route should carry a complexity tier"
    );
}

#[test]
fn test_complexity_tier_complex() {
    use crate::models::Tool;
    let config = create_test_config();
    let router = Router::new(config);
    let mut request = create_simple_request(
        "Please refactor the entire authentication module to use async/await",
    );
    request.max_tokens = 8000;
    request.tools = Some(vec![Tool {
        r#type: Some("function".to_string()),
        name: Some("code_editor".to_string()),
        description: Some("Edit code".to_string()),
        input_schema: Some(serde_json::json!({"type": "object"})),
    }]);
    let decision = router.route(&mut request).unwrap();
    assert_eq!(
        decision.complexity_tier.as_ref().map(|t| t.to_string()),
        Some("complex".to_string()),
        "Refactor + 8000 tokens + tools should score as complex"
    );
}

#[test]
fn test_non_default_routes_have_no_tier() {
    let config = create_test_config();
    let router = Router::new(config);
    let mut request = CanonicalRequest {
        model: "claude-3-5-haiku-latest".to_string(),
        messages: vec![Message {
            role: "user".to_string(),
            content: MessageContent::Text("quick task".to_string()),
        }],
        max_tokens: 256,
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
    assert_eq!(
        decision.route_type,
        crate::models::RouteType::Background,
        "Haiku model should route to background"
    );
    assert!(
        decision.complexity_tier.is_none(),
        "Non-default routes should not carry a tier"
    );
}

// ── Background regex coverage ───────────────────────────────────────────────
//
// The default `background_regex` is `(?i)claude.*haiku` — case-insensitive
// and required to match the substring "haiku" anywhere after "claude".
// These tests pin the contract for future regex tweaks.

#[test]
fn background_regex_matches_haiku_uppercase() {
    let config = create_test_config();
    let router = Router::new(config);

    let mut request = create_simple_request("Hello");
    request.model = "Claude-3-5-HAIKU-20241022".to_string();

    let decision = router.route(&mut request).unwrap();
    assert_eq!(
        decision.route_type,
        RouteType::Background,
        "Default `(?i)` flag must match HAIKU regardless of case"
    );
    assert_eq!(decision.model_name, "background.model");
}

#[test]
fn background_regex_matches_haiku_lowercase() {
    let config = create_test_config();
    let router = Router::new(config);

    let mut request = create_simple_request("Hello");
    request.model = "claude-haiku-4-5".to_string();

    let decision = router.route(&mut request).unwrap();
    assert_eq!(decision.route_type, RouteType::Background);
    assert_eq!(decision.model_name, "background.model");
}

#[test]
fn background_regex_does_not_match_sonnet() {
    let config = create_test_config();
    let router = Router::new(config);

    // Sonnet must not be classified as background; the default regex
    // requires a literal "haiku" substring.
    let mut request = create_simple_request("Hello");
    request.model = "claude-sonnet-4-5".to_string();

    let decision = router.route(&mut request).unwrap();
    assert_ne!(
        decision.route_type,
        RouteType::Background,
        "Sonnet must not match the haiku-only background regex"
    );
}

// ── Prompt-rule priority and skip behaviour ─────────────────────────────────
//
// The router walks `[[router.prompt_rules]]` in declaration order and stops
// at the first hit. These tests lock that contract and the negative path.

#[test]
fn prompt_rule_first_match_wins() {
    use crate::cli::PromptRule;
    let mut config = create_test_config();
    // Two rules whose patterns both match the same prompt — the first
    // declared rule must win regardless of how specific the second is.
    config.router.prompt_rules = vec![
        PromptRule {
            pattern: r"(?i)deploy".to_string(),
            model: "first-model".to_string(),
            strip_match: false,
        },
        PromptRule {
            pattern: r"(?i)deploy.*production".to_string(),
            model: "second-model".to_string(),
            strip_match: false,
        },
    ];
    let router = Router::new(config);

    let mut request = create_simple_request("Please deploy to production");
    let decision = router.route(&mut request).unwrap();
    assert_eq!(decision.route_type, RouteType::PromptRule);
    assert_eq!(
        decision.model_name, "first-model",
        "Earlier prompt rule must take precedence even when a later rule also matches"
    );
}

#[test]
fn prompt_rule_skipped_when_no_match() {
    use crate::cli::PromptRule;
    let mut config = create_test_config();
    config.router.prompt_rules = vec![PromptRule {
        pattern: r"(?i)refactor.*module".to_string(),
        model: "refactor-model".to_string(),
        strip_match: false,
    }];
    // Disable background so a haiku-named model would still fall through.
    config.router.background = None;
    let router = Router::new(config);

    // Prompt does not contain "refactor" — rule must be skipped and the
    // request continues down the priority chain to the default route.
    let mut request = create_simple_request("Just say hi");
    let decision = router.route(&mut request).unwrap();
    assert_ne!(decision.route_type, RouteType::PromptRule);
    assert_eq!(decision.model_name, "default.model");
}

// ── Model-name canonicalization at the router level ────────────────────────
//
// `canonicalize_model_name` is exhaustively tested in `model_name.rs`; these
// tests verify the **integration**: the canonicalized form is what reaches
// the `[[models]]` lookup, while the original `request.model` is overwritten
// in place so downstream stages (and the response surface) see the
// canonical key.

#[test]
fn canonicalized_name_used_in_models_lookup() {
    // A request for the date-suffixed Anthropic ID must hit the explicit
    // `[[models]]` entry whose name uses the canonical (date-stripped,
    // family-first) form. Without canonicalization, the lookup would miss
    // and the request would be auto-mapped to `default.model`.
    use crate::cli::ModelConfig;

    let mut config = create_test_config();
    config.models.push(ModelConfig {
        name: "claude-sonnet-3-5".to_string(),
        mappings: vec![],
        budget_usd: None,
        strategy: Default::default(),
        fan_out: None,
        deprecated: None,
    });
    let router = Router::new(config);

    let mut request = create_simple_request("Hello");
    request.model = "claude-3-5-sonnet-20241022".to_string();

    let decision = router.route(&mut request).unwrap();
    // Auto-map skipped because the canonical form matches an explicit
    // entry, so the request resolves to the canonical name verbatim.
    assert_eq!(decision.route_type, RouteType::Default);
    assert_eq!(decision.model_name, "claude-sonnet-3-5");
}

#[test]
fn original_name_returned_to_client_unchanged() {
    // When canonicalization yields the same string (already-canonical input),
    // `request.model` is not rewritten and the route decision carries the
    // exact name the client sent. This guarantees clients that pin a model
    // name see it preserved on the response surface.
    let mut config = create_test_config();
    // Disable auto-map to keep the test focused on canonicalization.
    config.router.auto_map_regex = Some("^never-matches-".to_string());
    let router = Router::new(config);

    let original = "gpt-4o";
    let mut request = create_simple_request("Hello");
    request.model = original.to_string();

    let decision = router.route(&mut request).unwrap();
    assert_eq!(
        request.model, original,
        "Already-canonical input must not be rewritten"
    );
    assert_eq!(decision.model_name, original);
}

// ── Auto-map edge cases (locked from PR #293) ──────────────────────────────
//
// PR #293 introduced the "auto-map skipped when an explicit `[[models]]`
// entry exists" guard. The tests above (`test_auto_map_skips_explicit_*`)
// cover the original Sonnet-4-6 regression. The aliases below cross-link
// the new naming convention requested in the test plan to the existing
// regression tests so future grep-based audits hit either name.

#[test]
fn auto_map_skipped_when_explicit_model_entry_exists() {
    // Alias for `test_auto_map_skips_explicit_virtual_model` under the
    // naming used in the routing test plan. Locks PR #293 against
    // accidental removal of the explicit-models guard.
    use crate::cli::ModelConfig;

    let mut config = create_test_config();
    config.models.push(ModelConfig {
        name: "claude-experimental".to_string(),
        mappings: vec![],
        budget_usd: None,
        strategy: Default::default(),
        fan_out: None,
        deprecated: None,
    });
    let router = Router::new(config);

    let mut request = create_simple_request("Hello");
    request.model = "claude-experimental".to_string();

    let decision = router.route(&mut request).unwrap();
    assert_eq!(
        decision.model_name, "claude-experimental",
        "Auto-map must defer to an explicit `[[models]]` entry"
    );
}

#[test]
fn auto_map_rewrites_unknown_claude_model_to_default() {
    // Alias for `test_auto_map_still_rewrites_unmapped_claude` under the
    // plan's naming. Counter-test for the guard above.
    let config = create_test_config();
    let router = Router::new(config);

    let mut request = create_simple_request("Hello");
    request.model = "claude-totally-new-variant-2099".to_string();

    let decision = router.route(&mut request).unwrap();
    assert_eq!(decision.model_name, "default.model");
}

#[test]
fn auto_map_does_not_match_non_claude_models() {
    // Alias for `test_no_auto_map_non_matching` — non-claude IDs survive
    // the auto-mapper untouched and reach the default route as-is.
    let config = create_test_config();
    let router = Router::new(config);

    let mut request = create_simple_request("Hello");
    request.model = "deepseek-v3".to_string();

    let decision = router.route(&mut request).unwrap();
    assert_eq!(decision.route_type, RouteType::Default);
    assert_eq!(decision.model_name, "deepseek-v3");
}

// ── Edge cases: malformed config, empty fields ─────────────────────────────

#[test]
fn router_accepts_invalid_auto_map_regex_falls_back_to_default() {
    // A malformed user-supplied regex must not crash `Router::new`; the
    // constructor falls back to the default `^claude-` pattern and logs.
    let mut config = create_test_config();
    config.router.auto_map_regex = Some("[invalid(regex".to_string());
    let router = Router::new(config);

    // Default fallback still rewrites claude-* models.
    let mut request = create_simple_request("Hello");
    request.model = "claude-something-new".to_string();
    let decision = router.route(&mut request).unwrap();
    assert_eq!(decision.model_name, "default.model");
}

#[test]
fn router_skips_invalid_prompt_rules_silently() {
    // Bad regex in `[[router.prompt_rules]]` is logged and skipped at
    // construction time; well-formed rules in the same list still apply.
    use crate::cli::PromptRule;
    let mut config = create_test_config();
    config.router.prompt_rules = vec![
        PromptRule {
            pattern: "[unclosed".to_string(),
            model: "broken-model".to_string(),
            strip_match: false,
        },
        PromptRule {
            pattern: r"(?i)valid-pattern".to_string(),
            model: "valid-model".to_string(),
            strip_match: false,
        },
    ];
    let router = Router::new(config);

    let mut request = create_simple_request("contains valid-pattern here");
    let decision = router.route(&mut request).unwrap();
    assert_eq!(decision.route_type, RouteType::PromptRule);
    assert_eq!(decision.model_name, "valid-model");
}

#[test]
fn router_handles_empty_prompt_rules_list() {
    // Empty `prompt_rules` must not change routing; falls through to default.
    let mut config = create_test_config();
    config.router.prompt_rules = vec![];
    config.router.background = None;
    let router = Router::new(config);

    let mut request = create_simple_request("anything goes");
    request.model = "deepseek-chat".to_string();
    let decision = router.route(&mut request).unwrap();
    assert_eq!(decision.route_type, RouteType::Default);
    assert_eq!(decision.model_name, "deepseek-chat");
}

// ── Routing priority order pins ────────────────────────────────────────────
//
// These tests fix the exact precedence chain documented in `Router::route`
// so any reordering shows up as a test failure rather than a silent
// behavior change.

#[test]
fn websearch_outranks_background() {
    // A request whose model name matches the background regex but which
    // also carries a `web_search` tool must route to websearch.
    let config = create_test_config();
    let router = Router::new(config);

    let mut request = create_simple_request("Hello");
    request.model = "claude-3-5-haiku-20241022".to_string();
    request.tools = Some(vec![crate::models::Tool {
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
fn background_outranks_auto_map() {
    // The auto-map step rewrites `claude-*` to `default` only after the
    // background check has run; a haiku request must not reach auto-map.
    let config = create_test_config();
    let router = Router::new(config);

    let mut request = create_simple_request("Hello");
    request.model = "claude-haiku-4-5".to_string();

    let decision = router.route(&mut request).unwrap();
    assert_eq!(decision.route_type, RouteType::Background);
    // Cross-check: model_name must NOT be the auto-map target.
    assert_ne!(decision.model_name, "default.model");
}

#[test]
fn prompt_rule_outranks_think_mode() {
    // Plan-mode is checked AFTER prompt rules. A request that triggers
    // both must take the prompt-rule branch.
    use crate::cli::PromptRule;
    let mut config = create_test_config();
    config.router.prompt_rules = vec![PromptRule {
        pattern: r"(?i)trigger".to_string(),
        model: "rule-model".to_string(),
        strip_match: false,
    }];
    let router = Router::new(config);

    let mut request = create_simple_request("This will trigger the rule");
    request.thinking = Some(crate::models::ThinkingConfig {
        r#type: "enabled".to_string(),
        budget_tokens: Some(8_000),
    });

    let decision = router.route(&mut request).unwrap();
    assert_eq!(decision.route_type, RouteType::PromptRule);
    assert_eq!(decision.model_name, "rule-model");
}

// ── Tier-routing integration with [[tiers.match]] ──────────────────────────
//
// The tier_match unit tests in `tier_match.rs` verify each condition in
// isolation. The tests below exercise the same logic through the public
// `Router::route` surface to lock the wiring in `Router::new`.

#[test]
fn tier_max_tokens_below_filters_correctly_via_router() {
    use crate::cli::{TierConfig, TierMatchCondition};
    let mut config = create_test_config();
    config.tiers = vec![TierConfig {
        name: "trivial".to_string(),
        providers: vec![],
        fanout: false,
        match_conditions: Some(TierMatchCondition {
            max_tokens_below: Some(500),
            ..Default::default()
        }),
    }];
    let router = Router::new(config);

    // Below threshold → trivial fires.
    let mut small = create_simple_request("hello");
    small.max_tokens = 256;
    let decision = router.route(&mut small).unwrap();
    assert_eq!(
        decision.complexity_tier.as_ref().map(ToString::to_string),
        Some("trivial".to_string()),
    );

    // Above threshold → declarative match misses; algorithmic fallback
    // selects whatever tier the scorer assigns (just assert it is not
    // forced to trivial).
    let mut big = create_simple_request("hello");
    big.max_tokens = 8_000;
    let decision = router.route(&mut big).unwrap();
    // The scorer may classify "hello" + 8K tokens as medium/complex; the
    // key invariant is that the declarative match did NOT pin trivial.
    let tier = decision
        .complexity_tier
        .as_ref()
        .map(ToString::to_string)
        .expect("scorer fallback should populate a tier");
    assert_ne!(tier, "trivial", "max_tokens_below must not match 8000");
}

#[test]
fn tier_keywords_match_in_last_message_via_router() {
    use crate::cli::{TierConfig, TierMatchCondition};
    let mut config = create_test_config();
    config.tiers = vec![TierConfig {
        name: "complex".to_string(),
        providers: vec![],
        fanout: false,
        match_conditions: Some(TierMatchCondition {
            keywords: vec!["refactor".to_string(), "migration".to_string()],
            ..Default::default()
        }),
    }];
    let router = Router::new(config);

    let mut request = create_simple_request("Plan the refactor strategy");
    let decision = router.route(&mut request).unwrap();
    assert_eq!(
        decision.complexity_tier.as_ref().map(ToString::to_string),
        Some("complex".to_string()),
    );
}

#[test]
fn tier_first_matching_wins_when_multiple_match_via_router() {
    // Two tier matchers whose conditions both fire — declaration order
    // wins, not specificity.
    use crate::cli::{TierConfig, TierMatchCondition};
    let mut config = create_test_config();
    config.tiers = vec![
        TierConfig {
            name: "medium".to_string(),
            providers: vec![],
            fanout: false,
            match_conditions: Some(TierMatchCondition {
                keywords: vec!["test".to_string()],
                ..Default::default()
            }),
        },
        TierConfig {
            name: "complex".to_string(),
            providers: vec![],
            fanout: false,
            match_conditions: Some(TierMatchCondition {
                keywords: vec!["test".to_string()],
                ..Default::default()
            }),
        },
    ];
    let router = Router::new(config);

    let mut request = create_simple_request("test the code");
    let decision = router.route(&mut request).unwrap();
    assert_eq!(
        decision.complexity_tier.as_ref().map(ToString::to_string),
        Some("medium".to_string()),
        "Earlier `[[tiers]]` entry must win when multiple match"
    );
}

#[test]
fn tier_unknown_name_skipped_with_warning() {
    // A `[[tiers]]` entry with a name that does not map to a
    // `ComplexityTier` variant must be skipped at construction time and
    // the router must continue to function.
    use crate::cli::{TierConfig, TierMatchCondition};
    let mut config = create_test_config();
    config.tiers = vec![TierConfig {
        name: "non-existent-tier".to_string(),
        providers: vec![],
        fanout: false,
        match_conditions: Some(TierMatchCondition::default()),
    }];
    let router = Router::new(config);

    // Router still routes; unknown tier was dropped during compile.
    let mut request = create_simple_request("hello");
    let decision = router.route(&mut request).unwrap();
    assert_eq!(decision.route_type, RouteType::Default);
}

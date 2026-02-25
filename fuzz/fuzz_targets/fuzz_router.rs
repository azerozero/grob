#![no_main]

use libfuzzer_sys::fuzz_target;

use grob::cli::{AppConfig, RouterConfig, PromptRule, ServerConfig};
use grob::models::{AnthropicRequest, Message, MessageContent};
use grob::router::Router;

/// Build a minimal AppConfig with several prompt_rules containing various regex patterns.
/// This is constructed once conceptually per fuzz iteration (cheap enough).
fn make_config() -> AppConfig {
    let router = RouterConfig {
        default: "default-model".to_string(),
        background: Some("background-model".to_string()),
        think: Some("think-model".to_string()),
        websearch: Some("websearch-model".to_string()),
        auto_map_regex: None,
        background_regex: None,
        gdpr: false,
        region: None,
        prompt_rules: vec![
            PromptRule {
                pattern: r"(?i)\bcommit\b".to_string(),
                model: "fast-model".to_string(),
                strip_match: false,
            },
            PromptRule {
                pattern: r"(?i)search\s+the\s+web".to_string(),
                model: "search-model".to_string(),
                strip_match: true,
            },
            PromptRule {
                pattern: r"\b\d{4}-\d{2}-\d{2}\b".to_string(),
                model: "date-model".to_string(),
                strip_match: false,
            },
            PromptRule {
                pattern: r"(?i)(translate|翻译)".to_string(),
                model: "translate-model".to_string(),
                strip_match: false,
            },
            PromptRule {
                pattern: r"(?i)use\s+(?P<name>\S+)".to_string(),
                model: "$name".to_string(),
                strip_match: true,
            },
        ],
    };

    AppConfig {
        server: ServerConfig::default(),
        router,
        providers: vec![],
        models: vec![],
        presets: Default::default(),
        budget: Default::default(),
        dlp: Default::default(),
        auth: Default::default(),
        tap: Default::default(),
        user: Default::default(),
    }
}

fuzz_target!(|data: &[u8]| {
    // Interpret fuzz input as a UTF-8 string to use as the message content
    let text = match std::str::from_utf8(data) {
        Ok(t) => t,
        Err(_) => return,
    };

    let config = make_config();
    let router = Router::new(config);

    // Build a minimal AnthropicRequest with the fuzzed text as the user message
    let mut request = AnthropicRequest {
        model: "claude-sonnet-4-20250514".to_string(),
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
    };

    // Route the request - should never panic
    let _ = router.route(&mut request);
});

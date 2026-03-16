//! Request routing engine with regex-based prompt rules and task-type classification.

/// Provider type inference from model name prefixes.
pub mod inference;
/// Message content extraction for routing decisions.
mod message;
/// Regex compilation and capture-group utilities.
mod rules;

use crate::cli::AppConfig;
use crate::models::{CanonicalRequest, RouteDecision, RouteType};
use anyhow::Result;
use regex::Regex;
use tracing::{debug, info};

// Re-export memchr for SIMD-accelerated byte search in pre-filters.
use memchr::memchr2;

/// Compiled prompt rule with pre-compiled regex
#[derive(Clone)]
pub struct CompiledPromptRule {
    /// Pre-compiled regex pattern for matching user prompts.
    pub regex: Regex,
    /// Target model name (may contain capture-group references).
    pub model: String,
    /// Whether to strip the matched text from the prompt.
    pub strip_match: bool,
    /// True if model contains capture group references ($1, $name, etc.)
    pub is_dynamic: bool,
}

/// Optimized model-name matcher.
///
/// Detects simple `^literal` prefix patterns at construction time and uses
/// `str::starts_with` (~2 ns) instead of a full regex match (~30 ns).
#[derive(Clone)]
enum AutoMapper {
    /// Anchored literal prefix, matched via `starts_with`.
    Prefix(String),
    /// General regex pattern.
    Regex(Regex),
}

impl AutoMapper {
    /// Builds a fast `Prefix` matcher for `^literal` patterns; falls back to `Regex`.
    fn new(pattern: &str) -> Option<Self> {
        if let Some(literal) = pattern.strip_prefix('^') {
            if !literal.is_empty()
                && literal.bytes().all(|b| {
                    !matches!(
                        b,
                        b'.' | b'*'
                            | b'+'
                            | b'?'
                            | b'('
                            | b')'
                            | b'['
                            | b']'
                            | b'{'
                            | b'}'
                            | b'|'
                            | b'\\'
                            | b'$'
                            | b'^'
                    )
                })
            {
                return Some(AutoMapper::Prefix(literal.to_string()));
            }
        }
        Regex::new(pattern).ok().map(AutoMapper::Regex)
    }

    #[inline]
    fn is_match(&self, text: &str) -> bool {
        match self {
            AutoMapper::Prefix(p) => text.starts_with(p.as_str()),
            AutoMapper::Regex(r) => r.is_match(text),
        }
    }
}

/// Extracts a pre-filter byte from a regex pattern's trailing required literal.
///
/// Returns the first byte (lowercased) of the last alphabetic run (≥ 3 chars)
/// at the end of the pattern. Only extracts when the literal is certainly
/// required (no alternation, no quantifiers after the literal).
///
/// For `(?i)claude.*haiku` → `Some(b'h')`.
fn extract_trailing_literal_byte(pattern: &str) -> Option<u8> {
    // Alternation makes individual literals optional — bail.
    if pattern.contains('|') {
        return None;
    }

    let bytes = pattern.as_bytes();
    // Skip trailing '$' anchor(s).
    let mut end = bytes.len();
    while end > 0 && bytes[end - 1] == b'$' {
        end -= 1;
    }
    if end == 0 {
        return None;
    }
    // Character before any trailing anchor must be alphabetic (no quantifier).
    if !bytes[end - 1].is_ascii_alphabetic() {
        return None;
    }
    // Walk backwards through the alphabetic run.
    let mut i = end;
    while i > 0 && bytes[i - 1].is_ascii_alphabetic() {
        i -= 1;
    }
    if end - i >= 3 {
        Some(bytes[i].to_ascii_lowercase())
    } else {
        None
    }
}

/// Router for intelligently selecting models based on request characteristics
#[derive(Clone)]
pub struct Router {
    config: AppConfig,
    auto_mapper: Option<AutoMapper>,
    background_regex: Option<Regex>,
    /// Both cases (lower, upper) of the trailing required literal's first byte.
    /// Enables SIMD-accelerated `memchr2` rejection before running the full regex.
    background_prefilter_bytes: Option<(u8, u8)>,
    prompt_rules: Vec<CompiledPromptRule>,
}

impl Router {
    /// Create a new router with configuration
    pub fn new(config: AppConfig) -> Self {
        let auto_mapper = {
            let pattern = config
                .router
                .auto_map_regex
                .as_deref()
                .unwrap_or("^claude-");
            AutoMapper::new(pattern).or_else(|| {
                tracing::warn!(
                    "Invalid auto_map_regex '{}', falling back to default",
                    pattern
                );
                AutoMapper::new("^claude-")
            })
        };

        let bg_pattern = config
            .router
            .background_regex
            .as_deref()
            .unwrap_or("(?i)claude.*haiku");
        let background_prefilter_bytes =
            extract_trailing_literal_byte(bg_pattern).map(|lo| (lo, lo.to_ascii_uppercase()));
        let background_regex = rules::compile_regex_with_fallback(
            config.router.background_regex.as_deref(),
            r"(?i)claude.*haiku",
            "background_regex",
        );

        // Compile prompt rules
        let prompt_rules: Vec<CompiledPromptRule> = config
            .router
            .prompt_rules
            .iter()
            .filter_map(|rule| match Regex::new(&rule.pattern) {
                Ok(regex) => {
                    let is_dynamic = rules::contains_capture_reference(&rule.model);
                    Some(CompiledPromptRule {
                        regex,
                        model: rule.model.clone(),
                        strip_match: rule.strip_match,
                        is_dynamic,
                    })
                }
                Err(e) => {
                    tracing::warn!(
                        "Invalid prompt_rule pattern '{}': {}. Skipping.",
                        rule.pattern,
                        e
                    );
                    None
                }
            })
            .collect();

        if !prompt_rules.is_empty() {
            info!("📝 Loaded {} prompt routing rules", prompt_rules.len());
        }

        Self {
            config,
            auto_mapper,
            background_regex,
            background_prefilter_bytes,
            prompt_rules,
        }
    }

    /// Route an incoming request to the appropriate model
    ///
    /// Priority order (highest to lowest):
    /// 1. WebSearch - tool-based detection (web_search tool present)
    /// 2. Background - model name regex match (e.g., haiku) - checked early to save costs
    /// 3. Subagent - GROB-SUBAGENT-MODEL tag in system prompt
    /// 4. Prompt Rules - regex pattern matching on user prompt (after background for cost savings)
    /// 5. Think - Plan Mode / reasoning enabled
    /// 6. Default - auto-mapped or original model name
    pub fn route(&self, request: &mut CanonicalRequest) -> Result<RouteDecision> {
        // 1. WebSearch (HIGHEST PRIORITY - tool-based detection, no model name needed)
        if let Some(ref websearch_model) = self.config.router.websearch {
            if self.has_web_search_tool(request) {
                debug!("🔍 Routing to websearch model (web_search tool detected)");
                return Ok(RouteDecision {
                    model_name: websearch_model.clone(),
                    route_type: RouteType::WebSearch,
                    matched_prompt: None,
                });
            }
        }

        // 2. Background tasks (checked BEFORE auto-mapping to avoid cloning original model)
        if let Some(ref background_model) = self.config.router.background {
            if self.is_background_task(&request.model) {
                debug!("🔄 Routing to background model");
                return Ok(RouteDecision {
                    model_name: background_model.clone(),
                    route_type: RouteType::Background,
                    matched_prompt: None,
                });
            }
        }

        // 3. Auto-mapping (model name transformation, after background check)
        if let Some(ref mapper) = self.auto_mapper {
            if mapper.is_match(&request.model) {
                debug!(
                    "🔀 Auto-mapped model '{}' → '{}'",
                    request.model, self.config.router.default
                );
                request.model.clone_from(&self.config.router.default);
            }
        }

        // 4. Subagent Model (system prompt tag)
        if let Some(model) = self.extract_subagent_model(request) {
            debug!(
                "🤖 Routing to subagent model (GROB-SUBAGENT-MODEL tag): {}",
                model
            );
            return Ok(RouteDecision {
                model_name: model,
                route_type: RouteType::Default,
                matched_prompt: None,
            });
        }

        // 5. Prompt Rules (pattern matching on user prompt)
        if let Some((model, matched_text)) = self.match_prompt_rule(request) {
            debug!("📝 Routing to model via prompt rule match: {}", model);
            return Ok(RouteDecision {
                model_name: model,
                route_type: RouteType::PromptRule,
                matched_prompt: Some(matched_text),
            });
        }

        // 6. Think mode (Plan Mode / Reasoning)
        if let Some(ref think_model) = self.config.router.think {
            if self.is_plan_mode(request) {
                debug!("🧠 Routing to think model (Plan Mode detected)");
                return Ok(RouteDecision {
                    model_name: think_model.clone(),
                    route_type: RouteType::Think,
                    matched_prompt: None,
                });
            }
        }

        // 7. Default fallback
        debug!("✅ Using model: {}", request.model);
        Ok(RouteDecision {
            model_name: request.model.clone(),
            route_type: RouteType::Default,
            matched_prompt: None,
        })
    }

    /// Check if request has web_search tool (tool-based detection)
    /// Following claude-code-router pattern: checks if tools array contains web_search type
    #[inline]
    fn has_web_search_tool(&self, request: &CanonicalRequest) -> bool {
        if let Some(ref tools) = request.tools {
            tools.iter().any(|tool| {
                tool.r#type
                    .as_ref()
                    .map(|t| t.starts_with("web_search"))
                    .unwrap_or(false)
            })
        } else {
            false
        }
    }

    /// Check if request is Plan Mode by detecting thinking field
    #[inline]
    fn is_plan_mode(&self, request: &CanonicalRequest) -> bool {
        request
            .thinking
            .as_ref()
            .map(|t| t.r#type == "enabled")
            .unwrap_or(false)
    }

    /// Detect background tasks using regex pattern.
    ///
    /// Uses SIMD-accelerated `memchr2` pre-filter to reject non-matching
    /// model names before invoking the full regex (~3 ns vs ~35 ns).
    #[inline]
    fn is_background_task(&self, model: &str) -> bool {
        if let Some(ref regex) = self.background_regex {
            // Fast SIMD pre-filter: reject if trailing literal's first byte is absent.
            if let Some((lo, hi)) = self.background_prefilter_bytes {
                if memchr2(lo, hi, model.as_bytes()).is_none() {
                    return false;
                }
            }
            regex.is_match(model)
        } else {
            false
        }
    }
}

// ── Trait implementation ──

impl crate::traits::RequestRouter for Router {
    fn route(&self, request: &mut CanonicalRequest) -> Result<RouteDecision> {
        self.route(request)
    }
}

#[cfg(test)]
mod tests {
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
            #[cfg(feature = "mcp")]
            mcp: Default::default(),
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
        // Turn 1: User: "OPUS write me tests" → Assistant: "Here are the tests..."
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
}

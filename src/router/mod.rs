use crate::cli::AppConfig;
use crate::models::{AnthropicRequest, MessageContent, RouteDecision, RouteType, SystemPrompt};
use anyhow::Result;
use once_cell::sync::Lazy;
use regex::Regex;
use tracing::{debug, info};

/// Regex to detect capture group references ($1, $name, ${1}, ${name})
static CAPTURE_REF_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\$(?:\d+|[a-zA-Z_]\w*|\{[^}]+\})").unwrap());

/// Pre-compiled regex for subagent model tag extraction (avoids per-request compilation)
static SUBAGENT_TAG_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"<GROB-SUBAGENT-MODEL>(.*?)</GROB-SUBAGENT-MODEL>").unwrap());

/// Check if a string contains capture group references
fn contains_capture_reference(s: &str) -> bool {
    s.contains('$') && CAPTURE_REF_PATTERN.is_match(s)
}

/// Compiled prompt rule with pre-compiled regex
#[derive(Clone)]
pub struct CompiledPromptRule {
    pub regex: Regex,
    pub model: String,
    pub strip_match: bool,
    /// True if model contains capture group references ($1, $name, etc.)
    pub is_dynamic: bool,
}

/// Router for intelligently selecting models based on request characteristics
#[derive(Clone)]
pub struct Router {
    config: AppConfig,
    auto_map_regex: Option<Regex>,
    background_regex: Option<Regex>,
    prompt_rules: Vec<CompiledPromptRule>,
}

impl Router {
    /// Create a new router with configuration
    pub fn new(config: AppConfig) -> Self {
        // Compile auto-map regex
        let auto_map_regex = config
            .router
            .auto_map_regex
            .as_ref()
            .map(|pattern| {
                if pattern.is_empty() {
                    // Empty string: use default Claude pattern
                    Regex::new(r"^claude-").expect("Invalid default Claude regex")
                } else {
                    // Custom pattern provided
                    match Regex::new(pattern) {
                        Ok(regex) => regex,
                        Err(e) => {
                            eprintln!(
                                "Warning: Invalid auto_map_regex pattern '{}': {}",
                                pattern, e
                            );
                            eprintln!("Falling back to default Claude pattern");
                            Regex::new(r"^claude-").expect("Invalid default Claude regex")
                        }
                    }
                }
            })
            .or_else(|| {
                // None: use default Claude pattern for backward compatibility
                Some(Regex::new(r"^claude-").expect("Invalid default Claude regex"))
            });

        // Compile background-task regex
        let background_regex = config
            .router
            .background_regex
            .as_ref()
            .map(|pattern| {
                if pattern.is_empty() {
                    // Empty string: use default claude-haiku pattern
                    Regex::new(r"(?i)claude.*haiku").expect("Invalid default background regex")
                } else {
                    // Custom pattern provided
                    match Regex::new(pattern) {
                        Ok(regex) => regex,
                        Err(e) => {
                            eprintln!(
                                "Warning: Invalid background_regex pattern '{}': {}",
                                pattern, e
                            );
                            eprintln!("Falling back to default claude-haiku pattern");
                            Regex::new(r"(?i)claude.*haiku")
                                .expect("Invalid default background regex")
                        }
                    }
                }
            })
            .or_else(|| {
                // None: use default claude-haiku pattern for backward compatibility
                Some(Regex::new(r"(?i)claude.*haiku").expect("Invalid default background regex"))
            });

        // Compile prompt rules
        let prompt_rules: Vec<CompiledPromptRule> = config
            .router
            .prompt_rules
            .iter()
            .filter_map(|rule| match Regex::new(&rule.pattern) {
                Ok(regex) => {
                    let is_dynamic = contains_capture_reference(&rule.model);
                    Some(CompiledPromptRule {
                        regex,
                        model: rule.model.clone(),
                        strip_match: rule.strip_match,
                        is_dynamic,
                    })
                }
                Err(e) => {
                    eprintln!(
                        "Warning: Invalid prompt_rule pattern '{}': {}. Skipping.",
                        rule.pattern, e
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
            auto_map_regex,
            background_regex,
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
    pub fn route(&self, request: &mut AnthropicRequest) -> Result<RouteDecision> {
        // Save original model for background task detection
        let original_model = request.model.clone();

        // 0. Auto-mapping (model name transformation FIRST)
        // Transform model name if it matches auto_map_regex
        if let Some(ref regex) = self.auto_map_regex {
            if regex.is_match(&request.model) {
                let old = request.model.clone();
                request.model = self.config.router.default.clone();
                debug!("🔀 Auto-mapped model '{}' → '{}'", old, request.model);
            }
        }

        // 1. WebSearch (HIGHEST PRIORITY - tool-based detection)
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

        // 2. Background tasks (check against ORIGINAL model name, before auto-mapping)
        // Checked early to prevent expensive models being used for background tasks
        if let Some(ref background_model) = self.config.router.background {
            if self.is_background_task(&original_model) {
                debug!("🔄 Routing to background model");
                return Ok(RouteDecision {
                    model_name: background_model.clone(),
                    route_type: RouteType::Background,
                    matched_prompt: None,
                });
            }
        }

        // 3. Subagent Model (system prompt tag)
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

        // 4. Prompt Rules (pattern matching on user prompt)
        // NOTE: Checked AFTER background to ensure background tasks use cheaper models
        if let Some((model, matched_text)) = self.match_prompt_rule(request) {
            debug!("📝 Routing to model via prompt rule match: {}", model);
            return Ok(RouteDecision {
                model_name: model,
                route_type: RouteType::PromptRule,
                matched_prompt: Some(matched_text),
            });
        }

        // 5. Think mode (Plan Mode / Reasoning)
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

        // 6. Default fallback
        // Use the transformed model name (from auto-mapping) or original if no mapping
        debug!("✅ Using model: {}", request.model);
        Ok(RouteDecision {
            model_name: request.model.clone(),
            route_type: RouteType::Default,
            matched_prompt: None,
        })
    }

    /// Check if request has web_search tool (tool-based detection)
    /// Following claude-code-router pattern: checks if tools array contains web_search type
    fn has_web_search_tool(&self, request: &AnthropicRequest) -> bool {
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
    fn is_plan_mode(&self, request: &AnthropicRequest) -> bool {
        request
            .thinking
            .as_ref()
            .map(|t| t.r#type == "enabled")
            .unwrap_or(false)
    }

    /// Detect background tasks using regex pattern
    /// Uses background_regex from config (defaults to claude-haiku pattern)
    fn is_background_task(&self, model: &str) -> bool {
        if let Some(ref regex) = self.background_regex {
            regex.is_match(model)
        } else {
            false
        }
    }

    /// Match prompt rules against the turn-starting user message content
    /// Returns (model_name, matched_text) if a rule matches, None otherwise
    /// Strips the matched phrase from the prompt if strip_match is true
    /// For dynamic rules (model contains $refs), expands capture groups in the model name
    ///
    /// NOTE: We check the turn-starting message (not just the last user message) so that
    /// prompt phrases like "OPUS" persist for the entire turn, even through tool calls.
    fn match_prompt_rule(&self, request: &mut AnthropicRequest) -> Option<(String, String)> {
        if self.prompt_rules.is_empty() {
            return None;
        }

        // Debug: dump message structure for troubleshooting
        if tracing::enabled!(tracing::Level::DEBUG) {
            use crate::models::ContentBlock;
            for (idx, msg) in request.messages.iter().enumerate() {
                let content_desc = match &msg.content {
                    MessageContent::Text(t) => {
                        let preview: String = t.chars().take(60).collect();
                        format!(
                            "Text({:?}{})",
                            preview,
                            if t.len() > 60 { "..." } else { "" }
                        )
                    }
                    MessageContent::Blocks(blocks) => {
                        let types: Vec<&str> = blocks
                            .iter()
                            .map(|b| match b {
                                ContentBlock::Known(k) => match k {
                                    crate::models::KnownContentBlock::Text { .. } => "text",
                                    crate::models::KnownContentBlock::Image { .. } => "image",
                                    crate::models::KnownContentBlock::ToolUse { .. } => "tool_use",
                                    crate::models::KnownContentBlock::ToolResult { .. } => {
                                        "tool_result"
                                    }
                                    crate::models::KnownContentBlock::Thinking { .. } => "thinking",
                                },
                                ContentBlock::Unknown(_) => "unknown",
                            })
                            .collect();
                        format!("Blocks({:?})", types)
                    }
                };
                debug!("🔍 msg[{}] role={}: {}", idx, msg.role, content_desc);
            }
        }

        // Extract turn-starting user message content (persists through tool calls)
        let user_content = self.extract_turn_starting_user_message(request)?;

        // Check each rule in order (first match wins)
        for rule in &self.prompt_rules {
            if let Some(captures) = rule.regex.captures(&user_content) {
                let matched_text = captures
                    .get(0)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();

                // Resolve the model name (expand capture refs if dynamic)
                let model_name = if rule.is_dynamic {
                    Self::expand_model_template(&rule.model, &captures)
                } else {
                    rule.model.clone()
                };

                debug!(
                    "📝 Prompt rule matched: pattern='{}' → model='{}' (strip_match={})",
                    rule.regex.as_str(),
                    model_name,
                    rule.strip_match
                );

                // Strip the matched phrase from the turn-starting message if requested
                if rule.strip_match {
                    self.strip_match_from_turn_starting_message(request, &rule.regex);
                }

                return Some((model_name, matched_text));
            }
        }

        None
    }

    /// Expand capture group references in a model template string
    /// Supports $1, $name, ${1}, ${name} syntax via regex crate's Captures::expand
    fn expand_model_template(template: &str, captures: &regex::Captures) -> String {
        let mut expanded = String::new();
        captures.expand(template, &mut expanded);
        expanded
    }

    /// Extract the text content from the last user message
    fn extract_last_user_message(&self, request: &AnthropicRequest) -> Option<String> {
        // Find the last user message
        let last_user = request.messages.iter().rev().find(|m| m.role == "user")?;

        // Extract text content (excluding system-reminder blocks)
        match &last_user.content {
            MessageContent::Text(text) => {
                if text.trim().starts_with("<system-reminder>") {
                    None
                } else {
                    Some(text.clone())
                }
            }
            MessageContent::Blocks(blocks) => {
                // Concatenate text blocks, excluding system-reminder blocks
                let text: String = blocks
                    .iter()
                    .filter_map(|block| block.as_text())
                    .filter(|s| !s.trim().starts_with("<system-reminder>"))
                    .collect::<Vec<_>>()
                    .join(" ");
                if text.is_empty() {
                    None
                } else {
                    Some(text)
                }
            }
        }
    }

    /// Extract the text content from the turn-starting user message
    ///
    /// A "turn" starts when:
    /// 1. The conversation begins, OR
    /// 2. After an assistant message that has no tool_use (i.e., the previous turn ended)
    ///
    /// This allows prompt phrases like "OPUS" to persist throughout a turn,
    /// even when the model makes tool calls and the last user message is just tool results.
    fn find_turn_start_index(&self, request: &AnthropicRequest) -> usize {
        use crate::models::ContentBlock;

        // Debug: log message structure for prompt rule detection
        debug!(
            "🔍 find_turn_start_index: {} messages in request",
            request.messages.len()
        );

        for (idx, msg) in request.messages.iter().enumerate().rev() {
            if msg.role == "assistant" {
                // Check if this assistant message has any tool_use blocks
                let has_tool_use = match &msg.content {
                    MessageContent::Text(_) => false,
                    MessageContent::Blocks(blocks) => blocks.iter().any(|block| {
                        matches!(
                            block,
                            ContentBlock::Known(crate::models::KnownContentBlock::ToolUse { .. })
                        )
                    }),
                };

                debug!(
                    "🔍 Assistant msg at idx={}: has_tool_use={}",
                    idx, has_tool_use
                );

                if !has_tool_use {
                    // This assistant message ends the previous turn
                    // Current turn starts after this message
                    debug!(
                        "🔍 Turn starts at idx={} (after assistant without tool_use)",
                        idx + 1
                    );
                    return idx + 1;
                }
            }
        }

        debug!("🔍 No turn boundary found, starting from idx=0");
        0 // No assistant message found, start from beginning
    }

    fn extract_turn_starting_user_message(&self, request: &AnthropicRequest) -> Option<String> {
        let turn_start_idx = self.find_turn_start_index(request);

        // Find the first user message with text content from turn_start_idx onwards
        for (offset, msg) in request.messages.iter().skip(turn_start_idx).enumerate() {
            if msg.role != "user" {
                continue;
            }

            // Check if this user message has text content (not just tool_result)
            let text_content = match &msg.content {
                MessageContent::Text(text) => {
                    if !text.trim().is_empty() && !text.trim().starts_with("<system-reminder>") {
                        Some(text.clone())
                    } else {
                        None
                    }
                }
                MessageContent::Blocks(blocks) => {
                    // Get text blocks, excluding system-reminder blocks (which are generated by client)
                    let text: String = blocks
                        .iter()
                        .filter_map(|block| block.as_text())
                        .filter(|s| !s.trim().starts_with("<system-reminder>"))
                        .collect::<Vec<_>>()
                        .join(" ");
                    if text.trim().is_empty() {
                        None
                    } else {
                        Some(text)
                    }
                }
            };

            if let Some(ref content) = text_content {
                let preview: String = content.chars().take(80).collect();
                debug!(
                    "🔍 Turn-starting user msg at idx={}: {:?}{}",
                    turn_start_idx + offset,
                    preview,
                    if content.len() > 80 { "..." } else { "" }
                );
                return text_content;
            }
        }

        // Fallback to last user message if no turn-starting message found
        debug!("🔍 No turn-starting user message found, falling back to last user message");
        self.extract_last_user_message(request)
    }

    /// Strip the matched phrase from the turn-starting user message
    fn strip_match_from_turn_starting_message(
        &self,
        request: &mut AnthropicRequest,
        regex: &Regex,
    ) {
        let turn_start_idx = self.find_turn_start_index(request);

        // Find the first user message with text content from turn_start_idx onwards
        for msg in request.messages.iter_mut().skip(turn_start_idx) {
            if msg.role != "user" {
                continue;
            }

            // Check if this message has non-system-reminder text content
            let has_text = match &msg.content {
                MessageContent::Text(text) => {
                    !text.trim().is_empty() && !text.trim().starts_with("<system-reminder>")
                }
                MessageContent::Blocks(blocks) => blocks.iter().any(|block| {
                    block
                        .as_text()
                        .map(|s| !s.trim().is_empty() && !s.trim().starts_with("<system-reminder>"))
                        .unwrap_or(false)
                }),
            };

            if has_text {
                // This is the turn-starting message, strip from it and return
                match &mut msg.content {
                    MessageContent::Text(text) => {
                        let new_text = regex.replace_all(text, "").to_string();
                        if new_text != *text {
                            debug!("🔪 Stripped matched phrase from turn-starting prompt");
                            *text = new_text;
                        }
                    }
                    MessageContent::Blocks(blocks) => {
                        for block in blocks.iter_mut() {
                            if let Some(text) = block.as_text_mut() {
                                let new_text = regex.replace_all(text, "").to_string();
                                if new_text != *text {
                                    debug!("🔪 Stripped matched phrase from turn-starting prompt block");
                                    *text = new_text;
                                }
                            }
                        }
                    }
                }
                return;
            }
        }

        // Fallback: strip from last user message if no turn-starting message found
        // (matches the fallback behavior in extract_turn_starting_user_message)
        self.strip_match_from_last_user_message(request, regex);
    }

    /// Strip the matched phrase from the last user message (fallback for edge cases)
    fn strip_match_from_last_user_message(&self, request: &mut AnthropicRequest, regex: &Regex) {
        // Find the last user message (mutable)
        let last_user = request.messages.iter_mut().rev().find(|m| m.role == "user");

        if let Some(msg) = last_user {
            match &mut msg.content {
                MessageContent::Text(text) => {
                    let stripped = regex.replace_all(text, "").to_string();
                    if stripped != *text {
                        debug!("🔪 Stripped matched phrase from prompt");
                        *text = stripped;
                    }
                }
                MessageContent::Blocks(blocks) => {
                    // Strip from all text blocks
                    for block in blocks.iter_mut() {
                        if let Some(text) = block.as_text_mut() {
                            let stripped = regex.replace_all(text, "").to_string();
                            if stripped != *text {
                                debug!("🔪 Stripped matched phrase from prompt block");
                                *text = stripped;
                            }
                        }
                    }
                }
            }
        }
    }

    /// Extract subagent model from system prompt tag
    /// Checks for <GROB-SUBAGENT-MODEL>model-name</GROB-SUBAGENT-MODEL> in system[1].text
    /// and removes the tag after extraction.
    ///
    /// First attempts to resolve the tag value as a model name in the models config.
    /// Falls back to treating it as a direct provider model name (deprecated behavior).
    fn extract_subagent_model(&self, request: &mut AnthropicRequest) -> Option<String> {
        // Check if system exists and is Blocks type with at least 2 blocks
        let system = request.system.as_mut()?;

        if let SystemPrompt::Blocks(blocks) = system {
            if blocks.len() < 2 {
                return None;
            }

            // Check second block (index 1) for tag
            let second_block = &mut blocks[1];
            if !second_block.text.contains("<GROB-SUBAGENT-MODEL>") {
                return None;
            }

            // Extract model name using pre-compiled regex
            if let Some(captures) = SUBAGENT_TAG_REGEX.captures(&second_block.text) {
                if let Some(model_match) = captures.get(1) {
                    let tag_value = model_match.as_str().to_string();

                    // Remove the tag from the text
                    second_block.text = SUBAGENT_TAG_REGEX
                        .replace_all(&second_block.text, "")
                        .to_string();

                    // First, try to find a model with this name in the models config (case-insensitive)
                    if let Some(_model) = self
                        .config
                        .models
                        .iter()
                        .find(|m| m.name.eq_ignore_ascii_case(&tag_value))
                    {
                        // Found a configured model with this name (use the configured case)
                        return Some(_model.name.clone());
                    }

                    // DEPRECATED: Fall back to treating the tag value as a direct provider model name
                    // This behavior is deprecated and should not be relied upon.
                    // Please configure a named model in the [models] section instead.
                    debug!("⚠️  GROB-SUBAGENT-MODEL tag '{}' not found in models config, using as direct provider model name (deprecated)", tag_value);
                    return Some(tag_value);
                }
            }
        }

        None
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
            tool_choice: None,
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
        assert!(super::contains_capture_reference("$1"));
        assert!(super::contains_capture_reference("$model"));
        assert!(super::contains_capture_reference("${1}"));
        assert!(super::contains_capture_reference("${name}"));
        assert!(super::contains_capture_reference("prefix-$1-suffix"));
        assert!(!super::contains_capture_reference("static-model"));
        assert!(!super::contains_capture_reference("no-refs-here"));
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
        let mut request = AnthropicRequest {
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
        let mut request = AnthropicRequest {
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

        let mut request = AnthropicRequest {
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

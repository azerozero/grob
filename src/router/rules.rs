use crate::models::{AnthropicRequest, ContentBlock, MessageContent, SystemPrompt};
use regex::Regex;
use std::sync::LazyLock;
use tracing::debug;

use super::Router;

/// Regex to detect capture group references ($1, $name, ${1}, ${name}).
/// SAFETY: pattern is a compile-time constant; unwrap cannot fail.
pub(super) static CAPTURE_REF_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$(?:\d+|[a-zA-Z_]\w*|\{[^}]+\})").unwrap());

/// Pre-compiled regex for subagent model tag extraction (avoids per-request compilation).
/// SAFETY: pattern is a compile-time constant; unwrap cannot fail.
static SUBAGENT_TAG_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"<GROB-SUBAGENT-MODEL>(.*?)</GROB-SUBAGENT-MODEL>").unwrap());

/// Check if a string contains capture group references
pub(super) fn contains_capture_reference(s: &str) -> bool {
    s.contains('$') && CAPTURE_REF_PATTERN.is_match(s)
}

/// Compile a regex pattern with fallback to a default pattern
pub(super) fn compile_regex_with_fallback(
    pattern: Option<&str>,
    default: &str,
    name: &str,
) -> Option<Regex> {
    let effective = pattern.map(|p| {
        if p.is_empty() {
            Regex::new(default).unwrap_or_else(|_| panic!("Invalid default {} regex", name))
        } else {
            match Regex::new(p) {
                Ok(regex) => regex,
                Err(e) => {
                    tracing::warn!("Invalid {} pattern '{}': {}", name, p, e);
                    tracing::warn!("Falling back to default {} pattern", name);
                    Regex::new(default).unwrap_or_else(|_| panic!("Invalid default {} regex", name))
                }
            }
        }
    });
    effective.or_else(|| {
        Some(Regex::new(default).unwrap_or_else(|_| panic!("Invalid default {} regex", name)))
    })
}

impl Router {
    /// Match prompt rules against the turn-starting user message content.
    /// Returns (model_name, matched_text) if a rule matches, None otherwise.
    pub(super) fn match_prompt_rule(
        &self,
        request: &mut AnthropicRequest,
    ) -> Option<(String, String)> {
        if self.prompt_rules.is_empty() {
            return None;
        }

        // Debug: dump message structure for troubleshooting
        if tracing::enabled!(tracing::Level::DEBUG) {
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
    fn expand_model_template(template: &str, captures: &regex::Captures) -> String {
        let mut expanded = String::new();
        captures.expand(template, &mut expanded);
        expanded
    }

    /// Extract subagent model from system prompt tag.
    /// Checks for <GROB-SUBAGENT-MODEL>model-name</GROB-SUBAGENT-MODEL> in system[1].text
    /// and removes the tag after extraction.
    pub(super) fn extract_subagent_model(&self, request: &mut AnthropicRequest) -> Option<String> {
        let system = request.system.as_mut()?;

        if let SystemPrompt::Blocks(blocks) = system {
            if blocks.len() < 2 {
                return None;
            }

            let second_block = &mut blocks[1];
            if !second_block.text.contains("<GROB-SUBAGENT-MODEL>") {
                return None;
            }

            if let Some(captures) = SUBAGENT_TAG_REGEX.captures(&second_block.text) {
                if let Some(model_match) = captures.get(1) {
                    let tag_value = model_match.as_str().to_string();

                    // Remove the tag from the text
                    second_block.text = SUBAGENT_TAG_REGEX
                        .replace_all(&second_block.text, "")
                        .to_string();

                    // First, try to find a model with this name in the models config
                    if let Some(model) = self
                        .config
                        .models
                        .iter()
                        .find(|m| m.name.eq_ignore_ascii_case(&tag_value))
                    {
                        return Some(model.name.clone());
                    }

                    // DEPRECATED: Fall back to treating the tag value as a direct provider model name
                    debug!("⚠️  GROB-SUBAGENT-MODEL tag '{}' not found in models config, using as direct provider model name (deprecated)", tag_value);
                    return Some(tag_value);
                }
            }
        }

        None
    }
}

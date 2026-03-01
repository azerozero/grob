use crate::models::{AnthropicRequest, MessageContent};
use regex::Regex;
use tracing::debug;

use super::Router;

impl Router {
    /// Extract the text content from the last user message
    pub(super) fn extract_last_user_message(&self, request: &AnthropicRequest) -> Option<String> {
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

    /// Find the index where the current turn starts.
    ///
    /// A "turn" starts when:
    /// 1. The conversation begins, OR
    /// 2. After an assistant message that has no tool_use (i.e., the previous turn ended)
    pub(super) fn find_turn_start_index(&self, request: &AnthropicRequest) -> usize {
        use crate::models::ContentBlock;

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
                    debug!(
                        "🔍 Turn starts at idx={} (after assistant without tool_use)",
                        idx + 1
                    );
                    return idx + 1;
                }
            }
        }

        debug!("🔍 No turn boundary found, starting from idx=0");
        0
    }

    /// Extract the text content from the turn-starting user message.
    ///
    /// This allows prompt phrases like "OPUS" to persist throughout a turn,
    /// even when the model makes tool calls and the last user message is just tool results.
    pub(super) fn extract_turn_starting_user_message(
        &self,
        request: &AnthropicRequest,
    ) -> Option<String> {
        let turn_start_idx = self.find_turn_start_index(request);

        // Find the first user message with text content from turn_start_idx onwards
        for (offset, msg) in request.messages.iter().skip(turn_start_idx).enumerate() {
            if msg.role != "user" {
                continue;
            }

            let text_content = match &msg.content {
                MessageContent::Text(text) => {
                    if !text.trim().is_empty() && !text.trim().starts_with("<system-reminder>") {
                        Some(text.clone())
                    } else {
                        None
                    }
                }
                MessageContent::Blocks(blocks) => {
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
    pub(super) fn strip_match_from_turn_starting_message(
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
                strip_regex_from_content(&mut msg.content, regex);
                return;
            }
        }

        // Fallback: strip from last user message
        self.strip_match_from_last_user_message(request, regex);
    }

    /// Strip the matched phrase from the last user message (fallback for edge cases)
    fn strip_match_from_last_user_message(&self, request: &mut AnthropicRequest, regex: &Regex) {
        let last_user = request.messages.iter_mut().rev().find(|m| m.role == "user");

        if let Some(msg) = last_user {
            strip_regex_from_content(&mut msg.content, regex);
        }
    }
}

/// Apply a regex replacement to all text within a message content (Text or Blocks).
fn strip_regex_from_content(content: &mut MessageContent, regex: &Regex) {
    match content {
        MessageContent::Text(text) => {
            let new_text = regex.replace_all(text, "").to_string();
            if new_text != *text {
                debug!("🔪 Stripped matched phrase from prompt");
                *text = new_text;
            }
        }
        MessageContent::Blocks(blocks) => {
            for block in blocks.iter_mut() {
                if let Some(text) = block.as_text_mut() {
                    let new_text = regex.replace_all(text, "").to_string();
                    if new_text != *text {
                        debug!("🔪 Stripped matched phrase from prompt block");
                        *text = new_text;
                    }
                }
            }
        }
    }
}

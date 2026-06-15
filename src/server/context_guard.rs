//! Pre-dispatch context-window guard.
//!
//! The guard is deliberately cheap: it uses Grob's existing character-count
//! token estimate so oversized requests fail before provider dispatch and
//! before ambiguous upstream 5xx wrappers can confuse clients.

use crate::models::{CanonicalRequest, MessageContent};

const WARN_RATIO: f32 = 0.80;
const HARD_RATIO: f32 = 0.95;
const DEFAULT_CONTEXT_WINDOW_TOKENS: u32 = 128_000;
const HANDOFF_MAX_CHARS: usize = 600;

#[derive(Debug, Clone)]
pub(crate) struct ContextGuardInfo {
    pub estimated_input_tokens: u32,
    pub context_window: u32,
    pub usage_ratio: f32,
    pub should_compact: bool,
    pub handoff: Option<String>,
}

impl ContextGuardInfo {
    pub(crate) fn compact_headers(&self) -> Vec<(&'static str, String)> {
        let mut headers = vec![
            ("x-grob-action", "compact".to_string()),
            ("x-grob-context-used", format!("{:.4}", self.usage_ratio)),
            ("x-grob-context-window", self.context_window.to_string()),
            (
                "x-grob-context-estimated-input",
                self.estimated_input_tokens.to_string(),
            ),
        ];
        if self.should_compact {
            headers.push(("x-grob-context-threshold", "hard".to_string()));
        } else {
            headers.push(("x-grob-context-threshold", "warn".to_string()));
        }
        headers
    }
}

pub(crate) enum ContextGuardDecision {
    Ok,
    Warn(ContextGuardInfo),
    Block(ContextGuardInfo),
}

pub(crate) fn evaluate_context_guard(
    inner: &crate::server::ReloadableState,
    request: &CanonicalRequest,
    logical_model: &str,
    first_mapping: Option<&crate::cli::ModelMapping>,
) -> ContextGuardDecision {
    let context_window = resolve_context_window(inner, logical_model, first_mapping);
    let estimated_input_tokens = crate::server::estimate_input_tokens(request);
    let usage_ratio = if context_window == 0 {
        0.0
    } else {
        estimated_input_tokens as f32 / context_window as f32
    };

    if usage_ratio < WARN_RATIO {
        return ContextGuardDecision::Ok;
    }

    let info = ContextGuardInfo {
        estimated_input_tokens,
        context_window,
        usage_ratio,
        should_compact: usage_ratio >= HARD_RATIO,
        handoff: extract_last_recap(request),
    };

    if info.should_compact {
        ContextGuardDecision::Block(info)
    } else {
        ContextGuardDecision::Warn(info)
    }
}

fn resolve_context_window(
    inner: &crate::server::ReloadableState,
    logical_model: &str,
    first_mapping: Option<&crate::cli::ModelMapping>,
) -> u32 {
    if let Some(configured) = inner
        .find_model(logical_model)
        .and_then(|m| m.context_window_tokens)
    {
        return configured.max(1);
    }

    let actual_model = first_mapping.map(|m| m.actual_model.as_str());
    infer_context_window(logical_model, actual_model)
}

fn infer_context_window(logical_model: &str, actual_model: Option<&str>) -> u32 {
    let mut names = vec![logical_model.to_ascii_lowercase()];
    if let Some(actual) = actual_model {
        names.push(actual.to_ascii_lowercase());
    }
    let joined = names.join(" ");

    if joined.contains("grok") && (joined.contains("4") || joined.contains("2m")) {
        return 2_000_000;
    }
    if joined.contains("gemini-1.5") || joined.contains("gemini-2") {
        return 1_000_000;
    }
    if joined.contains("claude") {
        return 200_000;
    }
    if joined.contains("gpt-4.1") || joined.contains("gpt-4o") || joined.contains("gpt-5") {
        return 128_000;
    }
    if joined.contains("gemma") || joined.contains("qwen") || joined.contains("llama") {
        return 128_000;
    }

    DEFAULT_CONTEXT_WINDOW_TOKENS
}

fn extract_last_recap(request: &CanonicalRequest) -> Option<String> {
    request
        .messages
        .iter()
        .rev()
        .filter_map(message_text)
        .find_map(extract_recap_from_text)
}

fn message_text(message: &crate::models::Message) -> Option<String> {
    match &message.content {
        MessageContent::Text(text) => Some(text.clone()),
        MessageContent::Blocks(blocks) => {
            let text = blocks
                .iter()
                .filter_map(|block| match block {
                    crate::models::ContentBlock::Known(
                        crate::models::KnownContentBlock::Text { text, .. },
                    ) => Some(text.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("\n");
            (!text.is_empty()).then_some(text)
        }
    }
}

fn extract_recap_from_text(text: String) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let idx = lower.find("recap:")?;
    let recap = text[idx + "recap:".len()..].trim();
    if recap.is_empty() {
        return None;
    }
    Some(truncate_chars(recap, HANDOFF_MAX_CHARS))
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let mut out = value.chars().take(max_chars).collect::<String>();
    out.push_str("...");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{CanonicalRequest, Message, MessageContent};

    fn request_with_text(text: &str) -> CanonicalRequest {
        CanonicalRequest {
            model: "default".to_string(),
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
    fn infer_context_window_handles_provider_families() {
        assert_eq!(
            infer_context_window("default", Some("claude-sonnet-4-5")),
            200_000
        );
        assert_eq!(
            infer_context_window("default", Some("gemini-2.5-pro")),
            1_000_000
        );
        assert_eq!(
            infer_context_window("default", Some("google/gemma-3-27b-it")),
            128_000
        );
    }

    #[test]
    fn extracts_last_recap() {
        let req = request_with_text("foo\nrecap: keep this short\nnext");
        assert_eq!(
            extract_last_recap(&req).as_deref(),
            Some("keep this short\nnext")
        );
    }
}

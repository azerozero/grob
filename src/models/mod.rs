use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Anthropic API request format
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AnthropicRequest {
    pub model: String,
    pub messages: Vec<Message>,
    pub max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thinking: Option<ThinkingConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_k: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_sequences: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<SystemPrompt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<Tool>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<serde_json::Value>,
}

/// Message in the conversation
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Message {
    pub role: String,
    pub content: MessageContent,
}

/// Message content can be string or array of content blocks
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum MessageContent {
    Text(String),
    Blocks(Vec<ContentBlock>),
}

/// System prompt can be string or array of system blocks
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum SystemPrompt {
    Text(String),
    Blocks(Vec<SystemBlock>),
}

/// System message block
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SystemBlock {
    pub r#type: String,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_control: Option<serde_json::Value>,
}

/// Tool result content can be string or array of content blocks
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ToolResultContent {
    Text(String),
    Blocks(Vec<ToolResultBlock>),
}

impl std::fmt::Display for ToolResultContent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ToolResultContent::Text(s) => write!(f, "{}", s),
            ToolResultContent::Blocks(blocks) => {
                let text = blocks
                    .iter()
                    .map(|block| match block {
                        ToolResultBlock::Known(KnownToolResultBlock::Text { text }) => text.clone(),
                        ToolResultBlock::Known(KnownToolResultBlock::Image { .. }) => {
                            "[Image]".to_string()
                        }
                        ToolResultBlock::Unknown(_) => "[Unknown]".to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                write!(f, "{}", text)
            }
        }
    }
}

/// Content blocks allowed in tool results.
/// Uses untagged enum to handle unknown types (like tool_reference) gracefully.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ToolResultBlock {
    Known(KnownToolResultBlock),
    Unknown(serde_json::Value),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum KnownToolResultBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "image")]
    Image { source: ImageSource },
}

/// Content block for multimodal messages.
///
/// Uses untagged deserialization with a two-level approach:
/// 1. First tries to parse as a KnownContentBlock (text, image, tool_use, etc.)
/// 2. If that fails, falls back to Unknown which captures the raw JSON
///
/// This allows the proxy to handle new content types (like "document" for PDFs,
/// or future types Anthropic may add) without failing to parse. Unknown types
/// are passed through unchanged to the backend provider.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ContentBlock {
    /// Known content types with structured parsing
    Known(KnownContentBlock),
    /// Unknown content types - pass through as raw JSON
    Unknown(serde_json::Value),
}

/// Known content block types that we parse specifically
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum KnownContentBlock {
    #[serde(rename = "text")]
    Text {
        text: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_control: Option<serde_json::Value>,
    },
    #[serde(rename = "image")]
    Image { source: ImageSource },
    #[serde(rename = "tool_use")]
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    #[serde(rename = "tool_result")]
    ToolResult {
        tool_use_id: String,
        content: ToolResultContent,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        is_error: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_control: Option<serde_json::Value>,
    },
    /// Thinking block - stored as raw JSON to preserve exact signature.
    #[serde(rename = "thinking")]
    Thinking {
        #[serde(flatten)]
        raw: serde_json::Value,
    },
}

// Convenience constructors for ContentBlock
impl ContentBlock {
    pub fn text(text: String, cache_control: Option<serde_json::Value>) -> Self {
        ContentBlock::Known(KnownContentBlock::Text {
            text,
            cache_control,
        })
    }

    pub fn image(source: ImageSource) -> Self {
        ContentBlock::Known(KnownContentBlock::Image { source })
    }

    pub fn tool_use(id: String, name: String, input: serde_json::Value) -> Self {
        ContentBlock::Known(KnownContentBlock::ToolUse { id, name, input })
    }

    pub fn thinking(raw: serde_json::Value) -> Self {
        ContentBlock::Known(KnownContentBlock::Thinking { raw })
    }

    /// Check if this is a tool result block
    pub fn is_tool_result(&self) -> bool {
        matches!(
            self,
            ContentBlock::Known(KnownContentBlock::ToolResult { .. })
        )
    }

    /// Get text content if this is a text block
    pub fn as_text(&self) -> Option<&str> {
        match self {
            ContentBlock::Known(KnownContentBlock::Text { text, .. }) => Some(text),
            _ => None,
        }
    }

    /// Get mutable reference to text content if this is a text block
    pub fn as_text_mut(&mut self) -> Option<&mut String> {
        match self {
            ContentBlock::Known(KnownContentBlock::Text { text, .. }) => Some(text),
            _ => None,
        }
    }
}

/// Image source for vision API
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ImageSource {
    pub r#type: String, // "base64" or "url"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// Tool definition for function calling
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Tool {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<serde_json::Value>,
}

/// Thinking/reasoning configuration for Plan Mode
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ThinkingConfig {
    pub r#type: String, // "enabled" or "disabled"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_tokens: Option<u32>,
}

/// Token usage information
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Usage {
    pub input_tokens: u32,
    pub output_tokens: u32,
}

/// Request for counting tokens
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CountTokensRequest {
    pub model: String,
    pub messages: Vec<Message>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<SystemPrompt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<Tool>>,
}

/// Response for token counting
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CountTokensResponse {
    pub input_tokens: u32,
}

/// Returns a sensible default max_tokens for a given model when the client
/// doesn't specify one. Based on each model's documented output token limit.
///
/// This is used by the OpenAI compat layer where max_tokens is optional.
/// Anthropic-native clients must always provide max_tokens explicitly.
pub fn default_max_tokens(model: &str) -> u32 {
    let m = model.to_lowercase();

    // --- OpenAI reasoning models (o-series) ---
    // o3, o4-mini support up to 100k output; use conservative 32k default
    if m.starts_with("o1") || m.starts_with("o3") || m.starts_with("o4") {
        return 32768;
    }

    // --- OpenAI GPT-4.1 family: 32k output ---
    if m.contains("gpt-4.1") {
        return 32768;
    }

    // --- OpenAI GPT-4o family: 16k output ---
    if m.contains("gpt-4o") {
        return 16384;
    }

    // --- OpenAI GPT-4 turbo / GPT-3.5: 4k output ---
    if m.contains("gpt-4-turbo") || m.contains("gpt-3.5") || m.contains("gpt-4-") {
        return 4096;
    }

    // --- Gemini 2.5 family: 65k output ---
    if m.contains("gemini-2.5") {
        return 65536;
    }

    // --- Gemini 2.0 / 1.5: 8k output ---
    if m.contains("gemini-2.0") || m.contains("gemini-1.5") || m.contains("gemini-1.0") {
        return 8192;
    }

    // --- Anthropic Claude 4.x (opus, sonnet): 16k default (up to 128k with extended output) ---
    if m.contains("claude-opus") || m.contains("claude-sonnet-4") {
        return 16384;
    }

    // --- Anthropic Claude 3.5 / Haiku 4.5: 8k ---
    if m.contains("claude-3.5") || m.contains("claude-3-5") || m.contains("claude-haiku") {
        return 8192;
    }

    // --- Anthropic Claude 3 Opus: 4k ---
    if m.contains("claude-3-opus") || m.contains("claude-3.0") {
        return 4096;
    }

    // --- DeepSeek: 8k ---
    if m.contains("deepseek") {
        return 8192;
    }

    // --- Codex: 16k ---
    if m.contains("codex") {
        return 16384;
    }

    // Fallback: safe default for unknown models
    8192
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_max_tokens_anthropic() {
        assert_eq!(default_max_tokens("claude-opus-4-6"), 16384);
        assert_eq!(default_max_tokens("claude-sonnet-4-6"), 16384);
        assert_eq!(default_max_tokens("claude-sonnet-4-5-20250514"), 16384);
        assert_eq!(default_max_tokens("claude-haiku-4-5"), 8192);
        assert_eq!(default_max_tokens("claude-3.5-sonnet-20241022"), 8192);
        assert_eq!(default_max_tokens("claude-3-5-sonnet-20241022"), 8192);
        assert_eq!(default_max_tokens("claude-3-opus-20240229"), 4096);
    }

    #[test]
    fn test_default_max_tokens_openai() {
        assert_eq!(default_max_tokens("gpt-4o"), 16384);
        assert_eq!(default_max_tokens("gpt-4o-mini"), 16384);
        assert_eq!(default_max_tokens("gpt-4.1"), 32768);
        assert_eq!(default_max_tokens("gpt-4.1-mini"), 32768);
        assert_eq!(default_max_tokens("gpt-4.1-nano"), 32768);
        assert_eq!(default_max_tokens("gpt-4-turbo"), 4096);
        assert_eq!(default_max_tokens("gpt-3.5-turbo"), 4096);
        assert_eq!(default_max_tokens("o3"), 32768);
        assert_eq!(default_max_tokens("o3-mini"), 32768);
        assert_eq!(default_max_tokens("o4-mini"), 32768);
    }

    #[test]
    fn test_default_max_tokens_gemini() {
        assert_eq!(default_max_tokens("gemini-2.5-pro"), 65536);
        assert_eq!(default_max_tokens("gemini-2.5-flash"), 65536);
        assert_eq!(default_max_tokens("gemini-2.0-flash"), 8192);
        assert_eq!(default_max_tokens("gemini-1.5-pro"), 8192);
    }

    #[test]
    fn test_default_max_tokens_other() {
        assert_eq!(default_max_tokens("deepseek-chat"), 8192);
        assert_eq!(default_max_tokens("deepseek-reasoner"), 8192);
        assert_eq!(default_max_tokens("codex-mini"), 16384);
        // Unknown model gets safe fallback
        assert_eq!(default_max_tokens("some-unknown-model"), 8192);
    }
}

/// Router decision result
#[derive(Debug, Clone)]
pub struct RouteDecision {
    pub model_name: String,
    pub route_type: RouteType,
    pub matched_prompt: Option<String>,
}

/// Type of routing decision
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteType {
    WebSearch,
    PromptRule,
    Think,
    Background,
    Default,
}

impl std::fmt::Display for RouteType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouteType::WebSearch => write!(f, "web-search"),
            RouteType::PromptRule => write!(f, "prompt-rule"),
            RouteType::Think => write!(f, "think"),
            RouteType::Background => write!(f, "background"),
            RouteType::Default => write!(f, "default"),
        }
    }
}

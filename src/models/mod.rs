//! Shared data models: Anthropic request/response types, routing types.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Anthropic API request format
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AnthropicRequest {
    /// Target model identifier (e.g. "claude-sonnet-4-20250514").
    pub model: String,
    /// Ordered conversation messages between user and assistant.
    pub messages: Vec<Message>,
    /// Maximum number of output tokens to generate.
    pub max_tokens: u32,
    /// Extended thinking / reasoning configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thinking: Option<ThinkingConfig>,
    /// Sampling temperature (0.0 = deterministic, 1.0 = creative).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    /// Nucleus sampling probability cutoff.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    /// Top-k sampling: considers only the k most likely tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_k: Option<u32>,
    /// Custom stop sequences that halt generation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_sequences: Option<Vec<String>>,
    /// Enables server-sent event streaming when true.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    /// Arbitrary key-value metadata attached to the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    /// System prompt prepended to the conversation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<SystemPrompt>,
    /// Tool definitions available for function calling.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<Tool>>,
    /// Controls which tool the model should use, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<serde_json::Value>,
}

/// Message in the conversation
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Message {
    /// Participant role: "user", "assistant", or "system".
    pub role: String,
    /// Payload of the message (plain text or structured blocks).
    pub content: MessageContent,
}

/// Message content can be string or array of content blocks
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum MessageContent {
    /// Plain text content as a single string.
    Text(String),
    /// Structured array of typed content blocks.
    Blocks(Vec<ContentBlock>),
}

/// System prompt can be string or array of system blocks
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum SystemPrompt {
    /// Plain text system prompt.
    Text(String),
    /// Array of typed system blocks with optional cache control.
    Blocks(Vec<SystemBlock>),
}

impl SystemPrompt {
    /// Converts the system prompt to a single plain-text string.
    pub fn to_text(&self) -> String {
        match self {
            SystemPrompt::Text(text) => text.clone(),
            SystemPrompt::Blocks(blocks) => blocks
                .iter()
                .map(|b| b.text.clone())
                .collect::<Vec<_>>()
                .join("\n"),
        }
    }
}

/// System message block
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SystemBlock {
    /// Block type identifier (typically "text").
    pub r#type: String,
    /// Text content of the system block.
    pub text: String,
    /// Cache control directives for prompt caching.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_control: Option<serde_json::Value>,
}

/// Tool result content can be string or array of content blocks
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ToolResultContent {
    /// Plain text tool output.
    Text(String),
    /// Structured blocks (text, images) from tool execution.
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
    /// Recognized block type (text or image).
    Known(KnownToolResultBlock),
    /// Unrecognized block type preserved as raw JSON passthrough.
    Unknown(serde_json::Value),
}

/// Recognized content block types within tool results.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum KnownToolResultBlock {
    /// Plain text output from a tool invocation.
    #[serde(rename = "text")]
    Text {
        /// The text content returned by the tool.
        text: String,
    },
    /// Image output from a tool invocation.
    #[serde(rename = "image")]
    Image {
        /// Image data source (base64 or URL).
        source: ImageSource,
    },
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
    /// Plain text content block with optional cache control.
    #[serde(rename = "text")]
    Text {
        /// The text content of the block.
        text: String,
        /// Cache control directives for prompt caching.
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_control: Option<serde_json::Value>,
    },
    /// Inline image content block.
    #[serde(rename = "image")]
    Image {
        /// Image data source (base64 or URL).
        source: ImageSource,
    },
    /// Model-initiated tool invocation block.
    #[serde(rename = "tool_use")]
    ToolUse {
        /// Unique identifier for this tool use (referenced by tool_result).
        id: String,
        /// Name of the tool being invoked.
        name: String,
        /// JSON input arguments passed to the tool.
        input: serde_json::Value,
    },
    /// Result returned from a tool invocation.
    #[serde(rename = "tool_result")]
    ToolResult {
        /// Identifier of the tool_use block this result corresponds to.
        tool_use_id: String,
        /// Content returned by the tool (text or structured blocks).
        content: ToolResultContent,
        /// Indicates the tool invocation ended in an error.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        is_error: bool,
        /// Cache control directives for prompt caching.
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_control: Option<serde_json::Value>,
    },
    /// Thinking block - stored as raw JSON to preserve exact signature.
    #[serde(rename = "thinking")]
    Thinking {
        /// Raw JSON preserving the full thinking block structure.
        #[serde(flatten)]
        raw: serde_json::Value,
    },
}

// Convenience constructors for ContentBlock
impl ContentBlock {
    /// Creates a text content block with optional cache control.
    pub fn text(text: String, cache_control: Option<serde_json::Value>) -> Self {
        ContentBlock::Known(KnownContentBlock::Text {
            text,
            cache_control,
        })
    }

    /// Creates an image content block from the given source.
    pub fn image(source: ImageSource) -> Self {
        ContentBlock::Known(KnownContentBlock::Image { source })
    }

    /// Creates a tool-use content block with the given parameters.
    pub fn tool_use(id: String, name: String, input: serde_json::Value) -> Self {
        ContentBlock::Known(KnownContentBlock::ToolUse { id, name, input })
    }

    /// Creates a thinking content block from raw JSON.
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
    /// Source type: "base64" for inline data or "url" for remote.
    pub r#type: String,
    /// MIME type of the image (e.g. "image/png").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    /// Base64-encoded image data (when type is "base64").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    /// Remote URL of the image (when type is "url").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// Tool definition for function calling
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Tool {
    /// Tool type (e.g. "function", "computer_20250124").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    /// Unique name identifying the tool.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Human-readable description of what the tool does.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// JSON Schema defining the expected input parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<serde_json::Value>,
}

/// Thinking/reasoning configuration for Plan Mode
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ThinkingConfig {
    /// Thinking mode: "enabled" or "disabled".
    pub r#type: String,
    /// Maximum tokens allocated for the thinking phase.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_tokens: Option<u32>,
}

/// Request for counting tokens
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CountTokensRequest {
    /// Model to use for tokenization.
    pub model: String,
    /// Conversation messages to count tokens for.
    pub messages: Vec<Message>,
    /// Optional system prompt included in the token count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<SystemPrompt>,
    /// Optional tool definitions included in the token count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<Tool>>,
}

/// Response for token counting
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CountTokensResponse {
    /// Total number of input tokens counted.
    pub input_tokens: u32,
}

/// Prefix-matched model patterns mapped to default max output tokens.
const MODEL_MAX_TOKENS_PREFIX: &[(&str, u32)] = &[
    ("o1", 32_768), // OpenAI reasoning models (o-series): up to 100k, conservative 32k
    ("o3", 32_768),
    ("o4", 32_768),
];

/// Substring-matched model patterns mapped to default max output tokens.
const MODEL_MAX_TOKENS_CONTAINS: &[(&str, u32)] = &[
    ("gpt-4.1", 32_768),         // OpenAI GPT-4.1 family
    ("gpt-4o", 16_384),          // OpenAI GPT-4o family
    ("gpt-4-turbo", 4_096),      // OpenAI GPT-4 turbo
    ("gpt-3.5", 4_096),          // OpenAI GPT-3.5
    ("gpt-4-", 4_096),           // OpenAI GPT-4 variants
    ("gemini-2.5", 65_536),      // Gemini 2.5 family
    ("gemini-2.0", 8_192),       // Gemini 2.0
    ("gemini-1.5", 8_192),       // Gemini 1.5
    ("gemini-1.0", 8_192),       // Gemini 1.0
    ("claude-opus", 16_384),     // Claude 4.x Opus (up to 128k with extended output)
    ("claude-sonnet-4", 16_384), // Claude 4.x Sonnet
    ("claude-3.5", 8_192),       // Claude 3.5
    ("claude-3-5", 8_192),       // Claude 3.5 (alternate naming)
    ("claude-haiku", 8_192),     // Claude Haiku
    ("claude-3-opus", 4_096),    // Claude 3 Opus
    ("claude-3.0", 4_096),       // Claude 3.0
    ("deepseek", 8_192),         // DeepSeek
    ("codex", 16_384),           // Codex
];

/// Fallback max output tokens when no model pattern matches.
const DEFAULT_MAX_TOKENS: u32 = 8_192;

/// Returns a sensible default max_tokens for a given model when the client
/// doesn't specify one. Based on each model's documented output token limit.
///
/// This is used by the OpenAI compat layer where max_tokens is optional.
/// Anthropic-native clients must always provide max_tokens explicitly.
pub fn default_max_tokens(model: &str) -> u32 {
    let model_lower = model.to_lowercase();

    for &(prefix, tokens) in MODEL_MAX_TOKENS_PREFIX {
        if model_lower.starts_with(prefix) {
            return tokens;
        }
    }

    for &(pattern, tokens) in MODEL_MAX_TOKENS_CONTAINS {
        if model_lower.contains(pattern) {
            return tokens;
        }
    }

    DEFAULT_MAX_TOKENS
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
    /// Resolved model name to dispatch the request to.
    pub model_name: String,
    /// Classification of how the route was determined.
    pub route_type: RouteType,
    /// Prompt-rule pattern that matched, if any.
    pub matched_prompt: Option<String>,
}

/// Type of routing decision
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteType {
    /// Routed to a web-search-capable model.
    WebSearch,
    /// Matched an explicit regex prompt rule from config.
    PromptRule,
    /// Routed to a model with extended thinking enabled.
    Think,
    /// Routed to a low-cost model for background tasks.
    Background,
    /// Fell through to the default model.
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

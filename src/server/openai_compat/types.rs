use serde::{Deserialize, Serialize};

/// OpenAI Chat Completions request format
#[derive(Debug, Deserialize)]
pub struct OpenAIRequest {
    /// Target model identifier (e.g. "gpt-4o").
    pub model: String,
    /// Ordered conversation messages forming the prompt.
    pub messages: Vec<OpenAIMessage>,
    /// Upper bound on tokens in the completion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    /// Sampling temperature between 0 and 2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    /// Nucleus sampling probability mass cutoff.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    /// Sequences where the model stops generating further tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop: Option<Vec<String>>,
    /// Enables server-sent event streaming when true.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    /// Tool definitions available for the model to invoke.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<serde_json::Value>>,
    /// Controls how the model selects which tool to call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<serde_json::Value>,
}

/// OpenAI chat message with role-based content
#[derive(Debug, Deserialize)]
pub struct OpenAIMessage {
    /// Message role: "system", "user", "assistant", or "tool".
    pub role: String,
    /// Message body as plain text or structured content parts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<OpenAIContent>,
    /// Optional author name for multi-participant conversations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Tool invocations requested by the assistant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<OpenAIToolCallInput>>,
    /// Identifies which tool call this message responds to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

/// Tool call in an incoming request (assistant message)
#[derive(Debug, Clone, Deserialize)]
pub struct OpenAIToolCallInput {
    /// Unique identifier for this tool call.
    pub id: String,
    /// Tool type, typically "function".
    pub r#type: Option<String>,
    /// Function name and serialized arguments to invoke.
    pub function: OpenAIFunctionInput,
}

/// Function reference in an incoming tool call
#[derive(Debug, Clone, Deserialize)]
pub struct OpenAIFunctionInput {
    /// Name of the function to call.
    pub name: String,
    /// JSON-encoded arguments for the function.
    pub arguments: String,
}

/// Content can be string or array of content parts
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum OpenAIContent {
    /// Represents content as a single plain text string.
    String(String),
    /// Represents content as an array of typed content parts.
    Parts(Vec<OpenAIContentPart>),
}

/// Content part (text or image_url)
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum OpenAIContentPart {
    /// Represents a plain text content segment.
    #[serde(rename = "text")]
    Text {
        /// Plain text content of this segment.
        text: String,
    },
    /// Represents an image referenced by URL or base64 data URI.
    #[serde(rename = "image_url")]
    ImageUrl {
        /// Image URL or base64 data URI payload.
        image_url: OpenAIImageUrl,
    },
}

/// Image URL object
#[derive(Debug, Clone, Deserialize)]
pub struct OpenAIImageUrl {
    /// Image URL or base64-encoded data URI.
    pub url: String,
}

/// OpenAI Chat Completions response format
#[derive(Debug, Serialize)]
pub struct OpenAIResponse {
    /// Unique identifier for this completion (e.g. "chatcmpl-...").
    pub id: String,
    /// Object type, always "chat.completion".
    #[serde(rename = "object")]
    pub object: String,
    /// Unix timestamp when the completion was generated.
    pub created: u64,
    /// Model used to produce the completion.
    pub model: String,
    /// Completion alternatives returned by the model.
    pub choices: Vec<OpenAIChoice>,
    /// Token consumption breakdown for the request.
    pub usage: OpenAIUsage,
}

/// A single completion choice in the response
#[derive(Debug, Serialize)]
pub struct OpenAIChoice {
    /// Zero-based position of this choice in the choices array.
    pub index: u32,
    /// Generated assistant message for this choice.
    pub message: OpenAIResponseMessage,
    /// Reason generation stopped (e.g. "stop", "tool_calls", "length").
    pub finish_reason: Option<String>,
}

/// Response message with optional tool calls
#[derive(Debug, Serialize)]
pub struct OpenAIResponseMessage {
    /// Message role, always "assistant" in responses.
    pub role: String,
    /// Text content of the response, absent when tool calls are emitted.
    pub content: Option<String>,
    /// Tool calls the assistant chose to invoke.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<OpenAIToolCall>>,
}

/// Tool call in a response
#[derive(Debug, Serialize)]
pub struct OpenAIToolCall {
    /// Unique identifier for this tool call.
    pub id: String,
    /// Tool type, always "function".
    pub r#type: String,
    /// Function name and arguments the model wants to invoke.
    pub function: OpenAIFunction,
}

/// Function name and serialized arguments in a tool call response
#[derive(Debug, Serialize)]
pub struct OpenAIFunction {
    /// Name of the function the model invoked.
    pub name: String,
    /// JSON-encoded arguments produced by the model.
    pub arguments: String,
}

/// Token usage statistics
#[derive(Debug, Serialize)]
pub struct OpenAIUsage {
    /// Number of tokens in the input prompt.
    pub prompt_tokens: u32,
    /// Number of tokens in the generated completion.
    pub completion_tokens: u32,
    /// Sum of prompt and completion tokens.
    pub total_tokens: u32,
}

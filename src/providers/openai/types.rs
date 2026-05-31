use serde::{Deserialize, Serialize};

/// OpenAI stream_options for requesting usage in streaming responses
#[derive(Debug, Serialize)]
pub(crate) struct OpenAIStreamOptions {
    pub include_usage: bool,
}

/// OpenAI Chat Completions request format
#[derive(Debug, Serialize)]
pub(crate) struct OpenAIRequest {
    pub model: String,
    pub messages: Vec<OpenAIMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_options: Option<OpenAIStreamOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<OpenAITool>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<serde_json::Value>,

    // ── Extension fields restored from CanonicalRequest.extensions ──
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_format: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency_penalty: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presence_penalty: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parallel_tool_calls: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logprobs: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_logprobs: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_tier: Option<String>,
}

/// OpenAI Responses API request format (for Codex models)
#[derive(Debug, Serialize)]
pub(crate) struct OpenAIResponsesRequest {
    pub model: String,
    pub input: OpenAIResponsesInput,
    /// System instructions for the model (required for ChatGPT Codex)
    pub instructions: String,
    /// Whether to store the conversation (must be false for ChatGPT backend)
    pub store: bool,
    /// Enable streaming responses
    pub stream: bool,
    /// Tool definitions in Responses-API (flattened `function`) shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<serde_json::Value>>,
    /// Tool selection strategy (`"auto"`, `"required"`, or a named function).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<serde_json::Value>,
    /// Whether the model may emit several tool calls in one turn.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parallel_tool_calls: Option<bool>,
    /// Reasoning controls, e.g. `{"effort": "low"}`. Lower effort cuts latency.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<serde_json::Value>,
}

/// Input for Responses API is an array of typed items.
// Single-variant untagged enum so it serializes as a bare JSON array.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub(crate) enum OpenAIResponsesInput {
    Items(Vec<OpenAIResponsesItem>),
}

/// One item in a Responses API `input[]` array.
///
/// Alongside plain `message` items, the ChatGPT Codex backend accepts the
/// `function_call` / `function_call_output` items that carry tool-use history
/// so multi-turn agent loops survive the Anthropic ⇄ Responses translation.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum OpenAIResponsesItem {
    /// A conversational message; `content` is plain text.
    Message {
        role: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        content: Option<String>,
    },
    /// An assistant tool call replayed from history.
    FunctionCall {
        call_id: String,
        name: String,
        /// JSON-encoded arguments string.
        arguments: String,
    },
    /// The output of a tool call, fed back to the model.
    FunctionCallOutput { call_id: String, output: String },
}

/// Content can be string or array of content parts
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum OpenAIContent {
    String(String),
    Parts(Vec<OpenAIContentPart>),
}

/// Content part (text or image_url)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub(crate) enum OpenAIContentPart {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "image_url")]
    ImageUrl { image_url: OpenAIImageUrl },
}

/// Image URL object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OpenAIImageUrl {
    pub url: String,
}

/// Tool call in assistant message
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct OpenAIToolCall {
    pub id: String,
    pub r#type: String, // "function"
    pub function: OpenAIFunctionCall,
}

/// Function call details
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct OpenAIFunctionCall {
    pub name: String,
    pub arguments: String, // JSON string
}

/// Tool definition
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct OpenAITool {
    pub r#type: String, // "function"
    pub function: OpenAIFunctionDef,
}

/// Function definition
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct OpenAIFunctionDef {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct OpenAIMessage {
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<OpenAIContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<OpenAIToolCall>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

/// OpenAI Chat Completions response format
// Fields read by serde deserialization
#[derive(Debug, Deserialize)]
pub(crate) struct OpenAIResponse {
    pub id: String,
    #[serde(default, rename = "object")]
    pub _object: String,
    pub model: String,
    pub choices: Vec<OpenAIChoice>,
    pub usage: OpenAIUsage,
}

#[derive(Debug, Deserialize)]
pub(crate) struct OpenAIChoice {
    pub message: OpenAIMessage,
    pub finish_reason: Option<String>,
}

// Fields read by serde deserialization
#[derive(Debug, Deserialize)]
pub(crate) struct OpenAIUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
}

/// OpenAI Streaming Chunk (for SSE transformation)
// Fields read by serde deserialization
#[derive(Debug, Deserialize)]
pub(crate) struct OpenAIStreamChunk {
    #[serde(default)]
    pub model: String,
    pub choices: Vec<OpenAIStreamChoice>,
    /// Usage data (only present in final chunk when stream_options.include_usage=true)
    #[serde(default)]
    pub usage: Option<OpenAIStreamUsage>,
}

/// Usage data from OpenAI streaming response
// Fields read by serde deserialization
#[derive(Debug, Deserialize)]
pub(crate) struct OpenAIStreamUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
}

// Fields read by serde deserialization
#[derive(Debug, Deserialize)]
pub(crate) struct OpenAIStreamChoice {
    pub delta: OpenAIStreamDelta,
    #[serde(default)]
    pub finish_reason: Option<String>,
}

// Fields read by serde deserialization
#[derive(Debug, Deserialize)]
pub(crate) struct OpenAIStreamDelta {
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub reasoning: Option<String>,
    #[serde(default)]
    pub tool_calls: Option<Vec<serde_json::Value>>,
}

/// OpenAI-compatible error response (returned by some providers in stream body)
#[derive(Debug, Deserialize)]
pub(crate) struct OpenAIStreamError {
    #[serde(default)]
    pub status_code: Option<u16>,
    pub error: OpenAIErrorDetail,
}

#[derive(Debug, Deserialize)]
pub(crate) struct OpenAIErrorDetail {
    pub message: String,
    #[serde(default)]
    pub r#type: Option<String>,
}

/// State for OpenAI → Anthropic SSE transformation
///
/// Tracks streaming state across multiple chunks to properly transform
/// OpenAI's incremental tool call format to Anthropic's content block format.
#[derive(Debug, Default)]
pub(crate) struct StreamTransformState {
    /// Has message_start been emitted?
    pub message_started: bool,
    /// Is a thinking content block currently open?
    pub thinking_block_open: bool,
    /// The block index assigned to the thinking block (if opened)
    pub thinking_block_index: u32,
    /// Is a text content block currently open?
    pub text_block_open: bool,
    /// The block index assigned to the text block (if opened)
    pub text_block_index: u32,
    /// Tool call indices that have had content_block_start emitted
    /// Maps OpenAI tool_call index → Anthropic content_block index
    pub tool_blocks: std::collections::HashMap<u32, u32>,
    /// Next available content block index
    pub next_block_index: u32,
    /// Has finish_reason been received?
    pub stream_ended: bool,
    /// Did this response include any tool calls? (for correct stop_reason)
    pub had_tool_calls: bool,
    /// Pending assistant text awaiting a leaked-tool-call scan.
    ///
    /// Text deltas are buffered here so a `<tool_call>` marker split across
    /// streamed fragments can still be detected before the text is forwarded.
    /// See [`crate::providers::openai::tool_salvage`].
    pub text_buffer: String,
    /// Count of tool calls salvaged from leaked text, used to mint unique ids.
    pub salvaged_tool_count: u32,
    /// Responses-API function-call output index → Anthropic content block index.
    ///
    /// Tracks structured Codex `function_call` items as they stream so argument
    /// deltas land on the right `tool_use` block.
    pub responses_fc_blocks: std::collections::HashMap<u64, u32>,
}

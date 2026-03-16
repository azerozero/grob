//! OpenAI Responses API request and response types.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// OpenAI Responses API request format (`POST /v1/responses`).
#[derive(Debug, Deserialize)]
pub struct ResponsesRequest {
    /// Target model identifier (e.g. "gpt-5.3-codex").
    pub model: String,
    /// System-level instructions prepended to the conversation.
    #[serde(default)]
    pub instructions: Option<String>,
    /// Conversation input: plain text or structured items.
    pub input: ResponsesInput,
    /// Enables server-sent event streaming when true.
    #[serde(default)]
    pub stream: Option<bool>,
    /// Tool definitions available for the model to invoke.
    #[serde(default)]
    pub tools: Option<Vec<Value>>,
    /// Reasoning configuration (e.g. `{ "effort": "high" }`).
    #[serde(default)]
    pub reasoning: Option<ReasoningConfig>,
    /// Sampling temperature between 0 and 2.
    #[serde(default)]
    pub temperature: Option<f32>,
    /// Nucleus sampling probability mass cutoff.
    #[serde(default)]
    pub top_p: Option<f32>,
    /// Upper bound on tokens in the response.
    #[serde(default)]
    pub max_output_tokens: Option<u32>,

    // ── Ignored gracefully (accepted but not processed) ──
    /// Reference to a previous response for multi-turn (ignored by grob).
    #[serde(default)]
    pub previous_response_id: Option<String>,
    /// Whether to persist the response server-side (ignored by grob).
    #[serde(default)]
    pub store: Option<bool>,
    /// Allows parallel tool calls (forwarded via extensions).
    #[serde(default)]
    pub parallel_tool_calls: Option<bool>,
    /// Requested service tier (forwarded via extensions).
    #[serde(default)]
    pub service_tier: Option<String>,
}

/// Conversation input: either a plain text string or structured items.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ResponsesInput {
    /// Simple text prompt.
    Text(String),
    /// Structured conversation items (messages, function calls, outputs).
    Items(Vec<InputItem>),
}

/// A single input item in a Responses API request.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum InputItem {
    /// A conversation message with role and content.
    #[serde(rename = "message")]
    Message {
        /// Message role: "user", "assistant", or "system".
        role: String,
        /// Message content as text or structured parts.
        content: InputContent,
    },
    /// A function call made by the assistant.
    #[serde(rename = "function_call")]
    FunctionCall {
        /// Unique identifier for this function call.
        #[serde(default)]
        id: Option<String>,
        /// Call identifier (alias for id in some SDK versions).
        #[serde(default)]
        call_id: Option<String>,
        /// Function name.
        name: String,
        /// JSON-encoded arguments string.
        arguments: String,
    },
    /// Output from a function call execution.
    #[serde(rename = "function_call_output")]
    FunctionCallOutput {
        /// Identifier of the function call this output responds to.
        call_id: String,
        /// Function execution result as a string.
        output: String,
    },
}

/// Content of an input message: plain text or structured parts.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum InputContent {
    /// Simple text content.
    Text(String),
    /// Array of typed content parts.
    Parts(Vec<InputContentPart>),
}

/// A typed content part within a message.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum InputContentPart {
    /// Text content part.
    #[serde(rename = "input_text")]
    InputText {
        /// The text content.
        text: String,
    },
}

/// Reasoning configuration for o-series and thinking models.
#[derive(Debug, Deserialize)]
pub struct ReasoningConfig {
    /// Reasoning effort level: "low", "medium", "high".
    #[serde(default)]
    pub effort: Option<String>,
}

// ── Response types ──

/// OpenAI Responses API response format.
#[derive(Debug, Serialize)]
pub struct ResponsesResponse {
    /// Unique response identifier (e.g. "resp_xxx").
    pub id: String,
    /// Object type, always "response".
    pub object: &'static str,
    /// Unix timestamp of response creation.
    pub created_at: u64,
    /// Model that generated the response.
    pub model: String,
    /// Output items (messages and function calls).
    pub output: Vec<OutputItem>,
    /// Response status, always "completed" for non-streaming.
    pub status: &'static str,
    /// Token usage statistics.
    pub usage: ResponsesUsage,
}

/// An output item in the Responses API response.
#[derive(Debug, Serialize)]
#[serde(tag = "type")]
pub enum OutputItem {
    /// A text message from the assistant.
    #[serde(rename = "message")]
    Message {
        /// Unique item identifier.
        id: String,
        /// Message role, always "assistant".
        role: &'static str,
        /// Message content parts.
        content: Vec<OutputContent>,
        /// Item status.
        status: &'static str,
    },
    /// A function call requested by the model.
    #[serde(rename = "function_call")]
    FunctionCall {
        /// Unique item identifier.
        id: String,
        /// Call identifier for matching with function_call_output.
        call_id: String,
        /// Function name.
        name: String,
        /// JSON-encoded function arguments.
        arguments: String,
        /// Item status.
        status: &'static str,
    },
}

/// Content within an output message.
#[derive(Debug, Serialize)]
#[serde(tag = "type")]
pub enum OutputContent {
    /// Text content block.
    #[serde(rename = "output_text")]
    OutputText {
        /// The text content.
        text: String,
    },
}

/// Token usage for the Responses API.
#[derive(Debug, Serialize)]
pub struct ResponsesUsage {
    /// Number of tokens in the input.
    pub input_tokens: u32,
    /// Number of tokens in the output.
    pub output_tokens: u32,
    /// Total tokens (input + output).
    pub total_tokens: u32,
}

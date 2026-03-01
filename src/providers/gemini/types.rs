use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Gemini API structures

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GeminiRequest {
    pub contents: Vec<GeminiContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_instruction: Option<GeminiSystemInstruction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation_config: Option<GeminiGenerationConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<GeminiTool>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_config: Option<GeminiToolConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct GeminiContent {
    pub role: String,
    pub parts: Vec<GeminiPart>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum GeminiPart {
    Text {
        text: String,
    },
    InlineData {
        inline_data: GeminiInlineData,
    },
    FunctionCall {
        #[serde(rename = "functionCall")]
        function_call: GeminiFunctionCall,
    },
    FunctionResponse {
        #[serde(rename = "functionResponse")]
        function_response: GeminiFunctionResponse,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct GeminiFunctionCall {
    pub name: String,
    pub args: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct GeminiFunctionResponse {
    pub name: String,
    pub response: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GeminiInlineData {
    pub mime_type: String,
    pub data: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct GeminiSystemInstruction {
    pub parts: Vec<GeminiPart>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GeminiGenerationConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_k: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_sequences: Option<Vec<String>>,
}

/// Gemini Tool supports multiple tool types via protobuf oneof
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub(crate) enum GeminiTool {
    /// Function calling tools
    FunctionDeclarations {
        #[serde(rename = "functionDeclarations")]
        function_declarations: Vec<GeminiFunctionDeclaration>,
    },
    /// Google Search tool
    GoogleSearch {
        #[serde(rename = "googleSearch")]
        google_search: GoogleSearchTool,
    },
    /// URL Context/Fetch tool
    UrlContext {
        #[serde(rename = "urlContext")]
        url_context: UrlContextTool,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GeminiToolConfig {
    pub function_calling_config: GeminiFunctionCallingConfig,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct GeminiFunctionCallingConfig {
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_function_names: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct GeminiFunctionDeclaration {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct GoogleSearchTool {}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct UrlContextTool {}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GeminiResponse {
    pub candidates: Vec<GeminiCandidate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_metadata: Option<GeminiUsageMetadata>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GeminiCandidate {
    pub content: GeminiContent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)] // Fields populated by serde deserialization
pub(crate) struct GeminiUsageMetadata {
    pub prompt_token_count: Option<i32>,
    pub candidates_token_count: Option<i32>,
    pub total_token_count: Option<i32>,
}

// Code Assist API structures (for OAuth)

#[derive(Debug, Clone, Serialize)]
pub(crate) struct CodeAssistRequest {
    pub model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_prompt_id: Option<String>,
    pub request: CodeAssistInnerRequest,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CodeAssistInnerRequest {
    pub contents: Vec<GeminiContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_instruction: Option<GeminiSystemInstruction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation_config: Option<GeminiGenerationConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<GeminiTool>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_config: Option<GeminiToolConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)] // Fields populated by serde deserialization
pub(crate) struct CodeAssistResponse {
    pub response: GeminiResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
}

// Error response structures for rate limiting

#[derive(Debug, Deserialize)]
pub(super) struct GeminiErrorResponse {
    pub error: GeminiError,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields populated by serde deserialization
pub(super) struct GeminiError {
    pub code: u16,
    pub message: String,
    pub status: String,
    #[serde(default)]
    pub details: Vec<GeminiErrorDetail>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "@type")]
pub(super) enum GeminiErrorDetail {
    #[serde(rename = "type.googleapis.com/google.rpc.RetryInfo")]
    RetryInfo {
        #[serde(rename = "retryDelay")]
        retry_delay: String,
    },
    #[serde(rename = "type.googleapis.com/google.rpc.ErrorInfo")]
    ErrorInfo {
        reason: String,
        domain: String,
        #[serde(default)]
        metadata: HashMap<String, String>,
    },
    #[serde(other)]
    Unknown,
}

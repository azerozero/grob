use crate::models::{
    self, AnthropicRequest, ContentBlock, KnownContentBlock, MessageContent, SystemPrompt, Tool,
    ToolResultContent,
};
use crate::providers::ProviderResponse;
use serde::{Deserialize, Serialize};

/// OpenAI Chat Completions request format
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct OpenAIRequest {
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
    pub tools: Option<Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct OpenAIMessage {
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<OpenAIContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[allow(dead_code)]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<OpenAIToolCallInput>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

/// Tool call in an incoming request (assistant message)
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct OpenAIToolCallInput {
    pub id: String,
    pub r#type: Option<String>,
    pub function: OpenAIFunctionInput,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OpenAIFunctionInput {
    pub name: String,
    pub arguments: String,
}

/// Content can be string or array of content parts
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum OpenAIContent {
    String(String),
    Parts(Vec<OpenAIContentPart>),
}

/// Content part (text or image_url)
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum OpenAIContentPart {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "image_url")]
    ImageUrl { image_url: OpenAIImageUrl },
}

/// Image URL object
#[derive(Debug, Clone, Deserialize)]
pub struct OpenAIImageUrl {
    pub url: String,
}

/// OpenAI Chat Completions response format
#[derive(Debug, Serialize)]
pub struct OpenAIResponse {
    pub id: String,
    #[serde(rename = "object")]
    pub object: String,
    pub created: u64,
    pub model: String,
    pub choices: Vec<OpenAIChoice>,
    pub usage: OpenAIUsage,
}

#[derive(Debug, Serialize)]
pub struct OpenAIChoice {
    pub index: u32,
    pub message: OpenAIResponseMessage,
    pub finish_reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct OpenAIResponseMessage {
    pub role: String,
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<OpenAIToolCall>>,
}

/// Tool call in a response
#[derive(Debug, Serialize)]
pub struct OpenAIToolCall {
    pub id: String,
    pub r#type: String,
    pub function: OpenAIFunction,
}

#[derive(Debug, Serialize)]
pub struct OpenAIFunction {
    pub name: String,
    pub arguments: String,
}

#[derive(Debug, Serialize)]
pub struct OpenAIUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

/// Convert OpenAI content to Anthropic MessageContent
fn openai_content_to_anthropic(content: Option<OpenAIContent>) -> MessageContent {
    match content {
        Some(OpenAIContent::String(text)) => MessageContent::Text(text),
        Some(OpenAIContent::Parts(parts)) => {
            let blocks: Vec<ContentBlock> = parts
                .iter()
                .filter_map(|part| match part {
                    OpenAIContentPart::Text { text } => {
                        Some(ContentBlock::text(text.clone(), None))
                    }
                    OpenAIContentPart::ImageUrl { image_url } => {
                        if image_url.url.starts_with("data:") {
                            if let Some(comma_idx) = image_url.url.find(',') {
                                let header = &image_url.url[..comma_idx];
                                let data = &image_url.url[comma_idx + 1..];
                                let media_type = if header.contains("image/jpeg") {
                                    "image/jpeg"
                                } else if header.contains("image/png") {
                                    "image/png"
                                } else if header.contains("image/gif") {
                                    "image/gif"
                                } else if header.contains("image/webp") {
                                    "image/webp"
                                } else {
                                    "image/png"
                                };
                                Some(ContentBlock::image(crate::models::ImageSource {
                                    r#type: "base64".to_string(),
                                    media_type: Some(media_type.to_string()),
                                    data: Some(data.to_string()),
                                    url: None,
                                }))
                            } else {
                                None
                            }
                        } else {
                            Some(ContentBlock::image(crate::models::ImageSource {
                                r#type: "url".to_string(),
                                media_type: None,
                                data: None,
                                url: Some(image_url.url.clone()),
                            }))
                        }
                    }
                })
                .collect();
            if blocks.is_empty() {
                MessageContent::Text(String::new())
            } else {
                MessageContent::Blocks(blocks)
            }
        }
        None => MessageContent::Text(String::new()),
    }
}

/// Transform OpenAI request to Anthropic format
pub fn transform_openai_to_anthropic(
    openai_req: OpenAIRequest,
) -> Result<AnthropicRequest, String> {
    let mut messages = Vec::new();
    let mut system_prompt: Option<SystemPrompt> = None;

    // Process messages
    for msg in openai_req.messages {
        match msg.role.as_str() {
            "system" => {
                // Extract system message
                if let Some(content) = msg.content {
                    let text = match content {
                        OpenAIContent::String(s) => s,
                        OpenAIContent::Parts(parts) => parts
                            .iter()
                            .filter_map(|p| {
                                if let OpenAIContentPart::Text { text } = p {
                                    Some(text.clone())
                                } else {
                                    None
                                }
                            })
                            .collect::<Vec<_>>()
                            .join("\n"),
                    };
                    system_prompt = Some(SystemPrompt::Text(text));
                }
            }
            "user" => {
                // Convert user messages
                let content = openai_content_to_anthropic(msg.content);
                messages.push(crate::models::Message {
                    role: "user".to_string(),
                    content,
                });
            }
            "assistant" => {
                // Convert assistant messages — may include tool_calls
                let mut blocks: Vec<ContentBlock> = Vec::new();

                // Text content
                if let Some(openai_content) = msg.content {
                    match openai_content {
                        OpenAIContent::String(text) if !text.is_empty() => {
                            blocks.push(ContentBlock::text(text, None));
                        }
                        OpenAIContent::Parts(parts) => {
                            for part in &parts {
                                if let OpenAIContentPart::Text { text } = part {
                                    if !text.is_empty() {
                                        blocks.push(ContentBlock::text(text.clone(), None));
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }

                // Tool calls → ToolUse blocks
                if let Some(tool_calls) = msg.tool_calls {
                    for tc in tool_calls {
                        let input: serde_json::Value = serde_json::from_str(&tc.function.arguments)
                            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
                        blocks.push(ContentBlock::tool_use(tc.id, tc.function.name, input));
                    }
                }

                if blocks.is_empty() {
                    blocks.push(ContentBlock::text(String::new(), None));
                }

                messages.push(crate::models::Message {
                    role: "assistant".to_string(),
                    content: MessageContent::Blocks(blocks),
                });
            }
            "tool" => {
                // Tool result → Anthropic tool_result block inside a user message
                let tool_use_id = msg.tool_call_id.unwrap_or_default();
                let text = match msg.content {
                    Some(OpenAIContent::String(s)) => s,
                    Some(OpenAIContent::Parts(parts)) => parts
                        .iter()
                        .filter_map(|p| {
                            if let OpenAIContentPart::Text { text } = p {
                                Some(text.clone())
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("\n"),
                    None => String::new(),
                };
                let block = ContentBlock::Known(KnownContentBlock::ToolResult {
                    tool_use_id,
                    content: ToolResultContent::Text(text),
                    is_error: false,
                    cache_control: None,
                });

                // Try to merge into previous user message (consecutive tool results)
                if let Some(last) = messages.last_mut() {
                    if last.role == "user" {
                        if let MessageContent::Blocks(ref mut existing) = &mut last.content {
                            // Only merge if last message contains only tool_result blocks
                            if existing.iter().all(|b| b.is_tool_result()) {
                                existing.push(block);
                                continue;
                            }
                        }
                    }
                }

                messages.push(crate::models::Message {
                    role: "user".to_string(),
                    content: MessageContent::Blocks(vec![block]),
                });
            }
            _ => {
                tracing::warn!("Skipping unsupported message role: {}", msg.role);
            }
        }
    }

    let max_tokens = openai_req
        .max_tokens
        .unwrap_or_else(|| models::default_max_tokens(&openai_req.model));

    Ok(AnthropicRequest {
        model: openai_req.model,
        messages,
        max_tokens,
        thinking: None,
        temperature: openai_req.temperature,
        top_p: openai_req.top_p,
        top_k: None,
        stop_sequences: openai_req.stop,
        stream: openai_req.stream,
        metadata: None,
        system: system_prompt,
        tools: openai_req.tools.as_ref().map(|tools| {
            tools
                .iter()
                .filter_map(|t| {
                    let func = t.get("function")?;
                    Some(Tool {
                        r#type: None,
                        name: func
                            .get("name")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        description: func
                            .get("description")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        input_schema: func.get("parameters").cloned(),
                    })
                })
                .collect()
        }),
        tool_choice: openai_req.tool_choice.as_ref().and_then(|tc| {
            if let Some(s) = tc.as_str() {
                match s {
                    "auto" => Some(serde_json::json!({"type": "auto"})),
                    "required" => Some(serde_json::json!({"type": "any"})),
                    "none" => Some(serde_json::json!({"type": "auto"})),
                    _ => None,
                }
            } else if let Some(obj) = tc.as_object() {
                if obj.get("type").and_then(|v| v.as_str()) == Some("function") {
                    let name = obj
                        .get("function")
                        .and_then(|f| f.get("name"))
                        .and_then(|n| n.as_str())
                        .unwrap_or("");
                    Some(serde_json::json!({"type": "tool", "name": name}))
                } else {
                    None
                }
            } else {
                None
            }
        }),
    })
}

/// Transform Anthropic response to OpenAI format
pub fn transform_anthropic_to_openai(
    anthropic_resp: ProviderResponse,
    model: String,
) -> OpenAIResponse {
    let mut text_parts: Vec<String> = Vec::new();
    let mut tool_calls: Vec<OpenAIToolCall> = Vec::new();

    for block in &anthropic_resp.content {
        match block {
            ContentBlock::Known(KnownContentBlock::Text { text, .. }) => {
                if !text.is_empty() {
                    text_parts.push(text.clone());
                }
            }
            ContentBlock::Known(KnownContentBlock::ToolUse { id, name, input }) => {
                tool_calls.push(OpenAIToolCall {
                    id: id.clone(),
                    r#type: "function".to_string(),
                    function: OpenAIFunction {
                        name: name.clone(),
                        arguments: serde_json::to_string(input).unwrap_or_default(),
                    },
                });
            }
            _ => {} // skip thinking, images, etc.
        }
    }

    let content = if text_parts.is_empty() {
        None
    } else {
        Some(text_parts.join("\n"))
    };
    let tool_calls_out = if tool_calls.is_empty() {
        None
    } else {
        Some(tool_calls)
    };

    // Map finish_reason
    let finish_reason = anthropic_resp.stop_reason.as_ref().map(|reason| {
        match reason.as_str() {
            "end_turn" => "stop",
            "max_tokens" => "length",
            "stop_sequence" => "stop",
            "tool_use" => "tool_calls",
            _ => "stop",
        }
        .to_string()
    });

    OpenAIResponse {
        id: anthropic_resp.id,
        object: "chat.completion".to_string(),
        created: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        model,
        choices: vec![OpenAIChoice {
            index: 0,
            message: OpenAIResponseMessage {
                role: anthropic_resp.role,
                content,
                tool_calls: tool_calls_out,
            },
            finish_reason,
        }],
        usage: OpenAIUsage {
            prompt_tokens: anthropic_resp.usage.input_tokens,
            completion_tokens: anthropic_resp.usage.output_tokens,
            total_tokens: anthropic_resp.usage.input_tokens + anthropic_resp.usage.output_tokens,
        },
    }
}

// ── Streaming types ──────────────────────────────────────────────────

use crate::providers::streaming::{parse_sse_events, SseEvent};
use bytes::Bytes;

/// OpenAI streaming chunk (SSE)
#[derive(Debug, Serialize)]
pub struct OpenAIStreamChunk {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub model: String,
    pub choices: Vec<OpenAIStreamChoice>,
}

#[derive(Debug, Serialize)]
pub struct OpenAIStreamChoice {
    pub index: u32,
    pub delta: OpenAIStreamDelta,
    pub finish_reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct OpenAIStreamDelta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<OpenAIStreamToolCallDelta>>,
}

#[derive(Debug, Serialize)]
pub struct OpenAIStreamToolCallDelta {
    pub index: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<OpenAIStreamFunctionDelta>,
}

#[derive(Debug, Serialize)]
pub struct OpenAIStreamFunctionDelta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<String>,
}

/// State machine that transforms Anthropic SSE events → OpenAI SSE chunks.
pub struct AnthropicToOpenAIStream {
    id: String,
    model: String,
    created: u64,
    tool_call_index: u32,
    sent_role: bool,
}

impl AnthropicToOpenAIStream {
    pub fn new(model: String) -> Self {
        Self {
            id: format!("chatcmpl-{}", uuid::Uuid::new_v4()),
            model,
            created: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            tool_call_index: 0,
            sent_role: false,
        }
    }

    /// Build an SSE line from a chunk struct
    fn make_sse(&self, chunk: &OpenAIStreamChunk) -> Bytes {
        let json = serde_json::to_string(chunk).unwrap_or_default();
        Bytes::from(format!("data: {}\n\n", json))
    }

    fn base_chunk(
        &self,
        delta: OpenAIStreamDelta,
        finish_reason: Option<String>,
    ) -> OpenAIStreamChunk {
        OpenAIStreamChunk {
            id: self.id.clone(),
            object: "chat.completion.chunk".to_string(),
            created: self.created,
            model: self.model.clone(),
            choices: vec![OpenAIStreamChoice {
                index: 0,
                delta,
                finish_reason,
            }],
        }
    }

    /// Transform a single Anthropic SSE event → bytes for the OpenAI client (or None to skip).
    pub fn transform_event(&mut self, event: &SseEvent) -> Option<Bytes> {
        let event_type = event.event.as_deref()?;

        match event_type {
            "message_start" => {
                if !self.sent_role {
                    self.sent_role = true;
                    let chunk = self.base_chunk(
                        OpenAIStreamDelta {
                            role: Some("assistant".into()),
                            content: None,
                            tool_calls: None,
                        },
                        None,
                    );
                    return Some(self.make_sse(&chunk));
                }
                None
            }
            "content_block_start" => {
                // Parse to detect tool_use blocks
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&event.data) {
                    if let Some(cb) = json.get("content_block") {
                        if cb.get("type").and_then(|v| v.as_str()) == Some("tool_use") {
                            let id = cb
                                .get("id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let name = cb
                                .get("name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let idx = self.tool_call_index;
                            self.tool_call_index += 1;
                            let chunk = self.base_chunk(
                                OpenAIStreamDelta {
                                    role: None,
                                    content: None,
                                    tool_calls: Some(vec![OpenAIStreamToolCallDelta {
                                        index: idx,
                                        id: Some(id),
                                        r#type: Some("function".into()),
                                        function: Some(OpenAIStreamFunctionDelta {
                                            name: Some(name),
                                            arguments: None,
                                        }),
                                    }]),
                                },
                                None,
                            );
                            return Some(self.make_sse(&chunk));
                        }
                    }
                }
                None
            }
            "content_block_delta" => {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&event.data) {
                    if let Some(delta) = json.get("delta") {
                        let delta_type = delta.get("type").and_then(|v| v.as_str()).unwrap_or("");
                        match delta_type {
                            "text_delta" => {
                                let text = delta.get("text").and_then(|v| v.as_str()).unwrap_or("");
                                let chunk = self.base_chunk(
                                    OpenAIStreamDelta {
                                        role: None,
                                        content: Some(text.to_string()),
                                        tool_calls: None,
                                    },
                                    None,
                                );
                                return Some(self.make_sse(&chunk));
                            }
                            "input_json_delta" => {
                                let partial = delta
                                    .get("partial_json")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                let idx = if self.tool_call_index > 0 {
                                    self.tool_call_index - 1
                                } else {
                                    0
                                };
                                let chunk = self.base_chunk(
                                    OpenAIStreamDelta {
                                        role: None,
                                        content: None,
                                        tool_calls: Some(vec![OpenAIStreamToolCallDelta {
                                            index: idx,
                                            id: None,
                                            r#type: None,
                                            function: Some(OpenAIStreamFunctionDelta {
                                                name: None,
                                                arguments: Some(partial.to_string()),
                                            }),
                                        }]),
                                    },
                                    None,
                                );
                                return Some(self.make_sse(&chunk));
                            }
                            _ => {} // skip thinking_delta etc.
                        }
                    }
                }
                None
            }
            "message_delta" => {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&event.data) {
                    if let Some(d) = json.get("delta") {
                        let stop = d
                            .get("stop_reason")
                            .and_then(|v| v.as_str())
                            .map(|r| match r {
                                "end_turn" | "stop_sequence" => "stop".to_string(),
                                "max_tokens" => "length".to_string(),
                                "tool_use" => "tool_calls".to_string(),
                                other => other.to_string(),
                            });
                        if stop.is_some() {
                            let chunk = self.base_chunk(
                                OpenAIStreamDelta {
                                    role: None,
                                    content: None,
                                    tool_calls: None,
                                },
                                stop,
                            );
                            return Some(self.make_sse(&chunk));
                        }
                    }
                }
                None
            }
            "message_stop" => Some(Bytes::from("data: [DONE]\n\n")),
            _ => None, // content_block_stop, ping, etc.
        }
    }

    /// Transform a raw byte chunk (may contain multiple SSE events) → concatenated OpenAI SSE bytes.
    pub fn transform_bytes(&mut self, raw: &[u8]) -> Bytes {
        let text = match std::str::from_utf8(raw) {
            Ok(t) => t,
            Err(_) => return Bytes::new(),
        };
        let events = parse_sse_events(text);
        let mut out = Vec::new();
        for ev in &events {
            if let Some(bytes) = self.transform_event(ev) {
                out.extend_from_slice(&bytes);
            }
        }
        Bytes::from(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ContentBlock, KnownContentBlock};
    use crate::providers::{ProviderResponse, Usage};

    fn mock_response(content: Vec<ContentBlock>) -> ProviderResponse {
        ProviderResponse {
            id: "msg_test".to_string(),
            r#type: "message".to_string(),
            role: "assistant".to_string(),
            content,
            model: "claude-3".to_string(),
            stop_reason: Some("end_turn".to_string()),
            stop_sequence: None,
            usage: Usage {
                input_tokens: 10,
                output_tokens: 20,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        }
    }

    fn simple_openai_request(messages: Vec<OpenAIMessage>) -> OpenAIRequest {
        OpenAIRequest {
            model: "claude-3".to_string(),
            messages,
            max_tokens: Some(1024),
            temperature: None,
            top_p: None,
            stop: None,
            stream: None,
            tools: None,
            tool_choice: None,
        }
    }

    #[test]
    fn test_system_message_extraction() {
        let req = simple_openai_request(vec![
            OpenAIMessage {
                role: "system".to_string(),
                content: Some(OpenAIContent::String(
                    "You are a helpful assistant.".to_string(),
                )),
                name: None,
                tool_calls: None,
                tool_call_id: None,
            },
            OpenAIMessage {
                role: "user".to_string(),
                content: Some(OpenAIContent::String("Hello".to_string())),
                name: None,
                tool_calls: None,
                tool_call_id: None,
            },
        ]);

        let result = transform_openai_to_anthropic(req).unwrap();

        // System message should be extracted into the system field
        match &result.system {
            Some(SystemPrompt::Text(text)) => {
                assert_eq!(text, "You are a helpful assistant.");
            }
            other => panic!("Expected SystemPrompt::Text, got {:?}", other),
        }

        // Messages should only contain the user message, not the system message
        assert_eq!(result.messages.len(), 1);
        assert_eq!(result.messages[0].role, "user");
    }

    #[test]
    fn test_tool_call_to_anthropic() {
        let req = simple_openai_request(vec![
            OpenAIMessage {
                role: "user".to_string(),
                content: Some(OpenAIContent::String("What's the weather?".to_string())),
                name: None,
                tool_calls: None,
                tool_call_id: None,
            },
            OpenAIMessage {
                role: "assistant".to_string(),
                content: Some(OpenAIContent::String("Let me check.".to_string())),
                name: None,
                tool_calls: Some(vec![OpenAIToolCallInput {
                    id: "call_123".to_string(),
                    r#type: Some("function".to_string()),
                    function: OpenAIFunctionInput {
                        name: "get_weather".to_string(),
                        arguments: r#"{"location":"Paris"}"#.to_string(),
                    },
                }]),
                tool_call_id: None,
            },
        ]);

        let result = transform_openai_to_anthropic(req).unwrap();

        // The assistant message should have blocks (text + tool_use)
        assert_eq!(result.messages.len(), 2);
        let assistant_msg = &result.messages[1];
        assert_eq!(assistant_msg.role, "assistant");

        match &assistant_msg.content {
            MessageContent::Blocks(blocks) => {
                assert_eq!(blocks.len(), 2);
                // First block: text
                match &blocks[0] {
                    ContentBlock::Known(KnownContentBlock::Text { text, .. }) => {
                        assert_eq!(text, "Let me check.");
                    }
                    other => panic!("Expected Text block, got {:?}", other),
                }
                // Second block: tool_use
                match &blocks[1] {
                    ContentBlock::Known(KnownContentBlock::ToolUse { id, name, input }) => {
                        assert_eq!(id, "call_123");
                        assert_eq!(name, "get_weather");
                        assert_eq!(input["location"], "Paris");
                    }
                    other => panic!("Expected ToolUse block, got {:?}", other),
                }
            }
            other => panic!("Expected Blocks content, got {:?}", other),
        }
    }

    #[test]
    fn test_anthropic_tool_use_to_openai() {
        let resp = mock_response(vec![
            ContentBlock::Known(KnownContentBlock::Text {
                text: "Here's the result.".to_string(),
                cache_control: None,
            }),
            ContentBlock::Known(KnownContentBlock::ToolUse {
                id: "toolu_abc".to_string(),
                name: "search".to_string(),
                input: serde_json::json!({"query": "rust"}),
            }),
        ]);

        let openai_resp = transform_anthropic_to_openai(resp, "claude-3".to_string());

        assert_eq!(openai_resp.choices.len(), 1);
        let choice = &openai_resp.choices[0];

        // Text content should be present
        assert_eq!(
            choice.message.content.as_deref(),
            Some("Here's the result.")
        );

        // Tool calls should be present
        let tool_calls = choice
            .message
            .tool_calls
            .as_ref()
            .expect("Expected tool_calls");
        assert_eq!(tool_calls.len(), 1);
        assert_eq!(tool_calls[0].id, "toolu_abc");
        assert_eq!(tool_calls[0].r#type, "function");
        assert_eq!(tool_calls[0].function.name, "search");
        assert_eq!(tool_calls[0].function.arguments, r#"{"query":"rust"}"#);
    }

    #[test]
    fn test_temperature_passthrough() {
        let req = OpenAIRequest {
            model: "claude-3".to_string(),
            messages: vec![OpenAIMessage {
                role: "user".to_string(),
                content: Some(OpenAIContent::String("Hi".to_string())),
                name: None,
                tool_calls: None,
                tool_call_id: None,
            }],
            max_tokens: Some(100),
            temperature: Some(0.7),
            top_p: None,
            stop: None,
            stream: None,
            tools: None,
            tool_choice: None,
        };

        let result = transform_openai_to_anthropic(req).unwrap();
        assert_eq!(result.temperature, Some(0.7));
    }

    #[test]
    fn test_stop_sequences_conversion() {
        let req = OpenAIRequest {
            model: "claude-3".to_string(),
            messages: vec![OpenAIMessage {
                role: "user".to_string(),
                content: Some(OpenAIContent::String("Hi".to_string())),
                name: None,
                tool_calls: None,
                tool_call_id: None,
            }],
            max_tokens: Some(100),
            temperature: None,
            top_p: None,
            stop: Some(vec!["STOP".to_string(), "END".to_string()]),
            stream: None,
            tools: None,
            tool_choice: None,
        };

        let result = transform_openai_to_anthropic(req).unwrap();
        let stop_seqs = result.stop_sequences.expect("Expected stop_sequences");
        assert_eq!(stop_seqs, vec!["STOP", "END"]);
    }

    #[test]
    fn test_streaming_flag_passthrough() {
        let req = OpenAIRequest {
            model: "claude-3".to_string(),
            messages: vec![OpenAIMessage {
                role: "user".to_string(),
                content: Some(OpenAIContent::String("Hi".to_string())),
                name: None,
                tool_calls: None,
                tool_call_id: None,
            }],
            max_tokens: Some(100),
            temperature: None,
            top_p: None,
            stop: None,
            stream: Some(true),
            tools: None,
            tool_choice: None,
        };

        let result = transform_openai_to_anthropic(req).unwrap();
        assert_eq!(result.stream, Some(true));
    }

    #[test]
    fn test_empty_messages_returns_empty() {
        let req = simple_openai_request(vec![]);

        let result = transform_openai_to_anthropic(req).unwrap();
        assert!(result.messages.is_empty());
        assert!(result.system.is_none());
    }

    #[test]
    fn test_image_content_translation() {
        let data_uri = "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQ==";
        let req = simple_openai_request(vec![OpenAIMessage {
            role: "user".to_string(),
            content: Some(OpenAIContent::Parts(vec![
                OpenAIContentPart::Text {
                    text: "What's in this image?".to_string(),
                },
                OpenAIContentPart::ImageUrl {
                    image_url: OpenAIImageUrl {
                        url: data_uri.to_string(),
                    },
                },
            ])),
            name: None,
            tool_calls: None,
            tool_call_id: None,
        }]);

        let result = transform_openai_to_anthropic(req).unwrap();
        assert_eq!(result.messages.len(), 1);

        match &result.messages[0].content {
            MessageContent::Blocks(blocks) => {
                assert_eq!(blocks.len(), 2);
                // First block: text
                match &blocks[0] {
                    ContentBlock::Known(KnownContentBlock::Text { text, .. }) => {
                        assert_eq!(text, "What's in this image?");
                    }
                    other => panic!("Expected Text block, got {:?}", other),
                }
                // Second block: image with base64 source
                match &blocks[1] {
                    ContentBlock::Known(KnownContentBlock::Image { source }) => {
                        assert_eq!(source.r#type, "base64");
                        assert_eq!(source.media_type.as_deref(), Some("image/jpeg"));
                        assert_eq!(source.data.as_deref(), Some("/9j/4AAQSkZJRgABAQ=="));
                        assert!(source.url.is_none());
                    }
                    other => panic!("Expected Image block, got {:?}", other),
                }
            }
            other => panic!("Expected Blocks content, got {:?}", other),
        }
    }
}

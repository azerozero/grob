use crate::models::{
    AnthropicRequest, ContentBlock, KnownContentBlock, MessageContent, SystemPrompt, Tool,
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

    Ok(AnthropicRequest {
        model: openai_req.model,
        messages,
        max_tokens: openai_req.max_tokens.unwrap_or(4096),
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

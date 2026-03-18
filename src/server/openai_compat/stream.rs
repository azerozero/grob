use bytes::Bytes;
use serde::Serialize;

use crate::providers::streaming::{parse_sse_events, SseEvent};

/// Represents one SSE chunk in the OpenAI streaming protocol.
///
/// Each chunk corresponds to a `data:` line in the server-sent event stream
/// and contains incremental content updates for the client.
#[derive(Debug, Serialize)]
pub struct OpenAIStreamChunk {
    /// Stable completion identifier shared across all chunks.
    pub id: String,
    /// Object type, always `"chat.completion.chunk"`.
    pub object: &'static str,
    /// Unix timestamp when the completion started.
    pub created: u64,
    /// Model name echoed from the request.
    pub model: String,
    /// Incremental choice updates (always one element).
    pub choices: Vec<OpenAIStreamChoice>,
}

/// Wraps a [`OpenAIStreamDelta`] with its position and stop signal.
#[derive(Debug, Serialize)]
pub struct OpenAIStreamChoice {
    /// Zero-based position (always 0; Grob returns one choice).
    pub index: u32,
    /// Incremental content or tool call fragment.
    pub delta: OpenAIStreamDelta,
    /// Set on the final chunk (e.g. `"stop"`, `"tool_calls"`, `"length"`).
    pub finish_reason: Option<String>,
}

/// Incremental content payload inside a streaming chunk.
#[derive(Debug, Serialize)]
pub struct OpenAIStreamDelta {
    /// Set to `"assistant"` on the first chunk only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Text fragment appended to the completion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// Incremental tool call updates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<OpenAIStreamToolCallDelta>>,
}

/// Incremental tool call update within a streaming chunk.
///
/// The first delta for a tool call carries `id`, `type`, and `function.name`.
/// Subsequent deltas carry only `function.arguments` fragments.
#[derive(Debug, Serialize)]
pub struct OpenAIStreamToolCallDelta {
    /// Position of this tool call in the tool_calls array.
    pub index: u32,
    /// Tool call identifier (present on the first delta only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Tool type, `"function"` (present on the first delta only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    /// Function name or argument fragment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<OpenAIStreamFunctionDelta>,
}

/// Carries either a function name or an argument fragment.
#[derive(Debug, Serialize)]
pub struct OpenAIStreamFunctionDelta {
    /// Function name (present on the first delta only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Partial JSON arguments string to be concatenated.
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
    /// Creates a stream translator for the given model name.
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
        // Write "data: " + JSON + "\n\n" into a single buffer to avoid an extra allocation.
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(b"data: ");
        serde_json::to_writer(&mut buf, chunk).unwrap_or_default();
        buf.extend_from_slice(b"\n\n");
        Bytes::from(buf)
    }

    fn base_chunk(
        &self,
        delta: OpenAIStreamDelta,
        finish_reason: Option<String>,
    ) -> OpenAIStreamChunk {
        OpenAIStreamChunk {
            id: self.id.clone(),
            object: "chat.completion.chunk",
            created: self.created,
            model: self.model.clone(),
            choices: vec![OpenAIStreamChoice {
                index: 0,
                delta,
                finish_reason,
            }],
        }
    }

    fn handle_content_block_start(&mut self, data: &str) -> Option<Bytes> {
        let json: serde_json::Value = serde_json::from_str(data).ok()?;
        let cb = json.get("content_block")?;
        if cb.get("type").and_then(|v| v.as_str()) != Some("tool_use") {
            return None;
        }
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
        Some(self.make_sse(&chunk))
    }

    fn handle_content_block_delta(&mut self, data: &str) -> Option<Bytes> {
        let json: serde_json::Value = serde_json::from_str(data).ok()?;
        let delta = json.get("delta")?;
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
                Some(self.make_sse(&chunk))
            }
            "input_json_delta" => {
                let partial = delta
                    .get("partial_json")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let idx = self.tool_call_index.saturating_sub(1);
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
                Some(self.make_sse(&chunk))
            }
            _ => None,
        }
    }

    fn handle_message_delta(&mut self, data: &str) -> Option<Bytes> {
        let json: serde_json::Value = serde_json::from_str(data).ok()?;
        let d = json.get("delta")?;
        let stop = d
            .get("stop_reason")
            .and_then(|v| v.as_str())
            .map(|r| match r {
                "end_turn" | "stop_sequence" => "stop".to_string(),
                "max_tokens" => "length".to_string(),
                "tool_use" => "tool_calls".to_string(),
                other => other.to_string(),
            });
        stop.as_ref()?;
        let chunk = self.base_chunk(
            OpenAIStreamDelta {
                role: None,
                content: None,
                tool_calls: None,
            },
            stop,
        );
        Some(self.make_sse(&chunk))
    }

    /// Transform a single Anthropic SSE event → bytes for the OpenAI client (or None to skip).
    pub fn transform_event(&mut self, event: &SseEvent) -> Option<Bytes> {
        match event.event.as_deref()? {
            "message_start" if !self.sent_role => {
                self.sent_role = true;
                let chunk = self.base_chunk(
                    OpenAIStreamDelta {
                        role: Some("assistant".into()),
                        content: None,
                        tool_calls: None,
                    },
                    None,
                );
                Some(self.make_sse(&chunk))
            }
            "content_block_start" => self.handle_content_block_start(&event.data),
            "content_block_delta" => self.handle_content_block_delta(&event.data),
            "message_delta" => self.handle_message_delta(&event.data),
            "message_stop" => Some(Bytes::from("data: [DONE]\n\n")),
            _ => None,
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

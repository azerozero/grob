use bytes::Bytes;
use serde::Serialize;

use crate::providers::streaming::{parse_sse_events, SseEvent};

/// OpenAI streaming chunk (SSE)
#[derive(Debug, Serialize)]
pub struct OpenAIStreamChunk {
    pub id: String,
    pub object: &'static str,
    pub created: u64,
    pub model: String,
    pub choices: Vec<OpenAIStreamChoice>,
}

/// Streaming choice with delta content
#[derive(Debug, Serialize)]
pub struct OpenAIStreamChoice {
    pub index: u32,
    pub delta: OpenAIStreamDelta,
    pub finish_reason: Option<String>,
}

/// Delta content in a streaming chunk
#[derive(Debug, Serialize)]
pub struct OpenAIStreamDelta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<OpenAIStreamToolCallDelta>>,
}

/// Incremental tool call update in a streaming chunk
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

/// Incremental function call update (name or argument fragment)
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

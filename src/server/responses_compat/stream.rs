//! SSE stream adapter: Anthropic SSE → OpenAI Responses API named-event SSE.
//!
//! The Responses API uses named SSE events (e.g. `event: response.output_text.delta`)
//! instead of the `data: {...}` format used by Chat Completions.

use bytes::Bytes;
use serde::Serialize;

use crate::providers::streaming::{parse_sse_events, SseEvent};

/// State machine that transforms Anthropic SSE events → Responses API SSE events.
pub struct AnthropicToResponsesStream {
    response_id: String,
    model: String,
    output_index: u32,
    content_index: u32,
    current_item_id: String,
}

impl AnthropicToResponsesStream {
    /// Creates a stream translator for the given model name.
    pub fn new(model: String) -> Self {
        Self {
            response_id: format!("resp_{}", uuid::Uuid::new_v4().simple()),
            model,
            output_index: 0,
            content_index: 0,
            current_item_id: String::new(),
        }
    }

    /// Formats a named SSE event: `event: <name>\ndata: <json>\n\n`
    fn make_event(event_name: &str, data: &impl Serialize) -> Bytes {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(b"event: ");
        buf.extend_from_slice(event_name.as_bytes());
        buf.extend_from_slice(b"\ndata: ");
        serde_json::to_writer(&mut buf, data).unwrap_or_default();
        buf.extend_from_slice(b"\n\n");
        Bytes::from(buf)
    }

    /// Formats the `response.created` event emitted at stream start.
    fn make_response_created(&self) -> Bytes {
        let data = serde_json::json!({
            "id": self.response_id,
            "object": "response",
            "model": self.model,
            "status": "in_progress",
            "output": [],
        });
        Self::make_event("response.created", &data)
    }

    fn handle_content_block_start(&mut self, data: &str) -> Vec<Bytes> {
        let mut out = Vec::new();
        let json: serde_json::Value = match serde_json::from_str(data) {
            Ok(v) => v,
            Err(_) => return out,
        };
        let Some(cb) = json.get("content_block") else {
            return out;
        };
        let cb_type = cb.get("type").and_then(|v| v.as_str()).unwrap_or("");

        match cb_type {
            "text" => {
                self.current_item_id = format!("msg_{}", uuid::Uuid::new_v4().simple());
                self.content_index = 0;

                // response.output_item.added (message)
                let item_added = serde_json::json!({
                    "output_index": self.output_index,
                    "item": {
                        "id": self.current_item_id,
                        "type": "message",
                        "role": "assistant",
                        "content": [],
                        "status": "in_progress",
                    }
                });
                out.push(Self::make_event("response.output_item.added", &item_added));

                // response.content_part.added
                let part_added = serde_json::json!({
                    "output_index": self.output_index,
                    "content_index": self.content_index,
                    "part": {
                        "type": "output_text",
                        "text": "",
                    }
                });
                out.push(Self::make_event("response.content_part.added", &part_added));
            }
            "tool_use" => {
                self.current_item_id = format!("fc_{}", uuid::Uuid::new_v4().simple());
                let call_id = cb
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let name = cb
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let item_added = serde_json::json!({
                    "output_index": self.output_index,
                    "item": {
                        "id": self.current_item_id,
                        "type": "function_call",
                        "call_id": call_id,
                        "name": name,
                        "arguments": "",
                        "status": "in_progress",
                    }
                });
                out.push(Self::make_event("response.output_item.added", &item_added));
            }
            _ => {}
        }

        out
    }

    fn handle_content_block_delta(&self, data: &str) -> Option<Bytes> {
        let json: serde_json::Value = serde_json::from_str(data).ok()?;
        let delta = json.get("delta")?;
        let delta_type = delta.get("type").and_then(|v| v.as_str()).unwrap_or("");

        match delta_type {
            "text_delta" => {
                let text = delta.get("text").and_then(|v| v.as_str()).unwrap_or("");
                let event_data = serde_json::json!({
                    "output_index": self.output_index,
                    "content_index": self.content_index,
                    "delta": text,
                });
                Some(Self::make_event("response.output_text.delta", &event_data))
            }
            "input_json_delta" => {
                let partial = delta
                    .get("partial_json")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let event_data = serde_json::json!({
                    "output_index": self.output_index,
                    "delta": partial,
                });
                Some(Self::make_event(
                    "response.function_call_arguments.delta",
                    &event_data,
                ))
            }
            _ => None,
        }
    }

    fn handle_content_block_stop(&mut self, _data: &str) -> Vec<Bytes> {
        let mut out = Vec::new();

        // Determine if this was text or tool_use based on current_item_id prefix
        if self.current_item_id.starts_with("msg_") {
            // response.content_part.done
            let part_done = serde_json::json!({
                "output_index": self.output_index,
                "content_index": self.content_index,
            });
            out.push(Self::make_event("response.content_part.done", &part_done));
        } else if self.current_item_id.starts_with("fc_") {
            // response.function_call_arguments.done
            let args_done = serde_json::json!({
                "output_index": self.output_index,
            });
            out.push(Self::make_event(
                "response.function_call_arguments.done",
                &args_done,
            ));
        }

        // response.output_item.done
        let item_done = serde_json::json!({
            "output_index": self.output_index,
            "item": {
                "id": self.current_item_id,
                "status": "completed",
            }
        });
        out.push(Self::make_event("response.output_item.done", &item_done));

        self.output_index += 1;
        out
    }

    /// Transform a single Anthropic SSE event into zero or more Responses SSE bytes.
    pub fn transform_event(&mut self, event: &SseEvent) -> Vec<Bytes> {
        let Some(event_type) = event.event.as_deref() else {
            return Vec::new();
        };

        match event_type {
            "message_start" => {
                vec![self.make_response_created()]
            }
            "content_block_start" => self.handle_content_block_start(&event.data),
            "content_block_delta" => self
                .handle_content_block_delta(&event.data)
                .into_iter()
                .collect(),
            "content_block_stop" => self.handle_content_block_stop(&event.data),
            "message_stop" => {
                let mut out = Vec::new();
                let completed = serde_json::json!({
                    "id": self.response_id,
                    "status": "completed",
                });
                out.push(Self::make_event("response.completed", &completed));
                out.push(Bytes::from("data: [DONE]\n\n"));
                out
            }
            _ => Vec::new(),
        }
    }

    /// Transforms raw bytes (potentially multiple SSE events) into Responses SSE bytes.
    pub fn transform_bytes(&mut self, raw: &[u8]) -> Bytes {
        let text = match std::str::from_utf8(raw) {
            Ok(t) => t,
            Err(_) => return Bytes::new(),
        };
        let events = parse_sse_events(text);
        let mut out = Vec::new();
        for ev in &events {
            for bytes in self.transform_event(ev) {
                out.extend_from_slice(&bytes);
            }
        }
        Bytes::from(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_start_emits_response_created() {
        let mut stream = AnthropicToResponsesStream::new("gpt-5.4".to_string());
        let event = SseEvent {
            event: Some("message_start".to_string()),
            data: r#"{"type":"message_start","message":{"id":"msg_1","model":"gpt-5.4"}}"#
                .to_string(),
        };
        let result = stream.transform_event(&event);
        assert_eq!(result.len(), 1);
        let text = std::str::from_utf8(&result[0]).unwrap();
        assert!(text.starts_with("event: response.created\n"));
    }

    #[test]
    fn text_block_emits_output_item_and_content_part() {
        let mut stream = AnthropicToResponsesStream::new("gpt-5.4".to_string());
        let event = SseEvent {
            event: Some("content_block_start".to_string()),
            data: r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#
                .to_string(),
        };
        let result = stream.transform_event(&event);
        assert_eq!(result.len(), 2);
        let s0 = std::str::from_utf8(&result[0]).unwrap();
        let s1 = std::str::from_utf8(&result[1]).unwrap();
        assert!(s0.contains("response.output_item.added"));
        assert!(s1.contains("response.content_part.added"));
    }

    #[test]
    fn text_delta_emits_output_text_delta() {
        let mut stream = AnthropicToResponsesStream::new("gpt-5.4".to_string());
        let event = SseEvent {
            event: Some("content_block_delta".to_string()),
            data: r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}"#
                .to_string(),
        };
        let result = stream.transform_event(&event);
        assert_eq!(result.len(), 1);
        let text = std::str::from_utf8(&result[0]).unwrap();
        assert!(text.contains("response.output_text.delta"));
        assert!(text.contains("Hello"));
    }

    #[test]
    fn tool_use_emits_function_call_events() {
        let mut stream = AnthropicToResponsesStream::new("gpt-5.4".to_string());

        // Start tool_use block
        let start = SseEvent {
            event: Some("content_block_start".to_string()),
            data: r#"{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"call_1","name":"ls"}}"#
                .to_string(),
        };
        let result = stream.transform_event(&start);
        assert_eq!(result.len(), 1);
        let text = std::str::from_utf8(&result[0]).unwrap();
        assert!(text.contains("response.output_item.added"));
        assert!(text.contains("function_call"));

        // Arguments delta
        let delta = SseEvent {
            event: Some("content_block_delta".to_string()),
            data: r#"{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"path\":\".\"}"}}"#
                .to_string(),
        };
        let result = stream.transform_event(&delta);
        assert_eq!(result.len(), 1);
        let text = std::str::from_utf8(&result[0]).unwrap();
        assert!(text.contains("response.function_call_arguments.delta"));
    }

    #[test]
    fn message_stop_emits_completed_and_done() {
        let mut stream = AnthropicToResponsesStream::new("gpt-5.4".to_string());
        let event = SseEvent {
            event: Some("message_stop".to_string()),
            data: r#"{"type":"message_stop"}"#.to_string(),
        };
        let result = stream.transform_event(&event);
        assert_eq!(result.len(), 2);
        let s0 = std::str::from_utf8(&result[0]).unwrap();
        let s1 = std::str::from_utf8(&result[1]).unwrap();
        assert!(s0.contains("response.completed"));
        assert!(s1.contains("[DONE]"));
    }
}

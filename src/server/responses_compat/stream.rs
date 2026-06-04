//! SSE stream adapter: Anthropic SSE → OpenAI Responses API named-event SSE.
//!
//! The Responses API uses named SSE events (e.g. `event: response.output_text.delta`)
//! instead of the `data: {...}` format used by Chat Completions.

use bytes::Bytes;
use std::collections::HashMap;

use crate::providers::streaming::{parse_sse_events, SseEvent};

#[derive(Debug)]
enum ActiveOutputItem {
    Message {
        item_id: String,
        output_index: u32,
        text: String,
    },
    FunctionCall {
        item_id: String,
        output_index: u32,
        call_id: String,
        name: String,
        arguments: String,
    },
}

#[derive(Debug, Default)]
struct StreamUsage {
    input_tokens: u32,
    output_tokens: u32,
}

impl StreamUsage {
    fn total_tokens(&self) -> u32 {
        self.input_tokens.saturating_add(self.output_tokens)
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens(),
        })
    }
}

/// State machine that transforms Anthropic SSE events → Responses API SSE events.
pub struct AnthropicToResponsesStream {
    response_id: String,
    model: String,
    next_output_index: u32,
    /// Active Anthropic content blocks keyed by their `index`.
    active_items: HashMap<u32, ActiveOutputItem>,
    /// Completed output items, included in the final `response.completed` so the
    /// client can render the assistant message (Codex reads `response.output`).
    output_items: Vec<(u32, serde_json::Value)>,
    usage: StreamUsage,
}

impl AnthropicToResponsesStream {
    /// Creates a stream translator for the given model name.
    pub fn new(model: String) -> Self {
        Self {
            response_id: format!("resp_{}", uuid::Uuid::new_v4().simple()),
            model,
            next_output_index: 0,
            active_items: HashMap::new(),
            output_items: Vec::new(),
            usage: StreamUsage::default(),
        }
    }

    /// Formats a named SSE event: `event: <name>\ndata: <json>\n\n`.
    ///
    /// Injects `"type": <name>` into the data — the Responses API requires every
    /// event payload to carry a `type` field equal to the event name, and
    /// clients (Codex CLI) dispatch on it. Without it the stream fails to decode.
    fn make_event(event_name: &str, data: &serde_json::Value) -> Bytes {
        let mut payload = data.clone();
        if let Some(map) = payload.as_object_mut() {
            map.insert(
                "type".to_string(),
                serde_json::Value::String(event_name.to_string()),
            );
        }
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(b"event: ");
        buf.extend_from_slice(event_name.as_bytes());
        buf.extend_from_slice(b"\ndata: ");
        serde_json::to_writer(&mut buf, &payload).unwrap_or_default();
        buf.extend_from_slice(b"\n\n");
        Bytes::from(buf)
    }

    /// Builds the `response` object shared by the lifecycle events.
    fn response_object(&self, status: &str, output: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "id": self.response_id,
            "object": "response",
            "model": self.model,
            "status": status,
            "output": output,
        })
    }

    fn completed_response_object(&self, output: serde_json::Value) -> serde_json::Value {
        let mut response = self.response_object("completed", output);
        if let Some(map) = response.as_object_mut() {
            map.insert("usage".to_string(), self.usage.to_json());
        }
        response
    }

    fn capture_usage(&mut self, data: &str, pointer: &str) {
        let Ok(json) = serde_json::from_str::<serde_json::Value>(data) else {
            return;
        };
        let Some(usage) = json.pointer(pointer) else {
            return;
        };

        if let Some(input) = usage.get("input_tokens").and_then(|v| v.as_u64()) {
            let input = u32::try_from(input).unwrap_or(u32::MAX);
            if input > 0 || self.usage.input_tokens == 0 {
                self.usage.input_tokens = input;
            }
        }
        if let Some(output) = usage.get("output_tokens").and_then(|v| v.as_u64()) {
            self.usage.output_tokens = self
                .usage
                .output_tokens
                .max(u32::try_from(output).unwrap_or(u32::MAX));
        }
    }

    /// Formats the `response.created` event emitted at stream start.
    fn make_response_created(&self) -> Bytes {
        let data = serde_json::json!({
            "response": self.response_object("in_progress", serde_json::json!([])),
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
        let block_index = json
            .get("index")
            .and_then(|v| v.as_u64())
            .unwrap_or(self.next_output_index as u64) as u32;
        let output_index = self.next_output_index;
        self.next_output_index += 1;

        match cb_type {
            "text" => {
                let item_id = format!("msg_{}", uuid::Uuid::new_v4().simple());

                // response.output_item.added (message)
                let item_added = serde_json::json!({
                    "output_index": output_index,
                    "item": {
                        "id": &item_id,
                        "type": "message",
                        "role": "assistant",
                        "content": [],
                        "status": "in_progress",
                    }
                });
                out.push(Self::make_event("response.output_item.added", &item_added));

                // response.content_part.added
                let part_added = serde_json::json!({
                    "item_id": &item_id,
                    "output_index": output_index,
                    "content_index": 0,
                    "part": {
                        "type": "output_text",
                        "text": "",
                    }
                });
                out.push(Self::make_event("response.content_part.added", &part_added));

                self.active_items.insert(
                    block_index,
                    ActiveOutputItem::Message {
                        item_id,
                        output_index,
                        text: String::new(),
                    },
                );
            }
            "tool_use" => {
                let item_id = format!("fc_{}", uuid::Uuid::new_v4().simple());
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
                let initial_arguments = cb
                    .get("input")
                    .filter(|v| {
                        !v.is_null() && !v.as_object().is_some_and(serde_json::Map::is_empty)
                    })
                    .and_then(|v| serde_json::to_string(v).ok())
                    .unwrap_or_default();

                let item_added = serde_json::json!({
                    "output_index": output_index,
                    "item": {
                        "id": &item_id,
                        "type": "function_call",
                        "call_id": &call_id,
                        "name": &name,
                        "arguments": "",
                        "status": "in_progress",
                    }
                });
                out.push(Self::make_event("response.output_item.added", &item_added));

                if !initial_arguments.is_empty() {
                    let event_data = serde_json::json!({
                        "item_id": &item_id,
                        "output_index": output_index,
                        "delta": &initial_arguments,
                    });
                    out.push(Self::make_event(
                        "response.function_call_arguments.delta",
                        &event_data,
                    ));
                }

                self.active_items.insert(
                    block_index,
                    ActiveOutputItem::FunctionCall {
                        item_id,
                        output_index,
                        call_id,
                        name,
                        arguments: initial_arguments,
                    },
                );
            }
            _ => {}
        }

        out
    }

    fn handle_content_block_delta(&mut self, data: &str) -> Option<Bytes> {
        let json: serde_json::Value = serde_json::from_str(data).ok()?;
        let delta = json.get("delta")?;
        let delta_type = delta.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let block_index = json.get("index").and_then(|v| v.as_u64())? as u32;

        match (delta_type, self.active_items.get_mut(&block_index)?) {
            (
                "text_delta",
                ActiveOutputItem::Message {
                    item_id,
                    output_index,
                    text: current_text,
                },
            ) => {
                let text = delta.get("text").and_then(|v| v.as_str()).unwrap_or("");
                current_text.push_str(text);
                let event_data = serde_json::json!({
                    "item_id": &*item_id,
                    "output_index": *output_index,
                    "content_index": 0,
                    "delta": text,
                });
                Some(Self::make_event("response.output_text.delta", &event_data))
            }
            (
                "input_json_delta",
                ActiveOutputItem::FunctionCall {
                    item_id,
                    output_index,
                    arguments,
                    ..
                },
            ) => {
                let partial = delta
                    .get("partial_json")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                arguments.push_str(partial);
                let event_data = serde_json::json!({
                    "item_id": &*item_id,
                    "output_index": *output_index,
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

    fn handle_content_block_stop(&mut self, data: &str) -> Vec<Bytes> {
        let mut out = Vec::new();
        let json: serde_json::Value = match serde_json::from_str(data) {
            Ok(v) => v,
            Err(_) => return out,
        };
        let Some(block_index) = json.get("index").and_then(|v| v.as_u64()).map(|v| v as u32) else {
            return out;
        };
        let Some(item_state) = self.active_items.remove(&block_index) else {
            return out;
        };

        match item_state {
            ActiveOutputItem::Message {
                item_id,
                output_index,
                text,
            } => {
                // response.output_text.done — carries the full accumulated text.
                let text_done = serde_json::json!({
                    "item_id": &item_id,
                    "output_index": output_index,
                    "content_index": 0,
                    "text": &text,
                });
                out.push(Self::make_event("response.output_text.done", &text_done));

                // response.content_part.done
                let part_done = serde_json::json!({
                    "item_id": &item_id,
                    "output_index": output_index,
                    "content_index": 0,
                    "part": { "type": "output_text", "text": &text },
                });
                out.push(Self::make_event("response.content_part.done", &part_done));

                let item = serde_json::json!({
                    "id": item_id,
                    "type": "message",
                    "role": "assistant",
                    "status": "completed",
                    "content": [{ "type": "output_text", "text": text }],
                });
                let item_done = serde_json::json!({
                    "output_index": output_index,
                    "item": item.clone(),
                });
                out.push(Self::make_event("response.output_item.done", &item_done));
                self.output_items.push((output_index, item));
            }
            ActiveOutputItem::FunctionCall {
                item_id,
                output_index,
                call_id,
                name,
                arguments,
            } => {
                let arguments = if arguments.is_empty() {
                    "{}".to_string()
                } else {
                    arguments
                };

                // Codex finalizes the tool call from this event, so include the
                // consolidated arguments, not just the item/index identifiers.
                let args_done = serde_json::json!({
                    "item_id": &item_id,
                    "output_index": output_index,
                    "arguments": &arguments,
                });
                out.push(Self::make_event(
                    "response.function_call_arguments.done",
                    &args_done,
                ));

                let item = serde_json::json!({
                    "id": item_id,
                    "type": "function_call",
                    "call_id": call_id,
                    "name": name,
                    "arguments": arguments,
                    "status": "completed",
                });
                let item_done = serde_json::json!({
                    "output_index": output_index,
                    "item": item.clone(),
                });
                out.push(Self::make_event("response.output_item.done", &item_done));
                self.output_items.push((output_index, item));
            }
        }

        out
    }

    /// Transform a single Anthropic SSE event into zero or more Responses SSE bytes.
    pub fn transform_event(&mut self, event: &SseEvent) -> Vec<Bytes> {
        let Some(event_type) = event.event.as_deref() else {
            return Vec::new();
        };

        match event_type {
            "message_start" => {
                self.capture_usage(&event.data, "/message/usage");
                let in_progress = serde_json::json!({
                    "response": self.response_object("in_progress", serde_json::json!([])),
                });
                vec![
                    self.make_response_created(),
                    Self::make_event("response.in_progress", &in_progress),
                ]
            }
            "content_block_start" => self.handle_content_block_start(&event.data),
            "content_block_delta" => self
                .handle_content_block_delta(&event.data)
                .into_iter()
                .collect(),
            "content_block_stop" => self.handle_content_block_stop(&event.data),
            "message_delta" => {
                self.capture_usage(&event.data, "/usage");
                Vec::new()
            }
            "message_stop" => {
                let mut output_items = std::mem::take(&mut self.output_items);
                output_items.sort_by_key(|(idx, _)| *idx);
                let output = serde_json::Value::Array(
                    output_items.into_iter().map(|(_, item)| item).collect(),
                );
                let completed =
                    serde_json::json!({ "response": self.completed_response_object(output) });
                vec![
                    Self::make_event("response.completed", &completed),
                    Bytes::from("data: [DONE]\n\n"),
                ]
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

    fn event(event: &str, data: &str) -> SseEvent {
        SseEvent {
            event: Some(event.to_string()),
            data: data.to_string(),
        }
    }

    fn append_events(out: &mut String, events: Vec<Bytes>) {
        for bytes in events {
            out.push_str(std::str::from_utf8(&bytes).unwrap());
        }
    }

    fn json_events(output: &str, event_name: &str) -> Vec<serde_json::Value> {
        parse_sse_events(output)
            .into_iter()
            .filter(|event| event.event.as_deref() == Some(event_name))
            .map(|event| serde_json::from_str(&event.data).unwrap())
            .collect()
    }

    #[test]
    fn message_start_emits_response_created() {
        let mut stream = AnthropicToResponsesStream::new("gpt-5.4".to_string());
        let event = SseEvent {
            event: Some("message_start".to_string()),
            data: r#"{"type":"message_start","message":{"id":"msg_1","model":"gpt-5.4"}}"#
                .to_string(),
        };
        let result = stream.transform_event(&event);
        // message_start now emits response.created + response.in_progress.
        assert_eq!(result.len(), 2);
        let created = std::str::from_utf8(&result[0]).unwrap();
        assert!(created.starts_with("event: response.created\n"));
        // The data carries `type` (clients dispatch on it) and a `response` object.
        assert!(created.contains(r#""type":"response.created""#));
        assert!(created.contains(r#""response":{"#));
        let in_progress = std::str::from_utf8(&result[1]).unwrap();
        assert!(in_progress.starts_with("event: response.in_progress\n"));
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
        let start = SseEvent {
            event: Some("content_block_start".to_string()),
            data: r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#
                .to_string(),
        };
        stream.transform_event(&start);

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
    fn message_then_tool_call_preserves_arguments_in_done_and_completed() {
        let mut stream = AnthropicToResponsesStream::new("gpt-5.5".to_string());
        let mut out = String::new();

        for ev in [
            event(
                "message_start",
                r#"{"type":"message_start","message":{"id":"msg_1","model":"gpt-5.5"}}"#,
            ),
            event(
                "content_block_start",
                r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#,
            ),
            event(
                "content_block_delta",
                r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"I'll run that."}}"#,
            ),
            event(
                "content_block_stop",
                r#"{"type":"content_block_stop","index":0}"#,
            ),
            event(
                "content_block_start",
                r#"{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"call_exec","name":"exec_command","input":{}}}"#,
            ),
            event(
                "content_block_delta",
                r#"{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"cmd\":\""}}"#,
            ),
            event(
                "content_block_delta",
                r#"{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"ls\"}"}}"#,
            ),
            event(
                "content_block_stop",
                r#"{"type":"content_block_stop","index":1}"#,
            ),
            event("message_stop", r#"{"type":"message_stop"}"#),
        ] {
            append_events(&mut out, stream.transform_event(&ev));
        }

        let args_done = json_events(&out, "response.function_call_arguments.done");
        assert_eq!(args_done.len(), 1);
        assert_eq!(args_done[0]["output_index"], 1);
        assert_eq!(args_done[0]["arguments"], r#"{"cmd":"ls"}"#);

        let tool_done = json_events(&out, "response.output_item.done")
            .into_iter()
            .find(|event| event["item"]["type"] == "function_call")
            .expect("function_call output_item.done");
        assert_eq!(tool_done["output_index"], 1);
        assert_eq!(tool_done["item"]["call_id"], "call_exec");
        assert_eq!(tool_done["item"]["name"], "exec_command");
        assert_eq!(tool_done["item"]["arguments"], r#"{"cmd":"ls"}"#);

        let completed = json_events(&out, "response.completed")
            .pop()
            .expect("response.completed");
        let output = completed["response"]["output"].as_array().unwrap();
        assert_eq!(output[0]["type"], "message");
        assert_eq!(output[1]["type"], "function_call");
        assert_eq!(output[1]["call_id"], "call_exec");
        assert_eq!(output[1]["arguments"], r#"{"cmd":"ls"}"#);
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

    #[test]
    fn response_completed_includes_usage_from_message_delta() {
        let mut stream = AnthropicToResponsesStream::new("gpt-5.5".to_string());
        let mut out = String::new();

        for ev in [
            event(
                "message_start",
                r#"{"type":"message_start","message":{"usage":{"input_tokens":123,"output_tokens":0}}}"#,
            ),
            event(
                "message_delta",
                r#"{"type":"message_delta","usage":{"input_tokens":456,"output_tokens":78}}"#,
            ),
            event("message_stop", r#"{"type":"message_stop"}"#),
        ] {
            append_events(&mut out, stream.transform_event(&ev));
        }

        let completed = json_events(&out, "response.completed")
            .pop()
            .expect("response.completed");
        assert_eq!(completed["response"]["usage"]["input_tokens"], 456);
        assert_eq!(completed["response"]["usage"]["output_tokens"], 78);
        assert_eq!(completed["response"]["usage"]["total_tokens"], 534);
    }
}

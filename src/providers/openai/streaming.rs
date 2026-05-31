use super::tool_salvage::{drain_buffer, salvage_complete, SalvageEvent, SalvagedToolCall};
use super::types::{OpenAIStreamChunk, StreamTransformState};

/// Transform an OpenAI streaming chunk to Anthropic SSE format.
///
/// Converts OpenAI's Chat Completions streaming format to Anthropic's Messages API
/// streaming format. The transformation is stateful across chunks.
///
/// # Event Mapping (OpenAI → Anthropic)
/// - First chunk → `message_start`
/// - `delta.reasoning` → `thinking` content block
/// - `delta.content` → `text` content block
/// - `delta.tool_calls` → `content_block_start` (tool_use) + `input_json_delta`
/// - `finish_reason` → `content_block_stop` + `message_delta` + `message_stop`
pub(crate) fn transform_openai_chunk_to_anthropic_sse(
    chunk: &OpenAIStreamChunk,
    message_id: &str,
    state: &mut StreamTransformState,
) -> String {
    let mut output = String::new();

    if !state.message_started {
        emit_message_start(&mut output, message_id, &chunk.model);
        state.message_started = true;
    }

    for choice in &chunk.choices {
        if let Some(reasoning) = choice.delta.reasoning.as_ref() {
            if !reasoning.is_empty() {
                emit_reasoning_delta(&mut output, state, reasoning);
            }
        }

        if let Some(text) = choice.delta.content.as_ref() {
            if !text.is_empty() {
                push_text(&mut output, state, text);
            }
        }

        if let Some(ref tool_calls) = choice.delta.tool_calls {
            emit_tool_call_deltas(&mut output, state, tool_calls);
        }

        if let Some(reason) = &choice.finish_reason {
            emit_stream_end(&mut output, state, chunk, reason);
        }
    }

    if output.is_empty() {
        output.push_str(": ping\n\n");
    }

    output
}

fn emit_block_stop(output: &mut String, index: u32) {
    let event = serde_json::json!({
        "type": "content_block_stop",
        "index": index
    });
    output.push_str(&format!("event: content_block_stop\ndata: {}\n\n", event));
}

fn close_open_blocks(output: &mut String, state: &mut StreamTransformState) {
    if state.thinking_block_open {
        emit_block_stop(output, state.thinking_block_index);
        state.thinking_block_open = false;
    }
    if state.text_block_open {
        emit_block_stop(output, state.text_block_index);
        state.text_block_open = false;
    }
}

fn emit_message_start(output: &mut String, message_id: &str, model: &str) {
    let event = serde_json::json!({
        "type": "message_start",
        "message": {
            "id": message_id,
            "type": "message",
            "role": "assistant",
            "content": [],
            "model": model,
            "stop_reason": null,
            "stop_sequence": null,
            "usage": { "input_tokens": 0, "output_tokens": 0 }
        }
    });
    output.push_str(&format!("event: message_start\ndata: {}\n\n", event));
}

fn emit_reasoning_delta(output: &mut String, state: &mut StreamTransformState, reasoning: &str) {
    if !state.thinking_block_open {
        state.thinking_block_open = true;
        state.thinking_block_index = state.next_block_index;
        state.next_block_index += 1;
        let block_start = serde_json::json!({
            "type": "content_block_start",
            "index": state.thinking_block_index,
            "content_block": { "type": "thinking", "thinking": "" }
        });
        output.push_str(&format!(
            "event: content_block_start\ndata: {}\n\n",
            block_start
        ));
    }

    let delta = serde_json::json!({
        "type": "content_block_delta",
        "index": state.thinking_block_index,
        "delta": { "type": "thinking_delta", "thinking": reasoning }
    });
    output.push_str(&format!("event: content_block_delta\ndata: {}\n\n", delta));
}

fn emit_text_delta(output: &mut String, state: &mut StreamTransformState, text: &str) {
    if state.thinking_block_open {
        emit_block_stop(output, state.thinking_block_index);
        state.thinking_block_open = false;
    }

    if !state.text_block_open {
        state.text_block_open = true;
        state.text_block_index = state.next_block_index;
        state.next_block_index += 1;
        let block_start = serde_json::json!({
            "type": "content_block_start",
            "index": state.text_block_index,
            "content_block": { "type": "text", "text": "" }
        });
        output.push_str(&format!(
            "event: content_block_start\ndata: {}\n\n",
            block_start
        ));
    }

    let delta = serde_json::json!({
        "type": "content_block_delta",
        "index": state.text_block_index,
        "delta": { "type": "text_delta", "text": text }
    });
    output.push_str(&format!("event: content_block_delta\ndata: {}\n\n", delta));
}

/// Buffers assistant text and emits complete text / salvaged tool-call events.
///
/// Routing text through the salvage scanner lets a `<tool_call>` block that the
/// model leaked into plain content be recovered as a real `tool_use` block. A
/// trailing fragment that might continue a split marker stays in
/// `state.text_buffer` until the next delta. See
/// [`crate::providers::openai::tool_salvage`].
fn push_text(output: &mut String, state: &mut StreamTransformState, text: &str) {
    state.text_buffer.push_str(text);
    let events = drain_buffer(&mut state.text_buffer);
    apply_salvage_events(output, state, events);
}

/// Flushes any buffered text at stream end, treating an unterminated marker as text.
fn flush_text_buffer(output: &mut String, state: &mut StreamTransformState) {
    if state.text_buffer.is_empty() {
        return;
    }
    let remaining = std::mem::take(&mut state.text_buffer);
    let events = salvage_complete(&remaining);
    apply_salvage_events(output, state, events);
}

/// Emits the SSE for an ordered list of salvage events.
fn apply_salvage_events(
    output: &mut String,
    state: &mut StreamTransformState,
    events: Vec<SalvageEvent>,
) {
    for event in events {
        match event {
            SalvageEvent::Text(text) => emit_text_delta(output, state, &text),
            SalvageEvent::ToolCall(call) => emit_salvaged_tool_use(output, state, &call),
        }
    }
}

/// Emits a complete `tool_use` content block for a tool call recovered from text.
///
/// Unlike [`emit_tool_call_deltas`], the salvaged call is fully known up front,
/// so the block is opened, filled, and closed in one shot. Setting
/// `had_tool_calls` forces `stop_reason="tool_use"` so the client runs the tool.
fn emit_salvaged_tool_use(
    output: &mut String,
    state: &mut StreamTransformState,
    call: &SalvagedToolCall,
) {
    close_open_blocks(output, state);

    let block_index = state.next_block_index;
    state.next_block_index += 1;
    state.salvaged_tool_count += 1;
    state.had_tool_calls = true;
    let tool_id = format!("toolu_salvaged_{}", state.salvaged_tool_count);

    tracing::info!(
        "Salvaged leaked tool call '{}' as tool_use block {} (id {})",
        call.name,
        block_index,
        tool_id
    );

    let block_start = serde_json::json!({
        "type": "content_block_start",
        "index": block_index,
        "content_block": {
            "type": "tool_use",
            "id": tool_id,
            "name": call.name,
            "input": {}
        }
    });
    output.push_str(&format!(
        "event: content_block_start\ndata: {}\n\n",
        block_start
    ));

    let input_delta = serde_json::json!({
        "type": "content_block_delta",
        "index": block_index,
        "delta": { "type": "input_json_delta", "partial_json": call.input.to_string() }
    });
    output.push_str(&format!(
        "event: content_block_delta\ndata: {}\n\n",
        input_delta
    ));

    emit_block_stop(output, block_index);
}

fn emit_tool_call_deltas(
    output: &mut String,
    state: &mut StreamTransformState,
    tool_calls: &[serde_json::Value],
) {
    close_open_blocks(output, state);

    for tool_call in tool_calls {
        let tool_index = tool_call.get("index").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

        let has_id = tool_call.get("id").and_then(|v| v.as_str()).is_some();
        let has_name = tool_call
            .get("function")
            .and_then(|f| f.get("name"))
            .and_then(|n| n.as_str())
            .is_some();

        if has_id && has_name && !state.tool_blocks.contains_key(&tool_index) {
            let tool_id = tool_call
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("tool_0");
            let tool_name = tool_call
                .get("function")
                .and_then(|f| f.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("unknown");

            let block_index = state.next_block_index;
            state.tool_blocks.insert(tool_index, block_index);
            state.next_block_index += 1;
            state.had_tool_calls = true;

            tracing::debug!(
                "Tool start: {} (id: {}) at block index {}",
                tool_name,
                tool_id,
                block_index
            );

            let block_start = serde_json::json!({
                "type": "content_block_start",
                "index": block_index,
                "content_block": {
                    "type": "tool_use",
                    "id": tool_id,
                    "name": tool_name,
                    "input": {}
                }
            });
            output.push_str(&format!(
                "event: content_block_start\ndata: {}\n\n",
                block_start
            ));
        }

        if let Some(args) = tool_call
            .get("function")
            .and_then(|f| f.get("arguments"))
            .and_then(|a| a.as_str())
        {
            if !args.is_empty() {
                let block_index =
                    state
                        .tool_blocks
                        .get(&tool_index)
                        .copied()
                        .unwrap_or_else(|| {
                            let idx = state.next_block_index;
                            state.tool_blocks.insert(tool_index, idx);
                            state.next_block_index += 1;
                            idx
                        });

                let input_delta = serde_json::json!({
                    "type": "content_block_delta",
                    "index": block_index,
                    "delta": { "type": "input_json_delta", "partial_json": args }
                });
                output.push_str(&format!(
                    "event: content_block_delta\ndata: {}\n\n",
                    input_delta
                ));
            }
        }
    }
}

/// Opens an Anthropic `tool_use` block for a streaming Codex `function_call` item.
///
/// Codex streams a structured tool call as `output_item.added` (the call shell),
/// then `function_call_arguments.delta` chunks, then `output_item.done`. The
/// block is keyed by the Responses `output_index` so argument deltas correlate.
fn emit_responses_fc_start(
    output: &mut String,
    state: &mut StreamTransformState,
    json: &serde_json::Value,
    item: &serde_json::Value,
) {
    let output_index = json
        .get("output_index")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if state.responses_fc_blocks.contains_key(&output_index) {
        return;
    }

    close_open_blocks(output, state);

    let call_id = item
        .get("call_id")
        .or_else(|| item.get("id"))
        .and_then(|v| v.as_str())
        .unwrap_or("call_0");
    let name = item
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let block_index = state.next_block_index;
    state.next_block_index += 1;
    state.responses_fc_blocks.insert(output_index, block_index);
    state.had_tool_calls = true;

    let block_start = serde_json::json!({
        "type": "content_block_start",
        "index": block_index,
        "content_block": { "type": "tool_use", "id": call_id, "name": name, "input": {} }
    });
    output.push_str(&format!(
        "event: content_block_start\ndata: {}\n\n",
        block_start
    ));

    // `output_item.added` sometimes already carries the full arguments.
    if let Some(args) = item.get("arguments").and_then(|v| v.as_str()) {
        if !args.is_empty() {
            emit_responses_fc_input(output, block_index, args);
        }
    }
}

/// Emits an `input_json_delta` for a streaming Codex function-call argument chunk.
fn emit_responses_fc_args(
    output: &mut String,
    state: &mut StreamTransformState,
    json: &serde_json::Value,
    delta: &str,
) {
    let output_index = json
        .get("output_index")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if let Some(&block_index) = state.responses_fc_blocks.get(&output_index) {
        emit_responses_fc_input(output, block_index, delta);
    }
}

/// Closes a streaming Codex function-call block on `output_item.done`.
///
/// If the `added`/`delta` events were never seen (a fully-buffered call), the
/// block is opened and filled from the complete item before closing.
fn emit_responses_fc_done(
    output: &mut String,
    state: &mut StreamTransformState,
    json: &serde_json::Value,
    item: &serde_json::Value,
) {
    let output_index = json
        .get("output_index")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if !state.responses_fc_blocks.contains_key(&output_index) {
        emit_responses_fc_start(output, state, json, item);
    }
    if let Some(block_index) = state.responses_fc_blocks.remove(&output_index) {
        emit_block_stop(output, block_index);
    }
}

/// Emits a tool-use `input_json_delta` carrying a partial arguments string.
fn emit_responses_fc_input(output: &mut String, block_index: u32, partial_json: &str) {
    let delta = serde_json::json!({
        "type": "content_block_delta",
        "index": block_index,
        "delta": { "type": "input_json_delta", "partial_json": partial_json }
    });
    output.push_str(&format!("event: content_block_delta\ndata: {}\n\n", delta));
}

fn emit_stream_end(
    output: &mut String,
    state: &mut StreamTransformState,
    chunk: &OpenAIStreamChunk,
    reason: &str,
) {
    state.stream_ended = true;
    flush_text_buffer(output, state);

    if state.thinking_block_open {
        emit_block_stop(output, state.thinking_block_index);
    }
    if state.text_block_open {
        emit_block_stop(output, state.text_block_index);
    }
    for block_index in state.tool_blocks.values() {
        emit_block_stop(output, *block_index);
    }

    // If response included tool calls, force stop_reason="tool_use"
    // even if provider sent finish_reason="stop" (some providers do this incorrectly)
    let stop_reason = if state.had_tool_calls {
        if reason != "tool_calls" {
            tracing::info!("Correcting stop_reason: provider sent finish_reason='{}' but response had tool calls, using stop_reason='tool_use'", reason);
        }
        "tool_use"
    } else {
        match reason {
            "stop" => "end_turn",
            "length" => "max_tokens",
            "tool_calls" => "tool_use",
            _ => "end_turn",
        }
    };

    let (input_tokens, output_tokens) = chunk
        .usage
        .as_ref()
        .map(|u| (u.prompt_tokens, u.completion_tokens))
        .unwrap_or((0, 0));

    let message_delta = serde_json::json!({
        "type": "message_delta",
        "delta": { "stop_reason": stop_reason, "stop_sequence": null },
        "usage": { "input_tokens": input_tokens, "output_tokens": output_tokens }
    });
    output.push_str(&format!(
        "event: message_delta\ndata: {}\n\n",
        message_delta
    ));

    let message_stop = serde_json::json!({ "type": "message_stop" });
    output.push_str(&format!("event: message_stop\ndata: {}\n\n", message_stop));
    tracing::debug!(
        "Sent message_stop event, stream_ended=true, output_tokens={}",
        output_tokens
    );
}

/// Ensures the Anthropic `message_start` event is emitted exactly once.
fn ensure_message_started(
    output: &mut String,
    state: &mut StreamTransformState,
    message_id: &str,
    model: &str,
) {
    if !state.message_started {
        emit_message_start(output, message_id, model);
        state.message_started = true;
    }
}

/// Transform a single ChatGPT/Codex Responses-API SSE event to Anthropic SSE.
///
/// The Responses API streams typed events (`response.output_text.delta`,
/// `response.reasoning_summary_text.delta`, `response.completed`, …) instead of
/// Chat-Completions `choices[].delta` chunks. Text deltas map to a `text` block,
/// reasoning summary deltas to a `thinking` block, and `response.completed`
/// closes the message. Events without an Anthropic equivalent yield an empty
/// string (filtered out downstream).
pub(crate) fn transform_codex_event_to_anthropic_sse(
    data: &str,
    message_id: &str,
    model: &str,
    state: &mut StreamTransformState,
) -> String {
    let mut output = String::new();

    let Ok(json) = serde_json::from_str::<serde_json::Value>(data) else {
        return output;
    };
    let event_type = json
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    match event_type {
        "response.created" => ensure_message_started(&mut output, state, message_id, model),
        ty if ty.ends_with("output_text.delta") => {
            ensure_message_started(&mut output, state, message_id, model);
            if let Some(delta) = json.get("delta").and_then(|v| v.as_str()) {
                if !delta.is_empty() {
                    push_text(&mut output, state, delta);
                }
            }
        }
        ty if ty.contains("reasoning") && ty.ends_with(".delta") => {
            ensure_message_started(&mut output, state, message_id, model);
            if let Some(delta) = json.get("delta").and_then(|v| v.as_str()) {
                if !delta.is_empty() {
                    emit_reasoning_delta(&mut output, state, delta);
                }
            }
        }
        "response.output_item.added" => {
            if let Some(item) = json.get("item") {
                if item.get("type").and_then(|t| t.as_str()) == Some("function_call") {
                    ensure_message_started(&mut output, state, message_id, model);
                    emit_responses_fc_start(&mut output, state, &json, item);
                }
            }
        }
        ty if ty.ends_with("function_call_arguments.delta") => {
            if let Some(delta) = json.get("delta").and_then(|v| v.as_str()) {
                emit_responses_fc_args(&mut output, state, &json, delta);
            }
        }
        "response.output_item.done" => {
            if let Some(item) = json.get("item") {
                if item.get("type").and_then(|t| t.as_str()) == Some("function_call") {
                    emit_responses_fc_done(&mut output, state, &json, item);
                }
            }
        }
        "response.completed" | "response.incomplete" | "response.failed" => {
            ensure_message_started(&mut output, state, message_id, model);
            emit_codex_stream_end(&mut output, state, &json);
        }
        _ => {}
    }

    output
}

/// Closes any open content blocks and emits `message_delta` + `message_stop`
/// for a terminal Responses-API event (`response.completed` / `.incomplete`).
fn emit_codex_stream_end(
    output: &mut String,
    state: &mut StreamTransformState,
    json: &serde_json::Value,
) {
    if state.stream_ended {
        return;
    }
    state.stream_ended = true;
    flush_text_buffer(output, state);

    close_open_blocks(output, state);
    for block_index in state.tool_blocks.values() {
        emit_block_stop(output, *block_index);
    }
    // Close any function-call blocks whose `output_item.done` never arrived.
    for block_index in state.responses_fc_blocks.values() {
        emit_block_stop(output, *block_index);
    }

    let response = json.get("response");
    let status = response
        .and_then(|r| r.get("status"))
        .and_then(|v| v.as_str())
        .unwrap_or("completed");
    let stop_reason = if state.had_tool_calls {
        "tool_use"
    } else if status == "incomplete" {
        "max_tokens"
    } else {
        "end_turn"
    };

    let usage = response.and_then(|r| r.get("usage"));
    let input_tokens = usage
        .and_then(|u| u.get("input_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let output_tokens = usage
        .and_then(|u| u.get("output_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let message_delta = serde_json::json!({
        "type": "message_delta",
        "delta": { "stop_reason": stop_reason, "stop_sequence": null },
        "usage": { "input_tokens": input_tokens, "output_tokens": output_tokens }
    });
    output.push_str(&format!(
        "event: message_delta\ndata: {}\n\n",
        message_delta
    ));
    output.push_str(&format!(
        "event: message_stop\ndata: {}\n\n",
        serde_json::json!({ "type": "message_stop" })
    ));
}

#[cfg(test)]
mod codex_stream_tests {
    use super::transform_codex_event_to_anthropic_sse as transform;
    use crate::providers::openai::types::StreamTransformState;

    fn run(events: &[&str]) -> String {
        let mut state = StreamTransformState::default();
        let mut out = String::new();
        for event in events {
            out.push_str(&transform(event, "msg_test", "gpt-5.5", &mut state));
        }
        out
    }

    #[test]
    fn emits_message_start_then_incremental_text_then_stop() {
        let out = run(&[
            r#"{"type":"response.created","response":{"model":"gpt-5.5"}}"#,
            r#"{"type":"response.output_text.delta","delta":"Hel"}"#,
            r#"{"type":"response.output_text.delta","delta":"lo"}"#,
            r#"{"type":"response.completed","response":{"status":"completed"}}"#,
        ]);
        assert!(out.contains("event: message_start"));
        assert!(out.contains("event: content_block_start"));
        assert!(out.contains("text_delta"));
        assert!(out.contains(r#""text":"Hel""#));
        assert!(out.contains(r#""text":"lo""#));
        assert!(out.contains("end_turn"));
        assert_eq!(out.matches("event: message_stop").count(), 1);
        assert_eq!(out.matches("event: message_start").count(), 1);
    }

    #[test]
    fn maps_reasoning_delta_to_thinking_block() {
        let out = run(&[
            r#"{"type":"response.reasoning_summary_text.delta","delta":"weighing"}"#,
            r#"{"type":"response.output_text.delta","delta":"answer"}"#,
            r#"{"type":"response.completed","response":{"status":"completed"}}"#,
        ]);
        assert!(out.contains("thinking_delta"));
        assert!(out.contains(r#""thinking":"weighing""#));
        assert!(out.contains(r#""text":"answer""#));
        // The thinking block is closed before the text block opens.
        assert!(out.contains("event: content_block_stop"));
    }

    #[test]
    fn incomplete_status_maps_to_max_tokens() {
        let out = run(&[
            r#"{"type":"response.output_text.delta","delta":"x"}"#,
            r#"{"type":"response.incomplete","response":{"status":"incomplete"}}"#,
        ]);
        assert!(out.contains("max_tokens"));
    }

    #[test]
    fn leaked_tool_call_in_text_is_salvaged_as_tool_use() {
        // The tool_call marker and JSON are split across deltas to exercise the
        // streaming buffer.
        let out = run(&[
            r#"{"type":"response.created","response":{"model":"gpt-5.5"}}"#,
            r#"{"type":"response.output_text.delta","delta":"sure, running <tool_"}"#,
            r#"{"type":"response.output_text.delta","delta":"call>{\"name\":\"Bash\","}"#,
            r#"{"type":"response.output_text.delta","delta":"\"arguments\":{\"command\":\"ls\"}}</tool_call>"}"#,
            r#"{"type":"response.completed","response":{"status":"completed"}}"#,
        ]);

        // The pre-marker text is still forwarded.
        assert!(out.contains(r#""text":"sure, running ""#));
        // A tool_use block is opened with the recovered name.
        assert!(out.contains(r#""type":"tool_use""#));
        assert!(out.contains(r#""name":"Bash""#));
        // Its input arrives as an input_json_delta.
        assert!(out.contains("input_json_delta"));
        assert!(out.contains(r#"command\":\"ls"#));
        // The leaked marker itself must not leak through as text.
        assert!(!out.contains("tool_call>"));
        // Salvaging forces stop_reason=tool_use so the client runs the tool.
        assert!(out.contains(r#""stop_reason":"tool_use""#));
    }

    #[test]
    fn structured_function_call_streams_as_tool_use() {
        let out = run(&[
            r#"{"type":"response.created","response":{"model":"gpt-5.5"}}"#,
            r#"{"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","call_id":"call_abc","name":"Bash","arguments":""}}"#,
            r#"{"type":"response.function_call_arguments.delta","output_index":0,"delta":"{\"command\":\""}"#,
            r#"{"type":"response.function_call_arguments.delta","output_index":0,"delta":"ls\"}"}"#,
            r#"{"type":"response.output_item.done","output_index":0,"item":{"type":"function_call","call_id":"call_abc","name":"Bash","arguments":"{\"command\":\"ls\"}"}}"#,
            r#"{"type":"response.completed","response":{"status":"completed"}}"#,
        ]);

        // A single tool_use block opened with the call's id and name.
        assert_eq!(out.matches(r#""type":"tool_use""#).count(), 1);
        assert!(out.contains(r#""id":"call_abc""#));
        assert!(out.contains(r#""name":"Bash""#));
        // Arguments arrive incrementally as input_json_delta, not text.
        assert!(out.contains("input_json_delta"));
        assert!(!out.contains("text_delta"));
        // The block is closed and the turn ends with tool_use.
        assert!(out.contains("event: content_block_stop"));
        assert!(out.contains(r#""stop_reason":"tool_use""#));
    }

    #[test]
    fn unknown_events_and_garbage_are_ignored() {
        let out = run(&[
            "not json",
            r#"{"type":"response.in_progress"}"#,
            r#"{"type":"response.output_item.added","item":{"type":"message"}}"#,
        ]);
        assert!(out.is_empty());
    }
}

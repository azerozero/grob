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
                emit_text_delta(&mut output, state, text);
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

fn emit_stream_end(
    output: &mut String,
    state: &mut StreamTransformState,
    chunk: &OpenAIStreamChunk,
    reason: &str,
) {
    state.stream_ended = true;

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

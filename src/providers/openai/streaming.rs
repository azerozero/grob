use super::tool_salvage::{drain_buffer, salvage_complete, SalvageEvent, SalvagedToolCall};
use super::types::{OpenAIStreamChunk, StreamTransformState};
use crate::providers::error::ProviderError;

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

    emit_tool_input_delta(output, block_index, &call.name, &call.input.to_string());

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
        if let Some(tool_name) = tool_call
            .get("function")
            .and_then(|f| f.get("name"))
            .and_then(|n| n.as_str())
        {
            state.tool_names.insert(tool_index, tool_name.to_string());
        }

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

                let tool_name = tool_call
                    .get("function")
                    .and_then(|f| f.get("name"))
                    .and_then(|n| n.as_str())
                    .or_else(|| state.tool_names.get(&tool_index).map(String::as_str))
                    .unwrap_or("unknown");
                emit_tool_input_delta(output, block_index, tool_name, args);
            }
        }
    }
}

/// Opens an Anthropic `tool_use` block for a streaming Codex `function_call` item.
///
/// Codex streams a structured tool call as `output_item.added` (the call shell),
/// then `function_call_arguments.delta` chunks, then `output_item.done`. The
/// block is keyed by the Responses `output_index` so argument deltas correlate.
fn resolve_responses_fc_output_index(
    state: &StreamTransformState,
    json: &serde_json::Value,
    item: Option<&serde_json::Value>,
    fallback_to_single_open: bool,
) -> Option<u64> {
    if let Some(output_index) = json.get("output_index").and_then(|v| v.as_u64()) {
        return Some(output_index);
    }

    for id in [
        json.get("item_id").and_then(|v| v.as_str()),
        item.and_then(|i| i.get("id")).and_then(|v| v.as_str()),
        item.and_then(|i| i.get("call_id")).and_then(|v| v.as_str()),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(output_index) = state.responses_fc_item_indexes.get(id) {
            return Some(*output_index);
        }
    }

    if fallback_to_single_open && state.responses_fc_blocks.len() == 1 {
        return state.responses_fc_blocks.keys().next().copied();
    }

    None
}

fn emit_responses_fc_start(
    output: &mut String,
    state: &mut StreamTransformState,
    json: &serde_json::Value,
    item: &serde_json::Value,
) {
    let output_index =
        resolve_responses_fc_output_index(state, json, Some(item), false).unwrap_or(0);
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
    state.responses_fc_args.entry(output_index).or_default();
    state
        .responses_fc_names
        .insert(output_index, name.to_string());
    for id in [
        item.get("id").and_then(|v| v.as_str()),
        item.get("call_id").and_then(|v| v.as_str()),
    ]
    .into_iter()
    .flatten()
    {
        state
            .responses_fc_item_indexes
            .insert(id.to_string(), output_index);
    }

    // Anthropic streams tool input incrementally: start with an empty object,
    // then send the real arguments as input_json_delta events.
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
            emit_tool_input_delta(output, block_index, name, args);
            state
                .responses_fc_args
                .entry(output_index)
                .or_default()
                .push_str(args);
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
    let Some(output_index) = resolve_responses_fc_output_index(state, json, None, true) else {
        return;
    };
    if let Some(&block_index) = state.responses_fc_blocks.get(&output_index) {
        let tool_name = state
            .responses_fc_names
            .get(&output_index)
            .map(String::as_str)
            .unwrap_or("unknown");
        emit_tool_input_delta(output, block_index, tool_name, delta);
        state
            .responses_fc_args
            .entry(output_index)
            .or_default()
            .push_str(delta);
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
    let output_index =
        resolve_responses_fc_output_index(state, json, Some(item), true).unwrap_or(0);
    if !state.responses_fc_blocks.contains_key(&output_index) {
        emit_responses_fc_start(output, state, json, item);
    }
    let emitted_args = state
        .responses_fc_args
        .get(&output_index)
        .is_some_and(|args| !args.is_empty());
    if !emitted_args {
        if let Some(args) = item.get("arguments").and_then(|v| v.as_str()) {
            if !args.is_empty() {
                if let Some(&block_index) = state.responses_fc_blocks.get(&output_index) {
                    let tool_name = state
                        .responses_fc_names
                        .get(&output_index)
                        .map(String::as_str)
                        .or_else(|| item.get("name").and_then(|v| v.as_str()))
                        .unwrap_or("unknown");
                    emit_tool_input_delta(output, block_index, tool_name, args);
                }
            }
        }
    }
    if let Some(block_index) = state.responses_fc_blocks.remove(&output_index) {
        emit_block_stop(output, block_index);
    }
    state.responses_fc_args.remove(&output_index);
    for id in [
        item.get("id").and_then(|v| v.as_str()),
        item.get("call_id").and_then(|v| v.as_str()),
    ]
    .into_iter()
    .flatten()
    {
        state.responses_fc_item_indexes.remove(id);
    }
    state.responses_fc_names.remove(&output_index);
}

/// Emits a tool-use `input_json_delta` carrying a partial arguments string.
fn emit_tool_input_delta(
    output: &mut String,
    block_index: u32,
    tool_name: &str,
    partial_json: &str,
) {
    let partial_json = sanitize_tool_input_delta(tool_name, partial_json);
    let delta = serde_json::json!({
        "type": "content_block_delta",
        "index": block_index,
        "delta": { "type": "input_json_delta", "partial_json": partial_json.as_ref() }
    });
    output.push_str(&format!("event: content_block_delta\ndata: {}\n\n", delta));
}

pub(crate) fn sanitize_tool_input_delta<'a>(
    tool_name: &str,
    partial_json: &'a str,
) -> std::borrow::Cow<'a, str> {
    if tool_name != "Read" || !has_read_tool_normalizable_field(partial_json) {
        return std::borrow::Cow::Borrowed(partial_json);
    }

    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(partial_json) else {
        return std::borrow::Cow::Borrowed(partial_json);
    };
    let Some(obj) = value.as_object_mut() else {
        return std::borrow::Cow::Borrowed(partial_json);
    };

    let mut changed = apply_read_pages_normalization(obj);
    changed |= apply_read_integer_normalization(obj, "offset", 0);
    changed |= apply_read_integer_normalization(obj, "limit", 1);

    if !changed {
        return std::borrow::Cow::Borrowed(partial_json);
    }

    match serde_json::to_string(&value) {
        Ok(sanitized) => {
            tracing::debug!("Normalized Read tool arguments");
            std::borrow::Cow::Owned(sanitized)
        }
        Err(_) => std::borrow::Cow::Borrowed(partial_json),
    }
}

fn has_read_tool_normalizable_field(partial_json: &str) -> bool {
    partial_json.contains("\"pages\"")
        || partial_json.contains("\"offset\"")
        || partial_json.contains("\"limit\"")
}

fn apply_read_pages_normalization(obj: &mut serde_json::Map<String, serde_json::Value>) -> bool {
    let Some(action) = normalize_read_pages(obj.get("pages")) else {
        return false;
    };

    match action {
        ReadPagesNormalization::Set(pages) => {
            obj.insert("pages".to_string(), serde_json::Value::String(pages));
        }
        ReadPagesNormalization::Remove => {
            obj.remove("pages");
        }
    }
    true
}

enum ReadPagesNormalization {
    Set(String),
    Remove,
}

fn normalize_read_pages(value: Option<&serde_json::Value>) -> Option<ReadPagesNormalization> {
    let value = value?;
    match value {
        serde_json::Value::String(raw) => normalize_read_pages_string(raw),
        serde_json::Value::Number(number) => page_number_to_string(number)
            .map(ReadPagesNormalization::Set)
            .or(Some(ReadPagesNormalization::Remove)),
        serde_json::Value::Array(items) => normalize_read_pages_array(items),
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Object(_) => {
            Some(ReadPagesNormalization::Remove)
        }
    }
}

fn normalize_read_pages_string(raw: &str) -> Option<ReadPagesNormalization> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Some(ReadPagesNormalization::Remove);
    }
    if !is_valid_read_pages_spec(trimmed) {
        return Some(ReadPagesNormalization::Remove);
    }
    if trimmed == raw {
        None
    } else {
        Some(ReadPagesNormalization::Set(trimmed.to_string()))
    }
}

fn normalize_read_pages_array(items: &[serde_json::Value]) -> Option<ReadPagesNormalization> {
    match items {
        [] => Some(ReadPagesNormalization::Remove),
        [single] => page_value_to_string(single)
            .map(ReadPagesNormalization::Set)
            .or(Some(ReadPagesNormalization::Remove)),
        [start, end] => match (page_value_to_u64(start), page_value_to_u64(end)) {
            (Some(start), Some(end)) if start <= end => {
                Some(ReadPagesNormalization::Set(format!("{start}-{end}")))
            }
            _ => Some(ReadPagesNormalization::Remove),
        },
        _ => Some(ReadPagesNormalization::Remove),
    }
}

fn page_value_to_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(raw) if is_valid_read_pages_spec(raw.trim()) => {
            Some(raw.trim().to_string())
        }
        serde_json::Value::Number(number) => page_number_to_string(number),
        _ => None,
    }
}

fn page_value_to_u64(value: &serde_json::Value) -> Option<u64> {
    match value {
        serde_json::Value::Number(number) => page_number_to_u64(number),
        serde_json::Value::String(raw) => raw.trim().parse::<u64>().ok().filter(|page| *page > 0),
        _ => None,
    }
}

fn page_number_to_string(number: &serde_json::Number) -> Option<String> {
    page_number_to_u64(number).map(|page| page.to_string())
}

fn page_number_to_u64(number: &serde_json::Number) -> Option<u64> {
    if let Some(page) = number.as_u64() {
        return (page > 0).then_some(page);
    }
    let page = number.as_f64()?;
    if page.is_finite() && page.fract() == 0.0 && page > 0.0 && page <= u64::MAX as f64 {
        Some(page as u64)
    } else {
        None
    }
}

fn is_valid_read_pages_spec(spec: &str) -> bool {
    if let Some((start, end)) = spec.split_once('-') {
        match (start.parse::<u64>(), end.parse::<u64>()) {
            (Ok(start), Ok(end)) => start > 0 && start <= end,
            _ => false,
        }
    } else {
        spec.parse::<u64>().is_ok_and(|page| page > 0)
    }
}

fn apply_read_integer_normalization(
    obj: &mut serde_json::Map<String, serde_json::Value>,
    field: &str,
    min: u64,
) -> bool {
    let Some(action) = normalize_read_integer(obj.get(field), min) else {
        return false;
    };

    match action {
        ReadIntegerNormalization::Set(value) => {
            obj.insert(field.to_string(), serde_json::Value::Number(value.into()));
        }
        ReadIntegerNormalization::Remove => {
            obj.remove(field);
        }
    }
    true
}

enum ReadIntegerNormalization {
    Set(u64),
    Remove,
}

fn normalize_read_integer(
    value: Option<&serde_json::Value>,
    min: u64,
) -> Option<ReadIntegerNormalization> {
    let value = value?;
    match value {
        serde_json::Value::String(raw) => parse_read_integer_string(raw, min)
            .map(ReadIntegerNormalization::Set)
            .or(Some(ReadIntegerNormalization::Remove)),
        serde_json::Value::Number(number) => {
            if number.as_u64().is_some_and(|value| value >= min) {
                None
            } else {
                read_integer_number_to_u64(number, min)
                    .map(ReadIntegerNormalization::Set)
                    .or(Some(ReadIntegerNormalization::Remove))
            }
        }
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Array(_)
        | serde_json::Value::Object(_) => Some(ReadIntegerNormalization::Remove),
    }
}

fn parse_read_integer_string(raw: &str, min: u64) -> Option<u64> {
    let trimmed = raw.trim();
    let digits = trimmed.strip_prefix('+').unwrap_or(trimmed);
    digits.parse::<u64>().ok().filter(|value| *value >= min)
}

fn read_integer_number_to_u64(number: &serde_json::Number, min: u64) -> Option<u64> {
    let value = number.as_f64()?;
    if value.is_finite() && value.fract() == 0.0 && value >= min as f64 && value <= u64::MAX as f64
    {
        Some(value as u64)
    } else {
        None
    }
}

fn message_delta_with_usage(
    stop_reason: &str,
    input_tokens: u64,
    output_tokens: u64,
    cache_read_input_tokens: u64,
) -> serde_json::Value {
    let mut usage = serde_json::json!({
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
    });
    if cache_read_input_tokens > 0 {
        if let Some(map) = usage.as_object_mut() {
            map.insert(
                "cache_read_input_tokens".to_string(),
                serde_json::Value::Number(cache_read_input_tokens.into()),
            );
        }
    }

    serde_json::json!({
        "type": "message_delta",
        "delta": { "stop_reason": stop_reason, "stop_sequence": null },
        "usage": usage
    })
}

fn responses_usage_tokens(usage: Option<&serde_json::Value>) -> (u64, u64, u64) {
    let Some(usage) = usage else {
        return (0, 0, 0);
    };
    let input_tokens = usage
        .get("input_tokens")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let output_tokens = usage
        .get("output_tokens")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let cached_tokens = usage
        .pointer("/input_tokens_details/cached_tokens")
        .or_else(|| usage.pointer("/prompt_tokens_details/cached_tokens"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);

    (
        input_tokens.saturating_sub(cached_tokens),
        output_tokens,
        cached_tokens,
    )
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

    let (input_tokens, output_tokens, cache_read_input_tokens) = chunk
        .usage
        .as_ref()
        .map(|u| {
            let cached = u.cached_tokens() as u64;
            let prompt = u.prompt_tokens as u64;
            (
                prompt.saturating_sub(cached),
                u.completion_tokens as u64,
                cached,
            )
        })
        .unwrap_or((0, 0, 0));

    let message_delta = message_delta_with_usage(
        stop_reason,
        input_tokens,
        output_tokens,
        cache_read_input_tokens,
    );
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
) -> Result<String, ProviderError> {
    let mut output = String::new();

    if state.stream_ended {
        return Ok(output);
    }

    let json =
        serde_json::from_str::<serde_json::Value>(data).map_err(|e| ProviderError::ApiError {
            status: 502,
            message: format!(
                "OpenAI Responses stream emitted malformed JSON SSE payload ({} bytes): {}",
                data.len(),
                e
            ),
        })?;
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
        "response.completed" | "response.incomplete" => {
            ensure_message_started(&mut output, state, message_id, model);
            emit_codex_stream_end(&mut output, state, &json);
        }
        "response.failed" => {
            ensure_message_started(&mut output, state, message_id, model);
            emit_codex_stream_failure(&mut output, state, &json);
        }
        _ => {}
    }

    Ok(output)
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

    let (input_tokens, output_tokens, cache_read_input_tokens) =
        responses_usage_tokens(response.and_then(|r| r.get("usage")));

    let message_delta = message_delta_with_usage(
        stop_reason,
        input_tokens,
        output_tokens,
        cache_read_input_tokens,
    );
    output.push_str(&format!(
        "event: message_delta\ndata: {}\n\n",
        message_delta
    ));
    output.push_str(&format!(
        "event: message_stop\ndata: {}\n\n",
        serde_json::json!({ "type": "message_stop" })
    ));
}

/// Emits an Anthropic-compatible stream error for a failed Responses-API event.
fn emit_codex_stream_failure(
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
    for block_index in state.responses_fc_blocks.values() {
        emit_block_stop(output, *block_index);
    }

    let message = json
        .pointer("/response/error/message")
        .or_else(|| json.pointer("/error/message"))
        .or_else(|| json.get("detail"))
        .and_then(|v| v.as_str())
        .unwrap_or("Responses stream failed");
    let event = serde_json::json!({
        "type": "error",
        "error": {
            "type": "api_error",
            "message": message
        }
    });
    output.push_str(&format!("event: error\ndata: {}\n\n", event));
}

#[cfg(test)]
mod codex_stream_tests {
    use super::transform_codex_event_to_anthropic_sse as transform;
    use crate::providers::openai::types::{OpenAIStreamChunk, StreamTransformState};
    use crate::providers::streaming::parse_sse_events;

    fn run(events: &[&str]) -> String {
        let mut state = StreamTransformState::default();
        let mut out = String::new();
        for event in events {
            out.push_str(&transform(event, "msg_test", "gpt-5.5", &mut state).unwrap());
        }
        out
    }

    fn run_openai_chunks(chunks: &[&str]) -> String {
        let mut state = StreamTransformState::default();
        let mut out = String::new();
        for chunk in chunks {
            let chunk: OpenAIStreamChunk = serde_json::from_str(chunk).unwrap();
            out.push_str(&super::transform_openai_chunk_to_anthropic_sse(
                &chunk, "msg_test", &mut state,
            ));
        }
        out
    }

    fn collected_tool_input(output: &str) -> String {
        parse_sse_events(output)
            .into_iter()
            .filter(|event| event.event.as_deref() == Some("content_block_delta"))
            .filter_map(|event| serde_json::from_str::<serde_json::Value>(&event.data).ok())
            .filter(|json| json["delta"]["type"] == "input_json_delta")
            .filter_map(|json| json["delta"]["partial_json"].as_str().map(str::to_string))
            .collect::<String>()
    }

    #[test]
    fn chat_completions_read_tool_empty_pages_argument_is_stripped() {
        let out = run_openai_chunks(&[
            r#"{"model":"gpt-4.1","choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_read","type":"function","function":{"name":"Read","arguments":""}}]},"finish_reason":null}]}"#,
            r#"{"model":"gpt-4.1","choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"file_path\":\"/tmp/SKILL.md\",\"offset\":0,\"limit\":2000,\"pages\":\"\"}"}}]},"finish_reason":null}]}"#,
            r#"{"model":"gpt-4.1","choices":[{"delta":{},"finish_reason":"tool_calls"}]}"#,
        ]);

        assert!(out.contains(r#""type":"tool_use""#));
        assert!(out.contains(r#""name":"Read""#));

        let input = collected_tool_input(&out);
        let json: serde_json::Value = serde_json::from_str(&input).unwrap();
        assert_eq!(json["file_path"], "/tmp/SKILL.md");
        assert_eq!(json["offset"], 0);
        assert_eq!(json["limit"], 2000);
        assert!(json.get("pages").is_none());
        assert!(out.contains(r#""stop_reason":"tool_use""#));
    }

    #[test]
    fn chat_completions_stream_preserves_cached_token_usage() {
        let out = run_openai_chunks(&[
            r#"{"model":"gpt-4.1","choices":[{"delta":{"content":"ok"},"finish_reason":null}]}"#,
            r#"{"model":"gpt-4.1","choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":42,"prompt_tokens_details":{"cached_tokens":700}}}"#,
        ]);

        assert!(out.contains(r#""input_tokens":300"#));
        assert!(out.contains(r#""output_tokens":42"#));
        assert!(out.contains(r#""cache_read_input_tokens":700"#));
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
    fn responses_stream_preserves_cached_token_usage() {
        let out = run(&[
            r#"{"type":"response.created","response":{"model":"gpt-5.5"}}"#,
            r#"{"type":"response.output_text.delta","delta":"ok"}"#,
            r#"{"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":1000,"output_tokens":42,"input_tokens_details":{"cached_tokens":700}}}}"#,
        ]);

        assert!(out.contains(r#""input_tokens":300"#));
        assert!(out.contains(r#""output_tokens":42"#));
        assert!(out.contains(r#""cache_read_input_tokens":700"#));
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
    fn failed_status_emits_error_not_successful_stop() {
        let out = run(&[
            r#"{"type":"response.output_text.delta","delta":"partial"}"#,
            r#"{"type":"response.failed","response":{"status":"failed","error":{"message":"boom"}}}"#,
        ]);
        assert!(out.contains("event: error"));
        assert!(out.contains("boom"));
        assert!(!out.contains("event: message_stop"));
        assert!(!out.contains(r#""stop_reason":"end_turn""#));
    }

    #[test]
    fn events_after_terminal_response_are_ignored() {
        let out = run(&[
            r#"{"type":"response.output_text.delta","delta":"before"}"#,
            r#"{"type":"response.completed","response":{"status":"completed"}}"#,
            r#"{"type":"response.output_text.delta","delta":"after"}"#,
            r#"{"type":"response.failed","response":{"status":"failed","error":{"message":"late"}}}"#,
        ]);
        assert!(out.contains(r#""text":"before""#));
        assert!(!out.contains(r#""text":"after""#));
        assert!(!out.contains("late"));
        assert_eq!(out.matches("event: message_stop").count(), 1);
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
    fn structured_function_call_after_preamble_uses_its_output_index() {
        let out = run(&[
            r#"{"type":"response.created","response":{"model":"gpt-5.5"}}"#,
            r#"{"type":"response.output_text.delta","output_index":0,"delta":"I'll run that."}"#,
            r#"{"type":"response.output_item.added","output_index":1,"item":{"id":"fc_1","type":"function_call","call_id":"call_exec","name":"exec_command","arguments":""}}"#,
            r#"{"type":"response.function_call_arguments.delta","item_id":"fc_1","output_index":1,"delta":"{\"cmd\":\""}"#,
            r#"{"type":"response.function_call_arguments.delta","item_id":"fc_1","output_index":1,"delta":"ls\"}"}"#,
            r#"{"type":"response.output_item.done","output_index":1,"item":{"id":"fc_1","type":"function_call","call_id":"call_exec","name":"exec_command","arguments":"{\"cmd\":\"ls\"}"}}"#,
            r#"{"type":"response.completed","response":{"status":"completed"}}"#,
        ]);

        assert!(out.contains(r#""text":"I'll run that.""#));
        assert!(out.contains(r#""type":"tool_use""#));
        assert!(out.contains(r#""id":"call_exec""#));
        assert!(out.contains(r#""name":"exec_command""#));
        assert_eq!(collected_tool_input(&out), r#"{"cmd":"ls"}"#);
        assert!(out.contains(r#""stop_reason":"tool_use""#));
    }

    #[test]
    fn structured_function_call_done_arguments_fill_missing_deltas() {
        let out = run(&[
            r#"{"type":"response.created","response":{"model":"gpt-5.5"}}"#,
            r#"{"type":"response.output_item.added","output_index":0,"item":{"id":"fc_1","type":"function_call","call_id":"call_exec","name":"exec_command","arguments":""}}"#,
            r#"{"type":"response.output_item.done","output_index":0,"item":{"id":"fc_1","type":"function_call","call_id":"call_exec","name":"exec_command","arguments":"{\"cmd\":\"ls\"}"}}"#,
            r#"{"type":"response.completed","response":{"status":"completed"}}"#,
        ]);

        assert!(out.contains(r#""type":"tool_use""#));
        assert!(out.contains("input_json_delta"));
        assert_eq!(collected_tool_input(&out), r#"{"cmd":"ls"}"#);
        assert!(out.contains(r#""stop_reason":"tool_use""#));
    }

    #[test]
    fn read_tool_empty_pages_argument_is_stripped() {
        let out = run(&[
            r#"{"type":"response.created","response":{"model":"gpt-5.5"}}"#,
            r#"{"type":"response.output_item.added","output_index":0,"item":{"id":"fc_read","type":"function_call","call_id":"call_read","name":"Read","arguments":""}}"#,
            r#"{"type":"response.function_call_arguments.delta","item_id":"fc_read","output_index":0,"delta":"{\"file_path\":\"/tmp/SKILL.md\",\"offset\":0,\"limit\":2000,\"pages\":\"\"}"}"#,
            r#"{"type":"response.output_item.done","output_index":0,"item":{"id":"fc_read","type":"function_call","call_id":"call_read","name":"Read","arguments":"{\"file_path\":\"/tmp/SKILL.md\",\"offset\":0,\"limit\":2000,\"pages\":\"\"}"}}"#,
            r#"{"type":"response.completed","response":{"status":"completed"}}"#,
        ]);

        let input = collected_tool_input(&out);
        let json: serde_json::Value = serde_json::from_str(&input).unwrap();
        assert_eq!(json["file_path"], "/tmp/SKILL.md");
        assert_eq!(json["offset"], 0);
        assert_eq!(json["limit"], 2000);
        assert!(json.get("pages").is_none());
        assert!(out.contains(r#""stop_reason":"tool_use""#));
    }

    #[test]
    fn read_tool_numeric_pages_argument_is_converted() {
        let out = run(&[
            r#"{"type":"response.created","response":{"model":"gpt-5.5"}}"#,
            r#"{"type":"response.output_item.added","output_index":0,"item":{"id":"fc_read","type":"function_call","call_id":"call_read","name":"Read","arguments":""}}"#,
            r#"{"type":"response.function_call_arguments.delta","item_id":"fc_read","output_index":0,"delta":"{\"file_path\":\"/tmp/manual.pdf\",\"pages\":3}"}"#,
            r#"{"type":"response.output_item.done","output_index":0,"item":{"id":"fc_read","type":"function_call","call_id":"call_read","name":"Read","arguments":"{\"file_path\":\"/tmp/manual.pdf\",\"pages\":3}"}}"#,
            r#"{"type":"response.completed","response":{"status":"completed"}}"#,
        ]);

        let input = collected_tool_input(&out);
        let json: serde_json::Value = serde_json::from_str(&input).unwrap();
        assert_eq!(json["file_path"], "/tmp/manual.pdf");
        assert_eq!(json["pages"], "3");
    }

    #[test]
    fn read_tool_pages_array_range_argument_is_converted() {
        let out = run(&[
            r#"{"type":"response.created","response":{"model":"gpt-5.5"}}"#,
            r#"{"type":"response.output_item.added","output_index":0,"item":{"id":"fc_read","type":"function_call","call_id":"call_read","name":"Read","arguments":""}}"#,
            r#"{"type":"response.function_call_arguments.delta","item_id":"fc_read","output_index":0,"delta":"{\"file_path\":\"/tmp/manual.pdf\",\"pages\":[1,5]}"}"#,
            r#"{"type":"response.output_item.done","output_index":0,"item":{"id":"fc_read","type":"function_call","call_id":"call_read","name":"Read","arguments":"{\"file_path\":\"/tmp/manual.pdf\",\"pages\":[1,5]}"}}"#,
            r#"{"type":"response.completed","response":{"status":"completed"}}"#,
        ]);

        let input = collected_tool_input(&out);
        let json: serde_json::Value = serde_json::from_str(&input).unwrap();
        assert_eq!(json["file_path"], "/tmp/manual.pdf");
        assert_eq!(json["pages"], "1-5");
    }

    #[test]
    fn read_tool_invalid_pages_argument_is_stripped() {
        let out = run(&[
            r#"{"type":"response.created","response":{"model":"gpt-5.5"}}"#,
            r#"{"type":"response.output_item.added","output_index":0,"item":{"id":"fc_read","type":"function_call","call_id":"call_read","name":"Read","arguments":""}}"#,
            r#"{"type":"response.function_call_arguments.delta","item_id":"fc_read","output_index":0,"delta":"{\"file_path\":\"/tmp/manual.pdf\",\"pages\":\"0-2\"}"}"#,
            r#"{"type":"response.output_item.done","output_index":0,"item":{"id":"fc_read","type":"function_call","call_id":"call_read","name":"Read","arguments":"{\"file_path\":\"/tmp/manual.pdf\",\"pages\":\"0-2\"}"}}"#,
            r#"{"type":"response.completed","response":{"status":"completed"}}"#,
        ]);

        let input = collected_tool_input(&out);
        let json: serde_json::Value = serde_json::from_str(&input).unwrap();
        assert_eq!(json["file_path"], "/tmp/manual.pdf");
        assert!(json.get("pages").is_none());
    }

    #[test]
    fn read_tool_string_offset_and_limit_arguments_are_converted() {
        let out = run(&[
            r#"{"type":"response.created","response":{"model":"gpt-5.5"}}"#,
            r#"{"type":"response.output_item.added","output_index":0,"item":{"id":"fc_read","type":"function_call","call_id":"call_read","name":"Read","arguments":""}}"#,
            r#"{"type":"response.function_call_arguments.delta","item_id":"fc_read","output_index":0,"delta":"{\"file_path\":\"/tmp/SKILL.md\",\"offset\":\" +0 \",\"limit\":\"2000\"}"}"#,
            r#"{"type":"response.output_item.done","output_index":0,"item":{"id":"fc_read","type":"function_call","call_id":"call_read","name":"Read","arguments":"{\"file_path\":\"/tmp/SKILL.md\",\"offset\":\" +0 \",\"limit\":\"2000\"}"}}"#,
            r#"{"type":"response.completed","response":{"status":"completed"}}"#,
        ]);

        let input = collected_tool_input(&out);
        let json: serde_json::Value = serde_json::from_str(&input).unwrap();
        assert_eq!(json["file_path"], "/tmp/SKILL.md");
        assert_eq!(json["offset"], 0);
        assert_eq!(json["limit"], 2000);
    }

    #[test]
    fn read_tool_invalid_offset_and_limit_arguments_are_stripped() {
        let out = run(&[
            r#"{"type":"response.created","response":{"model":"gpt-5.5"}}"#,
            r#"{"type":"response.output_item.added","output_index":0,"item":{"id":"fc_read","type":"function_call","call_id":"call_read","name":"Read","arguments":""}}"#,
            r#"{"type":"response.function_call_arguments.delta","item_id":"fc_read","output_index":0,"delta":"{\"file_path\":\"/tmp/SKILL.md\",\"offset\":-1,\"limit\":\"0\"}"}"#,
            r#"{"type":"response.output_item.done","output_index":0,"item":{"id":"fc_read","type":"function_call","call_id":"call_read","name":"Read","arguments":"{\"file_path\":\"/tmp/SKILL.md\",\"offset\":-1,\"limit\":\"0\"}"}}"#,
            r#"{"type":"response.completed","response":{"status":"completed"}}"#,
        ]);

        let input = collected_tool_input(&out);
        let json: serde_json::Value = serde_json::from_str(&input).unwrap();
        assert_eq!(json["file_path"], "/tmp/SKILL.md");
        assert!(json.get("offset").is_none());
        assert!(json.get("limit").is_none());
    }

    #[test]
    fn unknown_json_events_are_ignored() {
        let out = run(&[
            r#"{"type":"response.in_progress"}"#,
            r#"{"type":"response.output_item.added","item":{"type":"message"}}"#,
        ]);
        assert!(out.is_empty());
    }

    #[test]
    fn malformed_response_event_returns_error() {
        let mut state = StreamTransformState::default();
        let err = transform("not json", "msg_test", "gpt-5.5", &mut state).unwrap_err();
        let message = err.to_string();

        assert!(message.contains("malformed JSON SSE payload"));
        assert!(message.contains("8 bytes"));
    }
}

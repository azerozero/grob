//! Parsing of OpenAI Responses API / ChatGPT Codex SSE streams into canonical
//! content blocks, usage and stop reason.

use super::*;

/// Parse SSE response from ChatGPT Codex and extract content blocks.
///
/// The ChatGPT backend (`backend-api/codex`) delivers each finished block in a
/// `response.output_item.done` event and leaves `response.completed.output`
/// empty, whereas the standard Responses API populates `output[]` in the
/// `response.completed` event. Both layouts are handled: per-item events win,
/// with the completed-event output as a fallback.
#[derive(Debug)]
pub(crate) struct ParsedSseResponse {
    pub content: Vec<ContentBlock>,
    pub usage: Usage,
    pub stop_reason: Option<String>,
}

pub(crate) fn parse_sse_response(sse_text: &str) -> Result<ParsedSseResponse, ProviderError> {
    let mut item_blocks: Vec<ContentBlock> = Vec::new();
    let mut completed_blocks: Vec<ContentBlock> = Vec::new();
    let mut delta_text: BTreeMap<u64, String> = BTreeMap::new();
    let mut delta_reasoning: BTreeMap<u64, String> = BTreeMap::new();
    let mut pending_calls: BTreeMap<u64, PendingResponsesFunctionCall> = BTreeMap::new();
    let mut item_indexes: HashMap<String, u64> = HashMap::new();
    let mut stop_reason = Some("end_turn".to_string());
    let mut usage = Usage {
        input_tokens: 0,
        output_tokens: 0,
        cache_creation_input_tokens: None,
        cache_read_input_tokens: None,
    };
    let mut saw_terminal_event = false;

    for sse_event in parse_sse_events(sse_text) {
        let data = sse_event.data.trim();
        if data.is_empty() || data == "[DONE]" {
            continue;
        };
        let json = parse_responses_sse_json(data)?;
        let event_type = sse_event
            .event
            .as_deref()
            .or_else(|| json.get("type").and_then(|v| v.as_str()))
            .unwrap_or_default();

        match event_type {
            ty if ty.ends_with("output_text.delta") => {
                if let Some(delta) = json.get("delta").and_then(|v| v.as_str()) {
                    let output_index = json
                        .get("output_index")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    delta_text.entry(output_index).or_default().push_str(delta);
                }
            }
            ty if ty.contains("reasoning") && ty.ends_with(".delta") => {
                if let Some(delta) = json.get("delta").and_then(|v| v.as_str()) {
                    let output_index = json
                        .get("output_index")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    delta_reasoning
                        .entry(output_index)
                        .or_default()
                        .push_str(delta);
                }
            }
            "response.output_item.added" => {
                if let Some(item) = json.get("item") {
                    record_pending_responses_function_call(
                        &json,
                        item,
                        &mut pending_calls,
                        &mut item_indexes,
                    );
                }
            }
            ty if ty.ends_with("function_call_arguments.delta") => {
                if let Some(delta) = json.get("delta").and_then(|v| v.as_str()) {
                    if let Some(output_index) =
                        resolve_pending_call_output_index(&json, &pending_calls, &item_indexes)
                    {
                        pending_calls
                            .entry(output_index)
                            .or_default()
                            .arguments
                            .push_str(delta);
                    }
                }
            }
            "response.output_item.done" => {
                if let Some(item) = json.get("item") {
                    if let Some(block) = extract_codex_output_block(item)? {
                        item_blocks.push(block);
                    }
                }
            }
            "response.completed" => {
                saw_terminal_event = true;
                if let Some(response_usage) = json.get("response").and_then(|r| r.get("usage")) {
                    usage = parse_responses_usage(response_usage);
                }
                if let Some(output) = json
                    .get("response")
                    .and_then(|r| r.get("output"))
                    .and_then(|v| v.as_array())
                {
                    for item in output {
                        if let Some(block) = extract_codex_output_block(item)? {
                            completed_blocks.push(block);
                        }
                    }
                }
            }
            "response.incomplete" => {
                saw_terminal_event = true;
                stop_reason = Some("max_tokens".to_string());
                if let Some(response_usage) = json.get("response").and_then(|r| r.get("usage")) {
                    usage = parse_responses_usage(response_usage);
                }
            }
            "response.failed" => {
                let message = format!(
                    "OpenAI Responses API returned response.failed: {}",
                    responses_error_message(&json)
                );
                if is_context_window_exceeded_message(&message) {
                    return Err(ProviderError::InvalidRequest(message));
                }
                return Err(ProviderError::ProtocolError(message));
            }
            _ => {}
        }
    }

    let delta_blocks = build_delta_content_blocks(&delta_text, &delta_reasoning, &pending_calls)?;

    let content_blocks = if item_blocks.is_empty() {
        if completed_blocks.is_empty() {
            delta_blocks
        } else {
            completed_blocks
        }
    } else {
        item_blocks
    };

    if !content_blocks.is_empty() {
        return Ok(ParsedSseResponse {
            content: content_blocks,
            usage,
            stop_reason,
        });
    }

    let terminal_hint = if saw_terminal_event {
        " after terminal Responses event"
    } else {
        ""
    };
    Err(ProviderError::ProtocolError(format!(
        "Failed to parse SSE response: no content found{terminal_hint}"
    )))
}

#[derive(Debug, Default)]
struct PendingResponsesFunctionCall {
    call_id: Option<String>,
    name: Option<String>,
    arguments: String,
}

fn parse_responses_sse_json(data: &str) -> Result<serde_json::Value, ProviderError> {
    serde_json::from_str(data).map_err(|e| {
        ProviderError::ProtocolError(format!(
            "OpenAI Responses API emitted malformed SSE JSON payload ({} bytes): {}",
            data.len(),
            e
        ))
    })
}

fn responses_error_message(json: &serde_json::Value) -> String {
    json.pointer("/response/error/message")
        .or_else(|| json.pointer("/error/message"))
        .or_else(|| json.get("detail"))
        .and_then(|v| v.as_str())
        .unwrap_or("Responses API request failed")
        .to_string()
}

fn record_pending_responses_function_call(
    json: &serde_json::Value,
    item: &serde_json::Value,
    pending_calls: &mut BTreeMap<u64, PendingResponsesFunctionCall>,
    item_indexes: &mut HashMap<String, u64>,
) {
    if item.get("type").and_then(|v| v.as_str()) != Some("function_call") {
        return;
    }

    let output_index = json
        .get("output_index")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let pending = pending_calls.entry(output_index).or_default();
    pending.call_id = item
        .get("call_id")
        .or_else(|| item.get("id"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .or_else(|| pending.call_id.take());
    pending.name = item
        .get("name")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .or_else(|| pending.name.take());
    if let Some(arguments) = item.get("arguments").and_then(|v| v.as_str()) {
        pending.arguments.push_str(arguments);
    }

    for id in [
        item.get("id").and_then(|v| v.as_str()),
        item.get("call_id").and_then(|v| v.as_str()),
    ]
    .into_iter()
    .flatten()
    {
        item_indexes.insert(id.to_string(), output_index);
    }
}

fn resolve_pending_call_output_index(
    json: &serde_json::Value,
    pending_calls: &BTreeMap<u64, PendingResponsesFunctionCall>,
    item_indexes: &HashMap<String, u64>,
) -> Option<u64> {
    if let Some(output_index) = json.get("output_index").and_then(|v| v.as_u64()) {
        return Some(output_index);
    }
    if let Some(output_index) = json
        .get("item_id")
        .and_then(|v| v.as_str())
        .and_then(|id| item_indexes.get(id))
        .copied()
    {
        return Some(output_index);
    }
    if pending_calls.len() == 1 {
        return pending_calls.keys().next().copied();
    }
    None
}

fn build_delta_content_blocks(
    delta_text: &BTreeMap<u64, String>,
    delta_reasoning: &BTreeMap<u64, String>,
    pending_calls: &BTreeMap<u64, PendingResponsesFunctionCall>,
) -> Result<Vec<ContentBlock>, ProviderError> {
    let mut output_indexes = BTreeMap::new();
    for output_index in delta_text.keys() {
        output_indexes.insert(*output_index, ());
    }
    for output_index in delta_reasoning.keys() {
        output_indexes.insert(*output_index, ());
    }
    for output_index in pending_calls.keys() {
        output_indexes.insert(*output_index, ());
    }

    let mut blocks = Vec::new();
    for output_index in output_indexes.keys() {
        if let Some(reasoning) = delta_reasoning.get(output_index) {
            if !reasoning.is_empty() {
                blocks.push(ContentBlock::thinking(serde_json::json!({
                    "thinking": reasoning
                })));
            }
        }
        if let Some(text) = delta_text.get(output_index) {
            if !text.is_empty() {
                blocks.push(ContentBlock::text(text.clone(), None));
            }
        }
        if let Some(call) = pending_calls.get(output_index) {
            if let (Some(call_id), Some(name)) = (&call.call_id, &call.name) {
                let input = parse_responses_tool_arguments(name, &call.arguments)?;
                blocks.push(ContentBlock::tool_use(call_id.clone(), name.clone(), input));
            }
        }
    }

    Ok(blocks)
}

fn parse_responses_usage(usage: &serde_json::Value) -> Usage {
    let input_tokens = usage
        .get("input_tokens")
        .and_then(serde_json::Value::as_u64)
        .map(|v| u32::try_from(v).unwrap_or(u32::MAX))
        .unwrap_or(0);
    let output_tokens = usage
        .get("output_tokens")
        .and_then(serde_json::Value::as_u64)
        .map(|v| u32::try_from(v).unwrap_or(u32::MAX))
        .unwrap_or(0);
    let cached_tokens = usage
        .pointer("/input_tokens_details/cached_tokens")
        .or_else(|| usage.pointer("/prompt_tokens_details/cached_tokens"))
        .and_then(serde_json::Value::as_u64)
        .map(|v| u32::try_from(v).unwrap_or(u32::MAX))
        .unwrap_or(0);

    Usage {
        input_tokens: input_tokens.saturating_sub(cached_tokens),
        output_tokens,
        cache_creation_input_tokens: None,
        cache_read_input_tokens: (cached_tokens > 0).then_some(cached_tokens),
    }
}

/// Maps a Codex `output[]` item to the corresponding Anthropic content block.
///
/// Handles `function_call` (→ `tool_use`), `reasoning` (→ `thinking`), and
/// `message` (→ `text`) items; anything else yields `None`.
fn extract_codex_output_block(
    item: &serde_json::Value,
) -> Result<Option<ContentBlock>, ProviderError> {
    let Some(output_type) = item.get("type").and_then(|v| v.as_str()) else {
        return Ok(None);
    };

    if output_type == "function_call" {
        let Some(name) = item.get("name").and_then(|v| v.as_str()) else {
            return Ok(None);
        };
        let Some(call_id) = item
            .get("call_id")
            .or_else(|| item.get("id"))
            .and_then(|v| v.as_str())
        else {
            return Ok(None);
        };
        let arguments = item
            .get("arguments")
            .and_then(|v| v.as_str())
            .unwrap_or("{}");
        let input = parse_responses_tool_arguments(name, arguments)?;
        return Ok(Some(ContentBlock::tool_use(
            call_id.to_string(),
            name.to_string(),
            input,
        )));
    }

    // `message` items carry text under `content[]`; `reasoning` items carry it
    // under `summary[]`. Accept whichever is present.
    let Some(text) = item
        .get("content")
        .or_else(|| item.get("summary"))
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|first| first.get("text"))
        .and_then(|v| v.as_str())
    else {
        return Ok(None);
    };

    Ok(match output_type {
        "reasoning" => Some(ContentBlock::thinking(serde_json::json!({
            "thinking": text
        }))),
        "message" => Some(ContentBlock::text(text.to_string(), None)),
        _ => None,
    })
}

fn parse_responses_tool_arguments(
    tool_name: &str,
    arguments: &str,
) -> Result<serde_json::Value, ProviderError> {
    if arguments.trim().is_empty() {
        return Ok(serde_json::json!({}));
    }
    let sanitized =
        crate::providers::openai::streaming::sanitize_tool_input_delta(tool_name, arguments);
    parse_provider_tool_arguments("Responses", tool_name, sanitized.as_ref())
}

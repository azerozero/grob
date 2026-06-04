use super::types::*;
use crate::models::{CanonicalRequest, MessageContent};
use crate::providers::error::ProviderError;
use crate::providers::{CodexOptions, ContentBlock, KnownContentBlock, ProviderResponse, Usage};
use serde::Serialize;
use thiserror::Error;

/// Errors raised while translating a [`CanonicalRequest`] into OpenAI wire format.
///
/// These map to user-visible 4xx responses since the offending data is
/// always client-supplied (e.g. malformed tool-use input). The provider layer
/// converts them to [`ProviderError::SerializationError`] for the existing
/// error pipeline.
#[derive(Debug, Error)]
pub(crate) enum TransformError {
    /// Failed to serialize a `tool_use` block's `input` field as JSON.
    ///
    /// OpenAI requires tool arguments as a JSON-encoded string; if the canonical
    /// `Value` (or wrapped `Serialize` payload) cannot round-trip through
    /// `serde_json::to_string`, surface the error rather than sending an empty
    /// string upstream — empty arguments either parse-error in OpenAI or cause
    /// the model to invoke the tool with no input, both of which were
    /// previously silent.
    #[error("failed to serialize tool_use input for tool '{tool_name}': {source}")]
    ToolInputSerialization {
        /// Name of the tool whose input failed to serialize.
        tool_name: String,
        /// Underlying serde_json error.
        #[source]
        source: serde_json::Error,
    },
}

impl From<TransformError> for ProviderError {
    fn from(err: TransformError) -> Self {
        match err {
            TransformError::ToolInputSerialization { source, .. } => {
                ProviderError::SerializationError(source)
            }
        }
    }
}

/// Serializes a tool-use input value as a JSON string, attaching the tool name on failure.
///
/// # Errors
///
/// Returns [`TransformError::ToolInputSerialization`] if the value cannot be
/// encoded as JSON.
pub(crate) fn serialize_tool_input<T: Serialize>(
    input: &T,
    tool_name: &str,
) -> Result<String, TransformError> {
    serde_json::to_string(input).map_err(|source| TransformError::ToolInputSerialization {
        tool_name: tool_name.to_string(),
        source,
    })
}

/// Transform Anthropic request format to OpenAI Chat Completions format.
///
/// Handles structural differences between the two APIs:
/// - `tool_use` blocks → `tool_calls` array on assistant messages
/// - `tool_result` blocks → separate `tool` role messages
/// - `image` blocks → `image_url` content parts with data URI encoding
/// - `thinking` blocks → dropped (OpenAI doesn't support this)
/// - System role: hoisted to the top-level `system` message exactly once,
///   even if the canonical `messages` array also contains a system entry.
///
/// # Errors
///
/// Returns [`TransformError::ToolInputSerialization`] if a `tool_use`
/// block's `input` cannot be serialized as JSON.
pub(crate) fn transform_request(
    request: &CanonicalRequest,
) -> Result<OpenAIRequest, TransformError> {
    let mut openai_messages = Vec::new();

    // Add system message if present
    if let Some(ref system) = request.system {
        let system_text = system.to_text();
        openai_messages.push(OpenAIMessage {
            role: "system".to_string(),
            content: Some(OpenAIContent::String(system_text)),
            name: request.extensions.openai_system_name.clone(),
            reasoning: None,
            tool_calls: None,
            tool_call_id: None,
        });
    }

    // Transform messages.
    //
    // NOTE: A canonical `system` was already hoisted to the top-level OpenAI
    // `system` message above. Drop any residual system-role entries from the
    // messages array to prevent duplicate system messages in the OpenAI
    // payload (audit Bug #3 — clients may send `[user, system, assistant]`
    // and grob previously emitted two `role:"system"` messages).
    for (message_index, msg) in request.messages.iter().enumerate() {
        if msg.role == "system" {
            tracing::debug!(
                "Dropping system-role message from canonical messages array (already hoisted to top-level system)"
            );
            continue;
        }
        match &msg.content {
            MessageContent::Text(text) => {
                openai_messages.push(OpenAIMessage {
                    role: msg.role.clone(),
                    content: Some(OpenAIContent::String(text.clone())),
                    name: request
                        .extensions
                        .openai_message_names
                        .get(message_index)
                        .cloned()
                        .flatten(),
                    reasoning: None,
                    tool_calls: None,
                    tool_call_id: None,
                });
            }
            MessageContent::Blocks(blocks) => {
                let name = request
                    .extensions
                    .openai_message_names
                    .get(message_index)
                    .cloned()
                    .flatten();
                transform_block_message(&msg.role, name, blocks, &mut openai_messages)?;
            }
        }
    }

    // Invariant: at most one system message (the hoisted one at index 0)
    // remains in the OpenAI payload.
    debug_assert!(
        openai_messages
            .iter()
            .filter(|m| m.role == "system")
            .count()
            <= 1,
        "system role leaked into OpenAI messages array more than once"
    );

    // Transform tools if present
    let tools = transform_tools(request);

    // Request usage data in streaming responses
    let stream_options = if request.stream == Some(true) {
        Some(OpenAIStreamOptions {
            include_usage: true,
        })
    } else {
        None
    };

    let ext = &request.extensions;

    Ok(OpenAIRequest {
        model: request.model.clone(),
        messages: openai_messages,
        max_tokens: Some(request.max_tokens),
        temperature: request.temperature,
        top_p: request.top_p,
        stop: request.stop_sequences.clone(),
        stream: request.stream,
        stream_options,
        tools,
        tool_choice: transform_tool_choice(request),
        // Restore provider-specific fields from extensions
        response_format: ext.response_format.clone(),
        reasoning_effort: ext.reasoning_effort.clone(),
        seed: ext.seed,
        frequency_penalty: ext.frequency_penalty,
        presence_penalty: ext.presence_penalty,
        parallel_tool_calls: ext.parallel_tool_calls,
        user: ext.user.clone(),
        logprobs: ext.logprobs,
        top_logprobs: ext.top_logprobs,
        service_tier: ext.service_tier.clone(),
    })
}

/// Transform a message with content blocks into OpenAI messages.
fn transform_block_message(
    role: &str,
    name: Option<String>,
    blocks: &[ContentBlock],
    openai_messages: &mut Vec<OpenAIMessage>,
) -> Result<(), TransformError> {
    let tool_results = extract_tool_results(blocks);
    let tool_calls = extract_tool_calls(blocks)?;
    let content_parts = extract_content_parts(blocks);

    // Add separate tool result messages FIRST (OpenAI requires this ordering)
    for (tool_use_id, result_content) in tool_results {
        openai_messages.push(OpenAIMessage {
            role: "tool".to_string(),
            content: Some(OpenAIContent::String(result_content)),
            name: None,
            reasoning: None,
            tool_calls: None,
            tool_call_id: Some(tool_use_id),
        });
    }

    // Then add main message with content and/or tool_calls
    if !content_parts.is_empty() || !tool_calls.is_empty() {
        let content = if content_parts.is_empty() {
            None
        } else if content_parts.len() == 1 {
            if let OpenAIContentPart::Text { text } = &content_parts[0] {
                Some(OpenAIContent::String(text.clone()))
            } else {
                Some(OpenAIContent::Parts(content_parts.clone()))
            }
        } else {
            Some(OpenAIContent::Parts(content_parts))
        };

        openai_messages.push(OpenAIMessage {
            role: role.to_string(),
            content,
            name,
            reasoning: None,
            tool_calls: if tool_calls.is_empty() {
                None
            } else {
                Some(tool_calls)
            },
            tool_call_id: None,
        });
    }
    Ok(())
}

/// Extract tool_result blocks as (tool_use_id, content) pairs.
fn extract_tool_results(blocks: &[ContentBlock]) -> Vec<(String, String)> {
    blocks
        .iter()
        .filter_map(|block| {
            if let ContentBlock::Known(KnownContentBlock::ToolResult {
                tool_use_id,
                content,
                is_error,
                ..
            }) = block
            {
                let result_content = if *is_error {
                    tracing::debug!(
                        "Tool result is_error=true for {}, prefixing content",
                        tool_use_id
                    );
                    format!("[SYSTEM: Tools are disabled during warmup. Do NOT call any tools. Wait for the next user message before attempting any tool use.]\n{content}")
                } else {
                    content.to_string()
                };
                Some((tool_use_id.clone(), result_content))
            } else {
                None
            }
        })
        .collect()
}

/// Filters Anthropic `tool_use` content blocks and reshapes them as OpenAI `tool_calls` entries with JSON-stringified arguments.
///
/// # Errors
///
/// Returns [`TransformError::ToolInputSerialization`] if any tool's `input`
/// fails JSON serialization. Previously substituted an empty string, which
/// caused either an OpenAI parse error or a tool invocation with no
/// arguments — both silent.
fn extract_tool_calls(blocks: &[ContentBlock]) -> Result<Vec<OpenAIToolCall>, TransformError> {
    let mut calls = Vec::new();
    for block in blocks {
        if let ContentBlock::Known(KnownContentBlock::ToolUse { id, name, input }) = block {
            let arguments = serialize_tool_input(input, name)?;
            calls.push(OpenAIToolCall {
                id: id.clone(),
                r#type: "function".to_string(),
                function: OpenAIFunctionCall {
                    name: name.clone(),
                    arguments,
                },
            });
        }
    }
    Ok(calls)
}

/// Extract text and image content parts (excluding tool blocks and thinking).
fn extract_content_parts(blocks: &[ContentBlock]) -> Vec<OpenAIContentPart> {
    let mut parts = Vec::new();
    for block in blocks {
        match block {
            ContentBlock::Known(KnownContentBlock::Text { text, .. }) => {
                parts.push(OpenAIContentPart::Text { text: text.clone() });
            }
            ContentBlock::Known(KnownContentBlock::Image { source }) => {
                let url = if source.r#type == "base64" {
                    let media_type = source.media_type.as_deref().unwrap_or("image/png");
                    let data = source.data.as_deref().unwrap_or("");
                    format!("data:{};base64,{}", media_type, data)
                } else if let Some(url) = &source.url {
                    url.clone()
                } else {
                    continue;
                };
                parts.push(OpenAIContentPart::ImageUrl {
                    image_url: OpenAIImageUrl { url },
                });
            }
            // ToolUse, ToolResult, Thinking, Unknown — handled elsewhere or skipped
            _ => {}
        }
    }
    parts
}

/// Transform Anthropic tool definitions to OpenAI format.
fn transform_tools(request: &CanonicalRequest) -> Option<Vec<OpenAITool>> {
    request.tools.as_ref().map(|anthropic_tools| {
        anthropic_tools
            .iter()
            .filter_map(|tool| {
                Some(OpenAITool {
                    r#type: "function".to_string(),
                    function: OpenAIFunctionDef {
                        name: tool.name.as_ref()?.clone(),
                        description: tool.description.clone(),
                        parameters: tool.input_schema.clone(),
                    },
                })
            })
            .collect()
    })
}

/// Transform Anthropic tool_choice to OpenAI format.
fn transform_tool_choice(request: &CanonicalRequest) -> Option<serde_json::Value> {
    request.tool_choice.as_ref().and_then(|tc| {
        let tc_type = tc.get("type").and_then(|v| v.as_str()).unwrap_or("");
        match tc_type {
            "auto" => Some(serde_json::json!("auto")),
            "any" => Some(serde_json::json!("required")),
            "tool" => {
                let name = tc.get("name").and_then(|v| v.as_str()).unwrap_or("");
                Some(serde_json::json!({
                    "type": "function",
                    "function": { "name": name }
                }))
            }
            _ => None,
        }
    })
}

/// Transform OpenAI Chat Completions response to Anthropic Messages format.
pub(crate) fn transform_response(response: OpenAIResponse) -> ProviderResponse {
    let choice = match response.choices.into_iter().next() {
        Some(c) => c,
        None => {
            return ProviderResponse {
                id: response.id,
                r#type: "message".to_string(),
                role: "assistant".to_string(),
                content: vec![],
                model: response.model,
                stop_reason: Some("error".to_string()),
                stop_sequence: None,
                usage: Usage {
                    input_tokens: 0,
                    output_tokens: 0,
                    cache_creation_input_tokens: None,
                    cache_read_input_tokens: None,
                },
            };
        }
    };

    let mut content_blocks = Vec::new();
    let mut salvaged_tool_count = 0u32;

    // Add reasoning as thinking block
    if let Some(reasoning) = choice.message.reasoning {
        if !reasoning.is_empty() {
            content_blocks.push(ContentBlock::thinking(serde_json::json!({
                "thinking": reasoning
            })));
        }
    }

    // Extract text content
    let text = match choice.message.content {
        Some(OpenAIContent::String(s)) => s,
        Some(OpenAIContent::Parts(parts)) => parts
            .iter()
            .filter_map(|part| {
                if let OpenAIContentPart::Text { text } = part {
                    Some(text.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
        None => String::new(),
    };

    // Scan the text for tool calls the model leaked as plain content (Codex
    // sometimes does this) and re-emit them as structured tool_use blocks.
    let mut salvaged_tool = false;
    if !text.is_empty() {
        for event in super::tool_salvage::salvage_complete(&text) {
            match event {
                super::tool_salvage::SalvageEvent::Text(t) => {
                    if !t.is_empty() {
                        content_blocks.push(ContentBlock::text(t, None));
                    }
                }
                super::tool_salvage::SalvageEvent::ToolCall(call) => {
                    salvaged_tool = true;
                    salvaged_tool_count += 1;
                    content_blocks.push(ContentBlock::tool_use(
                        format!("toolu_salvaged_{salvaged_tool_count}"),
                        call.name,
                        call.input,
                    ));
                }
            }
        }
    }

    // Transform tool_calls to tool_use content blocks
    if let Some(tool_calls) = choice.message.tool_calls {
        for tool_call in tool_calls {
            let input = serde_json::from_str(&tool_call.function.arguments)
                .unwrap_or(serde_json::json!({}));
            content_blocks.push(ContentBlock::tool_use(
                tool_call.id,
                tool_call.function.name,
                input,
            ));
        }
    }

    // Map OpenAI finish_reason to Anthropic stop_reason. A salvaged tool call
    // overrides a plain "stop" so the client runs the recovered tool.
    let stop_reason = choice.finish_reason.map(|reason| match reason.as_str() {
        "stop" if salvaged_tool => "tool_use".to_string(),
        "stop" => "end_turn".to_string(),
        "length" => "max_tokens".to_string(),
        "tool_calls" => "tool_use".to_string(),
        _ => "end_turn".to_string(),
    });

    ProviderResponse {
        id: response.id,
        r#type: "message".to_string(),
        role: "assistant".to_string(),
        content: content_blocks,
        model: response.model,
        stop_reason,
        stop_sequence: None,
        usage: Usage {
            input_tokens: response.usage.prompt_tokens,
            output_tokens: response.usage.completion_tokens,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
    }
}

/// Parse SSE response from ChatGPT Codex and extract content blocks.
///
/// The ChatGPT backend (`backend-api/codex`) delivers each finished block in a
/// `response.output_item.done` event and leaves `response.completed.output`
/// empty, whereas the standard Responses API populates `output[]` in the
/// `response.completed` event. Both layouts are handled: per-item events win,
/// with the completed-event output as a fallback.
pub(crate) fn parse_sse_response(sse_text: &str) -> Result<Vec<ContentBlock>, ProviderError> {
    let lines: Vec<&str> = sse_text.lines().collect();

    let mut item_blocks: Vec<ContentBlock> = Vec::new();
    let mut completed_blocks: Vec<ContentBlock> = Vec::new();

    for (i, line) in lines.iter().enumerate() {
        let Some(event) = line.strip_prefix("event: ").map(str::trim) else {
            continue;
        };
        if event != "response.output_item.done" && event != "response.completed" {
            continue;
        }

        // The SSE `data:` payload sits on the line immediately after `event:`.
        let Some(json_str) = lines.get(i + 1).and_then(|l| l.strip_prefix("data: ")) else {
            continue;
        };
        let Ok(json) = serde_json::from_str::<serde_json::Value>(json_str) else {
            continue;
        };

        match event {
            "response.output_item.done" => {
                if let Some(block) = json.get("item").and_then(extract_codex_output_block) {
                    item_blocks.push(block);
                }
            }
            "response.completed" => {
                if let Some(output) = json
                    .get("response")
                    .and_then(|r| r.get("output"))
                    .and_then(|v| v.as_array())
                {
                    completed_blocks.extend(output.iter().filter_map(extract_codex_output_block));
                }
            }
            _ => {}
        }
    }

    let content_blocks = if item_blocks.is_empty() {
        completed_blocks
    } else {
        item_blocks
    };

    if !content_blocks.is_empty() {
        return Ok(content_blocks);
    }

    Err(ProviderError::ApiError {
        status: 500,
        message: "Failed to parse SSE response: no content found".to_string(),
    })
}

/// Maps a Codex `output[]` item to the corresponding Anthropic content block.
///
/// Handles `function_call` (→ `tool_use`), `reasoning` (→ `thinking`), and
/// `message` (→ `text`) items; anything else yields `None`.
fn extract_codex_output_block(item: &serde_json::Value) -> Option<ContentBlock> {
    let output_type = item.get("type").and_then(|v| v.as_str())?;

    if output_type == "function_call" {
        let name = item.get("name").and_then(|v| v.as_str())?;
        let call_id = item
            .get("call_id")
            .or_else(|| item.get("id"))
            .and_then(|v| v.as_str())?;
        let input = item
            .get("arguments")
            .and_then(|v| v.as_str())
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_else(|| serde_json::json!({}));
        return Some(ContentBlock::tool_use(
            call_id.to_string(),
            name.to_string(),
            input,
        ));
    }

    // `message` items carry text under `content[]`; `reasoning` items carry it
    // under `summary[]`. Accept whichever is present.
    let text = item
        .get("content")
        .or_else(|| item.get("summary"))
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|first| first.get("text"))
        .and_then(|v| v.as_str())?;

    match output_type {
        "reasoning" => Some(ContentBlock::thinking(serde_json::json!({
            "thinking": text
        }))),
        "message" => Some(ContentBlock::text(text.to_string(), None)),
        _ => None,
    }
}

/// Instructions used when the client forwards its own tools.
///
/// The full Codex CLI prompt describes built-in `shell`/`apply_patch`/`update_plan`
/// tools that do not exist when a client like Claude Code provides its own tool
/// set — that mismatch makes the model invent tool calls (often leaked as text).
/// This minimal preamble keeps the backend-expected "Codex" identity but defers
/// all tool behavior to the request's tools and the client's own system prompt.
const CODEX_TOOL_INSTRUCTIONS: &str = "You are Codex, based on GPT-5, operating as a coding agent. \
The harness provides its own system prompt and a set of tools in this request. Use ONLY those \
provided tools through the function-calling interface to take actions — do not assume any built-in \
`shell`, `apply_patch`, or `update_plan` tool exists, and never emit a tool call as plain text or \
inside a code block. When you need to run a command, read, or edit, call the matching provided tool \
with its required arguments. Omit optional arguments that are unset; never send an empty string as a \
placeholder for a missing optional argument.";

/// Per-call knobs for the Codex (OpenAI Responses API) transform.
///
/// Bundles the operator-forced overrides with the provider's [`CodexOptions`]
/// so the resolver functions stay parameterised instead of reaching for global
/// state. Build it with [`CodexTuning::from_options`].
#[derive(Clone, Copy)]
pub(crate) struct CodexTuning<'a> {
    /// Operator-forced reasoning effort (highest precedence). `None` = auto.
    pub forced_effort: Option<&'a str>,
    /// Operator-forced service tier (e.g. `"priority"`). `None` = request/none.
    pub forced_service_tier: Option<&'a str>,
    /// Models eligible for the `priority` tier and default `xhigh` effort.
    pub priority_models: &'a [String],
    /// When `true`, map the extended-thinking budget → effort (opt-in).
    pub reasoning_auto_map: bool,
    /// Thinking budget at/above which auto-map selects `xhigh` (else `medium`).
    pub reasoning_xhigh_min_budget: u32,
}

impl<'a> CodexTuning<'a> {
    /// Borrows a provider's [`CodexOptions`] alongside any forced overrides.
    pub(crate) fn from_options(
        opts: &'a CodexOptions,
        forced_effort: Option<&'a str>,
        forced_service_tier: Option<&'a str>,
    ) -> Self {
        Self {
            forced_effort,
            forced_service_tier,
            priority_models: &opts.priority_models,
            reasoning_auto_map: opts.reasoning_auto_map,
            reasoning_xhigh_min_budget: opts.reasoning_xhigh_min_budget,
        }
    }
}

/// Transform Anthropic request to OpenAI Responses API format.
pub(crate) fn transform_to_responses_request(
    request: &CanonicalRequest,
    codex_instructions: &str,
    tuning: &CodexTuning<'_>,
) -> Result<OpenAIResponsesRequest, ProviderError> {
    let tools = transform_responses_tools(request);

    // Codex CLI requests carry their own authoritative Codex agent prompt as
    // `instructions` (canonical `system`). Forward it verbatim as the
    // top-level `instructions` so the backend stays in full agentic mode.
    // Demoting it to a user item (the foreign-client path) makes the model emit
    // a preamble and stop instead of calling the provided tools.
    let codex_native = request.extensions.codex_native;

    let instructions = if codex_native {
        request
            .system
            .as_ref()
            .map(|s| s.to_text())
            .unwrap_or_else(|| codex_instructions.to_string())
    } else if tools.is_some() {
        // Forwarding tools and the full Codex CLI prompt at once makes a foreign
        // client's model call non-existent built-in tools, so defer to a preamble.
        CODEX_TOOL_INSTRUCTIONS.to_string()
    } else {
        codex_instructions.to_string()
    };

    let mut items = Vec::new();

    // Codex has no separate system role; hoist the system prompt to a user item.
    // Skip on the codex-native path: the system is already the top-level
    // `instructions` above, so re-adding it here would duplicate it.
    if !codex_native {
        if let Some(ref system) = request.system {
            items.push(OpenAIResponsesItem::Message {
                role: "user".to_string(),
                content: Some(system.to_text()),
            });
        }
    }

    for msg in &request.messages {
        // The ChatGPT Codex backend rejects `system`-role items ("System messages
        // are not allowed") — system guidance belongs in `instructions`. Fold any
        // system-role message (e.g. Claude Code `<system-reminder>` turns) into a
        // user item so its content survives.
        let role = if msg.role == "system" {
            "user"
        } else {
            msg.role.as_str()
        };
        match &msg.content {
            MessageContent::Text(text) => items.push(OpenAIResponsesItem::Message {
                role: role.to_string(),
                content: Some(text.clone()),
            }),
            MessageContent::Blocks(blocks) => {
                push_blocks_as_items(&mut items, role, blocks)?;
            }
        }
    }

    Ok(OpenAIResponsesRequest {
        model: request.model.clone(),
        input: OpenAIResponsesInput::Items(items),
        instructions,
        // The ChatGPT Codex backend REQUIRES store=false (returns 400 "Store must
        // be set to false" otherwise), so this is fixed for every path.
        store: false,
        stream: true,
        tool_choice: tools.as_ref().and(transform_responses_tool_choice(request)),
        parallel_tool_calls: tools.as_ref().map(|_| true),
        tools,
        reasoning: resolve_reasoning_effort(request, tuning)
            .map(|effort| serde_json::json!({ "effort": effort })),
        service_tier: resolve_service_tier(request, tuning),
    })
}

/// Resolves the Codex `service_tier` (processing speed) for a request.
///
/// A provider-config value wins, then a `service_tier` request extension. The
/// value passes through verbatim — the backend validates it — so `"priority"`
/// (faster handling) works without a whitelist. `None` leaves the field unset.
fn resolve_service_tier(request: &CanonicalRequest, tuning: &CodexTuning<'_>) -> Option<String> {
    let tier = tuning
        .forced_service_tier
        .map(str::to_string)
        .or_else(|| request.extensions.service_tier.clone())
        .filter(|s| !s.is_empty())?;
    // The "priority" (1.5x) tier exists only on some models (by default gpt-5.5
    // and gpt-5.4 — see `CodexOptions::priority_models`); others reject it with a
    // 400. Drop it for unsupported models so a provider forcing
    // `service_tier = "priority"` does not break `think`/`background` routes
    // (which resolve to codex/mini models). Other tiers pass through.
    if tier == "priority" && !priority_tier_supported(&request.model, tuning.priority_models) {
        return None;
    }
    Some(tier)
}

/// Returns whether the model offers the Codex `priority` (1.5x) service tier.
///
/// The eligible set is configurable via [`CodexOptions::priority_models`]
/// (default `["gpt-5.5", "gpt-5.4"]`). An entry matches the model by exact name
/// or as a prefix; a prefix match excludes `-mini` fast-tier variants unless the
/// model is listed verbatim. The same set also gates the default `xhigh` effort.
fn priority_tier_supported(model: &str, priority_models: &[String]) -> bool {
    let m = model.to_ascii_lowercase();
    priority_models.iter().any(|entry| {
        let p = entry.to_ascii_lowercase();
        m == p || (m.starts_with(&p) && !m.contains("mini"))
    })
}

/// Resolves the Codex reasoning effort for a request.
///
/// Precedence:
/// 1. A provider-config `forced_effort` or an explicit `reasoning_effort`
///    request extension (e.g. from a Codex CLI client) — passed through verbatim
///    so newer tiers (e.g. `xhigh`) work without a grob release.
/// 2. If `reasoning_auto_map` is enabled, the effort auto-maps from the
///    request's extended-thinking budget (legacy behavior).
/// 3. Otherwise the flat default: `xhigh` for the priority/flagship models
///    (see [`priority_tier_supported`]), and `None` for the rest so the backend
///    applies its own default effort.
fn resolve_reasoning_effort(
    request: &CanonicalRequest,
    tuning: &CodexTuning<'_>,
) -> Option<String> {
    let supplied = tuning
        .forced_effort
        .map(str::to_string)
        .or_else(|| request.extensions.reasoning_effort.clone())
        .filter(|s| !s.is_empty());
    if let Some(effort) = supplied {
        return Some(effort);
    }
    if tuning.reasoning_auto_map {
        return Some(auto_map_thinking_effort(
            request,
            tuning.reasoning_xhigh_min_budget,
        ));
    }
    // Flat default: max out the flagship models, leave the rest to the backend.
    if priority_tier_supported(&request.model, tuning.priority_models) {
        Some("xhigh".to_string())
    } else {
        None
    }
}

/// Maps Anthropic extended-thinking config to a Codex reasoning-effort tier.
///
/// Only used in the opt-in `reasoning_auto_map` mode. No thinking (or an
/// explicitly `disabled` block) maps to `low` for snappy responses. Any other
/// thinking block means the client opted into extended reasoning, so it maps
/// high: Claude Code's adaptive mode (`type: "adaptive"`, no budget — the same
/// for every `think`/`think hard`/`ultrathink` keyword, so they cannot be told
/// apart) maps to `xhigh`, the backend's max tier; an explicit budget maps to
/// `xhigh` at/above `xhigh_min_budget`, else `medium`. Effort tiers:
/// `low` < `medium` < `high` < `xhigh` (`max` is rejected by the backend).
///
/// Note: Claude Code's `/effort` slider is client-internal and never reaches the
/// API, so it cannot be mapped here — only the thinking keywords, which set a
/// thinking block, do.
fn auto_map_thinking_effort(request: &CanonicalRequest, xhigh_min_budget: u32) -> String {
    let Some(thinking) = request.thinking.as_ref() else {
        return "low".to_string();
    };
    if thinking.r#type == "disabled" {
        return "low".to_string();
    }
    match thinking.budget_tokens {
        Some(budget) if budget >= xhigh_min_budget => "xhigh",
        Some(_) => "medium",
        // Adaptive thinking (no budget) is opt-in deep reasoning — give it the max.
        None => "xhigh",
    }
    .to_string()
}

/// Expands a message's content blocks into Responses items, preserving order.
///
/// Text and image blocks collapse into `message` items; `tool_use` blocks become
/// `function_call` items and `tool_result` blocks become `function_call_output`
/// items, keyed by the shared Anthropic tool-use id so the round-trip stays
/// correlated. Thinking blocks are dropped.
fn push_blocks_as_items(
    items: &mut Vec<OpenAIResponsesItem>,
    role: &str,
    blocks: &[ContentBlock],
) -> Result<(), ProviderError> {
    let mut text = String::new();

    for block in blocks {
        match block {
            ContentBlock::Known(KnownContentBlock::Text { text: t, .. }) => {
                if !text.is_empty() {
                    text.push('\n');
                }
                text.push_str(t);
            }
            ContentBlock::Known(KnownContentBlock::ToolUse { id, name, input }) => {
                flush_text_item(items, role, &mut text);
                let arguments = serialize_tool_input(input, name)?;
                items.push(OpenAIResponsesItem::FunctionCall {
                    call_id: id.clone(),
                    name: name.clone(),
                    arguments,
                });
            }
            ContentBlock::Known(KnownContentBlock::ToolResult {
                tool_use_id,
                content,
                ..
            }) => {
                flush_text_item(items, role, &mut text);
                items.push(OpenAIResponsesItem::FunctionCallOutput {
                    call_id: tool_use_id.clone(),
                    output: content.to_string(),
                });
            }
            _ => {}
        }
    }

    flush_text_item(items, role, &mut text);
    Ok(())
}

/// Pushes accumulated text as a `message` item and clears the buffer.
fn flush_text_item(items: &mut Vec<OpenAIResponsesItem>, role: &str, text: &mut String) {
    if !text.is_empty() {
        items.push(OpenAIResponsesItem::Message {
            role: role.to_string(),
            content: Some(std::mem::take(text)),
        });
    }
}

/// Transforms Anthropic tool definitions into Responses-API (flattened) tools.
fn transform_responses_tools(request: &CanonicalRequest) -> Option<Vec<serde_json::Value>> {
    let tools: Vec<serde_json::Value> = request
        .tools
        .as_ref()?
        .iter()
        .filter_map(|tool| {
            let name = tool.name.as_ref()?;
            let mut entry = serde_json::json!({
                "type": "function",
                "name": name,
                "parameters": tool
                    .input_schema
                    .clone()
                    .unwrap_or_else(|| serde_json::json!({ "type": "object", "properties": {} })),
            });
            if let Some(description) = &tool.description {
                entry["description"] = serde_json::Value::String(description.clone());
            }
            Some(entry)
        })
        .collect();

    (!tools.is_empty()).then_some(tools)
}

/// Transforms Anthropic `tool_choice` into the Responses-API shape.
fn transform_responses_tool_choice(request: &CanonicalRequest) -> Option<serde_json::Value> {
    let tc = request.tool_choice.as_ref()?;
    match tc.get("type").and_then(|v| v.as_str()).unwrap_or("") {
        "auto" => Some(serde_json::json!("auto")),
        "any" => Some(serde_json::json!("required")),
        "tool" => {
            let name = tc.get("name").and_then(|v| v.as_str()).unwrap_or("");
            Some(serde_json::json!({ "type": "function", "name": name }))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        CanonicalRequest, ContentBlock, KnownContentBlock, Message, MessageContent, SystemPrompt,
    };
    use serde::{Serialize, Serializer};

    fn base_request() -> CanonicalRequest {
        CanonicalRequest {
            model: "gpt-4o".to_string(),
            messages: Vec::new(),
            max_tokens: 100,
            thinking: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop_sequences: None,
            stream: None,
            metadata: None,
            system: None,
            tools: None,
            tool_choice: None,
            extensions: Default::default(),
        }
    }

    #[test]
    fn responses_request_forwards_tools_and_tool_history() {
        use crate::models::{Message, Tool, ToolResultContent};

        let mut request = base_request();
        request.model = "gpt-5.5".to_string();
        request.tools = Some(vec![Tool {
            r#type: Some("function".to_string()),
            name: Some("Bash".to_string()),
            description: Some("Run a shell command".to_string()),
            input_schema: Some(serde_json::json!({
                "type": "object",
                "properties": { "command": { "type": "string" } }
            })),
        }]);
        request.messages = vec![
            Message {
                role: "user".to_string(),
                content: MessageContent::Text("list files".to_string()),
            },
            Message {
                role: "assistant".to_string(),
                content: MessageContent::Blocks(vec![
                    ContentBlock::text("Running ls".to_string(), None),
                    ContentBlock::tool_use(
                        "toolu_1".to_string(),
                        "Bash".to_string(),
                        serde_json::json!({ "command": "ls" }),
                    ),
                ]),
            },
            Message {
                role: "user".to_string(),
                content: MessageContent::Blocks(vec![ContentBlock::Known(
                    KnownContentBlock::ToolResult {
                        tool_use_id: "toolu_1".to_string(),
                        content: ToolResultContent::Text("file1\nfile2".to_string()),
                        is_error: false,
                        cache_control: None,
                    },
                )]),
            },
        ];

        let opts = CodexOptions::default();
        let req = transform_to_responses_request(
            &request,
            "FULL CODEX PROMPT",
            &CodexTuning::from_options(&opts, None, None),
        )
        .unwrap();
        let json = serde_json::to_value(&req).unwrap();

        // Tools are forwarded in the flattened Responses shape.
        assert_eq!(json["tools"][0]["type"], "function");
        assert_eq!(json["tools"][0]["name"], "Bash");
        assert!(json["tools"][0]["parameters"]["properties"]["command"].is_object());
        assert_eq!(json["parallel_tool_calls"], true);

        // The full Codex prompt is swapped for the tool-deferring preamble.
        let instructions = json["instructions"].as_str().unwrap();
        assert!(instructions.contains("provided tools"));
        assert!(!instructions.contains("FULL CODEX PROMPT"));

        // History carries the tool call and its output, correlated by id.
        let input = json["input"].as_array().unwrap();
        assert!(input.iter().any(|i| i["type"] == "function_call"
            && i["call_id"] == "toolu_1"
            && i["name"] == "Bash"));
        assert!(input.iter().any(|i| i["type"] == "function_call_output"
            && i["call_id"] == "toolu_1"
            && i["output"] == "file1\nfile2"));
        // The assistant's narration survives as a message item before the call.
        assert!(input
            .iter()
            .any(|i| i["type"] == "message" && i["role"] == "assistant"));
    }

    #[test]
    fn responses_request_folds_system_role_into_user() {
        use crate::models::Message;

        let mut request = base_request();
        request.system = None;
        request.messages = vec![Message {
            role: "system".to_string(),
            content: MessageContent::Text("be terse".to_string()),
        }];

        let opts = CodexOptions::default();
        let req = transform_to_responses_request(
            &request,
            "FULL",
            &CodexTuning::from_options(&opts, None, None),
        )
        .unwrap();
        let json = serde_json::to_value(&req).unwrap();
        let input = json["input"].as_array().unwrap();

        // No system-role items survive (the Codex backend rejects them)...
        assert!(input.iter().all(|i| i["role"] != "system"));
        // ...but the content is preserved as a user item.
        assert!(input
            .iter()
            .any(|i| i["role"] == "user" && i["content"] == "be terse"));
    }

    #[test]
    fn codex_native_request_forwards_system_as_instructions_once() {
        use crate::models::Tool;

        let mut request = base_request();
        request.model = "gpt-5.5".to_string();
        request.system = Some(SystemPrompt::Text("FULL CODEX CLI PROMPT".to_string()));
        request.extensions.codex_native = true;
        request.tools = Some(vec![Tool {
            r#type: Some("function".to_string()),
            name: Some("exec_command".to_string()),
            description: Some("Run a command".to_string()),
            input_schema: Some(serde_json::json!({
                "type": "object",
                "properties": { "cmd": { "type": "string" } }
            })),
        }]);
        request.messages = vec![Message {
            role: "user".to_string(),
            content: MessageContent::Text("run ls".to_string()),
        }];

        let opts = CodexOptions::default();
        let req = transform_to_responses_request(
            &request,
            "BUILTIN CODEX PROMPT",
            &CodexTuning::from_options(&opts, None, None),
        )
        .unwrap();
        let json = serde_json::to_value(&req).unwrap();

        assert_eq!(json["instructions"], "FULL CODEX CLI PROMPT");
        assert_eq!(json["tools"][0]["name"], "exec_command");

        let input = json["input"].as_array().unwrap();
        assert_eq!(input.len(), 1);
        assert_eq!(input[0]["role"], "user");
        assert_eq!(input[0]["content"], "run ls");
        assert!(!input
            .iter()
            .any(|item| item["content"] == "FULL CODEX CLI PROMPT"));
    }

    #[test]
    fn reasoning_effort_default_is_xhigh_for_priority_models() {
        // Default mode (auto_map off): flagship/priority models get xhigh, other
        // models are left unset so the backend applies its own default. A forced
        // or extension effort always wins.
        let opts = CodexOptions::default();
        let effort = |model: &str, forced: Option<&str>, ext: Option<&str>| {
            let mut req = base_request();
            req.system = None;
            req.model = model.to_string();
            req.extensions.reasoning_effort = ext.map(str::to_string);
            let tuning = CodexTuning::from_options(&opts, forced, None);
            serde_json::to_value(transform_to_responses_request(&req, "X", &tuning).unwrap())
                .unwrap()["reasoning"]["effort"]
                .clone()
        };

        // Priority/flagship model → xhigh by default (thinking ignored here).
        assert_eq!(effort("gpt-5.5", None, None), serde_json::json!("xhigh"));
        // Non-priority model → unset (the backend picks its own effort).
        assert_eq!(effort("gpt-5.3-codex", None, None), serde_json::Value::Null);
        // A forced effort wins on any model.
        assert_eq!(
            effort("gpt-5.5", Some("low"), None),
            serde_json::json!("low")
        );
        assert_eq!(
            effort("gpt-5.3-codex", Some("high"), None),
            serde_json::json!("high")
        );
        // A request extension forces effort when no provider override is set.
        assert_eq!(
            effort("gpt-4o", None, Some("medium")),
            serde_json::json!("medium")
        );
        // An empty forced effort falls back to the default (xhigh for priority).
        assert_eq!(
            effort("gpt-5.5", Some(""), None),
            serde_json::json!("xhigh")
        );
    }

    #[test]
    fn reasoning_auto_map_maps_thinking_budget_when_enabled() {
        use crate::models::ThinkingConfig;

        // Opt-in mode: effort follows the extended-thinking budget (legacy).
        let opts = CodexOptions {
            reasoning_auto_map: true,
            ..CodexOptions::default()
        };
        let effort = |thinking: Option<ThinkingConfig>, forced: Option<&str>| {
            let mut req = base_request();
            req.system = None;
            req.thinking = thinking;
            let tuning = CodexTuning::from_options(&opts, forced, None);
            serde_json::to_value(transform_to_responses_request(&req, "X", &tuning).unwrap())
                .unwrap()["reasoning"]["effort"]
                .clone()
        };
        let enabled = |b: u32| {
            Some(ThinkingConfig {
                r#type: "enabled".to_string(),
                budget_tokens: Some(b),
            })
        };
        let typed = |t: &str| {
            Some(ThinkingConfig {
                r#type: t.to_string(),
                budget_tokens: None,
            })
        };

        // No thinking → low; large budget → xhigh; smaller → medium.
        assert_eq!(effort(None, None), serde_json::json!("low"));
        assert_eq!(effort(enabled(20_000), None), serde_json::json!("xhigh"));
        assert_eq!(effort(enabled(4_000), None), serde_json::json!("medium"));
        // Adaptive (no budget) → xhigh; explicitly disabled → low.
        assert_eq!(effort(typed("adaptive"), None), serde_json::json!("xhigh"));
        assert_eq!(effort(typed("disabled"), None), serde_json::json!("low"));
        // A forced effort still wins over the auto-map.
        assert_eq!(effort(None, Some("minimal")), serde_json::json!("minimal"));
    }

    #[test]
    fn reasoning_xhigh_min_budget_is_configurable() {
        use crate::models::ThinkingConfig;

        // The auto-map xhigh threshold is parametrable, not hard-coded at 16000.
        let opts = CodexOptions {
            reasoning_auto_map: true,
            reasoning_xhigh_min_budget: 5_000,
            ..CodexOptions::default()
        };
        let effort = |budget: u32| {
            let mut req = base_request();
            req.system = None;
            req.thinking = Some(ThinkingConfig {
                r#type: "enabled".to_string(),
                budget_tokens: Some(budget),
            });
            let tuning = CodexTuning::from_options(&opts, None, None);
            serde_json::to_value(transform_to_responses_request(&req, "X", &tuning).unwrap())
                .unwrap()["reasoning"]["effort"]
                .clone()
        };

        assert_eq!(effort(4_999), serde_json::json!("medium"));
        assert_eq!(effort(5_000), serde_json::json!("xhigh"));
    }

    #[test]
    fn service_tier_is_forwarded_from_config_and_extension() {
        let opts = CodexOptions::default();
        let tier = |req: &CanonicalRequest, forced: Option<&str>| {
            let tuning = CodexTuning::from_options(&opts, None, forced);
            serde_json::to_value(transform_to_responses_request(req, "X", &tuning).unwrap())
                .unwrap()["service_tier"]
                .clone()
        };

        let mut req = base_request();
        req.system = None;
        req.model = "gpt-5.5".to_string(); // supports the priority tier

        // Unset by default.
        assert_eq!(tier(&req, None), serde_json::Value::Null);

        // Provider config forces it on a supporting model.
        assert_eq!(tier(&req, Some("priority")), serde_json::json!("priority"));

        // A request extension supplies it when no config override is set.
        req.extensions.service_tier = Some("priority".to_string());
        assert_eq!(tier(&req, None), serde_json::json!("priority"));

        // An empty forced value falls back to unset, not an empty string.
        req.extensions.service_tier = None;
        assert_eq!(tier(&req, Some("")), serde_json::Value::Null);

        // "priority" is dropped for models that don't offer it (would 400),
        // so forcing it on a codex/mini route is a silent no-op rather than a
        // failure. Other tiers still pass through on any model.
        req.model = "gpt-5.3-codex".to_string();
        assert_eq!(tier(&req, Some("priority")), serde_json::Value::Null);
        assert_eq!(tier(&req, Some("default")), serde_json::json!("default"));
        req.model = "gpt-5.4-mini".to_string();
        assert_eq!(tier(&req, Some("priority")), serde_json::Value::Null);
    }

    #[test]
    fn priority_models_list_is_configurable() {
        // Adding a model to `priority_models` enables the priority tier (and the
        // xhigh default) for it; removing the built-ins disables them — all
        // without a grob release.
        let opts = CodexOptions {
            priority_models: vec!["gpt-5.3-codex".to_string()],
            ..CodexOptions::default()
        };
        let resolve = |model: &str| {
            let mut req = base_request();
            req.system = None;
            req.model = model.to_string();
            let tuning = CodexTuning::from_options(&opts, None, Some("priority"));
            serde_json::to_value(transform_to_responses_request(&req, "X", &tuning).unwrap())
                .unwrap()
        };

        // The newly-listed model now gets priority and the default xhigh effort.
        let codex = resolve("gpt-5.3-codex");
        assert_eq!(codex["service_tier"], serde_json::json!("priority"));
        assert_eq!(codex["reasoning"]["effort"], serde_json::json!("xhigh"));

        // A model dropped from the list loses priority (silent no-op).
        let flagship = resolve("gpt-5.5");
        assert_eq!(flagship["service_tier"], serde_json::Value::Null);
    }

    #[test]
    fn responses_request_without_tools_keeps_full_instructions() {
        let mut request = base_request();
        request.system = None;
        let opts = CodexOptions::default();
        let req = transform_to_responses_request(
            &request,
            "FULL CODEX PROMPT",
            &CodexTuning::from_options(&opts, None, None),
        )
        .unwrap();
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["instructions"], "FULL CODEX PROMPT");
        assert!(json.get("tools").is_none() || json["tools"].is_null());
    }

    #[test]
    fn transform_strips_system_from_messages_after_hoisting() {
        // Bug #3: client sends `[user, system, assistant]` to grob, which
        // already hoists `request.system`; the original system role MUST be
        // dropped from the messages array, otherwise OpenAI receives two
        // `role:"system"` messages.
        let mut req = base_request();
        req.system = Some(SystemPrompt::Text("hoisted system".to_string()));
        req.messages = vec![
            Message {
                role: "user".to_string(),
                content: MessageContent::Text("hi".to_string()),
            },
            Message {
                role: "system".to_string(),
                content: MessageContent::Text("inline system that must be dropped".to_string()),
            },
            Message {
                role: "assistant".to_string(),
                content: MessageContent::Text("hello".to_string()),
            },
        ];

        let openai = transform_request(&req).expect("transform");

        let system_count = openai
            .messages
            .iter()
            .filter(|m| m.role == "system")
            .count();
        assert_eq!(
            system_count,
            1,
            "expected exactly one system message after hoisting; got {} (messages: {:?})",
            system_count,
            openai.messages.iter().map(|m| &m.role).collect::<Vec<_>>()
        );

        // The remaining system message must be the hoisted one.
        match &openai.messages[0].content {
            Some(OpenAIContent::String(s)) => assert_eq!(s, "hoisted system"),
            other => panic!("expected hoisted system text, got {:?}", other),
        }

        // Order of remaining roles preserved.
        let roles: Vec<&str> = openai.messages.iter().map(|m| m.role.as_str()).collect();
        assert_eq!(roles, vec!["system", "user", "assistant"]);
    }

    #[test]
    fn transform_strips_system_when_no_hoisted_system_field() {
        // If there's no `request.system` set, but a stray `role:"system"`
        // message slipped into `messages`, we still drop it — the canonical
        // wire format reserves `role:"system"` for the dedicated field.
        let mut req = base_request();
        req.messages = vec![
            Message {
                role: "system".to_string(),
                content: MessageContent::Text("inline".to_string()),
            },
            Message {
                role: "user".to_string(),
                content: MessageContent::Text("hi".to_string()),
            },
        ];

        let openai = transform_request(&req).expect("transform");
        let system_count = openai
            .messages
            .iter()
            .filter(|m| m.role == "system")
            .count();
        assert_eq!(system_count, 0);
        assert_eq!(openai.messages.len(), 1);
        assert_eq!(openai.messages[0].role, "user");
    }

    /// A `Serialize` payload that always errors. Mirrors `serde_json`'s
    /// internal failure surface so we can exercise the error path even when
    /// `serde_json::Value` itself is effectively infallible to encode.
    struct AlwaysFail;

    impl Serialize for AlwaysFail {
        fn serialize<S: Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("synthetic serialization failure"))
        }
    }

    #[test]
    fn transform_returns_error_when_tool_input_unserializable() {
        // Direct exercise of the helper used by extract_tool_calls. A
        // `Serialize` payload that always fails proves error propagation
        // surfaces the tool name and underlying serde_json error.
        let result = serialize_tool_input(&AlwaysFail, "broken_tool");
        let err = result.expect_err("expected serialization failure");
        match err {
            TransformError::ToolInputSerialization { tool_name, source } => {
                assert_eq!(tool_name, "broken_tool");
                assert!(
                    source
                        .to_string()
                        .contains("synthetic serialization failure"),
                    "source error did not bubble through: {}",
                    source
                );
            }
        }
    }

    #[test]
    fn transform_propagates_tool_input_error_to_provider_error() {
        // `From<TransformError> for ProviderError` keeps the legacy callers
        // (which return `ProviderError`) compatible while preserving the
        // structured error category.
        let err = TransformError::ToolInputSerialization {
            tool_name: "broken_tool".to_string(),
            source: serde_json::from_str::<serde_json::Value>("{").unwrap_err(),
        };
        let provider_err: ProviderError = err.into();
        assert!(matches!(provider_err, ProviderError::SerializationError(_)));
    }

    #[test]
    fn transform_succeeds_when_tool_input_well_formed() {
        // Sanity check: typical tool_use blocks still translate cleanly.
        let mut req = base_request();
        req.messages = vec![Message {
            role: "assistant".to_string(),
            content: MessageContent::Blocks(vec![ContentBlock::Known(
                KnownContentBlock::ToolUse {
                    id: "call_1".to_string(),
                    name: "weather".to_string(),
                    input: serde_json::json!({"city": "Paris"}),
                },
            )]),
        }];

        let openai = transform_request(&req).expect("transform");
        let assistant = openai
            .messages
            .iter()
            .find(|m| m.role == "assistant")
            .expect("assistant message");
        let tool_calls = assistant.tool_calls.as_ref().expect("tool_calls present");
        assert_eq!(tool_calls.len(), 1);
        assert_eq!(tool_calls[0].id, "call_1");
        assert_eq!(tool_calls[0].function.name, "weather");
        assert_eq!(tool_calls[0].function.arguments, r#"{"city":"Paris"}"#);
    }

    #[test]
    fn parse_sse_uses_output_item_done_when_completed_output_empty() {
        // The ChatGPT backend (`backend-api/codex`) carries the message in a
        // `response.output_item.done` event and leaves `completed.output` null.
        let sse = concat!(
            "event: response.output_item.done\n",
            "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"hi there\"}]}}\n",
            "\n",
            "event: response.completed\n",
            "data: {\"type\":\"response.completed\",\"response\":{\"output\":null}}\n",
        );

        let blocks = parse_sse_response(sse).expect("should extract content");
        assert_eq!(blocks.len(), 1);
        let value = serde_json::to_value(&blocks[0]).expect("serialize block");
        assert_eq!(value["type"], "text");
        assert_eq!(value["text"], "hi there");
    }

    #[test]
    fn parse_sse_falls_back_to_completed_output_for_standard_api() {
        // The public Responses API populates `output[]` in `response.completed`
        // and emits no per-item done events.
        let sse = concat!(
            "event: response.completed\n",
            "data: {\"type\":\"response.completed\",\"response\":{\"output\":[{\"type\":\"message\",\"content\":[{\"type\":\"output_text\",\"text\":\"final\"}]}]}}\n",
        );

        let blocks = parse_sse_response(sse).expect("should extract content");
        assert_eq!(blocks.len(), 1);
        let value = serde_json::to_value(&blocks[0]).expect("serialize block");
        assert_eq!(value["text"], "final");
    }

    #[test]
    fn parse_sse_maps_reasoning_summary_to_thinking() {
        let sse = concat!(
            "event: response.output_item.done\n",
            "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"reasoning\",\"summary\":[{\"type\":\"summary_text\",\"text\":\"weighing options\"}]}}\n",
            "\n",
            "event: response.output_item.done\n",
            "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"message\",\"content\":[{\"type\":\"output_text\",\"text\":\"answer\"}]}}\n",
        );

        let blocks = parse_sse_response(sse).expect("should extract content");
        assert_eq!(blocks.len(), 2);
        let thinking = serde_json::to_value(&blocks[0]).expect("serialize block");
        assert_eq!(thinking["type"], "thinking");
        assert_eq!(thinking["thinking"], "weighing options");
    }

    #[test]
    fn parse_sse_errors_when_no_content() {
        let sse = "event: response.created\ndata: {\"type\":\"response.created\"}\n";
        assert!(parse_sse_response(sse).is_err());
    }
}

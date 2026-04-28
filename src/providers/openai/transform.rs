use super::types::*;
use crate::models::{CanonicalRequest, MessageContent};
use crate::providers::error::ProviderError;
use crate::providers::{ContentBlock, KnownContentBlock, ProviderResponse, Usage};
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
    for msg in &request.messages {
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
                    reasoning: None,
                    tool_calls: None,
                    tool_call_id: None,
                });
            }
            MessageContent::Blocks(blocks) => {
                transform_block_message(&msg.role, blocks, &mut openai_messages)?;
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

    if !text.is_empty() {
        content_blocks.push(ContentBlock::text(text, None));
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

    // Map OpenAI finish_reason to Anthropic stop_reason
    let stop_reason = choice.finish_reason.map(|reason| match reason.as_str() {
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
/// Finds the `response.completed` event and extracts reasoning + message output.
pub(crate) fn parse_sse_response(sse_text: &str) -> Result<Vec<ContentBlock>, ProviderError> {
    let lines: Vec<&str> = sse_text.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        if !line.starts_with("event: response.completed") {
            continue;
        }

        let Some(data_line) = lines.get(i + 1) else {
            continue;
        };
        let Some(json_str) = data_line.strip_prefix("data: ") else {
            continue;
        };
        let Ok(json) = serde_json::from_str::<serde_json::Value>(json_str) else {
            continue;
        };

        let Some(output) = json
            .get("response")
            .and_then(|r| r.get("output"))
            .and_then(|v| v.as_array())
        else {
            continue;
        };

        let content_blocks: Vec<ContentBlock> = output
            .iter()
            .filter_map(extract_codex_output_block)
            .collect();

        if !content_blocks.is_empty() {
            return Ok(content_blocks);
        }
    }

    Err(ProviderError::ApiError {
        status: 500,
        message: "Failed to parse SSE response: no content found".to_string(),
    })
}

/// Maps a Codex `output[]` item (`reasoning` or `message`) to the corresponding Anthropic thinking or text block.
fn extract_codex_output_block(item: &serde_json::Value) -> Option<ContentBlock> {
    let output_type = item.get("type").and_then(|v| v.as_str())?;
    let text = item
        .get("content")
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

/// Transform Anthropic request to OpenAI Responses API format.
pub(crate) fn transform_to_responses_request(
    request: &CanonicalRequest,
    codex_instructions: &str,
) -> Result<OpenAIResponsesRequest, ProviderError> {
    let instructions = codex_instructions.to_string();
    let mut messages = Vec::new();

    // Add system message as user message (Codex doesn't have separate system role)
    if let Some(ref system) = request.system {
        messages.push(OpenAIResponsesMessage {
            role: "user".to_string(),
            content: Some(system.to_text()),
        });
    }

    for msg in &request.messages {
        let content = match &msg.content {
            MessageContent::Text(text) => text.clone(),
            MessageContent::Blocks(blocks) => {
                let text = blocks
                    .iter()
                    .filter_map(|block| block.as_text().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
                    .join("\n");
                if text.is_empty() {
                    String::new()
                } else {
                    text
                }
            }
        };

        messages.push(OpenAIResponsesMessage {
            role: msg.role.clone(),
            content: Some(content),
        });
    }

    Ok(OpenAIResponsesRequest {
        model: request.model.clone(),
        input: OpenAIResponsesInput::Messages(messages),
        instructions,
        store: false,
        stream: true,
    })
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
}

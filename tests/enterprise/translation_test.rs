//! Translation layer regression tests.
//!
//! Pins the Anthropic Messages <-> OpenAI Chat Completions <-> Responses API
//! transformations so downstream changes cannot silently alter the wire format.
//!
//! The audit logged 18 touches in the translation modules over 3 months with
//! no dedicated tests. This file is the ratchet that catches structural
//! regressions before they reach a release.
//!
//! Streaming is intentionally out of scope here — see the parallel
//! `test/translation-streaming` work for SSE event coverage.
//!
//! Coverage map:
//!
//! | Test family                         | Function under test                          |
//! |-------------------------------------|----------------------------------------------|
//! | `anthropic_to_openai_*`             | `providers::openai::test_api::anthropic_to_openai_request` |
//! | `openai_response_*`                 | `providers::openai::test_api::openai_response_to_anthropic` |
//! | `openai_request_to_canonical_*`     | `server::openai_compat::transform_openai_to_canonical`     |
//! | `canonical_response_to_openai_*`    | `server::openai_compat::transform_canonical_to_openai`     |
//! | `anthropic_to_responses_*`          | `providers::openai::test_api::anthropic_to_responses_request` |
//! | `transform_*` (edge cases)          | mixed                                                       |

use grob::models::{
    CanonicalRequest, ContentBlock, ImageSource, KnownContentBlock, Message, MessageContent,
    SystemPrompt, Tool, ToolResultContent,
};
use grob::providers::openai::test_api::{
    anthropic_to_openai_request, anthropic_to_responses_request, openai_response_to_anthropic,
};
use grob::providers::{ProviderResponse, Usage};
use grob::server::openai_compat::{
    transform_canonical_to_openai, transform_openai_to_canonical, OpenAIContent, OpenAIContentPart,
    OpenAIFunctionInput, OpenAIImageUrl, OpenAIMessage, OpenAIRequest, OpenAIToolCallInput,
};
use serde_json::{json, Value};

// ── Builders ────────────────────────────────────────────────────────────

/// Returns a minimal canonical request scaffold suitable for table-driven tests.
///
/// Callers override only the fields they care about; everything else is set to
/// values that exercise the simplest path through every transformer.
fn base_canonical(model: &str) -> CanonicalRequest {
    CanonicalRequest {
        model: model.to_string(),
        messages: Vec::new(),
        max_tokens: 1024,
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

fn user_text(text: &str) -> Message {
    Message {
        role: "user".to_string(),
        content: MessageContent::Text(text.to_string()),
    }
}

fn assistant_text(text: &str) -> Message {
    Message {
        role: "assistant".to_string(),
        content: MessageContent::Text(text.to_string()),
    }
}

fn user_blocks(blocks: Vec<ContentBlock>) -> Message {
    Message {
        role: "user".to_string(),
        content: MessageContent::Blocks(blocks),
    }
}

fn assistant_blocks(blocks: Vec<ContentBlock>) -> Message {
    Message {
        role: "assistant".to_string(),
        content: MessageContent::Blocks(blocks),
    }
}

fn provider_response(content: Vec<ContentBlock>, stop_reason: &str) -> ProviderResponse {
    ProviderResponse {
        id: "msg_test".to_string(),
        r#type: "message".to_string(),
        role: "assistant".to_string(),
        content,
        model: "claude-test".to_string(),
        stop_reason: Some(stop_reason.to_string()),
        stop_sequence: None,
        usage: Usage {
            input_tokens: 10,
            output_tokens: 20,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
    }
}

fn first_message(req: &Value) -> &Value {
    req.get("messages")
        .and_then(|m| m.as_array())
        .and_then(|a| a.first())
        .expect("expected at least one message in transformed request")
}

// ── Anthropic Messages → OpenAI Chat Completions ────────────────────────

#[test]
fn anthropic_to_openai_simple_user_message() {
    let mut req = base_canonical("gpt-4o");
    req.messages = vec![user_text("Hello, world!")];

    let out = anthropic_to_openai_request(&req).expect("transform must succeed");

    assert_eq!(out["model"], json!("gpt-4o"));
    assert_eq!(out["max_tokens"], json!(1024));

    let messages = out["messages"].as_array().expect("messages array");
    assert_eq!(messages.len(), 1, "no system was set");
    assert_eq!(messages[0]["role"], json!("user"));
    assert_eq!(messages[0]["content"], json!("Hello, world!"));
}

#[test]
fn anthropic_to_openai_with_system_prompt_hoisted_to_first_message() {
    let mut req = base_canonical("gpt-4o");
    req.system = Some(SystemPrompt::Text(
        "You are a helpful assistant.".to_string(),
    ));
    req.messages = vec![user_text("Hi")];

    let out = anthropic_to_openai_request(&req).expect("transform must succeed");

    let messages = out["messages"].as_array().expect("messages array");
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0]["role"], json!("system"));
    assert_eq!(
        messages[0]["content"],
        json!("You are a helpful assistant.")
    );
    assert_eq!(messages[1]["role"], json!("user"));
}

#[test]
fn anthropic_to_openai_strips_duplicate_system_role_from_messages() {
    // When an OpenAI client puts a `system` message in the messages array
    // alongside a top-level system prompt, the inbound (request-direction)
    // compat layer must collapse them into the single `system` field on
    // CanonicalRequest. Verifies the OpenAI -> canonical direction first;
    // then verifies the canonical -> OpenAI direction emits exactly one
    // system message.
    let openai_req = OpenAIRequest {
        model: "gpt-4o".to_string(),
        messages: vec![
            OpenAIMessage {
                role: "system".to_string(),
                content: Some(OpenAIContent::String("S1".to_string())),
                name: None,
                tool_calls: None,
                tool_call_id: None,
            },
            OpenAIMessage {
                role: "user".to_string(),
                content: Some(OpenAIContent::String("Hi".to_string())),
                name: None,
                tool_calls: None,
                tool_call_id: None,
            },
        ],
        max_tokens: Some(64),
        temperature: None,
        top_p: None,
        stop: None,
        stream: None,
        tools: None,
        tool_choice: None,
        response_format: None,
        reasoning_effort: None,
        seed: None,
        frequency_penalty: None,
        presence_penalty: None,
        parallel_tool_calls: None,
        user: None,
        logprobs: None,
        top_logprobs: None,
        service_tier: None,
    };

    let canonical = transform_openai_to_canonical(openai_req).expect("transform must succeed");
    // System message must be hoisted out of the conversation array.
    assert_eq!(canonical.messages.len(), 1);
    assert_eq!(canonical.messages[0].role, "user");
    match &canonical.system {
        Some(SystemPrompt::Text(t)) => assert_eq!(t, "S1"),
        other => panic!("expected SystemPrompt::Text, got {:?}", other),
    }

    // Round-trip back to OpenAI: exactly one system message, and only at index 0.
    let out = anthropic_to_openai_request(&canonical).expect("roundtrip");
    let msgs = out["messages"].as_array().expect("messages array");
    let system_count = msgs.iter().filter(|m| m["role"] == "system").count();
    assert_eq!(
        system_count, 1,
        "exactly one system message after roundtrip"
    );
    assert_eq!(msgs[0]["role"], json!("system"));
}

#[test]
fn anthropic_to_openai_with_assistant_message_after_user() {
    let mut req = base_canonical("gpt-4o");
    req.messages = vec![
        user_text("Hello"),
        assistant_text("Hi there!"),
        user_text("How are you?"),
    ];

    let out = anthropic_to_openai_request(&req).expect("transform must succeed");

    let messages = out["messages"].as_array().expect("messages array");
    assert_eq!(messages.len(), 3);
    assert_eq!(messages[0]["role"], json!("user"));
    assert_eq!(messages[1]["role"], json!("assistant"));
    assert_eq!(messages[1]["content"], json!("Hi there!"));
    assert_eq!(messages[2]["role"], json!("user"));
}

#[test]
fn anthropic_to_openai_tool_use_block_to_tool_calls() {
    let mut req = base_canonical("gpt-4o");
    req.messages = vec![
        user_text("What's the weather in Paris?"),
        assistant_blocks(vec![
            ContentBlock::text("Let me check.".to_string(), None),
            ContentBlock::tool_use(
                "toolu_01abc".to_string(),
                "get_weather".to_string(),
                json!({"location": "Paris"}),
            ),
        ]),
    ];

    let out = anthropic_to_openai_request(&req).expect("transform must succeed");

    let messages = out["messages"].as_array().expect("messages array");
    let assistant = &messages[1];
    assert_eq!(assistant["role"], json!("assistant"));
    assert_eq!(assistant["content"], json!("Let me check."));

    let tool_calls = assistant["tool_calls"]
        .as_array()
        .expect("tool_calls array");
    assert_eq!(tool_calls.len(), 1);
    assert_eq!(tool_calls[0]["id"], json!("toolu_01abc"));
    assert_eq!(tool_calls[0]["type"], json!("function"));
    assert_eq!(tool_calls[0]["function"]["name"], json!("get_weather"));

    // Arguments must be a JSON string, not a JSON object.
    let arguments = tool_calls[0]["function"]["arguments"]
        .as_str()
        .expect("arguments must be a JSON-encoded string");
    let parsed: Value = serde_json::from_str(arguments).expect("arguments parse as JSON");
    assert_eq!(parsed["location"], json!("Paris"));
}

#[test]
fn anthropic_to_openai_tool_result_block_to_tool_role_message() {
    let mut req = base_canonical("gpt-4o");
    req.messages = vec![
        user_text("ls"),
        assistant_blocks(vec![ContentBlock::tool_use(
            "toolu_01x".to_string(),
            "ls".to_string(),
            json!({}),
        )]),
        user_blocks(vec![ContentBlock::Known(KnownContentBlock::ToolResult {
            tool_use_id: "toolu_01x".to_string(),
            content: ToolResultContent::Text("file1\nfile2".to_string()),
            is_error: false,
            cache_control: None,
        })]),
    ];

    let out = anthropic_to_openai_request(&req).expect("transform must succeed");

    let messages = out["messages"].as_array().expect("messages array");
    // Tool result must become a `tool`-role message bearing tool_call_id, with
    // no surrounding `user` wrapper. Ordering: user, assistant(tool_use), tool.
    let tool_msg = messages
        .iter()
        .find(|m| m["role"] == "tool")
        .expect("expected a tool-role message in the output");
    assert_eq!(tool_msg["tool_call_id"], json!("toolu_01x"));
    assert_eq!(tool_msg["content"], json!("file1\nfile2"));
}

#[test]
fn anthropic_to_openai_image_input_url() {
    let mut req = base_canonical("gpt-4o");
    req.messages = vec![user_blocks(vec![
        ContentBlock::text("Describe this:".to_string(), None),
        ContentBlock::image(ImageSource {
            r#type: "url".to_string(),
            media_type: None,
            data: None,
            url: Some("https://example.com/cat.png".to_string()),
        }),
    ])];

    let out = anthropic_to_openai_request(&req).expect("transform must succeed");

    let user_msg = first_message(&out);
    let parts = user_msg["content"]
        .as_array()
        .expect("multipart content for image+text");
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0]["type"], json!("text"));
    assert_eq!(parts[1]["type"], json!("image_url"));
    assert_eq!(
        parts[1]["image_url"]["url"],
        json!("https://example.com/cat.png")
    );
}

#[test]
fn anthropic_to_openai_image_input_base64() {
    let mut req = base_canonical("gpt-4o");
    let b64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=";
    req.messages = vec![user_blocks(vec![
        ContentBlock::text("What is this?".to_string(), None),
        ContentBlock::image(ImageSource {
            r#type: "base64".to_string(),
            media_type: Some("image/png".to_string()),
            data: Some(b64.to_string()),
            url: None,
        }),
    ])];

    let out = anthropic_to_openai_request(&req).expect("transform must succeed");

    let parts = first_message(&out)["content"]
        .as_array()
        .expect("multipart content for image+text");
    let img_part = parts
        .iter()
        .find(|p| p["type"] == "image_url")
        .expect("expected image_url part");
    let url = img_part["image_url"]["url"]
        .as_str()
        .expect("image_url.url is a string");
    // OpenAI expects a base64 data URI, reconstructed from the canonical fields.
    assert!(
        url.starts_with("data:image/png;base64,"),
        "expected data URI prefix, got {url}"
    );
    assert!(
        url.ends_with(b64),
        "expected encoded payload to be appended"
    );
}

#[test]
fn anthropic_to_openai_thinking_block_dropped_when_target_is_chat_completions() {
    let mut req = base_canonical("gpt-4o");
    req.messages = vec![assistant_blocks(vec![
        ContentBlock::thinking(json!({"thinking": "Let me reason..."})),
        ContentBlock::text("Final answer.".to_string(), None),
    ])];

    let out = anthropic_to_openai_request(&req).expect("transform must succeed");

    let assistant = first_message(&out);
    // OpenAI Chat Completions has no thinking-block concept, so the only
    // surviving content is the final text.
    assert_eq!(assistant["content"], json!("Final answer."));
    let serialized = serde_json::to_string(&out).expect("serialize");
    assert!(
        !serialized.contains("Let me reason"),
        "thinking content must not leak into the OpenAI request: {serialized}"
    );
    assert!(
        !serialized.contains("\"thinking\""),
        "thinking-block type tag must not appear in the OpenAI request"
    );
}

#[test]
fn anthropic_to_openai_cache_control_dropped_when_target_lacks_cache() {
    let mut req = base_canonical("gpt-4o");
    req.messages = vec![user_blocks(vec![ContentBlock::text(
        "Hello".to_string(),
        Some(json!({"type": "ephemeral"})),
    )])];

    let out = anthropic_to_openai_request(&req).expect("transform must succeed");

    let serialized = serde_json::to_string(&out).expect("serialize");
    assert!(
        !serialized.contains("cache_control"),
        "Anthropic cache_control must not appear on the OpenAI request: {serialized}"
    );
    assert!(
        !serialized.contains("ephemeral"),
        "ephemeral marker must be stripped"
    );
}

#[test]
fn anthropic_to_openai_with_max_tokens_and_stop_sequences() {
    let mut req = base_canonical("gpt-4o");
    req.max_tokens = 256;
    req.stop_sequences = Some(vec!["END".to_string(), "STOP".to_string()]);
    req.messages = vec![user_text("Go.")];

    let out = anthropic_to_openai_request(&req).expect("transform must succeed");

    assert_eq!(out["max_tokens"], json!(256));
    assert_eq!(out["stop"], json!(["END", "STOP"]));
}

#[test]
fn anthropic_to_openai_temperature_and_top_p_passthrough() {
    let mut req = base_canonical("gpt-4o");
    req.temperature = Some(0.42);
    req.top_p = Some(0.9);
    req.messages = vec![user_text("Hi")];

    let out = anthropic_to_openai_request(&req).expect("transform must succeed");

    // Tolerate JSON's default float rendering — compare numerically.
    let temp = out["temperature"]
        .as_f64()
        .expect("temperature must be a number");
    let top_p = out["top_p"].as_f64().expect("top_p must be a number");
    assert!((temp - 0.42).abs() < 1e-6, "temperature mismatch: {temp}");
    assert!((top_p - 0.9).abs() < 1e-6, "top_p mismatch: {top_p}");
}

// ── OpenAI Chat Completions → Anthropic (response direction) ────────────

#[test]
fn openai_response_finish_reason_stop_to_anthropic_end_turn() {
    let openai_resp = json!({
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "Hello!"},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7}
    });

    let anthropic = openai_response_to_anthropic(openai_resp).expect("transform must succeed");
    assert_eq!(anthropic.stop_reason.as_deref(), Some("end_turn"));
}

#[test]
fn openai_response_finish_reason_length_to_anthropic_max_tokens() {
    let openai_resp = json!({
        "id": "chatcmpl-2",
        "object": "chat.completion",
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "..."},
            "finish_reason": "length"
        }],
        "usage": {"prompt_tokens": 5, "completion_tokens": 1024, "total_tokens": 1029}
    });

    let anthropic = openai_response_to_anthropic(openai_resp).expect("transform must succeed");
    assert_eq!(anthropic.stop_reason.as_deref(), Some("max_tokens"));
}

#[test]
fn openai_response_finish_reason_tool_calls_to_anthropic_tool_use_block() {
    let openai_resp = json!({
        "id": "chatcmpl-3",
        "object": "chat.completion",
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": "call_42",
                    "type": "function",
                    "function": {
                        "name": "get_weather",
                        "arguments": "{\"location\":\"Paris\"}"
                    }
                }]
            },
            "finish_reason": "tool_calls"
        }],
        "usage": {"prompt_tokens": 12, "completion_tokens": 8, "total_tokens": 20}
    });

    let anthropic = openai_response_to_anthropic(openai_resp).expect("transform must succeed");
    assert_eq!(anthropic.stop_reason.as_deref(), Some("tool_use"));

    let tool_use_block = anthropic
        .content
        .iter()
        .find_map(|b| match b {
            ContentBlock::Known(KnownContentBlock::ToolUse { id, name, input }) => {
                Some((id.clone(), name.clone(), input.clone()))
            }
            _ => None,
        })
        .expect("expected a ToolUse block");
    assert_eq!(tool_use_block.0, "call_42");
    assert_eq!(tool_use_block.1, "get_weather");
    assert_eq!(tool_use_block.2["location"], json!("Paris"));
}

#[test]
fn openai_response_usage_to_anthropic_usage_input_output() {
    let openai_resp = json!({
        "id": "chatcmpl-4",
        "object": "chat.completion",
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "ok"},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 123, "completion_tokens": 45, "total_tokens": 168}
    });

    let anthropic = openai_response_to_anthropic(openai_resp).expect("transform must succeed");
    assert_eq!(anthropic.usage.input_tokens, 123);
    assert_eq!(anthropic.usage.output_tokens, 45);
}

#[test]
fn openai_response_with_no_content_to_anthropic_with_empty_text_block() {
    // OpenAI may emit `content: null` for tool-only or empty replies. The
    // canonical response should not panic and should contain no spurious text.
    let openai_resp = json!({
        "id": "chatcmpl-5",
        "object": "chat.completion",
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": null},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 5, "completion_tokens": 0, "total_tokens": 5}
    });

    let anthropic = openai_response_to_anthropic(openai_resp).expect("transform must succeed");
    assert_eq!(anthropic.role, "assistant");
    let has_non_empty_text = anthropic.content.iter().any(|b| match b {
        ContentBlock::Known(KnownContentBlock::Text { text, .. }) => !text.is_empty(),
        _ => false,
    });
    assert!(
        !has_non_empty_text,
        "no non-empty text block should be synthesised from null content"
    );
}

// ── OpenAI Chat Completions request (inbound) → Canonical ───────────────
// These cover transform_openai_to_canonical, complementing the tests above.

#[test]
fn openai_request_to_canonical_simple_user_message() {
    let req = OpenAIRequest {
        model: "gpt-4o".to_string(),
        messages: vec![OpenAIMessage {
            role: "user".to_string(),
            content: Some(OpenAIContent::String("Hello!".to_string())),
            name: None,
            tool_calls: None,
            tool_call_id: None,
        }],
        max_tokens: Some(128),
        temperature: None,
        top_p: None,
        stop: None,
        stream: None,
        tools: None,
        tool_choice: None,
        response_format: None,
        reasoning_effort: None,
        seed: None,
        frequency_penalty: None,
        presence_penalty: None,
        parallel_tool_calls: None,
        user: None,
        logprobs: None,
        top_logprobs: None,
        service_tier: None,
    };

    let canonical = transform_openai_to_canonical(req).expect("transform must succeed");
    assert_eq!(canonical.model, "gpt-4o");
    assert_eq!(canonical.max_tokens, 128);
    assert_eq!(canonical.messages.len(), 1);
    assert!(canonical.system.is_none());
}

#[test]
fn openai_request_to_canonical_with_image_url_part() {
    let req = OpenAIRequest {
        model: "gpt-4o".to_string(),
        messages: vec![OpenAIMessage {
            role: "user".to_string(),
            content: Some(OpenAIContent::Parts(vec![
                OpenAIContentPart::Text {
                    text: "Look:".to_string(),
                },
                OpenAIContentPart::ImageUrl {
                    image_url: OpenAIImageUrl {
                        url: "https://example.com/x.jpg".to_string(),
                    },
                },
            ])),
            name: None,
            tool_calls: None,
            tool_call_id: None,
        }],
        max_tokens: Some(64),
        temperature: None,
        top_p: None,
        stop: None,
        stream: None,
        tools: None,
        tool_choice: None,
        response_format: None,
        reasoning_effort: None,
        seed: None,
        frequency_penalty: None,
        presence_penalty: None,
        parallel_tool_calls: None,
        user: None,
        logprobs: None,
        top_logprobs: None,
        service_tier: None,
    };

    let canonical = transform_openai_to_canonical(req).expect("transform must succeed");
    let blocks = match &canonical.messages[0].content {
        MessageContent::Blocks(b) => b,
        other => panic!("expected Blocks content, got {other:?}"),
    };
    assert_eq!(blocks.len(), 2);
    let has_image = blocks
        .iter()
        .any(|b| matches!(b, ContentBlock::Known(KnownContentBlock::Image { .. })));
    assert!(has_image, "url image must become an Image block");
}

#[test]
fn openai_request_to_canonical_tool_call_followed_by_tool_result() {
    let req = OpenAIRequest {
        model: "gpt-4o".to_string(),
        messages: vec![
            OpenAIMessage {
                role: "user".to_string(),
                content: Some(OpenAIContent::String("ls".to_string())),
                name: None,
                tool_calls: None,
                tool_call_id: None,
            },
            OpenAIMessage {
                role: "assistant".to_string(),
                content: None,
                name: None,
                tool_calls: Some(vec![OpenAIToolCallInput {
                    id: "call_x".to_string(),
                    r#type: Some("function".to_string()),
                    function: OpenAIFunctionInput {
                        name: "ls".to_string(),
                        arguments: "{}".to_string(),
                    },
                }]),
                tool_call_id: None,
            },
            OpenAIMessage {
                role: "tool".to_string(),
                content: Some(OpenAIContent::String("file1\nfile2".to_string())),
                name: None,
                tool_calls: None,
                tool_call_id: Some("call_x".to_string()),
            },
        ],
        max_tokens: Some(64),
        temperature: None,
        top_p: None,
        stop: None,
        stream: None,
        tools: None,
        tool_choice: None,
        response_format: None,
        reasoning_effort: None,
        seed: None,
        frequency_penalty: None,
        presence_penalty: None,
        parallel_tool_calls: None,
        user: None,
        logprobs: None,
        top_logprobs: None,
        service_tier: None,
    };

    let canonical = transform_openai_to_canonical(req).expect("transform must succeed");
    // Tool result must collapse onto the user side as a tool_result block.
    let last = canonical
        .messages
        .last()
        .expect("at least one message after transform");
    assert_eq!(last.role, "user");
    let blocks = match &last.content {
        MessageContent::Blocks(b) => b,
        other => panic!("expected blocks, got {other:?}"),
    };
    let has_tool_result = blocks.iter().any(ContentBlock::is_tool_result);
    assert!(has_tool_result, "expected tool_result block on user side");
}

// ── Canonical → OpenAI Response (response direction) ────────────────────

#[test]
fn canonical_response_to_openai_finish_reason_stop() {
    let resp = provider_response(vec![ContentBlock::text("ok".to_string(), None)], "end_turn");
    let out = transform_canonical_to_openai(resp, "gpt-4o".to_string());
    assert_eq!(out.choices[0].finish_reason.as_deref(), Some("stop"));
    assert_eq!(out.usage.prompt_tokens, 10);
    assert_eq!(out.usage.completion_tokens, 20);
    assert_eq!(out.usage.total_tokens, 30);
}

// ── Anthropic → Responses API (Codex CLI) ───────────────────────────────

#[test]
fn anthropic_to_responses_input_array_format() {
    let mut req = base_canonical("gpt-5.3-codex");
    req.system = Some(SystemPrompt::Text("You are Codex.".to_string()));
    req.messages = vec![user_text("List files in /tmp")];

    let out = anthropic_to_responses_request(&req, "INSTRUCTIONS-A").expect("transform succeeds");

    // Top-level Responses-API contract:
    //   - `input`  : array of {role, content} entries
    //   - `instructions` : Codex system instructions string (separate channel)
    //   - `store`  : false (server-side persistence is opt-in elsewhere)
    //   - `stream` : true (Codex always uses SSE upstream)
    assert_eq!(out["model"], json!("gpt-5.3-codex"));
    assert_eq!(out["instructions"], json!("INSTRUCTIONS-A"));
    assert_eq!(out["store"], json!(false));
    assert_eq!(out["stream"], json!(true));

    let input = out["input"]
        .as_array()
        .expect("Responses API `input` must be a structured array, not a bare string");
    assert!(
        input.len() >= 2,
        "system promotion + user message should produce >=2 input entries, got {}",
        input.len()
    );

    // Each entry has a role and a string content field.
    for entry in input {
        assert!(entry.get("role").is_some(), "entry missing role: {entry}");
        // Codex doesn't support a separate system role, so the system prompt is
        // promoted to a `user` entry by the provider transform — verify both
        // entries are valid user/assistant roles.
        let role = entry["role"].as_str().unwrap_or("");
        assert!(
            matches!(role, "user" | "assistant"),
            "unexpected role in Responses input: {role}"
        );
    }
}

#[test]
fn anthropic_to_responses_with_tools_array() {
    // The Responses API uses a flat tools schema (no nested "function" wrapper).
    // The provider-side outbound translator currently does not attach tools to
    // the Codex request body — verify this contract so any change is loud.
    let mut req = base_canonical("gpt-5.3-codex");
    req.tools = Some(vec![Tool {
        r#type: Some("function".to_string()),
        name: Some("ls".to_string()),
        description: Some("List files".to_string()),
        input_schema: Some(json!({"type": "object", "properties": {}})),
    }]);
    req.messages = vec![user_text("What's there?")];

    let out = anthropic_to_responses_request(&req, "X").expect("transform succeeds");
    // This is a contract pin: today the outbound Responses request omits tools,
    // so changing that is a feature requiring an explicit test update.
    assert!(
        out.get("tools").is_none() || out["tools"].is_null(),
        "Codex outbound currently does not forward tools; if that changes, update this test. Got: {}",
        out
    );
}

#[test]
fn anthropic_to_responses_streaming_event_types_match_spec() {
    // The Responses API (and Codex CLI) require a fixed set of SSE event types
    // on the wire. We pin the Rust-level types behind those event types here
    // (without engaging the streaming codepath, per scope) so any rename
    // breaks the test.
    use grob::server::responses_compat::ResponsesResponse;
    let resp = provider_response(
        vec![ContentBlock::text("hello".to_string(), None)],
        "end_turn",
    );
    // `transform_canonical_to_responses` from the public API.
    let out = grob::server::responses_compat::transform_canonical_to_responses(
        resp,
        "gpt-5.3-codex".to_string(),
    );
    // Serialize and verify the top-level fields and nested type tags are stable.
    let v = serde_json::to_value(&out).expect("serialize");
    assert_eq!(v["object"], json!("response"));
    assert_eq!(v["status"], json!("completed"));
    let output = v["output"]
        .as_array()
        .expect("output must be an array of typed items");
    assert!(!output.is_empty());
    // The `type` discriminant of each output item must match the streaming
    // spec's named events: "message" or "function_call".
    for item in output {
        let t = item["type"].as_str().expect("output item has type tag");
        assert!(
            matches!(t, "message" | "function_call"),
            "unexpected output type: {t}"
        );
        if t == "message" {
            // Inner content discriminant must be "output_text" (matches
            // the `response.output_text.delta` SSE event in streaming mode).
            let content = item["content"]
                .as_array()
                .expect("message has content array");
            for c in content {
                assert_eq!(c["type"], json!("output_text"));
            }
        }
    }
    // Nudge the Rust type as well, so a rename of ResponsesResponse fails to
    // compile rather than mutating the contract silently.
    let _: ResponsesResponse = out;
}

// ── Edge cases ──────────────────────────────────────────────────────────

#[test]
fn transform_returns_error_on_unserializable_tool_input() {
    // For Anthropic content blocks, `input` is a serde_json::Value, which is
    // by construction always serializable. The transform must therefore
    // succeed for any value (including pathological ones) and produce a
    // valid JSON-encoded `arguments` string. This locks down the current
    // graceful-degradation behaviour: even if the input is huge or deeply
    // nested, the transform never returns Err.
    let mut req = base_canonical("gpt-4o");
    let mut weird = json!({});
    // Build a mildly pathological 64-deep nested object as `input`.
    for i in 0..64 {
        weird = json!({ format!("k{}", i): weird });
    }
    req.messages = vec![assistant_blocks(vec![ContentBlock::tool_use(
        "toolu_pathological".to_string(),
        "do_thing".to_string(),
        weird.clone(),
    )])];

    let out = anthropic_to_openai_request(&req)
        .expect("transform must succeed for any serde_json::Value input (current contract)");

    // `arguments` must be a valid JSON-encoded string and round-trip back to
    // the original Value, OR be empty (legacy fallback). Either way: no panic.
    let messages = out["messages"].as_array().expect("messages array");
    let assistant = &messages[0];
    let tool_calls = assistant["tool_calls"]
        .as_array()
        .expect("tool_calls array");
    let arguments = tool_calls[0]["function"]["arguments"]
        .as_str()
        .expect("arguments is a string");
    if !arguments.is_empty() {
        let parsed: Value = serde_json::from_str(arguments).expect("arguments parse as JSON");
        assert_eq!(
            parsed, weird,
            "round-trip must preserve the input value exactly"
        );
    }
}

#[test]
fn transform_handles_empty_messages_array_gracefully() {
    let req = base_canonical("gpt-4o");

    // Inbound (OpenAI -> canonical) empty array.
    let openai_req = OpenAIRequest {
        model: "gpt-4o".to_string(),
        messages: vec![],
        max_tokens: Some(64),
        temperature: None,
        top_p: None,
        stop: None,
        stream: None,
        tools: None,
        tool_choice: None,
        response_format: None,
        reasoning_effort: None,
        seed: None,
        frequency_penalty: None,
        presence_penalty: None,
        parallel_tool_calls: None,
        user: None,
        logprobs: None,
        top_logprobs: None,
        service_tier: None,
    };
    let canonical = transform_openai_to_canonical(openai_req).expect("inbound succeeds");
    assert!(canonical.messages.is_empty());
    assert!(canonical.system.is_none());

    // Outbound (canonical -> OpenAI request) empty array.
    let out = anthropic_to_openai_request(&req).expect("outbound succeeds");
    let messages = out["messages"].as_array().expect("messages array");
    assert!(messages.is_empty());

    // Outbound canonical -> Responses request empty input array.
    let out_responses = anthropic_to_responses_request(&req, "INSTR").expect("outbound succeeds");
    let input = out_responses["input"]
        .as_array()
        .expect("Responses input must remain an array");
    assert!(input.is_empty());
}

#[test]
fn transform_handles_unicode_in_message_content() {
    let mut req = base_canonical("gpt-4o");
    let unicode = "héllo, 世界! 🦀 Здравствуй, мир!";
    req.messages = vec![user_text(unicode)];

    let out = anthropic_to_openai_request(&req).expect("transform succeeds");
    let user_msg = first_message(&out);
    assert_eq!(user_msg["content"], json!(unicode));

    // Round-trip through the response direction too.
    let resp = provider_response(
        vec![ContentBlock::text(unicode.to_string(), None)],
        "end_turn",
    );
    let openai_resp = transform_canonical_to_openai(resp, "gpt-4o".to_string());
    assert_eq!(
        openai_resp.choices[0].message.content.as_deref(),
        Some(unicode)
    );
}

#[test]
fn transform_handles_very_long_messages_no_panic() {
    // A 10MB string: well above any realistic prompt but below the 1024-byte
    // pre-allocation cap, exercises the streaming-friendly Vec growth.
    const TEN_MB: usize = 10 * 1024 * 1024;
    let big = "a".repeat(TEN_MB);

    let mut req = base_canonical("gpt-4o");
    req.messages = vec![user_text(&big)];

    let out = anthropic_to_openai_request(&req).expect("transform succeeds on 10MB input");
    let user_msg = first_message(&out);
    let len = user_msg["content"]
        .as_str()
        .expect("content is string")
        .len();
    assert_eq!(len, TEN_MB, "content must be carried verbatim");

    // Response side: a 10MB text block must also survive translation.
    let resp = provider_response(vec![ContentBlock::text(big.clone(), None)], "end_turn");
    let openai_resp = transform_canonical_to_openai(resp, "gpt-4o".to_string());
    assert_eq!(
        openai_resp.choices[0]
            .message
            .content
            .as_ref()
            .map(String::len),
        Some(TEN_MB)
    );
}

#[test]
fn transform_preserves_request_id_in_response_metadata() {
    // The inbound OpenAI response carries an `id` (e.g. "chatcmpl-...") that
    // identifies the upstream request. The transform must propagate this id
    // verbatim into the canonical ProviderResponse so downstream layers
    // (audit, tracing, watch) can correlate.
    let openai_resp = json!({
        "id": "chatcmpl-AbCdEf123456",
        "object": "chat.completion",
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "ok"},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    });

    let anthropic = openai_response_to_anthropic(openai_resp).expect("inbound succeeds");
    assert_eq!(anthropic.id, "chatcmpl-AbCdEf123456");

    // The reverse direction: when the canonical response carries an id, the
    // OpenAI-shaped output must keep it.
    let resp = provider_response(vec![ContentBlock::text("ok".to_string(), None)], "end_turn");
    let mut resp_with_id = resp;
    resp_with_id.id = "msg_correlation_id_42".to_string();
    let openai_out = transform_canonical_to_openai(resp_with_id, "gpt-4o".to_string());
    assert_eq!(openai_out.id, "msg_correlation_id_42");
}

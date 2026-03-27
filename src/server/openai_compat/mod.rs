//! OpenAI-compatible `/v1/chat/completions` format translation layer.
//!
//! Translates between the OpenAI Chat Completions API format and Grob's
//! canonical request/response types (structurally Anthropic Messages API).
//!
//! # Modules
//!
//! - `types` -- Request/response structs mirroring the OpenAI wire format.
//! - `transform` -- Bidirectional conversion between OpenAI and canonical formats.
//! - `stream` -- Real-time SSE event translator (Anthropic events to OpenAI chunks).
//!
//! # Data Flow
//!
//! ```text
//! OpenAI request ──► transform_openai_to_canonical ──► CanonicalRequest
//!                                                          │
//!                                                     (dispatch pipeline)
//!                                                          │
//! OpenAI response ◄── transform_canonical_to_openai ◄── ProviderResponse
//! ```
//!
//! For streaming, `AnthropicToOpenAIStream` converts Anthropic SSE events
//! (`message_start`, `content_block_delta`, etc.) into OpenAI-format
//! `chat.completion.chunk` events on the fly.

mod stream;
mod transform;
pub(crate) mod types;

// Re-export public API
pub use stream::AnthropicToOpenAIStream;
pub use transform::{transform_canonical_to_openai, transform_openai_to_canonical};
pub use types::{
    OpenAIChoice, OpenAIContent, OpenAIContentPart, OpenAIFunction, OpenAIFunctionInput,
    OpenAIImageUrl, OpenAIMessage, OpenAIRequest, OpenAIResponse, OpenAIResponseMessage,
    OpenAIToolCall, OpenAIToolCallInput, OpenAIUsage,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ContentBlock, KnownContentBlock, MessageContent, SystemPrompt};
    use crate::providers::{ProviderResponse, Usage};

    fn mock_response(content: Vec<ContentBlock>) -> ProviderResponse {
        ProviderResponse {
            id: "msg_test".to_string(),
            r#type: "message".to_string(),
            role: "assistant".to_string(),
            content,
            model: "claude-3".to_string(),
            stop_reason: Some("end_turn".to_string()),
            stop_sequence: None,
            usage: Usage {
                input_tokens: 10,
                output_tokens: 20,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        }
    }

    fn simple_openai_request(messages: Vec<OpenAIMessage>) -> OpenAIRequest {
        OpenAIRequest {
            model: "claude-3".to_string(),
            messages,
            max_tokens: Some(1024),
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
        }
    }

    #[test]
    fn test_system_message_extraction() {
        let req = simple_openai_request(vec![
            OpenAIMessage {
                role: "system".to_string(),
                content: Some(OpenAIContent::String(
                    "You are a helpful assistant.".to_string(),
                )),
                name: None,
                tool_calls: None,
                tool_call_id: None,
            },
            OpenAIMessage {
                role: "user".to_string(),
                content: Some(OpenAIContent::String("Hello".to_string())),
                name: None,
                tool_calls: None,
                tool_call_id: None,
            },
        ]);

        let result = transform_openai_to_canonical(req).unwrap();

        // System message should be extracted into the system field
        match &result.system {
            Some(SystemPrompt::Text(text)) => {
                assert_eq!(text, "You are a helpful assistant.");
            }
            other => panic!("Expected SystemPrompt::Text, got {:?}", other),
        }

        // Messages should only contain the user message, not the system message
        assert_eq!(result.messages.len(), 1);
        assert_eq!(result.messages[0].role, "user");
    }

    #[test]
    fn test_tool_call_to_anthropic() {
        let req = simple_openai_request(vec![
            OpenAIMessage {
                role: "user".to_string(),
                content: Some(OpenAIContent::String("What's the weather?".to_string())),
                name: None,
                tool_calls: None,
                tool_call_id: None,
            },
            OpenAIMessage {
                role: "assistant".to_string(),
                content: Some(OpenAIContent::String("Let me check.".to_string())),
                name: None,
                tool_calls: Some(vec![OpenAIToolCallInput {
                    id: "call_123".to_string(),
                    r#type: Some("function".to_string()),
                    function: OpenAIFunctionInput {
                        name: "get_weather".to_string(),
                        arguments: r#"{"location":"Paris"}"#.to_string(),
                    },
                }]),
                tool_call_id: None,
            },
        ]);

        let result = transform_openai_to_canonical(req).unwrap();

        // The assistant message should have blocks (text + tool_use)
        assert_eq!(result.messages.len(), 2);
        let assistant_msg = &result.messages[1];
        assert_eq!(assistant_msg.role, "assistant");

        match &assistant_msg.content {
            MessageContent::Blocks(blocks) => {
                assert_eq!(blocks.len(), 2);
                // First block: text
                match &blocks[0] {
                    ContentBlock::Known(KnownContentBlock::Text { text, .. }) => {
                        assert_eq!(text, "Let me check.");
                    }
                    other => panic!("Expected Text block, got {:?}", other),
                }
                // Second block: tool_use
                match &blocks[1] {
                    ContentBlock::Known(KnownContentBlock::ToolUse { id, name, input }) => {
                        assert_eq!(id, "call_123");
                        assert_eq!(name, "get_weather");
                        assert_eq!(input["location"], "Paris");
                    }
                    other => panic!("Expected ToolUse block, got {:?}", other),
                }
            }
            other => panic!("Expected Blocks content, got {:?}", other),
        }
    }

    #[test]
    fn test_anthropic_tool_use_to_openai() {
        let resp = mock_response(vec![
            ContentBlock::Known(KnownContentBlock::Text {
                text: "Here's the result.".to_string(),
                cache_control: None,
            }),
            ContentBlock::Known(KnownContentBlock::ToolUse {
                id: "toolu_abc".to_string(),
                name: "search".to_string(),
                input: serde_json::json!({"query": "rust"}),
            }),
        ]);

        let openai_resp = transform_canonical_to_openai(resp, "claude-3".to_string());

        assert_eq!(openai_resp.choices.len(), 1);
        let choice = &openai_resp.choices[0];

        // Text content should be present
        assert_eq!(
            choice.message.content.as_deref(),
            Some("Here's the result.")
        );

        // Tool calls should be present
        let tool_calls = choice
            .message
            .tool_calls
            .as_ref()
            .expect("Expected tool_calls");
        assert_eq!(tool_calls.len(), 1);
        assert_eq!(tool_calls[0].id, "toolu_abc");
        assert_eq!(tool_calls[0].r#type, "function");
        assert_eq!(tool_calls[0].function.name, "search");
        assert_eq!(tool_calls[0].function.arguments, r#"{"query":"rust"}"#);
    }

    #[test]
    fn test_temperature_passthrough() {
        let mut req = simple_openai_request(vec![OpenAIMessage {
            role: "user".to_string(),
            content: Some(OpenAIContent::String("Hi".to_string())),
            name: None,
            tool_calls: None,
            tool_call_id: None,
        }]);
        req.max_tokens = Some(100);
        req.temperature = Some(0.7);

        let result = transform_openai_to_canonical(req).unwrap();
        assert_eq!(result.temperature, Some(0.7));
    }

    #[test]
    fn test_stop_sequences_conversion() {
        let mut req = simple_openai_request(vec![OpenAIMessage {
            role: "user".to_string(),
            content: Some(OpenAIContent::String("Hi".to_string())),
            name: None,
            tool_calls: None,
            tool_call_id: None,
        }]);
        req.max_tokens = Some(100);
        req.stop = Some(vec!["STOP".to_string(), "END".to_string()]);

        let result = transform_openai_to_canonical(req).unwrap();
        let stop_seqs = result.stop_sequences.expect("Expected stop_sequences");
        assert_eq!(stop_seqs, vec!["STOP", "END"]);
    }

    #[test]
    fn test_streaming_flag_passthrough() {
        let mut req = simple_openai_request(vec![OpenAIMessage {
            role: "user".to_string(),
            content: Some(OpenAIContent::String("Hi".to_string())),
            name: None,
            tool_calls: None,
            tool_call_id: None,
        }]);
        req.max_tokens = Some(100);
        req.stream = Some(true);

        let result = transform_openai_to_canonical(req).unwrap();
        assert_eq!(result.stream, Some(true));
    }

    #[test]
    fn test_empty_messages_returns_empty() {
        let req = simple_openai_request(vec![]);

        let result = transform_openai_to_canonical(req).unwrap();
        assert!(result.messages.is_empty());
        assert!(result.system.is_none());
    }

    #[test]
    fn test_image_content_translation() {
        let data_uri = "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQ==";
        let req = simple_openai_request(vec![OpenAIMessage {
            role: "user".to_string(),
            content: Some(OpenAIContent::Parts(vec![
                OpenAIContentPart::Text {
                    text: "What's in this image?".to_string(),
                },
                OpenAIContentPart::ImageUrl {
                    image_url: OpenAIImageUrl {
                        url: data_uri.to_string(),
                    },
                },
            ])),
            name: None,
            tool_calls: None,
            tool_call_id: None,
        }]);

        let result = transform_openai_to_canonical(req).unwrap();
        assert_eq!(result.messages.len(), 1);

        match &result.messages[0].content {
            MessageContent::Blocks(blocks) => {
                assert_eq!(blocks.len(), 2);
                // First block: text
                match &blocks[0] {
                    ContentBlock::Known(KnownContentBlock::Text { text, .. }) => {
                        assert_eq!(text, "What's in this image?");
                    }
                    other => panic!("Expected Text block, got {:?}", other),
                }
                // Second block: image with base64 source
                match &blocks[1] {
                    ContentBlock::Known(KnownContentBlock::Image { source }) => {
                        assert_eq!(source.r#type, "base64");
                        assert_eq!(source.media_type.as_deref(), Some("image/jpeg"));
                        assert_eq!(source.data.as_deref(), Some("/9j/4AAQSkZJRgABAQ=="));
                        assert!(source.url.is_none());
                    }
                    other => panic!("Expected Image block, got {:?}", other),
                }
            }
            other => panic!("Expected Blocks content, got {:?}", other),
        }
    }

    // ── Insta snapshot tests ─────────────────────────────────

    #[test]
    fn snap_simple_user_message_to_canonical() {
        let req = simple_openai_request(vec![OpenAIMessage {
            role: "user".to_string(),
            content: Some(OpenAIContent::String("Hello, world!".to_string())),
            name: None,
            tool_calls: None,
            tool_call_id: None,
        }]);

        let canonical = transform_openai_to_canonical(req).unwrap();
        insta::assert_json_snapshot!("openai_simple_user_to_canonical", canonical);
    }

    #[test]
    fn snap_system_plus_user_to_canonical() {
        let req = simple_openai_request(vec![
            OpenAIMessage {
                role: "system".to_string(),
                content: Some(OpenAIContent::String(
                    "You are a helpful coding assistant.".to_string(),
                )),
                name: None,
                tool_calls: None,
                tool_call_id: None,
            },
            OpenAIMessage {
                role: "user".to_string(),
                content: Some(OpenAIContent::String("Write a Rust function.".to_string())),
                name: None,
                tool_calls: None,
                tool_call_id: None,
            },
        ]);

        let canonical = transform_openai_to_canonical(req).unwrap();
        insta::assert_json_snapshot!("openai_system_user_to_canonical", canonical);
    }

    #[test]
    fn snap_tool_call_roundtrip_to_canonical() {
        let req = simple_openai_request(vec![
            OpenAIMessage {
                role: "user".to_string(),
                content: Some(OpenAIContent::String("What's the weather?".to_string())),
                name: None,
                tool_calls: None,
                tool_call_id: None,
            },
            OpenAIMessage {
                role: "assistant".to_string(),
                content: None,
                name: None,
                tool_calls: Some(vec![OpenAIToolCallInput {
                    id: "call_abc123".to_string(),
                    r#type: Some("function".to_string()),
                    function: OpenAIFunctionInput {
                        name: "get_weather".to_string(),
                        arguments: r#"{"location":"Paris","units":"celsius"}"#.to_string(),
                    },
                }]),
                tool_call_id: None,
            },
            OpenAIMessage {
                role: "tool".to_string(),
                content: Some(OpenAIContent::String(
                    r#"{"temperature": 22, "condition": "sunny"}"#.to_string(),
                )),
                name: None,
                tool_calls: None,
                tool_call_id: Some("call_abc123".to_string()),
            },
        ]);

        let canonical = transform_openai_to_canonical(req).unwrap();
        insta::assert_json_snapshot!("openai_tool_call_roundtrip_to_canonical", canonical);
    }

    #[test]
    fn snap_multipart_image_to_canonical() {
        let req = simple_openai_request(vec![OpenAIMessage {
            role: "user".to_string(),
            content: Some(OpenAIContent::Parts(vec![
                OpenAIContentPart::Text {
                    text: "Describe this image.".to_string(),
                },
                OpenAIContentPart::ImageUrl {
                    image_url: OpenAIImageUrl {
                        url: "data:image/png;base64,iVBORw0KGgo=".to_string(),
                    },
                },
            ])),
            name: None,
            tool_calls: None,
            tool_call_id: None,
        }]);

        let canonical = transform_openai_to_canonical(req).unwrap();
        insta::assert_json_snapshot!("openai_multipart_image_to_canonical", canonical);
    }

    #[test]
    fn snap_canonical_text_response_to_openai() {
        let resp = mock_response(vec![ContentBlock::Known(KnownContentBlock::Text {
            text: "Hello! How can I help you today?".to_string(),
            cache_control: None,
        })]);

        let openai_resp = transform_canonical_to_openai(resp, "gpt-4o".to_string());

        // Redact the timestamp which changes every run.
        insta::assert_json_snapshot!("canonical_text_to_openai", openai_resp, {
            ".created" => "[timestamp]"
        });
    }

    #[test]
    fn snap_canonical_tool_use_response_to_openai() {
        let resp = mock_response(vec![
            ContentBlock::Known(KnownContentBlock::Text {
                text: "Let me search for that.".to_string(),
                cache_control: None,
            }),
            ContentBlock::Known(KnownContentBlock::ToolUse {
                id: "toolu_01XYZ".to_string(),
                name: "web_search".to_string(),
                input: serde_json::json!({"query": "Rust async runtime"}),
            }),
        ]);

        let openai_resp = transform_canonical_to_openai(resp, "gpt-4o".to_string());

        insta::assert_json_snapshot!("canonical_tool_use_to_openai", openai_resp, {
            ".created" => "[timestamp]"
        });
    }

    #[test]
    fn snap_stop_reason_mapping() {
        // Verify each Anthropic stop reason maps correctly to OpenAI format.
        let reasons = vec![
            ("end_turn", "stop"),
            ("max_tokens", "length"),
            ("stop_sequence", "stop"),
            ("tool_use", "tool_calls"),
        ];

        let mut mapped: Vec<(&str, &str)> = Vec::new();
        for (anthropic, expected_openai) in &reasons {
            let resp = ProviderResponse {
                id: "msg_test".to_string(),
                r#type: "message".to_string(),
                role: "assistant".to_string(),
                content: vec![ContentBlock::text("ok".to_string(), None)],
                model: "claude-3".to_string(),
                stop_reason: Some(anthropic.to_string()),
                stop_sequence: None,
                usage: Usage {
                    input_tokens: 1,
                    output_tokens: 1,
                    cache_creation_input_tokens: None,
                    cache_read_input_tokens: None,
                },
            };
            let oai = transform_canonical_to_openai(resp, "gpt-4o".to_string());
            let actual = oai.choices[0].finish_reason.as_deref().unwrap();
            assert_eq!(actual, *expected_openai);
            mapped.push((anthropic, expected_openai));
        }

        insta::assert_yaml_snapshot!("stop_reason_mapping", mapped);
    }

    #[test]
    fn snap_openai_tools_to_canonical() {
        let mut req = simple_openai_request(vec![OpenAIMessage {
            role: "user".to_string(),
            content: Some(OpenAIContent::String("Call the tool.".to_string())),
            name: None,
            tool_calls: None,
            tool_call_id: None,
        }]);
        req.tools = Some(vec![serde_json::json!({
            "type": "function",
            "function": {
                "name": "get_stock_price",
                "description": "Retrieves the current stock price.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "symbol": {
                            "type": "string",
                            "description": "Ticker symbol"
                        }
                    },
                    "required": ["symbol"]
                }
            }
        })]);
        req.tool_choice = Some(serde_json::json!("required"));

        let canonical = transform_openai_to_canonical(req).unwrap();
        insta::assert_json_snapshot!("openai_tools_to_canonical", canonical);
    }
}

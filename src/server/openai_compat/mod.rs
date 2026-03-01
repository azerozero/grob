//! OpenAI-compatible endpoint: /v1/chat/completions format translation.

mod stream;
mod transform;
pub(crate) mod types;

// Re-export public API
pub use stream::AnthropicToOpenAIStream;
pub use transform::{transform_anthropic_to_openai, transform_openai_to_anthropic};
pub use types::*;

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

        let result = transform_openai_to_anthropic(req).unwrap();

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

        let result = transform_openai_to_anthropic(req).unwrap();

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

        let openai_resp = transform_anthropic_to_openai(resp, "claude-3".to_string());

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
        let req = OpenAIRequest {
            model: "claude-3".to_string(),
            messages: vec![OpenAIMessage {
                role: "user".to_string(),
                content: Some(OpenAIContent::String("Hi".to_string())),
                name: None,
                tool_calls: None,
                tool_call_id: None,
            }],
            max_tokens: Some(100),
            temperature: Some(0.7),
            top_p: None,
            stop: None,
            stream: None,
            tools: None,
            tool_choice: None,
        };

        let result = transform_openai_to_anthropic(req).unwrap();
        assert_eq!(result.temperature, Some(0.7));
    }

    #[test]
    fn test_stop_sequences_conversion() {
        let req = OpenAIRequest {
            model: "claude-3".to_string(),
            messages: vec![OpenAIMessage {
                role: "user".to_string(),
                content: Some(OpenAIContent::String("Hi".to_string())),
                name: None,
                tool_calls: None,
                tool_call_id: None,
            }],
            max_tokens: Some(100),
            temperature: None,
            top_p: None,
            stop: Some(vec!["STOP".to_string(), "END".to_string()]),
            stream: None,
            tools: None,
            tool_choice: None,
        };

        let result = transform_openai_to_anthropic(req).unwrap();
        let stop_seqs = result.stop_sequences.expect("Expected stop_sequences");
        assert_eq!(stop_seqs, vec!["STOP", "END"]);
    }

    #[test]
    fn test_streaming_flag_passthrough() {
        let req = OpenAIRequest {
            model: "claude-3".to_string(),
            messages: vec![OpenAIMessage {
                role: "user".to_string(),
                content: Some(OpenAIContent::String("Hi".to_string())),
                name: None,
                tool_calls: None,
                tool_call_id: None,
            }],
            max_tokens: Some(100),
            temperature: None,
            top_p: None,
            stop: None,
            stream: Some(true),
            tools: None,
            tool_choice: None,
        };

        let result = transform_openai_to_anthropic(req).unwrap();
        assert_eq!(result.stream, Some(true));
    }

    #[test]
    fn test_empty_messages_returns_empty() {
        let req = simple_openai_request(vec![]);

        let result = transform_openai_to_anthropic(req).unwrap();
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

        let result = transform_openai_to_anthropic(req).unwrap();
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
}

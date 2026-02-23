use grob::models::{
    AnthropicRequest, ContentBlock, KnownContentBlock, MessageContent, SystemPrompt,
};
use serde_json::{json, Value};

#[test]
fn test_cache_control_serialization_round_trip() {
    // Test that cache_control survives round-trip serialization
    let original_request = json!({
        "max_tokens": 100,
        "model": "claude-3-5-sonnet-20241022",
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": "Test content",
                        "cache_control": {"type": "ephemeral"}
                    }
                ]
            }
        ],
        "system": [
            {
                "type": "text",
                "text": "System prompt",
                "cache_control": {"type": "ephemeral"}
            }
        ]
    });

    // First deserialization
    let deserialized: AnthropicRequest = serde_json::from_value(original_request.clone()).unwrap();

    // Serialize back to JSON
    let reserialized = serde_json::to_value(&deserialized).unwrap();

    // Verify cache_control is preserved
    let message_cache = reserialized.get("messages").unwrap().as_array().unwrap()[0]
        .get("content")
        .unwrap()
        .as_array()
        .unwrap()[0]
        .get("cache_control");

    assert!(
        message_cache.is_some(),
        "Message cache_control should be preserved"
    );
    assert_eq!(message_cache.unwrap(), &json!({"type": "ephemeral"}));

    let system_cache =
        reserialized.get("system").unwrap().as_array().unwrap()[0].get("cache_control");

    assert!(
        system_cache.is_some(),
        "System cache_control should be preserved"
    );
    assert_eq!(system_cache.unwrap(), &json!({"type": "ephemeral"}));
}

#[test]
fn test_cache_control_none_omitted_from_serialization() {
    // Test that cache_control: None is not included in serialized output
    let block_with_none = ContentBlock::text("Test".to_string(), None);

    let serialized = serde_json::to_string(&block_with_none).unwrap();
    let parsed: Value = serde_json::from_str(&serialized).unwrap();

    assert!(
        parsed.get("cache_control").is_none(),
        "cache_control: None should not appear in serialized output"
    );

    // Verify the structure is still valid
    assert_eq!(parsed.get("type").unwrap(), "text");
    assert_eq!(parsed.get("text").unwrap(), "Test");
}

#[test]
fn test_cache_control_some_included_in_serialization() {
    // Test that cache_control: Some(...) is included in serialized output
    let block_with_some =
        ContentBlock::text("Test".to_string(), Some(json!({"type": "ephemeral"})));

    let serialized = serde_json::to_string(&block_with_some).unwrap();
    let parsed: Value = serde_json::from_str(&serialized).unwrap();

    assert!(
        parsed.get("cache_control").is_some(),
        "cache_control: Some(...) should appear in serialized output"
    );
    assert_eq!(
        parsed.get("cache_control").unwrap(),
        &json!({"type": "ephemeral"})
    );
}

#[test]
fn test_multiple_content_blocks_mixed_caching() {
    // Test multiple content blocks with mixed caching behavior
    let request = json!({
        "max_tokens": 100,
        "model": "claude-3-5-sonnet-20241022",
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": "Cached content",
                        "cache_control": {"type": "ephemeral"}
                    },
                    {
                        "type": "text",
                        "text": "Non-cached content"
                    },
                    {
                        "type": "text",
                        "text": "Another cached",
                        "cache_control": {"type": "ephemeral"}
                    }
                ]
            }
        ]
    });

    let deserialized: AnthropicRequest = serde_json::from_value(request).unwrap();

    match &deserialized.messages[0].content {
        MessageContent::Blocks(blocks) => {
            assert_eq!(blocks.len(), 3);

            // First block has cache_control
            match &blocks[0] {
                ContentBlock::Known(KnownContentBlock::Text {
                    text,
                    cache_control,
                }) => {
                    assert_eq!(text, "Cached content");
                    assert!(cache_control.is_some());
                }
                _ => panic!("Expected Text block"),
            }

            // Second block has no cache_control
            match &blocks[1] {
                ContentBlock::Known(KnownContentBlock::Text {
                    text,
                    cache_control,
                }) => {
                    assert_eq!(text, "Non-cached content");
                    assert!(cache_control.is_none());
                }
                _ => panic!("Expected Text block"),
            }

            // Third block has cache_control
            match &blocks[2] {
                ContentBlock::Known(KnownContentBlock::Text {
                    text,
                    cache_control,
                }) => {
                    assert_eq!(text, "Another cached");
                    assert!(cache_control.is_some());
                }
                _ => panic!("Expected Text block"),
            }
        }
        _ => panic!("Expected blocks"),
    }
}

#[test]
fn test_cache_control_with_complex_nested_structure() {
    // Test cache_control with complex nested JSON values
    let complex_cache_control = json!({
        "type": "ephemeral",
        "ttl": 300,
        "metadata": {
            "source": "test",
            "version": "1.0"
        }
    });

    let request = json!({
        "max_tokens": 100,
        "model": "claude-3-5-sonnet-20241022",
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": "Test with complex cache control",
                        "cache_control": complex_cache_control
                    }
                ]
            }
        ]
    });

    let deserialized: AnthropicRequest = serde_json::from_value(request).unwrap();

    match &deserialized.messages[0].content {
        MessageContent::Blocks(blocks) => match &blocks[0] {
            ContentBlock::Known(KnownContentBlock::Text {
                text,
                cache_control,
            }) => {
                assert_eq!(text, "Test with complex cache control");
                assert!(cache_control.is_some());

                let cache_ctrl = cache_control.as_ref().unwrap();
                assert_eq!(cache_ctrl.get("type").unwrap(), "ephemeral");
                assert_eq!(cache_ctrl.get("ttl").unwrap(), 300);

                let metadata = cache_ctrl.get("metadata").unwrap();
                assert_eq!(metadata.get("source").unwrap(), "test");
                assert_eq!(metadata.get("version").unwrap(), "1.0");
            }
            _ => panic!("Expected Text block"),
        },
        _ => panic!("Expected blocks"),
    }
}

#[test]
fn test_image_blocks_dont_have_cache_control() {
    // Verify that image blocks don't interfere with cache_control handling
    let request = json!({
        "max_tokens": 100,
        "model": "claude-3-5-sonnet-20241022",
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": "Text before image",
                        "cache_control": {"type": "ephemeral"}
                    },
                    {
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": "image/png",
                            "data": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
                        }
                    },
                    {
                        "type": "text",
                        "text": "Text after image",
                        "cache_control": {"type": "ephemeral"}
                    }
                ]
            }
        ]
    });

    let deserialized: AnthropicRequest = serde_json::from_value(request).unwrap();

    match &deserialized.messages[0].content {
        MessageContent::Blocks(blocks) => {
            assert_eq!(blocks.len(), 3);

            // First text block
            match &blocks[0] {
                ContentBlock::Known(KnownContentBlock::Text {
                    text,
                    cache_control,
                }) => {
                    assert_eq!(text, "Text before image");
                    assert!(cache_control.is_some());
                }
                _ => panic!("Expected Text block"),
            }

            // Image block
            match &blocks[1] {
                ContentBlock::Known(KnownContentBlock::Image { source }) => {
                    assert_eq!(source.r#type, "base64");
                    assert!(source.data.is_some());
                }
                _ => panic!("Expected Image block"),
            }

            // Last text block
            match &blocks[2] {
                ContentBlock::Known(KnownContentBlock::Text {
                    text,
                    cache_control,
                }) => {
                    assert_eq!(text, "Text after image");
                    assert!(cache_control.is_some());
                }
                _ => panic!("Expected Text block"),
            }
        }
        _ => panic!("Expected blocks"),
    }
}

#[test]
fn test_tool_use_and_tool_result_blocks_ignore_cache_control() {
    // Test that tool blocks work correctly alongside cached text blocks
    let request = json!({
        "max_tokens": 100,
        "model": "claude-3-5-sonnet-20241022",
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": "Before tool use",
                        "cache_control": {"type": "ephemeral"}
                    },
                    {
                        "type": "tool_use",
                        "id": "tool_123",
                        "name": "test_tool",
                        "input": {"param": "value"}
                    },
                    {
                        "type": "text",
                        "text": "After tool use",
                        "cache_control": {"type": "ephemeral"}
                    }
                ]
            }
        ]
    });

    let deserialized: AnthropicRequest = serde_json::from_value(request).unwrap();

    match &deserialized.messages[0].content {
        MessageContent::Blocks(blocks) => {
            assert_eq!(blocks.len(), 3);

            // First text block with cache_control
            match &blocks[0] {
                ContentBlock::Known(KnownContentBlock::Text {
                    text,
                    cache_control,
                }) => {
                    assert_eq!(text, "Before tool use");
                    assert!(cache_control.is_some());
                }
                _ => panic!("Expected Text block"),
            }

            // Tool use block
            match &blocks[1] {
                ContentBlock::Known(KnownContentBlock::ToolUse { id, name, input }) => {
                    assert_eq!(id, "tool_123");
                    assert_eq!(name, "test_tool");
                    assert_eq!(input.get("param").unwrap(), "value");
                }
                _ => panic!("Expected ToolUse block"),
            }

            // Last text block with cache_control
            match &blocks[2] {
                ContentBlock::Known(KnownContentBlock::Text {
                    text,
                    cache_control,
                }) => {
                    assert_eq!(text, "After tool use");
                    assert!(cache_control.is_some());
                }
                _ => panic!("Expected Text block"),
            }
        }
        _ => panic!("Expected blocks"),
    }
}

#[test]
fn test_system_prompt_blocks_mixed_with_messages() {
    // Test that both system and message cache_control work together
    let request = json!({
        "max_tokens": 100,
        "model": "claude-3-5-sonnet-20241022",
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": "User message",
                        "cache_control": {"type": "ephemeral"}
                    }
                ]
            }
        ],
        "system": [
            {
                "type": "text",
                "text": "System prompt",
                "cache_control": {"type": "ephemeral"}
            },
            {
                "type": "text",
                "text": "Additional system text"
            }
        ]
    });

    let deserialized: AnthropicRequest = serde_json::from_value(request).unwrap();

    // Check system blocks
    if let Some(system) = &deserialized.system {
        match system {
            SystemPrompt::Blocks(blocks) => {
                assert_eq!(blocks.len(), 2);

                // First system block has cache_control
                assert!(blocks[0].cache_control.is_some());

                // Second system block doesn't have cache_control
                assert!(blocks[1].cache_control.is_none());
            }
            _ => panic!("Expected system blocks"),
        }
    }

    // Check message blocks
    match &deserialized.messages[0].content {
        MessageContent::Blocks(blocks) => {
            assert_eq!(blocks.len(), 1);
            match &blocks[0] {
                ContentBlock::Known(KnownContentBlock::Text { cache_control, .. }) => {
                    assert!(cache_control.is_some());
                }
                _ => panic!("Expected Text block"),
            }
        }
        _ => panic!("Expected blocks"),
    }
}

#[test]
fn test_empty_cache_control_object() {
    // Test that empty cache_control object is preserved
    let request = json!({
        "max_tokens": 100,
        "model": "claude-3-5-sonnet-20241022",
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": "Test",
                        "cache_control": {}
                    }
                ]
            }
        ]
    });

    let deserialized: AnthropicRequest = serde_json::from_value(request).unwrap();

    match &deserialized.messages[0].content {
        MessageContent::Blocks(blocks) => match &blocks[0] {
            ContentBlock::Known(KnownContentBlock::Text { cache_control, .. }) => {
                assert!(cache_control.is_some());
                let cache_ctrl = cache_control.as_ref().unwrap();
                assert!(cache_ctrl.is_object());
                assert!(cache_ctrl.as_object().unwrap().is_empty());
            }
            _ => panic!("Expected Text block"),
        },
        _ => panic!("Expected blocks"),
    }
}

#[test]
fn test_cache_control_backward_compatibility() {
    // Test that requests without cache_control still work
    let request_without_cache = json!({
        "max_tokens": 100,
        "model": "claude-3-5-sonnet-20241022",
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": "Old format without cache_control"
                    }
                ]
            }
        ],
        "system": [
            {
                "type": "text",
                "text": "Old system prompt"
            }
        ]
    });

    let deserialized: AnthropicRequest = serde_json::from_value(request_without_cache).unwrap();

    // Should work without any issues
    match &deserialized.messages[0].content {
        MessageContent::Blocks(blocks) => match &blocks[0] {
            ContentBlock::Known(KnownContentBlock::Text {
                text,
                cache_control,
            }) => {
                assert_eq!(text, "Old format without cache_control");
                assert!(cache_control.is_none());
            }
            _ => panic!("Expected Text block"),
        },
        _ => panic!("Expected blocks"),
    }

    // System should also work
    if let Some(system) = &deserialized.system {
        match system {
            SystemPrompt::Blocks(blocks) => {
                assert_eq!(blocks[0].text, "Old system prompt");
                assert!(blocks[0].cache_control.is_none());
            }
            _ => panic!("Expected system blocks"),
        }
    }
}

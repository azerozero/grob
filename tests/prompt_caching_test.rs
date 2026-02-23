use grob::models::{
    AnthropicRequest, ContentBlock, KnownContentBlock, MessageContent, SystemPrompt,
};
use serde_json::json;

#[test]
fn test_prompt_caching_preservation() {
    // Create a request with prompt caching in both system and message blocks
    let request_with_caching = json!({
        "model": "claude-3-5-sonnet-20241022",
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": "This content should be cached",
                        "cache_control": {"type": "ephemeral"}
                    },
                    {
                        "type": "text",
                        "text": "This content should not be cached"
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
        ],
        "max_tokens": 100
    });

    // Deserialize the request
    let anthropic_request: AnthropicRequest = serde_json::from_value(request_with_caching).unwrap();

    // Verify system caching is preserved
    if let Some(system) = &anthropic_request.system {
        match system {
            SystemPrompt::Blocks(blocks) => {
                assert_eq!(blocks.len(), 1);
                let system_block = &blocks[0];
                assert_eq!(system_block.text, "System prompt");
                assert!(
                    system_block.cache_control.is_some(),
                    "System cache_control should be preserved"
                );
            }
            _ => panic!("Expected system blocks"),
        }
    }

    // Verify message content caching is preserved
    assert_eq!(anthropic_request.messages.len(), 1);
    let message = &anthropic_request.messages[0];

    match &message.content {
        MessageContent::Blocks(blocks) => {
            assert_eq!(blocks.len(), 2);

            // First block should have cache_control
            match &blocks[0] {
                ContentBlock::Known(KnownContentBlock::Text {
                    text,
                    cache_control,
                }) => {
                    assert_eq!(text, "This content should be cached");
                    assert!(
                        cache_control.is_some(),
                        "Message content cache_control should be preserved"
                    );

                    // Verify cache_control structure
                    let cache_control = cache_control.as_ref().unwrap();
                    if let Some(cache_type) = cache_control.get("type") {
                        assert_eq!(cache_type, "ephemeral");
                    } else {
                        panic!("cache_control should have type field");
                    }
                }
                _ => panic!("Expected Text content block"),
            }

            // Second block should not have cache_control
            match &blocks[1] {
                ContentBlock::Known(KnownContentBlock::Text {
                    text,
                    cache_control,
                }) => {
                    assert_eq!(text, "This content should not be cached");
                    assert!(
                        cache_control.is_none(),
                        "Non-cached content should not have cache_control"
                    );
                }
                _ => panic!("Expected Text content block"),
            }
        }
        _ => panic!("Expected message content blocks"),
    }

    // Test serialization preserves cache_control
    let serialized = serde_json::to_string(&anthropic_request).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&serialized).unwrap();

    // Verify cache_control is present in serialized output
    if let Some(messages) = parsed.get("messages").and_then(|m| m.as_array()) {
        assert_eq!(messages.len(), 1);
        if let Some(content) = messages[0].get("content").and_then(|c| c.as_array()) {
            assert_eq!(content.len(), 2);

            // First content block should have cache_control
            let first_block = &content[0];
            assert!(
                first_block.get("cache_control").is_some(),
                "Serialized content should preserve cache_control"
            );

            // Second content block should not have cache_control
            let second_block = &content[1];
            assert!(
                second_block.get("cache_control").is_none(),
                "Non-cached content should not have cache_control in serialization"
            );
        }
    }

    // Verify system cache_control is also preserved in serialization
    if let Some(system) = parsed.get("system").and_then(|s| s.as_array()) {
        assert_eq!(system.len(), 1);
        let system_block = &system[0];
        assert!(
            system_block.get("cache_control").is_some(),
            "Serialized system should preserve cache_control"
        );
    }
}

#[test]
fn test_passthrough_caching_behavior() {
    // Test that when ContentBlock::text is constructed with cache_control: None,
    // it doesn't show up in serialized output (due to skip_serializing_if)
    let text_block_without_caching = ContentBlock::text("Regular text".to_string(), None);

    let text_block_with_caching = ContentBlock::text(
        "Cached text".to_string(),
        Some(json!({"type": "ephemeral"})),
    );

    // Serialize both blocks
    let serialized_without = serde_json::to_string(&text_block_without_caching).unwrap();
    let serialized_with = serde_json::to_string(&text_block_with_caching).unwrap();

    let parsed_without: serde_json::Value = serde_json::from_str(&serialized_without).unwrap();
    let parsed_with: serde_json::Value = serde_json::from_str(&serialized_with).unwrap();

    // Verify cache_control is absent when None
    assert!(
        parsed_without.get("cache_control").is_none(),
        "None cache_control should not appear in serialization"
    );

    // Verify cache_control is present when Some
    assert!(
        parsed_with.get("cache_control").is_some(),
        "Some(cache_control) should appear in serialization"
    );
}

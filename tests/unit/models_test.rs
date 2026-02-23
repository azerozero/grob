//! Unit tests for the models module

mod tests {
    use grob::models::{Message, MessageContent, RouteDecision, RouteType};

    #[test]
    fn test_route_decision_default() {
        let decision = RouteDecision {
            model_name: "test-model".to_string(),
            route_type: RouteType::Default,
            matched_prompt: None,
        };

        assert_eq!(decision.model_name, "test-model");
        assert_eq!(decision.route_type, RouteType::Default);
    }

    #[test]
    fn test_route_decision_with_prompt() {
        let decision = RouteDecision {
            model_name: "fast-model".to_string(),
            route_type: RouteType::PromptRule,
            matched_prompt: Some("[fast]".to_string()),
        };

        assert_eq!(decision.route_type, RouteType::PromptRule);
        assert_eq!(decision.matched_prompt, Some("[fast]".to_string()));
    }

    #[test]
    fn test_message_content_text() {
        let message = Message {
            role: "user".to_string(),
            content: MessageContent::Text("Hello world".to_string()),
        };

        if let MessageContent::Text(text) = message.content {
            assert_eq!(text, "Hello world");
        } else {
            panic!("Expected Text content");
        }
    }

    #[test]
    fn test_message_content_blocks() {
        use grob::models::ContentBlock;

        let message = Message {
            role: "user".to_string(),
            content: MessageContent::Blocks(vec![ContentBlock::text("Hello".to_string(), None)]),
        };

        if let MessageContent::Blocks(blocks) = message.content {
            assert_eq!(blocks.len(), 1);
        } else {
            panic!("Expected Blocks content");
        }
    }

    #[test]
    fn test_route_type_display() {
        assert_eq!(RouteType::Default.to_string(), "default");
        assert_eq!(RouteType::Think.to_string(), "think");
        assert_eq!(RouteType::WebSearch.to_string(), "web-search");
        assert_eq!(RouteType::Background.to_string(), "background");
        assert_eq!(RouteType::PromptRule.to_string(), "prompt-rule");
    }
}

use super::responses_request::responses_tool_output;
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
    assert!(input
        .iter()
        .any(|i| i["type"] == "function_call" && i["call_id"] == "toolu_1" && i["name"] == "Bash"));
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
    // ...but the content is preserved as a user item (typed-parts form).
    assert!(input.iter().any(|i| i["role"] == "user"
        && i["content"][0]["type"] == "input_text"
        && i["content"][0]["text"] == "be terse"));
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
    assert_eq!(input[0]["content"][0]["type"], "input_text");
    assert_eq!(input[0]["content"][0]["text"], "run ls");
    assert!(!input
        .iter()
        .any(|item| item["content"][0]["text"] == "FULL CODEX CLI PROMPT"));
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
        serde_json::to_value(transform_to_responses_request(&req, "X", &tuning).unwrap()).unwrap()
            ["reasoning"]["effort"]
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
        serde_json::to_value(transform_to_responses_request(&req, "X", &tuning).unwrap()).unwrap()
            ["reasoning"]["effort"]
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
        serde_json::to_value(transform_to_responses_request(&req, "X", &tuning).unwrap()).unwrap()
            ["reasoning"]["effort"]
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
        serde_json::to_value(transform_to_responses_request(req, "X", &tuning).unwrap()).unwrap()
            ["service_tier"]
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
        serde_json::to_value(transform_to_responses_request(&req, "X", &tuning).unwrap()).unwrap()
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
fn responses_request_forwards_image_blocks_as_input_image() {
    use crate::models::ImageSource;

    let mut request = base_request();
    request.model = "gpt-5.5".to_string();
    request.system = None;
    request.messages = vec![Message {
        role: "user".to_string(),
        content: MessageContent::Blocks(vec![
            ContentBlock::text("What is in this image?".to_string(), None),
            ContentBlock::Known(KnownContentBlock::Image {
                source: ImageSource {
                    r#type: "base64".to_string(),
                    media_type: Some("image/png".to_string()),
                    data: Some("aGVsbG8=".to_string()),
                    url: None,
                },
            }),
        ]),
    }];

    let opts = CodexOptions::default();
    let json = serde_json::to_value(
        transform_to_responses_request(
            &request,
            "INSTR",
            &CodexTuning::from_options(&opts, None, None),
        )
        .unwrap(),
    )
    .unwrap();

    // The text and the image share one message item, in order.
    let content = &json["input"][0]["content"];
    assert_eq!(content[0]["type"], "input_text");
    assert_eq!(content[0]["text"], "What is in this image?");
    assert_eq!(content[1]["type"], "input_image");
    assert_eq!(content[1]["image_url"], "data:image/png;base64,aGVsbG8=");
}

#[test]
fn responses_request_passes_image_url_through() {
    use crate::models::ImageSource;

    let mut request = base_request();
    request.system = None;
    request.messages = vec![Message {
        role: "user".to_string(),
        content: MessageContent::Blocks(vec![ContentBlock::Known(KnownContentBlock::Image {
            source: ImageSource {
                r#type: "url".to_string(),
                media_type: None,
                data: None,
                url: Some("https://example.com/cat.png".to_string()),
            },
        })]),
    }];

    let opts = CodexOptions::default();
    let json = serde_json::to_value(
        transform_to_responses_request(
            &request,
            "INSTR",
            &CodexTuning::from_options(&opts, None, None),
        )
        .unwrap(),
    )
    .unwrap();

    let part = &json["input"][0]["content"][0];
    assert_eq!(part["type"], "input_image");
    assert_eq!(part["image_url"], "https://example.com/cat.png");
}

#[test]
fn tool_result_text_stays_a_bare_string() {
    use crate::models::ToolResultContent;
    // Text-only results must keep the plain-string wire shape (cache-friendly).
    let out = responses_tool_output(&ToolResultContent::Text("file1\nfile2".to_string()));
    assert_eq!(out, serde_json::json!("file1\nfile2"));
}

#[test]
fn tool_result_image_survives_as_input_image() {
    use crate::models::{ImageSource, KnownToolResultBlock, ToolResultBlock, ToolResultContent};
    // A tool that returns an image: the image must reach the model as pixels,
    // not the literal "[Image]" text `Display` produced.
    let content = ToolResultContent::Blocks(vec![
        ToolResultBlock::Known(KnownToolResultBlock::Text {
            text: "screenshot:".to_string(),
        }),
        ToolResultBlock::Known(KnownToolResultBlock::Image {
            source: ImageSource {
                r#type: "base64".to_string(),
                media_type: Some("image/png".to_string()),
                data: Some("aGVsbG8=".to_string()),
                url: None,
            },
        }),
    ]);

    let out = responses_tool_output(&content);
    let parts = out
        .as_array()
        .expect("image output must be an array of parts");
    assert_eq!(parts[0]["type"], "input_text");
    assert_eq!(parts[0]["text"], "screenshot:");
    assert_eq!(parts[1]["type"], "input_image");
    assert_eq!(parts[1]["image_url"], "data:image/png;base64,aGVsbG8=");
    // No "[Image]" placeholder anywhere.
    assert!(!out.to_string().contains("[Image]"));
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
fn prompt_cache_key_is_stable_across_message_tails() {
    // The key must stay identical as a conversation grows, so every turn
    // routes to the same OpenAI prompt-cache node and hits the shared prefix.
    let opts = CodexOptions::default();
    let key = |messages: Vec<Message>| {
        let mut req = base_request();
        req.system = None;
        req.messages = messages;
        serde_json::to_value(
            transform_to_responses_request(
                &req,
                "INSTR",
                &CodexTuning::from_options(&opts, None, None),
            )
            .unwrap(),
        )
        .unwrap()["prompt_cache_key"]
            .clone()
    };
    let user = |text: &str| Message {
        role: "user".to_string(),
        content: MessageContent::Text(text.to_string()),
    };

    let turn1 = key(vec![user("first prompt")]);
    let turn2 = key(vec![
        user("first prompt"),
        Message {
            role: "assistant".to_string(),
            content: MessageContent::Text("reply".to_string()),
        },
        user("follow-up"),
    ]);

    assert!(turn1.as_str().unwrap().starts_with("grob-"));
    assert_eq!(turn1, turn2, "key must be stable as the conversation grows");
}

#[test]
fn prompt_cache_key_separates_conversations_and_instructions() {
    let opts = CodexOptions::default();
    let key = |instructions: &str, first: &str| {
        let mut req = base_request();
        req.system = None;
        req.messages = vec![Message {
            role: "user".to_string(),
            content: MessageContent::Text(first.to_string()),
        }];
        serde_json::to_value(
            transform_to_responses_request(
                &req,
                instructions,
                &CodexTuning::from_options(&opts, None, None),
            )
            .unwrap(),
        )
        .unwrap()["prompt_cache_key"]
            .clone()
    };

    // A different opening message means a different conversation → different key.
    assert_ne!(
        key("INSTR", "conversation A"),
        key("INSTR", "conversation B")
    );
    // Different system instructions also separate the cache namespace.
    assert_ne!(key("INSTR ONE", "same"), key("INSTR TWO", "same"));
}

/// One agent-loop turn: user asks, assistant calls a tool, tool answers.
fn agent_loop_request() -> CanonicalRequest {
    use crate::models::ToolResultContent;

    let mut request = base_request();
    request.model = "gpt-5.5".to_string();
    request.messages = vec![
        Message {
            role: "user".to_string(),
            content: MessageContent::Text("list files".to_string()),
        },
        Message {
            role: "assistant".to_string(),
            content: MessageContent::Blocks(vec![ContentBlock::tool_use(
                "toolu_1".to_string(),
                "Bash".to_string(),
                serde_json::json!({ "command": "ls" }),
            )]),
        },
        Message {
            role: "user".to_string(),
            content: MessageContent::Blocks(vec![ContentBlock::Known(
                KnownContentBlock::ToolResult {
                    tool_use_id: "toolu_1".to_string(),
                    content: ToolResultContent::Text("file1".to_string()),
                    is_error: false,
                    cache_control: None,
                },
            )]),
        },
    ];
    request
}

#[test]
fn reasoning_continuity_replays_the_item_just_before_its_call() {
    let request = agent_loop_request();
    let opts = CodexOptions::default();
    let store = reasoning_store::reasoning_store();

    // First turn establishes the conversation key the store is filed under.
    let first = serde_json::to_value(
        transform_to_responses_request(
            &request,
            "INSTR",
            &CodexTuning::from_options(&opts, None, None),
        )
        .unwrap(),
    )
    .unwrap();
    let conversation = first["prompt_cache_key"].as_str().unwrap().to_string();

    let item = serde_json::json!({
        "type": "reasoning",
        "id": "rs_1",
        "encrypted_content": "opaque-blob",
    });
    reasoning_store::record(
        &store,
        &conversation,
        &[("toolu_1".to_string(), vec![item.clone()])],
    );

    let json = serde_json::to_value(
        transform_to_responses_request(
            &request,
            "INSTR",
            &CodexTuning::from_options(&opts, None, None).with_reasoning_store(Some(&store)),
        )
        .unwrap(),
    )
    .unwrap();

    let input = json["input"].as_array().unwrap();
    let reasoning_at = input.iter().position(|i| i["type"] == "reasoning").unwrap();
    let call_at = input
        .iter()
        .position(|i| i["type"] == "function_call" && i["call_id"] == "toolu_1")
        .unwrap();

    // Anywhere other than immediately before its own call is a backend 400.
    assert_eq!(reasoning_at + 1, call_at);
    assert_eq!(input[reasoning_at], item);
}

#[test]
fn reasoning_continuity_is_off_without_a_store() {
    let opts = CodexOptions::default();
    let json = serde_json::to_value(
        transform_to_responses_request(
            &agent_loop_request(),
            "INSTR",
            &CodexTuning::from_options(&opts, None, None),
        )
        .unwrap(),
    )
    .unwrap();

    let input = json["input"].as_array().unwrap();
    assert!(input.iter().all(|i| i["type"] != "reasoning"));
}

#[test]
fn reasoning_from_another_conversation_is_not_replayed() {
    let request = agent_loop_request();
    let opts = CodexOptions::default();
    let store = reasoning_store::reasoning_store();

    // Same call_id, but filed under a conversation this request is not part of.
    reasoning_store::record(
        &store,
        "some-other-conversation",
        &[(
            "toolu_1".to_string(),
            vec![serde_json::json!({"type": "reasoning", "id": "rs_x"})],
        )],
    );

    let json = serde_json::to_value(
        transform_to_responses_request(
            &request,
            "INSTR",
            &CodexTuning::from_options(&opts, None, None).with_reasoning_store(Some(&store)),
        )
        .unwrap(),
    )
    .unwrap();

    let input = json["input"].as_array().unwrap();
    assert!(input.iter().all(|i| i["type"] != "reasoning"));
}

#[test]
fn reasoning_survives_a_full_capture_then_replay_round_trip() {
    use crate::models::ToolResultContent;

    let opts = CodexOptions::default();
    let store = reasoning_store::reasoning_store();
    let user = |text: &str| Message {
        role: "user".to_string(),
        content: MessageContent::Text(text.to_string()),
    };

    // ── Turn 1: the client's opening request ─────────────────────────
    let mut turn1 = base_request();
    turn1.model = "gpt-5.5".to_string();
    turn1.messages = vec![user("list files")];
    let sent1 = serde_json::to_value(
        transform_to_responses_request(
            &turn1,
            "INSTR",
            &CodexTuning::from_options(&opts, None, None).with_reasoning_store(Some(&store)),
        )
        .unwrap(),
    )
    .unwrap();
    let conversation = sent1["prompt_cache_key"].as_str().unwrap().to_string();

    // ── The backend answers with reasoning, then a tool call ─────────
    let mut state = StreamTransformState {
        capture_reasoning: true,
        ..Default::default()
    };
    for event in [
        r#"{"type":"response.created","response":{"model":"gpt-5.5"}}"#,
        r#"{"type":"response.output_item.done","output_index":0,"item":{"type":"reasoning","id":"rs_1","encrypted_content":"opaque-blob"}}"#,
        r#"{"type":"response.output_item.done","output_index":1,"item":{"type":"function_call","call_id":"toolu_1","name":"Bash","arguments":"{\"command\":\"ls\"}"}}"#,
        r#"{"type":"response.completed","response":{"status":"completed"}}"#,
    ] {
        super::super::streaming::transform_codex_event_to_anthropic_sse(
            event, "msg_1", "gpt-5.5", &mut state,
        )
        .unwrap();
    }
    reasoning_store::record(&store, &conversation, &state.captured_reasoning);

    // ── Turn 2: the client replays the grown history ─────────────────
    let mut turn2 = turn1.clone();
    turn2.messages.push(Message {
        role: "assistant".to_string(),
        content: MessageContent::Blocks(vec![ContentBlock::tool_use(
            "toolu_1".to_string(),
            "Bash".to_string(),
            serde_json::json!({ "command": "ls" }),
        )]),
    });
    turn2.messages.push(Message {
        role: "user".to_string(),
        content: MessageContent::Blocks(vec![ContentBlock::Known(KnownContentBlock::ToolResult {
            tool_use_id: "toolu_1".to_string(),
            content: ToolResultContent::Text("file1".to_string()),
            is_error: false,
            cache_control: None,
        })]),
    });
    let sent2 = serde_json::to_value(
        transform_to_responses_request(
            &turn2,
            "INSTR",
            &CodexTuning::from_options(&opts, None, None).with_reasoning_store(Some(&store)),
        )
        .unwrap(),
    )
    .unwrap();

    // The conversation key is what ties the two turns together; if it drifted
    // the lookup would silently miss and continuity would be a no-op.
    assert_eq!(sent2["prompt_cache_key"].as_str().unwrap(), conversation);

    let input = sent2["input"].as_array().unwrap();
    let reasoning_at = input.iter().position(|i| i["type"] == "reasoning").unwrap();
    assert_eq!(input[reasoning_at]["encrypted_content"], "opaque-blob");
    assert_eq!(input[reasoning_at + 1]["type"], "function_call");
    assert_eq!(input[reasoning_at + 1]["call_id"], "toolu_1");
}

#[test]
fn replayed_reasoning_keeps_the_encrypted_payload_byte_for_byte() {
    // The blob is opaque to grob; re-serializing it field by field would
    // invalidate it, so the stored value must come back out untouched.
    let request = agent_loop_request();
    let opts = CodexOptions::default();
    let store = reasoning_store::reasoning_store();

    let conversation = serde_json::to_value(
        transform_to_responses_request(
            &request,
            "INSTR",
            &CodexTuning::from_options(&opts, None, None),
        )
        .unwrap(),
    )
    .unwrap()["prompt_cache_key"]
        .as_str()
        .unwrap()
        .to_string();

    let item = serde_json::json!({
        "type": "reasoning",
        "id": "rs_1",
        "summary": [{"type": "summary_text", "text": "thought about it"}],
        "encrypted_content": "gAAAAABn+/=payload==",
        "status": "completed",
    });
    reasoning_store::record(
        &store,
        &conversation,
        &[("toolu_1".to_string(), vec![item.clone()])],
    );

    let json = serde_json::to_value(
        transform_to_responses_request(
            &request,
            "INSTR",
            &CodexTuning::from_options(&opts, None, None).with_reasoning_store(Some(&store)),
        )
        .unwrap(),
    )
    .unwrap();

    let replayed = json["input"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["type"] == "reasoning")
        .unwrap();
    assert_eq!(replayed, &item);
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
        TransformError::RequestValidation { message } => {
            panic!("unexpected request validation error: {message}");
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
fn transform_maps_request_validation_to_invalid_request() {
    let err = TransformError::RequestValidation {
        message: "invalid tool definition".to_string(),
    };
    let provider_err: ProviderError = err.into();
    assert!(
        matches!(provider_err, ProviderError::InvalidRequest(message) if message == "invalid tool definition")
    );
}

#[test]
fn transform_succeeds_when_tool_input_well_formed() {
    // Sanity check: typical tool_use blocks still translate cleanly.
    let mut req = base_request();
    req.messages = vec![Message {
        role: "assistant".to_string(),
        content: MessageContent::Blocks(vec![ContentBlock::Known(KnownContentBlock::ToolUse {
            id: "call_1".to_string(),
            name: "weather".to_string(),
            input: serde_json::json!({"city": "Paris"}),
        })]),
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

    let parsed = parse_sse_response(sse).expect("should extract content");
    let blocks = parsed.content;
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

    let parsed = parse_sse_response(sse).expect("should extract content");
    let blocks = parsed.content;
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

    let parsed = parse_sse_response(sse).expect("should extract content");
    let blocks = parsed.content;
    assert_eq!(blocks.len(), 2);
    let thinking = serde_json::to_value(&blocks[0]).expect("serialize block");
    assert_eq!(thinking["type"], "thinking");
    assert_eq!(thinking["thinking"], "weighing options");
}

#[test]
fn parse_sse_errors_when_no_content() {
    let sse = "event: response.created\ndata: {\"type\":\"response.created\"}\n";
    assert!(matches!(
        parse_sse_response(sse),
        Err(ProviderError::ProtocolError(message)) if message.contains("no content found")
    ));
}

#[test]
fn parse_sse_collects_output_text_deltas_when_done_items_are_absent() {
    let sse = concat!(
        "event: response.created\n",
        "data: {\"type\":\"response.created\"}\n\n",
        "event: response.output_text.delta\n",
        "data: {\"type\":\"response.output_text.delta\",\"delta\":\"Hel\"}\n\n",
        "event: response.output_text.delta\n",
        "data: {\"type\":\"response.output_text.delta\",\"delta\":\"lo\"}\n\n",
        "event: response.completed\n",
        "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":null}}\n",
    );

    let parsed = parse_sse_response(sse).expect("should extract delta text");
    assert_eq!(parsed.stop_reason.as_deref(), Some("end_turn"));
    let blocks = parsed.content;
    assert_eq!(blocks.len(), 1);
    let value = serde_json::to_value(&blocks[0]).expect("serialize block");
    assert_eq!(value["type"], "text");
    assert_eq!(value["text"], "Hello");
}

#[test]
fn parse_sse_incomplete_with_delta_content_maps_to_max_tokens() {
    let sse = concat!(
        "event: response.output_text.delta\n",
        "data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}\n\n",
        "event: response.incomplete\n",
        "data: {\"type\":\"response.incomplete\",\"response\":{\"status\":\"incomplete\",\"usage\":{\"input_tokens\":10,\"output_tokens\":2}}}\n",
    );

    let parsed = parse_sse_response(sse).expect("should preserve incomplete content");
    assert_eq!(parsed.stop_reason.as_deref(), Some("max_tokens"));
    assert_eq!(parsed.usage.input_tokens, 10);
    assert_eq!(parsed.usage.output_tokens, 2);
    let value = serde_json::to_value(&parsed.content[0]).expect("serialize block");
    assert_eq!(value["text"], "partial");
}

#[test]
fn parse_sse_failed_surfaces_upstream_message() {
    let sse = concat!(
        "event: response.failed\n",
        "data: {\"type\":\"response.failed\",\"response\":{\"status\":\"failed\",\"error\":{\"message\":\"boom\"}}}\n",
    );

    assert!(matches!(
        parse_sse_response(sse),
        Err(ProviderError::ProtocolError(message))
            if message.contains("response.failed") && message.contains("boom")
    ));
}

#[test]
fn parse_sse_failed_context_window_maps_to_invalid_request() {
    let sse = concat!(
        "event: response.failed\n",
        "data: {\"type\":\"response.failed\",\"response\":{\"status\":\"failed\",\"error\":{\"message\":\"Your input exceeds the context window of this model. Please adjust your input and try again.\"}}}\n",
    );

    assert!(matches!(
        parse_sse_response(sse),
        Err(ProviderError::InvalidRequest(message))
            if message.contains("context window") && message.contains("response.failed")
    ));
}

#[test]
fn parse_sse_rejects_malformed_terminal_json() {
    let sse = "event: response.completed\ndata: {not-json}\n";
    assert!(matches!(
        parse_sse_response(sse),
        Err(ProviderError::ProtocolError(message))
            if message.contains("malformed SSE JSON")
    ));
}

#[test]
fn parse_sse_builds_function_call_from_delta_events() {
    let sse = concat!(
        "event: response.output_item.added\n",
        "data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"id\":\"fc_read\",\"type\":\"function_call\",\"call_id\":\"call_read\",\"name\":\"Read\",\"arguments\":\"\"}}\n\n",
        "event: response.function_call_arguments.delta\n",
        "data: {\"type\":\"response.function_call_arguments.delta\",\"item_id\":\"fc_read\",\"output_index\":0,\"delta\":\"{\\\"file_path\\\":\\\"/tmp/SKILL.md\\\",\\\"offset\\\":0,\\\"limit\\\":2000,\\\"pages\\\":\\\"\\\"}\"}\n\n",
        "event: response.completed\n",
        "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":null}}\n",
    );

    let parsed = parse_sse_response(sse).expect("should extract pending function call");
    let value = serde_json::to_value(&parsed.content[0]).expect("serialize block");
    assert_eq!(value["type"], "tool_use");
    assert_eq!(value["name"], "Read");
    assert_eq!(value["input"]["file_path"], "/tmp/SKILL.md");
    assert!(value["input"].get("pages").is_none());
}

#[test]
fn parse_sse_preserves_responses_cached_tokens() {
    let sse = concat!(
        "event: response.completed\n",
        "data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":1000,\"output_tokens\":42,\"input_tokens_details\":{\"cached_tokens\":700}},\"output\":[{\"type\":\"message\",\"content\":[{\"type\":\"output_text\",\"text\":\"done\"}]}]}}\n",
    );

    let parsed = parse_sse_response(sse).expect("should extract content and usage");
    assert_eq!(parsed.usage.input_tokens, 300);
    assert_eq!(parsed.usage.output_tokens, 42);
    assert_eq!(parsed.usage.cache_read_input_tokens, Some(700));
    assert_eq!(parsed.usage.total_input_tokens(), 1000);
}

#[test]
fn transform_response_preserves_openai_cached_tokens() {
    let response: OpenAIResponse = serde_json::from_value(serde_json::json!({
        "id": "chatcmpl_1",
        "object": "chat.completion",
        "model": "gpt-4.1",
        "choices": [{
            "message": {"role": "assistant", "content": "ok"},
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": 1000,
            "completion_tokens": 42,
            "prompt_tokens_details": {"cached_tokens": 700}
        }
    }))
    .expect("valid response");

    let transformed = transform_response(response).expect("transform response");
    assert_eq!(transformed.usage.input_tokens, 300);
    assert_eq!(transformed.usage.output_tokens, 42);
    assert_eq!(transformed.usage.cache_read_input_tokens, Some(700));
    assert_eq!(transformed.usage.total_input_tokens(), 1000);
}

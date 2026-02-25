#![no_main]

use libfuzzer_sys::fuzz_target;

use grob::server::openai_compat::{OpenAIRequest, transform_openai_to_anthropic};

fuzz_target!(|data: &[u8]| {
    // Try to parse arbitrary bytes as JSON, then as an OpenAI request
    let json_value: serde_json::Value = match serde_json::from_slice(data) {
        Ok(v) => v,
        Err(_) => return,
    };

    // Try to deserialize the JSON value as an OpenAI ChatCompletionRequest.
    // This tests the deserialization layer with arbitrary JSON shapes.
    let openai_req: OpenAIRequest = match serde_json::from_value(json_value) {
        Ok(r) => r,
        Err(_) => return,
    };

    // Feed through the translation layer.
    // This should not panic regardless of the content of the request.
    let _ = transform_openai_to_anthropic(openai_req);
});

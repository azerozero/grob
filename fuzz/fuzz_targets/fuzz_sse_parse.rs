#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try to interpret arbitrary bytes as UTF-8 text
    let text = match std::str::from_utf8(data) {
        Ok(t) => t,
        Err(_) => return,
    };

    // Fuzz the SSE event parser with arbitrary text input.
    // The parser splits on \n\n boundaries and extracts "event:" and "data:" lines.
    let events = grob::providers::streaming::parse_sse_events(text);

    // For each parsed event, try to deserialize the data field as JSON.
    // This exercises the downstream JSON parsing that happens after SSE parsing.
    for event in &events {
        // Should never panic regardless of input
        let _ = serde_json::from_str::<serde_json::Value>(&event.data);

        // Also verify the event type field is accessible without panic
        let _ = event.event.as_deref();
    }
});

//! Criterion bench for the heuristic complexity classifier.
//!
//! Target: `classify_complexity` < 100µs per call (the "0.1 ms" stateless
//! goal stated in the routing intelligence design). Measures three
//! representative request shapes.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use grob::models::{CanonicalRequest, Message, MessageContent, SystemPrompt, Tool};
use grob::routing::classify::{classify_complexity, ScoringConfig};

fn make_request(text: &str, max_tokens: u32) -> CanonicalRequest {
    CanonicalRequest {
        model: "test-model".to_string(),
        messages: vec![Message {
            role: "user".to_string(),
            content: MessageContent::Text(text.to_string()),
        }],
        max_tokens,
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

fn dummy_tool(name: &str) -> Tool {
    Tool {
        r#type: Some("custom".to_string()),
        name: Some(name.to_string()),
        description: Some("dummy bench tool".to_string()),
        input_schema: None,
    }
}

fn bench_classify(c: &mut Criterion) {
    let config = ScoringConfig::default();

    // Trivial: short prompt, low max_tokens, no tools
    let trivial = make_request("What is 2+2?", 100);
    c.bench_function("classify_trivial", |b| {
        b.iter(|| black_box(classify_complexity(&trivial, &config)))
    });

    // Medium: ~50 words, 1 tool, mid max_tokens
    let medium_text = "Please help me refactor this Python function to be more idiomatic. \
                       It currently uses nested loops and could probably be expressed with \
                       list comprehensions or itertools, but I want to keep readability."
        .to_string();
    let mut medium = make_request(&medium_text, 1500);
    medium.tools = Some(vec![dummy_tool("read_file")]);
    c.bench_function("classify_medium", |b| {
        b.iter(|| black_box(classify_complexity(&medium, &config)))
    });

    // Complex: ~500 tokens of prompt, 5 tools, long system prompt, high max_tokens
    let complex_text = "x ".repeat(500);
    let mut complex = make_request(&complex_text, 8000);
    complex.tools = Some(vec![
        dummy_tool("read_file"),
        dummy_tool("write_file"),
        dummy_tool("search"),
        dummy_tool("execute"),
        dummy_tool("plan"),
    ]);
    complex.system = Some(SystemPrompt::Text(
        "You are an expert software engineer specialised in distributed systems. \
         Think step by step, plan your approach, and prefer correctness over speed. \
         When in doubt, ask clarifying questions before writing code."
            .repeat(3),
    ));
    c.bench_function("classify_complex", |b| {
        b.iter(|| black_box(classify_complexity(&complex, &config)))
    });
}

criterion_group!(benches, bench_classify);
criterion_main!(benches);

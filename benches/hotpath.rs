//! Hot-path performance benchmarks — time spent per component on a typical request.
//!
//! Run: cargo bench --bench hotpath
//! This measures each stage of the request pipeline individually so you can see
//! exactly where wall-clock time is spent.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use grob::cache::ResponseCache;
use grob::features::dlp::sprt::SprtDetector;
use grob::features::token_pricing::{get_pricing, PricingTable};
use grob::models::*;
use grob::providers::streaming::parse_sse_events;

// ── Helpers ────────────────────────────────────────────────────

fn make_request(model: &str, n_messages: usize) -> AnthropicRequest {
    let messages: Vec<Message> = (0..n_messages)
        .map(|i| Message {
            role: if i % 2 == 0 { "user" } else { "assistant" }.to_string(),
            content: MessageContent::Text(format!(
                "This is message {} with some typical content that you might see in a real conversation. \
                 It includes various words and punctuation to be realistic.",
                i
            )),
        })
        .collect();

    AnthropicRequest {
        model: model.to_string(),
        messages,
        max_tokens: 4096,
        thinking: None,
        temperature: Some(0.0),
        top_p: None,
        top_k: None,
        stop_sequences: None,
        stream: None,
        metadata: None,
        system: Some(SystemPrompt::Text(
            "You are a helpful assistant. Be concise and accurate.".to_string(),
        )),
        tools: None,
        tool_choice: None,
    }
}

fn make_large_request() -> AnthropicRequest {
    make_request("claude-sonnet-4-6", 20)
}

fn make_small_request() -> AnthropicRequest {
    make_request("claude-sonnet-4-6", 2)
}

fn make_provider_response() -> grob::providers::ProviderResponse {
    grob::providers::ProviderResponse {
        id: "msg_01XFDUDYJgAACzvnptvVoYEL".to_string(),
        r#type: "message".to_string(),
        role: "assistant".to_string(),
        content: vec![ContentBlock::Known(KnownContentBlock::Text {
            text: "Here is a detailed response that contains several paragraphs of text. \
                   This simulates a typical LLM response that would be cached and serialized. \
                   The response includes various formatting and content to be realistic.\n\n\
                   Second paragraph with more detail about the topic at hand. This adds \
                   additional bytes to make the serialization benchmark more representative \
                   of real-world usage patterns."
                .to_string(),
            cache_control: None,
        })],
        model: "claude-sonnet-4-6".to_string(),
        stop_reason: Some("end_turn".to_string()),
        stop_sequence: None,
        usage: grob::providers::Usage {
            input_tokens: 1500,
            output_tokens: 350,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
    }
}

// ── 1. serde_json: parse & serialize ───────────────────────────

fn bench_serde_json(c: &mut Criterion) {
    let mut group = c.benchmark_group("serde_json");

    // Parse: Value -> AnthropicRequest (from_value)
    let req = make_small_request();
    let json_value = serde_json::to_value(&req).unwrap();

    group.bench_function("from_value_small_2msg", |b| {
        b.iter(|| {
            let v = json_value.clone();
            black_box(serde_json::from_value::<AnthropicRequest>(v).unwrap())
        })
    });

    let req_large = make_large_request();
    let json_value_large = serde_json::to_value(&req_large).unwrap();

    group.bench_function("from_value_large_20msg", |b| {
        b.iter(|| {
            let v = json_value_large.clone();
            black_box(serde_json::from_value::<AnthropicRequest>(v).unwrap())
        })
    });

    // to_string_pretty (debug logging cost)
    group.bench_function("to_string_pretty_small", |b| {
        b.iter(|| black_box(serde_json::to_string_pretty(&json_value).unwrap()))
    });

    group.bench_function("to_string_pretty_large", |b| {
        b.iter(|| black_box(serde_json::to_string_pretty(&json_value_large).unwrap()))
    });

    // Serialize response to Vec<u8> (cache + response body)
    let response = make_provider_response();

    group.bench_function("to_vec_response", |b| {
        b.iter(|| black_box(serde_json::to_vec(&response).unwrap()))
    });

    // Double serialization cost (what A4 eliminated)
    group.bench_function("to_vec_response_x2", |b| {
        b.iter(|| {
            let a = serde_json::to_vec(&response).unwrap();
            let b_vec = serde_json::to_vec(&response).unwrap();
            black_box((a, b_vec))
        })
    });

    group.finish();
}

// ── 2. Cache key computation ───────────────────────────────────

fn bench_cache_key(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_key");

    let req = make_small_request();

    group.bench_function("compute_key_from_request_small", |b| {
        b.iter(|| black_box(ResponseCache::compute_key_from_request("tenant-123", &req)))
    });

    let req_large = make_large_request();

    group.bench_function("compute_key_from_request_large", |b| {
        b.iter(|| {
            black_box(ResponseCache::compute_key_from_request(
                "tenant-123",
                &req_large,
            ))
        })
    });

    // Old method simulation: to_value -> to_string -> hash (for comparison)
    group.bench_function("old_via_value_small", |b| {
        use sha2::{Digest, Sha256};
        b.iter(|| {
            let messages_json = serde_json::to_value(&req.messages).unwrap();
            let system_json = req
                .system
                .as_ref()
                .and_then(|s| serde_json::to_value(s).ok());
            let mut hasher = Sha256::new();
            hasher.update(b"tenant-123|");
            hasher.update(req.model.as_bytes());
            hasher.update(b"|");
            hasher.update(messages_json.to_string().as_bytes());
            hasher.update(b"|");
            if let Some(ref sys) = system_json {
                hasher.update(sys.to_string().as_bytes());
            }
            hasher.update(b"|");
            black_box(hex::encode(hasher.finalize()))
        })
    });

    group.bench_function("old_via_value_large", |b| {
        use sha2::{Digest, Sha256};
        b.iter(|| {
            let messages_json = serde_json::to_value(&req_large.messages).unwrap();
            let system_json = req_large
                .system
                .as_ref()
                .and_then(|s| serde_json::to_value(s).ok());
            let mut hasher = Sha256::new();
            hasher.update(b"tenant-123|");
            hasher.update(req_large.model.as_bytes());
            hasher.update(b"|");
            hasher.update(messages_json.to_string().as_bytes());
            hasher.update(b"|");
            if let Some(ref sys) = system_json {
                hasher.update(sys.to_string().as_bytes());
            }
            hasher.update(b"|");
            black_box(hex::encode(hasher.finalize()))
        })
    });

    group.finish();
}

// ── 3. SPRT entropy detector ───────────────────────────────────

fn bench_sprt(c: &mut Criterion) {
    let mut group = c.benchmark_group("sprt");
    let detector = SprtDetector::new();

    let clean = "This is a normal English text response from an LLM. It contains \
                 multiple sentences with regular vocabulary and punctuation. Nothing \
                 suspicious here, just standard conversational output that you would \
                 expect from a language model. "
        .repeat(10);

    group.bench_function("scan_clean_2kb", |b| {
        b.iter(|| black_box(detector.scan(&clean)))
    });

    let with_secret = format!(
        "{}Here is a secret: Kj7mP2xQ9vR4nL8wB3yD6fH1sT5gA0cE7iU2oN4pM9qW3rZ6kX8jV1bY5hC and more text{}",
        "Normal text. ".repeat(50),
        " after secret.".repeat(20)
    );

    group.bench_function("scan_with_secret_2kb", |b| {
        b.iter(|| black_box(detector.scan(&with_secret)))
    });

    let large_clean = "Regular text output from a helpful assistant. ".repeat(200);

    group.bench_function("scan_clean_10kb", |b| {
        b.iter(|| black_box(detector.scan(&large_clean)))
    });

    group.finish();
}

// ── 4. Token pricing lookup ────────────────────────────────────

fn bench_pricing(c: &mut Criterion) {
    let mut group = c.benchmark_group("pricing");

    // Static get_pricing (with LazyLock HashMap)
    group.bench_function("get_pricing_exact", |b| {
        b.iter(|| black_box(get_pricing("claude-sonnet-4-6")))
    });

    group.bench_function("get_pricing_fuzzy", |b| {
        b.iter(|| black_box(get_pricing("anthropic/claude-sonnet-4-6:beta")))
    });

    group.bench_function("get_pricing_miss", |b| {
        b.iter(|| black_box(get_pricing("unknown-model-xyz")))
    });

    // ModelPricing::calculate
    let pricing = get_pricing("claude-sonnet-4-6").unwrap();
    group.bench_function("calculate_cost", |b| {
        b.iter(|| black_box(pricing.calculate(1500, 350)))
    });

    // PricingTable (dynamic)
    let table = PricingTable::from_known();
    group.bench_function("table_get_exact", |b| {
        b.iter(|| black_box(table.get("claude-sonnet-4-6")))
    });

    group.bench_function("table_get_fuzzy", |b| {
        b.iter(|| black_box(table.get("anthropic/claude-sonnet-4-6:beta")))
    });

    group.finish();
}

// ── 5. SSE parsing ─────────────────────────────────────────────

fn bench_sse_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("sse_parsing");

    let single_event = "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\n";

    group.bench_function("parse_1_event", |b| {
        b.iter(|| black_box(parse_sse_events(single_event)))
    });

    // Typical chunk: 5 events
    let multi_events = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_01\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-sonnet-4-6\",\"content\":[],\"stop_reason\":null}}\n\n\
                        event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n\
                        event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Here is a response\"}}\n\n\
                        event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n\
                        event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":25}}\n\n";

    group.bench_function("parse_5_events", |b| {
        b.iter(|| black_box(parse_sse_events(multi_events)))
    });

    // Large streaming chunk (20 deltas)
    let mut large_stream = String::new();
    for i in 0..20 {
        large_stream.push_str(&format!(
            "event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":\"Word{} \"}}}}\n\n",
            i
        ));
    }

    group.bench_function("parse_20_events", |b| {
        b.iter(|| black_box(parse_sse_events(&large_stream)))
    });

    group.finish();
}

// ── 6. Audit log hashing ───────────────────────────────────────

fn bench_audit_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("audit");

    // We can't directly bench AuditLog::hash_entry (private),
    // but we can bench the SHA-256 + format! pattern it uses.
    use sha2::{Digest, Sha256};

    let fields = (
        "2026-02-27T10:00:00+00:00",
        "550e8400-e29b-41d4-a716-446655440000",
        "tenant-123",
        "",
        "Request",
        "Nc",
        "anthropic",
        "None",
        "",
        "192.168.1.1",
        42u64,
        "abc123hash",
        "claude-sonnet-4-6",
        1500u32,
        350u32,
        "Low",
    );

    // Old way: format! then digest
    group.bench_function("hash_entry_format_then_digest", |b| {
        b.iter(|| {
            let canonical = format!(
                "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
                fields.0,
                fields.1,
                fields.2,
                fields.3,
                fields.4,
                fields.5,
                fields.6,
                fields.7,
                fields.8,
                fields.9,
                fields.10,
                fields.11,
                fields.12,
                fields.13,
                fields.14,
                fields.15,
            );
            black_box(hex::encode(Sha256::digest(canonical.as_bytes())))
        })
    });

    // New way: write! directly into hasher
    group.bench_function("hash_entry_write_into_hasher", |b| {
        b.iter(|| {
            use std::io::Write;
            let mut hasher = Sha256::new();
            let _ = write!(
                hasher,
                "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
                fields.0,
                fields.1,
                fields.2,
                fields.3,
                fields.4,
                fields.5,
                fields.6,
                fields.7,
                fields.8,
                fields.9,
                fields.10,
                fields.11,
                fields.12,
                fields.13,
                fields.14,
                fields.15,
            );
            black_box(hex::encode(hasher.finalize()))
        })
    });

    group.finish();
}

// ── 7. Value clone cost (what A2 eliminated) ───────────────────

fn bench_value_clone(c: &mut Criterion) {
    let mut group = c.benchmark_group("value_clone");

    let req = make_small_request();
    let val = serde_json::to_value(&req).unwrap();

    group.bench_function("clone_small_2msg", |b| b.iter(|| black_box(val.clone())));

    let req_large = make_large_request();
    let val_large = serde_json::to_value(&req_large).unwrap();

    group.bench_function("clone_large_20msg", |b| {
        b.iter(|| black_box(val_large.clone()))
    });

    group.finish();
}

// ── Register all groups ────────────────────────────────────────

criterion_group!(
    benches,
    bench_serde_json,
    bench_cache_key,
    bench_sprt,
    bench_pricing,
    bench_sse_parsing,
    bench_audit_hash,
    bench_value_clone,
);
criterion_main!(benches);

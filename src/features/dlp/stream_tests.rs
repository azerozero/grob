use super::*;
use crate::features::dlp::config::{DlpConfig, SecretAction, SecretRule};
use futures::{stream, StreamExt};

fn engine(pattern: &str) -> Arc<DlpEngine> {
    DlpEngine::from_config(DlpConfig {
        enabled: true,
        no_builtins: true,
        secrets: vec![SecretRule {
            name: "synthetic".into(),
            pattern: pattern.into(),
            prefix: if pattern.starts_with("tok_") {
                "tok_"
            } else {
                "test-secret-"
            }
            .into(),
            action: SecretAction::Redact,
        }],
        ..Default::default()
    })
    .unwrap()
}

fn event(value: serde_json::Value) -> Bytes {
    Event::from_value(value).bytes
}
fn start(text: &str) -> Bytes {
    event(
        serde_json::json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":text}}),
    )
}
fn delta(text: &str) -> Bytes {
    event(
        serde_json::json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":text}}),
    )
}
fn stop() -> Bytes {
    event(serde_json::json!({"type":"content_block_stop","index":0}))
}

async fn collect(chunks: Vec<Bytes>, engine: Arc<DlpEngine>) -> (String, bool) {
    let results = DlpStream::new(stream::iter(chunks.into_iter().map(Ok)), engine)
        .collect::<Vec<_>>()
        .await;
    let failed = results.iter().any(Result::is_err);
    let output = results
        .into_iter()
        .filter_map(Result::ok)
        .flat_map(|b| b.to_vec())
        .collect::<Vec<_>>();
    (String::from_utf8(output).unwrap(), failed)
}

#[tokio::test]
async fn secrets_are_masked_after_prose_and_at_every_delta_split() {
    let engine = engine("test-secret-[0-9]{8}");
    let secret = ["test-secret-", "12345678"].concat();
    for split in 0..=secret.len() {
        let (out, failed) = collect(
            vec![
                start("Initial text. "),
                delta("This is an ordinary, sufficiently long sentence. "),
                delta(&secret[..split]),
                delta(&secret[split..]),
                stop(),
            ],
            engine.clone(),
        )
        .await;
        assert!(!failed);
        assert!(
            !out.contains(&secret),
            "secret leaked at delta split {split}"
        );
        assert!(out.contains("Initial text."));
    }
    let (out, failed) = collect(vec![start(&secret), stop()], engine).await;
    assert!(!failed && !out.contains(&secret));
}

#[tokio::test]
async fn framing_handles_every_byte_split_utf8_crlf_bom_and_coalesced_events() {
    let engine = engine("test-secret-[0-9]{8}");
    let payload = [start("été "), delta("test-secret-12345678"), stop()].concat();
    let payload = format!(
        "\u{feff}{}",
        String::from_utf8(payload).unwrap().replace('\n', "\r\n")
    )
    .into_bytes();
    for split in 0..=payload.len() {
        let (out, failed) = collect(
            vec![
                Bytes::copy_from_slice(&payload[..split]),
                Bytes::copy_from_slice(&payload[split..]),
            ],
            engine.clone(),
        )
        .await;
        assert!(!failed, "split {split}");
        assert!(out.contains("été"));
        assert!(!out.contains("test-secret-12345678"));
    }
}

#[tokio::test]
async fn regex_is_evaluated_on_complete_text_not_a_prefix() {
    let engine = engine("tok_[a-z]+$");
    let (out, failed) = collect(
        vec![start(""), delta("tok_secret"), delta("-suffix"), stop()],
        engine.clone(),
    )
    .await;
    assert!(!failed && out.contains("tok_secret-suffix"));
    let (out, failed) = collect(
        vec![start(""), delta("tok_"), delta("secret"), stop()],
        engine,
    )
    .await;
    assert!(!failed && !out.contains("tok_secret"));
}

#[tokio::test]
async fn incomplete_invalid_and_oversized_text_is_never_released() {
    let engine = engine("test-secret-[0-9]{8}");
    for chunks in [
        vec![start("test-secret-12345678")],
        vec![
            start(""),
            delta("test-secret-12345678"),
            Bytes::from_static(b"data: {broken}\n\n"),
        ],
        vec![start(""), delta(&"x".repeat(BUFFER_LIMIT)), stop()],
        vec![delta("test-secret-12345678"), stop()],
    ] {
        let (out, failed) = collect(chunks, engine.clone()).await;
        assert!(failed);
        assert!(out.is_empty(), "partial text escaped on failure");
    }
    let mut chunks = vec![start("")];
    chunks.extend((0..EVENT_COUNT_LIMIT).map(|_| delta("")));
    let (out, failed) = collect(chunks, engine).await;
    assert!(failed && out.is_empty());
}

#[tokio::test]
async fn tool_events_keep_payloads_and_order() {
    let values = vec![
        serde_json::json!({"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"a","name":"Read"}}),
        serde_json::json!({"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"b","name":"Read"}}),
        serde_json::json!({"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{}"}}),
        serde_json::json!({"type":"content_block_stop","index":1}),
        serde_json::json!({"type":"content_block_stop","index":2}),
    ];
    let chunks: Vec<_> = values.into_iter().map(event).collect();
    let expected = String::from_utf8(chunks.concat()).unwrap();
    let (out, failed) = collect(chunks, engine("test-secret-[0-9]{8}")).await;
    assert!(!failed);
    assert_eq!(out, expected);
}

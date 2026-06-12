//! End-to-end integration tests for the OpenAI Responses (`/v1/responses`) path.
//!
//! These tests drive a real grob HTTP server (spawned on an ephemeral loopback
//! port via [`grob::server::start_server`]) with a [`mockito`] upstream standing
//! in for the OpenAI Responses API. They exercise the full pipeline:
//!
//! ```text
//! reqwest client → /v1/responses → handle_responses
//!   → transform_responses_to_canonical → dispatch::dispatch
//!   → OpenAIProvider (/responses, store=false) → mockito
//!   → Codex SSE → Anthropic SSE → AnthropicToResponsesStream → client
//! ```
//!
//! Everything is offline and deterministic: no real provider is ever contacted,
//! storage is redirected into a per-test temp dir via `GROB_HOME`, and the
//! upstream returns canned Codex SSE bodies.
//!
//! The client model is named with a `codex` suffix on purpose: the OpenAI
//! provider only speaks the Responses API (`/responses`) when the resolved model
//! name contains "codex" (or the provider is OAuth). With an api-key provider
//! that is the only way to route through the Responses upstream path.

use std::sync::{Arc, Mutex};

/// Instructions sent by the (simulated) Codex client. The handler maps these to
/// the canonical `system` prompt, and because the Responses path is
/// `codex_native`, the provider forwards them verbatim as the upstream
/// `instructions` field — the contract this test pins.
const CLIENT_INSTRUCTIONS: &str = "You are a deterministic test agent. Obey the harness.";

/// Client-facing model name. Must contain `codex` so the OpenAI provider selects
/// the `/responses` upstream endpoint (see module docs).
///
/// Uses dashes (not `gpt-5.5-codex`) because the router canonicalizes dotted
/// versions of known families (`gpt-…` → `gpt-5-5-codex`); naming the
/// `[[models]]` entry in the already-canonical form keeps the lookup exact.
const CLIENT_MODEL: &str = "gpt-5-5-codex";

/// Spawned grob server under test: base URL plus a shutdown trigger.
struct TestServer {
    base_url: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<()>>,
    // Keep the temp dir alive for the lifetime of the server so `GROB_HOME`
    // remains valid; dropping it would delete the storage directory.
    _home: tempfile::TempDir,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

/// Reserves a free loopback TCP port by binding to `:0` and immediately
/// releasing it. The server rebinds with `SO_REUSEADDR`, so the race window is
/// harmless in practice for a local test.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

/// Builds a grob config that routes [`CLIENT_MODEL`] to an api-key OpenAI
/// provider whose `base_url` points at the mockito upstream, then spawns the
/// real server on a free port and waits until it answers `/health`.
async fn spawn_server(upstream_base_url: &str) -> TestServer {
    let port = free_port();

    // Redirect all persistent storage into a throwaway directory so the test
    // never touches the developer's real `~/.grob`.
    let home = tempfile::tempdir().expect("create temp GROB_HOME");
    std::env::set_var("GROB_HOME", home.path());

    let toml = format!(
        r#"
[server]
host = "127.0.0.1"
port = {port}

[router]
default = "{CLIENT_MODEL}"

[[providers]]
name = "openai-mock"
provider_type = "openai"
auth_type = "apikey"
api_key = "sk-test-not-a-real-key"
base_url = "{upstream_base_url}"
models = ["{CLIENT_MODEL}"]

[[models]]
name = "{CLIENT_MODEL}"

[[models.mappings]]
priority = 1
provider = "openai-mock"
actual_model = "{CLIENT_MODEL}"
"#
    );

    let config = grob::cli::AppConfig::from_content(&toml, "responses_e2e_test")
        .expect("config should parse and validate");

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let source = grob::cli::ConfigSource::File(std::path::PathBuf::from("responses_e2e_test.toml"));

    let handle = tokio::spawn(async move {
        let shutdown = async move {
            let _ = shutdown_rx.await;
        };
        // Errors here surface as a failed health-check below rather than a panic
        // on a background task.
        let _ = grob::server::start_server(config, source, shutdown).await;
    });

    let base_url = format!("http://127.0.0.1:{port}");
    wait_until_healthy(&base_url).await;

    TestServer {
        base_url,
        shutdown: Some(shutdown_tx),
        handle: Some(handle),
        _home: home,
    }
}

/// Polls `/health` until the server answers 200 or a deadline elapses.
async fn wait_until_healthy(base_url: &str) {
    let client = reqwest::Client::new();
    let health = format!("{base_url}/health");
    for _ in 0..100 {
        if let Ok(resp) = client.get(&health).send().await {
            if resp.status().is_success() {
                return;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("server did not become healthy at {health}");
}

/// A single Codex SSE event in upstream wire format.
///
/// Includes both the `event:` line (required by the non-streaming
/// `parse_sse_response` collector) and the `data:` line (consumed by the
/// streaming codex transformer, which reads the JSON `type`). Emitting both
/// keeps a single fixture valid for both client paths.
fn sse_event(event: &str, data: &str) -> String {
    format!("event: {event}\ndata: {data}\n\n")
}

/// Upstream Codex SSE body containing a text message and a function call.
///
/// Shape mirrors the real `/responses` stream: `response.created`, incremental
/// `output_text.delta`, a `function_call` opened via `output_item.added` with
/// `function_call_arguments.delta` chunks and a closing `output_item.done`, then
/// a terminal `response.completed` carrying usage.
fn upstream_sse_body() -> String {
    let mut body = String::new();
    body.push_str(&sse_event(
        "response.created",
        r#"{"type":"response.created","response":{"id":"resp_test","model":"gpt-5.5-codex"}}"#,
    ));
    body.push_str(&sse_event(
        "response.output_text.delta",
        r#"{"type":"response.output_text.delta","output_index":0,"delta":"Running "}"#,
    ));
    body.push_str(&sse_event(
        "response.output_text.delta",
        r#"{"type":"response.output_text.delta","output_index":0,"delta":"the tool."}"#,
    ));
    // Close the text message as its own output item. The non-streaming collector
    // (`parse_sse_response`) reconstructs content from `output_item.done` events,
    // so the message needs an explicit one alongside the function call.
    body.push_str(&sse_event(
        "response.output_item.done",
        r#"{"type":"response.output_item.done","output_index":0,"item":{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"output_text","text":"Running the tool."}]}}"#,
    ));
    body.push_str(&sse_event(
        "response.output_item.added",
        r#"{"type":"response.output_item.added","output_index":1,"item":{"id":"fc_1","type":"function_call","call_id":"call_abc","name":"Bash","arguments":""}}"#,
    ));
    body.push_str(&sse_event(
        "response.function_call_arguments.delta",
        r#"{"type":"response.function_call_arguments.delta","item_id":"fc_1","output_index":1,"delta":"{\"command\":\""}"#,
    ));
    body.push_str(&sse_event(
        "response.function_call_arguments.delta",
        r#"{"type":"response.function_call_arguments.delta","item_id":"fc_1","output_index":1,"delta":"ls\"}"}"#,
    ));
    body.push_str(&sse_event(
        "response.output_item.done",
        r#"{"type":"response.output_item.done","output_index":1,"item":{"id":"fc_1","type":"function_call","call_id":"call_abc","name":"Bash","arguments":"{\"command\":\"ls\"}"}}"#,
    ));
    body.push_str(&sse_event(
        "response.completed",
        r#"{"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":11,"output_tokens":7}}}"#,
    ));
    body
}

/// Registers a `POST /responses` mock that captures the upstream request body
/// (for the Codex-contract assertions) and replies with [`upstream_sse_body`].
///
/// Returns the created mock and the shared slot holding the captured body.
async fn mock_responses_upstream(
    server: &mut mockito::ServerGuard,
) -> (mockito::Mock, Arc<Mutex<Option<String>>>) {
    let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let capture_slot = Arc::clone(&captured);

    let mock = server
        .mock("POST", "/responses")
        // Record the raw upstream body unconditionally, then always match so the
        // canned SSE is served regardless of body shape. Assertions run on the
        // captured copy, decoupled from request matching.
        .match_request(move |req| {
            if let Ok(body) = req.utf8_lossy_body() {
                *capture_slot.lock().unwrap() = Some(body.into_owned());
            }
            true
        })
        .with_status(200)
        .with_header("content-type", "text/event-stream")
        .with_body(upstream_sse_body())
        // Both the non-streaming and streaming round-trips hit this one mock.
        .expect_at_least(2)
        .create_async()
        .await;

    (mock, captured)
}

/// Parses an SSE response body into `(event, data)` pairs.
fn parse_sse(body: &str) -> Vec<(String, String)> {
    let mut events = Vec::new();
    let mut event_name: Option<String> = None;
    let mut data = String::new();
    for line in body.lines() {
        if line.is_empty() {
            if event_name.is_some() || !data.is_empty() {
                events.push((
                    event_name.take().unwrap_or_default(),
                    std::mem::take(&mut data),
                ));
            }
        } else if let Some(rest) = line.strip_prefix("event: ") {
            event_name = Some(rest.to_string());
        } else if let Some(rest) = line.strip_prefix("data: ") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(rest);
        }
    }
    if event_name.is_some() || !data.is_empty() {
        events.push((event_name.unwrap_or_default(), data));
    }
    events
}

/// Asserts the upstream request honoured the Codex contract: `store=false` and
/// the client `instructions` forwarded verbatim.
fn assert_upstream_contract(captured: &Arc<Mutex<Option<String>>>) {
    let body = captured
        .lock()
        .unwrap()
        .clone()
        .expect("upstream should have received a request");
    let json: serde_json::Value =
        serde_json::from_str(&body).expect("upstream body should be JSON");

    assert_eq!(
        json.get("store").and_then(|v| v.as_bool()),
        Some(false),
        "upstream Responses request must set store=false (ChatGPT Codex contract); body: {body}"
    );
    assert_eq!(
        json.get("instructions").and_then(|v| v.as_str()),
        Some(CLIENT_INSTRUCTIONS),
        "upstream must forward the client instructions verbatim; body: {body}"
    );
    // The provider always streams from the upstream, even on the non-streaming
    // client path.
    assert_eq!(
        json.get("stream").and_then(|v| v.as_bool()),
        Some(true),
        "upstream Responses request must set stream=true; body: {body}"
    );
}

/// Posts a `/v1/responses` request to the server under test.
async fn post_responses(base_url: &str, stream: bool) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{base_url}/v1/responses"))
        .json(&serde_json::json!({
            "model": CLIENT_MODEL,
            "instructions": CLIENT_INSTRUCTIONS,
            "input": [
                { "type": "message", "role": "user",
                  "content": [ { "type": "input_text", "text": "list files" } ] }
            ],
            "stream": stream
        }))
        .send()
        .await
        .expect("request to grob should succeed")
}

/// Drives all three Responses-path cases against a single live grob server.
///
/// Both round-trips are folded into one `#[tokio::test]` on purpose:
/// [`grob::server::start_server`] installs a **process-global** Prometheus
/// recorder, so a second `start_server` in the same test binary would fail to
/// boot. One server, two sequential requests keeps the E2E coverage without
/// fighting that singleton.
#[tokio::test]
async fn responses_e2e_round_trip() {
    let mut upstream = mockito::Server::new_async().await;
    let (mock, captured) = mock_responses_upstream(&mut upstream).await;

    let server = spawn_server(&upstream.url()).await;

    // ── (a) Non-streaming round-trip ──
    let resp = post_responses(&server.base_url, false).await;
    let status = resp.status();
    let raw = resp.text().await.expect("read body");
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "non-streaming: expected HTTP 200; body: {raw}"
    );

    let body: serde_json::Value = serde_json::from_str(&raw).expect("response should be JSON");
    assert_eq!(body["object"], "response", "object should be \"response\"");
    assert_eq!(
        body["status"], "completed",
        "status should be \"completed\""
    );

    let output = body["output"]
        .as_array()
        .expect("output should be an array");
    assert!(!output.is_empty(), "output must contain at least one item");

    // The fixture yields both a text message and a function_call; assert both
    // survived the canonical → Responses re-encode.
    let has_message = output.iter().any(|item| item["type"] == "message");
    let has_function_call = output
        .iter()
        .any(|item| item["type"] == "function_call" && item["name"] == "Bash");
    assert!(
        has_message,
        "expected a message output item; got {output:?}"
    );
    assert!(
        has_function_call,
        "expected a Bash function_call output item; got {output:?}"
    );

    // (c) Upstream contract for the non-streaming call.
    assert_upstream_contract(&captured);

    // ── (b) Streaming round-trip ──
    *captured.lock().unwrap() = None; // isolate the streaming call's captured body.
    let resp = post_responses(&server.base_url, true).await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "streaming: expected HTTP 200"
    );

    let sse_text = resp.text().await.expect("should read SSE body");
    let events = parse_sse(&sse_text);
    let event_names: Vec<&str> = events.iter().map(|(e, _)| e.as_str()).collect();

    // Terminal + lifecycle events the Codex client relies on.
    assert!(
        event_names.contains(&"response.created"),
        "client SSE must contain response.created; saw {event_names:?}"
    );
    assert!(
        event_names.contains(&"response.output_text.delta"),
        "client SSE must contain response.output_text.delta; saw {event_names:?}"
    );
    assert!(
        event_names.contains(&"response.completed"),
        "client SSE must terminate with response.completed; saw {event_names:?}"
    );

    // The incremental text deltas reassemble into the upstream text.
    let streamed_text: String = events
        .iter()
        .filter(|(e, _)| e == "response.output_text.delta")
        .filter_map(|(_, d)| serde_json::from_str::<serde_json::Value>(d).ok())
        .filter_map(|v| v["delta"].as_str().map(str::to_string))
        .collect();
    assert!(
        streamed_text.contains("Running the tool."),
        "reassembled streamed text should contain the upstream message; got {streamed_text:?}"
    );

    // The function_call must survive: its name appears in the function-call
    // lifecycle events (output_item.done / completed).
    let function_call_seen = events.iter().any(|(e, d)| {
        (e == "response.output_item.done" || e == "response.completed")
            && serde_json::from_str::<serde_json::Value>(d)
                .map(|v| {
                    let s = v.to_string();
                    s.contains("function_call") && s.contains("Bash")
                })
                .unwrap_or(false)
    });
    assert!(
        function_call_seen,
        "function_call (Bash) must appear in output_item.done/completed; events: {event_names:?}"
    );

    // The streamed function-call arguments reassemble to the upstream JSON.
    let streamed_args: String = events
        .iter()
        .filter(|(e, _)| e == "response.function_call_arguments.delta")
        .filter_map(|(_, d)| serde_json::from_str::<serde_json::Value>(d).ok())
        .filter_map(|v| v["delta"].as_str().map(str::to_string))
        .collect();
    if !streamed_args.is_empty() {
        let parsed: serde_json::Value =
            serde_json::from_str(&streamed_args).expect("reassembled args should be JSON");
        assert_eq!(
            parsed["command"], "ls",
            "function_call arguments must be preserved; got {streamed_args:?}"
        );
    }

    // (c) Upstream contract for the streaming call.
    assert_upstream_contract(&captured);

    mock.assert_async().await;
}

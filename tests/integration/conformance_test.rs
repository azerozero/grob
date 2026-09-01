//! Agent-conformance gate: semantic fidelity of an agent turn, per route.
//!
//! A gateway can answer `HTTP 200`, stream valid SSE, and show plausible text
//! while having quietly destroyed the *meaning* of the turn: tool arguments
//! truncated, an image replaced by the word `[Image]`, `cache_control`
//! breakpoints dropped, a provider error flattened into an opaque 500. The
//! client sees success; the agent misbehaves. That failure class is invisible to
//! status-code assertions, and it is the one this project keeps shipping fixes
//! for (#476 images, #465 reasoning, #488 tool-result images, #489 errors).
//!
//! These tests are the executable half of
//! [`docs/reference/conformance.md`](../../docs/reference/conformance.md): each
//! one pins one **loss dimension** on one route, so a regression names the thing
//! that broke instead of failing as "expected 200, got 500".
//!
//! ## What a conformance assertion is
//!
//! Not "did it return 200" but "did the bytes that reached the provider still
//! mean what the client said, and did the bytes returned to the client still
//! mean what the provider said". Every test therefore inspects the **captured
//! upstream request** and/or the **client-visible response body**, never just
//! the status.
//!
//! ## Why one server for the whole file
//!
//! The Prometheus recorder is a process-global one-shot, so only the first
//! server in a test binary installs it. Startup tolerates that (a metrics
//! failure must never block serving, per ADR-0030), but a second server would
//! still be recording into nothing, so the suite spawns one server with several
//! configured routes and drives them sequentially.

use std::sync::{Arc, Mutex};

// ── Routes under test ────────────────────────────────────────────

/// Client-facing model routed to the Anthropic-compatible upstream.
const ANTHROPIC_MODEL: &str = "conformance-anthropic";

/// Client-facing model routed to the OpenAI Chat Completions upstream.
const OPENAI_MODEL: &str = "conformance-openai";

/// Client-facing model routed to an upstream that always fails, used to pin the
/// provider-error contract on the Anthropic route.
const ERROR_MODEL: &str = "conformance-error";

/// Same, for the OpenAI Chat route: error translation differs per provider, so
/// the contract has to be pinned on each.
const OPENAI_ERROR_MODEL: &str = "conformance-openai-error";

// ── Test server ──────────────────────────────────────────────────

/// Spawned grob server under test: base URL plus a shutdown trigger.
struct TestServer {
    base_url: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<()>>,
    // Keeps `GROB_HOME` valid for the server's lifetime; dropping it early
    // would delete the storage directory out from under the process.
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

/// Reserves a free loopback TCP port by binding to `:0` and releasing it.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

/// Spawns one grob server routing [`ANTHROPIC_MODEL`] and [`OPENAI_MODEL`] at
/// their respective mock upstreams, and waits until it answers `/health`.
async fn spawn_server(
    anthropic_upstream: &str,
    openai_upstream: &str,
    error_upstream: &str,
    openai_error_upstream: &str,
) -> TestServer {
    let port = free_port();

    // Redirect persistent storage into a throwaway dir so the suite never
    // touches the developer's real `~/.grob`.
    let home = tempfile::tempdir().expect("create temp GROB_HOME");
    std::env::set_var("GROB_HOME", home.path());

    let toml = format!(
        r#"
[server]
host = "127.0.0.1"
port = {port}

[router]
default = "{ANTHROPIC_MODEL}"

[[providers]]
name = "anthropic-mock"
provider_type = "anthropic"
auth_type = "apikey"
api_key = "sk-ant-test-not-a-real-key"
base_url = "{anthropic_upstream}"
models = ["claude-sonnet-4"]

[[providers]]
name = "openai-mock"
provider_type = "openai"
auth_type = "apikey"
api_key = "sk-test-not-a-real-key"
base_url = "{openai_upstream}"
models = ["gpt-4o"]

[[providers]]
name = "error-mock"
provider_type = "anthropic"
auth_type = "apikey"
api_key = "sk-ant-test-not-a-real-key"
base_url = "{error_upstream}"
models = ["claude-error"]

[[providers]]
name = "openai-error-mock"
provider_type = "openai"
auth_type = "apikey"
api_key = "sk-test-not-a-real-key"
base_url = "{openai_error_upstream}"
models = ["gpt-error"]

[[models]]
name = "{ANTHROPIC_MODEL}"

[[models.mappings]]
priority = 1
provider = "anthropic-mock"
actual_model = "claude-sonnet-4"

[[models]]
name = "{OPENAI_MODEL}"

[[models.mappings]]
priority = 1
provider = "openai-mock"
actual_model = "gpt-4o"

[[models]]
name = "{ERROR_MODEL}"

[[models.mappings]]
priority = 1
provider = "error-mock"
actual_model = "claude-error"

[[models]]
name = "{OPENAI_ERROR_MODEL}"

[[models.mappings]]
priority = 1
provider = "openai-error-mock"
actual_model = "gpt-error"
"#
    );

    let config = grob::cli::AppConfig::from_content(&toml, "conformance_test")
        .expect("config should parse and validate");

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let source = grob::cli::ConfigSource::File(std::path::PathBuf::from("conformance_test.toml"));

    let handle = tokio::spawn(async move {
        let shutdown = async move {
            let _ = shutdown_rx.await;
        };
        // A failure here surfaces as a failed health check below rather than a
        // panic on a detached task.
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

// ── Upstream mocks ───────────────────────────────────────────────

/// Shared slot holding the most recent raw upstream request body.
type Captured = Arc<Mutex<Option<String>>>;

/// Registers a mock at `path` that captures the upstream body and replies with
/// `body` under `status`.
///
/// Request matching always succeeds: assertions run against the captured copy,
/// so a shape mismatch fails with a readable diff instead of mockito's opaque
/// "no matching mock".
async fn mock_upstream(
    server: &mut mockito::ServerGuard,
    path: &str,
    status: usize,
    content_type: &str,
    body: String,
) -> (mockito::Mock, Captured) {
    let captured: Captured = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&captured);

    let mock = server
        .mock("POST", path)
        .match_request(move |req| {
            if let Ok(b) = req.utf8_lossy_body() {
                *slot.lock().unwrap() = Some(b.into_owned());
            }
            true
        })
        .with_status(status)
        .with_header("content-type", content_type)
        .with_body(body)
        .expect_at_least(1)
        .create_async()
        .await;

    (mock, captured)
}

/// Reads the captured upstream body as JSON, failing with the raw text when it
/// will not parse.
fn captured_json(captured: &Captured) -> serde_json::Value {
    let body = captured
        .lock()
        .unwrap()
        .clone()
        .expect("upstream should have received a request");
    serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("upstream body should be JSON ({e}); raw: {body}"))
}

/// A minimal, valid Anthropic non-streaming response.
fn anthropic_reply(text: &str) -> String {
    serde_json::json!({
        "id": "msg_conformance",
        "type": "message",
        "role": "assistant",
        "model": "claude-sonnet-4",
        "content": [ { "type": "text", "text": text } ],
        "stop_reason": "end_turn",
        "usage": { "input_tokens": 10, "output_tokens": 5 }
    })
    .to_string()
}

// ── The suite ────────────────────────────────────────────────────

/// Drives every conformance dimension against one live server.
///
/// Folded into a single `#[tokio::test]` for the process-global recorder reason
/// documented at module level. Each dimension is a helper with its own
/// assertions and its own failure message, so the output still names the
/// specific contract that broke.
#[tokio::test]
async fn agent_conformance_gate() {
    let mut anthropic_upstream = mockito::Server::new_async().await;
    let mut openai_upstream = mockito::Server::new_async().await;

    let (anthropic_mock, anthropic_captured) = mock_upstream(
        &mut anthropic_upstream,
        "/v1/messages",
        200,
        "application/json",
        anthropic_reply("ack"),
    )
    .await;

    let (openai_mock, openai_captured) = mock_upstream(
        &mut openai_upstream,
        "/chat/completions",
        200,
        "application/json",
        serde_json::json!({
            "id": "chatcmpl-conformance",
            "object": "chat.completion",
            "model": "gpt-4o",
            "choices": [ {
                "index": 0,
                "message": { "role": "assistant", "content": "ack" },
                "finish_reason": "stop"
            } ],
            "usage": { "prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15 }
        })
        .to_string(),
    )
    .await;

    // An upstream that always rejects, to pin the provider-error contract.
    let mut error_upstream = mockito::Server::new_async().await;
    let (error_mock, _error_captured) = mock_upstream(
        &mut error_upstream,
        "/v1/messages",
        429,
        "application/json",
        serde_json::json!({
            "type": "error",
            "error": { "type": "rate_limit_error", "message": "slow down" }
        })
        .to_string(),
    )
    .await;

    let mut openai_error_upstream = mockito::Server::new_async().await;
    let (openai_error_mock, _) = mock_upstream(
        &mut openai_error_upstream,
        "/chat/completions",
        400,
        "application/json",
        serde_json::json!({
            "error": {
                "type": "invalid_request_error",
                "code": "unsupported_parameter",
                "message": "this model does not support that parameter"
            }
        })
        .to_string(),
    )
    .await;

    let server = spawn_server(
        &anthropic_upstream.url(),
        &openai_upstream.url(),
        &error_upstream.url(),
        &openai_error_upstream.url(),
    )
    .await;

    tool_arguments_survive_translation(&server.base_url, &openai_captured).await;
    tool_arguments_survive_anthropic_route(&server.base_url, &anthropic_captured).await;
    anthropic_route_preserves_the_turn(&server.base_url, &anthropic_captured).await;
    images_are_forwarded_as_pixels(&server.base_url, &openai_captured).await;
    cache_control_survives_the_anthropic_route(&server.base_url, &anthropic_captured).await;
    system_prompt_is_not_dropped(&server.base_url, &openai_captured).await;
    multi_turn_history_is_ordered(&server.base_url, &openai_captured).await;
    provider_errors_stay_diagnosable(&server.base_url).await;
    openai_provider_errors_stay_diagnosable(&server.base_url).await;

    anthropic_mock.assert_async().await;
    openai_mock.assert_async().await;
    error_mock.assert_async().await;
    openai_error_mock.assert_async().await;
}

/// **Tool arguments must reach the provider byte-exact** (OpenAI Chat route).
///
/// The classic silent corruption: a tool call arrives with its JSON arguments
/// re-encoded, truncated, or double-escaped, so the agent executes the wrong
/// command. Nested objects, arrays, unicode and embedded quotes are all included
/// because they are what breaks under a naive string round-trip.
async fn tool_arguments_survive_translation(base_url: &str, captured: &Captured) {
    let args = serde_json::json!({
        "command": "grep -r \"needle\" .",
        "timeout": 30,
        "flags": ["-r", "-n"],
        "env": { "LANG": "fr_FR.UTF-8", "note": "accentué" }
    });

    let resp = post_messages(
        base_url,
        serde_json::json!({
            "model": OPENAI_MODEL,
            "max_tokens": 64,
            "messages": [
                { "role": "user", "content": "run it" },
                { "role": "assistant", "content": [ {
                    "type": "tool_use", "id": "toolu_1", "name": "Bash", "input": args
                } ] },
                { "role": "user", "content": [ {
                    "type": "tool_result", "tool_use_id": "toolu_1", "content": "done"
                } ] }
            ]
        }),
    )
    .await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "tool-arguments route should succeed"
    );

    let sent = captured_json(captured);
    let tool_calls = find_first(&sent, "tool_calls")
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    assert!(
        !tool_calls.is_empty(),
        "the tool call must survive translation to the OpenAI wire format; sent: {sent}"
    );

    let raw_args = tool_calls[0]["function"]["arguments"]
        .as_str()
        .expect("OpenAI encodes tool arguments as a JSON string");
    let round_tripped: serde_json::Value =
        serde_json::from_str(raw_args).expect("tool arguments must still be parseable JSON");

    assert_eq!(
        round_tripped, args,
        "tool arguments must arrive semantically identical, not merely present"
    );
}

/// **Tool arguments must reach the provider byte-exact** (Anthropic route).
///
/// Same contract on the native path. Cheap to assert and it pins the pass-through
/// so a future canonical-format change cannot silently reshape `input`.
async fn tool_arguments_survive_anthropic_route(base_url: &str, captured: &Captured) {
    let args = serde_json::json!({ "path": "/tmp/x", "depth": 2, "quoted": "say \"hi\"" });

    let resp = post_messages(
        base_url,
        serde_json::json!({
            "model": ANTHROPIC_MODEL,
            "max_tokens": 64,
            "messages": [
                { "role": "user", "content": "read it" },
                { "role": "assistant", "content": [ {
                    "type": "tool_use", "id": "toolu_2", "name": "Read", "input": args
                } ] },
                { "role": "user", "content": [ {
                    "type": "tool_result", "tool_use_id": "toolu_2", "content": "ok"
                } ] }
            ]
        }),
    )
    .await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "anthropic tool route should succeed"
    );

    let sent = captured_json(captured);
    let input = find_first(&sent, "input")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    assert_eq!(
        input, args,
        "tool_use input must pass through the native route unchanged; sent: {sent}"
    );
}

/// **The native route must preserve the whole turn**: system, image, order.
///
/// The Anthropic path is nominally pass-through, which is exactly why it is
/// worth pinning: "we don't transform it" is an assumption that quietly stops
/// being true the first time a sanitizer, a cache injector, or a canonical-format
/// change touches the request on its way out.
async fn anthropic_route_preserves_the_turn(base_url: &str, captured: &Captured) {
    const PNG_B64: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=";
    const SYSTEM: &str = "Native-route system prompt that must survive.";

    let resp = post_messages(
        base_url,
        serde_json::json!({
            "model": ANTHROPIC_MODEL,
            "max_tokens": 64,
            "system": SYSTEM,
            "messages": [
                { "role": "user", "content": "first user" },
                { "role": "assistant", "content": "first assistant" },
                { "role": "user", "content": [
                    { "type": "text", "text": "second user" },
                    { "type": "image", "source": {
                        "type": "base64", "media_type": "image/png", "data": PNG_B64
                    } }
                ] }
            ]
        }),
    )
    .await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "native turn-preservation route should succeed"
    );

    let sent = captured_json(captured);

    // System prompt.
    assert!(
        sent.to_string().contains(SYSTEM),
        "the system prompt must reach Anthropic; sent: {sent}"
    );

    // Image pixels, not a placeholder.
    assert!(
        sent.to_string().contains(PNG_B64),
        "the image bytes must reach Anthropic; sent: {sent}"
    );
    assert!(
        !sent.to_string().contains("[Image]"),
        "the image must not degrade to a placeholder on the native route; sent: {sent}"
    );

    // Order and roles.
    let messages = sent["messages"]
        .as_array()
        .expect("Anthropic requests carry a messages array");
    let convo: Vec<(&str, String)> = messages
        .iter()
        .map(|m| {
            (
                m["role"].as_str().unwrap_or_default(),
                m["content"].to_string(),
            )
        })
        .collect();
    let expected = [
        ("user", "first user"),
        ("assistant", "first assistant"),
        ("user", "second user"),
    ];
    assert_eq!(
        convo.len(),
        expected.len(),
        "every turn must survive the native route; sent: {sent}"
    );
    for (i, (role, text)) in expected.iter().enumerate() {
        assert_eq!(
            convo[i].0, *role,
            "turn {i} must keep its role; sent: {sent}"
        );
        assert!(
            convo[i].1.contains(text),
            "turn {i} must keep its content in order; sent: {sent}"
        );
    }
}

/// **An image must arrive as pixels, not as the word "[Image]"** (#476).
///
/// The regression this guards is specific: a multimodal turn degrades to a text
/// placeholder, the request still succeeds, and the model answers about an image
/// it never saw.
async fn images_are_forwarded_as_pixels(base_url: &str, captured: &Captured) {
    // 1x1 transparent PNG.
    const PNG_B64: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=";

    let resp = post_messages(
        base_url,
        serde_json::json!({
            "model": OPENAI_MODEL,
            "max_tokens": 64,
            "messages": [ { "role": "user", "content": [
                { "type": "text", "text": "what is this?" },
                { "type": "image", "source": {
                    "type": "base64", "media_type": "image/png", "data": PNG_B64
                } }
            ] } ]
        }),
    )
    .await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "image route should succeed"
    );

    let sent = captured_json(captured);
    let wire = sent.to_string();
    assert!(
        wire.contains(PNG_B64),
        "the image bytes must reach the provider; sent: {sent}"
    );
    assert!(
        find_first(&sent, "image_url").is_some(),
        "the image must be an image_url part, not inlined prose; sent: {sent}"
    );
    assert!(
        !wire.contains("[Image]"),
        "the image must not degrade to the '[Image]' placeholder; sent: {sent}"
    );
}

/// **`cache_control` breakpoints must survive** on the Anthropic route.
///
/// Dropping them is invisible in the response and silently multiplies cost,
/// which is why it belongs in a conformance gate rather than a cost dashboard.
async fn cache_control_survives_the_anthropic_route(base_url: &str, captured: &Captured) {
    let resp = post_messages(
        base_url,
        serde_json::json!({
            "model": ANTHROPIC_MODEL,
            "max_tokens": 64,
            "system": [ {
                "type": "text",
                "text": "You are a long, cacheable system prompt.",
                "cache_control": { "type": "ephemeral" }
            } ],
            "messages": [ { "role": "user", "content": [ {
                "type": "text",
                "text": "hello",
                "cache_control": { "type": "ephemeral" }
            } ] } ]
        }),
    )
    .await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "cache_control route should succeed"
    );

    // Assert each breakpoint at its own location. A single "is it anywhere?"
    // check would let one survivor mask the loss of the other, which is exactly
    // how a caching regression hides: the request still looks annotated.
    let sent = captured_json(captured);

    let system_cached = sent["system"]
        .as_array()
        .map(|blocks| blocks.iter().any(|b| b.get("cache_control").is_some()))
        .unwrap_or(false);
    assert!(
        system_cached,
        "the system breakpoint must reach Anthropic or the system prefix is re-billed \
         every turn; sent: {sent}"
    );

    let message_cached = sent["messages"]
        .as_array()
        .map(|msgs| {
            msgs.iter()
                .any(|m| find_first(m, "cache_control").is_some())
        })
        .unwrap_or(false);
    assert!(
        message_cached,
        "the message breakpoint must reach Anthropic; sent: {sent}"
    );
}

/// **The system prompt must not be dropped** when translating to OpenAI.
///
/// It carries the agent's instructions; losing it produces a fluent, confidently
/// wrong answer with a perfectly healthy 200.
async fn system_prompt_is_not_dropped(base_url: &str, captured: &Captured) {
    const SYSTEM: &str = "You must always answer in exactly three words.";

    let resp = post_messages(
        base_url,
        serde_json::json!({
            "model": OPENAI_MODEL,
            "max_tokens": 64,
            "system": SYSTEM,
            "messages": [ { "role": "user", "content": "hello" } ]
        }),
    )
    .await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "system-prompt route should succeed"
    );

    let sent = captured_json(captured);
    assert!(
        sent.to_string().contains(SYSTEM),
        "the system prompt must reach the provider verbatim; sent: {sent}"
    );
}

/// **Multi-turn history must keep its order and its roles.**
///
/// A reordered or role-flipped history is the subtlest corruption of all: every
/// message is present, so a "nothing was lost" check passes, yet the model reads
/// a different conversation.
async fn multi_turn_history_is_ordered(base_url: &str, captured: &Captured) {
    let resp = post_messages(
        base_url,
        serde_json::json!({
            "model": OPENAI_MODEL,
            "max_tokens": 64,
            "messages": [
                { "role": "user", "content": "first user" },
                { "role": "assistant", "content": "first assistant" },
                { "role": "user", "content": "second user" }
            ]
        }),
    )
    .await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "multi-turn route should succeed"
    );

    let sent = captured_json(captured);
    let messages = sent["messages"]
        .as_array()
        .expect("OpenAI requests carry a messages array");

    // Compare only the conversation turns: an injected system message is a
    // legitimate transformation, a reordered conversation is not.
    let convo: Vec<(String, String)> = messages
        .iter()
        .filter(|m| m["role"] != "system")
        .map(|m| {
            let role = m["role"].as_str().unwrap_or_default().to_string();
            let text = match &m["content"] {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            (role, text)
        })
        .collect();

    let expected = [
        ("user", "first user"),
        ("assistant", "first assistant"),
        ("user", "second user"),
    ];
    assert_eq!(
        convo.len(),
        expected.len(),
        "every conversation turn must survive; sent: {sent}"
    );
    for (i, (role, text)) in expected.iter().enumerate() {
        assert_eq!(
            convo[i].0, *role,
            "turn {i} must keep its role; sent: {sent}"
        );
        assert!(
            convo[i].1.contains(text),
            "turn {i} must keep its content in order; sent: {sent}"
        );
    }
}

/// **A provider error must stay diagnosable** (#489).
///
/// Flattening every upstream failure into an opaque `500` is the other half of
/// protocol infidelity: the agent cannot tell "slow down, retry later" from
/// "your request is malformed, do not retry", so it retries the unretryable and
/// gives up on the transient. The status must be the upstream's own, and the
/// provider's error body must arrive structured rather than stringified.
async fn provider_errors_stay_diagnosable(base_url: &str) {
    let resp = post_messages(
        base_url,
        serde_json::json!({
            "model": ERROR_MODEL,
            "max_tokens": 64,
            "messages": [ { "role": "user", "content": "hello" } ]
        }),
    )
    .await;

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::TOO_MANY_REQUESTS,
        "the upstream 429 must reach the client verbatim, not as a flattened 5xx"
    );

    let body: serde_json::Value = resp.json().await.expect("error body should be JSON");
    assert_eq!(
        body["error"]["upstream_status"], 429,
        "the upstream status must be reported; body: {body}"
    );
    assert_eq!(
        body["error"]["upstream_error"]["error"]["type"], "rate_limit_error",
        "the provider's own error type must arrive structured, not as an opaque \
         string the client has to re-parse; body: {body}"
    );
}

/// Same contract on the OpenAI Chat route.
///
/// Worth pinning separately: a `400 unsupported_parameter` is permanently fatal
/// for that request, while the Anthropic `429` is transient. An agent that
/// cannot tell them apart either retries forever or gives up immediately, and
/// the distinction only survives if the *code* comes through, not just the
/// status.
///
/// The fixture deliberately avoids `context_length_exceeded`: grob *recognises*
/// that one and rewrites it into a richer, actionable envelope (with a suggested
/// `/compact`), which is a different and intentional contract. This test pins
/// the generic path, where grob has no special knowledge and must simply not
/// lose what the provider said.
async fn openai_provider_errors_stay_diagnosable(base_url: &str) {
    let resp = post_messages(
        base_url,
        serde_json::json!({
            "model": OPENAI_ERROR_MODEL,
            "max_tokens": 64,
            "messages": [ { "role": "user", "content": "hello" } ]
        }),
    )
    .await;

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "the upstream 400 must reach the client verbatim, not as a flattened 5xx"
    );

    let body: serde_json::Value = resp.json().await.expect("error body should be JSON");
    assert_eq!(
        body["error"]["upstream_status"], 400,
        "the upstream status must be reported; body: {body}"
    );
    assert_eq!(
        body["error"]["upstream_error"]["error"]["code"], "unsupported_parameter",
        "the provider's error code must survive so the agent can tell a permanent \
         failure from a transient one; body: {body}"
    );
}

// ── Helpers ──────────────────────────────────────────────────────

/// Posts an Anthropic-format request to `/v1/messages` on the server under test.
async fn post_messages(base_url: &str, body: serde_json::Value) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{base_url}/v1/messages"))
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .expect("request to grob should succeed")
}

/// Depth-first search for the first value under `key` anywhere in `v`.
///
/// The wire shape differs per provider (and per nesting depth), so the tests
/// assert *presence and value* of a field rather than hard-coding a path that
/// would break on an unrelated envelope change.
fn find_first<'a>(v: &'a serde_json::Value, key: &str) -> Option<&'a serde_json::Value> {
    match v {
        serde_json::Value::Object(map) => {
            if let Some(found) = map.get(key) {
                return Some(found);
            }
            map.values().find_map(|child| find_first(child, key))
        }
        serde_json::Value::Array(items) => items.iter().find_map(|child| find_first(child, key)),
        _ => None,
    }
}

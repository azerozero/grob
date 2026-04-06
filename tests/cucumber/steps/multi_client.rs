use cucumber::{then, when};
use std::collections::HashMap;

use crate::world::E2eWorld;

/// Client configuration: project, provider, API key, budget.
struct ClientConfig {
    project: &'static str,
    api_key: &'static str,
}

/// Returns the predefined client configuration for A, B, or C.
fn client_config(name: &str) -> ClientConfig {
    match name {
        "A" => ClientConfig {
            project: "llm",
            api_key: "grob-client-a-key",
        },
        "B" => ClientConfig {
            project: "llm",
            api_key: "grob-client-b-key",
        },
        "C" => ClientConfig {
            project: "analytics",
            api_key: "grob-client-c-key",
        },
        _ => panic!("unknown client '{name}', expected A, B, or C"),
    }
}

/// Sends a chat request as the given client and records the snapshot.
async fn send_as_client(world: &mut E2eWorld, client_name: &str, content: &str) {
    let cfg = client_config(client_name);
    let url = format!("http://{}/v1/chat/completions", world.grob_host);
    let body = serde_json::json!({
        "model": "default",
        "messages": [{"role": "user", "content": content}],
        "max_tokens": 10,
        "metadata": {
            "project": cfg.project,
            "client_id": client_name,
        }
    });

    let resp = reqwest::Client::new()
        .post(&url)
        .header("X-Grob-API-Key", cfg.api_key)
        .header("X-Grob-Project", cfg.project)
        .json(&body)
        .send()
        .await
        .unwrap_or_else(|e| panic!("request as client {client_name} failed: {e}"));

    let status = resp.status().as_u16();
    let headers: HashMap<String, String> = resp
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_lowercase(),
                v.to_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    let body_text = resp.text().await.unwrap_or_default();

    let snap = world.clients.entry(client_name.to_string()).or_default();
    snap.last_status = status;
    snap.last_body = body_text;
    snap.last_headers = headers;
    if status == 200 {
        snap.ok_count += 1;
    }

    // Mirror into global state for steps that use the shared last_http_status.
    world.last_http_status = status;
    world.last_http_body = snap.last_body.clone();
    world.last_http_headers = snap.last_headers.clone();
}

/// Sends a request targeting a specific provider (for T1 routing test).
async fn send_targeting_provider(world: &mut E2eWorld, client_name: &str, provider: &str) {
    let cfg = client_config(client_name);
    let url = format!("http://{}/v1/chat/completions", world.grob_host);
    let body = serde_json::json!({
        "model": provider,
        "messages": [{"role": "user", "content": "ping"}],
        "max_tokens": 10,
        "metadata": {
            "project": cfg.project,
            "client_id": client_name,
        }
    });

    let resp = reqwest::Client::new()
        .post(&url)
        .header("X-Grob-API-Key", cfg.api_key)
        .header("X-Grob-Project", cfg.project)
        .json(&body)
        .send()
        .await
        .unwrap_or_else(|e| panic!("request as client {client_name} failed: {e}"));

    let status = resp.status().as_u16();
    let body_text = resp.text().await.unwrap_or_default();

    world.last_http_status = status;
    world.last_http_body = body_text;
}

// ---------------------------------------------------------------------------
// T1 — Isolation inter-projets
// ---------------------------------------------------------------------------

#[when(regex = r#"client ([A-C]) sends a request on project "(.+)""#)]
async fn client_sends_on_project(world: &mut E2eWorld, client: String, _project: String) {
    let content = format!(
        "ping-{}-{}",
        client,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    send_as_client(world, &client, &content).await;
}

#[when(regex = r#"client ([A-C]) sends a request targeting provider "(.+)""#)]
async fn client_targets_provider(world: &mut E2eWorld, client: String, provider: String) {
    send_targeting_provider(world, &client, &provider).await;
}

#[then(regex = r#"audit entries for client ([A-C]) have project "(.+)""#)]
async fn audit_client_project(world: &mut E2eWorld, client: String, project: String) {
    // Reload audit from volume.
    super::audit::load_audit_pub(world).await;
    let matching: Vec<_> = world
        .audit_lines
        .iter()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["client_id"].as_str() == Some(&client))
        .collect();

    assert!(
        !matching.is_empty(),
        "no audit entries found for client {client}"
    );
    for entry in &matching {
        assert_eq!(
            entry["project"].as_str().unwrap_or(""),
            project,
            "client {client} audit entry has wrong project: {entry}"
        );
    }
}

#[then("no audit entry mixes clients across projects")]
async fn no_cross_project_mixing(world: &mut E2eWorld) {
    super::audit::load_audit_pub(world).await;
    for line in &world.audit_lines {
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let client = v["client_id"].as_str().unwrap_or("");
        let project = v["project"].as_str().unwrap_or("");
        if client.is_empty() || project.is_empty() {
            continue;
        }
        let expected_project = client_config(client).project;
        assert_eq!(
            project, expected_project,
            "client {client} appeared in project {project}, expected {expected_project}"
        );
    }
}

// ---------------------------------------------------------------------------
// T2 — Budget isolation
// ---------------------------------------------------------------------------

#[when(regex = r#"client ([A-C]) spends up to budget limit on project "(.+)""#)]
async fn client_spends_to_limit(world: &mut E2eWorld, client: String, _project: String) {
    // Send requests until we get a 429 or reach a reasonable cap.
    for i in 0..100 {
        let content = format!("budget-test-{client}-{i}");
        send_as_client(world, &client, &content).await;
        let snap = world.clients.get(&client).unwrap();
        if snap.last_status == 429 {
            break;
        }
    }
}

#[then("both clients received 200 before their limits")]
async fn both_had_200(world: &mut E2eWorld) {
    let a = world.clients.get("A").expect("client A not found");
    let b = world.clients.get("B").expect("client B not found");
    assert!(a.ok_count > 0, "client A never received 200");
    assert!(b.ok_count > 0, "client B never received 200");
}

#[then(regex = r"the next request from client ([A-C]) returns (\d+)")]
async fn next_request_returns(world: &mut E2eWorld, client: String, expected: u16) {
    send_as_client(world, &client, "one-more-after-limit").await;
    let snap = world.clients.get(&client).unwrap();
    assert_eq!(
        snap.last_status, expected,
        "client {client}: expected {expected}, got {}",
        snap.last_status
    );
}

#[when(regex = r"client ([A-C]) has exhausted their budget")]
async fn client_exhausted(world: &mut E2eWorld, client: String) {
    // Ensure client has been driven to 429 already. If not, do it now.
    let status = world
        .clients
        .get(&client)
        .map(|s| s.last_status)
        .unwrap_or(0);
    if status != 429 {
        client_spends_to_limit(world, client, "llm".to_string()).await;
    }
}

#[then(regex = r"client ([A-C]) receives (\d+)")]
async fn client_receives(world: &mut E2eWorld, client: String, expected: u16) {
    let snap = world.clients.get(&client).expect("client not found");
    assert_eq!(
        snap.last_status, expected,
        "client {client}: expected {expected}, got {}",
        snap.last_status
    );
}

// ---------------------------------------------------------------------------
// T3 — DLP cross-projet
// ---------------------------------------------------------------------------

const FRENCH_SSN: &str = "1 85 01 75 123 456 78";

#[when(regex = r"client ([A-C]) sends a message containing a French SSN")]
async fn client_sends_ssn(world: &mut E2eWorld, client: String) {
    world.injected_ssn = FRENCH_SSN.to_string();
    let content = format!("Mon numero secu est {FRENCH_SSN}");
    send_as_client(world, &client, &content).await;
}

#[then(regex = r"the response to client ([A-C]) does not contain the original SSN")]
async fn response_redacted(world: &mut E2eWorld, client: String) {
    let snap = world.clients.get(&client).expect("client not found");
    assert!(
        !snap.last_body.contains(FRENCH_SSN),
        "client {client} response still contains the SSN"
    );
}

#[then(regex = r"the response to client ([A-C]) contains the original SSN")]
async fn response_not_redacted(world: &mut E2eWorld, client: String) {
    let snap = world.clients.get(&client).expect("client not found");
    assert!(
        snap.last_body.contains(FRENCH_SSN),
        "client {client} response should contain the SSN but doesn't"
    );
}

// ---------------------------------------------------------------------------
// T4 — Failover multi-LLM
// ---------------------------------------------------------------------------

#[then(regex = r"client ([A-C]) receives 502 or falls back to secondary")]
async fn failover_or_502(world: &mut E2eWorld, client: String) {
    let snap = world.clients.get(&client).expect("client not found");
    let status = snap.last_status;
    assert!(
        status == 502 || status == 200,
        "client {client}: expected 502 or 200 (fallback), got {status}"
    );
}

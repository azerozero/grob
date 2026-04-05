use cucumber::{then, when};

use crate::world::E2eWorld;

#[when(regex = r#"I send a chat request with model "(.+)" and content "(.+)""#)]
async fn send_chat_request(world: &mut E2eWorld, model: String, content: String) {
    let url = format!("http://{}/v1/chat/completions", world.grob_host);
    let body = serde_json::json!({
        "model": model,
        "messages": [{"role": "user", "content": content}],
        "max_tokens": 10
    });

    let mut req = reqwest::Client::new().post(&url).json(&body);

    if !world.jwt.is_empty() {
        req = req.header("Authorization", format!("Bearer {}", world.jwt));
    } else {
        req = req.header("X-Grob-API-Key", "grob-siege-master-key");
    }

    let resp = req.send().await.expect("request to grob failed");
    world.last_http_status = resp.status().as_u16();
    world.last_http_headers = resp
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_lowercase(),
                v.to_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    world.last_http_body = resp.text().await.unwrap_or_default();
}

#[when(regex = r"I send (\d+) chat requests through grob")]
async fn send_n_requests(world: &mut E2eWorld, n: u32) {
    for i in 0..n {
        // Unique content per request to avoid cache hits.
        let content = format!(
            "cucumber-{i}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        send_chat_request(world, "default".into(), content).await;
        assert!(
            world.last_http_status == 200 || world.last_http_status == 429,
            "unexpected status {} when sending batch requests",
            world.last_http_status
        );
    }
}

#[when(regex = r"I wait (\d+) seconds? for flush")]
async fn wait_seconds(_world: &mut E2eWorld, secs: u64) {
    tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
}

#[then(regex = r"the response status is (\d+)")]
async fn check_response_status(world: &mut E2eWorld, expected: u16) {
    assert_eq!(
        world.last_http_status, expected,
        "response body: {}",
        world.last_http_body
    );
}

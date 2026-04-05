use cucumber::given;

use crate::world::E2eWorld;

#[given(regex = r#"toxiproxy disables proxy "(.+)""#)]
async fn disable_proxy(world: &mut E2eWorld, proxy: String) {
    let url = format!("http://{}/proxies/{proxy}", world.toxi_host);

    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .json(&serde_json::json!({"enabled": false}))
        .send()
        .await
        .unwrap_or_else(|e| panic!("failed to disable proxy '{proxy}': {e}"));

    assert!(
        resp.status().is_success(),
        "failed to disable proxy '{proxy}': {}",
        resp.status()
    );

    world.disabled_proxies.push(proxy);

    // Give grob time to detect the broken connections.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
}

/// Re-enables all proxies via Toxiproxy reset + explicit re-enable.
pub async fn cleanup_proxies(world: &E2eWorld) {
    let client = reqwest::Client::new();
    // Reset removes all toxics.
    let _ = client
        .post(&format!("http://{}/reset", world.toxi_host))
        .send()
        .await;
    // Re-enable all known proxies (reset does not re-enable disabled proxies).
    for proxy in &["anthropic-mock", "openai-mock", "gemini-mock"] {
        let url = format!("http://{}/proxies/{proxy}", world.toxi_host);
        let _ = client
            .post(&url)
            .json(&serde_json::json!({"enabled": true}))
            .send()
            .await;
    }
}

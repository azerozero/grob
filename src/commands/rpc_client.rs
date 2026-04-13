//! Lightweight JSON-RPC 2.0 client for calling the running Grob server.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static REQUEST_ID: AtomicU64 = AtomicU64::new(1);

const RPC_TIMEOUT: Duration = Duration::from_secs(2);

/// Sends a JSON-RPC 2.0 call to `{base_url}/rpc`.
///
/// Returns the `result` field on success. Returns an error on
/// transport failure or if the server returns a JSON-RPC error.
pub async fn rpc_call(
    base_url: &str,
    method: &str,
    params: Option<serde_json::Value>,
) -> anyhow::Result<serde_json::Value> {
    let id = REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params.unwrap_or(serde_json::Value::Null),
        "id": id,
    });

    let resp = reqwest::Client::new()
        .post(format!("{base_url}/rpc"))
        .json(&body)
        .timeout(RPC_TIMEOUT)
        .send()
        .await?;

    let status = resp.status();
    let payload: serde_json::Value = resp.json().await?;

    if let Some(err) = payload.get("error") {
        let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
        let msg = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown");
        anyhow::bail!("RPC error {code}: {msg}");
    }

    if !status.is_success() {
        anyhow::bail!("HTTP {status} from server");
    }

    payload
        .get("result")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Missing result in JSON-RPC response"))
}

/// Attempts an RPC call, returning `None` on any failure.
///
/// Useful for optional server queries where local fallback is acceptable.
pub async fn try_rpc_call(
    base_url: &str,
    method: &str,
    params: Option<serde_json::Value>,
) -> Option<serde_json::Value> {
    rpc_call(base_url, method, params).await.ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_id_increments() {
        let a = REQUEST_ID.load(Ordering::Relaxed);
        let _ = REQUEST_ID.fetch_add(1, Ordering::Relaxed);
        let b = REQUEST_ID.load(Ordering::Relaxed);
        assert!(b > a);
    }

    #[tokio::test]
    async fn rpc_call_unreachable_host_returns_error() {
        let result = rpc_call("http://127.0.0.1:1", "grob/server/status", None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn try_rpc_call_unreachable_returns_none() {
        let result = try_rpc_call("http://127.0.0.1:1", "grob/server/status", None).await;
        assert!(result.is_none());
    }
}

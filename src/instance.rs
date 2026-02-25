use crate::cli::format_base_url;

/// Check if an instance is running on the given host:port by hitting /health.
pub async fn is_instance_running(host: &str, port: u16) -> bool {
    let url = format!("{}/health", format_base_url(host, port));
    match reqwest::Client::new()
        .get(&url)
        .timeout(std::time::Duration::from_millis(500))
        .send()
        .await
    {
        Ok(resp) => resp.status().is_success(),
        Err(_) => false,
    }
}

/// Find the PID of a running instance by querying /health.
/// Returns None if the instance is not running or PID is not in the response.
pub async fn find_instance_pid(host: &str, port: u16) -> Option<u32> {
    let url = format!("{}/health", format_base_url(host, port));
    let resp = reqwest::Client::new()
        .get(&url)
        .timeout(std::time::Duration::from_millis(500))
        .send()
        .await
        .ok()?;

    if !resp.status().is_success() {
        return None;
    }

    let body: serde_json::Value = resp.json().await.ok()?;
    body.get("pid")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
}

/// Stop a running instance by finding its PID and sending SIGTERM.
#[cfg(unix)]
#[allow(dead_code)]
pub async fn stop_instance(host: &str, port: u16) -> anyhow::Result<()> {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;

    let pid = find_instance_pid(host, port)
        .await
        .ok_or_else(|| anyhow::anyhow!("No running instance found on {}:{}", host, port))?;

    kill(Pid::from_raw(pid as i32), Signal::SIGTERM)
        .map_err(|e| anyhow::anyhow!("Failed to stop instance (PID {}): {}", pid, e))?;

    // Wait for graceful shutdown
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    Ok(())
}

/// Clean up legacy PID file if it exists.
pub fn cleanup_legacy_pid() {
    let _ = crate::pid::cleanup_pid();
}

/// Try to read PID from legacy PID file (backward compat).
pub fn legacy_pid() -> Option<u32> {
    crate::pid::read_pid().ok()
}

/// Check if a process is running (backward compat wrapper).
pub fn is_process_running(pid: u32) -> bool {
    crate::pid::is_process_running(pid)
}

#[cfg(test)]
mod tests {
    use crate::cli::{format_base_url, format_bind_addr};

    #[test]
    fn test_format_bind_addr() {
        assert_eq!(format_bind_addr("::1", 13456), "[::1]:13456");
        assert_eq!(format_bind_addr("127.0.0.1", 13456), "127.0.0.1:13456");
    }

    #[test]
    fn test_format_base_url() {
        assert_eq!(format_base_url("::", 13456), "http://[::]:13456");
        assert_eq!(
            format_base_url("127.0.0.1", 13456),
            "http://127.0.0.1:13456"
        );
    }
}

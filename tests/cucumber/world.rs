use cucumber::World;
use std::collections::HashMap;

/// Per-client response snapshot for multi-client scenarios.
#[derive(Debug, Default, Clone)]
pub struct ClientSnapshot {
    /// Last HTTP status received by this client.
    pub last_status: u16,
    /// Last HTTP response body.
    pub last_body: String,
    /// Last HTTP response headers.
    pub last_headers: HashMap<String, String>,
    /// Count of successful (200) responses.
    pub ok_count: u32,
}

/// Shared state across all steps in a scenario.
#[derive(Debug, Default, World)]
pub struct E2eWorld {
    /// Grob proxy host:port.
    pub grob_host: String,
    /// VidaiMock host:port.
    pub mock_host: String,
    /// Toxiproxy API host:port.
    pub toxi_host: String,
    /// JWT token for authenticated requests.
    pub jwt: String,
    /// Currently configured LLM CLI name.
    pub cli_name: String,
    /// CLI prompt flag (e.g. "-p" for claude, "-q" for codex).
    pub cli_prompt_flag: String,
    /// Last CLI exit code.
    pub last_exit_code: i32,
    /// Last CLI stdout.
    pub last_stdout: String,
    /// Last CLI stderr.
    pub last_stderr: String,
    /// Last HTTP response status.
    pub last_http_status: u16,
    /// Last HTTP response headers.
    pub last_http_headers: HashMap<String, String>,
    /// Last HTTP response body.
    pub last_http_body: String,
    /// Audit JSONL lines collected from the volume.
    pub audit_lines: Vec<String>,
    /// Toxiproxy proxies disabled during this scenario (for cleanup).
    pub disabled_proxies: Vec<String>,
    /// Temporary grob home directory for wizard tests.
    pub wizard_home: String,
    /// Config content snapshot for before/after comparison.
    pub wizard_config_snapshot: String,
    /// Per-client snapshots for multi-client scenarios (keyed by "A", "B", "C").
    pub clients: HashMap<String, ClientSnapshot>,
    /// SSN value injected in DLP scenarios for later assertion.
    pub injected_ssn: String,
}

impl E2eWorld {
    /// Resolves environment with defaults for local podman pod.
    pub fn init(&mut self) {
        self.grob_host =
            std::env::var("GROB_HOST").unwrap_or_else(|_| "127.0.0.1:13456".to_string());
        self.mock_host =
            std::env::var("MOCK_HOST").unwrap_or_else(|_| "127.0.0.1:8100".to_string());
        self.toxi_host =
            std::env::var("TOXI_HOST").unwrap_or_else(|_| "127.0.0.1:8474".to_string());
        // JWT: env var > token file > empty (falls back to API key).
        self.jwt = std::env::var("E2E_JWT").unwrap_or_else(|_| {
            // Try to read from the e2e auth tokens directory.
            let token_path = std::path::Path::new("tests/e2e/auth/tokens/jwt-default.txt");
            std::fs::read_to_string(token_path)
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        });
    }
}

//! HTTP server, timeouts, TLS and ACME configuration.

use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::cli::Port;

use super::telemetry::TracingConfig;

/// Server configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    /// Listening port (default: 13456)
    #[serde(default)]
    pub port: Port,
    /// Bind host address (default: "::1")
    #[serde(default = "default_host")]
    pub host: String,
    /// Optional API key for authenticating incoming requests
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "crate::auth::token_store::serialize_secret_opt",
        deserialize_with = "crate::auth::token_store::deserialize_secret_opt"
    )]
    pub api_key: Option<SecretString>,
    /// Log verbosity level (default: "info")
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// HTTP client timeout settings
    #[serde(default)]
    pub timeouts: TimeoutConfig,
    /// Request/response tracing configuration
    #[serde(default)]
    pub tracing: TracingConfig,
    /// TLS/HTTPS termination settings
    #[serde(default)]
    pub tls: TlsConfig,
    /// Port for the OAuth callback server (default: 1455)
    #[serde(default = "default_oauth_callback_port")]
    pub oauth_callback_port: u16,
}

// NOTE: 1455 is an unregistered IANA port unlikely to conflict with common
// dev tools. Must match the redirect_uri registered with OAuth providers.
fn default_oauth_callback_port() -> u16 {
    1455
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: Port::default(),
            host: default_host(),
            api_key: None,
            log_level: default_log_level(),
            timeouts: TimeoutConfig::default(),
            tracing: TracingConfig::default(),
            tls: TlsConfig::default(),
            oauth_callback_port: default_oauth_callback_port(),
        }
    }
}

fn default_host() -> String {
    "::1".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

/// TLS configuration for native HTTPS (requires `tls` feature)
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct TlsConfig {
    /// Enable TLS
    #[serde(default)]
    pub enabled: bool,
    /// Path to PEM certificate file (e.g. fullchain.pem from Let's Encrypt)
    #[serde(default)]
    pub cert_path: String,
    /// Path to PEM private key file (e.g. privkey.pem from Let's Encrypt)
    #[serde(default)]
    pub key_path: String,
    /// ACME (Let's Encrypt) auto-certificate configuration
    #[serde(default)]
    pub acme: AcmeConfig,
}

/// ACME (Let's Encrypt) auto-certificate configuration
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct AcmeConfig {
    /// Enable ACME automatic certificate provisioning
    #[serde(default)]
    pub enabled: bool,
    /// Domain names to obtain certificates for
    #[serde(default)]
    pub domains: Vec<String>,
    /// Contact email addresses for Let's Encrypt (e.g. `["admin@example.com"]`).
    #[serde(default)]
    pub contacts: Vec<String>,
    /// Cache directory for certificates (default: ~/.grob/certs/)
    #[serde(default)]
    pub cache_dir: String,
    /// Use Let's Encrypt staging environment (for testing)
    #[serde(default)]
    pub staging: bool,
}

/// Timeout configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TimeoutConfig {
    /// Total API request timeout in milliseconds (default: 600000)
    #[serde(default = "default_api_timeout")]
    pub api_timeout_ms: u64,
    /// TCP connection timeout in milliseconds (default: 10000)
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_ms: u64,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            api_timeout_ms: default_api_timeout(),
            connect_timeout_ms: default_connect_timeout(),
        }
    }
}

// NOTE: 10 min accommodates Claude's extended thinking (budget_tokens up to
// 128K) which can take 5-8 min for complex reasoning tasks.
fn default_api_timeout() -> u64 {
    600_000
}

// NOTE: 10s covers slow DNS + TLS handshake on cold connections. Most
// providers connect in <1s; this catches network-level failures early.
fn default_connect_timeout() -> u64 {
    10_000
}

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ── Validated newtypes ──────────────────────────────────────────────────────

/// Monthly budget in USD. Rejects negative values at parse time.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(transparent)]
pub struct BudgetUsd(f64);

impl BudgetUsd {
    /// Creates a new `BudgetUsd`, returning an error if negative.
    pub fn new(value: f64) -> Result<Self, String> {
        if value < 0.0 {
            Err(format!("budget_usd must be non-negative, got {}", value))
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the inner USD value.
    pub fn value(self) -> f64 {
        self.0
    }
}

impl Default for BudgetUsd {
    fn default() -> Self {
        Self(0.0)
    }
}

impl<'de> Deserialize<'de> for BudgetUsd {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = f64::deserialize(deserializer)?;
        BudgetUsd::new(v).map_err(serde::de::Error::custom)
    }
}

/// TCP port number. Rejects 0 at parse time, defaults to 13456.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Port(u16);

impl Port {
    /// Creates a new `Port`, returning an error if 0.
    pub fn new(value: u16) -> Result<Self, String> {
        if value == 0 {
            Err("port must be non-zero".to_string())
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the inner port number.
    pub fn value(self) -> u16 {
        self.0
    }
}

impl Default for Port {
    fn default() -> Self {
        Self(13456)
    }
}

impl From<Port> for u16 {
    fn from(p: Port) -> u16 {
        p.0
    }
}

impl std::fmt::Display for Port {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<BudgetUsd> for f64 {
    fn from(b: BudgetUsd) -> f64 {
        b.0
    }
}

impl std::fmt::Display for BudgetUsd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<BodySizeLimit> for usize {
    fn from(b: BodySizeLimit) -> usize {
        b.0
    }
}

impl std::fmt::Display for BodySizeLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<'de> Deserialize<'de> for Port {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = u16::deserialize(deserializer)?;
        Port::new(v).map_err(serde::de::Error::custom)
    }
}

/// Request body size limit in bytes. Rejects 0 at parse time, defaults to 10 MiB.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(transparent)]
pub struct BodySizeLimit(usize);

impl BodySizeLimit {
    /// Creates a new `BodySizeLimit`, returning an error if 0.
    pub fn new(value: usize) -> Result<Self, String> {
        if value == 0 {
            Err("max_body_size must be non-zero".to_string())
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the inner byte count.
    pub fn value(self) -> usize {
        self.0
    }
}

impl Default for BodySizeLimit {
    fn default() -> Self {
        Self(10 * 1024 * 1024) // 10 MiB
    }
}

impl<'de> Deserialize<'de> for BodySizeLimit {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = usize::deserialize(deserializer)?;
        BodySizeLimit::new(v).map_err(serde::de::Error::custom)
    }
}

/// Where the configuration comes from: local file or remote URL
#[derive(Debug, Clone)]
pub enum ConfigSource {
    File(PathBuf),
    Url(String),
}

impl std::fmt::Display for ConfigSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigSource::File(p) => write!(f, "{}", p.display()),
            ConfigSource::Url(u) => write!(f, "{}", u),
        }
    }
}

/// Budget configuration
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct BudgetConfig {
    /// Global monthly hard cap in USD (0 = unlimited)
    #[serde(default)]
    pub monthly_limit_usd: BudgetUsd,
    /// Log warning at this percentage of budget (default: 80)
    #[serde(default = "default_warn_percent")]
    pub warn_at_percent: u32,
}

fn default_warn_percent() -> u32 {
    80
}

/// Security configuration (wired into middleware stack)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityConfig {
    /// Master switch for security middleware
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Rate limit: requests per second per tenant/IP
    #[serde(default = "default_rate_limit_rps")]
    pub rate_limit_rps: u32,
    /// Rate limit: burst capacity
    #[serde(default = "default_rate_limit_burst")]
    pub rate_limit_burst: u32,
    /// Maximum request body size in bytes (default: 10MB)
    #[serde(default)]
    pub max_body_size: BodySizeLimit,
    /// Apply OWASP security headers to all responses
    #[serde(default = "default_true")]
    pub security_headers: bool,
    /// Enable circuit breaker for provider calls
    #[serde(default = "default_true")]
    pub circuit_breaker: bool,
    /// Directory for signed audit logs (empty = disabled)
    #[serde(default)]
    pub audit_dir: String,
    /// Audit log signing algorithm: "ecdsa-p256" (default) or "hmac-sha256"
    #[serde(default)]
    pub audit_signing_algorithm: String,
    /// Path to HMAC key file (only for hmac-sha256 algorithm; default: <audit_dir>/audit_hmac.key)
    #[serde(default)]
    pub audit_hmac_key_path: String,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rate_limit_rps: default_rate_limit_rps(),
            rate_limit_burst: default_rate_limit_burst(),
            max_body_size: BodySizeLimit::default(),
            security_headers: true,
            circuit_breaker: true,
            audit_dir: String::new(),
            audit_signing_algorithm: String::new(),
            audit_hmac_key_path: String::new(),
        }
    }
}

fn default_rate_limit_rps() -> u32 {
    100
}

fn default_rate_limit_burst() -> u32 {
    200
}

/// LLM response cache configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CacheConfig {
    /// Enable response caching (only for temperature=0 requests)
    #[serde(default)]
    pub enabled: bool,
    /// Maximum number of cached responses
    #[serde(default = "default_cache_max_capacity")]
    pub max_capacity: u64,
    /// TTL in seconds for cached entries
    #[serde(default = "default_cache_ttl")]
    pub ttl_secs: u64,
    /// Maximum single entry size in bytes (skip caching responses larger than this)
    #[serde(default = "default_cache_max_entry_bytes")]
    pub max_entry_bytes: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_capacity: default_cache_max_capacity(),
            ttl_secs: default_cache_ttl(),
            max_entry_bytes: default_cache_max_entry_bytes(),
        }
    }
}

fn default_cache_max_capacity() -> u64 {
    2000
}

fn default_cache_ttl() -> u64 {
    3600 // 1 hour
}

fn default_cache_max_entry_bytes() -> usize {
    2 * 1024 * 1024 // 2 MiB
}

/// EU AI Act compliance configuration
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ComplianceConfig {
    /// Enable EU AI Act compliance features
    #[serde(default)]
    pub enabled: bool,
    /// Add transparency headers (X-AI-Provider, X-AI-Model, X-AI-Generated, X-Grob-Audit-Id)
    #[serde(default)]
    pub transparency_headers: bool,
    /// Record model name in audit entries (Article 12)
    #[serde(default)]
    pub audit_model_name: bool,
    /// Record token counts in audit entries (Article 12)
    #[serde(default)]
    pub audit_token_counts: bool,
    /// Enable risk classification (Article 14)
    #[serde(default)]
    pub risk_classification: bool,
    /// Minimum risk level to trigger escalation (low, medium, high, critical)
    #[serde(default = "default_escalation_threshold")]
    pub escalation_threshold: String,
    /// Optional webhook URL for risk escalation notifications
    #[serde(default)]
    pub escalation_webhook: Option<String>,
}

fn default_escalation_threshold() -> String {
    "high".to_string()
}

/// User-defined configuration section (preserved across preset applies)
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct UserConfig {
    /// Free-form notes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// Environment variable overrides
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub env: std::collections::HashMap<String, String>,
}

/// Preset configuration
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct PresetConfig {
    /// URL to sync presets from (HTTP raw URL or git repo URL)
    pub sync_url: Option<String>,
    /// Sync interval: "6h", "12h", "1d", "30m"
    pub sync_interval: Option<String>,
    /// Set to false to disable auto-sync even if sync_url is configured
    #[serde(default = "default_auto_sync")]
    pub auto_sync: bool,
    /// Currently active preset name
    pub active: Option<String>,
}

fn default_auto_sync() -> bool {
    true
}

/// Server configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default)]
    pub port: Port,
    #[serde(default = "default_host")]
    pub host: String,
    pub api_key: Option<String>,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub timeouts: TimeoutConfig,
    #[serde(default)]
    pub tracing: TracingConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    /// Port for the OAuth callback server (default: 1455)
    #[serde(default = "default_oauth_callback_port")]
    pub oauth_callback_port: u16,
}

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
    /// Contact email addresses for Let's Encrypt (e.g. ["admin@example.com"])
    #[serde(default)]
    pub contacts: Vec<String>,
    /// Cache directory for certificates (default: ~/.grob/certs/)
    #[serde(default)]
    pub cache_dir: String,
    /// Use Let's Encrypt staging environment (for testing)
    #[serde(default)]
    pub staging: bool,
}

/// Message tracing configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TracingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_tracing_path")]
    pub path: String,
    /// Omit system prompt from traces (default: true, since system prompts are huge)
    #[serde(default = "default_true")]
    pub omit_system_prompt: bool,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_tracing_path(),
            omit_system_prompt: true,
        }
    }
}

fn default_tracing_path() -> String {
    "~/.grob/trace.jsonl".to_string()
}

fn default_true() -> bool {
    true
}

/// Timeout configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TimeoutConfig {
    #[serde(default = "default_api_timeout")]
    pub api_timeout_ms: u64,
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

fn default_api_timeout() -> u64 {
    600_000 // 10 minutes
}

fn default_connect_timeout() -> u64 {
    10_000 // 10 seconds
}

/// Router configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RouterConfig {
    pub default: String,
    pub background: Option<String>,
    pub think: Option<String>,
    pub websearch: Option<String>,
    /// Regex pattern for auto-mapping models (e.g., "^claude-").
    /// If empty/null, defaults to Claude models only.
    pub auto_map_regex: Option<String>,
    /// Regex pattern for detecting background tasks (e.g., "(?i)claude.*haiku").
    /// If empty/null, defaults to claude-haiku pattern.
    pub background_regex: Option<String>,
    /// Prompt-based routing rules. Routes to specific models when patterns match user prompt.
    #[serde(default)]
    pub prompt_rules: Vec<PromptRule>,
    /// Enable GDPR mode: only route to EU/global providers
    #[serde(default)]
    pub gdpr: bool,
    /// Region filter (e.g., "eu"). Used with gdpr=true to restrict providers
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
}

/// Prompt-based routing rule
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PromptRule {
    /// Regex pattern to match against user prompt content.
    /// Can include capture groups: (pattern) or named: (?P<name>pattern)
    pub pattern: String,
    /// Model to route to when pattern matches.
    /// Can reference capture groups: $1, $name, ${1}, ${name}, or mixed like "prefix-$1"
    pub model: String,
    /// Strip the matched phrase from the prompt (default: false)
    #[serde(default)]
    pub strip_match: bool,
}

/// Strategy for routing requests across multiple provider mappings
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ModelStrategy {
    /// Try providers sequentially by priority (default)
    #[default]
    Fallback,
    /// Send to multiple providers in parallel
    FanOut,
}

impl ModelStrategy {
    pub fn label(&self) -> &'static str {
        match self {
            ModelStrategy::Fallback => "fallback",
            ModelStrategy::FanOut => "fan_out",
        }
    }
}

/// Fan-out mode configuration
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FanOutMode {
    /// Return first successful response (fastest)
    #[default]
    Fastest,
    /// Send all responses to a judge model to pick the best
    BestQuality,
    /// Score responses by weighted criteria (latency, cost, length)
    Weighted,
}

/// Configuration for fan-out multi-response mode
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FanOutConfig {
    /// Fan-out mode
    #[serde(default)]
    pub mode: FanOutMode,
    /// Model to use as judge (for best_quality mode)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub judge_model: Option<String>,
    /// Criteria for the judge model
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub judge_criteria: Option<String>,
    /// Number of providers to fan out to (default: all mappings)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<usize>,
}

/// Model configuration with 1:N provider mappings
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ModelConfig {
    /// External model name (used in API requests)
    pub name: String,
    /// List of provider mappings with priorities (fallback support)
    pub mappings: Vec<ModelMapping>,
    /// Per-model monthly budget in USD (optional, overrides provider and global)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_usd: Option<BudgetUsd>,
    /// Strategy for using multiple mappings (default: fallback)
    #[serde(default)]
    pub strategy: ModelStrategy,
    /// Fan-out configuration (only used when strategy = fan_out)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fan_out: Option<FanOutConfig>,
    /// Deprecation warning message (logged + X-Model-Deprecated header)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deprecated: Option<String>,
}

/// Model mapping to a specific provider
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ModelMapping {
    /// Priority for this mapping (1 = highest priority)
    pub priority: u32,
    /// Provider name
    pub provider: String,
    /// Actual model name to use with the provider
    pub actual_model: String,
    /// Inject continuation prompt after tool results (for models that stop prematurely)
    #[serde(default)]
    pub inject_continuation_prompt: bool,
}

/// Per-project configuration overlay
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ProjectConfig {
    /// Router overrides
    #[serde(default)]
    pub router: Option<ProjectRouterOverlay>,
    /// Budget override
    #[serde(default)]
    pub budget: Option<BudgetConfig>,
    /// Preset name override
    #[serde(default)]
    pub presets: Option<PresetConfig>,
}

/// Router overlay for per-project config
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ProjectRouterOverlay {
    pub default: Option<String>,
    pub think: Option<String>,
    pub background: Option<String>,
    pub websearch: Option<String>,
    #[serde(default)]
    pub prompt_rules: Vec<PromptRule>,
}

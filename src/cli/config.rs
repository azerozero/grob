use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use super::{BodySizeLimit, BudgetUsd, Port};

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

// NOTE: 80% gives ~6 days warning before exhaustion at constant spend rate
// on a monthly budget, enough time for a human to react and adjust.
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
    /// Entries per Merkle batch (1 = per-entry signing, >1 = batch)
    #[serde(default = "default_batch_size")]
    pub audit_batch_size: usize,
    /// Max milliseconds before flushing an incomplete batch
    #[serde(default = "default_flush_interval_ms")]
    pub audit_flush_interval_ms: u64,
    /// Include Merkle inclusion proof in each batch entry
    #[serde(default)]
    pub audit_include_merkle_proof: bool,
    /// Enable adaptive provider scoring (opt-in, default false)
    #[serde(default)]
    pub adaptive_scoring: bool,
    /// EWMA alpha for latency smoothing (0.0–1.0, default 0.3)
    #[serde(default = "default_scoring_latency_alpha")]
    pub scoring_latency_alpha: f64,
    /// Rolling window size for success rate calculation (default 50)
    #[serde(default = "default_scoring_window_size")]
    pub scoring_window_size: usize,
    /// Decay rate per second of inactivity (default 0.001)
    #[serde(default = "default_scoring_decay_rate")]
    pub scoring_decay_rate: f64,
    /// Persist scores across restarts (default false)
    #[serde(default)]
    pub scoring_persist: bool,
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
            audit_batch_size: default_batch_size(),
            audit_flush_interval_ms: default_flush_interval_ms(),
            audit_include_merkle_proof: false,
            adaptive_scoring: false,
            scoring_latency_alpha: default_scoring_latency_alpha(),
            scoring_window_size: default_scoring_window_size(),
            scoring_decay_rate: default_scoring_decay_rate(),
            scoring_persist: false,
        }
    }
}

fn default_batch_size() -> usize {
    1
}

fn default_flush_interval_ms() -> u64 {
    5000
}

// NOTE: 100 rps sustains ~10 concurrent Claude Code sessions (each bursting
// ~10 req/s during tool-use loops) while protecting providers from runaway clients.
fn default_rate_limit_rps() -> u32 {
    100
}

// NOTE: 2x sustained rate allows short tool-use bursts without 429s.
fn default_rate_limit_burst() -> u32 {
    200
}

// NOTE: 0.3 gives ~70% weight to recent latency, ~30% to history. Standard
// EWMA smoothing factor — higher values react faster but amplify noise.
fn default_scoring_latency_alpha() -> f64 {
    0.3
}

// NOTE: 50-request window balances responsiveness (detects degradation within
// ~1 min at typical traffic) vs stability (no jitter from single outliers).
fn default_scoring_window_size() -> usize {
    50
}

// NOTE: 0.001/s means idle providers lose ~3.5% score per hour, preventing
// stale high scores while keeping recently-active providers competitive.
fn default_scoring_decay_rate() -> f64 {
    0.001
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

// NOTE: 2000 entries at ~2 KiB avg response = ~4 MiB memory. Enough for a
// full day of Claude Code sessions with temperature=0 (highly cacheable).
fn default_cache_max_capacity() -> u64 {
    2000
}

// NOTE: 1 hour balances freshness (model behavior doesn't change intra-hour)
// vs hit rate. Longer TTLs risk stale responses after provider updates.
fn default_cache_ttl() -> u64 {
    3600
}

// NOTE: 2 MiB covers 99%+ of LLM responses. Responses above this threshold
// (e.g., large code generation) have low cache hit probability anyway.
fn default_cache_max_entry_bytes() -> usize {
    2 * 1024 * 1024
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

/// Enforcement policy for security features that can warn or block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    /// Feature disabled entirely.
    #[default]
    Off,
    /// Log a warning at startup but allow the server to run.
    Warn,
    /// Refuse to start if the requirement is not met.
    Enforce,
}

/// Trusted Execution Environment (TEE) configuration.
///
/// Controls whether grob requires, recommends, or ignores TEE attestation.
/// When enabled, grob checks for AMD SEV-SNP at startup and can derive
/// hardware-bound keys for secret sealing.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TeeConfig {
    /// Whether TEE presence is off, warned, or enforced.
    #[serde(default)]
    pub mode: EnforcementMode,
    /// Publish an attestation report in the audit log on startup.
    #[serde(default = "default_true")]
    pub attestation_audit: bool,
    /// Derive encryption keys from TEE hardware (SNP_GET_DERIVED_KEY)
    /// instead of random filesystem keys.
    #[serde(default)]
    pub sealed_keys: bool,
}

impl Default for TeeConfig {
    fn default() -> Self {
        Self {
            mode: EnforcementMode::Off,
            attestation_audit: true,
            sealed_keys: false,
        }
    }
}

/// FIPS 140-3 compliance configuration.
///
/// When enabled, grob verifies that the crypto backend operates in FIPS
/// mode (e.g. OpenSSL FIPS provider or SymCrypt) and restricts algorithms
/// to FIPS-approved ones.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FipsConfig {
    /// Whether FIPS mode is off, warned, or enforced.
    #[serde(default)]
    pub mode: EnforcementMode,
}

impl Default for FipsConfig {
    fn default() -> Self {
        Self {
            mode: EnforcementMode::Off,
        }
    }
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

/// Message tracing configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TracingConfig {
    /// Enable request/response tracing to file
    #[serde(default)]
    pub enabled: bool,
    /// File path for trace output (default: ~/.grob/trace.jsonl)
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

/// OpenTelemetry export configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OtelConfig {
    /// Enable OpenTelemetry trace export
    #[serde(default)]
    pub enabled: bool,
    /// OTLP endpoint (default: http://localhost:4317)
    #[serde(default = "default_otel_endpoint")]
    pub endpoint: String,
    /// Service name reported in traces (default: "grob")
    #[serde(default = "default_otel_service_name")]
    pub service_name: String,
}

impl Default for OtelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_otel_endpoint(),
            service_name: default_otel_service_name(),
        }
    }
}

fn default_otel_endpoint() -> String {
    "http://localhost:4317".to_string()
}

fn default_otel_service_name() -> String {
    "grob".to_string()
}

fn default_true() -> bool {
    true
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

/// Router configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RouterConfig {
    /// Default model for unclassified requests
    pub default: String,
    /// Model for background/low-priority tasks
    pub background: Option<String>,
    /// Model for extended-thinking requests
    pub think: Option<String>,
    /// Model for web-search-enabled requests
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
    /// Can include capture groups: `(pattern)` or named: `(?P<name>pattern)`.
    pub pattern: String,
    /// Model to route to when pattern matches.
    /// Can reference capture groups: $1, $name, ${1}, ${name}, or mixed like "prefix-$1"
    pub model: String,
    /// Strip the matched phrase from the prompt (default: false)
    #[serde(default)]
    pub strip_match: bool,
}

/// Strategy for cycling through pooled API keys.
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PoolStrategy {
    /// Exhaust one key before moving to the next.
    #[default]
    Sequential,
    /// Rotate keys on every request.
    RoundRobin,
    /// Use first key; only switch on error.
    Fallback,
}

/// Multi-account key pool configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PoolConfig {
    /// Key rotation strategy (default: sequential).
    #[serde(default)]
    pub strategy: PoolStrategy,
    /// Additional API keys beyond the primary `api_key`.
    pub keys: Vec<String>,
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
    /// Returns the strategy name as a static string slice.
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
    /// Override for the default model
    pub default: Option<String>,
    /// Override for the thinking model
    pub think: Option<String>,
    /// Override for the background model
    pub background: Option<String>,
    /// Override for the web-search model
    pub websearch: Option<String>,
    /// Additional prompt-based routing rules (prepended to global rules)
    #[serde(default)]
    pub prompt_rules: Vec<PromptRule>,
}

// ── Harness (record/replay) ──────────────────────────────────────────────────

/// Configuration for the record-and-replay harness (opt-in `harness` feature).
///
/// The harness records HTTP request/response pairs to a tape file for offline
/// replay in sandwich tests. Enable via `[harness]` in `grob.toml`.
///
/// The `GROB_HARNESS_RECORD` environment variable overrides `record_path` when set.
#[cfg(feature = "harness")]
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct HarnessConfig {
    /// Path to the tape file for recording. When set, recording is active.
    ///
    /// Overridden by the `GROB_HARNESS_RECORD` environment variable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_path: Option<std::path::PathBuf>,

    /// Path to replay from. Mutually exclusive with `record_path`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_path: Option<std::path::PathBuf>,
}

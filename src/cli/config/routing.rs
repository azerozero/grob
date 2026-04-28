//! Router rules, model mappings, fan-out, tiers and per-project overlays.

use serde::{Deserialize, Serialize};

use crate::cli::BudgetUsd;

use super::budget::BudgetConfig;
use super::user::PresetConfig;

/// Router configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

/// Declarative match conditions for tier activation.
///
/// All specified fields are AND-combined: every non-empty field must match
/// for the tier to activate. Within a field (e.g. `keywords`), values are
/// OR-combined (any hit satisfies that field). Omitted/empty fields are
/// unconstrained.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct TierMatchCondition {
    /// Substring keywords matched against the last user message (OR-combined, case-insensitive).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keywords: Vec<String>,
    /// Glob patterns matched against file paths found in message content (OR-combined).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub file_patterns: Vec<String>,
    /// Tool names that must be present in the request (OR-combined).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<String>,
    /// Activates when `max_tokens >= this` value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens_above: Option<u32>,
    /// Activates when `max_tokens <= this` value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens_below: Option<u32>,
    /// Activates when message count `>= this` value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_messages: Option<usize>,
    /// Activates when estimated input tokens `>= this` value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_input_tokens: Option<u32>,
}

/// Declarative tier configuration mapping complexity tiers to provider lists.
///
/// Each `[[tiers]]` entry binds a [`ComplexityTier`](crate::routing::classify::ComplexityTier)
/// name (`trivial`, `medium`, `complex`) to an ordered list of provider names.
/// When the scoring heuristic classifies a request, the dispatch pipeline
/// resolves providers from the matching tier instead of the default model mappings.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TierConfig {
    /// Tier name — must match a `ComplexityTier` variant (case-insensitive).
    pub name: String,
    /// Ordered list of provider names to use for this tier.
    pub providers: Vec<String>,
    /// Send the request to all tier providers in parallel (fan-out).
    #[serde(default)]
    pub fanout: bool,
    /// Optional declarative match conditions (bypasses the algorithmic scorer).
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "match")]
    pub match_conditions: Option<TierMatchCondition>,
}

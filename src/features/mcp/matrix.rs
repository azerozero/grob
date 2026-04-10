//! Tool matrix catalogue: static TOML-defined tool capabilities per provider.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Weight applied to static reliability when blending with runtime scores.
///
/// Empirically chosen: 40% static gives a stable baseline while allowing
/// 60% of the composite to reflect real-world bench observations.
pub(crate) const STATIC_BLEND_WEIGHT: f64 = 0.4;

/// Weight applied to runtime scores when blending (1 - STATIC_BLEND_WEIGHT).
pub(crate) const RUNTIME_BLEND_WEIGHT: f64 = 0.6;

/// Reliability score for a tool on a specific provider.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProviderToolCapability {
    /// Static reliability from the catalogue (0.0..1.0).
    pub reliability: f64,
}

/// Schema definition for a tool's expected input.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ToolSchema {
    /// JSON Schema type (typically "object").
    #[serde(default)]
    pub r#type: String,
    /// Property definitions for the tool input.
    #[serde(default)]
    pub properties: HashMap<String, serde_json::Value>,
    /// Names of required input properties.
    #[serde(default)]
    pub required: Vec<String>,
}

/// Single tool entry in the matrix catalogue.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ToolEntry {
    /// Canonical tool name.
    pub name: String,
    /// Alternative names that map to this tool.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Tool category (e.g. "retrieval", "code", "math").
    #[serde(default)]
    pub category: String,
    /// Expected input schema for validation.
    #[serde(default)]
    pub schema: ToolSchema,
    /// Per-provider static capabilities.
    #[serde(default)]
    pub providers: HashMap<String, ProviderToolCapability>,
}

/// Runtime score for a (tool, provider) pair.
#[derive(Debug, Clone, Serialize)]
pub struct ToolScore {
    /// Combined static + dynamic score.
    pub composite: f64,
    /// Last bench timestamp (epoch seconds).
    pub last_bench_epoch: u64,
    /// Per-metric scores from the bench engine.
    pub metrics: HashMap<String, f64>,
}

impl Default for ToolScore {
    fn default() -> Self {
        Self {
            // Unseen tools start at 1.0 (optimistic) to avoid penalizing tools
            // before any bench data is collected.
            composite: 1.0,
            last_bench_epoch: 0,
            metrics: HashMap::new(),
        }
    }
}

/// Thread-safe runtime score store for (tool, provider) pairs.
///
/// Encapsulates the nested `Arc<RwLock<…>>` so callers never see the raw lock.
#[derive(Debug, Clone)]
pub struct RuntimeScores(Arc<RwLock<HashMap<String, HashMap<String, ToolScore>>>>);

impl RuntimeScores {
    /// Creates an empty score store.
    pub fn new() -> Self {
        Self(Arc::new(RwLock::new(HashMap::new())))
    }

    /// Inserts or updates the score for a (tool, provider) pair.
    pub async fn insert(
        &self,
        tool: impl Into<String>,
        provider: impl Into<String>,
        score: ToolScore,
    ) {
        self.0
            .write()
            .await
            .entry(tool.into())
            .or_default()
            .insert(provider.into(), score);
    }

    /// Returns the score for a (tool, provider) pair.
    pub async fn get(&self, tool: &str, provider: &str) -> Option<ToolScore> {
        self.0
            .read()
            .await
            .get(tool)
            .and_then(|providers| providers.get(provider))
            .cloned()
    }

    /// Returns a flat snapshot of all (tool, provider, score) triples.
    pub async fn snapshot(&self) -> Vec<(String, String, ToolScore)> {
        let guard = self.0.read().await;
        let mut result = Vec::new();
        for (tool, providers) in guard.iter() {
            for (provider, score) in providers {
                result.push((tool.clone(), provider.clone(), score.clone()));
            }
        }
        result
    }
}

impl Default for RuntimeScores {
    fn default() -> Self {
        Self::new()
    }
}

/// TOML file wrapper — `[[tools]]` array.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
struct ToolMatrixFile {
    #[serde(default)]
    tools: Vec<ToolEntry>,
}

/// In-memory tool matrix with indices for fast lookup.
#[derive(Clone)]
pub struct ToolMatrix {
    /// All tool entries from the catalogue.
    entries: Vec<ToolEntry>,
    /// name -> index into `entries`.
    name_index: HashMap<String, usize>,
    /// alias -> index into `entries`.
    alias_index: HashMap<String, usize>,
    /// Runtime scores from bench engine, keyed by (tool, provider).
    runtime_scores: RuntimeScores,
}

impl std::fmt::Debug for ToolMatrix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolMatrix")
            .field("tool_count", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl ToolMatrix {
    /// Loads the tool matrix from a TOML file path.
    ///
    /// Expands `~` to the user home directory. Returns an empty matrix if the
    /// file does not exist or cannot be parsed.
    pub fn load(path: impl AsRef<std::path::Path>) -> Self {
        let path = path.as_ref();
        let expanded = if path.starts_with("~") {
            match crate::home_dir() {
                Some(home) => match path.strip_prefix("~") {
                    Ok(rest) => home.join(rest),
                    Err(_) => path.to_path_buf(),
                },
                None => {
                    tracing::warn!(path = %path.display(), "Cannot expand home directory in matrix path");
                    return Self::empty();
                }
            }
        } else {
            path.to_path_buf()
        };

        let content = match std::fs::read_to_string(&expanded) {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!(
                    path = %expanded.display(),
                    error = %e,
                    "Tool matrix file not found"
                );
                return Self::empty();
            }
        };

        match toml::from_str::<ToolMatrixFile>(&content) {
            Ok(file) => {
                let count = file.tools.len();
                let matrix = Self::from_entries(file.tools);
                tracing::info!(
                    tool_count = count,
                    path = %expanded.display(),
                    "Tool matrix loaded"
                );
                matrix
            }
            Err(e) => {
                tracing::warn!(
                    path = %expanded.display(),
                    error = %e,
                    "Failed to parse tool matrix"
                );
                Self::empty()
            }
        }
    }

    /// Creates a matrix from a list of entries.
    pub fn from_entries(entries: Vec<ToolEntry>) -> Self {
        let mut name_index = HashMap::with_capacity(entries.len());
        let mut alias_index = HashMap::new();

        for (idx, entry) in entries.iter().enumerate() {
            name_index.insert(entry.name.clone(), idx);
            for alias in &entry.aliases {
                alias_index.insert(alias.clone(), idx);
            }
        }

        Self {
            entries,
            name_index,
            alias_index,
            runtime_scores: RuntimeScores::new(),
        }
    }

    /// Creates an empty matrix.
    pub fn empty() -> Self {
        Self::from_entries(Vec::new())
    }

    /// Returns the total number of tools in the catalogue.
    pub fn tool_count(&self) -> usize {
        self.entries.len()
    }

    /// Looks up a tool by canonical name or alias.
    pub fn query(&self, name: &str) -> Option<&ToolEntry> {
        self.name_index
            .get(name)
            .or_else(|| self.alias_index.get(name))
            .map(|&idx| &self.entries[idx])
    }

    /// Returns all tool entries.
    pub fn all_entries(&self) -> &[ToolEntry] {
        &self.entries
    }

    /// Returns the best provider for a tool based on static reliability.
    pub fn best_provider(&self, tool_name: &str) -> Option<(&str, f64)> {
        let entry = self.query(tool_name)?;
        entry
            .providers
            .iter()
            .max_by(|a, b| a.1.reliability.total_cmp(&b.1.reliability))
            .map(|(name, cap)| (name.as_str(), cap.reliability))
    }

    /// Returns the max score (static or runtime) for a tool across all providers.
    pub async fn max_score(&self, tool_name: &str) -> f64 {
        let entry = match self.query(tool_name) {
            Some(e) => e,
            None => return 0.0,
        };

        let mut max = 0.0_f64;

        for (provider, cap) in &entry.providers {
            let runtime = self
                .runtime_scores
                .get(tool_name, provider)
                .await
                .map(|s| s.composite)
                .unwrap_or(0.0);
            let blended = if runtime > 0.0 {
                STATIC_BLEND_WEIGHT * cap.reliability + RUNTIME_BLEND_WEIGHT * runtime
            } else {
                cap.reliability
            };
            max = max.max(blended);
        }

        max
    }

    /// Updates the runtime score for a (tool, provider) pair.
    pub async fn update_score(
        &self,
        tool: &str,
        provider: &str,
        composite: f64,
        metrics: HashMap<String, f64>,
    ) {
        let score = ToolScore {
            composite,
            last_bench_epoch: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            metrics,
        };
        self.runtime_scores.insert(tool, provider, score).await;
    }

    /// Returns a cloned handle to the runtime scores.
    ///
    /// Used internally by the bench engine to update scores directly.
    pub(crate) fn scores_handle(&self) -> RuntimeScores {
        self.runtime_scores.clone()
    }
}

impl Default for ToolMatrix {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entries() -> Vec<ToolEntry> {
        vec![ToolEntry {
            name: "web_search".to_string(),
            aliases: vec!["brave_search".to_string()],
            category: "retrieval".to_string(),
            schema: ToolSchema::default(),
            providers: HashMap::from([
                (
                    "anthropic".to_string(),
                    ProviderToolCapability { reliability: 0.95 },
                ),
                (
                    "openai".to_string(),
                    ProviderToolCapability { reliability: 0.90 },
                ),
            ]),
        }]
    }

    #[test]
    fn test_query_by_name() {
        let matrix = ToolMatrix::from_entries(sample_entries());
        assert!(matrix.query("web_search").is_some());
    }

    #[test]
    fn test_query_by_alias() {
        let matrix = ToolMatrix::from_entries(sample_entries());
        let entry = matrix.query("brave_search").unwrap();
        assert_eq!(entry.name, "web_search");
    }

    #[test]
    fn test_query_missing() {
        let matrix = ToolMatrix::from_entries(sample_entries());
        assert!(matrix.query("nonexistent").is_none());
    }

    #[test]
    fn test_best_provider() {
        let matrix = ToolMatrix::from_entries(sample_entries());
        let (provider, score) = matrix.best_provider("web_search").unwrap();
        assert_eq!(provider, "anthropic");
        assert!((score - 0.95).abs() < f64::EPSILON);
    }

    #[test]
    fn test_tool_count() {
        let matrix = ToolMatrix::from_entries(sample_entries());
        assert_eq!(matrix.tool_count(), 1);
    }

    #[tokio::test]
    async fn test_update_and_read_score() {
        let matrix = ToolMatrix::from_entries(sample_entries());
        matrix
            .update_score("web_search", "anthropic", 0.88, HashMap::new())
            .await;
        let score = matrix
            .scores_handle()
            .get("web_search", "anthropic")
            .await
            .unwrap();
        assert!((score.composite - 0.88).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_max_score_with_runtime() {
        let matrix = ToolMatrix::from_entries(sample_entries());
        // No runtime scores: max = static max (0.95)
        let max = matrix.max_score("web_search").await;
        assert!((max - 0.95).abs() < f64::EPSILON);

        // Add runtime score: blended = 0.4 * 0.95 + 0.6 * 1.0 = 0.98
        matrix
            .update_score("web_search", "anthropic", 1.0, HashMap::new())
            .await;
        let max = matrix.max_score("web_search").await;
        assert!((max - 0.98).abs() < 0.01);
    }

    #[test]
    fn test_load_nonexistent() {
        let matrix = ToolMatrix::load("/nonexistent/path.toml");
        assert_eq!(matrix.tool_count(), 0);
    }

    #[test]
    fn test_parse_toml_roundtrip() {
        let toml_str = r#"
[[tools]]
name = "code_exec"
aliases = ["run_code"]
category = "execution"
[tools.schema]
type = "object"
[tools.schema.properties]
code = { type = "string" }
[tools.providers.anthropic]
reliability = 0.85
        "#;
        let file: super::ToolMatrixFile = toml::from_str(toml_str).unwrap();
        assert_eq!(file.tools.len(), 1);
        assert_eq!(file.tools[0].name, "code_exec");
        assert_eq!(file.tools[0].aliases, vec!["run_code"]);
    }

    #[test]
    fn test_debug_impl() {
        let matrix = ToolMatrix::from_entries(sample_entries());
        let debug = format!("{:?}", matrix);
        assert!(debug.contains("tool_count: 1"));
    }
}

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Top-level DLP configuration, mapped from `[dlp]` in TOML.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct DlpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub scan_input: bool,
    #[serde(default = "default_true")]
    pub scan_output: bool,
    /// If non-empty, load and merge additional rules from this TOML file.
    #[serde(default)]
    pub rules_file: String,
    #[serde(default)]
    pub secrets: Vec<SecretRule>,
    #[serde(default)]
    pub custom_prefixes: Vec<CustomPrefixRule>,
    #[serde(default)]
    pub names: Vec<NameRule>,
    #[serde(default)]
    pub entropy: EntropyConfig,
    /// Enable per-API-key DLP session isolation.
    /// When true, each API key gets its own NameAnonymizer (unique pseudonyms)
    /// and CanaryGenerator (independent counter). Default: false.
    #[serde(default)]
    pub enable_sessions: bool,
}

fn default_true() -> bool {
    true
}

/// Gitleaks-style secret pattern rule.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecretRule {
    pub name: String,
    pub prefix: String,
    pub pattern: String,
    #[serde(default = "default_action_canary")]
    pub action: SecretAction,
}

/// Custom prefix rule for user-specific tokens (e.g. vault tokens).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CustomPrefixRule {
    pub name: String,
    pub prefix: String,
    pub length: usize,
    #[serde(default = "default_action_canary")]
    pub action: SecretAction,
}

/// Name anonymization rule.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NameRule {
    pub term: String,
    #[serde(default = "default_action_pseudonym")]
    pub action: NameAction,
}

/// Async entropy detection config.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EntropyConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_action_log")]
    pub action: EntropyAction,
}

impl Default for EntropyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            action: EntropyAction::Log,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SecretAction {
    Canary,
    Redact,
    Log,
}

fn default_action_canary() -> SecretAction {
    SecretAction::Canary
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NameAction {
    Pseudonym,
    Redact,
    Log,
}

fn default_action_pseudonym() -> NameAction {
    NameAction::Pseudonym
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EntropyAction {
    Log,
    Alert,
}

fn default_action_log() -> EntropyAction {
    EntropyAction::Log
}

/// Standalone rules file format (same arrays, no `[dlp]` wrapper).
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
struct RulesFile {
    #[serde(default)]
    secrets: Vec<SecretRule>,
    #[serde(default)]
    custom_prefixes: Vec<CustomPrefixRule>,
    #[serde(default)]
    names: Vec<NameRule>,
}

impl DlpConfig {
    /// Load and merge rules from an external file, if `rules_file` is set.
    pub fn load_external_rules(&mut self) -> Result<()> {
        if self.rules_file.is_empty() {
            return Ok(());
        }

        // Expand ~ to home dir
        let path = if self.rules_file.starts_with('~') {
            let home = dirs::home_dir().context("Failed to get home directory")?;
            home.join(self.rules_file.trim_start_matches("~/"))
        } else {
            std::path::PathBuf::from(&self.rules_file)
        };

        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read DLP rules file: {}", path.display()))?;

        let rules: RulesFile = toml::from_str(&content)
            .with_context(|| format!("Failed to parse DLP rules file: {}", path.display()))?;

        self.secrets.extend(rules.secrets);
        self.custom_prefixes.extend(rules.custom_prefixes);
        self.names.extend(rules.names);

        tracing::info!("Loaded external DLP rules from {}", path.display());

        Ok(())
    }
}

impl std::fmt::Display for SecretAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretAction::Canary => write!(f, "canary"),
            SecretAction::Redact => write!(f, "redact"),
            SecretAction::Log => write!(f, "log"),
        }
    }
}

impl std::fmt::Display for NameAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NameAction::Pseudonym => write!(f, "pseudonym"),
            NameAction::Redact => write!(f, "redact"),
            NameAction::Log => write!(f, "log"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dlp_config() {
        let toml_str = r#"
enabled = true
scan_input = true
scan_output = true

[[secrets]]
name = "github_token"
prefix = "ghp_"
pattern = "ghp_[A-Za-z0-9]{36}"
action = "canary"

[[names]]
term = "Thales"
action = "pseudonym"

[entropy]
enabled = true
action = "log"
        "#;
        let config: DlpConfig = toml::from_str(toml_str).unwrap();
        assert!(config.enabled);
        assert_eq!(config.secrets.len(), 1);
        assert_eq!(config.secrets[0].name, "github_token");
        assert_eq!(config.names.len(), 1);
        assert_eq!(config.names[0].term, "Thales");
        assert!(config.entropy.enabled);
    }

    #[test]
    fn test_defaults() {
        let toml_str = "enabled = true";
        let config: DlpConfig = toml::from_str(toml_str).unwrap();
        assert!(config.scan_input);
        assert!(config.scan_output);
        assert!(config.secrets.is_empty());
        assert!(config.names.is_empty());
        assert!(!config.entropy.enabled);
    }
}

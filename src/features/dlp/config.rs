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
    /// Disable all built-in secret detection rules (only use user-defined rules).
    #[serde(default)]
    pub no_builtins: bool,
    #[serde(default)]
    pub secrets: Vec<SecretRule>,
    #[serde(default)]
    pub custom_prefixes: Vec<CustomPrefixRule>,
    #[serde(default)]
    pub names: Vec<NameRule>,
    #[serde(default)]
    pub entropy: EntropyConfig,
    /// PII detection configuration (credit cards, IBAN, BIC).
    #[serde(default)]
    pub pii: PiiConfig,
    /// Enable per-API-key DLP session isolation.
    /// When true, each API key gets its own NameAnonymizer (unique pseudonyms)
    /// and CanaryGenerator (independent counter). Default: false.
    #[serde(default)]
    pub enable_sessions: bool,
    /// URL exfiltration scanner (anti-EchoLeak). Default: disabled.
    #[serde(default)]
    pub url_exfil: UrlExfilConfig,
    /// Prompt injection detector. Default: disabled.
    #[serde(default)]
    pub prompt_injection: PromptInjectionConfig,
    /// Signed config hot-reload settings. Default: disabled.
    #[serde(default)]
    pub signed_config: SignedConfigSettings,
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

/// PII detection configuration for financial data.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PiiConfig {
    /// Detect credit card numbers (Luhn-validated). Default: true.
    #[serde(default = "default_true")]
    pub credit_cards: bool,
    /// Detect IBAN numbers (mod97-validated). Default: true.
    #[serde(default = "default_true")]
    pub iban: bool,
    /// Detect BIC/SWIFT codes. Default: false (risk of false positives).
    #[serde(default)]
    pub bic: bool,
    /// Action to take on PII detection. Default: redact.
    #[serde(default = "default_pii_action")]
    pub action: PiiAction,
}

impl Default for PiiConfig {
    fn default() -> Self {
        Self {
            credit_cards: true,
            iban: true,
            bic: false,
            action: PiiAction::Redact,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PiiAction {
    Redact,
    Log,
}

fn default_pii_action() -> PiiAction {
    PiiAction::Redact
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

/// Action for URL exfiltration and prompt injection detections.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DlpAction {
    Redact,
    #[default]
    Log,
    Block,
}

impl std::fmt::Display for DlpAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DlpAction::Redact => write!(f, "redact"),
            DlpAction::Log => write!(f, "log"),
            DlpAction::Block => write!(f, "block"),
        }
    }
}

/// Domain matching mode for whitelist/blacklist.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DomainMatchMode {
    Exact,
    #[default]
    Suffix,
    Glob,
}

/// URL exfiltration scanner configuration (anti-EchoLeak CVE-2025-32711).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UrlExfilConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub action: DlpAction,
    #[serde(default = "default_true")]
    pub scan_markdown_images: bool,
    #[serde(default = "default_true")]
    pub scan_markdown_links: bool,
    #[serde(default = "default_true")]
    pub scan_raw_urls: bool,
    #[serde(default = "default_true")]
    pub flag_long_query_params: bool,
    #[serde(default = "default_true")]
    pub flag_base64_in_path: bool,
    #[serde(default = "default_true")]
    pub flag_data_uris: bool,
    #[serde(default = "default_max_query_length")]
    pub max_query_length: usize,
    #[serde(default)]
    pub whitelist_domains: Vec<String>,
    #[serde(default)]
    pub blacklist_domains: Vec<String>,
    #[serde(default)]
    pub domain_match_mode: DomainMatchMode,
}

fn default_max_query_length() -> usize {
    200
}

impl Default for UrlExfilConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            action: DlpAction::Log,
            scan_markdown_images: true,
            scan_markdown_links: true,
            scan_raw_urls: true,
            flag_long_query_params: true,
            flag_base64_in_path: true,
            flag_data_uris: true,
            max_query_length: 200,
            whitelist_domains: Vec::new(),
            blacklist_domains: Vec::new(),
            domain_match_mode: DomainMatchMode::Suffix,
        }
    }
}

/// Prompt injection detector configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PromptInjectionConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub action: DlpAction,
    /// Disable built-in injection patterns (only use custom_patterns).
    #[serde(default)]
    pub no_builtins: bool,
    #[serde(default)]
    pub custom_patterns: Vec<String>,
    #[serde(default = "default_languages")]
    pub languages: Vec<String>,
}

fn default_languages() -> Vec<String> {
    vec!["all".to_string()]
}

impl Default for PromptInjectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            action: DlpAction::Log,
            no_builtins: false,
            custom_patterns: Vec::new(),
            languages: default_languages(), // "all" = all 28 languages
        }
    }
}

/// Signed config hot-reload settings for domain lists and injection patterns.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct SignedConfigSettings {
    #[serde(default)]
    pub enabled: bool,
    /// File path or URL to the signed config TOML.
    #[serde(default)]
    pub source: String,
    /// Poll interval (e.g. "1h", "30m", "6h"). Default: "1h".
    #[serde(default = "default_poll_interval")]
    pub poll_interval: String,
    /// Require ECDSA P-256 signature verification.
    #[serde(default)]
    pub verify_signature: bool,
    /// Path to PEM or raw SEC1 P-256 public key.
    #[serde(default)]
    pub public_key_path: String,
    /// Suffix for detached signature files. Default: ".sig".
    #[serde(default = "default_sig_suffix")]
    pub detached_sig_suffix: String,
}

fn default_poll_interval() -> String {
    "1h".to_string()
}

fn default_sig_suffix() -> String {
    ".sig".to_string()
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

    /// Resolve all secret rules: prepend builtins (unless `no_builtins`),
    /// then append user-defined rules. Called once before engine construction.
    pub fn resolve_all_rules(&mut self) {
        if !self.no_builtins {
            let mut all = super::builtins::builtin_rules();
            all.append(&mut self.secrets);
            self.secrets = all;
        }
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
        assert!(!config.no_builtins);
        // PII defaults
        assert!(config.pii.credit_cards);
        assert!(config.pii.iban);
        assert!(!config.pii.bic);
    }

    #[test]
    fn test_resolve_all_rules_prepends_builtins() {
        let mut config = DlpConfig {
            enabled: true,
            secrets: vec![SecretRule {
                name: "user_rule".into(),
                prefix: "custom_".into(),
                pattern: "custom_[a-z]+".into(),
                action: SecretAction::Canary,
            }],
            ..Default::default()
        };
        config.resolve_all_rules();
        // Builtins come first
        assert!(config.secrets.len() > 1);
        assert_ne!(config.secrets[0].name, "user_rule");
        // User rule is last
        assert_eq!(config.secrets.last().unwrap().name, "user_rule");
    }

    #[test]
    fn test_no_builtins_opt_out() {
        let mut config = DlpConfig {
            enabled: true,
            no_builtins: true,
            secrets: vec![SecretRule {
                name: "only_rule".into(),
                prefix: "x_".into(),
                pattern: "x_[a-z]+".into(),
                action: SecretAction::Redact,
            }],
            ..Default::default()
        };
        config.resolve_all_rules();
        assert_eq!(config.secrets.len(), 1);
        assert_eq!(config.secrets[0].name, "only_rule");
    }

    #[test]
    fn test_parse_pii_config() {
        let toml_str = r#"
enabled = true

[pii]
credit_cards = true
iban = false
bic = true
action = "log"
        "#;
        let config: DlpConfig = toml::from_str(toml_str).unwrap();
        assert!(config.pii.credit_cards);
        assert!(!config.pii.iban);
        assert!(config.pii.bic);
        assert_eq!(config.pii.action, PiiAction::Log);
    }
}

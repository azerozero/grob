use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use super::AppConfig;

impl AppConfig {
    /// Create a default configuration file or migrate existing one
    pub(super) fn create_default_config(path: &Path) -> Result<()> {
        // Create parent directory if it doesn't exist
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create config directory: {}", parent.display())
            })?;
        }

        // Check for existing config in old location (config/default.toml)
        let old_config_path = PathBuf::from("config/default.toml");
        if old_config_path.exists() {
            // Migrate existing config
            eprintln!(
                "📦 Migrating existing config from {} to {}",
                old_config_path.display(),
                path.display()
            );

            std::fs::copy(&old_config_path, path).with_context(|| {
                format!(
                    "Failed to migrate config from {} to {}",
                    old_config_path.display(),
                    path.display()
                )
            })?;

            eprintln!("✅ Migration complete! Your existing configuration has been preserved.");
            eprintln!("   Old location: {}", old_config_path.display());
            eprintln!("   New location: {}", path.display());
            eprintln!();
            eprintln!("💡 You can safely delete the old config file if you want:");
            eprintln!("   rm {}", old_config_path.display());
        } else {
            // Generate default config content
            let default_config = Self::default_config_content();

            // Write to file
            std::fs::write(path, default_config).with_context(|| {
                format!("Failed to write default config file: {}", path.display())
            })?;

            eprintln!("Created default config file at: {}", path.display());
            eprintln!("Please edit the config file to add your providers and models.");
            eprintln!("Run 'grob preset apply medium' for a quick multi-provider setup.");
        }

        Ok(())
    }

    /// Generate default configuration content as TOML string
    pub(super) fn default_config_content() -> String {
        r#"# Grob Configuration
#
# This is a minimal default configuration.
# Edit this file or run 'grob preset apply <name>' for quick setup.
# See: grob preset list

[server]
host = "::1"
port = 13456
log_level = "info"

[server.timeouts]
api_timeout_ms = 600000      # 10 minutes
connect_timeout_ms = 10000   # 10 seconds

# Message tracing for debugging (logs full request/response to JSONL)
# [server.tracing]
# enabled = true
# path = "~/.grob/trace.jsonl"
# omit_system_prompt = true

[presets]
sync_url = "https://raw.githubusercontent.com/azerozero/grob/main/presets/"
[router]
# Default model to use when no routing conditions are met
# You MUST configure at least one provider and model before using Grob
default = "placeholder-model"

# Optional: Model for background tasks (e.g., "glm-4.5-air")
# background = ""

# Optional: Model for thinking/reasoning tasks (e.g., "claude-opus-4-6")
# think = ""

# Optional: Model for web search tasks (e.g., "glm-4.6")
# websearch = ""

# Optional: Regex pattern for auto-mapping models (e.g., "^claude-")
# auto_map_regex = ""

# Optional: Regex pattern for detecting background tasks (e.g., "(?i)claude.*haiku")
# background_regex = ""

# Optional: Prompt-based routing rules (first match wins)
# Routes to specific models when patterns match user prompt content
# [[router.prompt_rules]]
# pattern = "(?i)commit.*changes"   # Regex pattern to match
# model = "fast-model"              # Model to route to
# strip_match = false               # Strip matched phrase from prompt (default: false)

# Providers configuration
# Add providers below or use 'grob preset apply <name>'
# Example:
# [[providers]]
# name = "my-provider"
# provider_type = "anthropic"  # or "openai", "openrouter", etc.
# auth_type = "apikey"          # or "oauth"
# api_key = "your-api-key-here"
# enabled = true
# models = []

# Models configuration
# Add models below or use 'grob preset apply <name>'
# Example:
# [[models]]
# name = "my-model"
#
# [[models.mappings]]
# provider = "my-provider"
# actual_model = "claude-sonnet-4-6"
# priority = 1
"#
        .to_string()
    }
}

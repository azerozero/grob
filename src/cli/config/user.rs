//! User and preset configuration sections (preserved across preset applies).

use serde::{Deserialize, Serialize};

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

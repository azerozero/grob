//! Secrets backend configuration.
//!
//! Selects which [`SecretBackend`](crate::storage::secrets::SecretBackend)
//! resolves `secret:<name>` placeholders in `[[providers]] api_key`.
//!
//! Three backends ship today:
//!
//! - `local_encrypted` (default) — `~/.grob/secrets/<name>.enc` (AES-GCM)
//! - `env`                       — looks up `<NAME>` in the process env
//! - `file`                      — reads `<path>/<name>` (cleartext, intended
//!   to be backed by a Vault Agent / Kubernetes Secret mount)

use serde::{Deserialize, Serialize};

/// Top-level `[secrets]` section.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SecretsConfig {
    /// Backend used to resolve `secret:<name>` references.
    #[serde(default)]
    pub backend: SecretsBackend,
    /// File-backend specific options (only read when `backend = "file"`).
    #[serde(default)]
    pub file: SecretsFileConfig,
}

/// Backend selector.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretsBackend {
    /// AES-256-GCM encrypted store under `~/.grob/secrets/`.
    #[default]
    LocalEncrypted,
    /// Resolve via `std::env::var(NAME)` — no encryption at rest.
    Env,
    /// Read cleartext value from `<path>/<name>`. Intended to be backed by
    /// a Vault Agent template, Kubernetes Secret mount, or similar.
    File,
}

/// Options for the `file` backend.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecretsFileConfig {
    /// Directory containing one cleartext file per secret.
    #[serde(default = "default_secrets_file_path")]
    pub path: String,
}

impl Default for SecretsFileConfig {
    fn default() -> Self {
        Self {
            path: default_secrets_file_path(),
        }
    }
}

fn default_secrets_file_path() -> String {
    "/etc/grob/secrets".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_local_encrypted() {
        let cfg = SecretsConfig::default();
        assert_eq!(cfg.backend, SecretsBackend::LocalEncrypted);
    }

    #[test]
    fn parses_env_backend() {
        let toml = r#"backend = "env""#;
        let cfg: SecretsConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.backend, SecretsBackend::Env);
    }

    #[test]
    fn parses_file_backend_with_path() {
        let toml = r#"
            backend = "file"
            [file]
            path = "/run/secrets/grob"
        "#;
        let cfg: SecretsConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.backend, SecretsBackend::File);
        assert_eq!(cfg.file.path, "/run/secrets/grob");
    }

    #[test]
    fn file_backend_default_path() {
        let toml = r#"backend = "file""#;
        let cfg: SecretsConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.file.path, "/etc/grob/secrets");
    }
}

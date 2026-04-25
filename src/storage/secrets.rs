//! Pluggable secret backends for resolving `secret:<name>` placeholders.
//!
//! The default backend ([`LocalEncryptedBackend`]) reuses the AES-256-GCM
//! store managed by [`GrobStore`]. The other two ([`EnvBackend`],
//! [`FileBackend`]) are useful in deployments where secrets come from
//! Vault Agent, Kubernetes Secret mounts, or a 12-factor-style env.

use crate::cli::{SecretsBackend, SecretsConfig};
use crate::storage::GrobStore;
use secrecy::SecretString;
use std::path::PathBuf;
use std::sync::Arc;

/// Resolves named secrets to their cleartext value.
///
/// Backends are stateless once constructed. `get` returns `None` if the
/// secret is not defined; callers decide whether that is fatal or merely
/// triggers a fallback / warning.
pub trait SecretBackend: Send + Sync {
    /// Looks up a secret by its short name.
    fn get(&self, name: &str) -> Option<SecretString>;
    /// Identifier used in logs (e.g. `"local_encrypted"`).
    fn label(&self) -> &'static str;
}

/// AES-256-GCM encrypted store under `~/.grob/secrets/<name>.enc`.
pub struct LocalEncryptedBackend(Arc<GrobStore>);

impl LocalEncryptedBackend {
    /// Creates a backend backed by the supplied store.
    pub fn new(store: Arc<GrobStore>) -> Self {
        Self(store)
    }
}

impl SecretBackend for LocalEncryptedBackend {
    fn get(&self, name: &str) -> Option<SecretString> {
        self.0.get_secret(name)
    }
    fn label(&self) -> &'static str {
        "local_encrypted"
    }
}

/// Resolves via `std::env::var(NAME)`. No encryption at rest.
///
/// The lookup name is uppercased and dashes are replaced with underscores
/// so that `secret:minimax-api-key` reads from `MINIMAX_API_KEY`.
pub struct EnvBackend;

impl SecretBackend for EnvBackend {
    fn get(&self, name: &str) -> Option<SecretString> {
        let env_name = name.replace('-', "_").to_uppercase();
        std::env::var(env_name).ok().map(SecretString::new)
    }
    fn label(&self) -> &'static str {
        "env"
    }
}

/// Reads cleartext values from `<base_dir>/<name>`.
///
/// The expected workflow on Kubernetes is to mount a Vault Agent template
/// or a Kubernetes Secret as files under `base_dir`. Grob never writes to
/// this directory.
pub struct FileBackend {
    base_dir: PathBuf,
}

impl FileBackend {
    /// Creates a backend that reads from `base_dir`.
    pub fn new(base_dir: impl Into<PathBuf>) -> Self {
        Self {
            base_dir: base_dir.into(),
        }
    }
}

impl SecretBackend for FileBackend {
    fn get(&self, name: &str) -> Option<SecretString> {
        // Reject path traversal attempts; only single-component names allowed.
        if name.is_empty() || name.contains(['/', '\\']) || name.starts_with('.') {
            tracing::warn!("file secret backend: rejected suspicious name '{name}'");
            return None;
        }
        let path = self.base_dir.join(name);
        let bytes = std::fs::read(&path).ok()?;
        let value = String::from_utf8(bytes).ok()?;
        // Strip a single trailing newline (common when written by `echo` or `vault`).
        let trimmed = value.strip_suffix('\n').unwrap_or(&value).to_string();
        Some(SecretString::new(trimmed))
    }
    fn label(&self) -> &'static str {
        "file"
    }
}

/// Builds the configured backend from `[secrets]` and the local store.
///
/// `local_encrypted` (default) requires the store; the other backends
/// ignore it.
pub fn build_backend(cfg: &SecretsConfig, store: Arc<GrobStore>) -> Arc<dyn SecretBackend> {
    match cfg.backend {
        SecretsBackend::LocalEncrypted => Arc::new(LocalEncryptedBackend::new(store)),
        SecretsBackend::Env => Arc::new(EnvBackend),
        SecretsBackend::File => Arc::new(FileBackend::new(&cfg.file.path)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    // NOTE: env_backend with set_var would require `unsafe` (deny'd at lib level).
    // We only test the absent path here; the present path is exercised end-to-end
    // by `init.rs::resolve_provider_secrets` through the existing $VAR pathway.
    #[test]
    fn env_backend_returns_none_when_missing() {
        let b = EnvBackend;
        assert!(b.get("definitely-not-set-1234-grob").is_none());
    }

    #[test]
    fn env_backend_normalises_name() {
        // Smoke test: just verifies the transformation does not panic.
        let b = EnvBackend;
        let _ = b.get("dash-and-case-XYZ");
    }

    #[test]
    fn file_backend_reads_and_trims_newline() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("groq"), b"gsk-from-file\n").unwrap();
        let b = FileBackend::new(dir.path());
        let v = b.get("groq").unwrap();
        assert_eq!(v.expose_secret(), "gsk-from-file");
    }

    #[test]
    fn file_backend_rejects_path_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let b = FileBackend::new(dir.path());
        assert!(b.get("../etc/passwd").is_none());
        assert!(b.get(".hidden").is_none());
        assert!(b.get("a/b").is_none());
        assert!(b.get("").is_none());
    }

    #[test]
    fn file_backend_returns_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let b = FileBackend::new(dir.path());
        assert!(b.get("absent").is_none());
    }
}

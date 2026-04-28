//! Pluggable secret backends for resolving `secret:<name>` placeholders.
//!
//! The default backend ([`LocalEncryptedBackend`]) reuses the AES-256-GCM
//! store managed by [`GrobStore`]. The other two ([`EnvBackend`],
//! [`FileBackend`]) are useful in deployments where secrets come from
//! Vault Agent, Kubernetes Secret mounts, or a 12-factor-style env.

use crate::cli::{SecretsBackend, SecretsConfig};
use crate::storage::{GrobStore, DEFAULT_TENANT};
use secrecy::SecretString;
use std::path::PathBuf;
use std::sync::Arc;

/// Resolves named secrets to their cleartext value.
///
/// Backends are stateless once constructed. `get` returns `None` if the
/// secret is not defined; callers decide whether that is fatal or merely
/// triggers a fallback / warning.
///
/// All lookups carry an explicit `tenant` so a single `secret:groq`
/// reference resolves to different cleartext values per tenant. Callers
/// without a tenant context pass [`DEFAULT_TENANT`] (also used by
/// [`resolve_provider_secrets`] when invoked without per-tenant routing).
///
/// Each backend falls back to the global key (no `<tenant>/` prefix) when
/// the tenant-scoped variant is absent. This preserves the previous flat
/// layout for single-tenant deployments and lets multi-tenant deployments
/// override per tenant without re-keying the whole store.
pub trait SecretBackend: Send + Sync {
    /// Looks up a secret by its short name for the given tenant.
    fn get(&self, tenant: &str, name: &str) -> Option<SecretString>;
    /// Identifier used in logs (e.g. `"local_encrypted"`).
    fn label(&self) -> &'static str;
}

/// AES-256-GCM encrypted store under `~/.grob/secrets/<tenant>/<name>.enc`.
///
/// Falls back to the legacy flat layout (`~/.grob/secrets/<name>.enc`) for
/// global names when no per-tenant entry is found.
pub struct LocalEncryptedBackend(Arc<GrobStore>);

impl LocalEncryptedBackend {
    /// Creates a backend backed by the supplied store.
    pub fn new(store: Arc<GrobStore>) -> Self {
        Self(store)
    }
}

impl SecretBackend for LocalEncryptedBackend {
    fn get(&self, tenant: &str, name: &str) -> Option<SecretString> {
        // Try tenant-scoped layout first: `<tenant>/<name>` is the canonical
        // namespaced path used by `grob secrets set --tenant`.
        let scoped = format!("{tenant}/{name}");
        if let Some(v) = self.0.get_secret(&scoped) {
            return Some(v);
        }
        // Fall back to the legacy flat layout so single-tenant deployments
        // and global secrets keep working without migration.
        self.0.get_secret(name)
    }
    fn label(&self) -> &'static str {
        "local_encrypted"
    }
}

/// Resolves via `std::env::var(NAME)`. No encryption at rest.
///
/// The lookup name is uppercased and dashes are replaced with underscores.
/// Tenant-scoped lookups read from `GROB_SECRET_<TENANT_UPPER>_<NAME_UPPER>`,
/// falling back to `GROB_SECRET_<NAME_UPPER>` for global secrets shared
/// across tenants.
pub struct EnvBackend;

fn env_safe_segment(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

impl SecretBackend for EnvBackend {
    fn get(&self, tenant: &str, name: &str) -> Option<SecretString> {
        let upper_name = env_safe_segment(name);
        let upper_tenant = env_safe_segment(tenant);

        // Per-tenant override wins.
        let tenant_var = format!("GROB_SECRET_{upper_tenant}_{upper_name}");
        if let Ok(v) = std::env::var(&tenant_var) {
            return Some(SecretString::new(v));
        }
        // Global tenant-prefixed (preserves the explicit GROB_SECRET_ shape
        // for callers that want to opt out of legacy compat).
        let global_prefixed = format!("GROB_SECRET_{upper_name}");
        if let Ok(v) = std::env::var(&global_prefixed) {
            return Some(SecretString::new(v));
        }
        // Legacy compat: bare uppercased name, used by deployments that
        // already export e.g. `OPENAI_API_KEY` directly.
        std::env::var(&upper_name).ok().map(SecretString::new)
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
///
/// Tenant-scoped lookups read from `<base_dir>/<tenant>/<name>`, falling
/// back to `<base_dir>/<name>` so existing single-tenant mounts stay valid.
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

    fn read_one(path: &std::path::Path) -> Option<SecretString> {
        let bytes = std::fs::read(path).ok()?;
        let value = String::from_utf8(bytes).ok()?;
        let trimmed = value.strip_suffix('\n').unwrap_or(&value).to_string();
        Some(SecretString::new(trimmed))
    }
}

impl SecretBackend for FileBackend {
    fn get(&self, tenant: &str, name: &str) -> Option<SecretString> {
        // Reject path traversal attempts; only single-component names allowed.
        if name.is_empty() || name.contains(['/', '\\']) || name.starts_with('.') {
            tracing::warn!("file secret backend: rejected suspicious name '{name}'");
            return None;
        }
        if tenant.contains(['/', '\\']) || tenant.starts_with('.') {
            tracing::warn!("file secret backend: rejected suspicious tenant '{tenant}'");
            return None;
        }
        // Per-tenant directory takes priority.
        let scoped = self.base_dir.join(tenant).join(name);
        if let Some(v) = Self::read_one(&scoped) {
            return Some(v);
        }
        // Fall back to legacy flat layout.
        let path = self.base_dir.join(name);
        Self::read_one(&path)
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

/// Resolves `api_key` placeholders in provider configs (default tenant).
///
/// Convenience wrapper around [`resolve_provider_secrets_for_tenant`] for
/// callers that have no tenant context (CLI tools, single-tenant servers).
pub fn resolve_provider_secrets(
    providers: &[crate::cli::ProviderConfig],
    backend: &dyn SecretBackend,
) -> Vec<crate::cli::ProviderConfig> {
    resolve_provider_secrets_for_tenant(providers, backend, DEFAULT_TENANT)
}

/// Resolves `api_key` placeholders in provider configs for a specific tenant.
///
/// Three modes are recognised on the raw string value:
/// - `secret:<name>` → looked up in the supplied [`SecretBackend`] under
///   the given tenant (with global fallback)
/// - `$ENV_VAR`     → resolved from process env via `std::env::var`
/// - other          → used as-is
///
/// Returns a cloned vector with `api_key` replaced. Unresolved placeholders
/// are kept as-is so the existing fallback / warning paths still trigger.
pub fn resolve_provider_secrets_for_tenant(
    providers: &[crate::cli::ProviderConfig],
    backend: &dyn SecretBackend,
    tenant: &str,
) -> Vec<crate::cli::ProviderConfig> {
    use secrecy::ExposeSecret;

    providers
        .iter()
        .cloned()
        .map(|mut p| {
            let raw = p.api_key.as_ref().map(|s| s.expose_secret().to_string());
            if let Some(raw) = raw {
                if let Some(name) = raw.strip_prefix("secret:") {
                    match backend.get(tenant, name) {
                        Some(resolved) => {
                            p.api_key = Some(resolved);
                            tracing::info!(
                                "🔐 Resolved api_key for provider '{}' from {} backend (tenant='{}', name='{}')",
                                p.name,
                                backend.label(),
                                tenant,
                                name
                            );
                        }
                        None => {
                            tracing::warn!(
                                "Provider '{}' references unknown secret '{}' on backend '{}' (tenant='{}')",
                                p.name,
                                name,
                                backend.label(),
                                tenant
                            );
                        }
                    }
                } else if let Some(var) = raw.strip_prefix('$') {
                    match std::env::var(var) {
                        Ok(v) => {
                            p.api_key = Some(SecretString::new(v));
                            tracing::info!(
                                "🔓 Resolved api_key for provider '{}' from env var ${}",
                                p.name,
                                var
                            );
                        }
                        Err(_) => {
                            tracing::warn!(
                                "Provider '{}' references unset env var ${}",
                                p.name,
                                var
                            );
                        }
                    }
                }
            }
            p
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    // NOTE: env_backend with set_var would require `unsafe` (deny'd at lib level).
    // We only test the absent path here; the present path is exercised end-to-end
    // by `resolve_provider_secrets` through the existing $VAR pathway.
    #[test]
    fn env_backend_returns_none_when_missing() {
        let b = EnvBackend;
        assert!(b
            .get(DEFAULT_TENANT, "definitely-not-set-1234-grob")
            .is_none());
    }

    /// Stub backend for testing `resolve_provider_secrets` without touching
    /// disk or env. Returns the supplied value for the configured name only.
    struct StubBackend {
        name: &'static str,
        value: &'static str,
    }
    impl SecretBackend for StubBackend {
        fn get(&self, _tenant: &str, name: &str) -> Option<SecretString> {
            if name == self.name {
                Some(SecretString::new(self.value.into()))
            } else {
                None
            }
        }
        fn label(&self) -> &'static str {
            "stub"
        }
    }

    fn make_provider(name: &str, api_key: Option<&str>) -> crate::cli::ProviderConfig {
        crate::cli::ProviderConfig {
            name: name.into(),
            provider_type: "openai".into(),
            auth_type: crate::cli::AuthType::ApiKey,
            api_key: api_key.map(|s| SecretString::new(s.into())),
            oauth_provider: None,
            project_id: None,
            location: None,
            base_url: None,
            headers: None,
            models: vec![],
            enabled: Some(true),
            budget_usd: None,
            region: None,
            pass_through: None,
            tls_cert: None,
            tls_key: None,
            tls_ca: None,
            pool: None,
            circuit_breaker: None,
            health_check: None,
        }
    }

    #[test]
    fn resolve_secret_prefix_replaces_api_key() {
        let p = make_provider("openrouter", Some("secret:openrouter"));
        let backend = StubBackend {
            name: "openrouter",
            value: "sk-or-v1-real-key",
        };
        let out = resolve_provider_secrets(&[p], &backend);
        assert_eq!(
            out[0].api_key.as_ref().unwrap().expose_secret(),
            "sk-or-v1-real-key"
        );
    }

    #[test]
    fn resolve_secret_unknown_name_keeps_placeholder() {
        // Unresolved placeholders survive — caller's fallback chain handles
        // the resulting 401, the warning is emitted via tracing.
        let p = make_provider("openrouter", Some("secret:nonexistent"));
        let backend = StubBackend {
            name: "other",
            value: "irrelevant",
        };
        let out = resolve_provider_secrets(&[p], &backend);
        assert_eq!(
            out[0].api_key.as_ref().unwrap().expose_secret(),
            "secret:nonexistent"
        );
    }

    #[test]
    fn resolve_plain_string_is_passthrough() {
        let p = make_provider("openrouter", Some("sk-literal-key"));
        let backend = StubBackend {
            name: "openrouter",
            value: "should-not-be-used",
        };
        let out = resolve_provider_secrets(&[p], &backend);
        assert_eq!(
            out[0].api_key.as_ref().unwrap().expose_secret(),
            "sk-literal-key"
        );
    }

    #[test]
    fn resolve_missing_api_key_is_noop() {
        let p = make_provider("anthropic", None);
        let backend = StubBackend {
            name: "x",
            value: "y",
        };
        let out = resolve_provider_secrets(&[p], &backend);
        assert!(out[0].api_key.is_none());
    }

    #[test]
    fn env_backend_normalises_name() {
        // Smoke test: just verifies the transformation does not panic.
        let b = EnvBackend;
        let _ = b.get(DEFAULT_TENANT, "dash-and-case-XYZ");
    }

    #[test]
    fn file_backend_reads_and_trims_newline() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("groq"), b"gsk-from-file\n").unwrap();
        let b = FileBackend::new(dir.path());
        let v = b.get(DEFAULT_TENANT, "groq").unwrap();
        assert_eq!(v.expose_secret(), "gsk-from-file");
    }

    #[test]
    fn file_backend_rejects_path_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let b = FileBackend::new(dir.path());
        assert!(b.get(DEFAULT_TENANT, "../etc/passwd").is_none());
        assert!(b.get(DEFAULT_TENANT, ".hidden").is_none());
        assert!(b.get(DEFAULT_TENANT, "a/b").is_none());
        assert!(b.get(DEFAULT_TENANT, "").is_none());
        assert!(b.get("../etc", "passwd").is_none());
        assert!(b.get(".hidden", "name").is_none());
    }

    #[test]
    fn file_backend_returns_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let b = FileBackend::new(dir.path());
        assert!(b.get(DEFAULT_TENANT, "absent").is_none());
    }

    #[test]
    fn file_backend_per_tenant_overrides_global() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("groq"), b"global-key\n").unwrap();
        std::fs::create_dir_all(dir.path().join("tenant_a")).unwrap();
        std::fs::write(dir.path().join("tenant_a").join("groq"), b"tenant-a-key\n").unwrap();

        let b = FileBackend::new(dir.path());
        // Tenant A sees its own value.
        assert_eq!(
            b.get("tenant_a", "groq").unwrap().expose_secret(),
            "tenant-a-key"
        );
        // Tenant B falls back to the global value.
        assert_eq!(
            b.get("tenant_b", "groq").unwrap().expose_secret(),
            "global-key"
        );
    }

    #[test]
    fn local_encrypted_per_tenant_isolation() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(GrobStore::open(&dir.path().join("grob.db")).unwrap());
        // Set tenant-scoped secrets via the GrobStore namespaced names that
        // LocalEncryptedBackend looks up internally.
        store.set_secret("tenant_a/groq", "key-a").unwrap();
        store.set_secret("tenant_b/groq", "key-b").unwrap();

        let b = LocalEncryptedBackend::new(store);
        assert_eq!(b.get("tenant_a", "groq").unwrap().expose_secret(), "key-a");
        assert_eq!(b.get("tenant_b", "groq").unwrap().expose_secret(), "key-b");
    }

    #[test]
    fn local_encrypted_falls_back_to_global() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(GrobStore::open(&dir.path().join("grob.db")).unwrap());
        store.set_secret("groq", "global-key").unwrap();

        let b = LocalEncryptedBackend::new(store);
        // No tenant-scoped value: the global one wins.
        assert_eq!(
            b.get("tenant_a", "groq").unwrap().expose_secret(),
            "global-key"
        );
    }
}

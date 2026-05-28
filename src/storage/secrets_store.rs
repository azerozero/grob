//! Named-secret persistence for [`GrobStore`] (upstream provider API keys).
//!
//! Distinct from [`super::secrets`], which defines the pluggable secret
//! *backends*; this module is the on-disk AES-256-GCM store those backends
//! (and direct callers) read and write through `GrobStore`.

use std::path::PathBuf;

use anyhow::{Context, Result};

use super::{atomic, sanitize_filename, GrobStore};

impl GrobStore {
    fn secret_path(&self, name: &str) -> PathBuf {
        self.base_dir
            .join("secrets")
            .join(format!("{}.enc", sanitize_filename(name)))
    }

    fn ensure_secrets_dir(&self) -> Result<()> {
        let dir = self.base_dir.join("secrets");
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create secrets dir: {}", dir.display()))
    }

    /// Stores a named secret encrypted with AES-256-GCM.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption or the atomic file write fails.
    pub fn set_secret(&self, name: &str, value: &str) -> Result<()> {
        self.ensure_secrets_dir()?;
        let encrypted = self.cipher.encrypt(value.as_bytes())?;
        atomic::write_atomic(&self.secret_path(name), &encrypted)?;
        Ok(())
    }

    /// Reads a named secret. Returns `None` if absent or unreadable.
    ///
    /// A blob that fails authentication is logged and yields `None` rather than
    /// being silently surfaced as plaintext.
    pub fn get_secret(&self, name: &str) -> Option<secrecy::SecretString> {
        let path = self.secret_path(name);
        let encrypted = std::fs::read(&path).ok()?;
        let decrypted = match self.cipher.decrypt_or_plaintext(&encrypted) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(secret = name, error = %e, "failed to read secret");
                return None;
            }
        };
        let s = String::from_utf8(decrypted).ok()?;
        Some(secrecy::SecretString::new(s))
    }

    /// Lists secret names (no values).
    pub fn list_secrets(&self) -> Vec<String> {
        let dir = self.base_dir.join("secrets");
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => return vec![],
        };
        let mut names = vec![];
        for entry in entries.flatten() {
            let name = entry.file_name();
            let s = name.to_string_lossy();
            if let Some(stripped) = s.strip_suffix(".enc") {
                names.push(stripped.to_string());
            }
        }
        names.sort();
        names
    }

    /// Removes a named secret. Returns `Ok(false)` if it did not exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the file exists but cannot be removed.
    pub fn remove_secret(&self, name: &str) -> Result<bool> {
        let path = self.secret_path(name);
        if !path.exists() {
            return Ok(false);
        }
        std::fs::remove_file(&path)
            .with_context(|| format!("failed to remove secret: {}", path.display()))?;
        Ok(true)
    }
}

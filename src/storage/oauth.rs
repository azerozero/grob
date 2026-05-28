//! OAuth-token persistence for [`GrobStore`] (AES-256-GCM at rest).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::{atomic, sanitize_filename, GrobStore};
use crate::auth::token_store::OAuthToken;

impl GrobStore {
    fn token_path(&self, provider_id: &str) -> PathBuf {
        self.base_dir
            .join("tokens")
            .join(format!("{}.json.enc", sanitize_filename(provider_id)))
    }

    /// Saves an OAuth token (encrypted with AES-256-GCM).
    ///
    /// # Errors
    ///
    /// Returns an error if serialization, encryption, or the
    /// atomic file write fails.
    pub fn save_oauth_token(&self, token: &OAuthToken) -> Result<()> {
        let plaintext = serde_json::to_vec(token)?;
        let encrypted = self.cipher.encrypt(&plaintext)?;
        let path = self.token_path(&token.provider_id);
        atomic::write_atomic(&path, &encrypted)?;
        Ok(())
    }

    /// Gets an OAuth token by provider ID (decrypts from AES-256-GCM).
    ///
    /// Returns `None` if the file is absent or fails authentication; a failed
    /// authentication is logged rather than silently treated as plaintext.
    pub fn get_oauth_token(&self, provider_id: &str) -> Option<OAuthToken> {
        let path = self.token_path(provider_id);
        let encrypted = std::fs::read(&path).ok()?;
        let decrypted = match self.cipher.decrypt_or_plaintext(&encrypted) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(provider_id, error = %e, "failed to read OAuth token");
                return None;
            }
        };
        serde_json::from_slice(&decrypted).ok()
    }

    /// Deletes an OAuth token by provider ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be removed.
    pub fn delete_oauth_token(&self, provider_id: &str) -> Result<()> {
        let path = self.token_path(provider_id);
        if path.exists() {
            std::fs::remove_file(&path)
                .with_context(|| format!("failed to delete token: {}", path.display()))?;
        }
        Ok(())
    }

    /// Lists all provider IDs that have tokens.
    pub fn list_oauth_providers(&self) -> Vec<String> {
        let tokens_dir = self.base_dir.join("tokens");
        Self::list_enc_files(&tokens_dir)
    }

    /// Gets all OAuth tokens (decrypts each from AES-256-GCM).
    pub fn all_oauth_tokens(&self) -> std::collections::HashMap<String, OAuthToken> {
        let mut map = std::collections::HashMap::new();
        for provider_id in self.list_oauth_providers() {
            if let Some(token) = self.get_oauth_token(&provider_id) {
                map.insert(provider_id, token);
            }
        }
        map
    }

    /// Lists entity IDs from `*.json.enc` files in a directory.
    pub(super) fn list_enc_files(dir: &Path) -> Vec<String> {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return vec![],
        };
        let mut ids = vec![];
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if let Some(id) = name_str.strip_suffix(".json.enc") {
                ids.push(id.to_string());
            }
        }
        ids
    }
}

//! Cross-process OAuth refresh leases and durable uncertainty markers.

use super::{atomic, sanitize_filename, GrobStore};
use crate::auth::token_store::OAuthToken;
use anyhow::{Context, Result};
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use std::{fs::File, path::PathBuf, time::Duration};

impl GrobStore {
    fn refresh_path(&self, provider_id: &str, suffix: &str) -> PathBuf {
        self.base_dir.join("tokens").join(format!(
            "{}.refresh.{suffix}",
            sanitize_filename(provider_id)
        ))
    }

    /// Holds a kernel lease across the issuer request, without blocking Tokio.
    pub(crate) async fn lock_oauth_refresh(&self, provider_id: &str) -> Result<File> {
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        // Never unlink the lock file: waiters must all use the same inode.
        let file = options.open(self.refresh_path(provider_id, "lock"))?;
        crate::auth::token_store::set_owner_only_permissions(
            &self.refresh_path(provider_id, "lock"),
        )?;
        #[cfg(test)]
        super::process_tests::checkpoint("refresh-waiting");
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                match file.try_lock() {
                    Ok(()) => return Ok(file),
                    Err(std::fs::TryLockError::WouldBlock) => {
                        tokio::time::sleep(Duration::from_millis(25)).await;
                    }
                    Err(std::fs::TryLockError::Error(error)) => return Err(error),
                }
            }
        })
        .await
        .context("Timed out waiting for OAuth refresh lease")?
        .context("Failed to acquire OAuth refresh lease")
    }

    /// Refuses to reuse a refresh token whose previous issuer outcome is unknown.
    pub(crate) fn begin_oauth_refresh(&self, token: &OAuthToken) -> Result<()> {
        let path = self.refresh_path(&token.provider_id, "pending");
        // Metadata edits must never authorize reuse of an uncertain refresh token.
        let fingerprint = Sha256::digest(token.refresh_token.expose_secret().as_bytes());
        match std::fs::read(&path) {
            Ok(previous) => anyhow::ensure!(
                previous != fingerprint.as_slice(),
                "Previous OAuth refresh outcome is unknown; replace credentials or authenticate again"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("Cannot read OAuth refresh intent"),
        }
        atomic::write_atomic(&path, &fingerprint)
    }

    /// Clears the intent after a definitive rejection or a published result.
    pub(crate) fn finish_oauth_refresh(&self, provider_id: &str) -> Result<()> {
        atomic::remove_durable(&self.refresh_path(provider_id, "pending"))
    }
}

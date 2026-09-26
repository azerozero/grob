//! Authenticated, versioned bundles and durable authority/revocation metadata.

use serde::{Deserialize, Serialize};

/// Holds related credential fields together and erases owned plaintext on drop.
#[derive(Clone, Default, Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    /// Bearer token or API key.
    #[serde(default)]
    pub token: String,
    /// HTTP Basic username.
    #[serde(default)]
    pub username: String,
    /// HTTP Basic password.
    #[serde(default)]
    pub password: String,
}

impl Bundle {
    /// Validates credential sizes and the fields required by an injection scheme.
    ///
    /// # Errors
    /// Rejects empty, oversized, multiline or ambiguous credentials.
    pub fn validate(&self, injection: &super::config::Injection) -> super::Result<()> {
        if [&self.token, &self.username, &self.password]
            .iter()
            .any(|v| v.len() > 4096 || v.contains(['\r', '\n', '\0']))
        {
            return Err(super::CredentialError::Denied);
        }
        let valid = match injection {
            super::config::Injection::Basic => {
                !self.username.is_empty()
                    && !self.username.contains(':')
                    && !self.password.is_empty()
                    && self.token.is_empty()
            }
            _ => !self.token.is_empty() && self.username.is_empty() && self.password.is_empty(),
        };
        if !valid {
            return Err(super::CredentialError::Denied);
        }
        Ok(())
    }
}

/// Selects credential authority independently from network availability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Authority {
    /// Reads a locally provisioned bundle.
    Local,
    /// Reads Vault KV v2, optionally using explicitly bounded recovery.
    Vault,
}

/// Stores values and security metadata inside one authenticated encrypted envelope.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRecord {
    /// Record format version.
    pub format: u32,
    /// Exact tenant scope.
    pub tenant: String,
    /// Exact service scope.
    pub service: String,
    /// Complete binding configuration revision.
    pub policy: String,
    /// Mutation identifier used for cross-process compare-and-swap.
    pub generation: uuid::Uuid,
    /// Explicit source selected by the administrator.
    pub authority: Authority,
    /// Durable revocation, cleared only by explicit provisioning.
    pub revoked: bool,
    /// Whole credential version; absent until first remote verification.
    pub bundle: Option<Bundle>,
    /// Administrative expiry; legacy records retain their conservative combined deadline.
    pub expires_at: Option<i64>,
    /// Deletion deadline of the currently verified Vault version, independent from policy expiry.
    #[serde(default)]
    pub remote_expires_at: Option<i64>,
    /// Last successful remote validation, never advanced by failed requests.
    pub verified_at: Option<i64>,
    /// Highest accepted KV v2 version.
    pub remote_version: u64,
    /// Durable wall-clock high-water mark.
    pub observed_at: i64,
    /// Earliest next remote attempt, bounding outage retry amplification.
    pub retry_at: i64,
    /// Indicates the last authoritative attempt failed through unavailability.
    pub recovery: bool,
}

impl CredentialRecord {
    pub(crate) fn state(&self, binding: &super::config::ServiceBinding, now: i64) -> &'static str {
        if self.check(binding, now).is_err() || self.bundle.is_none() {
            return "unavailable";
        }
        if self.authority == Authority::Local {
            return "local";
        }
        if self.recovery {
            return if binding.vault.as_ref().is_some_and(|v| {
                v.max_offline_secs > 0
                    && self.verified_at.is_some_and(|t| {
                        now >= t && now < t.saturating_add(v.max_offline_secs as i64)
                    })
            }) {
                "recovery"
            } else {
                "unavailable"
            };
        }
        if now >= self.retry_at {
            "verification_due"
        } else {
            "remote"
        }
    }

    /// Creates an explicit administrative publication or authority switch.
    pub fn provision(
        binding: &super::config::ServiceBinding,
        authority: Authority,
        bundle: Option<Bundle>,
        expires_at: Option<i64>,
    ) -> Self {
        Self {
            format: 2,
            tenant: binding.tenant.clone(),
            service: binding.id.clone(),
            policy: binding.revision(),
            generation: uuid::Uuid::new_v4(),
            authority,
            revoked: false,
            bundle,
            expires_at,
            remote_expires_at: None,
            verified_at: None,
            remote_version: 0,
            observed_at: super::now(),
            retry_at: 0,
            recovery: false,
        }
    }

    pub(crate) fn check(
        &self,
        binding: &super::config::ServiceBinding,
        now: i64,
    ) -> super::Result<()> {
        self.check_authority(binding, now)?;
        if self.version_expired(now) {
            return Err(super::CredentialError::Denied);
        }
        Ok(())
    }

    pub(crate) fn effective_expiry(&self) -> Option<i64> {
        self.expires_at
            .into_iter()
            .chain(self.remote_expires_at)
            .min()
    }

    pub(crate) fn version_expired(&self, now: i64) -> bool {
        self.remote_expires_at.is_some_and(|e| now >= e)
    }

    // Cached version expiry may trigger a refresh; authority restrictions must never do so.
    pub(crate) fn check_authority(
        &self,
        binding: &super::config::ServiceBinding,
        now: i64,
    ) -> super::Result<()> {
        if self.revoked
            || self.policy != binding.revision()
            || now < self.observed_at
            || self.expires_at.is_some_and(|e| now >= e)
            || binding.expires_at.is_some_and(|e| now >= e)
        {
            return Err(super::CredentialError::Denied);
        }
        Ok(())
    }
}

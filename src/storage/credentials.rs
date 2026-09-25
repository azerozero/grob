//! Strict credential records; legacy global fallback and plaintext reads are deliberately absent.

use super::{atomic, GrobStore};
use crate::credentials::{
    config::ServiceBinding,
    record::{Authority, Bundle, CredentialRecord},
    CredentialError, Result,
};
use sha2::{Digest, Sha256};

impl GrobStore {
    fn credential_path(&self, tenant: &str, service: &str) -> std::path::PathBuf {
        let key = serde_json::to_vec(&(tenant, service)).expect("serializable scope");
        self.path()
            .join("credentials")
            .join(format!("{}.enc", hex::encode(Sha256::digest(key))))
    }

    fn read_credential(&self, tenant: &str, service: &str) -> Result<CredentialRecord> {
        let data = std::fs::read(self.credential_path(tenant, service)).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                CredentialError::Missing
            } else {
                CredentialError::Storage
            }
        })?;
        let clear = zeroize::Zeroizing::new(
            self.cipher
                .decrypt(&data)
                .map_err(|_| CredentialError::Storage)?,
        );
        let record: CredentialRecord =
            serde_json::from_slice(&clear).map_err(|_| CredentialError::Storage)?;
        if record.format != 1 || record.tenant != tenant || record.service != service {
            return Err(CredentialError::Storage);
        }
        Ok(record)
    }

    fn write_credential(&self, record: &CredentialRecord) -> Result<()> {
        let path = self.credential_path(&record.tenant, &record.service);
        std::fs::create_dir_all(path.parent().ok_or(CredentialError::Storage)?)
            .map_err(|_| CredentialError::Storage)?;
        // A newly created credentials directory must itself survive a host crash.
        #[cfg(unix)]
        std::fs::File::open(self.path())
            .and_then(|dir| dir.sync_all())
            .map_err(|_| CredentialError::Storage)?;
        let clear = zeroize::Zeroizing::new(
            serde_json::to_vec(record).map_err(|_| CredentialError::Storage)?,
        );
        let encrypted = self
            .cipher
            .encrypt(&clear)
            .map_err(|_| CredentialError::Storage)?;
        atomic::write_atomic(&path, &encrypted).map_err(|_| CredentialError::Storage)
    }

    /// Reads one strict scope and durably advances its clock high-water mark.
    ///
    /// # Errors
    /// Rejects missing, corrupt, misplaced records and clock rollback.
    pub fn credential_read(&self, tenant: &str, service: &str) -> Result<CredentialRecord> {
        let _lock = self
            .credential_lock()
            .map_err(|_| CredentialError::Storage)?;
        let mut record = self.read_credential(tenant, service)?;
        let now = crate::credentials::now();
        if now < record.observed_at {
            return Err(CredentialError::Denied);
        }
        if now > record.observed_at {
            record.observed_at = now;
            self.write_credential(&record)?;
        }
        Ok(record)
    }

    /// Publishes an administrative change, or replaces exactly one expected generation.
    ///
    /// # Errors
    /// Rejects storage failures or stale background updates after rotation/revocation.
    pub fn credential_publish(
        &self,
        mut record: CredentialRecord,
        expected: Option<uuid::Uuid>,
    ) -> Result<uuid::Uuid> {
        let _lock = self
            .credential_lock()
            .map_err(|_| CredentialError::Storage)?;
        if let Some(expected) = expected {
            let current = self.read_credential(&record.tenant, &record.service)?;
            if current.generation != expected {
                return Err(CredentialError::Changed);
            }
            record.observed_at = record.observed_at.max(current.observed_at);
        }
        record.generation = uuid::Uuid::new_v4();
        self.write_credential(&record)?;
        tracing::info!(tenant = %record.tenant, service = %record.service, authority = ?record.authority, generation = %record.generation, revoked = record.revoked, administrative = expected.is_none(), "credential publication");
        Ok(record.generation)
    }

    /// Rotates local credentials while preserving expiry unless an administrator supplies a new deadline.
    ///
    /// # Errors
    /// Rejects invalid bundles, corrupt existing records, expired deadlines and failed durable writes.
    pub fn credential_set_local(
        &self,
        binding: &ServiceBinding,
        bundle: Bundle,
        expires_at: Option<i64>,
    ) -> Result<()> {
        bundle.validate(&binding.injection)?;
        let _lock = self
            .credential_lock()
            .map_err(|_| CredentialError::Storage)?;
        let existing_expiry = match self.read_credential(&binding.tenant, &binding.id) {
            Ok(record) => record.expires_at,
            Err(CredentialError::Missing) => None,
            Err(error) => return Err(error),
        };
        let expires_at = expires_at.or(existing_expiry);
        if expires_at.is_some_and(|e| e <= crate::credentials::now()) {
            return Err(CredentialError::Denied);
        }
        let record =
            CredentialRecord::provision(binding, Authority::Local, Some(bundle), expires_at);
        self.write_credential(&record)?;
        tracing::info!(tenant = %record.tenant, service = %record.service, generation = %record.generation, expires_at = ?record.expires_at, "local credential publication");
        Ok(())
    }

    /// Durably revokes every source for one existing credential binding.
    ///
    /// # Errors
    /// Rejects missing or corrupt records and failed durable writes.
    pub fn credential_revoke(&self, tenant: &str, service: &str) -> Result<()> {
        let _lock = self
            .credential_lock()
            .map_err(|_| CredentialError::Storage)?;
        let mut record = self.read_credential(tenant, service)?;
        record.revoked = true;
        record.bundle = None;
        record.generation = uuid::Uuid::new_v4();
        self.write_credential(&record)?;
        tracing::info!(tenant = %record.tenant, service = %record.service, generation = %record.generation, "credential revocation");
        Ok(())
    }
}

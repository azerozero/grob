//! Virtual-key persistence for [`crate::storage::GrobStore`] (AES-256-GCM at rest).
//!
//! Hash-keyed records are authoritative for both authentication and management.
//! Legacy UUID index files are ignored.

use std::path::PathBuf;

use anyhow::Result;

use super::{atomic, sanitize_filename, GrobStore};
use crate::auth::virtual_keys::VirtualKeyRecord;

impl GrobStore {
    fn vkey_hash_path(&self, key_hash: &str) -> PathBuf {
        self.base_dir
            .join("vkeys")
            .join(format!("{}.json.enc", sanitize_filename(key_hash)))
    }

    /// Stores a virtual key record (encrypted with AES-256-GCM).
    ///
    /// Uses one authoritative hash-keyed file; no secondary index can drift.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization, encryption, or the
    /// atomic file write fails.
    pub fn store_virtual_key(&self, record: &VirtualKeyRecord) -> Result<()> {
        let _lock = self.credential_lock()?;
        self.write_virtual_key(record)
    }

    fn write_virtual_key(&self, record: &VirtualKeyRecord) -> Result<()> {
        let plaintext = zeroize::Zeroizing::new(serde_json::to_vec(record)?);
        let encrypted = self.cipher.encrypt(&plaintext)?;

        // Primary: by hash.
        atomic::write_atomic(&self.vkey_hash_path(&record.key_hash), &encrypted)?;

        Ok(())
    }

    /// Looks up a virtual key record by its SHA-256 hash.
    ///
    /// Returns `None` if absent or unreadable; an authentication failure is
    /// logged rather than silently treated as plaintext.
    pub fn lookup_virtual_key(&self, key_hash: &str) -> Option<VirtualKeyRecord> {
        let path = self.vkey_hash_path(key_hash);
        let encrypted = std::fs::read(&path).ok()?;
        let decrypted = match self.cipher.decrypt_or_plaintext(&encrypted) {
            Ok(d) => zeroize::Zeroizing::new(d),
            Err(e) => {
                tracing::warn!(error = %e, "failed to read virtual key by hash");
                return None;
            }
        };
        serde_json::from_slice(&decrypted).ok()
    }

    /// Lists all virtual key records.
    pub fn list_virtual_keys(&self) -> Vec<VirtualKeyRecord> {
        let vkeys_dir = self.base_dir.join("vkeys");
        let entries = match std::fs::read_dir(&vkeys_dir) {
            Ok(e) => e,
            Err(_) => return vec![],
        };

        let mut records = vec![];
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            // Skip id_ files to avoid duplicates.
            if name_str.starts_with("id_") {
                continue;
            }
            if !name_str.ends_with(".json.enc") {
                continue;
            }
            if let Ok(data) = std::fs::read(entry.path()) {
                match self.cipher.decrypt_or_plaintext(&data) {
                    Ok(decrypted) => {
                        if let Ok(record) = serde_json::from_slice::<VirtualKeyRecord>(
                            &zeroize::Zeroizing::new(decrypted),
                        ) {
                            records.push(record);
                        }
                    }
                    // Skip unreadable records rather than abort the whole list.
                    Err(e) => {
                        tracing::warn!(error = %e, "skipping unreadable virtual key record");
                    }
                }
            }
        }
        records
    }

    /// Revokes a virtual key by UUID (sets `revoked = true`).
    ///
    /// # Errors
    ///
    /// Returns an error if the record cannot be read, deserialized,
    /// or re-encrypted.
    pub fn revoke_virtual_key(&self, id: &uuid::Uuid) -> Result<bool> {
        let _lock = self.credential_lock()?;
        let Some(mut record) = self
            .list_virtual_keys()
            .into_iter()
            .find(|record| &record.id == id)
        else {
            return Ok(false);
        };
        record.revoked = true;
        self.write_virtual_key(&record)?;
        Ok(true)
    }

    /// Replaces a live key, preserving all restrictions and its expiration.
    ///
    /// Serializes management across processes. The replacement is persisted before
    /// revocation; its secret is only returned once the old key is revoked.
    ///
    /// # Errors
    /// Returns an error for missing, revoked, expired, or unwritable keys.
    pub fn rotate_virtual_key(&self, id: &uuid::Uuid) -> Result<(VirtualKeyRecord, String)> {
        let _lock = self.credential_lock()?;
        let mut old = self
            .list_virtual_keys()
            .into_iter()
            .find(|record| &record.id == id)
            .ok_or_else(|| anyhow::anyhow!("Key not found"))?;
        anyhow::ensure!(
            !old.revoked
                && old
                    .expires_at
                    .is_none_or(|expiry| expiry > chrono::Utc::now()),
            "Cannot rotate a revoked or expired key"
        );
        let (secret, key_hash) = crate::auth::virtual_keys::generate_key();
        let replacement = VirtualKeyRecord {
            id: uuid::Uuid::new_v4(),
            prefix: secret[..12].to_owned(),
            key_hash,
            created_at: chrono::Utc::now(),
            last_used_at: None,
            ..old.clone()
        };
        self.write_virtual_key(&replacement)?;
        old.revoked = true;
        if let Err(error) = self.write_virtual_key(&old) {
            std::fs::remove_file(self.vkey_hash_path(&replacement.key_hash))?;
            return Err(error);
        }
        Ok((replacement, secret))
    }

    /// Deletes a virtual key by UUID (removes both hash and id files).
    ///
    /// # Errors
    ///
    /// Returns an error if the files cannot be removed.
    pub fn delete_virtual_key(&self, id: &uuid::Uuid) -> Result<bool> {
        let _lock = self.credential_lock()?;
        let Some(record) = self
            .list_virtual_keys()
            .into_iter()
            .find(|record| &record.id == id)
        else {
            return Ok(false);
        };
        std::fs::remove_file(self.vkey_hash_path(&record.key_hash))?;
        let legacy = self
            .base_dir
            .join("vkeys")
            .join(format!("id_{id}.json.enc"));
        match std::fs::remove_file(legacy) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(true)
    }
}

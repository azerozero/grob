//! Virtual-key persistence for [`GrobStore`] (AES-256-GCM at rest).
//!
//! Each record is stored twice: keyed by hash for O(1) auth lookup and by
//! UUID for management operations.

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

    fn vkey_id_path(&self, id: &uuid::Uuid) -> PathBuf {
        self.base_dir
            .join("vkeys")
            .join(format!("id_{id}.json.enc"))
    }

    /// Stores a virtual key record (encrypted with AES-256-GCM).
    ///
    /// Creates two files: one keyed by hash (for O(1) auth lookup) and
    /// one keyed by UUID (for management operations).
    ///
    /// # Errors
    ///
    /// Returns an error if serialization, encryption, or the
    /// atomic file write fails.
    pub fn store_virtual_key(&self, record: &VirtualKeyRecord) -> Result<()> {
        let plaintext = serde_json::to_vec(record)?;
        let encrypted = self.cipher.encrypt(&plaintext)?;

        // Primary: by hash.
        atomic::write_atomic(&self.vkey_hash_path(&record.key_hash), &encrypted)?;
        // Secondary: by UUID.
        let encrypted2 = self.cipher.encrypt(&plaintext)?;
        atomic::write_atomic(&self.vkey_id_path(&record.id), &encrypted2)?;

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
            Ok(d) => d,
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
                        if let Ok(record) = serde_json::from_slice::<VirtualKeyRecord>(&decrypted) {
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
        let id_path = self.vkey_id_path(id);
        let data = match std::fs::read(&id_path) {
            Ok(d) => d,
            Err(_) => return Ok(false),
        };
        let decrypted = self.cipher.decrypt_or_plaintext(&data)?;
        let mut record: VirtualKeyRecord = serde_json::from_slice(&decrypted)?;
        record.revoked = true;
        self.store_virtual_key(&record)?;
        Ok(true)
    }

    /// Deletes a virtual key by UUID (removes both hash and id files).
    ///
    /// # Errors
    ///
    /// Returns an error if the files cannot be removed.
    pub fn delete_virtual_key(&self, id: &uuid::Uuid) -> Result<bool> {
        let id_path = self.vkey_id_path(id);
        let data = match std::fs::read(&id_path) {
            Ok(d) => d,
            Err(_) => return Ok(false),
        };
        let decrypted = self.cipher.decrypt_or_plaintext(&data)?;
        let record: VirtualKeyRecord = serde_json::from_slice(&decrypted)?;

        // Remove both files.
        let hash_path = self.vkey_hash_path(&record.key_hash);
        let _ = std::fs::remove_file(&hash_path);
        let _ = std::fs::remove_file(&id_path);
        Ok(true)
    }
}

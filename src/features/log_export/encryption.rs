//! Age-based envelope encryption for audit log content.
//!
//! Encrypts request/response content with a per-entry DEK, wrapped
//! for each authorized recipient using X25519.

use std::io::Write;

/// Encrypts content for multiple age recipients. Returns base64-encoded age blob.
///
/// # Errors
///
/// - [`EncryptError::NoRecipients`] if `recipient_keys` is empty.
/// - [`EncryptError::InvalidRecipient`] if a key cannot be parsed as an X25519 recipient.
/// - [`EncryptError::Encryption`] if age encryption or stream writing fails.
pub fn encrypt_for_recipients(
    content: &str,
    recipient_keys: &[String],
) -> Result<String, EncryptError> {
    if recipient_keys.is_empty() {
        return Err(EncryptError::NoRecipients);
    }

    let recipients: Vec<age::x25519::Recipient> = recipient_keys
        .iter()
        .map(|key| {
            key.parse::<age::x25519::Recipient>()
                .map_err(|_| EncryptError::InvalidRecipient(key.clone()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let encryptor =
        age::Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn age::Recipient))
            .map_err(|e| EncryptError::Encryption(e.to_string()))?;

    let mut encrypted = vec![];
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|e| EncryptError::Encryption(e.to_string()))?;
    writer
        .write_all(content.as_bytes())
        .map_err(|e| EncryptError::Encryption(e.to_string()))?;
    writer
        .finish()
        .map_err(|e| EncryptError::Encryption(e.to_string()))?;

    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.encode(&encrypted))
}

/// Decrypts a base64-encoded age blob with the given identity.
#[cfg(test)]
pub fn decrypt_with_identity(
    encrypted_b64: &str,
    identity: &age::x25519::Identity,
) -> Result<String, EncryptError> {
    use base64::Engine;
    use std::io::Read;

    let encrypted = base64::engine::general_purpose::STANDARD
        .decode(encrypted_b64)
        .map_err(|e| EncryptError::Encryption(e.to_string()))?;

    let decryptor = age::Decryptor::new_buffered(&encrypted[..])
        .map_err(|e| EncryptError::Encryption(e.to_string()))?;

    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|e| EncryptError::Encryption(e.to_string()))?;

    let mut decrypted = String::new();
    reader
        .read_to_string(&mut decrypted)
        .map_err(|e| EncryptError::Encryption(e.to_string()))?;
    Ok(decrypted)
}

/// Errors during encryption/decryption.
#[derive(Debug, thiserror::Error)]
pub enum EncryptError {
    /// No recipients provided.
    #[error("no recipients provided")]
    NoRecipients,
    /// Invalid age recipient key.
    #[error("invalid recipient key: {0}")]
    InvalidRecipient(String),
    /// Encryption/decryption failure.
    #[error("encryption error: {0}")]
    Encryption(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_keypair() -> (age::x25519::Identity, String) {
        let identity = age::x25519::Identity::generate();
        let pubkey = identity.to_public().to_string();
        (identity, pubkey)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (identity, pubkey) = generate_keypair();
        let content = "prompt: hello world\nresponse: hi there";

        let encrypted = encrypt_for_recipients(content, &[pubkey]).unwrap();
        assert!(!encrypted.is_empty());
        assert_ne!(encrypted, content);

        let decrypted = decrypt_with_identity(&encrypted, &identity).unwrap();
        assert_eq!(decrypted, content);
    }

    #[test]
    fn test_multi_recipient_roundtrip() {
        let (id1, pk1) = generate_keypair();
        let (id2, pk2) = generate_keypair();
        let (id3, pk3) = generate_keypair();
        let content = "secret audit content";

        let encrypted = encrypt_for_recipients(content, &[pk1, pk2, pk3]).unwrap();

        assert_eq!(decrypt_with_identity(&encrypted, &id1).unwrap(), content);
        assert_eq!(decrypt_with_identity(&encrypted, &id2).unwrap(), content);
        assert_eq!(decrypt_with_identity(&encrypted, &id3).unwrap(), content);
    }

    #[test]
    fn test_wrong_key_cannot_decrypt() {
        let (_id1, pk1) = generate_keypair();
        let (wrong_id, _) = generate_keypair();
        let content = "confidential";

        let encrypted = encrypt_for_recipients(content, &[pk1]).unwrap();
        let result = decrypt_with_identity(&encrypted, &wrong_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_no_recipients_error() {
        let result = encrypt_for_recipients("content", &[]);
        assert!(matches!(result, Err(EncryptError::NoRecipients)));
    }

    #[test]
    fn test_invalid_recipient_key() {
        let result = encrypt_for_recipients("content", &["not-a-valid-key".to_string()]);
        assert!(matches!(result, Err(EncryptError::InvalidRecipient(_))));
    }
}

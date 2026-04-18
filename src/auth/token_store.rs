use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

/// Serializes a [`SecretString`] by exposing its inner value.
fn serialize_secret<S>(secret: &SecretString, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(secret.expose_secret())
}

/// Deserializes a string into a [`SecretString`].
fn deserialize_secret<'de, D>(deserializer: D) -> Result<SecretString, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(SecretString::new(s))
}

/// Serializes an `Option<SecretString>` for storage.
pub(crate) fn serialize_secret_opt<S>(
    secret: &Option<SecretString>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match secret {
        Some(s) => serializer.serialize_some(s.expose_secret()),
        None => serializer.serialize_none(),
    }
}

/// Deserializes an `Option<String>` into `Option<SecretString>`.
pub(crate) fn deserialize_secret_opt<'de, D>(
    deserializer: D,
) -> Result<Option<SecretString>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<String> = Option::deserialize(deserializer)?;
    Ok(s.map(SecretString::new))
}

/// OAuth token information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthToken {
    /// Provider ID (e.g., "claude-max", "anthropic-oauth")
    pub provider_id: String,
    /// OAuth access token (stored securely)
    #[serde(
        serialize_with = "serialize_secret",
        deserialize_with = "deserialize_secret"
    )]
    pub access_token: SecretString,
    /// OAuth refresh token (stored securely)
    #[serde(
        serialize_with = "serialize_secret",
        deserialize_with = "deserialize_secret"
    )]
    pub refresh_token: SecretString,
    /// Token expiration time (UTC)
    pub expires_at: DateTime<Utc>,
    /// Optional enterprise URL for GitHub Copilot Enterprise
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enterprise_url: Option<String>,
    /// Optional Google Cloud project ID for Gemini Code Assist API
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    /// Marks the token as needing manual re-authentication (e.g. after a refresh 401).
    ///
    /// Optional with `#[serde(default)]` for backward compatibility with tokens
    /// persisted before this field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub needs_reauth: Option<bool>,
}

impl OAuthToken {
    /// Check if token is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    /// Check if token will expire soon (within 5 minutes)
    pub fn needs_refresh(&self) -> bool {
        let now = Utc::now();
        let buffer = chrono::Duration::minutes(5);
        now + buffer >= self.expires_at
    }
}

/// Token storage — persists to file-based GrobStore or JSON file (legacy).
#[derive(Debug, Clone)]
pub struct TokenStore {
    /// Path to token storage file (legacy fallback)
    file_path: PathBuf,
    /// In-memory cache of tokens
    tokens: Arc<RwLock<HashMap<String, OAuthToken>>>,
    /// Optional GrobStore backend
    store: Option<std::sync::Arc<crate::storage::GrobStore>>,
}

impl TokenStore {
    /// Creates a new token store backed by [`GrobStore`](crate::storage::GrobStore).
    ///
    /// # Errors
    ///
    /// Returns an error if loading existing tokens from the
    /// database fails.
    pub fn with_store(store: std::sync::Arc<crate::storage::GrobStore>) -> Result<Self> {
        let tokens = store.all_oauth_tokens();
        Ok(Self {
            file_path: PathBuf::new(),
            tokens: Arc::new(RwLock::new(tokens)),
            store: Some(store),
        })
    }

    /// Create an empty token store (no persistence, no OAuth).
    /// Used when the `oauth` feature is disabled.
    pub fn new_empty() -> Self {
        Self {
            file_path: PathBuf::new(),
            tokens: Arc::new(RwLock::new(HashMap::new())),
            store: None,
        }
    }

    /// Creates a new token store (legacy JSON mode).
    ///
    /// # Errors
    ///
    /// Returns an error if the token file exists but cannot be read
    /// or parsed as JSON.
    pub fn new(file_path: PathBuf) -> Result<Self> {
        let tokens = if file_path.exists() {
            let content = fs::read_to_string(&file_path).context("Failed to read token file")?;
            serde_json::from_str(&content).context("Failed to parse token file")?
        } else {
            HashMap::new()
        };

        Ok(Self {
            file_path,
            tokens: Arc::new(RwLock::new(tokens)),
            store: None,
        })
    }

    /// Gets the default token store path.
    ///
    /// # Errors
    ///
    /// Returns an error if the home directory cannot be determined
    /// or the config directory cannot be created.
    pub fn default_path() -> Result<PathBuf> {
        let home = crate::home_dir().context("Failed to get home directory (set GROB_HOME)")?;
        let config_dir = home.join(".grob");
        fs::create_dir_all(&config_dir).context("Failed to create config directory")?;
        Ok(config_dir.join("oauth_tokens.json"))
    }

    /// Creates a token store at the default location (legacy mode).
    ///
    /// # Errors
    ///
    /// Returns an error if the default path cannot be resolved or
    /// the token file cannot be read.
    pub fn at_default_path() -> Result<Self> {
        let path = Self::default_path()?;
        Self::new(path)
    }

    /// Saves a token for a provider.
    ///
    /// # Errors
    ///
    /// Returns an error if the database write or legacy JSON
    /// persistence fails.
    pub fn save(&self, token: OAuthToken) -> Result<()> {
        let provider_id = token.provider_id.clone();

        if let Some(ref store) = self.store {
            store.save_oauth_token(&token)?;
        }

        {
            let mut tokens = self.tokens.write().unwrap_or_else(|e| e.into_inner());
            tokens.insert(provider_id, token);
        }

        if self.store.is_none() {
            self.persist()?;
        }

        Ok(())
    }

    /// Get token for a provider
    pub fn get(&self, provider_id: &str) -> Option<OAuthToken> {
        let tokens = self.tokens.read().unwrap_or_else(|e| e.into_inner());
        tokens.get(provider_id).cloned()
    }

    /// Marks the token for `provider_id` as needing manual re-authentication.
    ///
    /// Called after a refresh-token failure (401) so the operator can be
    /// prompted to run `grob connect --force-reauth`.
    ///
    /// # Errors
    ///
    /// Returns an error if re-saving the updated token fails.
    pub fn mark_needs_reauth(&self, provider_id: &str) -> Result<bool> {
        let updated = {
            let tokens = self.tokens.read().unwrap_or_else(|e| e.into_inner());
            match tokens.get(provider_id) {
                Some(t) => {
                    let mut cloned = t.clone();
                    cloned.needs_reauth = Some(true);
                    Some(cloned)
                }
                None => None,
            }
        };
        if let Some(token) = updated {
            self.save(token)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Removes a token for a provider.
    ///
    /// # Errors
    ///
    /// Returns an error if the database deletion or legacy JSON
    /// persistence fails.
    pub fn remove(&self, provider_id: &str) -> Result<()> {
        if let Some(ref store) = self.store {
            store.delete_oauth_token(provider_id)?;
        }

        {
            let mut tokens = self.tokens.write().unwrap_or_else(|e| e.into_inner());
            tokens.remove(provider_id);
        }

        if self.store.is_none() {
            self.persist()?;
        }

        Ok(())
    }

    /// List all provider IDs that have tokens
    pub fn list_providers(&self) -> Vec<String> {
        let tokens = self.tokens.read().unwrap_or_else(|e| e.into_inner());
        tokens.keys().cloned().collect()
    }

    /// Get all tokens
    pub fn all(&self) -> HashMap<String, OAuthToken> {
        let tokens = self.tokens.read().unwrap_or_else(|e| e.into_inner());
        tokens.clone()
    }

    /// Persist tokens to file (legacy mode only)
    fn persist(&self) -> Result<()> {
        if self.store.is_some() {
            return Ok(()); // GrobStore handles persistence
        }

        // CodeQL: path-injection — mitigated by path traversal check below and
        // canonicalization to resolve symlinks and relative components.
        let path_str = self.file_path.to_string_lossy();
        anyhow::ensure!(
            !path_str.contains(".."),
            "Token file path must not contain '..': {}",
            path_str
        );

        // Canonicalize to resolve symlinks and ensure the path is absolute.
        let canonical_path = if self.file_path.exists() {
            self.file_path
                .canonicalize()
                .context("Failed to canonicalize token file path")?
        } else {
            // File does not exist yet; canonicalize the parent directory.
            let parent = self
                .file_path
                .parent()
                .context("Token file path has no parent directory")?;
            let canonical_parent = parent
                .canonicalize()
                .context("Failed to canonicalize parent directory")?;
            canonical_parent.join(
                self.file_path
                    .file_name()
                    .context("Token file path has no file name")?,
            )
        };

        let tokens = self.tokens.read().unwrap_or_else(|e| e.into_inner());
        let json = serde_json::to_string_pretty(&*tokens).context("Failed to serialize tokens")?;

        fs::write(&canonical_path, json).context("Failed to write token file")?;

        set_owner_only_permissions(&canonical_path)?;

        Ok(())
    }
}

/// Sets owner-only read/write permissions on a file (cross-platform).
///
/// On Unix sets mode `0o600`. On Windows removes inherited ACEs and grants
/// the current user `GENERIC_ALL`, denying access to other principals.
pub(crate) fn set_owner_only_permissions(path: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600); // CodeQL: hard-coded-cryptographic-value — this is a Unix file permission mode, not a cryptographic value.
        fs::set_permissions(path, perms)?;
    }

    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use std::ptr;

        // NOTE: Uses raw Win32 API to avoid heavy crate dependencies.
        // Sets a DACL with a single GENERIC_ALL ACE for the current user.
        #[allow(
            unsafe_code,
            non_snake_case,
            non_upper_case_globals,
            dead_code,
            clippy::upper_case_acronyms
        )]
        mod win32 {
            pub const DACL_SECURITY_INFORMATION: u32 = 0x00000004;
            pub const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x80000000;
            pub const TOKEN_QUERY: u32 = 0x0008;
            pub const TokenUser: u32 = 1;
            pub const ACL_REVISION: u8 = 2;
            pub const GENERIC_ALL: u32 = 0x10000000;

            #[repr(C)]
            pub struct ACL {
                pub AclRevision: u8,
                pub Sbz1: u8,
                pub AclSize: u16,
                pub AceCount: u16,
                pub Sbz2: u16,
            }

            extern "system" {
                pub fn GetCurrentProcess() -> isize;
                pub fn OpenProcessToken(
                    ProcessHandle: isize,
                    DesiredAccess: u32,
                    TokenHandle: *mut isize,
                ) -> i32;
                pub fn GetTokenInformation(
                    TokenHandle: isize,
                    TokenInformationClass: u32,
                    TokenInformation: *mut u8,
                    TokenInformationLength: u32,
                    ReturnLength: *mut u32,
                ) -> i32;
                pub fn GetLengthSid(pSid: *const u8) -> u32;
                pub fn InitializeAcl(pAcl: *mut ACL, nAclLength: u32, dwAclRevision: u32) -> i32;
                pub fn AddAccessAllowedAce(
                    pAcl: *mut ACL,
                    dwAceRevision: u32,
                    AccessMask: u32,
                    pSid: *const u8,
                ) -> i32;
                pub fn SetNamedSecurityInfoW(
                    pObjectName: *const u16,
                    ObjectType: u32,
                    SecurityInfo: u32,
                    psidOwner: *const u8,
                    psidGroup: *const u8,
                    pDacl: *const ACL,
                    pSacl: *const ACL,
                ) -> u32;
                pub fn CloseHandle(hObject: isize) -> i32;
            }
        }

        // SAFETY: Win32 ACL calls on owned file descriptor with correct buffer sizes.
        // Sets file permissions to owner-only via SetNamedSecurityInfoA.
        #[allow(unsafe_code)]
        unsafe {
            // Get current user SID.
            let mut token_handle: isize = 0;
            if win32::OpenProcessToken(
                win32::GetCurrentProcess(),
                win32::TOKEN_QUERY,
                &mut token_handle,
            ) == 0
            {
                anyhow::bail!("OpenProcessToken failed");
            }

            let mut buf = vec![0u8; 256];
            let mut needed: u32 = 0;
            if win32::GetTokenInformation(
                token_handle,
                win32::TokenUser,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut needed,
            ) == 0
            {
                win32::CloseHandle(token_handle);
                anyhow::bail!("GetTokenInformation failed");
            }

            // TOKEN_USER starts with a pointer to the SID.
            let sid_ptr = *(buf.as_ptr() as *const *const u8);
            let sid_len = win32::GetLengthSid(sid_ptr);

            // Build an ACL with a single GENERIC_ALL ACE for the current user.
            // ACCESS_ALLOWED_ACE is 12 bytes (ACE_HEADER 4 + Mask 4 + SidStart 4).
            let acl_size = std::mem::size_of::<win32::ACL>() + 12 + sid_len as usize;
            let mut acl_buf = vec![0u8; acl_size];
            let acl = acl_buf.as_mut_ptr() as *mut win32::ACL;

            if win32::InitializeAcl(acl, acl_size as u32, win32::ACL_REVISION as u32) == 0 {
                win32::CloseHandle(token_handle);
                anyhow::bail!("InitializeAcl failed");
            }

            if win32::AddAccessAllowedAce(
                acl,
                win32::ACL_REVISION as u32,
                win32::GENERIC_ALL,
                sid_ptr,
            ) == 0
            {
                win32::CloseHandle(token_handle);
                anyhow::bail!("AddAccessAllowedAce failed");
            }

            // Apply the DACL (PROTECTED flag blocks inheritance).
            let wide_path: Vec<u16> = path
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let result = win32::SetNamedSecurityInfoW(
                wide_path.as_ptr(),
                1, // SE_FILE_OBJECT
                win32::DACL_SECURITY_INFORMATION | win32::PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null(),
                ptr::null(),
                acl,
                ptr::null(),
            );

            win32::CloseHandle(token_handle);

            if result != 0 {
                anyhow::bail!("SetNamedSecurityInfoW failed with error code {}", result);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_token_store() {
        let temp_dir = TempDir::new().unwrap();
        let token_path = temp_dir.path().join("tokens.json");
        let store = TokenStore::new(token_path).unwrap();

        let token = OAuthToken {
            provider_id: "test-provider".to_string(),
            access_token: SecretString::new("access-123".to_string()),
            refresh_token: SecretString::new("refresh-456".to_string()),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            enterprise_url: None,
            project_id: None,
            needs_reauth: None,
        };

        store.save(token.clone()).unwrap();

        let retrieved = store.get("test-provider").unwrap();
        assert_eq!(retrieved.access_token.expose_secret(), "access-123");
        assert_eq!(retrieved.refresh_token.expose_secret(), "refresh-456");

        store.remove("test-provider").unwrap();
        assert!(store.get("test-provider").is_none());
    }

    #[test]
    fn test_token_expiration() {
        let expired_token = OAuthToken {
            provider_id: "test".to_string(),
            access_token: SecretString::new("token".to_string()),
            refresh_token: SecretString::new("refresh".to_string()),
            expires_at: Utc::now() - chrono::Duration::hours(1),
            enterprise_url: None,
            project_id: None,
            needs_reauth: None,
        };

        assert!(expired_token.is_expired());
        assert!(expired_token.needs_refresh());

        let valid_token = OAuthToken {
            provider_id: "test".to_string(),
            access_token: SecretString::new("token".to_string()),
            refresh_token: SecretString::new("refresh".to_string()),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            enterprise_url: None,
            project_id: None,
            needs_reauth: None,
        };

        assert!(!valid_token.is_expired());
        assert!(!valid_token.needs_refresh());
    }
}

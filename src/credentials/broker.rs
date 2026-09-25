//! Resolves shared credential records, coalescing refresh and fencing stale publications.

use super::{
    config::ServiceBinding,
    record::{Authority, Bundle, CredentialRecord},
    CredentialError, Result,
};
use crate::storage::GrobStore;
use serde::Deserialize;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

/// Bounds concurrency and detects wall-clock regression within one configuration snapshot.
pub(crate) struct Broker {
    gate: tokio::sync::Mutex<()>,
    started: Instant,
    wall: i64,
}

impl Default for Broker {
    fn default() -> Self {
        Self {
            gate: tokio::sync::Mutex::new(()),
            started: Instant::now(),
            wall: super::now(),
        }
    }
}

impl Broker {
    pub(crate) async fn resolve(
        &self,
        store: Arc<GrobStore>,
        binding: &ServiceBinding,
    ) -> Result<CredentialRecord> {
        let _gate = tokio::time::timeout(Duration::from_secs(6), self.gate.lock())
            .await
            .map_err(|_| CredentialError::Unavailable)?;
        let now = super::now();
        // A one-second allowance covers timestamp quantization, not arbitrary clock rollback.
        if now.saturating_add(1)
            < self
                .wall
                .saturating_add(self.started.elapsed().as_secs() as i64)
        {
            return Err(CredentialError::Denied);
        }
        let tenant = binding.tenant.clone();
        let service = binding.id.clone();
        let reader = store.clone();
        let mut record =
            tokio::task::spawn_blocking(move || reader.credential_read(&tenant, &service))
                .await
                .map_err(|_| CredentialError::Storage)??;
        let now = super::now();
        record.check(binding, now)?;
        if record.authority == Authority::Local {
            return checked_bundle(record, binding);
        }
        let vault = binding.vault.as_ref().ok_or(CredentialError::Denied)?;
        if now < record.retry_at {
            return if record.recovery {
                recovery(record, binding, now)
            } else {
                checked_bundle(record, binding)
            };
        }
        let expected = record.generation;
        let remote = tokio::time::timeout(Duration::from_secs(5), read_vault(vault)).await;
        match remote {
            Ok(Ok(remote))
                if remote.version >= record.remote_version
                    && remote.bundle.validate(&binding.injection).is_ok() =>
            {
                record.bundle = Some(remote.bundle);
                record.remote_version = remote.version;
                record.verified_at = Some(now);
                record.expires_at = min_expiry(record.expires_at, remote.expires_at);
                record.retry_at = now.saturating_add(vault.refresh_secs as i64);
                record.recovery = false;
            }
            Ok(Err(CredentialError::Unavailable)) | Err(_) => {
                record.retry_at = super::now().saturating_add(vault.refresh_secs as i64);
                record.recovery = true;
            }
            _ => {
                // Authority denials and invalid responses cannot be hidden by an older snapshot.
                record.revoked = true;
                record.bundle = None;
            }
        }
        let published = record.clone();
        record.generation = tokio::task::spawn_blocking(move || {
            store.credential_publish(published, Some(expected))
        })
        .await
        .map_err(|_| CredentialError::Storage)??;
        let now = super::now();
        record.check(binding, now)?;
        if record.recovery {
            recovery(record, binding, now)
        } else {
            checked_bundle(record, binding)
        }
    }
}

fn checked_bundle(record: CredentialRecord, binding: &ServiceBinding) -> Result<CredentialRecord> {
    record
        .bundle
        .as_ref()
        .ok_or(CredentialError::Unavailable)?
        .validate(&binding.injection)?;
    Ok(record)
}

fn recovery(
    record: CredentialRecord,
    binding: &ServiceBinding,
    now: i64,
) -> Result<CredentialRecord> {
    let vault = binding.vault.as_ref().ok_or(CredentialError::Denied)?;
    let verified = record.verified_at.ok_or(CredentialError::Unavailable)?;
    if vault.max_offline_secs == 0
        || now < verified
        || now >= verified.saturating_add(vault.max_offline_secs as i64)
    {
        return Err(CredentialError::Unavailable);
    }
    record.check(binding, now)?;
    checked_bundle(record, binding)
}

fn min_expiry(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

#[derive(Deserialize)]
struct VaultResponse {
    data: VaultData,
}
#[derive(Deserialize)]
struct VaultData {
    data: Bundle,
    metadata: Metadata,
}
#[derive(Deserialize)]
struct Metadata {
    version: u64,
    destroyed: bool,
    deletion_time: String,
}
struct Remote {
    bundle: Bundle,
    version: u64,
    expires_at: Option<i64>,
}

async fn read_vault(config: &super::config::VaultConfig) -> Result<Remote> {
    use futures::StreamExt;
    let url = super::transport::endpoint(&config.endpoint, &config.allowed_ips)?;
    let token = zeroize::Zeroizing::new(
        tokio::fs::read(&config.token_file)
            .await
            .map_err(|_| CredentialError::Denied)?,
    );
    if token.len() > 16384 {
        return Err(CredentialError::Denied);
    }
    let token = std::str::from_utf8(&token)
        .map_err(|_| CredentialError::Denied)?
        .trim_end_matches(['\r', '\n']);
    if token.is_empty() {
        return Err(CredentialError::Denied);
    }
    let mut header =
        reqwest::header::HeaderValue::from_str(token).map_err(|_| CredentialError::Denied)?;
    header.set_sensitive(true);
    let response = super::transport::client(&url, &config.allowed_ips)?
        .get(url)
        .header("X-Vault-Token", header)
        .header("accept-encoding", "identity")
        .send()
        .await
        .map_err(|e| {
            if super::transport::unavailable(&e) {
                CredentialError::Unavailable
            } else {
                CredentialError::Denied
            }
        })?;
    // 503 can mean sealed. Never convert it (or an opaque 500) into offline permission.
    if matches!(response.status().as_u16(), 502 | 504) {
        return Err(CredentialError::Unavailable);
    }
    if response.status() != reqwest::StatusCode::OK {
        return Err(CredentialError::Denied);
    }
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| CredentialError::Denied)?;
        if bytes.len() + chunk.len() > 65536 {
            return Err(CredentialError::Denied);
        }
        bytes.extend_from_slice(&chunk);
    }
    let parsed: VaultResponse =
        serde_json::from_slice(&bytes).map_err(|_| CredentialError::Denied)?;
    let metadata = parsed.data.metadata;
    if metadata.destroyed || metadata.version == 0 {
        return Err(CredentialError::Denied);
    }
    let expires_at = if metadata.deletion_time.is_empty() {
        None
    } else {
        let expiry = chrono::DateTime::parse_from_rfc3339(&metadata.deletion_time)
            .map_err(|_| CredentialError::Denied)?
            .timestamp();
        if expiry <= super::now() {
            return Err(CredentialError::Denied);
        }
        Some(expiry)
    };
    Ok(Remote {
        bundle: parsed.data.data,
        version: metadata.version,
        expires_at,
    })
}

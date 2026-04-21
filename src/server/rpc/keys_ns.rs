//! `grob/keys/*` namespace: virtual API key management.

use super::auth::{require_role, CallerIdentity};
use super::types::{rpc_err, Role, StatusResponse, ERR_INTERNAL, ERR_NOT_FOUND};
use crate::auth::virtual_keys::{generate_key, VirtualKeyRecord};
use crate::server::AppState;
use chrono::Utc;
use jsonrpsee::types::ErrorObjectOwned;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// Virtual key summary returned by `grob/keys/list`.
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyInfo {
    /// Unique key identifier.
    pub id: String,
    /// Human-readable label.
    pub name: String,
    /// Key prefix (first 12 chars, for display).
    pub prefix: String,
    /// Creation timestamp (RFC 3339).
    pub created_at: String,
    /// Whether the key has been revoked.
    pub revoked: bool,
}

/// Creates a new virtual API key, persists its hash in `GrobStore`, and returns the plaintext secret.
pub async fn create(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
    name: &str,
) -> Result<serde_json::Value, ErrorObjectOwned> {
    require_role(caller, Role::Admin)?;

    let (full_key, key_hash) = generate_key();
    let prefix = full_key[..12].to_string();
    let id = Uuid::new_v4();

    let record = VirtualKeyRecord {
        id,
        name: name.to_string(),
        prefix: prefix.clone(),
        key_hash,
        tenant_id: String::new(),
        budget_usd: None,
        rate_limit_rps: None,
        allowed_models: None,
        created_at: Utc::now(),
        expires_at: None,
        revoked: false,
        last_used_at: None,
    };

    state
        .grob_store
        .store_virtual_key(&record)
        .map_err(|e| rpc_err(ERR_INTERNAL, format!("Failed to store key: {e}")))?;

    tracing::info!(caller_ip = %caller.ip, key_id = %id, "Virtual key created");

    Ok(serde_json::json!({
        "key_id": id.to_string(),
        "name": name,
        "prefix": prefix,
        "secret": full_key,
        "message": "Store this secret securely — it cannot be retrieved later."
    }))
}

/// Lists all virtual API keys (secrets are never exposed).
pub async fn list(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
) -> Result<Vec<KeyInfo>, ErrorObjectOwned> {
    require_role(caller, Role::Admin)?;

    let records = state.grob_store.list_virtual_keys();

    Ok(records
        .into_iter()
        .map(|r| KeyInfo {
            id: r.id.to_string(),
            name: r.name,
            prefix: r.prefix,
            created_at: r.created_at.to_rfc3339(),
            revoked: r.revoked,
        })
        .collect())
}

/// Revokes a virtual API key by id, marking it unusable for future dispatch.
pub async fn revoke(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
    key_id: &str,
) -> Result<StatusResponse, ErrorObjectOwned> {
    require_role(caller, Role::Admin)?;

    let uuid = Uuid::parse_str(key_id)
        .map_err(|_| rpc_err(ERR_NOT_FOUND, format!("Invalid key ID: {key_id}")))?;

    let removed = state
        .grob_store
        .revoke_virtual_key(&uuid)
        .map_err(|e| rpc_err(ERR_INTERNAL, format!("Failed to revoke key: {e}")))?;

    if !removed {
        return Err(rpc_err(ERR_NOT_FOUND, format!("Key not found: {key_id}")));
    }

    tracing::info!(caller_ip = %caller.ip, key_id = %key_id, "Virtual key revoked");

    Ok(StatusResponse {
        status: "ok".into(),
        message: Some(format!("Key {key_id} revoked")),
    })
}

/// Rotates a virtual API key (revokes old, creates new with same name).
pub async fn rotate(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
    key_id: &str,
) -> Result<serde_json::Value, ErrorObjectOwned> {
    require_role(caller, Role::Admin)?;

    let uuid = Uuid::parse_str(key_id)
        .map_err(|_| rpc_err(ERR_NOT_FOUND, format!("Invalid key ID: {key_id}")))?;

    // Look up the existing key to preserve its name and settings.
    let records = state.grob_store.list_virtual_keys();
    let old = records
        .iter()
        .find(|r| r.id == uuid)
        .ok_or_else(|| rpc_err(ERR_NOT_FOUND, format!("Key not found: {key_id}")))?;

    let name = old.name.clone();
    let tenant_id = old.tenant_id.clone();
    let budget_usd = old.budget_usd;
    let rate_limit_rps = old.rate_limit_rps;
    let allowed_models = old.allowed_models.clone();

    // Revoke old key.
    state
        .grob_store
        .revoke_virtual_key(&uuid)
        .map_err(|e| rpc_err(ERR_INTERNAL, format!("Failed to revoke old key: {e}")))?;

    // Create replacement.
    let (full_key, key_hash) = generate_key();
    let prefix = full_key[..12].to_string();
    let new_id = Uuid::new_v4();

    let record = VirtualKeyRecord {
        id: new_id,
        name: name.clone(),
        prefix: prefix.clone(),
        key_hash,
        tenant_id,
        budget_usd,
        rate_limit_rps,
        allowed_models,
        created_at: Utc::now(),
        expires_at: None,
        revoked: false,
        last_used_at: None,
    };

    state
        .grob_store
        .store_virtual_key(&record)
        .map_err(|e| rpc_err(ERR_INTERNAL, format!("Failed to store rotated key: {e}")))?;

    tracing::info!(
        caller_ip = %caller.ip,
        old_key_id = %key_id,
        new_key_id = %new_id,
        "Virtual key rotated"
    );

    Ok(serde_json::json!({
        "old_key_id": key_id,
        "new_key_id": new_id.to_string(),
        "name": name,
        "prefix": prefix,
        "new_secret": full_key,
        "message": "Store this secret securely — it cannot be retrieved later."
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_info_serialization() {
        let info = KeyInfo {
            id: "550e8400-e29b-41d4-a716-446655440000".into(),
            name: "test key".into(),
            prefix: "grob_abc1234".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            revoked: false,
        };
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["name"], "test key");
        assert_eq!(json["revoked"], false);
    }

    #[test]
    fn key_info_revoked_state() {
        let info = KeyInfo {
            id: "test-id".into(),
            name: "old key".into(),
            prefix: "grob_old1234".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            revoked: true,
        };
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["revoked"], true);
    }

    #[test]
    fn key_info_roundtrip() {
        let info = KeyInfo {
            id: "test".into(),
            name: "roundtrip".into(),
            prefix: "grob_rt12345".into(),
            created_at: "2026-04-12T00:00:00Z".into(),
            revoked: false,
        };
        let json_str = serde_json::to_string(&info).unwrap();
        let parsed: KeyInfo = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed.name, "roundtrip");
    }
}

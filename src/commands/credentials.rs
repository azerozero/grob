//! Provisions and revokes gateway authority without passing values through command arguments.

use crate::{
    cli::AppConfig,
    credentials::record::{Authority, Bundle, CredentialRecord},
    storage::GrobStore,
};

/// Selects an administrative credential operation on the local encrypted store.
#[derive(Debug, clap::Subcommand)]
pub enum CredentialAction {
    /// Reads a complete token or username/password JSON bundle from stdin.
    Local {
        /// Configured service identifier.
        service: String,
        /// Optional credential expiry as a Unix timestamp.
        #[arg(long)]
        expires_at: Option<i64>,
    },
    /// Explicitly selects Vault authority and clears an earlier local override or revocation.
    Vault {
        /// Configured service identifier.
        service: String,
    },
    /// Revokes both local and remote authority until explicit provisioning.
    Revoke {
        /// Configured service identifier.
        service: String,
    },
    /// Shows source and validity metadata, never credential values.
    Status {
        /// Configured service identifier.
        service: String,
    },
    /// Checks policy, key custody, expiry and source readiness without making upstream calls.
    Check {
        /// Configured service identifier.
        service: String,
    },
}

/// Applies an explicit local administrative operation to a configured service.
///
/// # Errors
/// Rejects unknown bindings, invalid bundles, expired publications and storage failures.
pub fn run(config: &AppConfig, action: CredentialAction) -> anyhow::Result<()> {
    use std::io::Read;
    let service = match &action {
        CredentialAction::Local { service, .. }
        | CredentialAction::Vault { service }
        | CredentialAction::Revoke { service }
        | CredentialAction::Status { service }
        | CredentialAction::Check { service } => service,
    };
    let binding = config
        .credential_services
        .iter()
        .find(|b| &b.id == service)
        .ok_or_else(|| anyhow::anyhow!("unknown credential service"))?;
    binding.validate()?;
    let store = GrobStore::open(&GrobStore::default_path())?;
    match action {
        CredentialAction::Local { expires_at, .. } => {
            anyhow::ensure!(
                expires_at.is_none_or(|e| e > crate::credentials::now()),
                "credential already expired"
            );
            let mut clear = zeroize::Zeroizing::new(Vec::new());
            std::io::stdin()
                .lock()
                .take(16385)
                .read_to_end(&mut clear)?;
            anyhow::ensure!(clear.len() <= 16384, "credential bundle too large");
            let bundle: Bundle = serde_json::from_slice(&clear)
                .map_err(|_| anyhow::anyhow!("invalid credential bundle JSON"))?;
            bundle.validate(&binding.injection)?;
            store.credential_set_local(binding, bundle, expires_at)?;
            println!("Local authority published; new requests use this version.");
        }
        CredentialAction::Vault { .. } => {
            anyhow::ensure!(
                binding.vault.is_some(),
                "Vault is not configured for this service"
            );
            store.credential_publish(
                CredentialRecord::provision(binding, Authority::Vault, None, None),
                None,
            )?;
            println!("Vault authority selected; dispatch requires successful validation.");
        }
        CredentialAction::Revoke { .. } => {
            store.credential_revoke(&binding.tenant, &binding.id)?;
            println!("Credential binding revoked.");
        }
        CredentialAction::Status { .. } => {
            let record = store.credential_read(&binding.tenant, &binding.id)?;
            println!(
                "{}",
                serde_json::json!({"service": binding.id, "authority": record.authority, "generation": record.generation, "revoked": record.revoked, "verified_at": record.verified_at, "expires_at": record.effective_expiry(), "recovery": record.recovery, "policy_current": record.policy == binding.revision()})
            );
        }
        CredentialAction::Check { .. } => {
            let report = diagnose(&store, binding);
            println!("{report}");
            anyhow::ensure!(
                report["ready"] == true,
                "credential service is not ready; see diagnostic metadata"
            );
        }
    }
    Ok(())
}

fn diagnose(
    store: &GrobStore,
    binding: &crate::credentials::config::ServiceBinding,
) -> serde_json::Value {
    let mut warnings = Vec::new();
    if !store.uses_external_encryption_key() {
        warnings.push("storage_key_colocated_with_data");
    } else if store.path().join("encryption.key").exists() {
        warnings.push("local_key_copy_still_present");
    }
    let record = store.credential_read(&binding.tenant, &binding.id);
    let transport = crate::credentials::broker::Broker::new(binding).is_ok();
    let mut ready = false;
    let mut state = "unavailable";
    if let Ok(record) = &record {
        state = record.state(binding, crate::credentials::now());
        if record.effective_expiry().is_none() && binding.expires_at.is_none() {
            warnings.push("credential_has_no_expiry");
        }
        if record.format == 1 && record.authority == Authority::Vault && record.expires_at.is_some()
        {
            warnings.push("legacy_expiry_requires_review");
        }
        let valid = record.check(binding, crate::credentials::now()).is_ok();
        ready = valid
            && match record.authority {
                Authority::Local => record
                    .bundle
                    .as_ref()
                    .is_some_and(|b| b.validate(&binding.injection).is_ok()),
                Authority::Vault => binding.vault.as_ref().is_some_and(|v| {
                    warnings.push("remote_authority_not_probed");
                    if let Some(socket) = &v.proxy_socket {
                        warnings.push("companion_secret_cache_must_be_disabled");
                        crate::credentials::transport::check_proxy_socket(socket).is_ok()
                    } else {
                        crate::shared::secret_file::read(&v.token_file, 16384).is_ok_and(|bytes| {
                            crate::credentials::broker::vault_token_header(&bytes).is_ok()
                        })
                    }
                }),
            };
    }
    serde_json::json!({"service": binding.id, "ready": ready && transport, "state": state,
        "external_storage_key": store.uses_external_encryption_key(), "warnings": warnings})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn diagnostic_reports_lifecycle_without_values() {
        let dir = tempfile::tempdir().unwrap();
        let store = GrobStore::open(&dir.path().join("grob.db")).unwrap();
        let binding: crate::credentials::config::ServiceBinding = serde_json::from_value(serde_json::json!({
            "id":"test", "tenant":"test", "agents":["jwt:test"], "origin":"https://example.com",
            "allowed_ips":["203.0.113.1"], "paths":["/"], "methods":["GET"], "injection":{"type":"bearer"}
        })).unwrap();
        assert_eq!(diagnose(&store, &binding)["ready"], false);
        store
            .credential_set_local(
                &binding,
                Bundle {
                    token: "synthetic-private-token".into(),
                    username: String::new(),
                    password: String::new(),
                },
                None,
            )
            .unwrap();
        let report = diagnose(&store, &binding);
        assert_eq!(report["ready"], true);
        assert!(!report.to_string().contains("synthetic-private-token"));
        assert!(report["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w == "credential_has_no_expiry"));
        store
            .credential_revoke(&binding.tenant, &binding.id)
            .unwrap();
        assert_eq!(diagnose(&store, &binding)["ready"], false);
    }
}

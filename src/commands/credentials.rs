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
        | CredentialAction::Status { service } => service,
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
            store.credential_publish(
                CredentialRecord::provision(binding, Authority::Local, Some(bundle), expires_at),
                None,
            )?;
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
                serde_json::json!({"service": binding.id, "authority": record.authority, "generation": record.generation, "revoked": record.revoked, "verified_at": record.verified_at, "expires_at": record.expires_at, "recovery": record.recovery, "policy_current": record.policy == binding.revision()})
            );
        }
    }
    Ok(())
}

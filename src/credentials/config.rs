//! Administrator-owned service bindings; request data cannot select secret sources.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Binds an authenticated tenant and agents to an exact upstream service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceBinding {
    /// Stable service identifier used in `/v1/services/{id}/{path}`.
    pub id: String,
    /// Exact authenticated tenant identifier.
    pub tenant: String,
    /// Permitted identities: `key:<uuid>` or `jwt:<subject>`.
    pub agents: Vec<String>,
    /// Exact origin, including a nondefault port when applicable.
    pub origin: String,
    /// Pins connections to these addresses without DNS resolution; TLS still verifies the hostname.
    pub allowed_ips: Vec<IpAddr>,
    /// Exact, canonical paths, without query strings or wildcard matching.
    pub paths: Vec<String>,
    /// Permitted HTTP methods.
    pub methods: Vec<String>,
    /// Authentication representation injected into the outbound request.
    pub injection: Injection,
    /// Optional policy expiry, expressed as a Unix timestamp.
    pub expires_at: Option<i64>,
    /// Optional Vault configuration, unused while local authority is selected.
    pub vault: Option<VaultConfig>,
}

/// Selects the outbound authentication field.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Injection {
    /// Sets Authorization to Bearer plus the bundle's token.
    Bearer,
    /// Sets Authorization from one coherent username/password bundle.
    Basic,
    /// Sets one explicit API key header.
    Header {
        /// Header beginning with `x-`, excluding forwarding and framing controls.
        name: String,
    },
}

/// Reads a versioned KV secret using a separately managed Vault authentication token.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultConfig {
    /// Full KV v2 data endpoint, without query parameters.
    pub endpoint: String,
    /// Explicit network addresses permitted for Vault.
    pub allowed_ips: Vec<IpAddr>,
    /// Local token file, typically maintained by Vault Agent auto-auth; omitted for a Unix proxy.
    #[serde(default, skip_serializing_if = "empty_path")]
    pub token_file: std::path::PathBuf,
    /// Protected Unix socket of a same-user auto-auth proxy with secret caching disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_socket: Option<std::path::PathBuf>,
    /// Maximum time between successful authoritative reads, in seconds (1–300).
    pub refresh_secs: u64,
    /// Maximum offline age since verification; zero disables outage recovery.
    #[serde(default)]
    pub max_offline_secs: u64,
}

impl ServiceBinding {
    /// Validates the complete policy before publication or provisioning.
    ///
    /// # Errors
    /// Returns an error for ambiguous destinations, missing identities or unsafe fields.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.id.is_empty()
                && self.id.len() <= 80
                && self
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "invalid credential service id"
        );
        anyhow::ensure!(
            !self.tenant.is_empty() && !self.agents.is_empty(),
            "credential identities are required"
        );
        anyhow::ensure!(
            self.agents.iter().all(|a| a
                .strip_prefix("key:")
                .is_some_and(|v| uuid::Uuid::parse_str(v).is_ok())
                || a.strip_prefix("jwt:").is_some_and(|v| !v.is_empty())),
            "invalid credential agent identity"
        );
        let origin = super::transport::endpoint(&self.origin, &self.allowed_ips)
            .map_err(|_| anyhow::anyhow!("invalid service origin or addresses"))?;
        anyhow::ensure!(
            origin.path() == "/",
            "credential origin must not contain a path"
        );
        anyhow::ensure!(
            !self.paths.is_empty() && self.paths.iter().all(|p| canonical_path(p)),
            "credential paths must be exact canonical paths"
        );
        anyhow::ensure!(
            !self.methods.is_empty()
                && self.methods.iter().all(|m| matches!(
                    m.as_str(),
                    "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
                )),
            "invalid credential methods"
        );
        if let Injection::Header { name } = &self.injection {
            let name = name.to_ascii_lowercase();
            anyhow::ensure!(
                name.starts_with("x-")
                    && !name.starts_with("x-forwarded")
                    && !matches!(
                        name.as_str(),
                        "x-original-url"
                            | "x-rewrite-url"
                            | "x-http-method-override"
                            | "x-method-override"
                    )
                    && reqwest::header::HeaderName::from_bytes(name.as_bytes()).is_ok(),
                "invalid credential injection header"
            );
        }
        if let Some(vault) = &self.vault {
            super::transport::endpoint(&vault.endpoint, &vault.allowed_ips)
                .map_err(|_| anyhow::anyhow!("invalid Vault endpoint or addresses"))?;
            anyhow::ensure!(
                (1..=300).contains(&vault.refresh_secs) && vault.max_offline_secs <= 86400,
                "invalid Vault freshness bounds"
            );
            if let Some(socket) = &vault.proxy_socket {
                anyhow::ensure!(cfg!(unix), "Vault Unix proxy requires Unix");
                anyhow::ensure!(
                    socket.is_absolute() && vault.token_file.as_os_str().is_empty(),
                    "Vault proxy_socket must be absolute and cannot be combined with token_file"
                );
                let url = reqwest::Url::parse(&vault.endpoint)?;
                anyhow::ensure!(url.scheme() == "http" && url.host_str() == Some("localhost") && vault.allowed_ips.iter().all(|ip| ip.is_loopback()), "Vault Unix proxy requires an http://localhost endpoint and loopback address pins");
            } else {
                anyhow::ensure!(
                    vault.token_file.is_absolute(),
                    "Vault token_file must be absolute"
                );
            }
        }
        Ok(())
    }

    /// Returns an identity for all authorizing configuration, excluding secret material.
    pub fn revision(&self) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(
            serde_json::to_vec(self).expect("serializable binding"),
        ))
    }
}

pub(crate) fn canonical_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.contains("//")
        && !path.split('/').any(|s| matches!(s, "." | ".."))
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/-_.~".contains(&b))
}

fn empty_path(path: &std::path::Path) -> bool {
    path.as_os_str().is_empty()
}

use super::config::{DomainMatchMode, SignedConfigSettings};
use super::hot_config::{DomainMatcher, SharedHotConfig};
use anyhow::{Context, Result};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use regex::Regex;
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// The TOML format for signed config files.
#[derive(Debug, Deserialize)]
struct SignedConfigFile {
    /// Optional embedded signature (hex-encoded DER).
    #[serde(default)]
    signature: Option<String>,

    #[serde(default)]
    url_exfil: Option<UrlExfilOverrides>,

    #[serde(default)]
    prompt_injection: Option<InjectionOverrides>,
}

#[derive(Debug, Deserialize)]
struct UrlExfilOverrides {
    #[serde(default)]
    whitelist_domains: Vec<String>,
    #[serde(default)]
    blacklist_domains: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct InjectionOverrides {
    #[serde(default)]
    custom_patterns: Vec<String>,
}

/// Load a public key from a PEM file or raw SEC1 bytes.
pub fn load_public_key(path: &str) -> Result<VerifyingKey> {
    let data =
        std::fs::read(path).with_context(|| format!("Failed to read public key: {}", path))?;

    // Try PEM first
    let pem_str = String::from_utf8_lossy(&data);
    if pem_str.contains("BEGIN PUBLIC KEY") || pem_str.contains("BEGIN EC PUBLIC KEY") {
        // Extract base64 content between headers
        let b64: String = pem_str
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("");
        let der = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &b64)
            .context("Failed to decode PEM base64")?;
        VerifyingKey::from_sec1_bytes(&der)
            .or_else(|_| {
                // Try SubjectPublicKeyInfo DER
                use p256::pkcs8::DecodePublicKey;
                VerifyingKey::from_public_key_der(&der)
            })
            .map_err(|e| anyhow::anyhow!("Invalid P-256 public key: {}", e))
    } else {
        // Raw SEC1 bytes
        VerifyingKey::from_sec1_bytes(&data)
            .map_err(|e| anyhow::anyhow!("Invalid raw P-256 public key: {}", e))
    }
}

/// Verify an ECDSA P-256 signature over content.
fn verify_signature(public_key: &VerifyingKey, content: &[u8], signature_hex: &str) -> Result<()> {
    let sig_bytes = hex::decode(signature_hex).context("Failed to decode signature hex")?;
    let signature = Signature::from_der(&sig_bytes).context("Invalid DER signature format")?;
    public_key
        .verify(content, &signature)
        .map_err(|e| anyhow::anyhow!("Signature verification failed: {}", e))
}

/// Verify a detached signature file.
fn verify_detached_signature(
    public_key: &VerifyingKey,
    content: &[u8],
    sig_path: &str,
) -> Result<()> {
    let sig_hex = std::fs::read_to_string(sig_path)
        .with_context(|| format!("Failed to read detached signature: {}", sig_path))?;
    verify_signature(public_key, content, sig_hex.trim())
}

/// Fetch config content from a file path or URL.
async fn fetch_content(source: &str) -> Result<Vec<u8>> {
    if source.starts_with("http://") || source.starts_with("https://") {
        let resp = reqwest::get(source)
            .await
            .with_context(|| format!("Failed to fetch config from URL: {}", source))?;
        let status = resp.status();
        if !status.is_success() {
            anyhow::bail!("HTTP {} fetching {}", status, source);
        }
        Ok(resp.bytes().await?.to_vec())
    } else {
        // File path (expand ~)
        let path = if source.starts_with('~') {
            let home = dirs::home_dir().context("Failed to get home directory")?;
            home.join(source.trim_start_matches("~/"))
        } else {
            std::path::PathBuf::from(source)
        };
        std::fs::read(&path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))
    }
}

/// Parse and apply a signed config to the hot config.
fn apply_config(
    content: &[u8],
    domain_mode: &DomainMatchMode,
    hot_config: &SharedHotConfig,
) -> Result<()> {
    let text = std::str::from_utf8(content).context("Config is not valid UTF-8")?;
    let parsed: SignedConfigFile =
        toml::from_str(text).context("Failed to parse signed config TOML")?;

    let mut new_whitelist = Vec::new();
    let mut new_blacklist = Vec::new();
    let mut new_injection_patterns = Vec::new();

    if let Some(ref url_exfil) = parsed.url_exfil {
        new_whitelist = url_exfil
            .whitelist_domains
            .iter()
            .map(|d| DomainMatcher::new(d, domain_mode))
            .collect();
        new_blacklist = url_exfil
            .blacklist_domains
            .iter()
            .map(|d| DomainMatcher::new(d, domain_mode))
            .collect();
    }

    if let Some(ref injection) = parsed.prompt_injection {
        for pat in &injection.custom_patterns {
            match Regex::new(pat) {
                Ok(re) => new_injection_patterns.push(re),
                Err(e) => tracing::warn!("Invalid hot-loaded injection pattern '{}': {}", pat, e),
            }
        }
    }

    // Write-lock and swap
    let mut hot = hot_config.write().unwrap();
    hot.url_whitelist = new_whitelist;
    hot.url_blacklist = new_blacklist;
    hot.injection_custom_patterns = new_injection_patterns;
    hot.last_loaded = chrono::Utc::now();

    Ok(())
}

/// Spawn the background hot-reload loop.
pub fn spawn_hot_reload(
    settings: SignedConfigSettings,
    hot_config: SharedHotConfig,
    domain_mode: DomainMatchMode,
    public_key: Option<VerifyingKey>,
) {
    let interval_secs = match crate::preset::parse_interval(&settings.poll_interval) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                "Invalid signed_config poll_interval '{}': {}",
                settings.poll_interval,
                e
            );
            return;
        }
    };

    tracing::info!(
        "DLP signed config hot-reload: every {} ({}s) from {}",
        settings.poll_interval,
        interval_secs,
        settings.source,
    );

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;

            match reload_once(&settings, &hot_config, &domain_mode, public_key.as_ref()).await {
                Ok(ReloadStatus::Updated) => {
                    tracing::info!("DLP hot config updated from {}", settings.source);
                    metrics::counter!(
                        "grob_dlp_hot_reload_total",
                        "status" => "success"
                    )
                    .increment(1);
                }
                Ok(ReloadStatus::Unchanged) => {
                    metrics::counter!(
                        "grob_dlp_hot_reload_total",
                        "status" => "unchanged"
                    )
                    .increment(1);
                }
                Err(e) => {
                    tracing::error!("DLP hot config reload failed: {}", e);
                    metrics::counter!(
                        "grob_dlp_hot_reload_total",
                        "status" => "failed"
                    )
                    .increment(1);
                }
            }
        }
    });
}

enum ReloadStatus {
    Updated,
    Unchanged,
}

async fn reload_once(
    settings: &SignedConfigSettings,
    hot_config: &SharedHotConfig,
    domain_mode: &DomainMatchMode,
    public_key: Option<&VerifyingKey>,
) -> Result<ReloadStatus> {
    let content = fetch_content(&settings.source).await?;

    // Verify signature if required
    if settings.verify_signature {
        let pk = public_key.context("Signature verification enabled but no public key loaded")?;

        // Try embedded signature first
        let text = std::str::from_utf8(&content)?;
        let parsed: SignedConfigFile = toml::from_str(text)?;

        if let Some(ref embedded_sig) = parsed.signature {
            // For embedded sig: verify content without the signature field
            // Re-serialize without signature for canonical form
            let mut canonical: toml::Value = toml::from_str(text)?;
            if let Some(table) = canonical.as_table_mut() {
                table.remove("signature");
            }
            let canonical_bytes = toml::to_string(&canonical)?.into_bytes();
            verify_signature(pk, &canonical_bytes, embedded_sig).inspect_err(|_| {
                metrics::counter!(
                    "grob_dlp_hot_reload_total",
                    "status" => "sig_failed"
                )
                .increment(1);
            })?;
        } else {
            // Try detached signature
            let sig_path = format!("{}{}", settings.source, settings.detached_sig_suffix);
            verify_detached_signature(pk, &content, &sig_path).inspect_err(|_| {
                metrics::counter!(
                    "grob_dlp_hot_reload_total",
                    "status" => "sig_failed"
                )
                .increment(1);
            })?;
        }

        metrics::counter!("grob_dlp_signature_verified_total", "result" => "valid").increment(1);
    }

    // Hash check — skip if unchanged
    let hash = format!("{:x}", Sha256::digest(&content));
    {
        let current = hot_config.read().unwrap();
        if current.source_hash == hash {
            return Ok(ReloadStatus::Unchanged);
        }
    }

    // Log old → new hash on change
    {
        let current = hot_config.read().unwrap();
        tracing::info!(
            old_hash = %current.source_hash,
            new_hash = %hash,
            source = %settings.source,
            "DLP signed config changed"
        );
    }

    // Apply new config
    apply_config(&content, domain_mode, hot_config)?;

    // Update hash and expose as gauge label for observability
    {
        let mut hot = hot_config.write().unwrap();
        hot.source_hash = hash.clone();
    }
    metrics::gauge!("grob_dlp_config_hash_info", "hash" => hash[..16].to_string()).set(1.0);

    Ok(ReloadStatus::Updated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::dlp::hot_config;

    #[test]
    fn test_apply_config_updates_hot_config() {
        let hot = hot_config::build_initial_hot_config(&[], &[], &DomainMatchMode::Suffix, &[]);
        let toml_content = br#"
[url_exfil]
whitelist_domains = ["github.com", "docs.rs"]
blacklist_domains = ["evil.com"]

[prompt_injection]
custom_patterns = ["(?i)corporate\\s+override"]
"#;

        apply_config(toml_content, &DomainMatchMode::Suffix, &hot).unwrap();

        let h = hot.read().unwrap();
        assert_eq!(h.url_whitelist.len(), 2);
        assert_eq!(h.url_blacklist.len(), 1);
        assert_eq!(h.injection_custom_patterns.len(), 1);
        assert!(h.url_whitelist[0].matches("github.com"));
        assert!(h.url_blacklist[0].matches("evil.com"));
    }

    #[test]
    fn test_apply_config_invalid_regex_skipped() {
        let hot = hot_config::build_initial_hot_config(&[], &[], &DomainMatchMode::Suffix, &[]);
        let toml_content = br#"
[prompt_injection]
custom_patterns = ["(?i)valid", "[invalid"]
"#;

        apply_config(toml_content, &DomainMatchMode::Suffix, &hot).unwrap();

        let h = hot.read().unwrap();
        // Only the valid pattern should be loaded
        assert_eq!(h.injection_custom_patterns.len(), 1);
    }

    #[test]
    fn test_signature_verification() {
        use p256::ecdsa::{signature::Signer, SigningKey};

        // Generate a test keypair
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let verifying_key = *signing_key.verifying_key();

        let content = b"test content for signing";
        let signature: Signature = signing_key.sign(content);
        let sig_hex = hex::encode(signature.to_der());

        // Valid signature should pass
        assert!(verify_signature(&verifying_key, content, &sig_hex).is_ok());

        // Tampered content should fail
        assert!(verify_signature(&verifying_key, b"tampered content", &sig_hex).is_err());

        // Wrong key should fail
        let wrong_key = SigningKey::random(&mut rand::thread_rng());
        let wrong_vk = *wrong_key.verifying_key();
        assert!(verify_signature(&wrong_vk, content, &sig_hex).is_err());
    }
}

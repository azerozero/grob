use super::common::is_grob_healthy;
use crate::{cli, storage};

pub async fn cmd_doctor(config: &cli::AppConfig, config_source: &cli::ConfigSource) {
    println!("🩺 Grob Doctor — Diagnostic Checks");
    println!("   Version: {}", env!("CARGO_PKG_VERSION"));
    println!();

    let mut issues = 0u32;

    // 1. Config file
    match config_source {
        cli::ConfigSource::File(p) => {
            if p.exists() {
                println!("  ✅ Config file: {}", p.display());
            } else {
                println!("  ❌ Config file not found: {}", p.display());
                issues += 1;
            }
        }
        cli::ConfigSource::Url(u) => {
            println!("  ℹ️  Config from URL: {}", u);
        }
    }

    // 2. Config version
    if let Some(ref v) = config.version {
        println!("  ✅ Config version: {}", v);
    } else {
        println!("  ℹ️  Config version: not set (optional)");
    }

    // 3. Providers with credentials
    let enabled_providers: Vec<_> = config.providers.iter().filter(|p| p.is_enabled()).collect();
    let total = enabled_providers.len();
    let with_keys = enabled_providers
        .iter()
        .filter(|p| p.api_key.is_some() || p.oauth_provider.is_some())
        .count();
    if total == 0 {
        println!("  ❌ No providers configured");
        issues += 1;
    } else if with_keys < total {
        println!("  ⚠️  Providers: {}/{} have credentials", with_keys, total);
        issues += 1;
    } else {
        println!(
            "  ✅ Providers: {}/{} configured with credentials",
            with_keys, total
        );
    }

    // 4. Models
    let model_count = config.models.len();
    if model_count == 0 {
        println!("  ❌ No models configured");
        issues += 1;
    } else {
        println!("  ✅ Models: {} configured", model_count);
    }

    // 5. Service running
    let base_url = cli::format_base_url(&config.server.host, config.server.port);
    if is_grob_healthy(&base_url).await {
        println!("  ✅ Service: running on {}", base_url);
    } else {
        println!("  ℹ️  Service: not running (start with `grob start -d`)");
    }

    // 6. Port availability
    if !is_grob_healthy(&base_url).await {
        let addr = cli::format_bind_addr(&config.server.host, config.server.port);
        match std::net::TcpListener::bind(&addr) {
            Ok(_) => println!("  ✅ Port {}: available", config.server.port),
            Err(_) => {
                println!(
                    "  ❌ Port {}: in use by another process",
                    config.server.port
                );
                issues += 1;
            }
        }
    }

    // 7. DLP
    if config.dlp.enabled {
        println!("  ✅ DLP: enabled");
    } else {
        println!("  ℹ️  DLP: disabled");
    }

    // 8. Security
    if config.security.enabled {
        println!(
            "  ✅ Security: enabled (rate_limit={}rps, circuit_breaker={})",
            config.security.rate_limit_rps, config.security.circuit_breaker
        );
    } else {
        println!("  ℹ️  Security: disabled");
    }

    // 9. Storage
    match storage::GrobStore::open(&storage::GrobStore::default_path()) {
        Ok(_) => println!("  ✅ Storage (redb): accessible"),
        Err(e) => {
            println!("  ❌ Storage (redb): {}", e);
            issues += 1;
        }
    }

    // 10. Missing env vars
    let mut missing_env = Vec::new();
    for provider in &config.providers {
        if !provider.is_enabled() {
            continue;
        }
        if let Some(ref key) = provider.api_key {
            if let Some(var) = key.strip_prefix('$') {
                if std::env::var(var).is_err() {
                    missing_env.push(format!("${} ({})", var, provider.name));
                }
            }
        }
    }
    if missing_env.is_empty() {
        println!("  ✅ Environment variables: all set");
    } else {
        println!("  ❌ Missing env vars: {}", missing_env.join(", "));
        issues += 1;
    }

    // 11. Podman
    match std::process::Command::new("podman")
        .arg("--version")
        .output()
    {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout);
            println!("  ✅ Podman: {}", version.trim());
        }
        _ => {
            println!("  ℹ️  Podman: not found (optional, for container deployment)");
        }
    }

    println!();
    if issues == 0 {
        println!("  🎉 All checks passed!");
    } else {
        println!("  ⚠️  {} issue(s) found", issues);
    }
}

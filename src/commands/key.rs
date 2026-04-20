//! Virtual API key management commands (create, list, revoke).

use crate::auth::virtual_keys::{generate_key, VirtualKeyRecord};
use crate::cli;
use crate::storage::GrobStore;
use chrono::{Duration, Utc};
use uuid::Uuid;

/// Returns the RPC base URL if the server is running, `None` otherwise.
async fn live_base_url(config: &cli::AppConfig) -> Option<String> {
    let host = &config.server.host;
    let port = config.server.port.value();
    if crate::shared::instance::is_instance_running(host, port).await {
        Some(cli::format_base_url(host, port))
    } else {
        None
    }
}

/// Creates a new virtual API key via RPC or local store.
pub async fn cmd_key_create(
    config: &cli::AppConfig,
    name: &str,
    tenant: &str,
    budget: Option<f64>,
    rate_limit: Option<u32>,
    allowed_models: Option<Vec<String>>,
    expires_in_days: Option<u64>,
) {
    if let Some(base_url) = live_base_url(config).await {
        create_via_rpc(&base_url, name).await;
    } else {
        create_local(
            name,
            tenant,
            budget,
            rate_limit,
            allowed_models,
            expires_in_days,
        );
    }
}

/// Lists all virtual API keys via RPC or local store.
pub async fn cmd_key_list(config: &cli::AppConfig, json: bool) {
    if let Some(base_url) = live_base_url(config).await {
        list_via_rpc(&base_url, json).await;
    } else {
        list_local(json);
    }
}

/// Revokes a virtual key via RPC or local store.
pub async fn cmd_key_revoke(config: &cli::AppConfig, id_or_prefix: &str) {
    if let Some(base_url) = live_base_url(config).await {
        revoke_via_rpc(&base_url, id_or_prefix).await;
    } else {
        revoke_local(id_or_prefix);
    }
}

// ── RPC path ──

async fn create_via_rpc(base_url: &str, name: &str) {
    use super::rpc_client::rpc_call;

    let params = serde_json::json!({ "name": name });
    match rpc_call(base_url, "grob/keys/create", Some(params)).await {
        Ok(result) => {
            println!("Virtual key created successfully.\n");
            if let Some(id) = result["key_id"].as_str() {
                println!("  ID:       {}", id);
            }
            if let Some(n) = result["name"].as_str() {
                println!("  Name:     {}", n);
            }
            if let Some(p) = result["prefix"].as_str() {
                println!("  Prefix:   {}", p);
            }
            if let Some(s) = result["secret"].as_str() {
                println!("\n  Key: {}\n", s);
                println!("  Save this key now -- it will not be shown again.");
            }
        }
        Err(e) => {
            eprintln!("Failed to create key via RPC: {e}");
            std::process::exit(1);
        }
    }
}

async fn list_via_rpc(base_url: &str, json: bool) {
    use super::rpc_client::rpc_call;

    match rpc_call(base_url, "grob/keys/list", None).await {
        Ok(result) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&result).unwrap_or_default()
                );
                return;
            }

            let keys = match result.as_array() {
                Some(arr) => arr,
                None => {
                    println!("No virtual keys found.");
                    return;
                }
            };

            if keys.is_empty() {
                println!("No virtual keys found.");
                return;
            }

            println!(
                "{:<36}  {:<16}  {:<14}  {:<8}  CREATED",
                "ID", "NAME", "PREFIX", "REVOKED"
            );
            println!("{}", "-".repeat(90));

            for k in keys {
                println!(
                    "{:<36}  {:<16}  {:<14}  {:<8}  {}",
                    k["id"].as_str().unwrap_or("?"),
                    truncate(k["name"].as_str().unwrap_or("?"), 16),
                    k["prefix"].as_str().unwrap_or("?"),
                    if k["revoked"].as_bool().unwrap_or(false) {
                        "yes"
                    } else {
                        "no"
                    },
                    k["created_at"].as_str().unwrap_or("?"),
                );
            }

            println!("\n{} key(s) total.", keys.len());
        }
        Err(e) => {
            eprintln!("Failed to list keys via RPC: {e}");
            std::process::exit(1);
        }
    }
}

async fn revoke_via_rpc(base_url: &str, id_or_prefix: &str) {
    use super::rpc_client::rpc_call;

    let params = serde_json::json!({ "key_id": id_or_prefix });
    match rpc_call(base_url, "grob/keys/revoke", Some(params)).await {
        Ok(result) => {
            let msg = result["message"].as_str().unwrap_or("Key revoked");
            println!("{msg}");
        }
        Err(e) => {
            eprintln!("Failed to revoke key via RPC: {e}");
            std::process::exit(1);
        }
    }
}

// ── Local path (server not running) ──

fn create_local(
    name: &str,
    tenant: &str,
    budget: Option<f64>,
    rate_limit: Option<u32>,
    allowed_models: Option<Vec<String>>,
    expires_in_days: Option<u64>,
) {
    let store = match GrobStore::open(&GrobStore::default_path()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to open storage: {e}");
            std::process::exit(1);
        }
    };

    let (full_key, key_hash) = generate_key();
    let prefix = full_key[..12].to_string();
    let now = Utc::now();

    let expires_at = expires_in_days.map(|days| now + Duration::days(days as i64));

    let record = VirtualKeyRecord {
        id: Uuid::new_v4(),
        name: name.to_string(),
        prefix: prefix.clone(),
        key_hash,
        tenant_id: tenant.to_string(),
        budget_usd: budget,
        rate_limit_rps: rate_limit,
        allowed_models,
        created_at: now,
        expires_at,
        revoked: false,
        last_used_at: None,
    };

    if let Err(e) = store.store_virtual_key(&record) {
        eprintln!("Failed to store virtual key: {e}");
        std::process::exit(1);
    }

    println!("Virtual key created successfully.\n");
    println!("  ID:       {}", record.id);
    println!("  Name:     {name}");
    println!("  Tenant:   {tenant}");
    println!("  Prefix:   {prefix}");
    if let Some(b) = budget {
        println!("  Budget:   ${b:.2}/month");
    }
    if let Some(r) = rate_limit {
        println!("  Rate:     {r} req/s");
    }
    if let Some(exp) = expires_at {
        println!("  Expires:  {}", exp.format("%Y-%m-%d %H:%M UTC"));
    }
    println!();
    println!("  Key: {full_key}");
    println!();
    println!("  Save this key now -- it will not be shown again.");
}

fn list_local(json: bool) {
    let store = match GrobStore::open(&GrobStore::default_path()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to open storage: {e}");
            std::process::exit(1);
        }
    };

    let keys = store.list_virtual_keys();

    if json {
        match serde_json::to_string_pretty(&keys) {
            Ok(output) => println!("{output}"),
            Err(e) => {
                eprintln!("Failed to serialize keys: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    if keys.is_empty() {
        println!("No virtual keys found.");
        return;
    }

    println!(
        "{:<36}  {:<16}  {:<14}  {:<10}  {:<8}  CREATED",
        "ID", "NAME", "PREFIX", "TENANT", "REVOKED"
    );
    println!("{}", "-".repeat(110));

    for k in &keys {
        println!(
            "{:<36}  {:<16}  {:<14}  {:<10}  {:<8}  {}",
            k.id,
            truncate(&k.name, 16),
            k.prefix,
            truncate(&k.tenant_id, 10),
            if k.revoked { "yes" } else { "no" },
            k.created_at.format("%Y-%m-%d"),
        );
    }

    println!("\n{} key(s) total.", keys.len());
}

fn revoke_local(id_or_prefix: &str) {
    let store = match GrobStore::open(&GrobStore::default_path()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to open storage: {e}");
            std::process::exit(1);
        }
    };

    if let Ok(uuid) = Uuid::parse_str(id_or_prefix) {
        match store.revoke_virtual_key(&uuid) {
            Ok(true) => {
                println!("Key {uuid} revoked.");
                return;
            }
            Ok(false) => {
                eprintln!("No key found with ID {uuid}.");
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("Failed to revoke key: {e}");
                std::process::exit(1);
            }
        }
    }

    let keys = store.list_virtual_keys();
    let matches: Vec<_> = keys
        .iter()
        .filter(|k| k.prefix.starts_with(id_or_prefix))
        .collect();

    match matches.len() {
        0 => {
            eprintln!("No key found matching '{id_or_prefix}'.");
            std::process::exit(1);
        }
        1 => {
            let key = &matches[0];
            match store.revoke_virtual_key(&key.id) {
                Ok(true) => println!("Key {} ({}) revoked.", key.id, key.prefix),
                Ok(false) => {
                    eprintln!("Key not found (race condition?).");
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("Failed to revoke key: {e}");
                    std::process::exit(1);
                }
            }
        }
        n => {
            eprintln!(
                "Prefix '{id_or_prefix}' matches {n} keys. Be more specific or use the full UUID:"
            );
            for k in &matches {
                eprintln!("  {} ({})", k.id, k.prefix);
            }
            std::process::exit(1);
        }
    }
}

/// Truncates a string to `max_len`, appending ".." if truncated.
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}..", &s[..max_len - 2])
    }
}

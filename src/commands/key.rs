//! Virtual API key management commands (create, list, revoke).

use crate::auth::virtual_keys::{generate_key, VirtualKeyRecord};
use crate::storage::GrobStore;
use chrono::{Duration, Utc};
use uuid::Uuid;

/// Creates a new virtual API key, stores it, and prints the full key once.
pub fn cmd_key_create(
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

/// Lists all virtual keys in table or JSON format.
pub fn cmd_key_list(json: bool) {
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

/// Revokes a virtual key by UUID or prefix match.
pub fn cmd_key_revoke(id_or_prefix: &str) {
    let store = match GrobStore::open(&GrobStore::default_path()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to open storage: {e}");
            std::process::exit(1);
        }
    };

    // Try UUID first.
    if let Ok(uuid) = Uuid::parse_str(id_or_prefix) {
        match store.revoke_virtual_key(&uuid) {
            Ok(true) => {
                // SAFETY: key ID (UUID) is a public identifier, not a secret.
                println!("Key {uuid} revoked.");
                return;
            }
            Ok(false) => {
                // SAFETY: key ID (UUID) is a public identifier, not a secret.
                eprintln!("No key found with ID {uuid}.");
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("Failed to revoke key: {e}");
                std::process::exit(1);
            }
        }
    }

    // Fall back to prefix match.
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

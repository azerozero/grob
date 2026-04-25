//! Manage upstream provider secrets stored encrypted in `~/.grob/secrets/`.
//!
//! Each secret is a single AES-256-GCM encrypted blob keyed by name.
//! Reuses the same `StorageCipher` as OAuth tokens and virtual keys —
//! the master key lives at `~/.grob/encryption.key` (chmod 600).
//!
//! Three modes for `[[providers]] api_key`:
//!
//! - `secret:<name>`     → looked up in this store at startup
//! - `$ENV_VAR`          → resolved from process env at startup
//! - `<plain string>`    → used as-is (least secure, accepted for dev)

use crate::storage::GrobStore;
use secrecy::ExposeSecret;
use std::io::{self, BufRead, Write};

/// Adds a secret. Reads the value from stdin (one line, trimmed).
///
/// Pipe to keep it out of shell history:
///
/// ```sh
/// printf '%s' "$MY_KEY" | grob secrets add minimax
/// ```
pub fn cmd_secrets_add(name: &str) {
    if name.is_empty() {
        eprintln!("error: secret name is required");
        std::process::exit(2);
    }
    let store = match open_store() {
        Some(s) => s,
        None => return,
    };

    print!("Enter value for '{name}' (one line, will be encrypted): ");
    let _ = io::stdout().flush();

    let mut value = String::new();
    if io::stdin().lock().read_line(&mut value).is_err() {
        eprintln!("error: failed to read value from stdin");
        std::process::exit(1);
    }
    let value = value.trim_end_matches(['\n', '\r']);
    if value.is_empty() {
        eprintln!("error: empty secret rejected");
        std::process::exit(2);
    }

    if let Err(e) = store.set_secret(name, value) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
    println!("✅ Secret '{name}' stored encrypted at ~/.grob/secrets/{name}.enc");
}

/// Lists all secret names. No values are displayed.
pub fn cmd_secrets_list(json: bool) {
    let store = match open_store() {
        Some(s) => s,
        None => return,
    };
    let names = store.list_secrets();

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&names).unwrap_or_else(|_| "[]".into())
        );
        return;
    }

    if names.is_empty() {
        println!("No secrets stored. Use `grob secrets add <name>` to create one.");
        return;
    }
    println!("Secrets ({} total):", names.len());
    for n in &names {
        println!("  • {n}");
    }
}

/// Shows a secret. Redacted by default; pass `--unsafe-show` to reveal.
pub fn cmd_secrets_show(name: &str, unsafe_show: bool) {
    let store = match open_store() {
        Some(s) => s,
        None => return,
    };
    let secret = match store.get_secret(name) {
        Some(s) => s,
        None => {
            eprintln!("error: secret '{name}' not found");
            std::process::exit(1);
        }
    };

    let value = secret.expose_secret();
    if unsafe_show {
        println!("{value}");
    } else {
        println!("{}", redact(value));
        eprintln!("(redacted; pass --unsafe-show to reveal)");
    }
}

/// Removes a secret.
pub fn cmd_secrets_rm(name: &str, force: bool) {
    let store = match open_store() {
        Some(s) => s,
        None => return,
    };

    if !force {
        eprint!("Remove secret '{name}'? [y/N] ");
        let _ = io::stderr().flush();
        let mut answer = String::new();
        if io::stdin().lock().read_line(&mut answer).is_err() {
            eprintln!("aborted");
            return;
        }
        if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
            eprintln!("aborted");
            return;
        }
    }

    match store.remove_secret(name) {
        Ok(true) => println!("✅ Removed '{name}'"),
        Ok(false) => {
            eprintln!("warn: '{name}' did not exist");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

/// Opens GrobStore at the default path. Prints + exits on failure.
fn open_store() -> Option<GrobStore> {
    match GrobStore::open(&GrobStore::default_path()) {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("error: failed to open storage: {e}");
            std::process::exit(1);
        }
    }
}

/// Redacts a secret for display (first 4 + last 4 chars).
fn redact(value: &str) -> String {
    if value.len() <= 12 {
        "***".to_string()
    } else {
        format!("{}...{}", &value[..4], &value[value.len() - 4..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_short_string() {
        assert_eq!(redact("short"), "***");
        assert_eq!(redact("twelvechars1"), "***");
    }

    #[test]
    fn redact_long_string() {
        assert_eq!(redact("sk-abcdefghijklmnopqr"), "sk-a...opqr");
    }
}

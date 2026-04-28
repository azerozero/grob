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

use crate::cli::AppConfig;
use crate::commands::credential_check::{check_api_key, CheckOutcome};
use crate::storage::GrobStore;
use secrecy::ExposeSecret;
use std::io::{self, BufRead, Write};
use std::time::Duration;

/// HTTP timeout for each provider probe in [`cmd_secrets_test`].
const TEST_TIMEOUT: Duration = Duration::from_secs(10);

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

/// Tests stored secrets by probing each referencing provider.
///
/// When `name` is `Some`, only that secret is tested; otherwise every
/// secret in the encrypted store is tested. For each secret, looks up
/// the provider(s) referencing it via `secret:<name>` in the loaded
/// config, then sends a single low-cost probe (typically `GET /v1/models`)
/// using a 10-second timeout per call.
///
/// Per-secret status mapping:
/// - `✓` HTTP 2xx — the key is valid right now.
/// - `✗` HTTP 401 / 403 — the key is invalid or revoked.
/// - `⚠` Network error, 5xx, unknown provider type, or no referencing
///   provider — the key may still be valid; treated as a warning.
///
/// Process exits with code 1 if any secret is `✗`, otherwise 0.
/// Secret values are never written to stdout, stderr, or the log.
pub async fn cmd_secrets_test(config: &AppConfig, name: Option<&str>, json: bool) {
    let store = match open_store() {
        Some(s) => s,
        None => return,
    };

    // Resolve the candidate name list. An explicit name is honoured even
    // if the secret is not currently stored (we still want a clear error).
    let names: Vec<String> = match name {
        Some(n) => vec![n.to_string()],
        None => {
            let all = store.list_secrets();
            if all.is_empty() {
                if json {
                    println!("[]");
                } else {
                    println!("No secrets stored. Use `grob secrets add <name>` to create one.");
                }
                return;
            }
            all
        }
    };

    let mut reports: Vec<TestReport> = Vec::with_capacity(names.len());
    for n in &names {
        reports.push(test_one_secret(config, &store, n).await);
    }

    if json {
        let arr = serde_json::Value::Array(
            reports
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "name": r.name,
                        "providers": r.providers,
                        "status": r.status_label(),
                        "detail": r.detail,
                    })
                })
                .collect(),
        );
        println!(
            "{}",
            serde_json::to_string_pretty(&arr).unwrap_or_else(|_| "[]".into())
        );
    } else {
        print_human_report(&reports);
    }

    let any_invalid = reports
        .iter()
        .any(|r| matches!(r.status, TestStatus::Invalid));
    if any_invalid {
        std::process::exit(1);
    }
}

/// Per-secret outcome aggregated from one or more provider probes.
#[derive(Debug, Clone)]
struct TestReport {
    name: String,
    providers: Vec<String>,
    status: TestStatus,
    detail: String,
}

impl TestReport {
    fn status_label(&self) -> &'static str {
        match self.status {
            TestStatus::Ok => "ok",
            TestStatus::Invalid => "invalid",
            TestStatus::Warn => "warn",
        }
    }
}

/// Aggregated per-secret status. Multiple-provider secrets resolve to the
/// strictest non-warn outcome (any Invalid wins, then Ok, then Warn).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestStatus {
    Ok,
    Invalid,
    Warn,
}

/// Probes one secret and returns a [`TestReport`].
async fn test_one_secret(config: &AppConfig, store: &GrobStore, name: &str) -> TestReport {
    if store.get_secret(name).is_none() {
        return TestReport {
            name: name.to_string(),
            providers: vec![],
            status: TestStatus::Warn,
            detail: "secret not found in store".into(),
        };
    }

    // Find every provider that references `secret:<name>`.
    let placeholder = format!("secret:{name}");
    let referencing: Vec<&crate::cli::ProviderConfig> = config
        .providers
        .iter()
        .filter(|p| {
            p.is_enabled()
                && p.api_key
                    .as_ref()
                    .map(|s| s.expose_secret() == placeholder.as_str())
                    .unwrap_or(false)
        })
        .collect();

    if referencing.is_empty() {
        return TestReport {
            name: name.to_string(),
            providers: vec![],
            status: TestStatus::Warn,
            detail: "no enabled provider references this secret".into(),
        };
    }

    // Resolve once to the cleartext key for probing — never logged.
    let key = match store.get_secret(name) {
        Some(s) => s,
        None => {
            return TestReport {
                name: name.to_string(),
                providers: referencing.iter().map(|p| p.name.clone()).collect(),
                status: TestStatus::Warn,
                detail: "secret disappeared during read".into(),
            };
        }
    };
    let key_value = key.expose_secret();

    let mut provider_names: Vec<String> = Vec::with_capacity(referencing.len());
    let mut details: Vec<String> = Vec::with_capacity(referencing.len());
    let mut any_ok = false;
    let mut any_invalid = false;

    for p in &referencing {
        provider_names.push(p.name.clone());
        let outcome = check_api_key(
            &p.provider_type,
            p.base_url.as_deref(),
            key_value,
            TEST_TIMEOUT,
        )
        .await;
        match outcome {
            CheckOutcome::Ok => {
                any_ok = true;
                details.push(format!("{}: ok", p.name));
            }
            CheckOutcome::Invalid { status } => {
                any_invalid = true;
                details.push(format!("{}: HTTP {status}", p.name));
            }
            CheckOutcome::Network { reason } => {
                details.push(format!("{}: {reason}", p.name));
            }
            CheckOutcome::Skipped { reason } => {
                details.push(format!("{}: {reason}", p.name));
            }
        }
    }

    // Aggregation precedence: Invalid > Ok > Warn. A bad key is bad even
    // if one provider fronting it returned 200 from cache; show the
    // problem prominently. Conversely, if any provider says 200 and
    // none say 401, accept it and downgrade network noise to a warn note.
    let status = if any_invalid {
        TestStatus::Invalid
    } else if any_ok {
        TestStatus::Ok
    } else {
        TestStatus::Warn
    };

    TestReport {
        name: name.to_string(),
        providers: provider_names,
        status,
        detail: details.join("; "),
    }
}

/// Prints the human-readable summary table for `secrets test`.
fn print_human_report(reports: &[TestReport]) {
    let mut ok = 0usize;
    let mut bad = 0usize;
    let mut warn = 0usize;
    println!("Testing {} secret(s)...", reports.len());
    println!();
    for r in reports {
        let (icon, label) = match r.status {
            TestStatus::Ok => {
                ok += 1;
                ("✓", "ok")
            }
            TestStatus::Invalid => {
                bad += 1;
                ("✗", "invalid")
            }
            TestStatus::Warn => {
                warn += 1;
                ("⚠", "warn")
            }
        };
        let providers = if r.providers.is_empty() {
            "-".to_string()
        } else {
            r.providers.join(",")
        };
        println!("  {icon} {:<24} [{label}] via {providers}", r.name);
        if !r.detail.is_empty() {
            println!("      {}", r.detail);
        }
    }
    println!();
    println!("Summary: {ok} ok, {bad} invalid, {warn} warn");
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

    #[test]
    fn test_status_label_matches_variant() {
        // Aggregation precedence is exercised end-to-end in test_one_secret;
        // here we just assert the JSON label mapping stays stable so
        // downstream scripts depending on `secrets test --json` don't break.
        let r = TestReport {
            name: "x".into(),
            providers: vec![],
            status: TestStatus::Ok,
            detail: String::new(),
        };
        assert_eq!(r.status_label(), "ok");
        let r = TestReport {
            status: TestStatus::Invalid,
            ..r
        };
        assert_eq!(r.status_label(), "invalid");
        let r = TestReport {
            status: TestStatus::Warn,
            ..r
        };
        assert_eq!(r.status_label(), "warn");
    }
}

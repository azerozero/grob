//! Low-level TTY input helpers for the setup wizard.
//!
//! Shared between all screens and the top-level orchestrator. Keeps
//! `mod.rs` focused on flow rather than stdin/stdout plumbing.

use std::io::{self, Write};

/// Reads one trimmed line from stdin, returning an empty string on EOF.
pub(in crate::commands::setup) fn read_line() -> String {
    let mut s = String::new();
    io::stdin().read_line(&mut s).ok();
    s.trim().to_string()
}

/// Prompts for a number in `1..=max`, looping until the input is valid.
pub(in crate::commands::setup) fn prompt_choice(max: usize) -> usize {
    loop {
        print!("  > ");
        io::stdout().flush().ok();
        if let Ok(n) = read_line().parse::<usize>() {
            if n >= 1 && n <= max {
                return n;
            }
        }
        println!("  Enter a number between 1 and {}", max);
    }
}

/// Prompts for a comma/space-separated list of 1-based indices or `all`.
///
/// Returns zero-based indices filtered to `0..max`.
pub(in crate::commands::setup) fn prompt_multi(max: usize) -> Vec<usize> {
    loop {
        print!("  > ");
        io::stdout().flush().ok();
        let input = read_line();
        if input.eq_ignore_ascii_case("all") {
            return (0..max).collect();
        }
        let v: Vec<usize> = input
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter_map(|s| s.trim().parse::<usize>().ok())
            .filter(|&n| n >= 1 && n <= max)
            .map(|n| n - 1)
            .collect();
        if !v.is_empty() {
            return v;
        }
        println!("  Enter numbers separated by commas (e.g. 1,3) or 'all'");
    }
}

/// Reads an API key and optionally validates it against the provider.
///
/// Returns `None` when the env var is already set (user defers to env), when
/// the user enters an empty key, or when validation fails and the user
/// declines to override.
pub(in crate::commands::setup) fn prompt_key_for_provider(
    env_var: &str,
    provider_name: Option<&str>,
) -> Option<String> {
    if std::env::var(env_var).is_ok() {
        println!("    ${} already set in environment", env_var);
        return None;
    }
    print!("    API key: ");
    io::stdout().flush().ok();
    let key = read_line();
    if key.is_empty() {
        println!("    Skipped");
        return None;
    }

    // Best-effort validation when the provider is known.
    if let Some(name) = provider_name {
        let rt = tokio::runtime::Handle::try_current();
        let valid = match rt {
            Ok(handle) => tokio::task::block_in_place(|| {
                handle.block_on(crate::commands::credential_check::validate_api_key(
                    name, &key,
                ))
            }),
            Err(_) => {
                // No runtime available — skip validation.
                true
            }
        };
        if !valid {
            println!(
                "    Warning: {} returned auth error. The key may be expired, revoked, or incorrect.",
                name
            );
            println!("    Check your key at the provider dashboard, or try a different one.");
            println!("    Continue anyway? [y/N]");
            if !confirm("    > ") {
                println!(
                    "    Key rejected. Run: grob connect {} (to retry later)",
                    name
                );
                return None;
            }
        }
    }

    println!("    Accepted (stored as ${} reference)", env_var);
    Some(key)
}

/// Prompts for a URL, requiring an `http://` or `https://` scheme.
pub(in crate::commands::setup) fn prompt_url(label: &str) -> String {
    loop {
        print!("    {}: ", label);
        io::stdout().flush().ok();
        let url = read_line();
        if url.starts_with("http://") || url.starts_with("https://") {
            return url;
        }
        println!("    URL must start with http:// or https://");
    }
}

/// Returns `true` when the user answers `y`/`yes` (case-insensitive).
pub(in crate::commands::setup) fn confirm(prompt: &str) -> bool {
    print!("{}", prompt);
    io::stdout().flush().ok();
    let a = read_line();
    a.eq_ignore_ascii_case("y") || a.eq_ignore_ascii_case("yes")
}

//! Screen 2: per-provider authentication choice (OAuth vs API key vs env).

use crate::commands::setup::detect::{auth_for, discover_credentials};
use crate::commands::setup::input::{prompt_choice, prompt_key_for_provider};
use crate::commands::setup::types::AuthOverride;

/// Env var opt-out: set `GROB_SETUP_NO_ENV_SKIP=1` to keep the legacy
/// interactive prompt when an env var is already present. Defaults to
/// the GH_TOKEN-style auto-skip: detected key wins silently.
fn env_skip_enabled() -> bool {
    !matches!(
        std::env::var("GROB_SETUP_NO_ENV_SKIP")
            .ok()
            .as_deref()
            .map(str::trim),
        Some("1") | Some("true") | Some("yes")
    )
}

/// Emits an `AuthOverride` that defers to the detected env var.
fn auto_accept_env(out: &mut Vec<AuthOverride>, name: &str, env_var: &str) {
    println!(
        "    ${} detected — using it (set GROB_SETUP_NO_ENV_SKIP=1 to override)",
        env_var
    );
    out.push(AuthOverride {
        provider: name.to_string(),
        use_oauth: false,
        oauth_id: String::new(),
        entered_key: None,
        env_var: env_var.to_string(),
    });
}

/// Prompts the user to pick an auth strategy for each provider.
pub(in crate::commands::setup) fn screen_auth(providers: &[String]) -> Vec<AuthOverride> {
    if providers.is_empty() {
        return vec![];
    }

    let discovered = discover_credentials();

    println!();
    println!("  Provider authentication:");
    if !discovered.is_empty() {
        println!();
        println!("  Detected credentials in environment:");
        for (name, var) in &discovered {
            println!("    {} (${} found)", name, var);
        }
    }
    println!();

    let mut out = Vec::new();
    for name in providers {
        let (supports_oauth, oauth_id, env_var) = match auth_for(name) {
            Some(v) => v,
            None => continue,
        };

        let env_present = discovered.iter().any(|(n, _)| *n == name.as_str());

        println!("  {}:", name);
        if env_present && supports_oauth {
            auth_env_with_oauth(&mut out, name, oauth_id, env_var);
        } else if env_present {
            auth_env_no_oauth(&mut out, name, env_var);
        } else if supports_oauth {
            auth_oauth_or_key(&mut out, name, oauth_id, env_var);
        } else {
            auth_key_only(&mut out, name, env_var);
        }
        println!();
    }
    out
}

/// Env var detected + OAuth available: 3 choices (or auto-skip in GH_TOKEN mode).
fn auth_env_with_oauth(out: &mut Vec<AuthOverride>, name: &str, oauth_id: &str, env_var: &str) {
    if env_skip_enabled() {
        auto_accept_env(out, name, env_var);
        return;
    }
    println!("    ${} detected in environment", env_var);
    println!("    [1] Use environment variable (recommended)");
    println!("    [2] OAuth (subscription)");
    println!("    [3] Enter a different API key");
    match prompt_choice(3) {
        1 => {
            out.push(AuthOverride {
                provider: name.to_string(),
                use_oauth: false,
                oauth_id: String::new(),
                entered_key: None,
                env_var: env_var.to_string(),
            });
            println!("    Using ${}", env_var);
        }
        2 => {
            out.push(AuthOverride {
                provider: name.to_string(),
                use_oauth: true,
                oauth_id: oauth_id.to_string(),
                entered_key: None,
                env_var: env_var.to_string(),
            });
            println!("    OAuth — will prompt on first `grob start`");
        }
        _ => {
            let key = prompt_key_for_provider(env_var, Some(name));
            out.push(AuthOverride {
                provider: name.to_string(),
                use_oauth: false,
                oauth_id: String::new(),
                entered_key: key,
                env_var: env_var.to_string(),
            });
        }
    }
}

/// Env var detected, no OAuth: use env or enter key (auto-skip in GH_TOKEN mode).
fn auth_env_no_oauth(out: &mut Vec<AuthOverride>, name: &str, env_var: &str) {
    if env_skip_enabled() {
        auto_accept_env(out, name, env_var);
        return;
    }
    println!("    ${} detected in environment", env_var);
    println!("    [1] Use environment variable (recommended)");
    println!("    [2] Enter a different API key");
    if prompt_choice(2) == 1 {
        out.push(AuthOverride {
            provider: name.to_string(),
            use_oauth: false,
            oauth_id: String::new(),
            entered_key: None,
            env_var: env_var.to_string(),
        });
        println!("    Using ${}", env_var);
    } else {
        let key = prompt_key_for_provider(env_var, Some(name));
        out.push(AuthOverride {
            provider: name.to_string(),
            use_oauth: false,
            oauth_id: String::new(),
            entered_key: key,
            env_var: env_var.to_string(),
        });
    }
}

/// No env var, OAuth available: OAuth or API key.
fn auth_oauth_or_key(out: &mut Vec<AuthOverride>, name: &str, oauth_id: &str, env_var: &str) {
    println!("    [1] OAuth (subscription, recommended)");
    println!("    [2] API key (${})", env_var);
    if prompt_choice(2) == 1 {
        out.push(AuthOverride {
            provider: name.to_string(),
            use_oauth: true,
            oauth_id: oauth_id.to_string(),
            entered_key: None,
            env_var: env_var.to_string(),
        });
        println!("    OAuth — will prompt on first `grob start`");
    } else {
        let key = prompt_key_for_provider(env_var, Some(name));
        out.push(AuthOverride {
            provider: name.to_string(),
            use_oauth: false,
            oauth_id: String::new(),
            entered_key: key,
            env_var: env_var.to_string(),
        });
    }
}

/// No env var, no OAuth: enter key or set later.
fn auth_key_only(out: &mut Vec<AuthOverride>, name: &str, env_var: &str) {
    println!("    [1] Enter API key now");
    println!(
        "    [2] Set ${} later. Run: export {}=<your-key>",
        env_var, env_var
    );
    if prompt_choice(2) == 1 {
        let key = prompt_key_for_provider(env_var, Some(name));
        out.push(AuthOverride {
            provider: name.to_string(),
            use_oauth: false,
            oauth_id: String::new(),
            entered_key: key,
            env_var: env_var.to_string(),
        });
    } else {
        println!(
            "    Set it before running grob: export {}=<your-key>",
            env_var
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guards the default GH_TOKEN-style skip behavior.
    #[test]
    fn env_skip_default_is_enabled() {
        std::env::remove_var("GROB_SETUP_NO_ENV_SKIP");
        assert!(env_skip_enabled());
    }

    /// `GROB_SETUP_NO_ENV_SKIP=1` must restore the legacy interactive prompt.
    #[test]
    fn env_skip_disabled_by_env_var() {
        std::env::set_var("GROB_SETUP_NO_ENV_SKIP", "1");
        assert!(!env_skip_enabled());
        std::env::remove_var("GROB_SETUP_NO_ENV_SKIP");
    }

    /// Values other than 1/true/yes are ignored.
    #[test]
    fn env_skip_ignores_garbage() {
        std::env::set_var("GROB_SETUP_NO_ENV_SKIP", "maybe");
        assert!(env_skip_enabled());
        std::env::remove_var("GROB_SETUP_NO_ENV_SKIP");
    }

    /// Auto-accept emits exactly one override pointing at the env var.
    #[test]
    fn auto_accept_produces_single_env_override() {
        let mut out = Vec::new();
        auto_accept_env(&mut out, "anthropic", "ANTHROPIC_API_KEY");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].provider, "anthropic");
        assert_eq!(out[0].env_var, "ANTHROPIC_API_KEY");
        assert!(!out[0].use_oauth);
        assert!(out[0].entered_key.is_none());
    }
}

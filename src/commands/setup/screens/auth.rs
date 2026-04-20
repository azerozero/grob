//! Screen 2: per-provider authentication choice (OAuth vs API key vs env).

use crate::commands::setup::detect::{auth_for, discover_credentials};
use crate::commands::setup::input::{prompt_choice, prompt_key_for_provider};
use crate::commands::setup::types::AuthOverride;

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

/// Env var detected + OAuth available: 3 choices.
fn auth_env_with_oauth(out: &mut Vec<AuthOverride>, name: &str, oauth_id: &str, env_var: &str) {
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

/// Env var detected, no OAuth: use env or enter key.
fn auth_env_no_oauth(out: &mut Vec<AuthOverride>, name: &str, env_var: &str) {
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

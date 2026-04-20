//! Screen 4: custom OpenAI-compatible or Anthropic-compatible endpoints.

use std::io::{self, Write};

use crate::commands::setup::input::{confirm, prompt_choice, prompt_url, read_line};
use crate::commands::setup::types::CustomEndpoint;

/// Prompts the user to add zero or more custom endpoints.
pub(in crate::commands::setup) fn screen_custom_endpoints() -> Vec<CustomEndpoint> {
    println!();
    println!("  Custom endpoints:");
    println!("    [1] Add a custom OpenAI-compatible endpoint");
    println!("    [2] Add a custom Anthropic-compatible endpoint");
    println!("    [3] Skip (no custom endpoints)");

    let mut endpoints = Vec::new();
    loop {
        let choice = prompt_choice(3);
        if choice == 3 {
            break;
        }

        let provider_type = if choice == 1 {
            "openai_compatible"
        } else {
            "anthropic_compatible"
        };

        print!("    Provider name (e.g. my-llm): ");
        io::stdout().flush().ok();
        let name = read_line();
        if name.is_empty() {
            println!("    Skipped");
            continue;
        }

        let base_url = prompt_url("Base URL (e.g. https://my-llm.company.com/v1)");
        let api_key = validate_custom_key(provider_type, &base_url);

        endpoints.push(CustomEndpoint {
            name,
            provider_type: provider_type.to_string(),
            base_url,
            api_key,
        });

        println!();
        println!("    Add another custom endpoint?");
        println!("    [1] Add OpenAI-compatible");
        println!("    [2] Add Anthropic-compatible");
        println!("    [3] Done");
    }
    endpoints
}

/// Reads an API key and best-effort validates it against the custom endpoint.
fn validate_custom_key(provider_type: &str, base_url: &str) -> Option<String> {
    print!("    API key: ");
    io::stdout().flush().ok();
    let key = read_line();
    if key.is_empty() {
        println!("    Skipped — set the key via env var before running grob");
        return None;
    }

    let rt = tokio::runtime::Handle::try_current();
    let valid = match rt {
        Ok(handle) => tokio::task::block_in_place(|| {
            handle.block_on(crate::commands::credential_check::validate_custom_endpoint(
                provider_type,
                base_url,
                &key,
            ))
        }),
        Err(_) => true,
    };
    if !valid {
        println!("    Warning: endpoint returned auth error. The key may be invalid.");
        println!("    Verify the base URL and API key, then retry. Continue anyway? [y/N]");
        if !confirm("    > ") {
            println!("    Key rejected. Set the correct key via env var before running grob.");
            return None;
        }
    }

    println!("    Accepted");
    Some(key)
}

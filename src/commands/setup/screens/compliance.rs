//! Screen 5: security & compliance posture (Standard / DLP / GDPR / Enterprise / Local).

use crate::commands::setup::input::{confirm, prompt_choice};
use crate::commands::setup::types::{Compliance, ToolInfo};

/// Prompts the user for a compliance profile.
pub(in crate::commands::setup) fn screen_compliance(tools: &[&ToolInfo]) -> Compliance {
    println!();
    println!("  Security & compliance:");
    println!("    [1] Standard (default — no restrictions)");
    println!("    [2] DLP (secret scanning + PII detection)");
    println!("    [3] EU/GDPR + EU AI Act (EU-only + DLP + transparency)");
    println!("    [4] Enterprise (audit + DLP + rate limiting + OWASP)");
    println!("    [5] Local-only (Ollama — zero data transfer)");

    let choice = prompt_choice(5);
    match choice {
        2 => Compliance::Dlp,
        3 => {
            let warnings = gdpr_warnings(tools);
            if !warnings.is_empty() {
                println!();
                println!("  GDPR compatibility notes:");
                for w in &warnings {
                    println!("    {}", w);
                }
                println!();
                if !confirm("  Continue anyway? [y/N] ") {
                    println!("    Falling back to Standard");
                    return Compliance::Standard;
                }
            }
            Compliance::EuGdpr
        }
        4 => Compliance::Enterprise,
        5 => Compliance::LocalOnly,
        _ => Compliance::Standard,
    }
}

/// Emits per-tool caveats the user should be aware of before picking GDPR.
fn gdpr_warnings(tools: &[&ToolInfo]) -> Vec<String> {
    tools
        .iter()
        .filter_map(|t| match t.name {
            "Claude Code" | "Forge" => Some(format!(
                "{}: Anthropic does not guarantee EU-only processing.",
                t.name
            )),
            "Codex CLI" => Some(format!(
                "{}: OpenAI EU residency — verify your project is set to EU region.",
                t.name
            )),
            _ => None,
        })
        .collect()
}

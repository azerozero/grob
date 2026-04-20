//! Screen 1: pick the coding tools that will route through grob.

use crate::commands::setup::input::prompt_multi;
use crate::commands::setup::types::{ToolInfo, TOOLS};

/// Prompts the user to select one or more tools.
///
/// Returns `None` when the user picks the "Custom setup" escape hatch or
/// when the selection yields no known tool (falls back to the manual path).
pub(in crate::commands::setup) fn screen_tools() -> Option<(Vec<usize>, String, String)> {
    println!("Which tools will you route through Grob?");
    println!("  (enter numbers separated by commas, e.g. 1,3)");
    println!();
    for (i, t) in TOOLS.iter().enumerate() {
        println!("  [{}] {:<16} {} {}", i + 1, t.name, t.tag, t.endpoint);
    }
    println!();
    println!("  [{}] Custom setup (manual)", TOOLS.len() + 1);
    println!();

    let sel = prompt_multi(TOOLS.len() + 1);
    if sel.contains(&TOOLS.len()) {
        return None;
    }

    let tools: Vec<&ToolInfo> = sel.iter().filter_map(|&i| TOOLS.get(i)).collect();
    if tools.is_empty() {
        return None;
    }

    let (preset, desc) = match (
        tools.iter().any(|t| t.needs_anthropic),
        tools.iter().any(|t| t.needs_openai),
    ) {
        (true, true) | (false, true) => ("fast", "Anthropic + OpenAI + Gemini + OpenRouter"),
        _ => ("perf", "Anthropic OAuth + OpenRouter fallback"),
    };

    let names: Vec<&str> = tools.iter().map(|t| t.name).collect();
    println!();
    println!("Setting up for {}...", names.join(" + "));
    println!("  Preset: {} ({})", preset, desc);

    Some((sel, preset.to_string(), desc.to_string()))
}

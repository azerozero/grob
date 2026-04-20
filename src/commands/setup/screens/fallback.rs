//! Screen 3: choose the fallback provider (used when the primary fails).

use crate::commands::setup::input::{prompt_choice, prompt_key_for_provider};
use crate::commands::setup::types::FallbackChoice;

/// Prompts the user for a fallback provider.
///
/// Always prompted (even when a preset ships a fallback) so the user can
/// explicitly opt out and avoid the phantom `$OPENROUTER_API_KEY not set`
/// warning at startup.
pub(in crate::commands::setup) fn screen_fallback(
    preset_has_fallback: bool,
) -> (FallbackChoice, Option<String>) {
    println!();
    println!("  Fallback provider (used when the primary is down or rate-limited):");
    println!("    [1] None (no fallback — primary only)");
    println!("    [2] OpenRouter (recommended — 100+ models, sign up: https://openrouter.ai)");
    println!("    [3] Gemini (requires $GEMINI_API_KEY)");
    if preset_has_fallback {
        println!("    [4] Keep preset default");
    } else {
        println!("    [4] Keep preset default (if any)");
    }
    match prompt_choice(4) {
        1 => (FallbackChoice::None, None),
        2 => (
            FallbackChoice::OpenRouter,
            prompt_key_for_provider("OPENROUTER_API_KEY", Some("openrouter")),
        ),
        3 => (
            FallbackChoice::Gemini,
            prompt_key_for_provider("GEMINI_API_KEY", Some("gemini")),
        ),
        _ => (FallbackChoice::KeepPreset, None),
    }
}

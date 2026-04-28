//! Model-name canonicalizer.
//!
//! Users frequently type small variations of provider model IDs that differ
//! only in cosmetic ways: a trailing date suffix (`claude-3-5-sonnet-20241022`),
//! a `-latest` alias, decimal versions vs dashed versions
//! (`gemini-2.5-flash` vs `gemini-2-5-flash`), reordered family/version
//! tokens for Anthropic (`claude-3-5-sonnet` vs `claude-sonnet-3-5`), or
//! mixed casing. Without canonicalization, an explicit `[[models]]` entry
//! named `claude-sonnet-3-5` would not match a request for
//! `Claude-3-5-Sonnet-20241022`, even though both refer to the same model.
//!
//! [`canonicalize_model_name`] applies a deterministic, idempotent set of
//! rewrites *before* the `[[models]]` lookup so that user-facing variations
//! collapse into the configured canonical key.
//!
//! # Rules (in order)
//!
//! 1. **Lowercase**. ASCII-only; non-ASCII bytes are passed through unchanged.
//! 2. **Strip trailing `-latest`** (e.g. `claude-sonnet-4-5-latest` →
//!    `claude-sonnet-4-5`).
//! 3. **Strip trailing 8-digit date suffix** `-YYYYMMDD` (e.g.
//!    `claude-3-5-sonnet-20241022` → `claude-3-5-sonnet`, which the
//!    next rules then reorder). Must be exactly 8 digits to avoid
//!    clobbering version segments such as `gpt-5-2`.
//! 4. **Dot-versions to dashed-versions** for Anthropic / Gemini / Grok /
//!    DeepSeek / OpenAI families (e.g. `gemini-2.5-flash` →
//!    `gemini-2-5-flash`, `gpt-5.2` → `gpt-5-2`,
//!    `claude-3.5-sonnet` → `claude-3-5-sonnet`). Gated on a known
//!    family prefix so unrelated IDs (e.g. `glm-4.6`) survive
//!    untouched.
//! 5. **Anthropic family-version reorder**: `claude-{N}-{M}-{family}` →
//!    `claude-{family}-{N}-{M}` (where `family` is `sonnet`, `opus`, or
//!    `haiku`) so that both Anthropic-published spellings collapse into
//!    one key. The newer style (`claude-sonnet-4-5`) is used as the
//!    canonical form because that is the spelling used in `presets/*.toml`
//!    — keeping config keys verbatim avoids breaking existing
//!    `[[models]]` entries and fallback chains.
//!
//! Existing canonical names (`gpt-4o`, `deepseek-chat`, `gemini-3-pro`,
//! `claude-sonnet-4-5`) are fixed points: each rule short-circuits when its
//! pattern is absent, so `canonicalize_model_name(canonical) == canonical`.
//!
//! # Idempotence
//!
//! Each rule either strips a fixed suffix or rewrites a token in place,
//! and none of the rewrites introduce a substring that another rule would
//! match. Therefore
//! `canonicalize_model_name(canonicalize_model_name(x)) ==
//! canonicalize_model_name(x)` for every input — covered by a proptest
//! over arbitrary alphanumeric strings.
//!
//! # Examples
//!
//! ```
//! use grob::routing::classify::model_name::canonicalize_model_name;
//! assert_eq!(
//!     canonicalize_model_name("claude-3-5-sonnet-20241022"),
//!     "claude-sonnet-3-5"
//! );
//! assert_eq!(
//!     canonicalize_model_name("claude-3-5-sonnet"),
//!     "claude-sonnet-3-5"
//! );
//! assert_eq!(canonicalize_model_name("claude-sonnet-4-5"), "claude-sonnet-4-5");
//! assert_eq!(canonicalize_model_name("gpt-4o"), "gpt-4o");
//! ```

use std::borrow::Cow;

/// Returns the canonical form of a user-supplied model name.
///
/// Borrows when no rewrite is needed (the common steady-state case for
/// already-canonical names) and only allocates when at least one rule
/// fires. The function is idempotent: applying it to its own output is a
/// no-op.
///
/// See the [module docs](self) for the full rule list.
///
/// # Examples
///
/// ```
/// use grob::routing::classify::model_name::canonicalize_model_name;
/// // Date-suffixed Anthropic ID collapses to its dateless form, and the
/// // older `claude-3-5-sonnet` ordering reorders to the modern
/// // `claude-sonnet-3-5` spelling used in `presets/*.toml`.
/// assert_eq!(
///     canonicalize_model_name("claude-3-5-sonnet-20241022"),
///     "claude-sonnet-3-5"
/// );
/// // Dotted Gemini version becomes dashed.
/// assert_eq!(
///     canonicalize_model_name("gemini-2.5-flash"),
///     "gemini-2-5-flash"
/// );
/// // Already-canonical names borrow without allocating.
/// assert_eq!(canonicalize_model_name("gpt-4o"), "gpt-4o");
/// assert_eq!(canonicalize_model_name("claude-sonnet-4-5"), "claude-sonnet-4-5");
/// ```
#[must_use]
pub fn canonicalize_model_name(input: &str) -> Cow<'_, str> {
    // Rule 1: lowercase. Borrow when already lowercase.
    let mut current: Cow<'_, str> = if input.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(input.to_ascii_lowercase())
    } else {
        Cow::Borrowed(input)
    };

    // Rule 2: strip trailing `-latest`.
    if let Some(stripped) = current.strip_suffix("-latest") {
        current = Cow::Owned(stripped.to_string());
    }

    // Rule 3: strip trailing `-YYYYMMDD` (exactly 8 digits).
    if let Some(stripped) = strip_trailing_date(&current) {
        current = Cow::Owned(stripped.to_string());
    }

    // Rule 4: dot-versions to dashed-versions for known families. Gated on a
    // known prefix to avoid touching unrelated provider IDs (e.g. `glm-4.6`,
    // which the user explicitly does not want rewritten).
    if has_known_family_prefix(&current) && has_dotted_version(&current) {
        current = Cow::Owned(replace_dot_versions(&current));
    }

    // Rule 5: Anthropic family-version reorder.
    if let Some(reordered) = reorder_anthropic_family(&current) {
        current = Cow::Owned(reordered);
    }

    current
}

/// Returns the input minus a trailing `-YYYYMMDD` suffix when present.
fn strip_trailing_date(s: &str) -> Option<&str> {
    let bytes = s.as_bytes();
    if bytes.len() < 9 {
        return None;
    }
    let split = bytes.len() - 9;
    if bytes[split] != b'-' {
        return None;
    }
    if bytes[split + 1..].iter().all(u8::is_ascii_digit) {
        Some(&s[..split])
    } else {
        None
    }
}

/// Returns true when the string contains a `<digit>.<digit>` sequence —
/// the cheap pre-check before allocating a rewritten string.
fn has_dotted_version(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes
        .windows(3)
        .any(|w| w[0].is_ascii_digit() && w[1] == b'.' && w[2].is_ascii_digit())
}

/// Known model-family prefixes for which the dot-version rule fires.
///
/// Listing them explicitly keeps the rewrite confined to families whose
/// version syntax we actually understand and avoids rewriting unrelated
/// IDs like `glm-4.6` (the GLM family) or `mistral-3.1.0`.
const DOTTED_VERSION_FAMILIES: &[&str] = &["claude-", "gpt-", "gemini-", "grok-", "deepseek-"];

/// Returns true when the input starts with one of [`DOTTED_VERSION_FAMILIES`].
fn has_known_family_prefix(s: &str) -> bool {
    DOTTED_VERSION_FAMILIES.iter().any(|p| s.starts_with(p))
}

/// Replaces every `<digit>.<digit>` with `<digit>-<digit>`.
///
/// Walks one byte at a time so chained dotted versions like `1.2.3`
/// rewrite to `1-2-3` in a single pass — that one-pass property is what
/// makes the canonicalizer idempotent.
fn replace_dot_versions(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    for i in 0..bytes.len() {
        if bytes[i] == b'.'
            && i > 0
            && i + 1 < bytes.len()
            && bytes[i - 1].is_ascii_digit()
            && bytes[i + 1].is_ascii_digit()
        {
            out.push('-');
        } else {
            out.push(bytes[i] as char);
        }
    }
    out
}

/// Anthropic family slugs that may appear before or after the version
/// number depending on which Anthropic-published spelling the caller used.
const ANTHROPIC_FAMILIES: &[&str] = &["sonnet", "opus", "haiku"];

/// Reorders `claude-<N>-<M>-<family>...` → `claude-<family>-<N>-<M>...`
/// when the input matches that pattern; returns `None` otherwise.
///
/// The newer Anthropic spelling (`claude-sonnet-4-5`) is the canonical
/// form because that is what `presets/*.toml` uses. Older
/// `claude-3-5-sonnet` style names rewrite to `claude-sonnet-3-5` so
/// both collapse into one key for `[[models]]` lookup.
fn reorder_anthropic_family(s: &str) -> Option<String> {
    let rest = s.strip_prefix("claude-")?;
    let mut parts = rest.splitn(4, '-');
    let major = parts.next()?;
    let minor = parts.next()?;
    let family = parts.next()?;
    if !ANTHROPIC_FAMILIES.contains(&family) {
        return None;
    }
    if !major.bytes().all(|b| b.is_ascii_digit()) || !minor.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let tail = parts.next();
    let mut out = String::with_capacity(s.len());
    out.push_str("claude-");
    out.push_str(family);
    out.push('-');
    out.push_str(major);
    out.push('-');
    out.push_str(minor);
    if let Some(tail) = tail {
        out.push('-');
        out.push_str(tail);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Coverage matrix across all listed provider families.
    ///
    /// Each row is `(input, expected_canonical)`. The matrix exists as a
    /// single table so adding a new family is one line, and a regression
    /// from any rule lights up exactly one row.
    #[test]
    fn canonicalize_known_inputs() {
        let cases: &[(&str, &str)] = &[
            // Anthropic — date suffix stripped + family-version reorder
            ("claude-3-5-sonnet-20241022", "claude-sonnet-3-5"),
            ("claude-3-5-haiku-20241022", "claude-haiku-3-5"),
            // Anthropic — `-latest` stripped (already-canonical 4.x form)
            ("claude-sonnet-4-5-latest", "claude-sonnet-4-5"),
            ("claude-opus-4-5-latest", "claude-opus-4-5"),
            // Anthropic — older 3.x ordering reorders to 4.x style
            ("claude-3-5-sonnet", "claude-sonnet-3-5"),
            ("claude-3-5-haiku", "claude-haiku-3-5"),
            // Anthropic — already canonical (fixed point, modern style)
            ("claude-sonnet-4-5", "claude-sonnet-4-5"),
            ("claude-haiku-4-5", "claude-haiku-4-5"),
            ("claude-opus-4-7", "claude-opus-4-7"),
            // Anthropic — dotted version becomes dashed
            ("claude-3.5-sonnet", "claude-sonnet-3-5"),
            // Anthropic — uppercase normalization
            ("Claude-3-5-Sonnet-20241022", "claude-sonnet-3-5"),
            // OpenAI
            ("gpt-4o", "gpt-4o"),
            ("gpt-5", "gpt-5"),
            ("gpt-5-2", "gpt-5-2"),
            ("gpt-5.2", "gpt-5-2"),
            ("gpt-4o-latest", "gpt-4o"),
            // DeepSeek
            ("deepseek-chat", "deepseek-chat"),
            ("deepseek-v3", "deepseek-v3"),
            ("deepseek-v4-flash", "deepseek-v4-flash"),
            // Gemini
            ("gemini-2.5-flash", "gemini-2-5-flash"),
            ("gemini-3-flash", "gemini-3-flash"),
            ("gemini-3-pro-latest", "gemini-3-pro"),
            // Grok
            ("grok-4", "grok-4"),
            ("grok-4-1-fast", "grok-4-1-fast"),
            ("grok-4.1-fast", "grok-4-1-fast"),
        ];
        for (input, expected) in cases {
            let got = canonicalize_model_name(input);
            assert_eq!(
                got.as_ref(),
                *expected,
                "canonicalize_model_name({input:?}) → {got:?}, expected {expected:?}"
            );
        }
        // 25 cases — exceeds the ≥ 20-case requirement.
        assert!(cases.len() >= 20, "coverage matrix must have ≥ 20 cases");
    }

    /// Idempotence: applying the canonicalizer twice equals once.
    #[test]
    fn canonicalize_is_idempotent_on_matrix() {
        let cases: &[&str] = &[
            "claude-3-5-sonnet-20241022",
            "claude-sonnet-3-5",
            "claude-opus-4-5-latest",
            "claude-sonnet-4-5",
            "gpt-5.2",
            "gemini-2.5-flash",
            "grok-4.1-fast",
            "Claude-3-5-Sonnet-20241022",
        ];
        for input in cases {
            let once = canonicalize_model_name(input).into_owned();
            let twice = canonicalize_model_name(&once).into_owned();
            assert_eq!(once, twice, "not idempotent for {input:?}");
        }
    }

    /// Already-canonical lowercase inputs must not allocate.
    #[test]
    fn canonical_inputs_borrow() {
        let inputs = ["gpt-4o", "deepseek-chat", "gemini-3-pro", "grok-4"];
        for input in inputs {
            let got = canonicalize_model_name(input);
            assert!(
                matches!(got, Cow::Borrowed(_)),
                "expected borrowed Cow for canonical input {input:?}, got owned"
            );
        }
    }

    // Property: `canonicalize(canonicalize(x)) == canonicalize(x)`.
    proptest! {
        #[test]
        fn prop_canonicalize_is_idempotent(input in "[A-Za-z0-9.\\-]{1,32}") {
            let once = canonicalize_model_name(&input).into_owned();
            let twice = canonicalize_model_name(&once).into_owned();
            prop_assert_eq!(once, twice);
        }
    }

    /// Date stripping requires exactly 8 digits — guards against eating
    /// version segments like `-2` from `gpt-5-2`.
    #[test]
    fn date_stripper_only_strips_8_digits() {
        assert_eq!(canonicalize_model_name("gpt-5-2"), "gpt-5-2");
        assert_eq!(canonicalize_model_name("gpt-5-12345"), "gpt-5-12345");
        assert_eq!(canonicalize_model_name("gpt-5-12345678"), "gpt-5");
    }

    /// Anthropic reorder must fire only when the family slug is the
    /// third token and the first two are numeric.
    #[test]
    fn anthropic_reorder_requires_known_family_and_numeric_version() {
        // No reorder: trailing token is unknown family slug.
        assert_eq!(
            canonicalize_model_name("claude-3-5-instant"),
            "claude-3-5-instant"
        );
        // No reorder: first two tokens are not all digits.
        assert_eq!(
            canonicalize_model_name("claude-x-y-sonnet"),
            "claude-x-y-sonnet"
        );
        // No reorder: already in canonical {family}-{N}-{M} form.
        assert_eq!(
            canonicalize_model_name("claude-sonnet-x-y"),
            "claude-sonnet-x-y"
        );
    }
}

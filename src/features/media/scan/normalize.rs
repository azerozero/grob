//! OCR text normalisation for the image path.
//!
//! Measured, not guessed: feeding real OCR output to the existing DLP engine
//! caught 3 of 4 planted secrets, and the miss was instructive. Repairing the
//! errors one at a time showed that a *single* wrong character defeats a rule,
//! and that survival depends on the shape of the pattern rather than on the
//! quality of the OCR:
//!
//! - `AKIA[0-9A-Z]{16}` survived `AKIAI` being read as `AKIAT`, because the
//!   error landed inside a character class.
//! - `sk_live_…` did not survive `sk_Live_` plus a multiplication sign, because
//!   those errors landed in a literal prefix, which forgives nothing.
//!
//! So the useful lever is not a better OCR engine, it is folding the confusions
//! engines actually make before the scan. That is cheap and aimed squarely at
//! the observed failure mode.
//!
//! This applies to the **image path only**. Loosening the text path would
//! manufacture false positives for every request that never involved an image.

/// Folds visually confusable characters into their canonical form.
///
/// Only substitutions observed in real OCR output are folded. Every extra
/// mapping widens the false-positive surface, so the list stays short and
/// evidence-driven rather than exhaustive.
#[must_use]
pub fn fold_confusions(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            // Vision rendered "51H8xYz" as "51H8×Yz".
            '\u{d7}' => 'x',                 // multiplication sign
            '\u{2212}' => '-',               // minus sign
            '\u{2013}' | '\u{2014}' => '-',  // en/em dash
            '\u{2018}' | '\u{2019}' => '\'', // curly quotes
            '\u{201c}' | '\u{201d}' => '"',
            '\u{00a0}' => ' ', // non-breaking space
            other => other,
        })
        .collect()
}

/// Produces the variants of `text` worth scanning.
///
/// The original always comes first: a rule that already matches must not be
/// affected by any of this. Extra variants are only added when they actually
/// differ, so the common case of clean OCR costs one scan.
///
/// The lowercase variant exists because literal prefixes are where OCR errors
/// are fatal, and case is the single most common such error (`sk_live_` read
/// as `sk_Live_`). Underscore repair covers engines that drop them entirely,
/// which is what `ocrs` did on the same fixture.
#[must_use]
pub fn scan_variants(text: &str) -> Vec<String> {
    let mut variants = vec![text.to_string()];

    let folded = fold_confusions(text);
    if folded != text {
        variants.push(folded.clone());
    }

    // The repairs have to compose, not merely coexist. `ocrs` rendered
    // "sk_live_" as "sk Live_": a dropped underscore *and* a case error in
    // the same literal. Fixing either alone leaves the rule unmatched, which
    // is exactly the trap measured on the raw output.
    let lowered = folded.to_lowercase();
    // `ocrs` also rendered "AWS_ACCESS_KEY_ID" as "AWS ACCESS KEY ID".
    let underscored = folded.replace(' ', "_");
    let both = lowered.replace(' ', "_");

    for candidate in [lowered, underscored, both] {
        if !variants.contains(&candidate) {
            variants.push(candidate);
        }
    }

    variants
}

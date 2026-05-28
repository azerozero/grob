//! Credit card detection and Luhn validation.
//!
//! Regex-based match of 13-19 digit runs (with optional spaces/dashes), followed
//! by Luhn mod-10 checksum validation. Also generates Luhn-valid fake card
//! numbers for canary replacement.

use regex::Regex;
use std::sync::LazyLock;

// SAFETY: pattern is a compile-time constant; unwrap cannot fail.
pub(super) static CC_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:\d[ -]?){13,19}\b").unwrap());

/// Validates a credit card number using the Luhn algorithm.
///
/// Expects a digit-only string (no spaces or dashes). Returns true
/// when the sum of alternating doubled digits mod 10 equals 0.
///
/// # Examples
///
/// ```
/// use grob::features::dlp::pii::luhn_check;
///
/// // Valid Visa test number
/// assert!(luhn_check("4111111111111111"));
/// // Invalid (last digit changed)
/// assert!(!luhn_check("4111111111111112"));
/// ```
pub fn luhn_check(digits: &str) -> bool {
    let mut sum: u32 = 0;
    let mut double = false;

    for ch in digits.chars().rev() {
        let mut d = ch.to_digit(10).unwrap_or(0);
        if double {
            d *= 2;
            // mutants::skip — d *= 2 only produces even values
            // (0,2,4,6,8,10,12,14,16,18). d == 9 is unreachable, so > and >= are equivalent.
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }

    sum.is_multiple_of(10)
}

/// Generates a Luhn-valid fake credit card number with the same length.
pub(super) fn generate_canary_cc(original: &str, id: u64) -> String {
    let digits_only: String = original.chars().filter(|c| c.is_ascii_digit()).collect();
    let len = digits_only.len();
    if len < 2 {
        return "0".repeat(len);
    }

    // Keep the first digit (card network) but replace the rest with id-derived digits.
    let first = digits_only.chars().next().unwrap_or('4');
    let seed = format!("{}{:0>width$}", first, id, width = len - 2);
    let mut partial: Vec<u8> = seed
        .chars()
        .take(len - 1)
        .map(|c| c.to_digit(10).unwrap_or(0) as u8)
        .collect();

    // Defensive pad: the format! above always generates >= len-1 chars thanks
    // to the zero-padding {:0>width$}, so this loop never fires.
    // mutants::skip — defensive dead code, partial.len() == len-1 always holds here.
    while partial.len() < len - 1 {
        partial.push(0);
    }

    let check = luhn_check_digit(&partial);
    partial.push(check);

    partial.iter().map(|d| (b'0' + d) as char).collect()
}

/// Computes the Luhn check digit for a sequence of digits.
pub(super) fn luhn_check_digit(digits: &[u8]) -> u8 {
    let mut sum: u32 = 0;
    for (i, &d) in digits.iter().rev().enumerate() {
        let mut val = d as u32;
        if i % 2 == 0 {
            val *= 2;
            // mutants::skip — val *= 2 only produces even values (0..18),
            // so val == 9 is unreachable and > vs >= are equivalent.
            if val > 9 {
                val -= 9;
            }
        }
        sum += val;
    }
    ((10 - (sum % 10)) % 10) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_luhn_valid_visa() {
        assert!(luhn_check("4532015112830366"));
    }

    #[test]
    fn test_luhn_valid_mastercard() {
        assert!(luhn_check("5425233430109903"));
    }

    #[test]
    fn test_luhn_valid_amex() {
        assert!(luhn_check("374245455400126"));
    }

    #[test]
    fn test_luhn_invalid() {
        assert!(!luhn_check("4532015112830367")); // off by one
        assert!(!luhn_check("1234567890123456"));
    }

    /// Kills: L212 *= -> += (d *= 2 -> d += 2 changes the result).
    #[test]
    fn test_kill_mutant_212_luhn_double_multiplication() {
        assert!(luhn_check("4111111111111111"));
        assert!(!luhn_check("4111111111111112"));
    }

    /// Kills: L213 > -> >= / == / < (d > 9 threshold).
    #[test]
    fn test_kill_mutant_213_luhn_d_gt_9_threshold() {
        assert!(luhn_check("5425233430109903"));
        assert!(!luhn_check("5425233430109900"));
    }

    /// Kills: L214 -= -> += (d -= 9 must subtract, not add).
    #[test]
    fn test_kill_mutant_214_luhn_subtract_9() {
        assert!(luhn_check("5425233430109903"));
        assert!(!luhn_check("5425233430109904"));
    }

    /// Kills: L217 += -> -= (sum += d must accumulate, not subtract).
    #[test]
    fn test_kill_mutant_217_luhn_sum_accumulate() {
        assert!(luhn_check("4532015112830366"));
        assert!(!luhn_check("4532015112830360"));
    }

    /// Kills: L218 delete ! (double = !double toggle).
    #[test]
    fn test_kill_mutant_218_luhn_double_toggle() {
        assert!(luhn_check("374245455400126"));
        assert!(!luhn_check("374245455400127"));
    }

    /// Kills: L340:12 < -> <= (len < 2 guard). With <=, len==2 would return "00"
    /// instead of generating a canary derived from the input.
    #[test]
    fn test_kill_mutant_340_canary_cc_len_2_generates_valid() {
        let canary = generate_canary_cc("41", 1);
        assert_eq!(canary.len(), 2);
        assert_eq!(
            canary.chars().next().unwrap(),
            '4',
            "The first digit must be preserved (network): {canary}"
        );
        assert!(
            luhn_check(&canary),
            "Canary CC 2 chars must pass Luhn: {canary}"
        );
    }

    /// Kills: L334 < (len < 2 guard). len==1 must return "0".
    #[test]
    fn test_kill_mutant_334_canary_cc_len_1_returns_zero() {
        let canary = generate_canary_cc("4", 1);
        assert_eq!(canary, "0");
    }

    /// Kills: L349:19 - -> + / / (width = len - 2).
    #[test]
    fn test_kill_mutant_349_canary_cc_seed_width() {
        let canary = generate_canary_cc("4111111111111111", 42);
        assert_eq!(canary.len(), 16, "Canary must have exactly 16 chars");
        assert!(
            luhn_check(&canary),
            "Canary 16 chars must pass Luhn: {canary}"
        );
    }

    /// Kills: L354:25 < -> > (while partial.len() < len - 1 pad loop).
    #[test]
    fn test_kill_mutant_354_canary_cc_pad_loop() {
        let canary = generate_canary_cc("4111111111111111", 1);
        assert_eq!(canary.len(), 16);
        assert!(luhn_check(&canary), "Canary pad must pass Luhn: {canary}");
        for c in canary.chars() {
            assert!(c.is_ascii_digit(), "Char '{c}' is not a digit");
        }
    }

    /// Kills: L362:34 + -> - ((b'0' + d) as char).
    #[test]
    fn test_kill_mutant_362_canary_cc_ascii_digits() {
        let canary = generate_canary_cc("5425233430109903", 999);
        assert_eq!(canary.len(), 16);
        for c in canary.chars() {
            assert!(
                c.is_ascii_digit(),
                "Expected digit, got '{c}' (U+{:04X})",
                c as u32
            );
        }
        assert!(luhn_check(&canary), "Canary must pass Luhn: {canary}");
    }

    /// Kills: L364 *= -> += and L365-366 > / -= (same pattern as luhn_check).
    #[test]
    fn test_kill_mutant_364_luhn_check_digit_correct() {
        let digits = vec![4, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1];
        let check = luhn_check_digit(&digits);
        let mut full: Vec<u8> = digits;
        full.push(check);
        let s: String = full.iter().map(|d| (b'0' + d) as char).collect();
        assert!(luhn_check(&s));
    }

    /// Kills: L372 % -> / in ((10 - (sum % 10)) % 10).
    #[test]
    fn test_kill_mutant_372_luhn_check_digit_modulo() {
        for prefix in [
            vec![5, 4, 2, 5, 2, 3, 3, 4, 3, 0, 1, 0, 9, 9, 0],
            vec![3, 7, 4, 2, 4, 5, 4, 5, 5, 4, 0, 0, 1, 2],
        ] {
            let check = luhn_check_digit(&prefix);
            let mut full = prefix;
            full.push(check);
            let s: String = full.iter().map(|d| (b'0' + d) as char).collect();
            assert!(luhn_check(&s), "Luhn check digit failed for {s}");
        }
    }

    proptest::proptest! {
        /// Luhn check digit generation always produces valid numbers.
        #[test]
        fn prop_luhn_check_digit_valid(digits in proptest::collection::vec(0u8..10, 12..18)) {
            let check = luhn_check_digit(&digits);
            let mut full: Vec<u8> = digits;
            full.push(check);
            let s: String = full.iter().map(|d| (b'0' + d) as char).collect();
            proptest::prop_assert!(luhn_check(&s), "Generated number must pass Luhn: {s}");
        }
    }
}

//! IBAN detection and ISO 7064 mod-97 validation.
//!
//! Matches `CC99...` patterns (country + 2-digit check + body) and validates
//! via rearrangement + modular arithmetic. Canary generator emits a valid
//! IBAN with the same country code and length.

use regex::Regex;
use std::sync::LazyLock;

// SAFETY: pattern is a compile-time constant; unwrap cannot fail.
pub(super) static IBAN_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Z]{2}\d{2}[A-Z0-9]{12,30}\b").unwrap());

/// Validates an IBAN using ISO 7064 mod-97 arithmetic.
///
/// Rearranges country+check to end, converts letters to digits, then
/// verifies the remainder equals 1. Returns false for strings shorter
/// than 15 characters or containing non-alphanumeric characters.
///
/// # Examples
///
/// ```
/// use grob::features::dlp::pii::iban_mod97_check;
///
/// // Valid French IBAN
/// assert!(iban_mod97_check("FR7630006000011234567890189"));
/// // Invalid (modified check digits)
/// assert!(!iban_mod97_check("FR0030006000011234567890189"));
/// // Too short
/// assert!(!iban_mod97_check("FR76300060"));
/// ```
pub fn iban_mod97_check(iban: &str) -> bool {
    if iban.len() < 15 {
        return false;
    }

    // Rearrange: move first 4 chars to end
    let rearranged = format!("{}{}", &iban[4..], &iban[..4]);

    // Convert letters to digits (A=10, B=11, ..., Z=35) and compute mod 97
    let mut remainder: u64 = 0;
    for ch in rearranged.chars() {
        if let Some(d) = ch.to_digit(10) {
            remainder = (remainder * 10 + d as u64) % 97;
        } else if ch.is_ascii_uppercase() {
            let val = (ch as u64) - b'A' as u64 + 10;
            // Two-digit number: shift by 2 decimal places
            remainder = (remainder * 100 + val) % 97;
        } else {
            return false; // invalid character
        }
    }

    remainder == 1
}

/// Generates a fake IBAN with the same country code and length.
pub(super) fn generate_canary_iban(original: &str, id: u64) -> String {
    let country = if original.len() >= 2 {
        &original[..2]
    } else {
        "XX"
    };
    let body_len = original.len().saturating_sub(4); // minus country(2) + check(2)
    let body = format!("{:0>width$}", id, width = body_len);

    // Compute mod97 check digits (ISO 7064)
    let rearranged = format!("{}{}00", body, country);
    let mut remainder: u64 = 0;
    for ch in rearranged.chars() {
        let val = if ch.is_ascii_uppercase() {
            (ch as u64) - 55 // A=10, B=11, ...
        } else {
            ch.to_digit(10).unwrap_or(0) as u64
        };
        if val >= 10 {
            remainder = (remainder * 100 + val) % 97;
        } else {
            remainder = (remainder * 10 + val) % 97;
        }
    }
    let check = 98 - remainder;

    format!("{}{:02}{}", country, check, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iban_valid_fr() {
        assert!(iban_mod97_check("FR7630006000011234567890189"));
    }

    #[test]
    fn test_iban_valid_de() {
        assert!(iban_mod97_check("DE89370400440532013000"));
    }

    #[test]
    fn test_iban_valid_gb() {
        assert!(iban_mod97_check("GB29NWBK60161331926819"));
    }

    #[test]
    fn test_iban_invalid() {
        assert!(!iban_mod97_check("FR7630006000011234567890188"));
        assert!(!iban_mod97_check("XX000000000000"));
    }

    /// Tue : L228:19 < -> == (si ==, un IBAN de 14 chars passerait le guard).
    /// Tue : L228:19 < -> <= (si <=, un IBAN valide de 15 chars serait rejete).
    #[test]
    fn test_kill_mutant_228_iban_length_guard() {
        assert!(!iban_mod97_check("FR123456789012"));
        assert!(!iban_mod97_check("FR1234567890"));
        // 15 chars VALIDE (Norway NO9386011117947)
        assert!(iban_mod97_check("NO9386011117947"));
    }

    /// Tue : L239:53 % -> / et L239:41 + -> - dans remainder calc.
    #[test]
    fn test_kill_mutant_239_iban_remainder_arithmetic() {
        assert!(iban_mod97_check("DE89370400440532013000"));
        assert!(!iban_mod97_check("DE89370400440532013001"));
    }

    /// Tue : L243 replace * 100 avec autre chose dans letter conversion.
    #[test]
    fn test_kill_mutant_243_iban_letter_two_digit_shift() {
        assert!(iban_mod97_check("GB82WEST12345698765432"));
    }

    /// Tue : L249 == -> != (remainder == 1 final check).
    #[test]
    fn test_kill_mutant_249_iban_remainder_must_be_1() {
        assert!(iban_mod97_check("FR7630006000011234567890189"));
        assert!(!iban_mod97_check("FR0030006000011234567890189"));
    }

    /// Tue : L405:49 % -> + dans le calcul remainder % 97 de generate_canary_iban.
    #[test]
    fn test_kill_mutant_405_canary_iban_mod97_valid_multiple() {
        for id in [1, 7, 42, 99, 123, 9999, 100_000] {
            let canary = generate_canary_iban("FR7630006000011234567890189", id);
            assert!(canary.starts_with("FR"));
            assert_eq!(canary.len(), 27);
            assert!(
                iban_mod97_check(&canary),
                "Canary IBAN id={id} doit etre mod97-valide"
            );
        }
    }

    /// Tue : L377 len >= 2 guard et L382 saturating_sub.
    #[test]
    fn test_kill_mutant_377_canary_iban_short_input() {
        let canary = generate_canary_iban("X", 1);
        assert!(!canary.is_empty());
    }

    /// Tue : L394/397 val >= 10 branch (lettres vs digits dans le calcul).
    #[test]
    fn test_kill_mutant_394_canary_iban_letter_digit_branch() {
        let canary = generate_canary_iban("GB29NWBK60161331926819", 42);
        assert!(canary.starts_with("GB"));
        assert!(
            iban_mod97_check(&canary),
            "Canary GB doit etre mod97-valide"
        );
    }

    /// Tue : L400 - -> + (check = 98 - remainder).
    #[test]
    fn test_kill_mutant_400_canary_iban_check_digit_subtraction() {
        let canary = generate_canary_iban("DE89370400440532013000", 7);
        assert!(
            iban_mod97_check(&canary),
            "Canary DE doit etre mod97-valide"
        );
    }

    proptest::proptest! {
        /// IBAN mod97 validation rejects random alphanumeric strings.
        #[test]
        fn prop_iban_rejects_random(body in "[A-Z]{2}[0-9]{2}[A-Z0-9]{15,28}") {
            // Overwhelming majority of random strings fail mod97.
            // We just verify no panics and check the function is total.
            let _ = iban_mod97_check(&body);
        }
    }
}

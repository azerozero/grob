//! BIC / SWIFT code detection and ISO 9362 format validation.
//!
//! Matches 8 or 11 character BIC patterns and validates structure:
//! 4-letter bank code, ISO 3166 country code, alphanumeric location,
//! and optional 3-character branch code. Canary generator emits a fake
//! BIC preserving the original country and location suffix.

use regex::Regex;
use std::sync::LazyLock;

// SAFETY: pattern is a compile-time constant; unwrap cannot fail.
pub(super) static BIC_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b").unwrap());

/// Validates a BIC/SWIFT code format.
///
/// Checks 4-letter bank code, 2-letter ISO 3166 country code, 2-character
/// alphanumeric location, and optional 3-character branch code.
///
/// # Examples
///
/// ```
/// use grob::features::dlp::bic::bic_format_check;
///
/// // Valid 8-char BIC (BNP Paribas, France)
/// assert!(bic_format_check("BNPAFRPP"));
/// // Valid 11-char BIC with branch
/// assert!(bic_format_check("BNPAFRPP123"));
/// // Invalid: wrong length
/// assert!(!bic_format_check("BNPA"));
/// // Invalid: lowercase
/// assert!(!bic_format_check("bnpafrpp"));
/// ```
pub fn bic_format_check(bic: &str) -> bool {
    let len = bic.len();
    if len != 8 && len != 11 {
        return false;
    }

    // First 4: letters (bank code)
    if !bic[..4].chars().all(|c| c.is_ascii_uppercase()) {
        return false;
    }

    // Next 2: ISO 3166 country code
    let country = &bic[4..6];
    if !is_valid_country_code(country) {
        return false;
    }

    // Next 2: location (alphanumeric)
    if !bic[6..8]
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return false;
    }

    // Optional 3: branch (alphanumeric)
    if len == 11
        && !bic[8..11]
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return false;
    }

    true
}

/// Generates a fake BIC preserving the original country and location suffix.
pub(super) fn generate_canary_bic(original: &str) -> String {
    format!("GROB{}{}", &original[4..6], &original[6..])
}

/// Validate ISO 3166-1 alpha-2 country code against a static table.
fn is_valid_country_code(code: &str) -> bool {
    const COUNTRY_CODES: &[&str] = &[
        "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU", "AW", "AX",
        "AZ", "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BQ",
        "BR", "BS", "BT", "BV", "BW", "BY", "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK",
        "CL", "CM", "CN", "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM",
        "DO", "DZ", "EC", "EE", "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK", "FM", "FO", "FR",
        "GA", "GB", "GD", "GE", "GF", "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS",
        "GT", "GU", "GW", "GY", "HK", "HM", "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN",
        "IO", "IQ", "IR", "IS", "IT", "JE", "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN",
        "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC", "LI", "LK", "LR", "LS", "LT", "LU", "LV",
        "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP", "MQ",
        "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA", "NC", "NE", "NF", "NG", "NI",
        "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM",
        "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW", "SA", "SB", "SC",
        "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "SS", "ST", "SV",
        "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO", "TR",
        "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG", "VI",
        "VN", "VU", "WF", "WS", "XK", "YE", "YT", "ZA", "ZM", "ZW",
    ];
    COUNTRY_CODES.contains(&code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bic_valid_8() {
        assert!(bic_format_check("DEUTDEFF")); // Deutsche Bank Frankfurt
    }

    #[test]
    fn test_bic_valid_11() {
        assert!(bic_format_check("BNPAFRPP75A")); // BNP Paribas Paris
    }

    #[test]
    fn test_bic_invalid_country() {
        assert!(!bic_format_check("DEUTXXFF")); // XX is not a valid country
    }

    #[test]
    fn test_bic_invalid_length() {
        assert!(!bic_format_check("DEUTDE")); // too short
        assert!(!bic_format_check("DEUTDEFFAAAA")); // too long (12)
    }

    /// Tue : L257 != 8 && != 11 (accept only 8 or 11).
    #[test]
    fn test_kill_mutant_257_bic_length_strict() {
        assert!(!bic_format_check("DEUTD")); // 5 chars
        assert!(!bic_format_check("DEUTDEFF1")); // 9 chars
        assert!(!bic_format_check("DEUTDEFF12")); // 10 chars
        assert!(bic_format_check("DEUTDEFF")); // 8 exact
        assert!(bic_format_check("BNPAFRPP75A")); // 11 exact
    }

    /// Tue : L262 !...all(uppercase) first 4 bank code.
    #[test]
    fn test_kill_mutant_262_bic_bank_code_uppercase_only() {
        assert!(!bic_format_check("dEUTDEFF")); // lowercase first char
        assert!(!bic_format_check("DEuTDEFF")); // lowercase third char
        assert!(!bic_format_check("D3UTDEFF")); // digit in bank code
    }

    /// Tue : L268 is_valid_country_code negation.
    #[test]
    fn test_kill_mutant_268_bic_country_validation() {
        assert!(!bic_format_check("DEUTXXFF")); // XX invalid country
        assert!(!bic_format_check("DEUTQQFF")); // QQ invalid
        assert!(bic_format_check("DEUTDEFF")); // DE valid
        assert!(bic_format_check("BNPAFRPP")); // FR valid
    }

    /// Tue : L273-278 location alphanumeric check.
    #[test]
    fn test_kill_mutant_273_bic_location_alphanum() {
        assert!(!bic_format_check("DEUTDE!!")); // special chars in location
        assert!(bic_format_check("DEUTDE5F")); // digit in location ok
        assert!(bic_format_check("DEUTDEFF")); // letters in location ok
    }

    /// Tue : L281-287 branch alphanumeric check (11-char BIC).
    #[test]
    fn test_kill_mutant_281_bic_branch_alphanum() {
        assert!(!bic_format_check("DEUTDEFF!!!")); // special chars in branch
        assert!(bic_format_check("DEUTDEFF123")); // digits in branch ok
        assert!(bic_format_check("DEUTDEFFABC")); // letters in branch ok
    }

    /// Tue : L293 replace -> true/false (country code validation).
    #[test]
    fn test_kill_mutant_293_country_code_validation() {
        assert!(is_valid_country_code("FR"));
        assert!(is_valid_country_code("DE"));
        assert!(is_valid_country_code("US"));
        assert!(!is_valid_country_code("XX"));
        assert!(!is_valid_country_code("QQ"));
        assert!(!is_valid_country_code(""));
    }

    #[test]
    fn test_canary_bic_preserves_suffix() {
        let canary = generate_canary_bic("BNPAFRPP");
        assert!(canary.starts_with("GROB"));
        assert_eq!(&canary[4..6], "FR");
        assert_eq!(&canary[6..], "PP");
        assert_eq!(canary.len(), 8);
    }
}

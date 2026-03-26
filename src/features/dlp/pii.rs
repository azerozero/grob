use super::config::{PiiAction, PiiConfig};
use regex::Regex;
use std::sync::LazyLock;

// SAFETY: patterns are compile-time constants; unwrap cannot fail.
static CC_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(?:\d[ -]?){13,19}\b").unwrap());
static IBAN_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Z]{2}\d{2}[A-Z0-9]{12,30}\b").unwrap());
static BIC_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b").unwrap());

/// Type of PII detected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PiiType {
    /// Payment card number (Visa, Mastercard, Amex, etc.).
    CreditCard,
    /// International Bank Account Number.
    Iban,
    /// Bank Identifier Code (SWIFT).
    Bic,
}

impl std::fmt::Display for PiiType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PiiType::CreditCard => write!(f, "credit_card"),
            PiiType::Iban => write!(f, "iban"),
            PiiType::Bic => write!(f, "bic"),
        }
    }
}

/// A single PII detection event.
#[derive(Debug, Clone)]
pub struct PiiDetection {
    /// Category of PII that was detected.
    pub pii_type: PiiType,
    /// Byte offset where the match begins.
    pub start: usize,
    /// Byte offset where the match ends (exclusive).
    pub end: usize,
}

/// PII scanner with mathematical validation (Luhn, mod97, BIC format).
/// Separated from `SecretScanner` because PII requires post-match validation
/// beyond simple regex matching.
pub struct PiiScanner {
    credit_card_re: Option<&'static Regex>,
    iban_re: Option<&'static Regex>,
    bic_re: Option<&'static Regex>,
    action: PiiAction,
}

impl PiiScanner {
    /// Build a PII scanner from config. Returns `None` if all detectors are disabled.
    pub fn from_config(config: &PiiConfig) -> Option<Self> {
        let any_enabled = config.credit_cards || config.iban || config.bic;
        if !any_enabled {
            return None;
        }

        let credit_card_re = if config.credit_cards {
            Some(&*CC_REGEX)
        } else {
            None
        };

        let iban_re = if config.iban {
            Some(&*IBAN_REGEX)
        } else {
            None
        };

        let bic_re = if config.bic { Some(&*BIC_REGEX) } else { None };

        Some(Self {
            credit_card_re,
            iban_re,
            bic_re,
            action: config.action.clone(),
        })
    }

    /// Fast pre-filter: check if text could plausibly contain PII.
    /// Returns false if there aren't enough consecutive digits or uppercase letters.
    #[inline]
    pub fn might_contain_pii(&self, text: &str) -> bool {
        let bytes = text.as_bytes();
        let mut digit_run = 0u32;
        let mut upper_run = 0u32;

        for &b in bytes {
            if b.is_ascii_digit() {
                digit_run += 1;
                if digit_run >= 8 {
                    return true;
                }
            } else if b == b' ' || b == b'-' {
                // spaces/dashes don't break digit runs (credit cards)
            } else {
                digit_run = 0;
            }

            if b.is_ascii_uppercase() {
                upper_run += 1;
                if upper_run >= 8 {
                    return true;
                }
            } else if b.is_ascii_digit() {
                // digits don't break uppercase runs (IBAN: FR7630006000011234567890189)
            } else {
                upper_run = 0;
            }
        }
        false
    }

    /// Scan text, validate matches mathematically, and return redacted text + detections.
    /// Returns `None` if no valid PII found.
    pub fn redact(&self, text: &str) -> Option<(String, Vec<PiiDetection>)> {
        let mut detections = Vec::new();

        // Collect all matches with positions
        if let Some(re) = self.credit_card_re {
            for m in re.find_iter(text) {
                let digits: String = m.as_str().chars().filter(|c| c.is_ascii_digit()).collect();
                if digits.len() >= 13 && digits.len() <= 19 && luhn_check(&digits) {
                    detections.push(PiiDetection {
                        pii_type: PiiType::CreditCard,
                        start: m.start(),
                        end: m.end(),
                    });
                }
            }
        }

        if let Some(re) = self.iban_re {
            for m in re.find_iter(text) {
                if iban_mod97_check(m.as_str()) {
                    detections.push(PiiDetection {
                        pii_type: PiiType::Iban,
                        start: m.start(),
                        end: m.end(),
                    });
                }
            }
        }

        if let Some(re) = self.bic_re {
            for m in re.find_iter(text) {
                if bic_format_check(m.as_str()) {
                    detections.push(PiiDetection {
                        pii_type: PiiType::Bic,
                        start: m.start(),
                        end: m.end(),
                    });
                }
            }
        }

        if detections.is_empty() {
            return None;
        }

        // Sort by position, remove overlaps
        detections.sort_by_key(|d| d.start);

        if self.action == PiiAction::Log {
            return Some((text.to_string(), detections));
        }

        let mut result = String::with_capacity(text.len());
        let mut last_end = 0;

        for det in &detections {
            if det.start < last_end {
                continue;
            }
            result.push_str(&text[last_end..det.start]);
            match self.action {
                PiiAction::Canary => {
                    let fake = generate_pii_canary(&det.pii_type, &text[det.start..det.end]);
                    result.push_str(&fake);
                }
                PiiAction::Redact => {
                    let label = match det.pii_type {
                        PiiType::CreditCard => "[CARD REDACTED]",
                        PiiType::Iban => "[IBAN REDACTED]",
                        PiiType::Bic => "[BIC REDACTED]",
                    };
                    result.push_str(label);
                }
                PiiAction::Log => unreachable!(),
            }
            last_end = det.end;
        }
        result.push_str(&text[last_end..]);

        Some((result, detections))
    }
}

/// Luhn algorithm: validates credit card numbers.
/// Sum of alternating doubled digits mod 10 == 0.
fn luhn_check(digits: &str) -> bool {
    let mut sum: u32 = 0;
    let mut double = false;

    for ch in digits.chars().rev() {
        let mut d = ch.to_digit(10).unwrap_or(0);
        if double {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }

    sum.is_multiple_of(10)
}

/// IBAN mod97 validation (ISO 7064).
/// Rearranges country+check to end, converts letters to digits, checks mod 97 == 1.
/// Uses chunked arithmetic to avoid u64 overflow.
fn iban_mod97_check(iban: &str) -> bool {
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

/// BIC/SWIFT format validation.
/// Format: 4 letters (bank) + 2 letters (ISO 3166 country) + 2 alphanum (location)
/// + optional 3 alphanum (branch).
fn bic_format_check(bic: &str) -> bool {
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

/// Generates a syntactically valid fake PII value (canary) for transparent replacement.
/// The fake value has the same length and format as the original but different digits.
fn generate_pii_canary(pii_type: &PiiType, original: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);

    match pii_type {
        PiiType::CreditCard => generate_canary_cc(original, id),
        PiiType::Iban => generate_canary_iban(original, id),
        PiiType::Bic => format!("GROB{}{}", &original[4..6], &original[6..]),
    }
}

/// Generates a Luhn-valid fake credit card number with the same length.
fn generate_canary_cc(original: &str, id: u64) -> String {
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

    // Pad if needed
    while partial.len() < len - 1 {
        partial.push(0);
    }

    // Compute Luhn check digit
    let check = luhn_check_digit(&partial);
    partial.push(check);

    partial.iter().map(|d| (b'0' + d) as char).collect()
}

/// Computes the Luhn check digit for a sequence of digits.
fn luhn_check_digit(digits: &[u8]) -> u8 {
    let mut sum: u32 = 0;
    for (i, &d) in digits.iter().rev().enumerate() {
        let mut val = d as u32;
        if i % 2 == 0 {
            val *= 2;
            if val > 9 {
                val -= 9;
            }
        }
        sum += val;
    }
    ((10 - (sum % 10)) % 10) as u8
}

/// Generates a fake IBAN with the same country code and length.
fn generate_canary_iban(original: &str, id: u64) -> String {
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

    fn default_scanner() -> PiiScanner {
        PiiScanner::from_config(&PiiConfig {
            credit_cards: true,
            iban: true,
            bic: true,
            action: PiiAction::Redact,
        })
        .unwrap()
    }

    // ── Luhn ──────────────────────────────────────────────────

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

    // ── IBAN ──────────────────────────────────────────────────

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
        assert!(!iban_mod97_check("FR7630006000011234567890188")); // wrong check
        assert!(!iban_mod97_check("XX000000000000")); // too short / invalid
    }

    // ── BIC ───────────────────────────────────────────────────

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

    // ── Pre-filter ────────────────────────────────────────────

    #[test]
    fn test_might_contain_pii_digits() {
        let scanner = default_scanner();
        assert!(scanner.might_contain_pii("card: 4532 0151 1283 0366"));
        assert!(!scanner.might_contain_pii("hello world"));
        assert!(!scanner.might_contain_pii("short 123"));
    }

    #[test]
    fn test_might_contain_pii_uppercase() {
        let scanner = default_scanner();
        assert!(scanner.might_contain_pii("IBAN: FR7630006000011234567890189"));
        assert!(scanner.might_contain_pii("BIC: DEUTDEFF"));
    }

    // ── Integration ───────────────────────────────────────────

    #[test]
    fn test_redact_credit_card() {
        let scanner = default_scanner();
        let text = "Pay with 4532015112830366 please";
        let (redacted, detections) = scanner.redact(text).unwrap();
        assert!(redacted.contains("[CARD REDACTED]"));
        assert!(!redacted.contains("4532015112830366"));
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].pii_type, PiiType::CreditCard);
    }

    #[test]
    fn test_redact_credit_card_with_spaces() {
        let scanner = default_scanner();
        let text = "Card: 4532 0151 1283 0366 done";
        let (redacted, detections) = scanner.redact(text).unwrap();
        assert!(redacted.contains("[CARD REDACTED]"));
        assert_eq!(detections.len(), 1);
    }

    #[test]
    fn test_redact_iban() {
        let scanner = default_scanner();
        let text = "Transfer to FR7630006000011234567890189 now";
        let (redacted, detections) = scanner.redact(text).unwrap();
        assert!(redacted.contains("[IBAN REDACTED]"));
        assert!(!redacted.contains("FR7630006000011234567890189"));
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].pii_type, PiiType::Iban);
    }

    #[test]
    fn test_redact_bic() {
        let scanner = default_scanner();
        let text = "BIC is DEUTDEFF for transfer";
        let (redacted, detections) = scanner.redact(text).unwrap();
        assert!(redacted.contains("[BIC REDACTED]"));
        assert!(!redacted.contains("DEUTDEFF"));
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].pii_type, PiiType::Bic);
    }

    #[test]
    fn test_invalid_card_not_redacted() {
        let scanner = default_scanner();
        // Invalid Luhn: 1234567890123456
        let text = "number 1234567890123456 here";
        assert!(scanner.redact(text).is_none());
    }

    #[test]
    fn test_invalid_iban_not_redacted() {
        let scanner = default_scanner();
        // Invalid mod97
        let text = "IBAN: FR7630006000011234567890188";
        // This might not even match the regex if length is wrong, or fails mod97
        if let Some((_, detections)) = scanner.redact(text) {
            // If regex matched, mod97 should reject it
            assert!(
                detections.iter().all(|d| d.pii_type != PiiType::Iban),
                "Invalid IBAN should not be detected"
            );
        }
    }

    #[test]
    fn test_disabled_returns_none() {
        let config = PiiConfig {
            credit_cards: false,
            iban: false,
            bic: false,
            action: PiiAction::Redact,
        };
        assert!(PiiScanner::from_config(&config).is_none());
    }

    #[test]
    fn test_log_mode_no_redaction() {
        let scanner = PiiScanner::from_config(&PiiConfig {
            credit_cards: true,
            iban: false,
            bic: false,
            action: PiiAction::Log,
        })
        .unwrap();
        let text = "Pay with 4532015112830366 please";
        let (result, detections) = scanner.redact(text).unwrap();
        // Log mode: text unchanged but detection still reported
        assert!(result.contains("4532015112830366"));
        assert_eq!(detections.len(), 1);
    }

    #[test]
    fn test_canary_credit_card_is_luhn_valid() {
        let fake = generate_pii_canary(&PiiType::CreditCard, "4532015112830366");
        assert_eq!(fake.len(), 16, "Canary CC must be 16 digits");
        assert!(luhn_check(&fake), "Canary CC must pass Luhn: {fake}");
        assert_ne!(fake, "4532015112830366", "Canary must differ from original");
    }

    #[test]
    fn test_canary_iban_is_valid() {
        let fake = generate_pii_canary(&PiiType::Iban, "FR7630006000011234567890189");
        assert!(fake.starts_with("FR"), "Canary IBAN keeps country code");
        assert_eq!(fake.len(), 27, "Canary IBAN same length as original");
    }

    #[test]
    fn test_canary_mode_replaces_with_fake() {
        let config = PiiConfig {
            credit_cards: true,
            iban: true,
            bic: false,
            action: PiiAction::Canary,
        };
        let scanner = PiiScanner::from_config(&config).expect("scanner");
        let text = "Pay with 4532015112830366 please";
        let r = scanner.redact(text);
        assert!(r.is_some(), "Expected canary CC detection");
        let r = r.unwrap();
        assert!(
            !r.0.contains("4532015112830366"),
            "Original CC must be gone"
        );
        assert!(
            !r.0.contains("[CARD REDACTED]"),
            "Must not use redaction label"
        );
        assert!(Vec::len(&r.1) == 1);
    }

    #[test]
    fn test_false_positive_rejection_random_digits() {
        let scanner = default_scanner();
        // Random 16-digit number that fails Luhn
        let text = "ID: 9876543210987654 ref";
        // Should not be detected (fails Luhn)
        if let Some((_, detections)) = scanner.redact(text) {
            assert!(
                detections.is_empty(),
                "Random digits should fail Luhn validation"
            );
        }
    }
}

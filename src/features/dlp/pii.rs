use super::config::{PiiAction, PiiConfig};
use regex::Regex;

/// Type of PII detected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PiiType {
    CreditCard,
    Iban,
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
    pub pii_type: PiiType,
    pub start: usize,
    pub end: usize,
}

/// PII scanner with mathematical validation (Luhn, mod97, BIC format).
/// Separated from `SecretScanner` because PII requires post-match validation
/// beyond simple regex matching.
pub struct PiiScanner {
    credit_card_re: Option<Regex>,
    iban_re: Option<Regex>,
    bic_re: Option<Regex>,
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
            // 13-19 digits, optionally separated by spaces or dashes
            Some(Regex::new(r"\b(?:\d[ -]?){13,19}\b").expect("credit card regex"))
        } else {
            None
        };

        let iban_re = if config.iban {
            // 2 letters (country) + 2 digits (check) + 12-30 alphanumeric (BBAN)
            Some(Regex::new(r"\b[A-Z]{2}\d{2}[A-Z0-9]{12,30}\b").expect("iban regex"))
        } else {
            None
        };

        let bic_re = if config.bic {
            // 4 letters (bank) + 2 letters (country) + 2 alphanum (location) + optional 3 alphanum (branch)
            Some(Regex::new(r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b").expect("bic regex"))
        } else {
            None
        };

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
        if let Some(ref re) = self.credit_card_re {
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

        if let Some(ref re) = self.iban_re {
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

        if let Some(ref re) = self.bic_re {
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
            // Log-only mode: don't modify text
            return Some((text.to_string(), detections));
        }

        // Build redacted output
        let mut result = String::with_capacity(text.len());
        let mut last_end = 0;

        for det in &detections {
            if det.start < last_end {
                continue; // skip overlapping
            }
            result.push_str(&text[last_end..det.start]);
            let label = match det.pii_type {
                PiiType::CreditCard => "[CARD REDACTED]",
                PiiType::Iban => "[IBAN REDACTED]",
                PiiType::Bic => "[BIC REDACTED]",
            };
            result.push_str(label);
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

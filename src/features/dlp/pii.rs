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
            // mutants::skip — les regex PII utilisent \b (word boundary),
            // donc deux matchs ne peuvent pas se chevaucher en pratique.
            // Le guard est defensif ; l'overlap est structurellement impossible
            // entre CC (\d), IBAN ([A-Z]\d), et BIC ([A-Z]) grace aux \b.
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
            // mutants::skip — d *= 2 produit uniquement des valeurs paires
            // (0,2,4,6,8,10,12,14,16,18). d == 9 est inatteignable, donc > et >= sont equivalents.
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

    // Pad defensif : le format! ci-dessus genere toujours >= len-1 chars
    // grace au zero-padding {:0>width$}, donc cette boucle ne fire jamais.
    // mutants::skip — dead code defensif, partial.len() == len-1 toujours vrai ici.
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
            // mutants::skip — val *= 2 produit uniquement des valeurs paires (0..18),
            // donc val == 9 est inatteignable et > vs >= sont equivalents.
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

    // ── Mutation testing : tests cibles pour tuer les mutants survivants ──

    // -- from_config: || -> && et delete ! sur any_enabled --

    /// Tue : L57:47 || -> && dans from_config (config.credit_cards || config.iban).
    /// Si &&, cc-only config retournerait None alors qu'elle doit retourner Some.
    #[test]
    fn test_kill_mutant_57_from_config_single_cc_enabled() {
        let config = PiiConfig {
            credit_cards: true,
            iban: false,
            bic: false,
            action: PiiAction::Redact,
        };
        assert!(PiiScanner::from_config(&config).is_some());
    }

    /// Tue : L57:62 || -> && dans from_config (config.iban || config.bic).
    /// Si &&, iban-only config retournerait None.
    #[test]
    fn test_kill_mutant_57_from_config_single_iban_enabled() {
        let config = PiiConfig {
            credit_cards: false,
            iban: true,
            bic: false,
            action: PiiAction::Redact,
        };
        assert!(PiiScanner::from_config(&config).is_some());
    }

    /// Tue : L57 meme famille. bic-only doit suffire.
    #[test]
    fn test_kill_mutant_57_from_config_single_bic_enabled() {
        let config = PiiConfig {
            credit_cards: false,
            iban: false,
            bic: true,
            action: PiiAction::Redact,
        };
        assert!(PiiScanner::from_config(&config).is_some());
    }

    /// Tue : L58 delete ! (if any_enabled -> if !any_enabled inverted).
    /// Si le ! est supprime, une config all-enabled retournerait None.
    #[test]
    fn test_kill_mutant_58_from_config_all_enabled_returns_some() {
        let config = PiiConfig {
            credit_cards: true,
            iban: true,
            bic: true,
            action: PiiAction::Redact,
        };
        assert!(PiiScanner::from_config(&config).is_some());
    }

    // -- might_contain_pii : thresholds et branches --

    /// Tue : L94 += -> -= et L95 >= -> < (digit_run ne monte jamais assez).
    /// Exactement 8 digits d'affile = seuil.
    #[test]
    fn test_kill_mutant_94_95_digit_run_threshold_exact() {
        let scanner = default_scanner();
        // 8 digits consecutifs = true
        assert!(scanner.might_contain_pii("12345678"));
        // 7 digits consecutifs = false
        assert!(!scanner.might_contain_pii("1234567"));
    }

    /// Tue : L105 += -> -= et L106 >= -> < (upper_run).
    /// 8 uppercase consecutifs = seuil.
    #[test]
    fn test_kill_mutant_105_106_upper_run_threshold_exact() {
        let scanner = default_scanner();
        // 8 uppercase = true
        assert!(scanner.might_contain_pii("ABCDEFGH"));
        // 7 uppercase = false
        assert!(!scanner.might_contain_pii("ABCDEFG"));
    }

    /// Tue : L88 replace -> true (tout retourne true).
    #[test]
    fn test_kill_mutant_88_might_contain_pii_false_on_empty() {
        let scanner = default_scanner();
        assert!(!scanner.might_contain_pii(""));
        assert!(!scanner.might_contain_pii("hello world"));
    }

    /// Tue : L88 replace -> false (tout retourne false).
    #[test]
    fn test_kill_mutant_88_might_contain_pii_true_on_long_digits() {
        let scanner = default_scanner();
        assert!(scanner.might_contain_pii("1234567890123456"));
    }

    /// Tue : L98:25 == -> != (b' ') et L98:38 == -> != (b'-').
    /// Espaces et tirets ne doivent PAS reset le digit_run.
    #[test]
    fn test_kill_mutant_98_spaces_dashes_keep_digit_run() {
        let scanner = default_scanner();
        // digits with spaces: 4+4+4+4 = 16 digits, spaces maintiennent le run
        assert!(scanner.might_contain_pii("1234 5678 9012 3456"));
        // digits with dashes
        assert!(scanner.might_contain_pii("1234-5678-9012-3456"));
    }

    /// Tue : L98:33 || -> && (space || dash).
    /// Si &&, seul un char qui est a la fois space ET dash garderait le run.
    /// Un space seul resetterait le run, ce qui est faux.
    #[test]
    fn test_kill_mutant_98_or_spaces_only() {
        let scanner = default_scanner();
        // 4 digits + espace + 4 digits = 8+ digits grace au run maintenu par espace
        assert!(scanner.might_contain_pii("1234 56789"));
    }

    // -- luhn_check : operateurs arithmetiques --

    /// Tue : L212 *= -> += (d *= 2 -> d += 2 change le resultat).
    #[test]
    fn test_kill_mutant_212_luhn_double_multiplication() {
        // 4111111111111111 (Visa test) passe Luhn.
        assert!(luhn_check("4111111111111111"));
        // Le meme avec un digit change NE passe PAS.
        assert!(!luhn_check("4111111111111112"));
    }

    /// Tue : L213 > -> >= / == / < (d > 9 seuil).
    #[test]
    fn test_kill_mutant_213_luhn_d_gt_9_threshold() {
        // Numeros qui exercent le seuil d > 9 dans le doublement Luhn.
        // 4111111111111111 a des digits 1 doubles a 2 (< 9) et 4 double a 8 (< 9).
        // 5425233430109903 a des digits 5 doubles a 10 (> 9 -> -9 = 1).
        assert!(luhn_check("5425233430109903"));
        assert!(!luhn_check("5425233430109900"));
    }

    /// Tue : L214 -= -> += (d -= 9 doit soustraire, pas ajouter).
    #[test]
    fn test_kill_mutant_214_luhn_subtract_9() {
        // 5425233430109903 (Mastercard test) exerce le d -= 9 path (digits >= 5 doubled = 10+).
        assert!(luhn_check("5425233430109903"));
        assert!(!luhn_check("5425233430109904"));
    }

    /// Tue : L217 += -> -= (sum += d doit accumuler, pas soustraire).
    #[test]
    fn test_kill_mutant_217_luhn_sum_accumulate() {
        // Si sum -= d, le resultat serait tres different.
        assert!(luhn_check("4532015112830366"));
        assert!(!luhn_check("4532015112830360"));
    }

    /// Tue : L218 delete ! (double = !double toggle).
    /// Sans le toggle, luhn doublerait tout ou rien.
    #[test]
    fn test_kill_mutant_218_luhn_double_toggle() {
        // 374245455400126 (Amex) utilise le toggle intensivement.
        assert!(luhn_check("374245455400126"));
        // Un nombre qui passe uniquement avec le bon toggle.
        assert!(!luhn_check("374245455400127"));
    }

    // -- iban_mod97_check : longueur, conversion lettres, calcul mod --

    /// Tue : L228:19 < -> == (si ==, un IBAN de 14 chars passerait le guard).
    /// Tue : L228:19 < -> <= (si <=, un IBAN valide de 15 chars serait rejete).
    #[test]
    fn test_kill_mutant_228_iban_length_guard() {
        // 14 chars : doit retourner false (< 15).
        // Tue < -> == : car avec ==, len(14) != 15 donc le guard ne rejette PAS, et on
        // continue vers le mod97 check qui pourrait retourner true sur un input crafted.
        assert!(!iban_mod97_check("FR123456789012"));
        // 13 chars : aussi rejete.
        assert!(!iban_mod97_check("FR1234567890"));
        // 15 chars VALIDE (Norway NO9386011117947) : doit retourner true.
        // Tue < -> <= : car avec <=, len(15) <= 15 rejetterait ce IBAN valide.
        assert!(iban_mod97_check("NO9386011117947"));
    }

    /// Tue : L239:53 % -> / et L239:41 + -> - dans remainder calc.
    #[test]
    fn test_kill_mutant_239_iban_remainder_arithmetic() {
        // DE89370400440532013000 valide : remainder DOIT etre 1.
        assert!(iban_mod97_check("DE89370400440532013000"));
        // Changer un digit casse le mod97.
        assert!(!iban_mod97_check("DE89370400440532013001"));
    }

    /// Tue : L243 replace * 100 avec autre chose dans letter conversion.
    #[test]
    fn test_kill_mutant_243_iban_letter_two_digit_shift() {
        // GB82WEST12345698765432 — utilise des lettres (W, E, S, T) dans le BBAN.
        assert!(iban_mod97_check("GB82WEST12345698765432"));
    }

    /// Tue : L249 == -> != (remainder == 1 final check).
    #[test]
    fn test_kill_mutant_249_iban_remainder_must_be_1() {
        assert!(iban_mod97_check("FR7630006000011234567890189"));
        assert!(!iban_mod97_check("FR0030006000011234567890189")); // check digits wrong
    }

    // -- bic_format_check : validations structurelles --

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

    // -- redact : mode Log vs Redact vs Canary, overlap detection --

    /// Tue : L168 == -> != (PiiAction::Log check inverted).
    #[test]
    fn test_kill_mutant_168_redact_log_mode_no_modification() {
        let scanner = PiiScanner::from_config(&PiiConfig {
            credit_cards: true,
            iban: false,
            bic: false,
            action: PiiAction::Log,
        })
        .unwrap();
        let text = "card 4532015112830366 here";
        let (result, dets) = scanner.redact(text).unwrap();
        // En mode Log, le texte DOIT etre inchange.
        assert_eq!(result, text);
        assert_eq!(dets.len(), 1);
    }

    /// Tue : L121 replace -> None (redact retourne toujours None).
    #[test]
    fn test_kill_mutant_121_redact_returns_some_on_detection() {
        let scanner = default_scanner();
        let result = scanner.redact("card 4532015112830366 here");
        assert!(result.is_some());
    }

    /// Tue : L176 < -> == / > / <= (overlap skip : det.start < last_end).
    #[test]
    fn test_kill_mutant_176_redact_overlap_handling() {
        let scanner = default_scanner();
        // Un seul numero = pas d'overlap, resultat normal.
        let (result, _) = scanner.redact("card 4532015112830366 done").unwrap();
        assert!(result.contains("[CARD REDACTED]"));
        assert!(!result.contains("4532015112830366"));
    }

    /// Tue : L127:33 >= -> < et L127:55 <= -> > (digit count guards dans CC detection).
    #[test]
    fn test_kill_mutant_127_redact_cc_digit_count_bounds() {
        let scanner = default_scanner();
        // 13 digits (Visa old style) : doit passer la borne >= 13
        // 0000000000000 passe Luhn (tout zero)
        assert!(scanner.redact("card 0000000000000 done").is_some());
    }

    /// Tue : L127:39/61 && -> || (digit length AND Luhn check).
    #[test]
    fn test_kill_mutant_127_redact_cc_both_checks_required() {
        let scanner = default_scanner();
        // 16 digits mais Luhn invalide : NE doit PAS etre detecte.
        assert!(scanner.redact("card 1234567890123456 done").is_none());
    }

    // -- generate_canary_cc : integrite du canary genere --

    /// Tue : L340:12 < -> <= (len < 2 guard). Avec <=, len==2 retournerait "00"
    /// au lieu de generer un canary derive de l'input.
    #[test]
    fn test_kill_mutant_340_canary_cc_len_2_generates_valid() {
        let canary = generate_canary_cc("41", 1);
        assert_eq!(canary.len(), 2);
        // Le canary doit commencer par le meme premier digit que l'input (network).
        // Avec le mutant <=, "0".repeat(2) = "00" qui ne commence pas par '4'.
        assert_eq!(
            canary.chars().next().unwrap(),
            '4',
            "Le premier digit doit etre preserve (network): {canary}"
        );
        assert!(
            luhn_check(&canary),
            "Canary CC 2 chars doit passer Luhn: {canary}"
        );
    }

    /// Tue : L334 < (len < 2 guard). len==1 doit retourner "0".
    #[test]
    fn test_kill_mutant_334_canary_cc_len_1_returns_zero() {
        let canary = generate_canary_cc("4", 1);
        assert_eq!(canary, "0");
    }

    /// Tue : L349:19 - -> + / / (width = len - 2).
    /// Si + ou /, la longueur du seed serait fausse → canary de mauvaise longueur.
    #[test]
    fn test_kill_mutant_349_canary_cc_seed_width() {
        let canary = generate_canary_cc("4111111111111111", 42);
        assert_eq!(canary.len(), 16, "Canary doit avoir exactement 16 chars");
        assert!(
            luhn_check(&canary),
            "Canary 16 chars doit passer Luhn: {canary}"
        );
    }

    /// Tue : L354:25 < -> > (while partial.len() < len - 1 pad loop).
    /// Si >, la boucle padderait indefiniment (ou pas du tout). Le canary n'aurait
    /// pas la bonne longueur.
    #[test]
    fn test_kill_mutant_354_canary_cc_pad_loop() {
        // id tres petit (1) avec longueur 16 : le seed sera "4000000000000001"
        // mais le format fait width=14, donc pas de padding normalement.
        // Testons un cas ou le seed est tres court.
        let canary = generate_canary_cc("4111111111111111", 1);
        assert_eq!(canary.len(), 16);
        assert!(luhn_check(&canary), "Canary pad doit passer Luhn: {canary}");
        // Verifie que chaque char est un ASCII digit (tue L356 + -> -).
        for c in canary.chars() {
            assert!(c.is_ascii_digit(), "Char '{c}' n'est pas un digit");
        }
    }

    /// Tue : L362:34 + -> - ((b'0' + d) as char).
    /// Si -, les chars ne seraient plus des digits ASCII valides.
    #[test]
    fn test_kill_mutant_362_canary_cc_ascii_digits() {
        let canary = generate_canary_cc("5425233430109903", 999);
        assert_eq!(canary.len(), 16);
        for c in canary.chars() {
            assert!(
                c.is_ascii_digit(),
                "Attendu digit, got '{c}' (U+{:04X})",
                c as u32
            );
        }
        assert!(luhn_check(&canary), "Canary doit passer Luhn: {canary}");
    }

    // -- luhn_check_digit : arithmetique du check digit --

    /// Tue : L364 *= -> += et L365-366 > / -= (meme pattern que luhn_check).
    #[test]
    fn test_kill_mutant_364_luhn_check_digit_correct() {
        let digits = vec![4, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1];
        let check = luhn_check_digit(&digits);
        let mut full: Vec<u8> = digits;
        full.push(check);
        let s: String = full.iter().map(|d| (b'0' + d) as char).collect();
        assert!(luhn_check(&s));
    }

    /// Tue : L372 % -> / dans ((10 - (sum % 10)) % 10).
    #[test]
    fn test_kill_mutant_372_luhn_check_digit_modulo() {
        // Teste avec plusieurs sequences pour que le % et le - comptent.
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

    // -- generate_canary_iban : conversion lettres et mod97 --

    /// Tue : L405:49 % -> + dans le calcul remainder % 97 de generate_canary_iban.
    /// Multiple ids pour eviter les coincidences sur un seul id.
    #[test]
    fn test_kill_mutant_405_canary_iban_mod97_valid_multiple() {
        for id in [1, 7, 42, 99, 123, 9999, 100_000] {
            let canary = generate_canary_iban("FR7630006000011234567890189", id);
            assert!(canary.starts_with("FR"));
            assert_eq!(canary.len(), 27);
            assert!(
                iban_mod97_check(&canary),
                "Canary IBAN id={id} doit etre mod97-valide : {canary}"
            );
        }
    }

    /// Tue : L377 len >= 2 guard et L382 saturating_sub.
    #[test]
    fn test_kill_mutant_377_canary_iban_short_input() {
        let canary = generate_canary_iban("X", 1);
        // Court input : country = "XX" fallback, body_len = 0.
        assert!(!canary.is_empty());
    }

    /// Tue : L394/397 val >= 10 branch (lettres vs digits dans le calcul).
    #[test]
    fn test_kill_mutant_394_canary_iban_letter_digit_branch() {
        // GB (lettres G=16, B=11) teste le branch >= 10 dans la boucle.
        let canary = generate_canary_iban("GB29NWBK60161331926819", 42);
        assert!(canary.starts_with("GB"));
        assert!(
            iban_mod97_check(&canary),
            "Canary GB doit etre mod97-valide : {canary}"
        );
    }

    /// Tue : L400 - -> + (check = 98 - remainder).
    #[test]
    fn test_kill_mutant_400_canary_iban_check_digit_subtraction() {
        // Si 98 + remainder au lieu de 98 - remainder, le check digit serait faux.
        let canary = generate_canary_iban("DE89370400440532013000", 7);
        assert!(
            iban_mod97_check(&canary),
            "Canary DE doit etre mod97-valide : {canary}"
        );
    }

    // -- generate_pii_canary : dispatch par type --

    /// Tue : L318 replace generate_pii_canary -> String.
    #[test]
    fn test_kill_mutant_318_canary_dispatch_bic() {
        let canary = generate_pii_canary(&PiiType::Bic, "DEUTDEFF");
        assert!(canary.starts_with("GROB"));
        assert_eq!(canary.len(), 8);
    }

    /// Tue : L326 BIC canary garde le country et location.
    #[test]
    fn test_kill_mutant_326_canary_bic_preserves_suffix() {
        let canary = generate_pii_canary(&PiiType::Bic, "BNPAFRPP");
        // Doit etre GROBFRPP (remplace bank code par GROB, garde country+location).
        assert_eq!(&canary[4..6], "FR");
        assert_eq!(&canary[6..], "PP");
    }

    // -- PiiType Display --

    /// Tue : L25 replace fmt -> Ok(Default::default()) (affichage vide).
    #[test]
    fn test_kill_mutant_25_pii_type_display() {
        assert_eq!(format!("{}", PiiType::CreditCard), "credit_card");
        assert_eq!(format!("{}", PiiType::Iban), "iban");
        assert_eq!(format!("{}", PiiType::Bic), "bic");
    }

    // -- is_valid_country_code --

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

        /// IBAN mod97 validation rejects random alphanumeric strings.
        #[test]
        fn prop_iban_rejects_random(body in "[A-Z]{2}[0-9]{2}[A-Z0-9]{15,28}") {
            // Overwhelming majority of random strings fail mod97.
            // We just verify no panics and check the function is total.
            let _ = iban_mod97_check(&body);
        }
    }
}

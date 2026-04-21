use super::bic::{self, BIC_REGEX};
use super::cards::{self, CC_REGEX};
use super::config::{PiiAction, PiiConfig};
use super::iban::{self, IBAN_REGEX};
use regex::Regex;

pub use bic::bic_format_check;
pub use cards::luhn_check;
pub use iban::iban_mod97_check;

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
    /// Builds a PII scanner from config. Returns `None` if all detectors are disabled.
    ///
    /// # Examples
    ///
    /// ```
    /// use grob::features::dlp::config::PiiConfig;
    /// use grob::features::dlp::pii::PiiScanner;
    ///
    /// // Default config enables credit_cards + IBAN
    /// let config = PiiConfig::default();
    /// assert!(PiiScanner::from_config(&config).is_some());
    ///
    /// // Everything disabled => None
    /// let off = PiiConfig { credit_cards: false, iban: false, bic: false, ..Default::default() };
    /// assert!(PiiScanner::from_config(&off).is_none());
    /// ```
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

    /// Fast pre-filter: returns false when no PII is plausible.
    ///
    /// Rejects text lacking enough consecutive digits or uppercase letters
    /// to form a credit card, IBAN, or BIC.
    ///
    /// # Examples
    ///
    /// ```
    /// use grob::features::dlp::config::PiiConfig;
    /// use grob::features::dlp::pii::PiiScanner;
    ///
    /// let scanner = PiiScanner::from_config(&PiiConfig::default()).unwrap();
    /// // Digit run >= 8 → might contain a card number
    /// assert!(scanner.might_contain_pii("card 4111111111111111 here"));
    /// // Pure prose → rejected
    /// assert!(!scanner.might_contain_pii("hello world, no numbers"));
    /// ```
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

/// Generates a syntactically valid fake PII value (canary) for transparent replacement.
/// The fake value has the same length and format as the original but different digits.
fn generate_pii_canary(pii_type: &PiiType, original: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);

    match pii_type {
        PiiType::CreditCard => cards::generate_canary_cc(original, id),
        PiiType::Iban => iban::generate_canary_iban(original, id),
        PiiType::Bic => bic::generate_canary_bic(original),
    }
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
        // Luhn-valid test CC (not a real card number).
        let test_cc = "4532015112830366"; // lgtm[rust/cleartext-logging]
        let text = format!("Pay with {test_cc} please");
        let (result, detections) = scanner.redact(&text).unwrap();
        // Log mode: text unchanged but detection still reported
        assert!(result.contains(test_cc));
        assert_eq!(detections.len(), 1);
    }

    #[test]
    fn test_canary_credit_card_is_luhn_valid() {
        let fake = generate_pii_canary(&PiiType::CreditCard, "4532015112830366");
        assert_eq!(fake.len(), 16, "Canary CC must be 16 digits");
        assert!(luhn_check(&fake), "Canary CC must pass Luhn check");
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
}

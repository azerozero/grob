use super::config::{NameAction, NameRule};
use aho_corasick::AhoCorasick;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Bidirectional name anonymizer using Aho-Corasick for O(n) multi-pattern matching.
pub struct NameAnonymizer {
    /// Forward automaton: real names → pseudonyms.
    forward_ac: AhoCorasick,
    /// Reverse automaton: pseudonyms → real names.
    reverse_ac: AhoCorasick,
    rules: Vec<NameRule>,
    /// HMAC key for deterministic pseudonym generation.
    #[allow(dead_code)]
    secret_key: [u8; 32],
    /// Precomputed pseudonyms (parallel to rules).
    pseudonyms: Vec<String>,
}

impl NameAnonymizer {
    pub fn new(rules: &[NameRule]) -> Self {
        let secret_key = Self::derive_key();
        Self::build(rules, &secret_key)
    }

    /// Build with a session-specific seed mixed into the HMAC key.
    /// Different seeds produce different pseudonyms for the same names.
    pub fn new_with_session(rules: &[NameRule], session_seed: &[u8]) -> Self {
        let base_key = Self::derive_key();
        let mut mac = HmacSha256::new_from_slice(&base_key).expect("HMAC key valid");
        mac.update(session_seed);
        let session_key: [u8; 32] = mac.finalize().into_bytes().into();
        Self::build(rules, &session_key)
    }

    fn build(rules: &[NameRule], secret_key: &[u8; 32]) -> Self {
        let pseudonyms: Vec<String> = rules
            .iter()
            .map(|r| Self::compute_pseudonym(&r.term, secret_key))
            .collect();

        let forward_patterns: Vec<&str> = rules.iter().map(|r| r.term.as_str()).collect();
        let forward_ac = if forward_patterns.is_empty() {
            {
                let empty: Vec<&str> = vec![];
                AhoCorasick::builder().build(&empty).unwrap()
            }
        } else {
            AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(&forward_patterns)
                .expect("DLP name patterns must be valid")
        };

        let reverse_patterns: Vec<&str> = pseudonyms.iter().map(|p| p.as_str()).collect();
        let reverse_ac = if reverse_patterns.is_empty() {
            {
                let empty: Vec<&str> = vec![];
                AhoCorasick::builder().build(&empty).unwrap()
            }
        } else {
            AhoCorasick::builder()
                .build(&reverse_patterns)
                .expect("DLP pseudonym patterns must be valid")
        };

        Self {
            forward_ac,
            reverse_ac,
            rules: rules.to_vec(),
            secret_key: *secret_key,
            pseudonyms,
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Replace real names → pseudonyms. Returns None if no match found (zero allocation).
    pub fn anonymize_if_match(&self, text: &str) -> Option<(String, Vec<(String, String)>)> {
        if self.rules.is_empty() {
            return None;
        }

        // Fast check: does any pattern match at all?
        self.forward_ac.find(text)?;

        let mut result = String::with_capacity(text.len());
        let mut replacements = Vec::new();
        let mut last_end = 0;

        for mat in self.forward_ac.find_iter(text) {
            let idx = mat.pattern().as_usize();
            let rule = &self.rules[idx];

            result.push_str(&text[last_end..mat.start()]);

            match rule.action {
                NameAction::Pseudonym => {
                    let pseudo = &self.pseudonyms[idx];
                    result.push_str(pseudo);
                    replacements.push((rule.term.clone(), pseudo.clone()));
                }
                NameAction::Redact => {
                    result.push_str("[NAME]");
                    replacements.push((rule.term.clone(), "[NAME]".into()));
                }
                NameAction::Log => {
                    result.push_str(&text[mat.start()..mat.end()]);
                    replacements.push((rule.term.clone(), rule.term.clone()));
                }
            }

            last_end = mat.end();
        }

        result.push_str(&text[last_end..]);
        Some((result, replacements))
    }

    /// Replace pseudonyms → real names. Returns None if no match found (zero allocation).
    pub fn deanonymize_if_match(&self, text: &str) -> Option<String> {
        if self.rules.is_empty() {
            return None;
        }

        // Fast check: does any pseudonym appear?
        self.reverse_ac.find(text)?;

        let mut result = String::with_capacity(text.len());
        let mut last_end = 0;

        for mat in self.reverse_ac.find_iter(text) {
            let idx = mat.pattern().as_usize();
            result.push_str(&text[last_end..mat.start()]);
            result.push_str(&self.rules[idx].term);
            last_end = mat.end();
        }

        result.push_str(&text[last_end..]);
        Some(result)
    }

    fn derive_key() -> [u8; 32] {
        if let Ok(secret) = std::env::var("GROB_DLP_SECRET") {
            let mut mac =
                HmacSha256::new_from_slice(b"grob-dlp-key-derivation").expect("HMAC key valid");
            mac.update(secret.as_bytes());
            mac.finalize().into_bytes().into()
        } else {
            tracing::warn!(
                "DLP: GROB_DLP_SECRET not set, using default key. \
                 Pseudonyms are predictable. Set GROB_DLP_SECRET for production use."
            );
            let mut mac =
                HmacSha256::new_from_slice(b"grob-dlp-default-key").expect("HMAC key valid");
            mac.update(b"pseudonym-generation");
            mac.finalize().into_bytes().into()
        }
    }

    fn compute_pseudonym(name: &str, key: &[u8; 32]) -> String {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key valid");
        mac.update(name.to_lowercase().as_bytes());
        let hash = mac.finalize().into_bytes();

        let adj_idx = u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]) as usize;
        let noun_idx = u32::from_le_bytes([hash[4], hash[5], hash[6], hash[7]]) as usize;
        let hex_suffix = format!("{:02x}{:02x}", hash[8], hash[9]);

        let adj = ADJECTIVES[adj_idx % ADJECTIVES.len()];
        let noun = NOUNS[noun_idx % NOUNS.len()];

        format!("{}-{}-{}", adj, noun, hex_suffix)
    }
}

/// 64 adjectives × 64 nouns = 4096 combinations, plus hex suffix for collision resistance.
const ADJECTIVES: &[&str] = &[
    "Alpha", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot", "Golf", "Hotel", "India", "Juliet",
    "Kilo", "Lima", "Mike", "November", "Oscar", "Papa", "Quebec", "Romeo", "Sierra", "Tango",
    "Uniform", "Victor", "Whiskey", "Xray", "Yankee", "Zulu", "Iron", "Copper", "Silver", "Golden",
    "Cobalt", "Onyx", "Arctic", "Boreal", "Crimson", "Dusk", "Ember", "Frost", "Granite", "Hollow",
    "Ivory", "Jasper", "Kelvin", "Lunar", "Mist", "Noble", "Orbit", "Prism", "Radiant", "Stellar",
    "Tempest", "Ultra", "Vivid", "Winter", "Zenith", "Azure", "Beryl", "Citrine", "Dune", "Flint",
    "Glacier", "Helix", "Indigo", "Jet",
];

const NOUNS: &[&str] = &[
    "Phoenix",
    "Falcon",
    "Eagle",
    "Condor",
    "Hawk",
    "Raven",
    "Sparrow",
    "Crane",
    "Osprey",
    "Heron",
    "Pelican",
    "Albatross",
    "Starling",
    "Finch",
    "Robin",
    "Wren",
    "Cedar",
    "Maple",
    "Birch",
    "Willow",
    "Pine",
    "Oak",
    "Elm",
    "Ash",
    "Coral",
    "Amber",
    "Jade",
    "Pearl",
    "Opal",
    "Quartz",
    "Topaz",
    "Garnet",
    "Lynx",
    "Otter",
    "Puma",
    "Fox",
    "Wolf",
    "Bear",
    "Seal",
    "Elk",
    "Agate",
    "Basalt",
    "Cinder",
    "Drift",
    "Ember",
    "Forge",
    "Gale",
    "Helm",
    "Isle",
    "Jetty",
    "Knoll",
    "Ledge",
    "Mesa",
    "North",
    "Pass",
    "Ridge",
    "Shoal",
    "Tor",
    "Vale",
    "Arch",
    "Brook",
    "Cape",
    "Dell",
    "Fjord",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn test_rules() -> Vec<NameRule> {
        vec![
            NameRule {
                term: "Thales".into(),
                action: NameAction::Pseudonym,
            },
            NameRule {
                term: "Projet Neptune".into(),
                action: NameAction::Pseudonym,
            },
        ]
    }

    #[test]
    fn test_anonymize_replaces_names() {
        let anon = NameAnonymizer::new(&test_rules());
        let result = anon.anonymize_if_match("Working at Thales on Projet Neptune");
        assert!(result.is_some());
        let (text, replacements) = result.unwrap();
        assert!(!text.contains("Thales"));
        assert!(!text.contains("Projet Neptune"));
        assert_eq!(replacements.len(), 2);
    }

    #[test]
    fn test_no_match_returns_none() {
        let anon = NameAnonymizer::new(&test_rules());
        assert!(anon.anonymize_if_match("Hello world").is_none());
    }

    #[test]
    fn test_deterministic_pseudonyms() {
        let anon1 = NameAnonymizer::new(&test_rules());
        let anon2 = NameAnonymizer::new(&test_rules());
        let r1 = anon1.anonymize_if_match("Thales").unwrap().0;
        let r2 = anon2.anonymize_if_match("Thales").unwrap().0;
        assert_eq!(r1, r2, "Same name should always produce same pseudonym");
    }

    #[test]
    fn test_deanonymize_reverses() {
        let anon = NameAnonymizer::new(&test_rules());
        let (anonymized, _) = anon.anonymize_if_match("Working at Thales").unwrap();
        let restored = anon.deanonymize_if_match(&anonymized);
        assert!(restored.is_some());
        assert_eq!(restored.unwrap(), "Working at Thales");
    }

    #[test]
    fn test_deanonymize_no_match_returns_none() {
        let anon = NameAnonymizer::new(&test_rules());
        assert!(anon.deanonymize_if_match("Hello world").is_none());
    }

    #[test]
    fn test_case_insensitive_forward() {
        let anon = NameAnonymizer::new(&test_rules());
        let result = anon.anonymize_if_match("Working at THALES");
        assert!(result.is_some());
        let (text, replacements) = result.unwrap();
        assert!(!text.to_lowercase().contains("thales"));
        assert_eq!(replacements.len(), 1);
    }

    #[test]
    fn test_empty_anonymizer() {
        let anon = NameAnonymizer::new(&[]);
        assert!(anon.is_empty());
        assert!(anon.anonymize_if_match("anything").is_none());
    }

    #[test]
    fn test_redact_action() {
        let rules = vec![NameRule {
            term: "Secret".into(),
            action: NameAction::Redact,
        }];
        let anon = NameAnonymizer::new(&rules);
        let result = anon.anonymize_if_match("The Secret project");
        assert!(result.is_some());
        let (text, _) = result.unwrap();
        assert!(text.contains("[NAME]"));
        assert!(!text.contains("Secret"));
    }
}

/// Entropy alert from SPRT async scan.
#[derive(Debug, Clone)]
pub struct EntropyAlert {
    pub start: usize,
    pub end: usize,
    pub entropy: f32,
    pub text_snippet: String,
}

/// Async SPRT (Sequential Probability Ratio Test) detector for unknown high-entropy sequences.
/// Runs post-stream, never blocks. Uses Shannon entropy on sliding windows.
pub struct SprtDetector {
    /// Minimum window size to consider (bytes).
    min_window: usize,
    /// Shannon entropy threshold (bits/byte) above which a window is suspicious.
    /// Natural English ~3.5-4.5, base64 ~5.5-6.0, random ~7.5-8.0.
    entropy_threshold: f32,
    /// SPRT log-likelihood ratio bounds.
    upper_bound: f32, // ln((1-beta)/alpha)
    lower_bound: f32, // ln(beta/(1-alpha))
}

impl Default for SprtDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SprtDetector {
    pub fn new() -> Self {
        let alpha = 0.01_f32; // false positive rate
        let beta = 0.01_f32; // false negative rate

        Self {
            min_window: 16,
            entropy_threshold: 5.5,
            upper_bound: ((1.0 - beta) / alpha).ln(),
            lower_bound: (beta / (1.0 - alpha)).ln(),
        }
    }

    /// Scan completed response text for unknown high-entropy sequences.
    /// Returns positions of suspicious sequences (for logging, not blocking).
    pub fn scan(&self, text: &str) -> Vec<EntropyAlert> {
        if text.len() < self.min_window {
            return Vec::new();
        }

        let mut alerts = Vec::new();

        // Split by whitespace to get tokens (safe for UTF-8, no byte-indexing)
        let mut search_start = 0;
        for token in text.split_whitespace() {
            // Find the byte offset of this token in the original text
            let token_start = text[search_start..]
                .find(token)
                .map(|pos| search_start + pos)
                .unwrap_or(search_start);
            let token_end = token_start + token.len();
            search_start = token_end;

            // Token-length heuristic: short tokens (< min_window) are unlikely to be secrets
            if token.len() < self.min_window {
                continue;
            }

            // SPRT test on the token
            if self.sprt_test(token) {
                let entropy = shannon_entropy(token.as_bytes());
                if entropy >= self.entropy_threshold {
                    // Safely truncate snippet at char boundary
                    let snippet = if token.len() > 40 {
                        let end = token
                            .char_indices()
                            .take_while(|(i, _)| *i < 40)
                            .last()
                            .map(|(i, c)| i + c.len_utf8())
                            .unwrap_or(40.min(token.len()));
                        format!("{}...", &token[..end])
                    } else {
                        token.to_string()
                    };
                    alerts.push(EntropyAlert {
                        start: token_start,
                        end: token_end,
                        entropy,
                        text_snippet: snippet,
                    });
                }
            }
        }

        alerts
    }

    /// Run SPRT on a token. Returns true if the token is classified as high-entropy.
    fn sprt_test(&self, token: &str) -> bool {
        let bytes = token.as_bytes();
        let mut log_ratio = 0.0_f32;

        // H0: character drawn from natural code distribution (~4.0 bits/byte)
        // H1: character drawn from random/secret distribution (~7.0 bits/byte)
        let h0_entropy = 4.0_f32;
        let h1_entropy = 7.0_f32;

        for &b in bytes {
            if !b.is_ascii() {
                // Non-ASCII: treat as natural text (Unicode identifiers)
                log_ratio += (h0_entropy / h1_entropy).ln();
            } else {
                // Approximate: characters in [A-Za-z0-9+/=] are "high entropy candidates"
                let is_b64_char = b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=';
                if is_b64_char {
                    // Evidence for H1 (random)
                    log_ratio += (h1_entropy / h0_entropy).ln();
                } else {
                    // Evidence for H0 (natural)
                    log_ratio += (h0_entropy / h1_entropy).ln();
                }
            }

            // SPRT decision boundaries
            if log_ratio >= self.upper_bound {
                return true; // Accept H1: high entropy
            }
            if log_ratio <= self.lower_bound {
                return false; // Accept H0: natural
            }
        }

        // Inconclusive: check Shannon entropy directly
        shannon_entropy(bytes) >= self.entropy_threshold
    }
}

/// Compute Shannon entropy of a byte sequence (bits per byte).
fn shannon_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    let len = data.len() as f32;
    let mut entropy = 0.0_f32;

    for &count in &counts {
        if count > 0 {
            let p = count as f32 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_high_entropy_detection() {
        let detector = SprtDetector::new();
        // A truly random-looking token with high entropy (mixed case, digits, special)
        let text = "Here is a token: Kj7mP2xQ9vR4nL8wB3yD6fH1sT5gA0cE7iU2oN4pM9qW3rZ6kX8jV1bY5hC and done";
        let alerts = detector.scan(text);
        // The high-entropy token should trigger
        assert!(
            !alerts.is_empty(),
            "Should detect high-entropy random token"
        );
    }

    #[test]
    fn test_natural_text_no_alert() {
        let detector = SprtDetector::new();
        let text = "This is a normal English sentence with no secrets at all.";
        let alerts = detector.scan(text);
        assert!(alerts.is_empty(), "Normal text should not trigger alerts");
    }

    #[test]
    fn test_short_tokens_ignored() {
        let detector = SprtDetector::new();
        let text = "abc def ghi";
        let alerts = detector.scan(text);
        assert!(alerts.is_empty(), "Short tokens should be ignored");
    }

    #[test]
    fn test_shannon_entropy() {
        // All same byte: 0 entropy
        assert_eq!(shannon_entropy(b"aaaa"), 0.0);
        // Two equally likely bytes: 1 bit
        let e = shannon_entropy(b"abab");
        assert!((e - 1.0).abs() < 0.01);
    }
}

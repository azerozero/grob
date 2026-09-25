//! Removes literal credential echoes while retaining only a bounded chunk suffix.

use zeroize::{Zeroize, Zeroizing};

pub(crate) struct EchoFilter {
    patterns: Vec<Zeroizing<Vec<u8>>>,
    pending: Zeroizing<Vec<u8>>,
    max_len: usize,
    replacement: Vec<u8>,
}

impl EchoFilter {
    pub(crate) fn new(values: impl IntoIterator<Item = String>) -> Self {
        let mut patterns: Vec<_> = values
            .into_iter()
            .filter(|v| !v.is_empty())
            .map(|v| Zeroizing::new(v.into_bytes()))
            .collect();
        patterns.sort_by_key(|v| std::cmp::Reverse(v.len()));
        let max_len = patterns.iter().map(|v| v.len()).max().unwrap_or(1);
        let mut replacement = b"[redacted]".to_vec();
        if patterns
            .iter()
            .any(|p| replacement.windows(p.len()).any(|w| w == p.as_slice()))
        {
            // Even the replacement marker must not reproduce an unusually short credential.
            replacement = (33u8..=126)
                .find(|b| !patterns.iter().any(|p| p.as_slice() == [*b]))
                .map(|b| vec![b])
                .unwrap_or_default();
        }
        Self {
            patterns,
            pending: Zeroizing::new(Vec::new()),
            max_len,
            replacement,
        }
    }

    pub(crate) fn push(&mut self, bytes: &[u8], finish: bool) -> Vec<u8> {
        self.pending.extend_from_slice(bytes);
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < self.pending.len() && (finish || self.pending.len() - pos >= self.max_len) {
            if let Some(pattern) = self
                .patterns
                .iter()
                .find(|p| self.pending[pos..].starts_with(p))
            {
                out.extend_from_slice(&self.replacement);
                pos += pattern.len();
            } else {
                out.push(self.pending[pos]);
                pos += 1;
            }
        }
        let rest = self.pending[pos..].to_vec();
        self.pending.zeroize();
        *self.pending = rest;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn redacts_every_chunk_boundary_and_overlapping_representation() {
        let input = b"before Bearer synthetic-credential then synthetic-credential end";
        for chunk in 1..=input.len() {
            let mut filter = EchoFilter::new([
                "synthetic-credential".into(),
                "Bearer synthetic-credential".into(),
            ]);
            let mut out = Vec::new();
            for bytes in input.chunks(chunk) {
                out.extend(filter.push(bytes, false));
            }
            out.extend(filter.push(&[], true));
            assert_eq!(out, b"before [redacted] then [redacted] end");
        }
    }

    #[test]
    fn replacement_does_not_reproduce_a_credential_matching_the_marker() {
        let mut filter = EchoFilter::new(["[redacted]".into()]);
        let out = filter.push(b"[redacted]", true);
        assert!(!out.windows(10).any(|w| w == b"[redacted]"));
    }
}

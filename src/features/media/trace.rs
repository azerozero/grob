//! Opaque provenance identifiers and their resolution.
//!
//! A `TraceId` is the only thing ever written into an image. Never a tenant,
//! a session, a model or a policy: whatever is embedded travels with the file
//! forever, so putting business data there would turn the provenance marker
//! into the exfiltration channel it exists to detect. The identifier is a
//! random handle, and the mapping from handle to context stays in grob.
//!
//! # Why 61 bits
//!
//! Not a round number, and not arbitrary. It is the usable payload of the
//! watermark that has to carry it: `TrustMark`'s Bch5 variant reports
//! `data_bits() == 61`, and any other length is rejected outright. Measured,
//! not assumed. Choosing 64 or 128 here would produce identifiers that fit
//! the manifest layer and silently fail the watermark layer, which is exactly
//! the kind of mismatch that surfaces late and hurts.
//!
//! 2^61 is about 2.3 x 10^18, so collisions are not a practical concern at
//! any volume this proxy will see.

use serde::{Deserialize, Serialize};

/// Number of usable payload bits, fixed by the watermark layer.
pub const TRACE_ID_BITS: u32 = 61;

/// Mask covering the usable bits.
const TRACE_ID_MASK: u64 = (1u64 << TRACE_ID_BITS) - 1;

/// Length of the canonical hexadecimal rendering.
///
/// 61 bits need 16 hex digits, with the top 3 bits of the first always clear.
const TRACE_ID_HEX_LEN: usize = 16;

/// An opaque provenance handle.
///
/// Carries no meaning by itself, which is the point: reading it out of an
/// image tells you nothing without the registry, so an image that escapes
/// does not leak who produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TraceId(u64);

impl TraceId {
    /// Generates a fresh identifier from the system CSPRNG.
    ///
    /// Randomness matters beyond collision avoidance: a sequential or
    /// time-derived identifier would leak volume and timing to anyone
    /// collecting marked images.
    #[must_use]
    pub fn generate() -> Self {
        use rand::Rng as _;
        Self(rand::thread_rng().gen::<u64>() & TRACE_ID_MASK)
    }

    /// Builds an identifier from raw bits, discarding any above the 61st.
    ///
    /// Truncating rather than rejecting keeps round-trips total: a watermark
    /// decoder that hands back a wider integer yields the same identifier it
    /// was given.
    #[must_use]
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits & TRACE_ID_MASK)
    }

    /// Returns the raw bits, guaranteed to fit in 61.
    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Renders the identifier as 16 lowercase hex digits.
    #[must_use]
    pub fn to_hex(self) -> String {
        format!("{:016x}", self.0)
    }

    /// Parses the canonical hexadecimal rendering.
    ///
    /// Rejects anything that is not exactly 16 hex digits, and anything with
    /// bits set above the 61st: a value that cannot round-trip through the
    /// watermark is not a valid identifier, whatever it looks like.
    #[must_use]
    pub fn from_hex(text: &str) -> Option<Self> {
        if text.len() != TRACE_ID_HEX_LEN {
            return None;
        }
        let bits = u64::from_str_radix(text, 16).ok()?;
        (bits & !TRACE_ID_MASK == 0).then_some(Self(bits))
    }

    /// Renders as the bit string a watermark encoder expects.
    ///
    /// Exactly [`TRACE_ID_BITS`] characters of `0` and `1`, most significant
    /// first, because encoders reject any other length.
    #[must_use]
    pub fn to_bit_string(self) -> String {
        (0..TRACE_ID_BITS)
            .rev()
            .map(|i| if self.0 >> i & 1 == 1 { '1' } else { '0' })
            .collect()
    }

    /// Parses the bit string produced by a watermark decoder.
    #[must_use]
    pub fn from_bit_string(bits: &str) -> Option<Self> {
        if bits.len() != TRACE_ID_BITS as usize {
            return None;
        }
        let mut value = 0u64;
        for c in bits.chars() {
            // Shift and set in one expression: a separate `value |= 1` after
            // the shift is indistinguishable from `^= 1`, since the low bit is
            // always zero at that point.
            value = match c {
                '0' => value << 1,
                '1' => (value << 1) | 1,
                _ => return None,
            };
        }
        Some(Self(value))
    }
}

impl std::fmt::Display for TraceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

/// What a provenance handle resolves to.
///
/// This is the half that stays in grob. It is deliberately richer than
/// anything embedded in an image, because it is protected by the journal's
/// file permissions rather than travelling with the file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceRecord {
    /// Opaque handle, hex-rendered.
    pub trace_id: String,
    /// RFC-3339 timestamp of issuance.
    pub ts: String,
    /// Owning tenant, when the request carried one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// Model the request was routed to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Perceptual fingerprint, so an image can be recognised even after the
    /// handle itself has been stripped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phash: Option<String>,
}

impl TraceRecord {
    /// Builds a record for a freshly issued handle.
    #[must_use]
    pub fn new(trace_id: TraceId) -> Self {
        Self {
            trace_id: trace_id.to_hex(),
            ts: chrono::Utc::now().to_rfc3339(),
            tenant: None,
            model: None,
            phash: None,
        }
    }

    /// Attaches the owning tenant.
    #[must_use]
    pub fn with_tenant(mut self, tenant: impl Into<String>) -> Self {
        self.tenant = Some(tenant.into());
        self
    }

    /// Attaches the routed model.
    #[must_use]
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }

    /// Attaches the perceptual fingerprint.
    #[must_use]
    pub fn with_phash(mut self, phash: impl Into<String>) -> Self {
        self.phash = Some(phash.into());
        self
    }
}

/// Append-only registry resolving handles to their context.
///
/// Same shape as the observation journal: one JSON object per line, one file
/// per month, opened for append. A torn tail costs one record, never the file.
#[derive(Debug)]
pub struct TraceRegistry {
    dir: std::path::PathBuf,
    file: Option<std::fs::File>,
    month: String,
}

impl TraceRegistry {
    /// Opens (creating if needed) the registry under `base_dir`.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory or the current month's file cannot
    /// be created or opened for append.
    pub fn open(base_dir: &std::path::Path) -> anyhow::Result<Self> {
        use anyhow::Context as _;

        let dir = base_dir.join("media").join("trace");
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create trace dir: {}", dir.display()))?;
        let month = super::registry::current_month();
        let file = Self::open_month(&dir, &month)?;
        Ok(Self {
            dir,
            file: Some(file),
            month,
        })
    }

    /// Opens one month's file for append.
    fn open_month(dir: &std::path::Path, month: &str) -> anyhow::Result<std::fs::File> {
        use anyhow::Context as _;

        let path = dir.join(format!("{month}.jsonl"));
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("failed to open trace registry: {}", path.display()))
    }

    /// Records a handle and its context.
    ///
    /// # Errors
    ///
    /// Returns an error if the record cannot be serialised or written.
    pub fn record(&mut self, record: &TraceRecord) -> anyhow::Result<()> {
        use anyhow::Context as _;
        use std::io::Write as _;

        let month = super::registry::current_month();
        if self.needs_rollover(&month) {
            self.file = Some(Self::open_month(&self.dir, &month)?);
            self.month = month;
        }
        let Some(file) = self.file.as_mut() else {
            return Ok(());
        };
        let line = serde_json::to_string(record).context("failed to serialise trace record")?;
        writeln!(file, "{line}").context("failed to append to trace registry")?;
        Ok(())
    }

    /// Returns whether a write must move to a different month's file.
    ///
    /// Named rather than inlined so the decision is testable: inverting it
    /// would reopen the file on every single write, which no assertion about
    /// the resulting records would notice.
    #[must_use]
    pub fn needs_rollover(&self, month: &str) -> bool {
        month != self.month
    }

    /// Returns the month currently open for append.
    #[must_use]
    pub fn current_month(&self) -> &str {
        &self.month
    }

    /// Resolves a handle to its context.
    ///
    /// Searches newest-first within each month so a re-issued handle resolves
    /// to its most recent context. Returns `None` when the handle is unknown,
    /// which is the expected answer for an image grob never marked.
    ///
    /// # Errors
    ///
    /// Returns an error only if an existing file cannot be read.
    pub fn resolve(&self, trace_id: TraceId) -> anyhow::Result<Option<TraceRecord>> {
        let wanted = trace_id.to_hex();
        for month in self.months()? {
            let records = self.replay(&month)?;
            if let Some(found) = records.into_iter().rev().find(|r| r.trace_id == wanted) {
                return Ok(Some(found));
            }
        }
        Ok(None)
    }

    /// Finds records sharing a perceptual fingerprint.
    ///
    /// The fallback for an image whose embedded handle was stripped: the
    /// fingerprint is computed from the pixels, so nothing needs to have
    /// survived inside the file.
    ///
    /// # Errors
    ///
    /// Returns an error only if an existing file cannot be read.
    pub fn resolve_by_phash(&self, phash: &str) -> anyhow::Result<Vec<TraceRecord>> {
        let mut out = Vec::new();
        for month in self.months()? {
            out.extend(
                self.replay(&month)?
                    .into_iter()
                    .filter(|r| r.phash.as_deref() == Some(phash)),
            );
        }
        Ok(out)
    }

    /// Lists stored months, newest first.
    fn months(&self) -> anyhow::Result<Vec<String>> {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return Ok(Vec::new());
        };
        let mut months: Vec<String> = entries
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                name.strip_suffix(".jsonl").map(str::to_string)
            })
            .collect();
        months.sort_unstable_by(|a, b| b.cmp(a));
        Ok(months)
    }

    /// Replays every record for `month`.
    ///
    /// Unparseable lines are skipped: a torn tail from a crash must not make
    /// the whole registry unreadable.
    ///
    /// # Errors
    ///
    /// Returns an error only if an existing file cannot be read.
    pub fn replay(&self, month: &str) -> anyhow::Result<Vec<TraceRecord>> {
        use anyhow::Context as _;
        use std::io::BufRead as _;

        let path = self.dir.join(format!("{month}.jsonl"));
        if !path.exists() {
            return Ok(Vec::new());
        }
        let file = std::fs::File::open(&path)
            .with_context(|| format!("failed to read trace registry: {}", path.display()))?;
        Ok(std::io::BufReader::new(file)
            .lines()
            .map_while(Result::ok)
            .filter_map(|line| serde_json::from_str(&line).ok())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_ids_fit_the_watermark_payload() {
        // The constraint that fixes this type's width: TrustMark Bch5 accepts
        // exactly 61 bits and rejects everything else. An identifier that
        // does not fit would pass the manifest layer and fail the watermark,
        // which is the mismatch this test exists to prevent.
        for _ in 0..1000 {
            let id = TraceId::generate();
            assert!(
                id.bits() < (1u64 << TRACE_ID_BITS),
                "{id} does not fit in {TRACE_ID_BITS} bits"
            );
            assert_eq!(id.to_bit_string().len(), TRACE_ID_BITS as usize);
        }
    }

    #[test]
    fn generated_ids_are_not_predictable() {
        // Sequential or time-derived identifiers would leak volume and timing
        // to anyone collecting marked images.
        let ids: std::collections::BTreeSet<u64> =
            (0..1000).map(|_| TraceId::generate().bits()).collect();
        assert_eq!(ids.len(), 1000, "generated ids collided");

        // Consecutive draws must not be adjacent, which a counter would be.
        let a = TraceId::generate().bits();
        let b = TraceId::generate().bits();
        assert_ne!(a.wrapping_add(1), b);
    }

    #[test]
    fn hex_round_trips() {
        for _ in 0..100 {
            let id = TraceId::generate();
            let hex = id.to_hex();
            assert_eq!(hex.len(), TRACE_ID_HEX_LEN);
            assert_eq!(TraceId::from_hex(&hex), Some(id));
            assert_eq!(id.to_string(), hex);
        }
    }

    #[test]
    fn bit_string_round_trips() {
        // The form a watermark encoder and decoder actually exchange.
        for _ in 0..100 {
            let id = TraceId::generate();
            let bits = id.to_bit_string();
            assert_eq!(bits.len(), TRACE_ID_BITS as usize);
            assert!(bits.chars().all(|c| c == '0' || c == '1'));
            assert_eq!(TraceId::from_bit_string(&bits), Some(id));
        }
    }

    #[test]
    fn bit_string_is_most_significant_first() {
        let id = TraceId::from_bits(1);
        let bits = id.to_bit_string();
        assert!(bits.starts_with('0'), "leading bit should be clear: {bits}");
        assert!(
            bits.ends_with('1'),
            "value 1 should set the last bit: {bits}"
        );
    }

    #[test]
    fn oversized_input_is_truncated_not_silently_wrong() {
        // A decoder handing back a wider integer must yield the identifier it
        // was given, so round-trips stay total.
        let id = TraceId::from_bits(u64::MAX);
        assert_eq!(id.bits(), (1u64 << TRACE_ID_BITS) - 1);
        assert_eq!(TraceId::from_bit_string(&id.to_bit_string()), Some(id));
    }

    #[test]
    fn malformed_renderings_are_refused() {
        assert_eq!(TraceId::from_hex(""), None);
        assert_eq!(TraceId::from_hex("abc"), None);
        assert_eq!(TraceId::from_hex("not-hex-at-all!!"), None);
        // 17 digits is the wrong length even though it parses as a number.
        assert_eq!(TraceId::from_hex("00000000000000001"), None);
        // Correct length, but bits set above the 61st cannot round-trip
        // through the watermark, so they are not a valid identifier.
        assert_eq!(TraceId::from_hex("ffffffffffffffff"), None);

        assert_eq!(TraceId::from_bit_string(""), None);
        assert_eq!(TraceId::from_bit_string(&"0".repeat(60)), None);
        assert_eq!(TraceId::from_bit_string(&"0".repeat(62)), None);
        assert_eq!(TraceId::from_bit_string(&"2".repeat(61)), None);
    }

    #[test]
    fn a_handle_resolves_to_its_context() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut registry = TraceRegistry::open(dir.path()).expect("open");

        let id = TraceId::generate();
        registry
            .record(
                &TraceRecord::new(id)
                    .with_tenant("acme")
                    .with_model("claude-sonnet")
                    .with_phash("00000000deadbeef"),
            )
            .expect("record");

        let found = registry
            .resolve(id)
            .expect("resolve")
            .expect("known handle");
        assert_eq!(found.trace_id, id.to_hex());
        assert_eq!(found.tenant.as_deref(), Some("acme"));
        assert_eq!(found.model.as_deref(), Some("claude-sonnet"));
    }

    #[test]
    fn an_unknown_handle_resolves_to_nothing() {
        // The expected answer for an image grob never marked, and not an error.
        let dir = tempfile::tempdir().expect("tempdir");
        let registry = TraceRegistry::open(dir.path()).expect("open");
        assert!(registry
            .resolve(TraceId::generate())
            .expect("resolve")
            .is_none());
    }

    #[test]
    fn a_stripped_handle_is_recovered_by_fingerprint() {
        // The whole point of keeping the fingerprint alongside: an image whose
        // embedded handle was removed can still be traced, because the
        // fingerprint is computed from pixels rather than read from the file.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut registry = TraceRegistry::open(dir.path()).expect("open");

        let id = TraceId::generate();
        registry
            .record(
                &TraceRecord::new(id)
                    .with_tenant("acme")
                    .with_phash("cafebabecafebabe"),
            )
            .expect("record");
        registry
            .record(&TraceRecord::new(TraceId::generate()).with_phash("0123456789abcdef"))
            .expect("record");

        let found = registry
            .resolve_by_phash("cafebabecafebabe")
            .expect("resolve");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].tenant.as_deref(), Some("acme"));
    }

    #[test]
    fn a_record_carries_no_secret_by_construction() {
        // Everything embedded in an image is just the handle. The context
        // lives here, protected by file permissions rather than travelling
        // with the file.
        let id = TraceId::generate();
        let record = TraceRecord::new(id).with_tenant("acme");
        let json = serde_json::to_value(&record).expect("serialise");
        let object = json.as_object().expect("object");

        let allowed = ["trace_id", "ts", "tenant", "model", "phash"];
        for key in object.keys() {
            assert!(allowed.contains(&key.as_str()), "unexpected field '{key}'");
        }
    }

    #[test]
    fn a_torn_tail_costs_one_record_not_the_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut registry = TraceRegistry::open(dir.path()).expect("open");
        let id = TraceId::generate();
        registry.record(&TraceRecord::new(id)).expect("record");

        let path = dir
            .path()
            .join("media")
            .join("trace")
            .join(format!("{}.jsonl", super::super::registry::current_month()));
        let mut raw = std::fs::read_to_string(&path).expect("read");
        raw.push_str("{\"trace_id\":\"truncat");
        std::fs::write(&path, raw).expect("write");

        assert!(registry.resolve(id).expect("resolve").is_some());
    }

    #[test]
    fn rollover_happens_only_when_the_month_changes() {
        // Inverting this decision would reopen the file on every write, which
        // no assertion about the resulting records would ever notice.
        let dir = tempfile::tempdir().expect("tempdir");
        let registry = TraceRegistry::open(dir.path()).expect("open");

        let now = registry.current_month().to_string();
        assert!(
            !registry.needs_rollover(&now),
            "same month must not roll over"
        );
        assert!(
            registry.needs_rollover("1999-01"),
            "a past month must roll over"
        );
        assert!(
            registry.needs_rollover("2999-12"),
            "a future month must roll over"
        );
        assert!(registry.needs_rollover(""), "an empty month must roll over");
    }

    #[test]
    fn re_issuing_a_handle_resolves_to_the_latest_context() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut registry = TraceRegistry::open(dir.path()).expect("open");
        let id = TraceId::generate();

        registry
            .record(&TraceRecord::new(id).with_tenant("first"))
            .expect("record");
        registry
            .record(&TraceRecord::new(id).with_tenant("second"))
            .expect("record");

        let found = registry.resolve(id).expect("resolve").expect("known");
        assert_eq!(found.tenant.as_deref(), Some("second"));
    }
}

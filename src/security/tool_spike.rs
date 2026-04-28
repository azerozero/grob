//! Per-session tool-call spike anomaly detector for Grob (T-AD1).
//!
//! Tracks tool-use volume (Anthropic `tool_use` blocks emitted by the
//! model and `tool_result` blocks echoed back by the client) inside a
//! 60-second rolling window keyed by session id (or tenant id when no
//! session id is provided). Two thresholds are configurable: a warn
//! level that emits a log + metric, and a block level that surfaces
//! an [`AppError`]-equivalent rejection plus an audit log entry.
//!
//! The window is implemented as a fixed-size ring of one-second
//! buckets (60 buckets). Buckets older than the window are zeroed
//! out lazily on each access, so old samples drop out automatically
//! without a background task.
//!
//! Conforms to the security architecture rationale captured in the
//! `[security]` config block (see [`SecurityConfig`]).
//!
//! [`SecurityConfig`]: crate::cli::SecurityConfig

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Number of buckets in the sliding ring. One bucket per second.
const BUCKET_COUNT: usize = 60;
/// Total window covered by the ring.
const WINDOW: Duration = Duration::from_secs(60);

/// Outcome of an [`ToolSpikeDetector::observe`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpikeAction {
    /// Below all thresholds — proceed silently.
    Allow,
    /// Crossed `warn_per_min` but not `block_per_min` — log + metric, allow.
    Warn,
    /// Crossed `block_per_min` — surface a 429 to the client and audit-log.
    Block,
}

/// Configuration for the tool-spike detector.
#[derive(Debug, Clone)]
pub struct ToolSpikeConfig {
    /// Threshold above which a warning fires (no block).
    pub warn_per_min: u32,
    /// Threshold above which the request is blocked with 429.
    pub block_per_min: u32,
}

impl Default for ToolSpikeConfig {
    fn default() -> Self {
        Self {
            warn_per_min: 100,
            block_per_min: 500,
        }
    }
}

impl ToolSpikeConfig {
    /// Returns whether the detector is effectively enabled.
    ///
    /// A `block_per_min` of zero disables blocking; a `warn_per_min`
    /// of zero disables warnings. When both are zero the detector
    /// short-circuits to [`SpikeAction::Allow`] without taking the
    /// internal lock.
    pub fn is_active(&self) -> bool {
        self.warn_per_min > 0 || self.block_per_min > 0
    }
}

/// Per-key sliding-window bucket ring.
#[derive(Debug)]
struct BucketRing {
    /// Counts per second; index = (epoch_secs % BUCKET_COUNT).
    buckets: [u32; BUCKET_COUNT],
    /// Epoch second of the most recently written bucket.
    last_second: u64,
    /// Wall-clock anchor used to age stale entries during cleanup.
    last_touch: Instant,
}

impl BucketRing {
    fn new(now_secs: u64) -> Self {
        Self {
            buckets: [0; BUCKET_COUNT],
            last_second: now_secs,
            last_touch: Instant::now(),
        }
    }

    /// Adds `count` to the current second's bucket and returns the
    /// total volume across the rolling 60-second window.
    fn record(&mut self, now_secs: u64, count: u32) -> u32 {
        self.advance(now_secs);
        let idx = (now_secs % BUCKET_COUNT as u64) as usize;
        self.buckets[idx] = self.buckets[idx].saturating_add(count);
        self.last_touch = Instant::now();
        self.total()
    }

    /// Zero out buckets that fell out of the rolling window.
    ///
    /// If more than `BUCKET_COUNT` seconds have elapsed since the
    /// last write, every bucket is stale and the ring is fully
    /// cleared in one pass.
    fn advance(&mut self, now_secs: u64) {
        if now_secs <= self.last_second {
            return;
        }
        let elapsed = now_secs - self.last_second;
        if elapsed >= BUCKET_COUNT as u64 {
            self.buckets = [0; BUCKET_COUNT];
        } else {
            // Clear every bucket strictly between last_second and now_secs.
            for offset in 1..=elapsed {
                let idx = ((self.last_second + offset) % BUCKET_COUNT as u64) as usize;
                self.buckets[idx] = 0;
            }
        }
        self.last_second = now_secs;
    }

    /// Returns the sum of all buckets in the current window.
    fn total(&self) -> u32 {
        self.buckets.iter().fold(0u32, |a, b| a.saturating_add(*b))
    }

    /// Reset the ring (used by [`ToolSpikeDetector::reset_session`]).
    fn clear(&mut self) {
        self.buckets = [0; BUCKET_COUNT];
    }
}

/// Sliding-window per-session counter with warn/block thresholds.
///
/// The detector is cheap enough to be called inline on every dispatch:
/// a single mutex acquisition, an integer addition, and one bucket
/// rotation in the steady state.
///
/// # Examples
///
/// ```
/// use grob::security::tool_spike::{ToolSpikeConfig, ToolSpikeDetector, SpikeAction};
///
/// let detector = ToolSpikeDetector::new(ToolSpikeConfig {
///     warn_per_min: 10,
///     block_per_min: 20,
/// });
/// assert_eq!(detector.observe("session-1", 5), SpikeAction::Allow);
/// assert_eq!(detector.observe("session-1", 7), SpikeAction::Warn);
/// assert_eq!(detector.observe("session-1", 9), SpikeAction::Block);
/// ```
#[derive(Debug)]
pub struct ToolSpikeDetector {
    config: ToolSpikeConfig,
    rings: Mutex<HashMap<String, BucketRing>>,
    /// Wall-clock origin used to derive the current "second" without
    /// pulling in `chrono` for hot-path bucket math.
    epoch: Instant,
}

impl ToolSpikeDetector {
    /// Creates a detector with the given configuration.
    pub fn new(config: ToolSpikeConfig) -> Self {
        Self {
            config,
            rings: Mutex::new(HashMap::new()),
            epoch: Instant::now(),
        }
    }

    /// Returns the configured thresholds.
    pub fn config(&self) -> &ToolSpikeConfig {
        &self.config
    }

    /// Records `count` tool calls for `key` and classifies the result.
    ///
    /// Always returns the most severe action triggered by the new
    /// total. A `count` of zero still drives bucket rotation, which
    /// is useful for observability snapshots.
    pub fn observe(&self, key: &str, count: u32) -> SpikeAction {
        if !self.config.is_active() {
            return SpikeAction::Allow;
        }
        let now_secs = self.now_secs();
        let mut rings = self.rings.lock().unwrap_or_else(|e| e.into_inner());
        let ring = rings
            .entry(key.to_string())
            .or_insert_with(|| BucketRing::new(now_secs));
        let total = ring.record(now_secs, count);
        self.classify(total)
    }

    /// Returns the current rolling-window total for `key` without
    /// recording a new sample. Useful for tests and metrics.
    pub fn current_total(&self, key: &str) -> u32 {
        let now_secs = self.now_secs();
        let mut rings = self.rings.lock().unwrap_or_else(|e| e.into_inner());
        match rings.get_mut(key) {
            Some(ring) => {
                ring.advance(now_secs);
                ring.total()
            }
            None => 0,
        }
    }

    /// Drops the counter for a session.
    ///
    /// Called when the upstream session signals end-of-life so the
    /// detector does not falsely attribute future activity to a stale
    /// identifier (e.g. when session ids are recycled).
    pub fn reset_session(&self, key: &str) {
        let mut rings = self.rings.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ring) = rings.get_mut(key) {
            ring.clear();
        }
    }

    /// Drops counters that have not been touched for at least `WINDOW`.
    ///
    /// Exposed for the background cleanup task; safe to call at any
    /// cadence — heavier than `observe` only by an iteration over the
    /// HashMap.
    pub fn cleanup_idle(&self) {
        let mut rings = self.rings.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        rings.retain(|_, ring| now.duration_since(ring.last_touch) < WINDOW);
    }

    fn classify(&self, total: u32) -> SpikeAction {
        if self.config.block_per_min > 0 && total >= self.config.block_per_min {
            SpikeAction::Block
        } else if self.config.warn_per_min > 0 && total >= self.config.warn_per_min {
            SpikeAction::Warn
        } else {
            SpikeAction::Allow
        }
    }

    fn now_secs(&self) -> u64 {
        // Anchored to the detector's start; ensures stable ordering
        // even when wall-clock time jumps backwards.
        let elapsed = Instant::now().saturating_duration_since(self.epoch);
        elapsed.as_secs()
    }

    /// Test-only constructor that anchors the detector at a synthetic
    /// epoch. Lets tests advance time deterministically.
    #[cfg(test)]
    fn with_epoch(config: ToolSpikeConfig, epoch: Instant) -> Self {
        Self {
            config,
            rings: Mutex::new(HashMap::new()),
            epoch,
        }
    }

    /// Test-only helper: record `count` at `secs_since_epoch` instead
    /// of "now". Mirrors `observe` exactly so production semantics
    /// stay identical.
    #[cfg(test)]
    fn observe_at(&self, key: &str, count: u32, secs_since_epoch: u64) -> SpikeAction {
        if !self.config.is_active() {
            return SpikeAction::Allow;
        }
        let mut rings = self.rings.lock().unwrap_or_else(|e| e.into_inner());
        let ring = rings
            .entry(key.to_string())
            .or_insert_with(|| BucketRing::new(secs_since_epoch));
        let total = ring.record(secs_since_epoch, count);
        self.classify(total)
    }
}

/// Counts the number of `tool_use` and `tool_result` content blocks
/// in a [`CanonicalRequest`], which approximates the per-request
/// tool-call volume contributed by the client. Models that emit many
/// tool-use blocks per turn show up as a spike across consecutive
/// requests inside the same session.
pub fn count_tool_blocks(request: &crate::models::CanonicalRequest) -> u32 {
    use crate::models::{ContentBlock, KnownContentBlock, MessageContent};

    let mut count: u32 = 0;
    for msg in &request.messages {
        let MessageContent::Blocks(blocks) = &msg.content else {
            continue;
        };
        for block in blocks {
            if matches!(
                block,
                ContentBlock::Known(
                    KnownContentBlock::ToolUse { .. } | KnownContentBlock::ToolResult { .. }
                )
            ) {
                count = count.saturating_add(1);
            }
        }
    }
    count
}

/// Resolves the spike-detector key for a request.
///
/// Priority:
/// 1. `metadata.session_id` (string) on the request body.
/// 2. `metadata.user_id` (Anthropic Messages API field).
/// 3. The provided `tenant_id` fallback (or `"anon"`).
pub fn resolve_key(request: &crate::models::CanonicalRequest, tenant_id: Option<&str>) -> String {
    if let Some(meta) = request.metadata.as_ref() {
        if let Some(sid) = meta.get("session_id").and_then(|v| v.as_str()) {
            if !sid.is_empty() {
                return sid.to_string();
            }
        }
        if let Some(uid) = meta.get("user_id").and_then(|v| v.as_str()) {
            if !uid.is_empty() {
                return uid.to_string();
            }
        }
    }
    tenant_id.unwrap_or("anon").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(warn: u32, block: u32) -> ToolSpikeConfig {
        ToolSpikeConfig {
            warn_per_min: warn,
            block_per_min: block,
        }
    }

    #[test]
    fn allow_under_warn() {
        let det = ToolSpikeDetector::new(cfg(100, 500));
        let action = det.observe("s1", 50);
        assert_eq!(action, SpikeAction::Allow);
        assert_eq!(det.current_total("s1"), 50);
    }

    #[test]
    fn warn_at_threshold_no_block() {
        let det = ToolSpikeDetector::new(cfg(100, 500));
        // 200 calls in well under 60s → must trigger warn (>=100) but
        // not block (<500). Spread synthetically across a few buckets.
        let mut last = SpikeAction::Allow;
        for _ in 0..200 {
            last = det.observe("hot", 1);
        }
        assert_eq!(last, SpikeAction::Warn);
        assert_eq!(det.current_total("hot"), 200);
    }

    #[test]
    fn block_above_threshold() {
        let det = ToolSpikeDetector::new(cfg(100, 500));
        // 600 calls in <60s → must block.
        let mut last = SpikeAction::Allow;
        let mut blocked = 0;
        for _ in 0..600 {
            last = det.observe("noisy", 1);
            if last == SpikeAction::Block {
                blocked += 1;
            }
        }
        assert_eq!(last, SpikeAction::Block);
        assert!(blocked > 0, "must have hit block at least once");
    }

    #[test]
    fn window_decays_after_60_seconds() {
        let epoch = Instant::now();
        let det = ToolSpikeDetector::with_epoch(cfg(100, 500), epoch);

        // Bucket second 5 with 200 calls.
        for _ in 0..200 {
            assert_ne!(det.observe_at("decay", 1, 5), SpikeAction::Block);
        }
        assert_eq!(det.observe_at("decay", 0, 5), SpikeAction::Warn);

        // Jump 70s ahead → all old buckets should fall out.
        assert_eq!(det.observe_at("decay", 0, 75), SpikeAction::Allow);
    }

    #[test]
    fn boundary_partial_decay() {
        let epoch = Instant::now();
        let det = ToolSpikeDetector::with_epoch(cfg(100, 500), epoch);

        // 60 hits at second 0.
        for _ in 0..60 {
            det.observe_at("part", 1, 0);
        }
        // 60 more at second 30 → total 120 → warn.
        for _ in 0..60 {
            det.observe_at("part", 1, 30);
        }
        assert_eq!(det.observe_at("part", 0, 30), SpikeAction::Warn);

        // At second 65, the second-0 bucket has fallen out (window is
        // 60 buckets wide). Remaining = the 60 hits from second 30.
        assert_eq!(det.observe_at("part", 0, 65), SpikeAction::Allow);
        assert_eq!(det.current_total_at("part", 65), 60);
    }

    #[test]
    fn reset_session_clears_counter() {
        let det = ToolSpikeDetector::new(cfg(100, 500));
        for _ in 0..120 {
            det.observe("end-me", 1);
        }
        assert_eq!(det.observe("end-me", 0), SpikeAction::Warn);
        det.reset_session("end-me");
        assert_eq!(det.observe("end-me", 0), SpikeAction::Allow);
    }

    #[test]
    fn disabled_when_thresholds_zero() {
        let det = ToolSpikeDetector::new(cfg(0, 0));
        assert_eq!(det.observe("anything", 100_000), SpikeAction::Allow);
    }

    #[test]
    fn distinct_keys_isolated() {
        let det = ToolSpikeDetector::new(cfg(100, 500));
        for _ in 0..120 {
            det.observe("a", 1);
        }
        assert_eq!(det.observe("a", 0), SpikeAction::Warn);
        // Sibling key untouched.
        assert_eq!(det.observe("b", 1), SpikeAction::Allow);
    }

    #[test]
    fn count_tool_blocks_from_canonical_request() {
        use crate::models::{CanonicalRequest, ContentBlock, Message, MessageContent};

        let mut req = CanonicalRequest {
            model: "x".into(),
            messages: vec![Message {
                role: "assistant".into(),
                content: MessageContent::Blocks(vec![
                    ContentBlock::tool_use(
                        "id-1".into(),
                        "Read".into(),
                        serde_json::json!({"path": "/tmp/a"}),
                    ),
                    ContentBlock::tool_use(
                        "id-2".into(),
                        "Read".into(),
                        serde_json::json!({"path": "/tmp/b"}),
                    ),
                    ContentBlock::text("hi".into(), None),
                ]),
            }],
            max_tokens: 10,
            thinking: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop_sequences: None,
            stream: None,
            metadata: None,
            system: None,
            tools: None,
            tool_choice: None,
            extensions: Default::default(),
        };
        assert_eq!(count_tool_blocks(&req), 2);

        // Add a second message with a tool_result (count grows by 1).
        req.messages.push(Message {
            role: "user".into(),
            content: MessageContent::Blocks(vec![ContentBlock::Known(
                crate::models::KnownContentBlock::ToolResult {
                    tool_use_id: "id-1".into(),
                    content: crate::models::ToolResultContent::Text("ok".into()),
                    is_error: false,
                    cache_control: None,
                },
            )]),
        });
        assert_eq!(count_tool_blocks(&req), 3);
    }

    #[test]
    fn resolve_key_priority_session_user_tenant() {
        use crate::models::CanonicalRequest;
        use std::collections::HashMap;

        let make = |meta: Option<HashMap<String, serde_json::Value>>| CanonicalRequest {
            model: "x".into(),
            messages: vec![],
            max_tokens: 1,
            thinking: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop_sequences: None,
            stream: None,
            metadata: meta,
            system: None,
            tools: None,
            tool_choice: None,
            extensions: Default::default(),
        };

        // No metadata → tenant fallback.
        assert_eq!(resolve_key(&make(None), Some("tenant-a")), "tenant-a");
        assert_eq!(resolve_key(&make(None), None), "anon");

        // session_id wins.
        let mut m = HashMap::new();
        m.insert("session_id".into(), serde_json::json!("sess-1"));
        m.insert("user_id".into(), serde_json::json!("user-1"));
        assert_eq!(resolve_key(&make(Some(m)), Some("tenant-a")), "sess-1");

        // user_id used when session_id absent.
        let mut m = HashMap::new();
        m.insert("user_id".into(), serde_json::json!("user-2"));
        assert_eq!(resolve_key(&make(Some(m)), Some("tenant-a")), "user-2");

        // Empty session_id falls through to user_id.
        let mut m = HashMap::new();
        m.insert("session_id".into(), serde_json::json!(""));
        m.insert("user_id".into(), serde_json::json!("user-3"));
        assert_eq!(resolve_key(&make(Some(m)), None), "user-3");
    }

    #[test]
    fn cleanup_idle_drops_stale_keys() {
        let det = ToolSpikeDetector::new(cfg(100, 500));
        det.observe("ephemeral", 1);
        // Force last_touch into the past by reaching into the lock.
        {
            let mut rings = det.rings.lock().unwrap();
            if let Some(ring) = rings.get_mut("ephemeral") {
                ring.last_touch = Instant::now() - Duration::from_secs(120);
            }
        }
        det.cleanup_idle();
        let rings = det.rings.lock().unwrap();
        assert!(!rings.contains_key("ephemeral"));
    }

    impl ToolSpikeDetector {
        fn current_total_at(&self, key: &str, secs_since_epoch: u64) -> u32 {
            let mut rings = self.rings.lock().unwrap_or_else(|e| e.into_inner());
            match rings.get_mut(key) {
                Some(ring) => {
                    ring.advance(secs_since_epoch);
                    ring.total()
                }
                None => 0,
            }
        }
    }
}

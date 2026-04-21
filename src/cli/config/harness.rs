//! Record-and-replay harness configuration (opt-in `harness` feature).

use serde::{Deserialize, Serialize};

/// Configuration for the record-and-replay harness (opt-in `harness` feature).
///
/// The harness records HTTP request/response pairs to a tape file for offline
/// replay in sandwich tests. Enable via `[harness]` in `grob.toml`.
///
/// The `GROB_HARNESS_RECORD` environment variable overrides `record_path` when set.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct HarnessConfig {
    /// Path to the tape file for recording. When set, recording is active.
    ///
    /// Overridden by the `GROB_HARNESS_RECORD` environment variable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_path: Option<std::path::PathBuf>,

    /// Path to replay from. Mutually exclusive with `record_path`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_path: Option<std::path::PathBuf>,
}

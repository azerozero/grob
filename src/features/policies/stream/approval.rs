//! HIT approval channel lifecycle: pending map types and channel setup.
//!
//! Manages the shared `HitPendingApprovals` map that bridges the SSE stream
//! (which creates approval channels) and the `POST /api/hit/approve` HTTP
//! endpoint (which resolves them).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::features::policies::hit::HitOverride;

// ── Pending approval entry types ──────────────────────────────────────────────

/// Multisig pending state: collects M-of-N human signatures before resolving.
pub struct HitMultiSigPending {
    /// Accumulates distinct signed authorizations.
    pub collector: crate::features::policies::multisig::MultiSigCollector,
    /// Resolves the stream's oneshot when enough signatures are collected.
    pub sender: tokio::sync::oneshot::Sender<bool>,
    /// Last authorization hash (for chain linking).
    pub last_hash: Option<String>,
}

/// Quorum pending state: collects N human votes and tallies via quorum strategy.
pub struct HitQuorumPending {
    /// Quorum strategy configuration.
    pub config: crate::features::policies::quorum::QuorumConfig,
    /// Votes cast so far.
    pub votes: Vec<crate::features::policies::quorum::VoterDecision>,
    /// Resolves the stream's oneshot when quorum is reached.
    pub sender: tokio::sync::oneshot::Sender<bool>,
}

/// A pending HIT approval entry stored in the shared map.
///
/// Supports three resolution modes:
/// - [`Simple`]: first caller to `POST /api/hit/approve` decides.
/// - [`MultiSig`]: M-of-N distinct signers must approve via `MultiSigCollector`.
/// - [`Quorum`]: N votes are tallied with a configurable quorum strategy.
pub enum HitApprovalEntry {
    /// Single approver — first response wins.
    Simple(tokio::sync::oneshot::Sender<bool>),
    /// Multi-party signing — requires `required_signatures` distinct approvals.
    MultiSig(HitMultiSigPending),
    /// Quorum voting — requires reaching the configured approval threshold.
    Quorum(HitQuorumPending),
}

/// Shared map of pending approval requests keyed by `"{request_id}:{tool_name}"`.
///
/// Populated by [`HitStream`] when a tool requires approval, consumed by the
/// `POST /api/hit/approve` HTTP handler.
pub type HitPendingApprovals = Mutex<HashMap<String, HitApprovalEntry>>;

// ── Channel setup ─────────────────────────────────────────────────────────────

/// Creates the approval channel entry in the shared map and emits the
/// `HitApprovalRequest` event on the event bus.
///
/// Returns the `Receiver` half of the oneshot channel; the `Sender` half is
/// stored in the map under `"{request_id}:{tool_name}"`.
pub fn setup_approval(
    request_id: &str,
    tool_name: &str,
    tool_input_preview: &str,
    policy: &HitOverride,
    approval_tx_store: &Option<Arc<HitPendingApprovals>>,
    event_bus: &Option<crate::features::watch::EventBus>,
) -> tokio::sync::oneshot::Receiver<bool> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let key = format!("{}:{}", request_id, tool_name);

    let entry = match policy.auth_method.as_str() {
        "multisig" => HitApprovalEntry::MultiSig(HitMultiSigPending {
            collector: crate::features::policies::multisig::MultiSigCollector::new(
                policy.required_signatures.unwrap_or(2) as usize,
            ),
            sender: tx,
            last_hash: None,
        }),
        "quorum" => HitApprovalEntry::Quorum(HitQuorumPending {
            config: policy.quorum.clone().unwrap_or_else(default_quorum_config),
            votes: Vec::new(),
            sender: tx,
        }),
        _ => HitApprovalEntry::Simple(tx),
    };

    if let Some(ref store) = approval_tx_store {
        if let Ok(mut map) = store.lock() {
            map.insert(key, entry);
        }
    }

    if let Some(ref bus) = event_bus {
        bus.emit(
            crate::features::watch::events::WatchEvent::HitApprovalRequest {
                request_id: request_id.to_string(),
                tool_name: tool_name.to_string(),
                tool_input_preview: tool_input_preview.to_string(),
                auth_method: policy.auth_method.clone(),
                webhook_url: policy.webhook_url.clone(),
                timestamp: chrono::Utc::now(),
            },
        );
    }

    rx
}

fn default_quorum_config() -> crate::features::policies::quorum::QuorumConfig {
    crate::features::policies::quorum::QuorumConfig {
        strategy: crate::features::policies::quorum::QuorumStrategy::Majority,
        min_voters: 3,
        required_approvals: 2,
        voter_timeout_ms: 5000,
        on_failure: crate::features::policies::quorum::QuorumFailureAction::EscalateHuman,
    }
}

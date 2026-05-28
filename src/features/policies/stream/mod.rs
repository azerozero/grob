//! HIT (Human Intent Token) SSE stream wrapper.
//!
//! Intercepts `tool_use` blocks in streaming responses and evaluates them
//! against the HIT policy. The decision is deferred until the complete
//! `content_block_stop` event so that argument-matching deny rules (e.g.
//! `Bash(rm -rf*)`) and receipt hashes have access to the real tool input.
//!
//! # State machine
//!
//! ```text
//!   Passthrough
//!       │  content_block_start (tool_use)
//!       ▼
//!   BufferingInput           ← buffers ALL chunks until content_block_stop
//!       │  content_block_stop
//!       ├─► AutoApprove  → flush pending_chunks, write receipt → Passthrough
//!       ├─► Deny         → drop pending_chunks, write receipt → Passthrough
//!       └─► RequireApproval → keep pending_chunks, emit event → Paused
//!                                │ oneshot resolves (approve/deny)
//!                                └─────────────────────────────► Passthrough
//! ```
//!
//! # Errors
//!
//! `poll_next` propagates `ProviderError` items from the inner stream unchanged.
//!
//! # Panics
//!
//! `poll_next` panics if the `approval_tx_store` mutex is poisoned (another thread
//! panicked while holding the lock). This is a fatal condition — poisoned approval
//! state cannot be safely recovered.

pub mod approval;
pub mod sse_parser;

pub use approval::{HitApprovalEntry, HitMultiSigPending, HitPendingApprovals, HitQuorumPending};

use approval::setup_approval;
use sse_parser::{extract_block_index, extract_partial_json, extract_tool_name};

use crate::features::policies::hit::{evaluate_tool_use, HitDecision, HitOverride, ToolUseInfo};
use crate::features::policies::hit_auth::{
    AuthDecision, AuthMethod, HitAuthParams, HitAuthorization,
};
use bytes::Bytes;
use futures::stream::Stream;
use futures::Future;
use memchr::memmem;
use pin_project::pin_project;
use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

// ── State machine ─────────────────────────────────────────────────────────────

/// Internal state machine for [`HitStream`].
enum HitStreamState {
    /// Normal passthrough — no active tool_use interception.
    Passthrough,
    /// Buffering all chunks for a tool_use block until `content_block_stop`.
    ///
    /// The approval/deny decision is deferred until the complete tool input is
    /// available so that argument-matching deny rules work correctly.
    BufferingInput { tool_name: String, tool_index: u32 },
    /// Paused waiting for human approval via oneshot channel.
    /// All incoming chunks are buffered and flushed on approval.
    Paused,
}

// ── HitStream struct ──────────────────────────────────────────────────────────

/// Stream adapter that intercepts `tool_use` blocks and applies HIT policy.
///
/// Performance notes:
/// - SIMD-accelerated [`memchr::memmem`] for fast `content_block_start` detection.
/// - Zero-copy passthrough for chunks without tool_use events.
/// - [`BufferingInput`](HitStreamState::BufferingInput) buffers the entire tool
///   block (typically < 2 KiB) before emitting any chunk, enabling deny-pattern
///   matching on tool arguments.
///
/// # Errors
///
/// [`Stream::poll_next`] propagates `ProviderError` items from the inner stream
/// unchanged. No additional errors are introduced by this adapter.
///
/// # Panics
///
/// [`Stream::poll_next`] panics if the `approval_tx_store` mutex is poisoned.
#[pin_project]
pub struct HitStream<S> {
    #[pin]
    inner: S,
    policy: HitOverride,
    request_id: String,
    state: HitStreamState,
    /// Chunks buffered in `BufferingInput` or `Paused` states.
    pending_chunks: VecDeque<Bytes>,
    /// Accumulated `partial_json` fragments from `input_json_delta` chunks.
    tool_input_buffer: String,
    /// Oneshot receiver for human approval decision (Paused state only).
    approval_rx: Option<tokio::sync::oneshot::Receiver<bool>>,
    /// Shared map where approval entries are stored for the approve endpoint.
    approval_tx_store: Option<Arc<HitPendingApprovals>>,
    /// Event bus for emitting HIT events.
    event_bus: Option<crate::features::watch::EventBus>,
    /// Compiled flag regexes (from `policy.flag_patterns`).
    flag_regexes: Vec<regex::Regex>,
    /// SHA-256 hash of the last `HitAuthorization` receipt (for chaining).
    last_hit_hash: Option<String>,
    /// Audit log for persisting HIT authorization receipts.
    audit_log: Option<Arc<crate::security::AuditLog>>,
    /// Tool name captured when entering `Paused` (for receipt writing on resolve).
    paused_tool_name: Option<String>,
}

impl<S> HitStream<S>
where
    S: Stream<Item = Result<Bytes, crate::providers::error::ProviderError>> + Send,
{
    /// Wraps an inner stream with HIT policy evaluation.
    pub fn new(
        inner: S,
        policy: HitOverride,
        request_id: String,
        approval_tx_store: Option<Arc<HitPendingApprovals>>,
        event_bus: Option<crate::features::watch::EventBus>,
        audit_log: Option<Arc<crate::security::AuditLog>>,
    ) -> Self {
        let flag_regexes = policy
            .flag_patterns
            .iter()
            .filter_map(|p| match regex::Regex::new(p) {
                Ok(r) => Some(r),
                Err(e) => {
                    tracing::warn!(pattern = %p, error = %e, "HIT: invalid flag_pattern, skipping");
                    None
                }
            })
            .collect();

        Self {
            inner,
            policy,
            request_id,
            state: HitStreamState::Passthrough,
            pending_chunks: VecDeque::new(),
            tool_input_buffer: String::new(),
            approval_rx: None,
            approval_tx_store,
            event_bus,
            flag_regexes,
            last_hit_hash: None,
            audit_log,
            paused_tool_name: None,
        }
    }
}

// ── Receipt writing ───────────────────────────────────────────────────────────

/// Decision context for a single `HitAuthorization` receipt.
struct ReceiptContext<'a> {
    tool_name: &'a str,
    tool_input: &'a str,
    decision: AuthDecision,
    auth_method: AuthMethod,
    signer: &'a str,
}

/// Creates a [`HitAuthorization`] and appends it to the audit chain.
///
/// Chaining is maintained via `last_hit_hash` (SHA-256 of the previous receipt
/// in this session). The audit log handles its own independent signing chain.
fn write_hit_receipt(
    last_hit_hash: &mut Option<String>,
    audit_log: &Option<Arc<crate::security::AuditLog>>,
    request_id: &str,
    ctx: ReceiptContext<'_>,
) {
    let auth = HitAuthorization::new(HitAuthParams {
        request_id: request_id.to_string(),
        tool_name: ctx.tool_name.to_string(),
        tool_input: ctx.tool_input.to_string(),
        decision: ctx.decision,
        auth_method: ctx.auth_method,
        signer: ctx.signer.to_string(),
        previous_hash: last_hit_hash.take(),
    });
    *last_hit_hash = Some(auth.hash.clone());

    if let Some(ref log) = audit_log {
        use crate::security::audit_log::{AuditEntry, AuditEvent, Classification, RiskLevel};
        let Ok(receipt_json) = serde_json::to_string(&auth) else {
            return;
        };
        let entry = AuditEntry {
            timestamp: chrono::Utc::now(),
            event_id: uuid::Uuid::new_v4().to_string(),
            tenant_id: request_id.to_string(),
            user_id: Some(auth.signer.clone()),
            action: AuditEvent::HitApproval,
            classification: Classification::C2,
            backend_routed: receipt_json,
            request_hash: Some(auth.tool_input_hash.clone()),
            dlp_rules_triggered: vec![],
            ip_source: "internal".to_string(),
            duration_ms: 0,
            previous_hash: String::new(),
            signature: vec![],
            signature_algorithm: String::new(),
            model_name: Some(ctx.tool_name.to_string()),
            input_tokens: None,
            output_tokens: None,
            risk_level: Some(RiskLevel::High),
            batch_id: None,
            batch_index: None,
            merkle_root: None,
            merkle_proof: None,
        };
        if let Err(e) = log.write(entry) {
            tracing::warn!(error = %e, "HIT: failed to write receipt to audit log");
        }
    }
}

// ── Projected mutable view ─────────────────────────────────────────────────────

/// Borrowed projection of the mutable [`HitStream`] fields the phase helpers
/// touch, bundled to replace the previous 9–13 free-function parameters.
///
/// Built from the `pin_project` projection in [`Stream::poll_next`]; all fields
/// are borrows into the live stream, so methods here mutate the stream directly.
struct HitStreamMut<'a> {
    /// Current state-machine position.
    state: &'a mut HitStreamState,
    /// Oneshot receiver for the human approval decision.
    approval_rx: &'a mut Option<tokio::sync::oneshot::Receiver<bool>>,
    /// Tool name captured when entering `Paused`.
    paused_tool_name: &'a mut Option<String>,
    /// Accumulated `partial_json` for the in-flight tool block.
    tool_input_buffer: &'a mut String,
    /// Chunks buffered while not in `Passthrough`.
    pending_chunks: &'a mut VecDeque<Bytes>,
    /// Tag of the last receipt, for chain linking.
    last_hit_hash: &'a mut Option<String>,
    /// Audit log sink for receipts.
    audit_log: &'a Option<Arc<crate::security::AuditLog>>,
    /// Correlation identifier for the owning request.
    request_id: &'a str,
    /// Active HIT policy.
    policy: &'a HitOverride,
    /// Shared pending-approval map for the approve endpoint.
    approval_tx_store: &'a Option<Arc<HitPendingApprovals>>,
    /// Event bus for HIT events.
    event_bus: &'a Option<crate::features::watch::EventBus>,
}

impl HitStreamMut<'_> {
    /// Polls the approval oneshot and resolves the paused state.
    ///
    /// Returns `true` if approval is still pending (oneshot not ready).
    fn poll_paused_approval(&mut self, cx: &mut Context<'_>) -> bool {
        let rx = match self.approval_rx.as_mut() {
            Some(rx) => rx,
            None => return false,
        };
        // SAFETY: oneshot::Receiver is Unpin so Pin::new is fine.
        match Pin::new(rx).poll(cx) {
            Poll::Ready(Ok(approved)) => {
                let tool_name = self.paused_tool_name.take().unwrap_or_default();
                let tool_input = std::mem::take(self.tool_input_buffer);
                if let Some(ref bus) = self.event_bus {
                    bus.emit(
                        crate::features::watch::events::WatchEvent::HitApprovalResponse {
                            request_id: self.request_id.to_string(),
                            tool_name: tool_name.clone(),
                            approved,
                            timestamp: chrono::Utc::now(),
                        },
                    );
                }
                write_hit_receipt(
                    self.last_hit_hash,
                    self.audit_log,
                    self.request_id,
                    ReceiptContext {
                        tool_name: &tool_name,
                        tool_input: &tool_input,
                        decision: if approved {
                            AuthDecision::Approve
                        } else {
                            AuthDecision::Deny
                        },
                        auth_method: self.policy.auth_method,
                        signer: "human",
                    },
                );
                *self.approval_rx = None;
                *self.state = HitStreamState::Passthrough;
                if !approved {
                    self.pending_chunks.clear();
                    tracing::info!(
                        request_id = %self.request_id,
                        tool = %tool_name,
                        "HIT: tool_use denied by human"
                    );
                }
                false
            }
            Poll::Ready(Err(_)) => {
                self.pending_chunks.clear();
                self.tool_input_buffer.clear();
                *self.approval_rx = None;
                *self.paused_tool_name = None;
                *self.state = HitStreamState::Passthrough;
                tracing::warn!(
                    request_id = %self.request_id,
                    "HIT: approval channel closed, treating as deny"
                );
                false
            }
            Poll::Pending => true,
        }
    }

    /// Applies the HIT decision after a complete tool_use block.
    fn apply_hit_decision(&mut self, decision: HitDecision, tname: &str) {
        match decision {
            HitDecision::AutoApprove => {
                tracing::debug!(request_id = %self.request_id, tool = %tname, "HIT: auto-approved");
                write_hit_receipt(
                    self.last_hit_hash,
                    self.audit_log,
                    self.request_id,
                    ReceiptContext {
                        tool_name: tname,
                        tool_input: self.tool_input_buffer,
                        decision: AuthDecision::Approve,
                        auth_method: AuthMethod::MachineKey,
                        signer: "policy",
                    },
                );
                self.tool_input_buffer.clear();
                *self.state = HitStreamState::Passthrough;
            }
            HitDecision::Deny => {
                tracing::info!(request_id = %self.request_id, tool = %tname, "HIT: tool_use denied by policy");
                metrics::counter!("grob_hit_denied_total").increment(1);
                write_hit_receipt(
                    self.last_hit_hash,
                    self.audit_log,
                    self.request_id,
                    ReceiptContext {
                        tool_name: tname,
                        tool_input: self.tool_input_buffer,
                        decision: AuthDecision::Deny,
                        auth_method: AuthMethod::MachineKey,
                        signer: "policy",
                    },
                );
                self.pending_chunks.clear();
                self.tool_input_buffer.clear();
                *self.state = HitStreamState::Passthrough;
            }
            HitDecision::RequireApproval => self.apply_require_approval(tname),
        }
    }

    /// Handles the `RequireApproval` branch for each auth method.
    fn apply_require_approval(&mut self, tname: &str) {
        match self.policy.auth_method {
            AuthMethod::MachineKey => {
                tracing::info!(request_id = %self.request_id, tool = %tname, "HIT: machine_key auto-approved");
                write_hit_receipt(
                    self.last_hit_hash,
                    self.audit_log,
                    self.request_id,
                    ReceiptContext {
                        tool_name: tname,
                        tool_input: self.tool_input_buffer,
                        decision: AuthDecision::Approve,
                        auth_method: AuthMethod::MachineKey,
                        signer: "machine_key",
                    },
                );
                self.tool_input_buffer.clear();
                *self.state = HitStreamState::Passthrough;
            }
            AuthMethod::Yubikey => {
                tracing::warn!(
                    request_id = %self.request_id,
                    auth_method = %self.policy.auth_method,
                    "HIT: yubikey auth not yet implemented (WI-8b), falling back to prompt"
                );
                self.enter_paused(tname);
            }
            _ => {
                tracing::info!(
                    request_id = %self.request_id, tool = %tname,
                    auth_method = %self.policy.auth_method, "HIT: requesting human approval"
                );
                metrics::counter!("grob_hit_approval_requested_total").increment(1);
                self.enter_paused(tname);
            }
        }
    }

    /// Transitions the stream into the `Paused` state with an approval channel.
    fn enter_paused(&mut self, tname: &str) {
        let preview: String = self.tool_input_buffer.chars().take(200).collect();
        let rx = setup_approval(
            self.request_id,
            tname,
            &preview,
            self.policy,
            self.approval_tx_store,
            self.event_bus,
        );
        *self.approval_rx = Some(rx);
        *self.paused_tool_name = Some(tname.to_string());
        *self.state = HitStreamState::Paused;
    }
}

/// Scans a text_delta chunk for flagged patterns and emits events.
fn check_flag_patterns(
    bytes: &[u8],
    flag_regexes: &[regex::Regex],
    event_bus: &Option<crate::features::watch::EventBus>,
    request_id: &str,
) {
    if flag_regexes.is_empty() || memmem::find(bytes, b"text_delta").is_none() {
        return;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    for re in flag_regexes.iter() {
        if let Some(m) = re.find(text) {
            if let Some(ref bus) = event_bus {
                bus.emit(
                    crate::features::watch::events::WatchEvent::HitFlaggedContent {
                        request_id: request_id.to_string(),
                        pattern: re.as_str().to_string(),
                        matched_text: m.as_str().to_string(),
                        timestamp: chrono::Utc::now(),
                    },
                );
            }
            tracing::warn!(
                request_id = %request_id,
                pattern = re.as_str(),
                "HIT: dangerous pattern in response"
            );
            break;
        }
    }
}

// ── Stream impl ───────────────────────────────────────────────────────────────

impl<S> Stream for HitStream<S>
where
    S: Stream<Item = Result<Bytes, crate::providers::error::ProviderError>> + Send,
{
    type Item = Result<Bytes, crate::providers::error::ProviderError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();

        // Phase 1: if paused, poll the approval oneshot.
        let approval_pending = if matches!(*this.state, HitStreamState::Paused) {
            HitStreamMut {
                state: &mut *this.state,
                approval_rx: &mut *this.approval_rx,
                paused_tool_name: &mut *this.paused_tool_name,
                tool_input_buffer: &mut *this.tool_input_buffer,
                pending_chunks: &mut *this.pending_chunks,
                last_hit_hash: &mut *this.last_hit_hash,
                audit_log: this.audit_log,
                request_id: this.request_id,
                policy: this.policy,
                approval_tx_store: this.approval_tx_store,
                event_bus: this.event_bus,
            }
            .poll_paused_approval(cx)
        } else {
            false
        };

        // Phase 2: flush pending chunks (only in Passthrough).
        if matches!(*this.state, HitStreamState::Passthrough) {
            if let Some(chunk) = this.pending_chunks.pop_front() {
                return Poll::Ready(Some(Ok(chunk)));
            }
        }

        // Phase 3: poll inner stream (single call per poll_next).
        match this.inner.poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                if matches!(*this.state, HitStreamState::Paused) {
                    this.pending_chunks.push_back(bytes);
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }

                if let HitStreamState::BufferingInput {
                    tool_name: ref tname,
                    tool_index: ref tidx,
                } = *this.state
                {
                    let (tname, tidx) = (tname.clone(), *tidx);

                    if let Some(partial) = extract_partial_json(&bytes, tidx) {
                        this.tool_input_buffer.push_str(&partial);
                    }
                    this.pending_chunks.push_back(bytes.clone());

                    if memmem::find(&bytes, b"content_block_stop").is_some() {
                        if let Some(stop_idx) = extract_block_index(&bytes) {
                            if stop_idx == tidx {
                                let tool_info = ToolUseInfo {
                                    name: tname.clone(),
                                    input_preview: this.tool_input_buffer.clone(),
                                };
                                let decision = evaluate_tool_use(this.policy, &tool_info);
                                HitStreamMut {
                                    state: &mut *this.state,
                                    approval_rx: &mut *this.approval_rx,
                                    paused_tool_name: &mut *this.paused_tool_name,
                                    tool_input_buffer: &mut *this.tool_input_buffer,
                                    pending_chunks: &mut *this.pending_chunks,
                                    last_hit_hash: &mut *this.last_hit_hash,
                                    audit_log: this.audit_log,
                                    request_id: this.request_id,
                                    policy: this.policy,
                                    approval_tx_store: this.approval_tx_store,
                                    event_bus: this.event_bus,
                                }
                                .apply_hit_decision(decision, &tname);
                            }
                        }
                    }

                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }

                // Passthrough: fast path and tool_use detection.
                if memmem::find(&bytes, b"content_block_start").is_none() {
                    check_flag_patterns(&bytes, this.flag_regexes, this.event_bus, this.request_id);
                    return Poll::Ready(Some(Ok(bytes)));
                }

                if let Some(tool_name) = extract_tool_name(&bytes) {
                    let tool_index = extract_block_index(&bytes).unwrap_or(0);
                    this.tool_input_buffer.clear();
                    this.pending_chunks.push_back(bytes);
                    *this.state = HitStreamState::BufferingInput {
                        tool_name,
                        tool_index,
                    };
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }

                Poll::Ready(Some(Ok(bytes)))
            }

            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),

            Poll::Ready(None) => {
                if matches!(*this.state, HitStreamState::Paused) {
                    this.pending_chunks.clear();
                    this.tool_input_buffer.clear();
                    *this.approval_rx = None;
                    *this.paused_tool_name = None;
                    *this.state = HitStreamState::Passthrough;
                }
                Poll::Ready(None)
            }

            Poll::Pending => {
                let _ = approval_pending;
                Poll::Pending
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

//! Integration tests for the HIT (Human Intent Token) approval flow.
//!
//! Tests the complete flow: LLM streaming response → stream intercepts tool_use →
//! approval channel created → external caller resolves approval → stream resumes.
//!
//! This validates the full pipeline at the stream + approval-store boundary, which
//! is the seam between the SSE interception layer and the HTTP approve endpoint.

use bytes::Bytes;
use futures::StreamExt;
use grob::features::policies::hit::HitOverride;
use grob::features::policies::stream::{HitApprovalEntry, HitPendingApprovals, HitStream};
use std::sync::Arc;

// ── SSE helpers ──

fn tool_use_start(name: &str, index: u32) -> Bytes {
    Bytes::from(format!(
        "event: content_block_start\ndata: {{\"type\":\"content_block_start\",\"index\":{index},\"content_block\":{{\"type\":\"tool_use\",\"id\":\"call_1\",\"name\":\"{name}\"}}}}\n\n"
    ))
}

fn tool_use_delta(index: u32, partial: &str) -> Bytes {
    Bytes::from(format!(
        "event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":{index},\"delta\":{{\"type\":\"input_json_delta\",\"partial_json\":\"{partial}\"}}}}\n\n"
    ))
}

fn content_block_stop(index: u32) -> Bytes {
    Bytes::from(format!(
        "event: content_block_stop\ndata: {{\"type\":\"content_block_stop\",\"index\":{index}}}\n\n"
    ))
}

fn text_chunk(text: &str) -> Bytes {
    Bytes::from(format!(
        "event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":\"{text}\"}}}}\n\n"
    ))
}

fn require_approval_policy() -> HitOverride {
    HitOverride {
        auto_approve: vec![],
        require_approval: vec!["Edit".into(), "Bash".into()],
        deny: vec!["Bash(rm -rf*)".into()],
        auth_method: "prompt".into(),
        flag_patterns: vec![],
        webhook_url: None,
        required_signatures: None,
        quorum: None,
        scoring: None,
    }
}

// ── Tests ──

/// Full HIT flow: tool_use detected → stream pauses → HTTP-layer approves → stream resumes.
///
/// Simulates what happens when a user clicks "Approve" in the grob watch TUI or calls
/// `POST /api/hit/approve`. The approval store is the same `Arc<HitPendingApprovals>`
/// that `AppState.hit_pending` holds at runtime.
#[tokio::test]
async fn hit_approve_flow_resumes_stream() {
    let store: Arc<HitPendingApprovals> = Arc::new(HitPendingApprovals::default());
    let store_clone = Arc::clone(&store);

    let chunks: Vec<Result<Bytes, grob::providers::error::ProviderError>> = vec![
        Ok(text_chunk("thinking...")),
        Ok(tool_use_start("Edit", 1)),
        Ok(tool_use_delta(1, "{\\\"path\\\":\\\"main.rs\\\",")),
        Ok(tool_use_delta(1, "\\\"content\\\":\\\"fn main() {}\\\"}")),
        Ok(content_block_stop(1)),
        Ok(text_chunk("done")),
    ];

    let mut stream = HitStream::new(
        futures::stream::iter(chunks),
        require_approval_policy(),
        "integration-req-1".to_string(),
        Some(store_clone),
        None,
        None,
    );

    // "thinking..." passes through immediately.
    let first = stream.next().await.unwrap().unwrap();
    assert!(String::from_utf8_lossy(&first).contains("thinking"));

    // Simulate the HTTP approve endpoint: resolve the pending approval.
    let approval_store = Arc::clone(&store);
    tokio::spawn(async move {
        loop {
            let tx = {
                let mut map = approval_store.lock().unwrap();
                map.remove("integration-req-1:Edit").and_then(|e| {
                    if let HitApprovalEntry::Simple(tx) = e {
                        Some(tx)
                    } else {
                        None
                    }
                })
            };
            if let Some(tx) = tx {
                tx.send(true).unwrap();
                return;
            }
            tokio::task::yield_now().await;
        }
    });

    // Stream should resume and emit all buffered chunks + "done".
    let mut remaining = Vec::new();
    while let Some(item) = stream.next().await {
        remaining.push(item.unwrap());
    }

    // tool_use_start + 2 deltas + stop + "done" = 5 chunks.
    assert_eq!(remaining.len(), 5, "expected 5 chunks after approval");
    let last = String::from_utf8_lossy(&remaining[4]);
    assert!(last.contains("done"), "last chunk should be 'done'");
}

/// Deny flow: stream should drop the entire tool_use block and continue.
#[tokio::test]
async fn hit_deny_flow_drops_tool_block() {
    let store: Arc<HitPendingApprovals> = Arc::new(HitPendingApprovals::default());
    let store_clone = Arc::clone(&store);

    let chunks: Vec<Result<Bytes, grob::providers::error::ProviderError>> = vec![
        Ok(text_chunk("start")),
        Ok(tool_use_start("Edit", 1)),
        Ok(tool_use_delta(1, "{\\\"path\\\":\\\"bad.rs\\\"}")),
        Ok(content_block_stop(1)),
        Ok(text_chunk("end")),
    ];

    let mut stream = HitStream::new(
        futures::stream::iter(chunks),
        require_approval_policy(),
        "integration-req-2".to_string(),
        Some(store_clone),
        None,
        None,
    );

    let first = stream.next().await.unwrap().unwrap();
    assert!(String::from_utf8_lossy(&first).contains("start"));

    // Deny the tool.
    let approval_store = Arc::clone(&store);
    tokio::spawn(async move {
        loop {
            let tx = {
                let mut map = approval_store.lock().unwrap();
                map.remove("integration-req-2:Edit").and_then(|e| {
                    if let HitApprovalEntry::Simple(tx) = e {
                        Some(tx)
                    } else {
                        None
                    }
                })
            };
            if let Some(tx) = tx {
                tx.send(false).unwrap();
                return;
            }
            tokio::task::yield_now().await;
        }
    });

    let mut remaining = Vec::new();
    while let Some(item) = stream.next().await {
        remaining.push(item.unwrap());
    }

    // Only "end" should remain (tool_use block dropped).
    assert_eq!(
        remaining.len(),
        1,
        "tool_use block should be dropped on deny"
    );
    assert!(String::from_utf8_lossy(&remaining[0]).contains("end"));
}

/// Deny-by-arg-pattern: `Bash(rm -rf*)` is denied via policy without human interaction.
#[tokio::test]
async fn hit_deny_arg_pattern_no_human_needed() {
    let chunks: Vec<Result<Bytes, grob::providers::error::ProviderError>> = vec![
        Ok(text_chunk("executing")),
        Ok(tool_use_start("Bash", 1)),
        Ok(tool_use_delta(1, "{\\\"command\\\":")),
        Ok(tool_use_delta(1, "\\\"rm -rf /var/data\\\"}")),
        Ok(content_block_stop(1)),
        Ok(text_chunk("finished")),
    ];

    let stream = HitStream::new(
        futures::stream::iter(chunks),
        require_approval_policy(),
        "integration-req-3".to_string(),
        None,
        None,
        None,
    );

    let collected: Vec<Bytes> = stream.filter_map(|r| async { r.ok() }).collect().await;

    // Only text chunks pass through; the Bash(rm -rf*) block is dropped by policy.
    assert_eq!(collected.len(), 2);
    assert!(String::from_utf8_lossy(&collected[0]).contains("executing"));
    assert!(String::from_utf8_lossy(&collected[1]).contains("finished"));
}

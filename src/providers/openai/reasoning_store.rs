//! Cross-turn storage for encrypted Responses-API reasoning items.
//!
//! Under `store = false` the ChatGPT Codex backend returns its reasoning state
//! as opaque `encrypted_content` on `reasoning` output items and keeps nothing
//! server-side. Codex CLI owns the conversation in native Responses format and
//! simply replays every recorded item, reasoning included, on the next turn.
//!
//! grob cannot do that: it is a translator, and Claude Code re-sends the history
//! in Anthropic format, which has no place to carry a `reasoning` item. So grob
//! keeps its own copy here, anchored to the tool call the reasoning produced,
//! and splices it back in when that tool call is replayed.
//!
//! Only reasoning that immediately precedes a `function_call` is stored — that
//! call's `call_id` is the one anchor that survives the round trip through
//! Anthropic's format. Reasoning that closes a text-only turn is dropped.

use moka::sync::Cache;
use std::time::Duration;

/// How long an unreplayed reasoning item stays available.
///
/// An agent loop replays the previous turn's reasoning within seconds; an hour
/// covers a user who walks away mid-conversation without letting abandoned
/// sessions accumulate.
const REASONING_TTL: Duration = Duration::from_secs(3600);

/// Upper bound on retained reasoning items across all live conversations.
///
/// Each entry is one `encrypted_content` blob (a few KB), so this caps the store
/// in the low hundreds of MB even when every slot is full.
const REASONING_CAPACITY: u64 = 20_000;

/// Reasoning items keyed by `"<conversation>:<call_id>"`.
///
/// The conversation part is the same prefix hash grob sends as
/// `prompt_cache_key`, so two different Claude Code sessions never collide and
/// the key stays stable across process restarts within one conversation.
pub(crate) type ReasoningStore = Cache<String, serde_json::Value>;

/// Builds a reasoning store.
pub(crate) fn reasoning_store() -> ReasoningStore {
    Cache::builder()
        .max_capacity(REASONING_CAPACITY)
        .time_to_live(REASONING_TTL)
        .name("codex_reasoning")
        .build()
}

/// Returns the process-wide reasoning store.
///
/// Process-global rather than per-provider so a `/api/config/reload` — which
/// rebuilds the provider registry — does not throw away the reasoning of
/// conversations that are still in flight.
pub(crate) fn global() -> &'static ReasoningStore {
    static STORE: std::sync::OnceLock<ReasoningStore> = std::sync::OnceLock::new();
    STORE.get_or_init(reasoning_store)
}

/// Composes the store key for one tool call within one conversation.
pub(crate) fn reasoning_key(conversation: &str, call_id: &str) -> String {
    format!("{conversation}:{call_id}")
}

/// Records the reasoning items captured from one streamed response.
///
/// `captured` pairs each `call_id` with the reasoning items the model emitted
/// immediately before it, in wire order.
pub(crate) fn record(
    store: &ReasoningStore,
    conversation: &str,
    captured: &[(String, Vec<serde_json::Value>)],
) {
    for (call_id, items) in captured {
        // The backend rejects an input that repeats a reasoning item id, so when
        // several arrive before one call they are stored — and later replayed —
        // as a group in their original order.
        for (nth, item) in items.iter().enumerate() {
            store.insert(
                reasoning_key(conversation, &grouped_call_id(call_id, nth)),
                item.clone(),
            );
        }
    }
}

/// Returns the reasoning items to splice in ahead of `call_id`, in wire order.
pub(crate) fn replay(
    store: &ReasoningStore,
    conversation: &str,
    call_id: &str,
) -> Vec<serde_json::Value> {
    let mut items = Vec::new();
    // Group members are stored under `call_id`, `call_id#1`, `call_id#2`, … so
    // walking until the first miss recovers the whole group in order.
    for nth in 0.. {
        match store.get(&reasoning_key(conversation, &grouped_call_id(call_id, nth))) {
            Some(item) => items.push(item),
            None => break,
        }
    }
    items
}

/// Suffixes the second and later reasoning items sharing one `call_id`.
fn grouped_call_id(call_id: &str, nth: usize) -> String {
    if nth == 0 {
        call_id.to_string()
    } else {
        format!("{call_id}#{nth}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn item(id: &str) -> serde_json::Value {
        json!({"type": "reasoning", "id": id, "encrypted_content": "enc"})
    }

    #[test]
    fn replays_what_was_recorded() {
        let store = reasoning_store();
        record(&store, "conv-a", &[("call_1".into(), vec![item("rs_1")])]);

        assert_eq!(replay(&store, "conv-a", "call_1"), vec![item("rs_1")]);
    }

    #[test]
    fn keeps_a_group_of_reasoning_items_in_wire_order() {
        let store = reasoning_store();
        record(
            &store,
            "conv-a",
            &[(
                "call_1".into(),
                vec![item("rs_1"), item("rs_2"), item("rs_3")],
            )],
        );

        assert_eq!(
            replay(&store, "conv-a", "call_1"),
            vec![item("rs_1"), item("rs_2"), item("rs_3")]
        );
    }

    #[test]
    fn separates_conversations_sharing_a_call_id() {
        let store = reasoning_store();
        record(&store, "conv-a", &[("call_1".into(), vec![item("rs_a")])]);
        record(&store, "conv-b", &[("call_1".into(), vec![item("rs_b")])]);

        assert_eq!(replay(&store, "conv-a", "call_1"), vec![item("rs_a")]);
        assert_eq!(replay(&store, "conv-b", "call_1"), vec![item("rs_b")]);
    }

    #[test]
    fn returns_nothing_for_an_unknown_call() {
        let store = reasoning_store();
        record(&store, "conv-a", &[("call_1".into(), vec![item("rs_1")])]);

        assert!(replay(&store, "conv-a", "call_missing").is_empty());
        assert!(replay(&store, "conv-missing", "call_1").is_empty());
    }
}

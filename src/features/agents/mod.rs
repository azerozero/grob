//! Agent identity: who is asking, and on whose behalf.
//!
//! Grob already knows the tenant and the model behind a request. It does not
//! know the *agent*, which is the unit operators actually reason about when
//! several automated callers share one API key. Without it, cost is
//! attributable to a key rather than to the thing that spent it.
//!
//! # Identity is carried, never inferred
//!
//! The identifier arrives in a header. Deriving it from traffic shape or
//! prompt content would be guesswork, and a wrong attribution is worse than
//! none: it points an investigation at the wrong agent.
//!
//! This first slice deliberately establishes identity and attribution only.
//! Enforcement (budgets, capabilities, leases) needs a registry to check
//! against, and shipping the observable half first means the enforceable half
//! arrives with real data behind it rather than assumptions.

use serde::{Deserialize, Serialize};

/// Header carrying the calling agent's identifier.
pub const AGENT_ID_HEADER: &str = "x-grob-agent-id";

/// Header carrying the parent agent's identifier, for spawned subagents.
pub const PARENT_AGENT_ID_HEADER: &str = "x-grob-parent-agent-id";

/// Longest accepted identifier.
///
/// Bounded because it is journaled and logged: an unbounded identifier is an
/// unbounded write on a path the caller controls.
const MAX_AGENT_ID_LEN: usize = 128;

/// A validated agent identifier.
///
/// Deliberately not a UUID. Operators name their agents, and a readable name
/// in a spend report is worth more than a generated one nobody recognises.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AgentId(String);

impl AgentId {
    /// Validates and wraps an identifier.
    ///
    /// Accepts ASCII alphanumerics plus `-`, `_`, `.` and `:`. The character
    /// set is narrow on purpose: the value reaches log lines, journal records
    /// and metric labels, so anything that could inject a separator or a
    /// control character is refused at the boundary rather than escaped at
    /// each use.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.len() > MAX_AGENT_ID_LEN {
            return None;
        }
        let valid = trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'));
        valid.then(|| Self(trimmed.to_string()))
    }

    /// Returns the identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The agent behind a request, and its parent when it was spawned by another.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentContext {
    /// Calling agent, when one identified itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<AgentId>,
    /// Parent agent, for a spawned subagent.
    ///
    /// Recorded rather than enforced here. Lineage is what later makes
    /// hierarchical budgets and recursive termination possible, and it has to
    /// be captured before it can be relied upon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<AgentId>,
}

impl AgentContext {
    /// Extracts the context from request headers.
    ///
    /// Malformed values are dropped rather than rejected. An agent header is
    /// metadata for attribution, not authorisation, so a bad one must not
    /// fail a request that would otherwise succeed. Enforcement comes later,
    /// against a registry, and that is where a bad identifier should bite.
    #[must_use]
    pub fn from_headers(headers: &axum::http::HeaderMap) -> Self {
        let read = |name: &str| -> Option<AgentId> {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .and_then(AgentId::parse)
        };
        let agent_id = read(AGENT_ID_HEADER);
        let parent_id = read(PARENT_AGENT_ID_HEADER);

        // A parent without a child is meaningless, and keeping it would
        // produce lineage records with no descendant to attach them to.
        if agent_id.is_none() {
            return Self::default();
        }
        // A self-parented agent is a cycle. Dropping the parent here keeps
        // the identity (spend is still attributable) while refusing lineage
        // that would make a hierarchy non-terminating. Detecting it and
        // storing it anyway would only move the problem to every consumer.
        let parent_id = if parent_id == agent_id {
            None
        } else {
            parent_id
        };
        Self {
            agent_id,
            parent_id,
        }
    }

    /// Returns the identifier, when present.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        self.agent_id.as_ref().map(AgentId::as_str)
    }

    /// Returns the parent identifier, when present.
    #[must_use]
    pub fn parent(&self) -> Option<&str> {
        self.parent_id.as_ref().map(AgentId::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(*name, HeaderValue::from_str(value).expect("header value"));
        }
        map
    }

    #[test]
    fn readable_identifiers_are_accepted() {
        // Operators name their agents. A readable name in a spend report is
        // worth more than a generated one nobody recognises.
        for raw in [
            "planner",
            "code-reviewer",
            "team.backend:worker-3",
            "agent_42",
            "a",
        ] {
            assert!(AgentId::parse(raw).is_some(), "{raw} should be accepted");
        }
    }

    #[test]
    fn identifiers_that_could_corrupt_a_log_line_are_refused() {
        // The value reaches log lines, journal records and metric labels.
        // Refusing at the boundary beats escaping at each use site, because
        // one forgotten escape is a corrupted record.
        for raw in [
            "agent id",        // space
            "agent\nid",       // newline: would forge a journal line
            "agent\tid",       // tab
            "agent\"id",       // quote: would break JSON if unescaped
            "agent/../../etc", // path traversal shape
            "agent{}",         // brace
            "café",            // non-ASCII
            "",                // empty
            "   ",             // whitespace only
        ] {
            assert!(AgentId::parse(raw).is_none(), "{raw:?} should be refused");
        }
    }

    #[test]
    fn overlong_identifiers_are_refused() {
        // The value is journaled, so an unbounded identifier is an unbounded
        // write on a path the caller controls.
        assert!(AgentId::parse(&"a".repeat(MAX_AGENT_ID_LEN)).is_some());
        assert!(AgentId::parse(&"a".repeat(MAX_AGENT_ID_LEN + 1)).is_none());
    }

    #[test]
    fn surrounding_whitespace_is_trimmed_not_rejected() {
        let id = AgentId::parse("  planner  ").expect("trimmed");
        assert_eq!(id.as_str(), "planner");
    }

    #[test]
    fn a_request_without_headers_carries_no_agent() {
        let context = AgentContext::from_headers(&HeaderMap::new());
        assert!(context.id().is_none());
        assert_eq!(context.id(), None);
        assert_eq!(context.parent(), None);
    }

    #[test]
    fn lineage_is_captured_when_both_headers_are_present() {
        let context = AgentContext::from_headers(&headers(&[
            (AGENT_ID_HEADER, "worker-3"),
            (PARENT_AGENT_ID_HEADER, "planner"),
        ]));
        assert_eq!(context.id(), Some("worker-3"));
        assert_eq!(context.parent(), Some("planner"));
    }

    #[test]
    fn a_parent_without_a_child_is_discarded() {
        // Keeping it would produce lineage records with no descendant to
        // attach them to.
        let context = AgentContext::from_headers(&headers(&[(PARENT_AGENT_ID_HEADER, "planner")]));
        assert!(context.id().is_none());
        assert_eq!(context.parent(), None);
    }

    #[test]
    fn a_malformed_header_does_not_fail_the_request() {
        // Agent identity is metadata for attribution, not authorisation. A
        // bad header must not break a request that would otherwise succeed;
        // enforcement belongs later, against a registry.
        let context = AgentContext::from_headers(&headers(&[(AGENT_ID_HEADER, "bad id!")]));
        assert!(context.id().is_none());

        // A valid agent with a malformed parent keeps its own identity.
        let context = AgentContext::from_headers(&headers(&[
            (AGENT_ID_HEADER, "worker-3"),
            (PARENT_AGENT_ID_HEADER, "bad parent!"),
        ]));
        assert_eq!(context.id(), Some("worker-3"));
        assert_eq!(context.parent(), None);
    }

    #[test]
    fn a_self_parented_agent_loses_its_cyclic_lineage() {
        // Detecting a cycle and storing it anyway would push the problem onto
        // every consumer. The identity survives, so spend stays attributable;
        // only the impossible lineage is dropped.
        let context = AgentContext::from_headers(&headers(&[
            (AGENT_ID_HEADER, "planner"),
            (PARENT_AGENT_ID_HEADER, "planner"),
        ]));
        assert_eq!(context.id(), Some("planner"));
        assert_eq!(context.parent(), None);

        let context = AgentContext::from_headers(&headers(&[
            (AGENT_ID_HEADER, "worker-3"),
            (PARENT_AGENT_ID_HEADER, "planner"),
        ]));
        assert_eq!(context.parent(), Some("planner"));
    }

    #[test]
    fn spend_records_attribute_to_an_agent_and_stay_backward_compatible() {
        // The point of this slice: cost becomes attributable to the thing
        // that spent it rather than to the API key it shared.
        let dir = tempfile::tempdir().expect("tempdir");
        // open() takes a file path and derives the base dir from its parent.
        let store = crate::storage::GrobStore::open(&dir.path().join("grob.db")).expect("store");

        store.record_spend_for_agent(None, 1.5, "anthropic", "sonnet", Some("planner"));
        store.record_spend_for_agent(None, 2.5, "anthropic", "sonnet", Some("worker-3"));
        // A legacy caller with no agent must keep working unchanged.
        store.record_spend(None, 1.0, "anthropic", "sonnet");

        let month = crate::features::token_pricing::spend::current_month();
        let path = dir.path().join("spend").join(format!("{month}.jsonl"));
        let raw = std::fs::read_to_string(&path).expect("read journal");

        let lines: Vec<serde_json::Value> = raw
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("parse line"))
            .collect();
        assert_eq!(lines.len(), 3);

        let agents: Vec<Option<&str>> = lines
            .iter()
            .map(|l| l.get("agent").and_then(serde_json::Value::as_str))
            .collect();
        assert_eq!(agents, vec![Some("planner"), Some("worker-3"), None]);

        // The agent-less record must not even carry the key, so existing
        // exports parse it exactly as before.
        assert!(
            !lines[2].as_object().expect("object").contains_key("agent"),
            "an absent agent must be omitted, not written as null"
        );
    }

    /// The failure this repository hit three times in the media slice, now
    /// guarded here before it becomes a fourth: code merged, fully tested,
    /// and called by nothing.
    ///
    /// Unit tests cannot see it, because each piece passes alone. This walks
    /// the source and fails when a wiring point loses its caller.
    #[test]
    fn agent_attribution_stays_wired_into_the_request_path() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

        // (symbol, why it matters, file where a caller must exist).
        let wirings = [
            (
                "AgentContext::from_headers",
                "no request would ever be attributed",
                "server/handlers.rs",
            ),
            (
                "ctx.agent_id()",
                "the parsed agent would never reach the spend record",
                "server/dispatch/telemetry.rs",
            ),
            (
                "record_attributed",
                "attribution would stop at the budget layer",
                "server/budget.rs",
            ),
            (
                "agent_id",
                "streamed responses would bill to nobody while \
                 non-streaming ones stayed attributed, which is worse than \
                 no attribution because the gap is invisible",
                "server/dispatch/retry.rs",
            ),
            (
                "record_spend_for_agent",
                "nothing would reach the journal",
                "features/token_pricing/spend.rs",
            ),
        ];

        for (symbol, consequence, caller) in wirings {
            let path = root.join(caller);
            let contents = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
            assert!(
                contents.contains(symbol),
                "{caller} no longer references {symbol}: {consequence}. \
                 Wire it back up or delete the feature."
            );
        }
    }

    /// Proves attribution survives the *whole* production path rather than
    /// just the storage call: tracker -> store -> journal on disk.
    #[test]
    fn the_tracker_carries_attribution_all_the_way_to_the_journal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = crate::storage::GrobStore::open(&dir.path().join("grob.db")).expect("store");
        let mut tracker = crate::features::token_pricing::spend::SpendTracker::with_store(
            std::sync::Arc::new(store),
        );

        tracker.record_attributed(None, "anthropic", "sonnet", 1.5, Some("planner"));
        // Same call shape without an agent must behave exactly as before.
        tracker.record_attributed(None, "anthropic", "sonnet", 2.0, None);

        let month = crate::features::token_pricing::spend::current_month();
        let raw = std::fs::read_to_string(dir.path().join("spend").join(format!("{month}.jsonl")))
            .expect("read journal");
        let agents: Vec<Option<String>> = raw
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                serde_json::from_str::<serde_json::Value>(l)
                    .expect("parse")
                    .get("agent")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string)
            })
            .collect();
        assert_eq!(agents, vec![Some("planner".to_string()), None]);
    }

    #[test]
    fn an_absent_agent_is_omitted_from_serialisation() {
        // Existing journals and exports must stay byte-compatible for the
        // overwhelming majority of requests, which carry no agent.
        let json = serde_json::to_string(&AgentContext::default()).expect("serialise");
        assert_eq!(json, "{}");
    }
}

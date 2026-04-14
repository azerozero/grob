//! Declarative tier matcher: evaluates `[tiers.match]` conditions at routing time.

use crate::cli::TierMatchCondition;
use crate::models::CanonicalRequest;
use crate::router::classify::{self, ComplexityTier};
use globset::{Glob, GlobMatcher};
use tracing::debug;

/// Pre-compiled tier match with glob matchers for file patterns.
#[derive(Clone)]
pub(crate) struct CompiledTierMatch {
    tier: ComplexityTier,
    condition: TierMatchCondition,
    file_globs: Vec<GlobMatcher>,
}

impl CompiledTierMatch {
    /// Compiles a tier match condition into a ready-to-evaluate matcher.
    ///
    /// # Errors
    ///
    /// Returns an error if any `file_patterns` glob is invalid.
    pub fn new(
        tier: ComplexityTier,
        condition: TierMatchCondition,
    ) -> Result<Self, globset::Error> {
        let file_globs = condition
            .file_patterns
            .iter()
            .map(|p| Glob::new(p).map(|g| g.compile_matcher()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            tier,
            condition,
            file_globs,
        })
    }

    /// Evaluates all conditions against a request (AND-combined).
    fn matches(&self, request: &CanonicalRequest) -> bool {
        if !self.condition.keywords.is_empty() && !self.matches_keywords(request) {
            return false;
        }
        if !self.file_globs.is_empty() && !self.matches_file_patterns(request) {
            return false;
        }
        if !self.condition.tools.is_empty() && !self.matches_tools(request) {
            return false;
        }
        if let Some(above) = self.condition.max_tokens_above {
            if request.max_tokens < above {
                return false;
            }
        }
        if let Some(below) = self.condition.max_tokens_below {
            if request.max_tokens > below {
                return false;
            }
        }
        if let Some(min_msgs) = self.condition.min_messages {
            if request.messages.len() < min_msgs {
                return false;
            }
        }
        true
    }

    fn matches_keywords(&self, request: &CanonicalRequest) -> bool {
        let text = match classify::extract_last_user_text(request) {
            Some(t) => t.to_lowercase(),
            None => return false,
        };
        self.condition
            .keywords
            .iter()
            .any(|kw| text.contains(&kw.to_lowercase()))
    }

    fn matches_file_patterns(&self, request: &CanonicalRequest) -> bool {
        let text = match classify::extract_last_user_text(request) {
            Some(t) => t,
            None => return false,
        };
        let paths = extract_file_paths(&text);
        paths
            .iter()
            .any(|p| self.file_globs.iter().any(|g| g.is_match(p)))
    }

    fn matches_tools(&self, request: &CanonicalRequest) -> bool {
        let tools = match &request.tools {
            Some(t) => t,
            None => return false,
        };
        self.condition.tools.iter().any(|required| {
            tools.iter().any(|t| {
                t.name
                    .as_deref()
                    .is_some_and(|n| n.eq_ignore_ascii_case(required))
            })
        })
    }
}

/// Evaluates compiled tier matchers in declaration order, returns the first match.
pub(crate) fn evaluate_tier_matches(
    matchers: &[CompiledTierMatch],
    request: &CanonicalRequest,
) -> Option<ComplexityTier> {
    for m in matchers {
        if m.matches(request) {
            debug!(tier = %m.tier, "📊 Declarative tier match");
            return Some(m.tier);
        }
    }
    None
}

/// Extracts file-path-like tokens from text for glob matching.
fn extract_file_paths(text: &str) -> Vec<&str> {
    text.split(|c: char| c.is_whitespace() || c == '`' || c == '\'' || c == '"')
        .filter(|token| {
            !token.is_empty()
                && (token.contains('/')
                    || token
                        .rfind('.')
                        .is_some_and(|dot| dot > 0 && dot < token.len() - 1))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::extensions::RequestExtensions;
    use crate::models::{Message, MessageContent, Tool};

    fn request_with_text(text: &str, max_tokens: u32) -> CanonicalRequest {
        CanonicalRequest {
            model: "test".into(),
            messages: vec![Message {
                role: "user".into(),
                content: MessageContent::Text(text.into()),
            }],
            max_tokens,
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
            extensions: RequestExtensions::default(),
        }
    }

    fn request_with_tools(text: &str, tool_names: &[&str]) -> CanonicalRequest {
        let tools = tool_names
            .iter()
            .map(|name| Tool {
                r#type: Some("function".into()),
                name: Some(name.to_string()),
                description: None,
                input_schema: None,
            })
            .collect();
        let mut req = request_with_text(text, 4096);
        req.tools = Some(tools);
        req
    }

    fn condition(keywords: &[&str], file_patterns: &[&str]) -> TierMatchCondition {
        TierMatchCondition {
            keywords: keywords.iter().map(|s| s.to_string()).collect(),
            file_patterns: file_patterns.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn keywords_match_case_insensitive() {
        let m =
            CompiledTierMatch::new(ComplexityTier::Complex, condition(&["unsafe"], &[])).unwrap();
        assert!(m.matches(&request_with_text("Use unsafe block here", 4096)));
    }

    #[test]
    fn keywords_no_match() {
        let m =
            CompiledTierMatch::new(ComplexityTier::Complex, condition(&["unsafe"], &[])).unwrap();
        assert!(!m.matches(&request_with_text("use safe patterns only", 4096)));
    }

    #[test]
    fn file_patterns_match_rs() {
        let m = CompiledTierMatch::new(ComplexityTier::Complex, condition(&[], &["*.rs"])).unwrap();
        assert!(m.matches(&request_with_text("edit src/main.rs please", 4096)));
    }

    #[test]
    fn file_patterns_match_tf() {
        let m = CompiledTierMatch::new(ComplexityTier::Complex, condition(&[], &["*.tf"])).unwrap();
        assert!(m.matches(&request_with_text("update infra/main.tf", 4096)));
    }

    #[test]
    fn file_patterns_no_match() {
        let m = CompiledTierMatch::new(ComplexityTier::Complex, condition(&[], &["*.rs"])).unwrap();
        assert!(!m.matches(&request_with_text("edit main.py please", 4096)));
    }

    #[test]
    fn tools_match_name() {
        let cond = TierMatchCondition {
            tools: vec!["code_editor".into()],
            ..Default::default()
        };
        let m = CompiledTierMatch::new(ComplexityTier::Complex, cond).unwrap();
        assert!(m.matches(&request_with_tools(
            "edit file",
            &["code_editor", "web_search"]
        )));
    }

    #[test]
    fn tools_no_match() {
        let cond = TierMatchCondition {
            tools: vec!["code_editor".into()],
            ..Default::default()
        };
        let m = CompiledTierMatch::new(ComplexityTier::Complex, cond).unwrap();
        assert!(!m.matches(&request_with_tools("edit file", &["web_search"])));
    }

    #[test]
    fn max_tokens_above_match() {
        let cond = TierMatchCondition {
            max_tokens_above: Some(4000),
            ..Default::default()
        };
        let m = CompiledTierMatch::new(ComplexityTier::Complex, cond).unwrap();
        assert!(m.matches(&request_with_text("anything", 8000)));
    }

    #[test]
    fn max_tokens_above_no_match() {
        let cond = TierMatchCondition {
            max_tokens_above: Some(4000),
            ..Default::default()
        };
        let m = CompiledTierMatch::new(ComplexityTier::Complex, cond).unwrap();
        assert!(!m.matches(&request_with_text("anything", 100)));
    }

    #[test]
    fn max_tokens_below_match() {
        let cond = TierMatchCondition {
            max_tokens_below: Some(500),
            ..Default::default()
        };
        let m = CompiledTierMatch::new(ComplexityTier::Trivial, cond).unwrap();
        assert!(m.matches(&request_with_text("anything", 100)));
    }

    #[test]
    fn min_messages_match() {
        let cond = TierMatchCondition {
            min_messages: Some(2),
            ..Default::default()
        };
        let m = CompiledTierMatch::new(ComplexityTier::Complex, cond).unwrap();
        let mut req = request_with_text("msg1", 4096);
        req.messages.push(Message {
            role: "assistant".into(),
            content: MessageContent::Text("reply".into()),
        });
        req.messages.push(Message {
            role: "user".into(),
            content: MessageContent::Text("msg2".into()),
        });
        assert!(m.matches(&req));
    }

    #[test]
    fn all_conditions_and_combined() {
        let cond = TierMatchCondition {
            keywords: vec!["unsafe".into()],
            file_patterns: vec!["*.rs".into()],
            ..Default::default()
        };
        let m = CompiledTierMatch::new(ComplexityTier::Complex, cond).unwrap();
        // Both match
        assert!(m.matches(&request_with_text("use unsafe in main.rs", 4096)));
        // Only keywords match, file_patterns don't
        assert!(!m.matches(&request_with_text("use unsafe in main.py", 4096)));
        // Only file_patterns match, keywords don't
        assert!(!m.matches(&request_with_text("edit main.rs safely", 4096)));
    }

    #[test]
    fn empty_condition_matches_everything() {
        let m =
            CompiledTierMatch::new(ComplexityTier::Trivial, TierMatchCondition::default()).unwrap();
        assert!(m.matches(&request_with_text("anything", 4096)));
    }

    #[test]
    fn first_match_wins_declaration_order() {
        let m1 =
            CompiledTierMatch::new(ComplexityTier::Complex, condition(&["unsafe"], &[])).unwrap();
        let m2 =
            CompiledTierMatch::new(ComplexityTier::Medium, condition(&["unsafe"], &[])).unwrap();
        let matchers = vec![m1, m2];
        let req = request_with_text("use unsafe here", 4096);
        assert_eq!(
            evaluate_tier_matches(&matchers, &req),
            Some(ComplexityTier::Complex)
        );
    }

    #[test]
    fn no_matchers_returns_none() {
        let req = request_with_text("anything", 4096);
        assert_eq!(evaluate_tier_matches(&[], &req), None);
    }

    #[test]
    fn extract_file_paths_basic() {
        let paths = extract_file_paths("edit src/main.rs and infra/vpc.tf please");
        assert!(paths.contains(&"src/main.rs"));
        assert!(paths.contains(&"infra/vpc.tf"));
    }

    #[test]
    fn extract_file_paths_backtick_delimited() {
        let paths = extract_file_paths("fix `main.rs` now");
        assert!(paths.contains(&"main.rs"));
    }

    #[test]
    fn extract_file_paths_no_extension_excluded() {
        let paths = extract_file_paths("hello world");
        assert!(paths.is_empty());
    }
}

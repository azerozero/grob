//! Quorum voting: N independent LLM voters decide on tool_use actions.
//!
//! When a HIT decision is `RequireApproval` and quorum is configured,
//! multiple LLMs vote on whether the tool action should be approved.

use serde::{Deserialize, Serialize};

/// Quorum configuration from `[policies.hit.quorum]` TOML section.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct QuorumConfig {
    /// Voting strategy.
    #[serde(default = "default_strategy")]
    pub strategy: QuorumStrategy,
    /// Minimum number of voters.
    #[serde(default = "default_min_voters")]
    pub min_voters: usize,
    /// Required approvals for majority strategy.
    #[serde(default = "default_required_approvals")]
    pub required_approvals: usize,
    /// Timeout per voter in milliseconds.
    #[serde(default = "default_voter_timeout_ms")]
    pub voter_timeout_ms: u64,
    /// Action on timeout or failure.
    #[serde(default)]
    pub on_failure: QuorumFailureAction,
}

fn default_strategy() -> QuorumStrategy {
    QuorumStrategy::Majority
}
fn default_min_voters() -> usize {
    3
}
fn default_required_approvals() -> usize {
    2
}
fn default_voter_timeout_ms() -> u64 {
    5000
}

/// How votes are aggregated.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum QuorumStrategy {
    /// Majority of voters must approve.
    Majority,
    /// All voters must approve.
    Unanimous,
}

/// Action when quorum cannot be reached.
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum QuorumFailureAction {
    /// Deny the action.
    Deny,
    /// Escalate to human approval.
    #[default]
    EscalateHuman,
}

/// Result of a quorum vote.
#[derive(Debug, Clone, PartialEq)]
pub enum QuorumResult {
    /// Quorum approved the action.
    Approve,
    /// Quorum denied the action.
    Deny,
    /// Quorum inconclusive, escalate to human.
    Escalate,
}

/// Individual voter decision.
#[derive(Debug, Clone, PartialEq)]
pub enum VoterDecision {
    /// Voter approves the action.
    Approve,
    /// Voter denies the action.
    Deny,
    /// Voter abstained or timed out.
    Abstain,
}

/// Tallies voter decisions and returns the quorum result.
pub fn tally_votes(config: &QuorumConfig, votes: &[VoterDecision]) -> QuorumResult {
    let approvals = votes
        .iter()
        .filter(|v| **v == VoterDecision::Approve)
        .count();
    let denials = votes.iter().filter(|v| **v == VoterDecision::Deny).count();

    match config.strategy {
        QuorumStrategy::Majority => {
            if approvals >= config.required_approvals {
                QuorumResult::Approve
            } else if denials > votes.len() - config.required_approvals {
                // Impossible to reach required approvals.
                QuorumResult::Deny
            } else {
                match config.on_failure {
                    QuorumFailureAction::Deny => QuorumResult::Deny,
                    QuorumFailureAction::EscalateHuman => QuorumResult::Escalate,
                }
            }
        }
        QuorumStrategy::Unanimous => {
            if denials > 0 {
                QuorumResult::Deny
            } else if approvals == votes.len() && (approvals + denials) >= config.min_voters {
                QuorumResult::Approve
            } else {
                match config.on_failure {
                    QuorumFailureAction::Deny => QuorumResult::Deny,
                    QuorumFailureAction::EscalateHuman => QuorumResult::Escalate,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(strategy: QuorumStrategy) -> QuorumConfig {
        QuorumConfig {
            strategy,
            min_voters: 3,
            required_approvals: 2,
            voter_timeout_ms: 5000,
            on_failure: QuorumFailureAction::EscalateHuman,
        }
    }

    #[test]
    fn test_majority_approve() {
        let config = test_config(QuorumStrategy::Majority);
        let votes = vec![
            VoterDecision::Approve,
            VoterDecision::Approve,
            VoterDecision::Deny,
        ];
        assert_eq!(tally_votes(&config, &votes), QuorumResult::Approve);
    }

    #[test]
    fn test_majority_deny() {
        let config = test_config(QuorumStrategy::Majority);
        let votes = vec![
            VoterDecision::Deny,
            VoterDecision::Deny,
            VoterDecision::Approve,
        ];
        assert_eq!(tally_votes(&config, &votes), QuorumResult::Deny);
    }

    #[test]
    fn test_unanimous_approve() {
        let config = test_config(QuorumStrategy::Unanimous);
        let votes = vec![
            VoterDecision::Approve,
            VoterDecision::Approve,
            VoterDecision::Approve,
        ];
        assert_eq!(tally_votes(&config, &votes), QuorumResult::Approve);
    }

    #[test]
    fn test_unanimous_one_deny() {
        let config = test_config(QuorumStrategy::Unanimous);
        let votes = vec![
            VoterDecision::Approve,
            VoterDecision::Deny,
            VoterDecision::Approve,
        ];
        assert_eq!(tally_votes(&config, &votes), QuorumResult::Deny);
    }

    #[test]
    fn test_timeout_escalates() {
        let config = test_config(QuorumStrategy::Majority);
        // Only 1 vote cast (2 timed out / abstained).
        let votes = vec![
            VoterDecision::Approve,
            VoterDecision::Abstain,
            VoterDecision::Abstain,
        ];
        assert_eq!(tally_votes(&config, &votes), QuorumResult::Escalate);
    }

    #[test]
    fn test_timeout_deny_policy() {
        let mut config = test_config(QuorumStrategy::Majority);
        config.on_failure = QuorumFailureAction::Deny;
        let votes = vec![
            VoterDecision::Approve,
            VoterDecision::Abstain,
            VoterDecision::Abstain,
        ];
        assert_eq!(tally_votes(&config, &votes), QuorumResult::Deny);
    }
}

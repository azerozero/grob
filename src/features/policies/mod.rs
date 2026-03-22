//! Unified policy engine for per-tenant/zone/compliance request evaluation.
//!
//! Evaluates [`RequestContext`] against glob-based [`MatchRules`] to produce
//! a [`ResolvedPolicy`] with overrides for DLP, rate limiting, routing, budget,
//! log export, and HIT authorization.

pub mod config;
pub mod context;
pub mod hit;
pub mod hit_auth;
#[cfg(feature = "policies")]
pub mod matcher;
pub mod multisig;
pub mod quorum;
pub mod resolved;

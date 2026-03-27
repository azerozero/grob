// Enterprise E2E test suite — 5-layer test scaffolding
//
// Layer 1: Snapshot tests (insta) — routing decision stability per preset
// Layer 2: Property tests (proptest) — DLP, budget, audit invariants
// Layer 3: Scenario tests — failover, DLP bypass, budget enforcement
mod preset_snapshot_test;
mod property_audit_test;
mod property_budget_test;
mod property_dlp_test;
mod property_routing_test;
mod scenario_budget_test;
mod scenario_dlp_bypass_test;
mod scenario_failover_test;
mod snapshot_error_test;

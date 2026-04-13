//! CLI subcommands: start, stop, status, doctor, spend, etc.

/// Self-contained performance evaluation of the proxy pipeline.
pub mod bench;
/// Shared utilities and helpers used across subcommands.
pub mod common;
/// Shell completion script generation for supported shells.
pub mod completions;
/// Compares running config against the on-disk TOML file.
pub mod config_diff;
/// Push/pull config between grob instances for environment promotion.
pub mod config_promote;
/// Restore config from backup file.
pub mod config_rollback;
/// Establishes a live connection to a running grob instance.
pub mod connect;
/// Best-effort API key validation via lightweight provider calls.
pub mod credential_check;
/// Diagnoses configuration, connectivity, and provider health.
pub mod doctor;
/// Displays resolved environment variables and config paths.
pub mod env;
/// Executes a one-shot LLM request without starting the server.
pub mod exec;
/// Record and replay sandwich testing harness.
#[cfg(feature = "harness")]
pub mod harness;
/// Initializes a new grob configuration file interactively.
pub mod init;
/// Virtual API key management (create, list, revoke).
pub mod key;
/// Lists, inspects, and manages available LLM models.
pub mod model;
/// Manages named configuration presets (save, load, delete).
pub mod preset;
/// Stops and restarts the grob server in one operation.
pub mod restart;
/// Lightweight JSON-RPC 2.0 client for calling the running server.
pub mod rpc_client;
/// Starts the server in foreground (non-daemonized) mode.
pub mod run;
/// Interactive first-run setup wizard.
pub mod setup;
/// Installs shell completion scripts to standard locations.
pub mod setup_completions;
/// Displays cumulative spend, budget status, and cost breakdowns.
pub mod spend;
/// Launches the grob server as a background daemon.
pub mod start;
/// Reports whether the grob daemon is running and healthy.
pub mod status;
/// Gracefully shuts down the running grob daemon.
pub mod stop;
/// Checks for and applies grob binary upgrades.
pub mod upgrade;
/// Validates the TOML configuration file for errors.
pub mod validate;
